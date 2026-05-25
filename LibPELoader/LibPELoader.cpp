#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#include <vector>
#include "pch.h"
#include "PELoader.h"
namespace {

    HMODULE getModuleHandle(std::string_view moduleName, HANDLE hProcess) {
        DWORD flags = LIST_MODULES_64BIT;

        DWORD sizeNeeded = 0;
        if (!EnumProcessModulesEx(hProcess, nullptr, 0, &sizeNeeded, flags)) {
            std::cerr << "EnumProcessModulesEx failed (get size): " << GetLastError() << "\n";
            return NULL;
        }
        if (sizeNeeded == 0) return NULL;

        size_t count = sizeNeeded / sizeof(HMODULE);
        std::vector<HMODULE> modules(count);
        DWORD bytesReturned = 0;
        if (!EnumProcessModulesEx(hProcess, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &bytesReturned, flags)) {
            std::cerr << "EnumProcessModulesEx failed (retrieve): " << GetLastError() << "\n";
            return NULL;
        }
        size_t numReturned = bytesReturned / sizeof(HMODULE);
        constexpr DWORD nameBufLen = 4096;

        for (size_t i = 0; i < numReturned; ++i) {
            char nameBuf[nameBufLen] = { 0 };
            if (!GetModuleBaseNameA(hProcess, modules[i], nameBuf, nameBufLen)) {
                continue;
            }
           
            if (_stricmp(moduleName.data(), nameBuf) == 0) {
                return modules[i];
            }
        }
        return NULL;
    }

    bool injectDLL(HANDLE hProc, std::string_view dllName) {
        auto sizeOfPath{ (dllName.size() + 1) * sizeof(char) };
        BYTE* baseAddress{ reinterpret_cast<BYTE*>(
            VirtualAllocEx(hProc, NULL, sizeOfPath, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        ) };

        if (!baseAddress) {
            std::cerr << "VirtualAllocEx failed: " << GetLastError() << '\n';
            return false;
        }


        SIZE_T numBytesWritten{ 0 };
        if (!WriteProcessMemory(hProc, baseAddress, dllName.data(), sizeOfPath, &numBytesWritten)) {
            std::cerr << "WriteProcessMemory failed: " << GetLastError() << '\n';
            VirtualFreeEx(hProc, baseAddress, 0, MEM_RELEASE);
            return false;
        }

        if (numBytesWritten < sizeOfPath) {
            std::cerr << "Error: Partial write\n";
            VirtualFreeEx(hProc, baseAddress, 0, MEM_RELEASE);
            return false;
        }

        // We assume kernel32 is loaded in the same location as in current process (may not be true).

        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), baseAddress, 0, NULL);
        if (!hThread) {
            std::cerr << "CreateRemoteThread failed: " << GetLastError() << '\n';
            VirtualFree(baseAddress, 0, MEM_RELEASE);
            return false;
        }
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        VirtualFreeEx(hProc, baseAddress, 0, MEM_RELEASE);
        return true;
    }

    bool relocateImage(unsigned char* baseAddress, const PIMAGE_NT_HEADERS pNTHeader, uintptr_t delta) {


        const IMAGE_DATA_DIRECTORY& relocDataDir{ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] };
        
        DWORD currentSize{ 0 };
        while (currentSize < relocDataDir.Size) {

            PIMAGE_BASE_RELOCATION baseReloc{ reinterpret_cast<PIMAGE_BASE_RELOCATION>(baseAddress + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + currentSize) };
            currentSize += baseReloc->SizeOfBlock;

            DWORD numberOfRecords{ baseReloc->SizeOfBlock };
            numberOfRecords -= sizeof(IMAGE_BASE_RELOCATION);
            numberOfRecords /= sizeof(uint16_t);

            for (DWORD i{ 0 }; i < numberOfRecords; i++) {
                uint16_t* relocEntry{ reinterpret_cast<uint16_t*>(reinterpret_cast<unsigned char*>(baseReloc) + sizeof(IMAGE_BASE_RELOCATION) + (i * sizeof(uint16_t))) };
                uint16_t relocType{ static_cast<uint16_t>(*relocEntry >> 12) }; // get upper 4 bits
                uint16_t relocRVA{ static_cast<uint16_t>(*relocEntry & 0xfff) }; // lower 12 bits give the rva
                unsigned char* relocValue{ baseAddress + baseReloc->VirtualAddress + relocRVA };

                switch (relocType) {
                case IMAGE_REL_BASED_LOW:
                    *reinterpret_cast<uint16_t*>(relocValue) += LOWORD(delta);
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *reinterpret_cast<uint16_t*>(relocValue) += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *reinterpret_cast<uint32_t*>(relocValue) += static_cast<uint32_t>(delta);
                    break;

                case IMAGE_REL_BASED_DIR64:
                    *reinterpret_cast<uint64_t*>(relocValue) += delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    //nothing to do here
                    break;
                default:
                    std::cerr << "Invalid/Unsupported relocation type: " << relocType << "\n";
                    return false;
                    break;
                }
            }
        }
        return true;
    }

    bool resolveIAT(HANDLE hProc, unsigned char* baseAddress, const PIMAGE_NT_HEADERS pNTHeader, unsigned char* remoteAddress) {
        auto importDirAddress{ baseAddress + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress };

        PIMAGE_IMPORT_DESCRIPTOR pImportDirectoryEntry{ reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importDirAddress) };
        PIMAGE_THUNK_DATA importAddressTable{ reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->FirstThunk) };

        for (; pImportDirectoryEntry->OriginalFirstThunk; pImportDirectoryEntry++) {

            char* dllName = reinterpret_cast<char*>(baseAddress + pImportDirectoryEntry->Name);

            HMODULE hDll{ LoadLibraryA(dllName) };

            if (!hDll) {
                std::cerr << "Failed to load library: " << dllName << " : " << GetLastError();
                return false;
            }
            
            if (!injectDLL(hProc, dllName)) {
                std::cerr << "Loading DLL into remote process failed\n";
                return false;
            }

            PIMAGE_THUNK_DATA pImportLookupTable = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pImportAddressTable{ reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->FirstThunk) };
            int index = 0;
            auto iltEntry{ pImportLookupTable[index] };

            HANDLE hRemoteHandle = getModuleHandle(dllName, hProc);
            if (hRemoteHandle == NULL) {
                std::cerr << "getModuleHandle failed\n";
                return false;
            }

            while (iltEntry.u1.AddressOfData) {

                uintptr_t procAddress{ 0 };

                if (IMAGE_ORDINAL_FLAG & iltEntry.u1.Ordinal) {
                    char* ordinal{ reinterpret_cast<char*>(IMAGE_ORDINAL(iltEntry.u1.Ordinal)) };
                    procAddress =  (uintptr_t)GetProcAddress(hDll, ordinal) ;

                    
                    if (!procAddress) {
                        std::cerr << "GetProcAddress failed: " << GetLastError() << '\n';
                        return false;
                    }
                   
                }
                else {
                    char* funcName{ reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(baseAddress + iltEntry.u1.AddressOfData)->Name };
                    procAddress = (uintptr_t)GetProcAddress(hDll, funcName) ;
                    if (!procAddress) {
                        std::cerr << "GetProcAddress failed: " << GetLastError() << '\n';
                        return false;
                    }
                }

                uintptr_t offset = (uintptr_t)procAddress - (uintptr_t)hDll;
                pImportAddressTable[index].u1.Function = static_cast<ULONGLONG>((uintptr_t)hRemoteHandle + offset);

                index++;
                iltEntry = pImportLookupTable[index];
            }
        }
        return true;
    }
}

bool PELdr::PELoader::loadPE(HANDLE inpProc, unsigned char* peBuffer) {
    if (!inpProc) {
        std::cerr << "Invalid handle passed\n";
        return false;
    }
    hProc = inpProc;
    PIMAGE_DOS_HEADER dosHeader{ reinterpret_cast<PIMAGE_DOS_HEADER>(peBuffer) };
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid PE provided\n";
        return false;
    }

    pNTHeader =  reinterpret_cast<PIMAGE_NT_HEADERS>(peBuffer + dosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE provided\n";
        return false;
    }
    if (pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 and pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        std::cerr << "Invalid/Unsupported machine type provided\n";
        return false;
    }

    const WORD* bitType = reinterpret_cast<WORD*>(&(pNTHeader->OptionalHeader));

    if (*bitType != IMAGE_NT_OPTIONAL_HDR64_MAGIC && *bitType != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        std::cerr << "Unsupported PE\n";
        return false;
    }

    bool is64Bit{ false };
    USHORT processMachine{ 0 };
    USHORT nativeMachine{ 0 };
    if (!IsWow64Process2(GetCurrentProcess(), &processMachine, &nativeMachine)) {
        std::cerr << "Could not retrive bitness of current process: " << GetLastError();
        return false;
    }
    if (nativeMachine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "Invalid native machine type detected";
        return false;
    }

    if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
        is64Bit = true;
    }

    if ((*bitType == IMAGE_NT_OPTIONAL_HDR64_MAGIC && !is64Bit) || (*bitType == IMAGE_NT_OPTIONAL_HDR32_MAGIC && is64Bit)) {
        std::cerr << "Invalid PE type provided\n";
        return false;
    }

    const WORD numberOfSections{ pNTHeader->FileHeader.NumberOfSections };
    
    LPVOID lBuffer = VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);

    if (lBuffer == NULL) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << '\n';
        return false;
    }
    localBuffer = reinterpret_cast<unsigned char*>(lBuffer);

    std::memcpy(localBuffer, peBuffer, pNTHeader->OptionalHeader.SizeOfHeaders);
    

    LPVOID baseAddressAlloc{ VirtualAllocEx(hProc, NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };

    if (baseAddressAlloc == NULL) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << '\n';
        return false;
    }
    
    const uintptr_t sectionHeaderAddress{ reinterpret_cast<uintptr_t>(peBuffer + dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader) };

    for (DWORD sectionIndex{ 0 }; sectionIndex < numberOfSections; ++sectionIndex) {
        PIMAGE_SECTION_HEADER sectionHeader{ reinterpret_cast<PIMAGE_SECTION_HEADER>(sectionHeaderAddress + (sectionIndex * sizeof(IMAGE_SECTION_HEADER))) };
       
        std::memcpy(reinterpret_cast<void*>((unsigned char*)localBuffer + sectionHeader->VirtualAddress), peBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);

    }

    baseAddress = reinterpret_cast<unsigned char*>(baseAddressAlloc);

    delta = reinterpret_cast<uintptr_t>(baseAddress) - pNTHeader->OptionalHeader.ImageBase;

    if (!relocateImage(localBuffer, pNTHeader, delta)) {
        std::cerr << "Image relocation failed\n";
        return false;
    }
  
    if (!resolveIAT(hProc, localBuffer, pNTHeader, baseAddress)) {
        std::cerr << "Resolving imports failed\n";
        return false;
    }

    
    SIZE_T numBytesWritten{ 0 };
    if (!WriteProcessMemory(hProc, baseAddressAlloc, localBuffer, pNTHeader->OptionalHeader.SizeOfImage, &numBytesWritten)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << '\n';
        return false;
    }

    for (DWORD sectionIndex{ 0 }; sectionIndex < numberOfSections; ++sectionIndex) {
        PIMAGE_SECTION_HEADER sectionHeader{ reinterpret_cast<PIMAGE_SECTION_HEADER>(sectionHeaderAddress + (sectionIndex * sizeof(IMAGE_SECTION_HEADER))) };

        DWORD sectionProt{ 0 };

        if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)) {
            sectionProt = PAGE_EXECUTE_READWRITE;

        }
        else if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
            sectionProt = PAGE_EXECUTE_READ;
        }
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            sectionProt = PAGE_EXECUTE;
        }
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            sectionProt = PAGE_READWRITE;
        }
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
            sectionProt = PAGE_READONLY;
        }
        else {
            sectionProt = PAGE_NOACCESS;
        };


        DWORD oldFlags{ 0 };

        if (!VirtualProtectEx(hProc, reinterpret_cast<void*>(baseAddress + sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize, sectionProt, &oldFlags)) {
            std::cerr << "VirtualProtectEx failed: " << GetLastError() << '\n';
            return false;
        }
    }

    return true;

}
bool PELdr::PELoader::callEntry() {
    using DLLEntry = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

    using EXEEntry = void(WINAPI*)(void);

    
    auto entryPoint{ (unsigned char*)baseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint };

    if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        if (hProc == GetCurrentProcess()) {
            DLLEntry dllEntry{ reinterpret_cast<DLLEntry>(entryPoint) };
            dllEntry(reinterpret_cast<HINSTANCE>(baseAddress), DLL_PROCESS_ATTACH, NULL);
        }
        else {
            std::cerr << "Cannot call DLL entry in remote process\n";
            return false;
        }

        
    }
    else {
       
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entryPoint), NULL, 0, NULL);
        if (!hThread) {
            std::cerr << "CreateRemoteThread failed: " << GetLastError() << '\n';
            VirtualFree(baseAddress, 0, MEM_RELEASE);
            return false;
        }
        WaitForSingleObject(hThread, INFINITE);
       
    }
    return true;
}


bool  PELdr::PELoader::callExport(std::string_view funcName) {
    PIMAGE_OPTIONAL_HEADER optionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&(pNTHeader->OptionalHeader));
    PIMAGE_EXPORT_DIRECTORY exportTable = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(localBuffer + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PUINT32 nameArray = reinterpret_cast<PUINT32>(localBuffer + exportTable->AddressOfNames);
    

    //TODO: Use binary search
    for (UINT32 i = 0; i < exportTable->NumberOfNames; i++) {
        UINT32 nameRVA = nameArray[i];
        char* functionName = (char*)(localBuffer + nameRVA);
        if (std::strcmp(funcName.data(), functionName) == 0) {

            PUINT16 ordinalTable = reinterpret_cast<PUINT16>(localBuffer + exportTable->AddressOfNameOrdinals);
            DWORD* exportAddressTable = reinterpret_cast<DWORD*>(localBuffer + exportTable->AddressOfFunctions);
            DWORD ordinal = ordinalTable[i];
            uintptr_t offset = static_cast<uintptr_t>(exportAddressTable[ordinal]);

            HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(baseAddress + offset), NULL, 0, NULL);
            if (!hThread) {
                std::cerr << "CreateRemoteThread failed: " << GetLastError() << '\n';
                return false;
            }
            WaitForSingleObject(hThread, INFINITE);
            return true;
        }
    }
    std::cerr << "The function: " << funcName << " was not found\n";
    return false;
}