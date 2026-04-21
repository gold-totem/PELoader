#include "pch.h"

namespace {
    bool relocateImage(unsigned char* baseAddress, const PIMAGE_NT_HEADERS pNTHeader) {


        const IMAGE_DATA_DIRECTORY& relocDataDir{ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] };
        uintptr_t delta{ reinterpret_cast<uintptr_t>(baseAddress) - pNTHeader->OptionalHeader.ImageBase };

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
    bool resolveIAT(unsigned char* baseAddress, const PIMAGE_NT_HEADERS pNTHeader) {
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
            PIMAGE_THUNK_DATA pImportLookupTable = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pImportAddressTable{ reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->FirstThunk) };
            int index = 0;
            auto iltEntry{ pImportLookupTable[index] };
            while (iltEntry.u1.AddressOfData) {
                if (IMAGE_ORDINAL_FLAG & iltEntry.u1.Ordinal) {
                    char* ordinal{ reinterpret_cast<char*>(IMAGE_ORDINAL(iltEntry.u1.Ordinal)) };
                    auto procAddress{ GetProcAddress(hDll, ordinal) };
                    if (!procAddress) {
                        std::cerr << "GetProcAddress failed: " << GetLastError() << '\n';
                        return false;
                    }
                    pImportAddressTable[index].u1.Function = reinterpret_cast<ULONGLONG>(procAddress);
                }
                else {
                    char* funcName{ reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(baseAddress + iltEntry.u1.AddressOfData)->Name };
                    auto procAddress{ GetProcAddress(hDll, funcName) };
                    if (!procAddress) {
                        std::cerr << "GetProcAddress failed: " << GetLastError() << '\n';
                        return false;
                    }
                    pImportAddressTable[index].u1.Function = reinterpret_cast<ULONGLONG>(procAddress);

                }
                index++;
                iltEntry = pImportLookupTable[index];
            }
        }
        return true;
    }
    bool tlsCallbacks(unsigned char* baseAddress, const PIMAGE_NT_HEADERS pNTHeader) {
        IMAGE_DATA_DIRECTORY& tlsDir = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

        if (tlsDir.Size) {
            PIMAGE_TLS_DIRECTORY tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(baseAddress + tlsDir.VirtualAddress);

            PIMAGE_TLS_CALLBACK* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);

            if (!callbacks) return false;

            for (; *callbacks; ++callbacks) {
                (*callbacks)(reinterpret_cast<LPVOID>(baseAddress), DLL_PROCESS_ATTACH, nullptr);
            }
        }
        return true;
    }
    bool callEntry(unsigned char* baseAddress, const PIMAGE_NT_HEADERS pNTHeader) {
        using DLLEntry = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

        using EXEEntry = void(WINAPI*)(void);

        auto entryPoint{ baseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint };

        if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            DLLEntry dllEntry{ reinterpret_cast<DLLEntry>(entryPoint) };
            dllEntry(reinterpret_cast<HINSTANCE>(baseAddress), DLL_PROCESS_ATTACH, NULL);
        }
        else {
            EXEEntry exeEntry{ reinterpret_cast<EXEEntry>(entryPoint) };

            exeEntry();
        }
        return true;
    }
}

bool loadPE(unsigned char* peBuffer) {

    const PIMAGE_DOS_HEADER dosHeader{ reinterpret_cast<PIMAGE_DOS_HEADER>(peBuffer) };
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid PE provided\n";
        return false;
    }
    const PIMAGE_NT_HEADERS pNTHeader{ reinterpret_cast<PIMAGE_NT_HEADERS>(peBuffer + dosHeader->e_lfanew) };
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

    const uintptr_t sectionHeaderAddress{ reinterpret_cast<uintptr_t>(peBuffer + dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader) };

    LPVOID baseAddressAlloc{ VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

    if (baseAddressAlloc == NULL) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << '\n';
        return false;
    }
    unsigned char* baseAddress{ reinterpret_cast<unsigned char*>(baseAddressAlloc) };

    std::memcpy(baseAddressAlloc, peBuffer, pNTHeader->OptionalHeader.SizeOfHeaders);


    for (DWORD sectionIndex{ 0 }; sectionIndex < numberOfSections; ++sectionIndex) {
        PIMAGE_SECTION_HEADER sectionHeader{ reinterpret_cast<PIMAGE_SECTION_HEADER>(sectionHeaderAddress + (sectionIndex * sizeof(IMAGE_SECTION_HEADER))) };

        std::memcpy(reinterpret_cast<void*>(baseAddress + sectionHeader->VirtualAddress), peBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
        DWORD oldFlags{ 0 };

        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE || sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect(reinterpret_cast<void*>(baseAddress + sectionHeader->VirtualAddress), sectionHeader->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldFlags);
        }

    }

    if (!relocateImage(baseAddress, pNTHeader)) {
        std::cerr << "Image relocation failed\n";
        VirtualFree(baseAddress, 0, MEM_RELEASE);
        return false;
    }

    if (!resolveIAT(baseAddress, pNTHeader)) {
        std::cerr << "Resolving imports failed\n";
        VirtualFree(baseAddress, 0, MEM_RELEASE);
        return false;
    }

    if (!tlsCallbacks(baseAddress, pNTHeader)) {
        std::cerr << "TLS callbacks failed\n";
        VirtualFree(baseAddress, 0, MEM_RELEASE);
        return false;
    }


    if (!callEntry(baseAddress, pNTHeader)) {
        std::cerr << "Invoking entry point failed\n";
        VirtualFree(baseAddress, 0, MEM_RELEASE);
        return false;
    }

    return true;
}
