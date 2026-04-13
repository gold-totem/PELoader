#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
namespace {

    /*TODO: add support for 32 bit PEs.
    * memory protection fixing
    * TLS call backs
    */


    /*
    struct PEInfo {
        DWORD       addressOfEntryPoint;
        ULONGLONG   imageBase;
        DWORD       sectionAlignment;
        DWORD       fileAlignment;
        DWORD       sizeOfImage;
        DWORD       sizeOfHeaders;
        DWORD       numberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY dataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    template <typename T>
    PEInfo getPEInfoData(T optionalHeader) {
        PEInfo info{};

        info.addressOfEntryPoint = optionalHeader.AddressOfEntryPoint;
        info.imageBase = optionalHeader.ImageBase;
        info.sectionAlignment = optionalHeader.SectionAlignment;
        info.fileAlignment = optionalHeader.FileAlignment;
        info.sizeOfImage = optionalHeader.SizeOfImage;
        info.sizeOfHeaders = optionalHeader.SizeOfHeaders;
        info.numberOfRvaAndSizes = optionalHeader.NumberOfRvaAndSizes;

        std::memcpy(
            info.dataDirectory,
            optionalHeader.DataDirectory,
            sizeof(IMAGE_DATA_DIRECTORY) * optionalHeader.NumberOfRvaAndSizes
        );

        return info;
    }

    PEInfo getPEInfo(PIMAGE_NT_HEADERS32 pNTHeader, bool isPE32) {
        if (isPE32) {
            return getPEInfoData(pNTHeader->OptionalHeader);
        }
        return getPEInfoData(reinterpret_cast<PIMAGE_NT_HEADERS64>(pNTHeader)->OptionalHeader);
    }
}
*/
}
bool loadPE(unsigned char* peBuffer, size_t sizeOfPEBuffer) {

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

    if (*bitType != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "Unsupported PE\n";
        return false;
    }



    WORD numberOfSections{ pNTHeader->FileHeader.NumberOfSections };

    const uintptr_t sectionHeaderAddress{ reinterpret_cast<uintptr_t>(peBuffer + dosHeader->e_lfanew  + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader)};
    
    LPVOID baseAddressAlloc{ VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

    if (baseAddressAlloc == NULL) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << '\n';
        return false;
    }
    unsigned char* baseAddress{ reinterpret_cast<unsigned char*>(baseAddressAlloc) };
    std::memcpy(baseAddressAlloc, peBuffer, pNTHeader->OptionalHeader.SizeOfHeaders);
    

    for (DWORD sectionIndex{ 0 }; sectionIndex < numberOfSections; ++sectionIndex) {
        PIMAGE_SECTION_HEADER sectionHeader{ reinterpret_cast<PIMAGE_SECTION_HEADER>( sectionHeaderAddress + (sectionIndex * sizeof(IMAGE_SECTION_HEADER))) };

        std::memcpy(reinterpret_cast<void*>(baseAddress + sectionHeader->VirtualAddress), peBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
    }
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
            uint16_t* relocEntry{ reinterpret_cast<uint16_t*>(reinterpret_cast<unsigned char*>(baseReloc) + sizeof(IMAGE_BASE_RELOCATION) + (i * sizeof(uint16_t)))};
            uint16_t relocType{ static_cast<uint16_t>(*relocEntry >> 12) }; // get upper 4 bits
            uint16_t relocRVA{ static_cast<uint16_t>(*relocEntry & 0xfff) }; // lower 12 bits give the rva
            unsigned char* relocValue{ baseAddress + baseReloc->VirtualAddress + relocRVA };

            switch (relocType) {
            case IMAGE_REL_BASED_LOW:
                std::cout << "IMAGE_REL_BASED_LOW\n";
                break;
            case IMAGE_REL_BASED_HIGH:
                std::cout << "IMAGE_REL_BASED_HIGH\n";
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                std::cout << "IMAGE_REL_BASED_HIGHLOW\n";
                break;
            case IMAGE_REL_BASED_DIR64:
                //std::cout << "IMAGE_REL_BASED_DIR64\n";
                *reinterpret_cast<uint64_t*>(relocValue) += delta;
                break;
            case IMAGE_REL_BASED_HIGHADJ:
                std::cout << "IMAGE_REL_BASED_HIGHADJ\n";
                i++;
                break;

            case IMAGE_REL_BASED_ABSOLUTE:
                //std::cout << "IMAGE_REL_BASED_ABSOLUTE\n";
                //nothing to do here
                break;
            default:
                std::cerr << "Invalid/Unsupported relocation type: "<<relocType << "\n";
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                return false;
                break;
            }
        }
    }

    auto importDirAddress{ baseAddress + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress };

    PIMAGE_IMPORT_DESCRIPTOR pImportDirectoryEntry{ reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importDirAddress) };
    PIMAGE_THUNK_DATA importAddressTable{ reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->FirstThunk) };

    for (; pImportDirectoryEntry->OriginalFirstThunk;  pImportDirectoryEntry++) {

        char* dllName = reinterpret_cast<char*>(baseAddress + pImportDirectoryEntry->Name);

        HMODULE hDll{ LoadLibraryA(dllName) };

        if (!hDll) {
            std::cerr << "Failed to load library: " << dllName << " : " << GetLastError();
            VirtualFree(baseAddress, 0, MEM_RELEASE);
            return false;
        }
        PIMAGE_THUNK_DATA pImportLookupTable = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pImportAddressTable{ reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + pImportDirectoryEntry->FirstThunk) };
        int index = 0;
        auto iltEntry{ pImportLookupTable[index] };
        while (iltEntry.u1.AddressOfData) {
            if (IMAGE_ORDINAL_FLAG64 & iltEntry.u1.Ordinal) {
                char* ordinal{ reinterpret_cast<char*>(IMAGE_ORDINAL(iltEntry.u1.Ordinal)) };
                pImportAddressTable[index].u1.Function = reinterpret_cast<ULONGLONG>(GetProcAddress(hDll, ordinal)); //TODO: check errors
            }
            else {  
                char* funcName{ reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(baseAddress + iltEntry.u1.AddressOfData)->Name };
                pImportAddressTable[index].u1.Function = reinterpret_cast<ULONGLONG>(GetProcAddress(hDll, funcName));

            }
            index++;
            iltEntry = pImportLookupTable[index];
        }
    }
    

    using DLLEntry = BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID);

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
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage:\n\t" << argv[0] << " <pe_path>\n";
        return EXIT_FAILURE;
    }
    std::ifstream file(argv[1], std::ios::binary);

    if (!file) {
        std::cerr << "Failed to open file\n";
        return EXIT_FAILURE;
    }

    size_t fileSize = std::filesystem::file_size(argv[1]);
    std::vector<unsigned char> bytes(fileSize);

    file.read(reinterpret_cast<char*>(bytes.data()), fileSize);

    if (!file) {
        std::cerr << "Failed to read file\n";
        return EXIT_FAILURE;
    }

    //uintptr_t entryPoint{ 0 };

    if (!loadPE(bytes.data(), bytes.size())) {
        std::cerr << "Failed loading the PE\n";
        return EXIT_FAILURE;
    }
    std::cout << "Successfully loaded the PE\nPress Enter to continue:";
    char c;
    std::cin >> c;
}