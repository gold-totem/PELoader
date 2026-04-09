#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
namespace {

    //TODO: add support for 32 bit PEs.
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
bool loadPE(unsigned char* peBuffer, size_t sizeOfPEBuffer, uintptr_t entryPoint) {

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
    
    const LPVOID baseAddress{ VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

    if (baseAddress == NULL) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << '\n';
        return false;
    }

    std::memcpy(baseAddress, peBuffer, pNTHeader->OptionalHeader.SizeOfHeaders);
    

    for (DWORD sectionIndex{ 0 }; sectionIndex < numberOfSections; ++sectionIndex) {
        PIMAGE_SECTION_HEADER sectionHeader{ reinterpret_cast<PIMAGE_SECTION_HEADER>( sectionHeaderAddress + (sectionIndex * sizeof(IMAGE_SECTION_HEADER))) };

        std::memcpy(reinterpret_cast<unsigned char*>(baseAddress) + sectionHeader->VirtualAddress, peBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
    }
    const IMAGE_DATA_DIRECTORY& relocDataDir{ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] };


    uintptr_t delta{ reinterpret_cast<uintptr_t>(baseAddress) - pNTHeader->OptionalHeader.ImageBase };

    
    DWORD currentSize{ 0 };
    while (currentSize < relocDataDir.Size) {

        PIMAGE_BASE_RELOCATION baseReloc{ reinterpret_cast<PIMAGE_BASE_RELOCATION>( (reinterpret_cast<unsigned char*>(baseAddress)) + (relocDataDir.VirtualAddress) + currentSize ) };
        currentSize += baseReloc->SizeOfBlock;

        DWORD numberOfRecords{ baseReloc->SizeOfBlock };
        numberOfRecords -= sizeof(IMAGE_BASE_RELOCATION);
        numberOfRecords /= sizeof(uint16_t);

        for (DWORD i{ 0 }; i < numberOfRecords; i++) {
            uint16_t* relocEntry{ reinterpret_cast<uint16_t*>(reinterpret_cast<unsigned char*>(baseReloc) + sizeof(IMAGE_BASE_RELOCATION) + (i * sizeof(uint16_t)))};
            uint16_t relocType{ static_cast<uint16_t>(*relocEntry >> 12) }; // get upper 4 bits
            uint16_t relocRVA{ static_cast<uint16_t>(*relocEntry & 0xfff) }; // lower 12 bits give the rva
            unsigned char* relocValue{ reinterpret_cast<unsigned char*>(baseAddress) + relocRVA };

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
                *reinterpret_cast<uint64_t*>(relocValue) += delta;
                break;
            case IMAGE_REL_BASED_HIGHADJ:
                std::cout << "IMAGE_REL_BASED_HIGHADJ\n";
                i++;
                break;

            default:
                std::cerr << "Invalid/Unsupported relocation type\n";
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                return false;
                break;
            }
        }
    }

    const IMAGE_IMPORT_DESCRIPTOR& pImportDirectoryEntry{ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress };
    IMAGE_IMPORT_DESCRIPTOR* pImportDirectoryEntry = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(importDirectoryTable);
    while (pImportDirectoryEntry->Characteristics) {
        struct ImportTable importTablestruct;

        importTablestruct.dllName = reinterpret_cast<char*>(base + pImportDirectoryEntry->Name);
        importTablestruct.iatOffset = pImportDirectoryEntry->FirstThunk;

        if (peType == PEType::PE64) {
            uint64_t* pImportLookupTable = reinterpret_cast<uint64_t*>(base + pImportDirectoryEntry->Characteristics);
            int index = 0;
            uint64_t iltEntry{ pImportLookupTable[index] };
            while (iltEntry != 0) {
                if (!(IMAGE_ORDINAL_FLAG64 & iltEntry)) {
                    importTablestruct.functionData.emplace_back(reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + iltEntry));
                }
                index++;
                iltEntry = pImportLookupTable[index];
            }

        }
        else {
            uint32_t* pImportLookupTable = reinterpret_cast<uint32_t*>(base + pImportDirectoryEntry->Characteristics);
            int index = 0;
            uint32_t iltEntry{ pImportLookupTable[index] };
            while (iltEntry != 0) {
                if (!(IMAGE_ORDINAL_FLAG64 & iltEntry)) {
                    importTablestruct.functionData.emplace_back(reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + iltEntry));
                }
                index++;
                iltEntry = pImportLookupTable[index];
            }
        }
        pImportDirectoryEntry++;
        importTable.emplace_back(importTablestruct);
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

    uintptr_t entryPoint{ 0 };

    if (!loadPE(bytes.data(), bytes.size(), entryPoint)) {
        std::cerr << "Failed loading the PE\n";
        return EXIT_FAILURE;
    }

    std::cout << "Successfully loaded the PE\n";
}