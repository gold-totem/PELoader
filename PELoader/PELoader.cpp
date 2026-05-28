#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
#include "InProcLoader.h"

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
    PELdr::InProcLoader peLoader;

    if (!peLoader.loadPE(bytes.data())) {
        std::cerr << "Failed loading the PE\n";
        return EXIT_FAILURE;
    }

    if (!peLoader.callEntry()) {
        std::cerr << "Failed executing the PE\n";
        return EXIT_FAILURE;
    }

    if (!peLoader.callExport("sayHello")) {
        std::cerr << "Failed calling function\n";
    }

    std::cout << "Successfully loaded the PE\n";
    return EXIT_SUCCESS;
}