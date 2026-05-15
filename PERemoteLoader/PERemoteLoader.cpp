#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
#include "DllLoader.h"

int main(int argc, char* argv[]) {

    if (argc != 2) {
        std::cerr << "Usage:\n\t" << argv[0] << " <dll_path>\n";
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

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION victimProcInfo{ 0 };
    if (!CreateProcessW(L"D:\\workspace\\VSRepos\\Learning\\PELoader\\x64\\Release\\hello.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &victimProcInfo)) {
        std::cerr << "Victim process creation failed: " << GetLastError() << '\n';
        return EXIT_FAILURE;
    }
    DWORD pid;
    std::cout << "Enter Pid: ";
    //std::cin >> pid;
    HANDLE hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION , false, victimProcInfo.dwProcessId) };

    if (!hProcess) {
        std::cerr << "OpenProcessfailed: " << GetLastError() << '\n';
        return EXIT_FAILURE;
    }

    LoadDLL::DllLoader DllLoader;
    std::cout << "loading the DLL\n";
    if (!DllLoader.loadDLL(hProcess, bytes.data(), "sayHello")) {
        std::cerr << "Failed loading the DLL\n";
        return EXIT_FAILURE;
    }

    std::cout << "Successfully loaded the DLL\n";
    char c;
    //std::cin >> c;
    if (!TerminateProcess(hProcess, EXIT_SUCCESS)) {
        std::cerr << "Terminate process failed: " << GetLastError() << '\n';
    }
    return EXIT_SUCCESS;
}