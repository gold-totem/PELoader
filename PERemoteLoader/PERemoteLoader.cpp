#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
#include "PELoader.h"
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

    if (!CreateProcessW(L"C:\\Windows\\System32\\SndVol.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &victimProcInfo)) {
        std::cerr << "Victim process creation failed: " << GetLastError() << '\n';
        return EXIT_FAILURE;
    }
    CloseHandle(victimProcInfo.hProcess);
    CloseHandle(victimProcInfo.hThread);
    HANDLE hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_TERMINATE , false, victimProcInfo.dwProcessId) };

    if (!hProcess) {
        std::cerr << "OpenProcessfailed: " << GetLastError() << '\n';
        return EXIT_FAILURE;
    }

    PELdr::PELoader DllLoader;
    if (!DllLoader.loadPE(hProcess, bytes.data())) {
        std::cerr << "Failed loading the DLL\n";
    }

    if (!DllLoader.callEntry()) {
        std::cerr << "Failed calling the entry\n";
    }
    
    
    if (!DllLoader.callExport("sayHello")) {
        std::cerr << "Failed calling the export\n";
    }

    if (!TerminateProcess(hProcess, EXIT_SUCCESS)) {
        std::cerr << "Terminate process failed: " << GetLastError() << '\n';
    }

    return EXIT_SUCCESS;
}