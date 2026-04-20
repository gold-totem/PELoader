#include <Windows.h>
#include <iostream>
int main() {

	if (!MessageBox(NULL, L"The executable has been loaded successfully.", L"Success", MB_OK)) {
		std::cerr << "Error using MessageBox: " << GetLastError() << '\n';
	}
}