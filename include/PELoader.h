#pragma once
#include <vector>
#include <optional>
#include <Windows.h>
namespace PELdr {
	class PELoader {
	public:
		bool loadPE(HANDLE hProc, unsigned char* peBuffer);
		bool callEntry();
		bool callExport(std::string_view funcName);
	private:

		unsigned char* localBuffer{ nullptr };
		HANDLE hProc{ nullptr };
		unsigned char* baseAddress{ nullptr };
		PIMAGE_NT_HEADERS pNTHeader{ nullptr };
		uintptr_t delta{ 0 };
	};
}
