#pragma once
#include <vector>
namespace PELdr {
	class PELoader {
	public:
		bool loadPE(HANDLE hProc, unsigned char* peBuffer);
		bool callEntry();

		~PELoader() {
			if (baseAddress) {
				//VirtualFree(baseAddress, 0, MEM_RELEASE);
			}
		}
	//private:
		//std::vector<unsigned char> buffer;
		PVOID buffer{ nullptr };
		HANDLE hProc{ nullptr };
		unsigned char* baseAddress{ nullptr };
		PIMAGE_NT_HEADERS pNTHeader{ nullptr };
		uintptr_t delta{ 0 };
	};
}
