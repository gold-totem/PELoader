#pragma once
namespace PELdr {
	class PELoader {
	public:
		bool loadPE(HANDLE hProc, unsigned char* peBuffer);
		bool callEntry();

		~PELoader() {
			if (baseAddress) {
				VirtualFree(baseAddress, 0, MEM_RELEASE);
			}
		}
	private:
		HANDLE hProc{ nullptr };
		unsigned char* baseAddress{ nullptr };
		PIMAGE_NT_HEADERS pNTHeader{ nullptr };
	};
}
