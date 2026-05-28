#pragma once
#include <vector>
#include <optional>
namespace PELdr {
	class InProcLoader {
	public:
		bool loadPE(unsigned char* peBuffer);
		bool callEntry();
		bool callExport(std::string_view funcName);
	private:
		
		unsigned char* baseAddress{ nullptr };
		PIMAGE_NT_HEADERS pNTHeader{ nullptr };
	};
}
