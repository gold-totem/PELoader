#pragma once
#include <string>
#include <Windows.h>
namespace LoadDLL {
	class DllLoader {
	public:
		bool loadDLL(HANDLE inpProc, unsigned char* peBuffer, std::string_view functionName);
	};
}