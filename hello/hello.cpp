#include <windows.h>
#include <iostream>

int main()
{
    unsigned long long i = 0;

    std::cout << "PID: " << GetCurrentProcessId() << '\n';
    while (true) {
        
        std::cout << "Hello: " << i << "\n";
        Sleep(10000);
        ++i;
    }
   
}