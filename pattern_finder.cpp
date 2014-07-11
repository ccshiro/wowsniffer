#include "pattern_finder.h"

// NOTE: WoW only runs on x86 and x64
#if defined(_M_X64) || defined(__amd64__)
    #define BUILD_64_BIT
#else
    #define BUILD_32_BIT
#endif

#ifndef UNICODE
    #define UNICODE
#endif
#ifndef _UNICODE
    #define _UNICODE
#endif
#include <windows.h>
#include <psapi.h>

#include <sstream>

using namespace std;

static int next_byte();

size_t start_addr;
size_t curr_addr;
size_t end_addr;

void* find_pattern(const unsigned char* bytestr, int len, const bool* gaps)
{
    int n = 0, c;

    curr_addr = start_addr;

    while ((c = next_byte()) != -1 && n < len)
    {
        if (gaps[n] == true || bytestr[n] == (unsigned char)c)
            ++n;
        else
            n = 0;
    }

    if (n == len)
        return (void*)(curr_addr - (len+1));

    return NULL;
}

static int next_byte()
{
    if (start_addr == 0)
    {
#ifdef BUILD_32_BIT
        HMODULE module = GetModuleHandle(L"WoW.exe");
#else
        HMODULE module = GetModuleHandle(L"WoW-64.exe");
#endif
        if (module == NULL)
        {
            stringstream ss;
            ss << "GetModuleHandle failed with error: " << GetLastError();
            MessageBoxA(0, ss.str().c_str(), 0, 0);
            return -1;
        }

        MODULEINFO module_info;
        if (GetModuleInformation(GetCurrentProcess(), module, &module_info,
            sizeof(MODULEINFO)) == 0)
        {
            stringstream ss;
            ss << "GetModuleInformation failed with error: " << GetLastError();
            MessageBoxA(0, ss.str().c_str(), 0, 0);
            return -1;
        }

        // FIXME: end_addr will be further off than the end of the actual code
        // space of the WoW module
        start_addr = curr_addr = (size_t)module_info.lpBaseOfDll;
        end_addr = start_addr + (size_t)module_info.SizeOfImage;
    }

    if (curr_addr >= end_addr)
        return -1;

    unsigned char* ptr = (unsigned char*)curr_addr++;
    return *ptr;
}
