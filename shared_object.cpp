/*
 * Sniffer, the module to be injected into WoW to sniff the network data.
 *
 * Copyright (C) 2014 shiro <shiro@worldofcorecraft.com>
 *
 * This file is part of wowsniffer, which is licensed under the MIT license.
 * See LICENSE for details.
 */

// NOTE: WoW only runs on x86 and x64
#if defined(_M_X64) || defined(__amd64__)
    #define BUILD_64_BIT
#else
    #define BUILD_32_BIT
#endif

#define SA_CAT_INT(a, b) a ## b
#define SA_CAT(a, b) SA_CAT_INT(a, b)
#define STATIC_ASSERT(cond) typedef int SA_CAT(sahack_, __LINE__)[cond ? 1 : -1]
STATIC_ASSERT(sizeof(int) == 4);

#ifndef UNICODE
    #define UNICODE
#endif
#ifndef _UNICODE
    #define _UNICODE
#endif
#include <windows.h>

#include <sstream>
#include <string>

#include "MinHook.h"

#include "pattern_finder.h"

#define DLL_EXPORT __declspec(dllexport)

using namespace std;

HANDLE pipe = 0;

// send message over pipe
void send_msg(const std::string& msg);
void implement_hooks();

struct packet_data
{
    void*           vtable;
    void*           data;
    char            unk[8];
    unsigned int    size;
    char            unk2[4];
};

// TODO: Seems to be one extra parameter for recv in 64-bit WoW. This seemed
// strange to me, but I did not invest the time in verifying it. Need to check
// it.

#ifdef BUILD_32_BIT
// NOTE: __thiscall receives the this pointer through ecx, __fastcall passes
// arg1 through ecx and arg2 through edx. We abuse this property of __fastcall
// to hook the recv and send functions, which use the __thiscall convention.

typedef void (__thiscall *recv_func_t)(void*, void*, packet_data&, void*);
typedef void (__thiscall *send_func_t)(void*, packet_data&, void*);

recv_func_t real_recv;
send_func_t real_send;

void __fastcall hookd_recv(void* this_ptr, size_t /*ignored*/, void* unk,
    packet_data& data, void* unk2);
void __fastcall hookd_send(void* this_ptr, size_t /*ignored*/,
    packet_data& data, void* unk);
#else
// NOTE: Microsoft x64 only defines one calling convention, so we need not
// resort to trickery with __thiscall and __fastcall, as we do for x86

typedef void (*recv_func_t)(void*, void*, packet_data&, void*, void*);
typedef void (*send_func_t)(void*, packet_data&, void*);

recv_func_t real_recv;
send_func_t real_send;

void hookd_recv(void* this_ptr, void* unk,
    packet_data& data, void* unk2, void* unk3);
void hookd_send(void* this_ptr,
    packet_data& data, void* unk);
#endif

BOOL APIENTRY DllMain(HMODULE mod, DWORD call_reason, LPVOID lpReserved)
{
    return TRUE;
}

extern"C" DLL_EXPORT void launch_pipe()
{
    pipe = CreateNamedPipe(L"\\\\.\\pipe\\wowsniffer",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096 * sizeof(wchar_t), 5 * sizeof(wchar_t), 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE)
    {
        stringstream ss;
        ss << "CreateNamedPipe failed with error: " << GetLastError();
        MessageBoxA(0, ss.str().c_str(), 0, 0);
        pipe = 0;
        return;
    }

    if (ConnectNamedPipe(pipe, NULL) == 0)
    {
        stringstream ss;
        ss << "ConnectNamedPipe failed with error: " << GetLastError();
        MessageBoxA(0, ss.str().c_str(), 0, 0);
        pipe = 0;
        return;
    }

    // Wait for the client sending "YOLO", respond with the same
    // This signifies a pipe set-up successfully
    char yolo_buf[5] = {0};
    DWORD read = 0;
    if (ReadFile(pipe, yolo_buf, 5, &read, NULL) == 0)
    {
        stringstream ss;
        ss << "ReadFile failed with error: " << GetLastError();
        MessageBoxA(0, ss.str().c_str(), 0, 0);
        DisconnectNamedPipe(pipe);
        pipe = 0;
        return;
    }

    if (strcmp(yolo_buf, "YOLO") != 0)
    {
        MessageBox(0, L"Client did not send correct pipe message", 0, 0);
        DisconnectNamedPipe(pipe);
        pipe = 0;
        return;
    }

    DWORD written = 0;
    if (WriteFile(pipe, yolo_buf, 5, &written, NULL) == 0)
    {
        stringstream ss;
        ss << "WriteFile failed with error: " << GetLastError();
        MessageBoxA(0, ss.str().c_str(), 0, 0);
        DisconnectNamedPipe(pipe);
        pipe = 0;
        return;
    }

    implement_hooks();
}

extern"C" DLL_EXPORT void close_pipe()
{
    if (pipe)
    {
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        pipe = 0;
    }

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

void send_msg(const std::string& msg)
{
    if (!pipe)
        return;

    DWORD written = 0;
    WriteFile(pipe, msg.c_str(), DWORD(msg.size() + 1), &written, NULL);
}

void* get_recv();
void* get_send();

void implement_hooks()
{
    if (MH_Initialize() != MH_OK)
        return;

    void* recv = get_recv();
    void* send = get_send();

    if (!recv || !send)
        return;

    // Hook recv
    if (MH_CreateHook(recv, hookd_recv, reinterpret_cast<void**>(&real_recv))
        != MH_OK)
        return;
    if (MH_EnableHook(recv) != MH_OK)
        return;
    
    // Hook send
    if (MH_CreateHook(send, hookd_send, reinterpret_cast<void**>(&real_send))
        != MH_OK)
        return;
    if (MH_EnableHook(send) != MH_OK)
        return;
}

// XXX: make sure pattern doesnt include size of stack, which is probably not patch resistant

void* get_recv()
{
#ifdef BUILD_32_BIT
    unsigned char byte_str[] =
    "\x55\x8B\xEC\xFF\x05\x00\x00\x00\x00\x53\x8B\x5D\x0C\x56\x57\x8D";
    bool gaps[16] = { false };
    gaps[5] = true;
    gaps[6] = true;
    gaps[7] = true;
    gaps[8] = true;
    int len = 16;
#else
    unsigned char byte_str[] =
    "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57"
    "\x48\x83\xEC\x00\xFF\x05\x00\x00\x00\x00\x8B\xEA\x48\x8B\xF1\x48";
    bool gaps[32] = { false };
    gaps[19] = true;
    gaps[22] = true;
    gaps[23] = true;
    gaps[24] = true;
    gaps[25] = true;
    int len = 32;
#endif

    void* func = find_pattern(byte_str, len, gaps);
    if (func == NULL)
    {
        send_msg("Unable to find the receive function. This probably means your"
            " wowsniffer is out of date.");
    }

    return func;
}

void* get_send()
{
#ifdef BUILD_32_BIT
    unsigned char byte_str[] =
    "\x55\x8B\xEC\x83\xEC\x10\x53\x56\x8B\xF1\x8D\x8E\x34\x05\x00\x00";
    bool gaps[16] = { false };
    int len = 16;
#else
    unsigned char byte_str[] =
    "\x48\x89\x5C\x24\x10\x48\x89\x6C\x24\x18\x56\x57\x41\x54\x41\x55"
    "\x41\x56\x48\x83\xEC\x00\x48\x8D\xB1\x38\x05\x00\x00\x48\x8B\xD9";
    bool gaps[32] = { false };
    gaps[21] = true;
    int len = 32;
#endif

    void* func = find_pattern(byte_str, len, gaps);
    if (func == NULL)
    {
        send_msg("Unable to find the send function. This probably means your"
            " wowsniffer is out of date.");
    }

    return func;
}

string format_data(void* data, unsigned int len);

#ifdef BUILD_32_BIT
void __fastcall hookd_recv(void* this_ptr, size_t /*ignored*/, void* unk,
    packet_data& data, void* unk2)
#else
void hookd_recv(void* this_ptr, void* unk,
    packet_data& data, void* unk2, void* unk3)
#endif
{
    // Dump data to pipe
    stringstream ss;
    ss << "==RECV\n";
    ss << "(SERVER) ";
    ss << format_data(data.data, data.size);
    ss << "\n";
    send_msg(ss.str());

    // TODO: Read todo up top
#ifdef BUILD_32_BIT
    real_recv(this_ptr, unk, data, unk2);
#else
    real_recv(this_ptr, unk, data, unk2, unk3);
#endif
}

#ifdef BUILD_32_BIT
void __fastcall hookd_send(void* this_ptr, size_t /*ignored*/,
    packet_data& data, void* unk)
#else
void hookd_send(void* this_ptr,
    packet_data& data, void* unk)
#endif
{
    // Dump data to pipe
    stringstream ss;
    ss << "==SEND\n";
    ss << "(CLIENT) ";
    ss << format_data(data.data, data.size);
    ss << "\n";
    send_msg(ss.str());

    real_send(this_ptr, data, unk);
}

string format_data(void* data, unsigned int len)
{
    stringstream ss;

    unsigned int opcode = *(unsigned int*)data;
    ss << "OPCODE: " << hex << uppercase << opcode
        << " SIZE: " << len-4 << "\n";

    unsigned int lines = (len-4)/16;
    if ((len-4) % 16 != 0)
        ++lines;

    for (unsigned int n = 0; n < lines; ++n)
    {
        ss << "    ";
        for (int i = 0; i < 16; ++i)
        {
            unsigned int offset = 4 + n * 16 + i;
            if (offset >= len)
                break;

            char buf[3];
            sprintf(buf, "%02X", ((unsigned char*)data)[offset]);
            ss << buf << " ";
        }
        ss << "\n";
    }

    return ss.str();
}
