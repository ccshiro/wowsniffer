/*
 * DLL Injector, to inject the target program into wow's process.
 *
 * Copyright (C) 2014 shiro <shiro@worldofcorecraft.com>
 *
 * This file is part of wowsniffer, which is licensed under the MIT license.
 * See LICENSE for details.
 */

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
#include <psapi.h>

#include <iostream>
#include <sstream>
#include <csignal>

using namespace std;

bool extract_args(int argc, char* argv[]);
void usage(const char* name);
bool connect_pipe();
void read_loop();
void sigint_handler(int);

void find_sniffer_dll();

int pid = -1;

HMODULE sniffer_dll;
HANDLE proc;
FARPROC free_lib;
FARPROC close_pipe_addr;
HANDLE pipe;
bool read_loop_active;
bool closed_down = true;
bool dump_recv = true;
bool dump_send = true;

int main(int argc, char* argv[])
{
    if (!extract_args(argc, argv))
    {
        usage(argv[0]);
        return -1;
    }

    // NOTE We can rely on kernel32.dll being loaded into the same base-address
    // for all currently running processes (this would not hold true between
    // system restarts).
    FARPROC load_lib = GetProcAddress(GetModuleHandle(L"kernel32.dll"),
        "LoadLibraryW");
    free_lib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
    if (load_lib == NULL || free_lib == NULL)
    {
        cout << "Unable to find address of LoadLibraryW and FreeLibrary" << endl;
        return -1;
    }

    wchar_t dll_path[MAX_PATH];
    DWORD len = GetFullPathName(L"sniffer.dll", MAX_PATH, dll_path, NULL);
    if (len > MAX_PATH)
    {
        cout << "Could not construct full path to sniffer.dll; path would"
            " exceed MAX_PATH" << endl;
        return -1;
    }

    len *= sizeof(wchar_t);

    // NOTE: Unlike LOAD_LIBRARY_AS_IMAGE_RESOURCE, DONT_RESOLVE_DLL_REFERENCES,
    // will result in an actually loaded, but not initialized, module (allowing
    // us to invoke GetProcAddress, for example). For these shady reasons it
    // should be avoided; but for our case it works out okay.
    HMODULE sniffer_lib = LoadLibraryEx(dll_path, NULL,
        DONT_RESOLVE_DLL_REFERENCES);
    if (sniffer_lib == NULL)
    {
        cout << "Could not find sniffer.dll" << endl;
        return -1;
    }

    // Figure out the address of launch_pipe() and close_pipe()
    FARPROC launch_pipe_addr = GetProcAddress(sniffer_lib, "launch_pipe");
    close_pipe_addr = GetProcAddress(sniffer_lib, "close_pipe");
    if (launch_pipe_addr == 0 || close_pipe_addr == 0)
    {
        cout << "Could not find launch_pipe() export in sniffer.dll" << endl;
        cout << GetLastError() << endl;
        return -1;
    }

    // Subtract the address sniffer.dll is loaded at, to obtain the relative
    // address of launch_pipe() and close_pipe()
    launch_pipe_addr = (FARPROC)((size_t)launch_pipe_addr
        - (size_t)sniffer_lib);
    close_pipe_addr = (FARPROC)((size_t)close_pipe_addr
        - (size_t)sniffer_lib);

    FreeLibrary(sniffer_lib);

    proc = OpenProcess(
        SYNCHRONIZE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD
        | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, pid);
    if (proc == NULL)
    {
        usage(argv[0]);
        return -1;
    }

    // Write the full path of the DLL to the target process
    void* allocd_mem = VirtualAllocEx(proc, NULL, len, MEM_COMMIT,
        PAGE_READWRITE);
    if (allocd_mem == NULL)
    {
        cout << "VirtualAllocEx failed with error id: " << GetLastError()
            << endl;
        return -1;
    }

    if (WriteProcessMemory(proc, allocd_mem,
        (void*)dll_path, len, NULL) == 0)
    {
        cout << "WriteProcessMemory failed with error id: " << GetLastError()
            << endl;
        VirtualFreeEx(proc, allocd_mem, len, MEM_RELEASE);
        return -1;
    }

    // Call LoadLibraryW remotely
    HANDLE remote_thread = CreateRemoteThread(proc, NULL, 0,
        (LPTHREAD_START_ROUTINE)load_lib, allocd_mem, 0, NULL);
    if (remote_thread == NULL)
    {
        cout << "CreateRemoteThread failed with error id: " << GetLastError()
            << endl;
        VirtualFreeEx(proc, allocd_mem, len, MEM_RELEASE);
        return -1;
    }
    WaitForSingleObject(remote_thread, INFINITE);

    find_sniffer_dll();
    if (sniffer_dll == NULL)
        cout << "LoadLibraryW failed at the target. This could mean that"
            " sniffer.dll is not in the directory you ran this program from, or"
            " that WoW does not have the privileges needed to read from this"
            " directory." << endl;

    CloseHandle(remote_thread);
    VirtualFreeEx(proc, allocd_mem, len, MEM_RELEASE);

    if (sniffer_dll == NULL)
        return -1;

    // Invoke launch_pipe()
    launch_pipe_addr = FARPROC((size_t)sniffer_dll +
        (size_t)launch_pipe_addr);
    remote_thread = CreateRemoteThread(proc, NULL, 0,
        (LPTHREAD_START_ROUTINE)launch_pipe_addr, NULL, 0, NULL);
    if (remote_thread == NULL)
    {
        cout << "CreateRemoteThread failed with error id: " << GetLastError()
            << endl;
        return -1;
    }
    // NOTE: Don't wait for launch_pipe() to finish; it is blocking until we
    // connect to the pipe

    // Setup SIGINT handler
    signal(SIGINT, sigint_handler);

    cout << "Injected sniffer.dll successfully" << endl;

    if (!connect_pipe())
        return -1;

    cout << "Connected pipe successfully" << endl;

    closed_down = false;
    read_loop();
    
    while (!closed_down)
        Sleep(100);
}

bool extract_args(int argc, char* argv[])
{
    if (argc < 2)
        return false;

    for (int i = 1; i < argc; ++i)
    {
        const char* arg = argv[i];
        int len = (int)strlen(arg);

        if (len > 1 && arg[0] == '-')
        {
            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
                return false;
            else if (strcmp(arg, "--ignore-server") == 0)
                dump_recv = false;
            else if (strcmp(arg, "--ignore-client") == 0)
                dump_send = false;
            else
                return false;
        }
        else
        {
            stringstream ss;
            ss << arg;
            ss >> pid;
            if (!ss)
                return false;
        }
    }

    return true;
}

void usage(const char* name)
{
    cout << "usage: " << name << " [-h] [--ignore-server] [--ignore-client]"
        " pid\n\n";
    cout << "mandatory arguments:\n";
    cout << "  pid                process id of world of warcraft\n\n";
    cout << "optional arguments:\n";
    cout << "  -h, --help         show this help message and exit\n";
    cout << "  --ignore-server    do not dump received data\n";
    cout << "  --ignore-client    do not dump sent data" << endl;
}

bool connect_pipe()
{
    // Wait for pipe to become available
    while (true)
    {
        pipe = CreateFile(L"\\\\.\\pipe\\wowsniffer",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe != INVALID_HANDLE_VALUE)
            break;
        Sleep(500);
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (SetNamedPipeHandleState(pipe, &mode, NULL, NULL) == 0)
    {
        cout << "SetNamedPipeHandleState failed with error: " << GetLastError()
            << endl;
        return false;
    }

    // Let pipe know we're here
    char yolo_resp[5];
    char yolo_send[] = "YOLO";
    DWORD read = 0;
    if (TransactNamedPipe(pipe, yolo_send, 5, yolo_resp, 5, &read, NULL) == 0)
    {
        cout << "TransactNamedPipe failed with error: " << GetLastError()
            << endl;
        return false;
    }

    return true;
}

void read_loop()
{
    read_loop_active = true;

    char recv_buf[4096];
    while (read_loop_active)
    {
        DWORD read = 0;
        if (ReadFile(pipe, recv_buf, 4096, &read, NULL) == 0)
        {
            if (!read_loop_active)
                return;

            DWORD err = GetLastError();
            if (err != ERROR_MORE_DATA)
            {
                cout << "ReadFile error: " << err << endl;
                continue;
            }
        }

        string str(recv_buf);
        string::size_type t = str.find('\n');
        if (t == string::npos)
        {
            cout << recv_buf << endl;
            continue;
        }

        string type = str.substr(0, t);
        str.erase(0, t);

        if ((type == "==RECV" && dump_recv) ||
            (type == "==SEND" && dump_send))
            cout << str;
    }
}

void sigint_handler(int)
{
    read_loop_active = false;

    if (sniffer_dll && proc)
    {
        close_pipe_addr = FARPROC((size_t)sniffer_dll
            + (size_t)close_pipe_addr);
        HANDLE remote_thread = CreateRemoteThread(proc, NULL, 0,
            (LPTHREAD_START_ROUTINE)close_pipe_addr, NULL, 0, NULL);
        if (remote_thread != NULL)
        {
            WaitForSingleObject(remote_thread, INFINITE);
            cout << "Closed pipe successfully" << endl;
        }
        else
        {
            cout << "Unable to shutdown pipe correctly. You'll need to restart"
                " WoW. Sorry!" << endl;
        }

        remote_thread = CreateRemoteThread(proc, NULL, 0,
            (LPTHREAD_START_ROUTINE)free_lib, (LPVOID)sniffer_dll, 0, NULL);
        if (remote_thread != NULL)
        {
            WaitForSingleObject(remote_thread, INFINITE);
            cout << "Unloaded sniffer.dll successfully" << endl;
        }
        else
        {
            cout << "Unable to unload sniffer.dll. You'll need to restart WoW"
                ". Sorry!" << endl;
        }
    }

    if (proc)
        CloseHandle(proc);

    closed_down = true;
}

void find_sniffer_dll()
{
    // 256 modules ought to be enough for anybody
    HMODULE modules[256] = { NULL };
    DWORD req_size = 0;

    EnumProcessModules(proc, modules, 256 * sizeof(HMODULE), &req_size);

    for (int i = 0; i < 256 && sniffer_dll == NULL; ++i)
    {
        if (modules[i] == NULL)
            break;
        wchar_t name_buf[256];
        if (GetModuleBaseName(proc, modules[i], name_buf, 256) == 0)
            continue;
        if (CompareStringOrdinal(name_buf, -1, L"sniffer.dll", -1, FALSE)
            == CSTR_EQUAL)
            sniffer_dll = modules[i];
    }
}
