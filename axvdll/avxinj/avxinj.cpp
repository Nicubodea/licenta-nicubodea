// avxinj.cpp : Defines the entry point for the console application.
//

#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[])
{
    HMODULE hKBase;
    HANDLE hProc;
    hKBase = GetModuleHandleA("kernelbase.dll");
    PBYTE pLoad;
    pLoad = (PBYTE)GetProcAddress(hKBase, "LoadLibraryA");
    LPVOID addr;
    DWORD pid = atoi(argv[1]);

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProc == NULL)
    {
        printf("fail open process %d", GetLastError());
        return 1;
    }

    addr = VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (addr == NULL)
    {
        printf("fail alloc  %d", GetLastError());
        return 2;
    }
    CHAR* buff = "C:\\Users\\nbodea\\Documents\\Training\\Git\\axvdll\\x64\\Debug\\axvdll.dll";
    SIZE_T ret; 

    if(!WriteProcessMemory(hProc, addr, buff, strlen(buff), &ret))
    {
        printf("fail wpm %d", GetLastError());
        return 3;
    }

    HANDLE tid = CreateRemoteThreadEx(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoad, addr, 0, NULL, NULL);

    if (tid == INVALID_HANDLE_VALUE)
    {
        printf("fail create thread %d", GetLastError());
        return 3;
    }

    return 0;
}

