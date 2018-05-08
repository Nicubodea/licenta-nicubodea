// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include <stdio.h>
#include "Zydis/Zydis.h"
#include "exports.h"
#include "hooker.h"
#include <vector>
#include <tlhelp32.h>
#include "communication.h"

typedef struct _HOOK_API_DESCRIPTOR
{
    CHAR FunctionName[MAX_PATH];
    DWORD Module;
    BYTE Ordinal;
} HOOK_API_DESCRIPTOR, *PHOOK_API_DESCRIPTOR;

#define LIB_KERNEL32 0
#define LIB_KERNELBASE 1
#define LIB_NTDLL 2

HOOK_API_DESCRIPTOR gApiDescriptors[] = {
    { "GetStartupInfoA", LIB_KERNEL32, 0 },
    { "IsBadReadPtr", LIB_KERNEL32, 1 },
    { "IsBadWritePtr", LIB_KERNEL32, 2 },
    { "IsBadStringPtrW", LIB_KERNEL32, 3 },
    { "GlobalLock", LIB_KERNEL32, 4 },
    { "GlobalReAlloc", LIB_KERNEL32, 5 },
    { "GlobalUnlock", LIB_KERNEL32, 6 },
    { "GlobalSize", LIB_KERNEL32, 7 },
    { "GetLongPathNameW", LIB_KERNEL32, 8 },
    { "CreateToolhelp32Snapshot", LIB_KERNEL32, 9 },
    { "Thread32First", LIB_KERNEL32, 10 },
    { "Thread32Next", LIB_KERNEL32, 11 },
    { "Module32FirstW", LIB_KERNEL32, 12 },
    { "Module32NextW", LIB_KERNEL32, 13 },
    { "GetShortPathNameA", LIB_KERNEL32, 15 },
    { "GetShortPathNameW", LIB_KERNEL32, 16 },
    { "GetPrivateProfileStringA", LIB_KERNEL32, 17 },
    { "GlobalHandle", LIB_KERNEL32, 18 },
    { "GetPrivateProfileStringW", LIB_KERNEL32, 19 },
    { "GetProfileStringW", LIB_KERNEL32, 20 },
    { "GlobalMemoryStatus", LIB_KERNEL32, 21 },
    { "LocalSize", LIB_KERNEL32, 22 },
    { "GetPrivateProfileSectionW", LIB_KERNEL32, 23 },
    { "GetPrivateProfileIntW", LIB_KERNEL32, 24 },
    { "IsBadStringPtrA", LIB_KERNEL32, 25 },
    { "Process32First", LIB_KERNEL32, 26 },
    { "Process32Next", LIB_KERNEL32, 27 },
    { "GetProfileStringA", LIB_KERNEL32, 28 },
    { "GlobalFlags", LIB_KERNEL32, 29 },
    { "WinExec", LIB_KERNEL32, 30 },
    { "GetPrivateProfileIntA", LIB_KERNEL32, 31 },
    { "WritePrivateProfileStringA", LIB_KERNEL32, 32 },
    { "CopyFileA", LIB_KERNEL32, 33 },
    { "GetLogicalDriveStringsA", LIB_KERNEL32, 34 },
    { "GetProcAddress", LIB_KERNELBASE, 35 },
    { "LocalAlloc", LIB_KERNELBASE, 36 },
    { "GetFileType", LIB_KERNELBASE, 37 },
    { "GetEnvironmentStringsW", LIB_KERNELBASE, 38 },
    { "VirtualQuery", LIB_KERNELBASE, 39 },
    { "GetModuleFileNameW", LIB_KERNELBASE, 40 },
    { "GetProcessVersion", LIB_KERNELBASE, 41 },
    { "LocalFree", LIB_KERNELBASE, 42 },
    { "VirtualAlloc", LIB_KERNELBASE, 43 },
    { "VirtualFree", LIB_KERNELBASE, 44 },
    { "GetModuleFileNameA", LIB_KERNELBASE, 45 },
    { "LoadLibraryExA", LIB_KERNELBASE, 46 },
    { "CreateFileA", LIB_KERNELBASE, 47 },
    { "LoadLibraryA", LIB_KERNELBASE, 48 },
    { "FreeLibrary", LIB_KERNELBASE, 49 },
    { "GetModuleHandleA", LIB_KERNELBASE, 50 },
    { "RegCreateKeyExA", LIB_KERNELBASE, 51 },
    { "GetModuleHandleW", LIB_KERNELBASE, 52 },
    { "ReadFile", LIB_KERNELBASE, 53 },
    { "WriteFile", LIB_KERNELBASE, 54 },
    { "WSAStartup", LIB_KERNELBASE, 55 },
    { "RegCreateKeyExW", LIB_KERNELBASE, 56 },
    { "GlobalAlloc", LIB_KERNELBASE, 57 },
    { "GlobalFree", LIB_KERNELBASE, 58 },
    { "GetFileAttributesW", LIB_KERNELBASE, 59 },
    { "GetEnvironmentVariableW", LIB_KERNELBASE, 60 },
    { "GetFullPathNameW", LIB_KERNELBASE, 61 },
    { "LoadLibraryExW", LIB_KERNELBASE, 62 },
    { "CreateProcessW", LIB_KERNELBASE, 63 },
    { "GetLongPathNameW", LIB_KERNELBASE, 64 },
    { "MulDiv", LIB_KERNELBASE, 65 },
    { "SetThreadPriority", LIB_KERNELBASE, 66 },
    { "HeapCreate", LIB_KERNELBASE, 67 },
    { "CreateThread", LIB_KERNELBASE, 68 },
    { "SetEnvironmentVariableA", LIB_KERNELBASE, 69 },
    { "SetCurrentDirectoryA", LIB_KERNELBASE, 70 },
    { "GetFileAttributesA", LIB_KERNELBASE, 71 },
    { "ResumeThread", LIB_KERNELBASE, 72 },
    { "GetFileSize", LIB_KERNELBASE, 73 },
    { "CreateFileW", LIB_KERNELBASE, 74 },
    { "GetDriveTypeA", LIB_KERNELBASE, 75 },
    { "GetShortPathNameW", LIB_KERNELBASE, 76 },
    { "GetTempFileNameA", LIB_KERNELBASE, 77 },
    { "SetEndOfFile", LIB_KERNELBASE, 78 },
    { "SetFilePointer", LIB_KERNELBASE, 79 },
    { "GetEnvironmentVariableA", LIB_KERNELBASE, 80 },
    { "DeleteFileA", LIB_KERNELBASE, 81 },
    { "GetDriveTypeW", LIB_KERNELBASE, 82 },
    { "GetThreadPriority", LIB_KERNELBASE, 83 },
    { "OpenProcess", LIB_KERNELBASE, 84 },
    { "SearchPathW", LIB_KERNELBASE, 85 },
    { "GetFullPathNameA", LIB_KERNELBASE, 86 },
    { "FindNextFileA", LIB_KERNELBASE, 87 },
    { "FindClose", LIB_KERNELBASE, 88 },
    { "GlobalMemoryStatusEx", LIB_KERNELBASE, 89 },
    { "LocalLock", LIB_KERNELBASE, 90 },
    { "LocalUnlock", LIB_KERNELBASE, 91 },
    { "HeapDestroy", LIB_KERNELBASE, 92 },
    { "GetCurrentDirectoryW", LIB_KERNELBASE, 93 },
    { "SetCurrentDirectoryW", LIB_KERNELBASE, 94 },
    { "GetFileAttributesExA", LIB_KERNELBASE, 95 },
    { "FindFirstChangeNotificationW", LIB_KERNELBASE, 96 },
    { "LocalReAlloc", LIB_KERNELBASE, 97 },
    { "GetFileAttributesExW", LIB_KERNELBASE, 98 },
    { "RegEnumValueA", LIB_KERNELBASE, 99 },
    { "ntohs", LIB_KERNELBASE, 100 },
    { "FindFirstFileW", LIB_KERNELBASE, 101 },
    { "VirtualProtect", LIB_KERNELBASE, 102 },
    { "GetCurrentDirectoryA", LIB_KERNELBASE, 103 },
    { "GetStartupInfoW", LIB_KERNELBASE, 104 },
    { "GetModuleHandleExW", LIB_KERNELBASE, 105 },
    { "GetExitCodeThread", LIB_KERNELBASE, 106 },
    { "GetTempPathA", LIB_KERNELBASE, 107 },
    { "SetFileAttributesA", LIB_KERNELBASE, 108 },
    { "GetDiskFreeSpaceA", LIB_KERNELBASE, 109 },
    { "GetFileInformationByHandle", LIB_KERNELBASE, 110 },
    { "FindFirstFileA", LIB_KERNELBASE, 111 },
    { "CreateProcessA", LIB_KERNELBASE, 112 },
    { "CreateDirectoryA", LIB_KERNELBASE, 113 },
    { "SearchPathA", LIB_KERNELBASE, 114 },
    { "GetTempPathW", LIB_KERNELBASE, 115 },
    { "UnlockFile", LIB_KERNELBASE, 116 },
    { "SuspendThread", LIB_KERNELBASE, 117 },
    { "CreateFiber", LIB_KERNELBASE, 118 },
    { "SwitchToFiber", LIB_KERNELBASE, 119 },
    { "DeleteFileW", LIB_KERNELBASE, 120 },
    { "GetProcessTimes", LIB_KERNELBASE, 121 },
    { "GetExitCodeProcess", LIB_KERNELBASE, 122 },
    { "QueryDosDeviceW", LIB_KERNELBASE, 123 },
    { "NtOpenKey", LIB_NTDLL, 124 },
    { "NtQueryValueKey", LIB_NTDLL, 125 },
    { "NtEnumerateKey", LIB_NTDLL, 126 },
    { "NtQueryKey", LIB_NTDLL, 127 },
    { "NtSetValueKey", LIB_NTDLL, 128 },
};


ZydisDecoder gZydisDecoder;
std::vector<PHOOK_DATA> gHooks;
std::vector<PEXPORT> gExports;
SOCKET gSocket;

DWORD pid;

BOOLEAN gHooksEstablished;
extern "C" void EmuBuffer();

VOID
AvxDllEstablishHooks(
    VOID
);

VOID AvxInitZydis(
    VOID
);

VOID AvxInitEmuBuffer(
    VOID
);

VOID AvxDllPurgeAllHooks(
    VOID
);

VOID AvxDllFreeExports(
    VOID
);

VOID AvxDllInitComm(
    VOID
)
{
    NTSTATUS status;
    status = AvxCommGetConnectionSocket(&gSocket);
}

VOID AvxSuspendAllThreads(
    VOID
)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        return;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        //printf("[ERROR] Failed getting first thread snapshot!\n");

        CloseHandle(hThreadSnap);

        return;
    }

    do
    {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
        {
            HANDLE tid = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE,
                te32.th32ThreadID);
            SuspendThread(tid);

            CloseHandle(tid);
        }

    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
}

VOID AvxResumeAllThreads(
    VOID
)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        return;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        //printf("[ERROR] Failed getting first thread snapshot!\n");

        CloseHandle(hThreadSnap);

        return;
    }

    do
    {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
        {
            HANDLE tid = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE,
                te32.th32ThreadID);
            ResumeThread(tid);

            CloseHandle(tid);
        }

    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
        pid = GetCurrentProcessId();
        AvxDllInitComm();
        AvxSuspendAllThreads();
        AvxInitZydis();
        AvxInitEmuBuffer();
        AvxDllEstablishHooks();
        AvxResumeAllThreads();
        gHooksEstablished = TRUE;
        break;
	case DLL_THREAD_ATTACH:
        //printf("thread attach");
        break;
	case DLL_THREAD_DETACH:
        //printf("thread detach");
        break;
	case DLL_PROCESS_DETACH:
        AvxDllPurgeAllHooks();
        AvxDllFreeExports();
        AvxCommUninitComm(&gSocket);
		break;
	}
	return TRUE;
}

VOID
AvxInitZydis(VOID)
{
    ZydisDecoderInit(&gZydisDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

VOID
AvxDllEstablishHooks(
        VOID
    )
{
    ZydisDecodedInstruction instrux;
    HMODULE hNtdll, hKernel32, hKernelbase;
    PHOOK_DATA hook;
    ZydisStatus status;
    DWORD ntdllNr = 0, k32Nr = 0, kbaseNr = 0;
    PEXPORT ntdllExp, k32Exp, kbaseExp;

    hNtdll = GetModuleHandleA("ntdll.dll");
    hKernel32 = GetModuleHandleA("kernel32.dll");
    hKernelbase = GetModuleHandleA("kernelbase.dll");

    AvxFindAllExports(hNtdll, &ntdllNr, &ntdllExp);
    AvxFindAllExports(hKernel32, &k32Nr, &k32Exp);
    AvxFindAllExports(hKernelbase, &kbaseNr, &kbaseExp);

    gExports.push_back(ntdllExp);
    gExports.push_back(k32Exp);
    gExports.push_back(kbaseExp);
    
    BOOL p = FALSE;
    for (int j = 0; j < ARRAYSIZE(gApiDescriptors); j++)
    {
        if (gApiDescriptors[j].Module == LIB_NTDLL)
        {
            for (int i = 0; i < ntdllNr; i++)
            {
                if (strcmp(gApiDescriptors[j].FunctionName, ntdllExp[i].ExportName) == 0)
                {
                    status = AvxEstablishApiHook(&ntdllExp[i], hNtdll, &hook, gApiDescriptors[j].Ordinal);
                    if (!ZYDIS_SUCCESS(status))
                    {
                        continue;
                    }
                }
            }
        }
        
        if (gApiDescriptors[j].Module == LIB_KERNEL32)
        {
            for (int i = 0; i < k32Nr; i++)
            {
                if (strcmp(gApiDescriptors[j].FunctionName, k32Exp[i].ExportName) == 0)
                {
                    status = AvxEstablishApiHook(&k32Exp[i], hKernel32, &hook, gApiDescriptors[j].Ordinal);
                    if (!ZYDIS_SUCCESS(status))
                    {
                        continue;
                    }
                }
            }
        }

        if (gApiDescriptors[j].Module == LIB_KERNELBASE)
        {
            for (int i = 0; i < kbaseNr; i++)
            {
                if (strcmp(gApiDescriptors[j].FunctionName, kbaseExp[i].ExportName) == 0)
                {
                    status = AvxEstablishApiHook(&kbaseExp[i], hKernelbase, &hook, gApiDescriptors[j].Ordinal);
                    if (!ZYDIS_SUCCESS(status))
                    {
                        continue;
                    }
                }
                
            }
        }
    }

}


extern std::vector<EXPORT*> vExportsCalled;

VOID AvxInitEmuBuffer(
    VOID
)
{
    DWORD old;
    VirtualProtect((PBYTE)EmuBuffer, 0x60, PAGE_EXECUTE_READWRITE, &old);
}

VOID AvxDllPurgeAllHooks(
    VOID
)
{
    gHooksEstablished = FALSE;
    for (DWORD i = 0; i < gHooks.size(); i++)
    {
        AvxPurgeApiHook(gHooks[i]);
    }
    gHooks.clear();
}

VOID AvxDllFreeExports(
    VOID
)
{
    for (DWORD i = 0; i < gExports.size(); i++)
    {
        AvxReleaseExports(&gExports[i]);
    }
}