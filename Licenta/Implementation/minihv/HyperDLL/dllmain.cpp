// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include <stdio.h>
#include "Zydis/Zydis.h"
#include "exports.h"
#include "hooker.h"
#include <vector>
#include <tlhelp32.h>

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
    { "LoadLibraryA", LIB_KERNELBASE, 48 },
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

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        pid = GetCurrentProcessId();
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