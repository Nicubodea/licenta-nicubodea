// dllmain.cpp : Defines the entry point for the DLL application.
#include "structures.h"
#include <windows.h>
#include <ntstatus.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;

}

extern
LONG
HyperCall(
    DWORD Type,
    PVOID Structure
);

__declspec(dllexport)
LONG
HyperCommAddProtectionToProcess(
    char* ProcessName,
    int Mask
)
{
    PPROTECTION_INFO pInfo = (PPROTECTION_INFO)VirtualAlloc(NULL, sizeof(PROTECTION_INFO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    strcpy((char*)pInfo->Name, ProcessName);

    pInfo->Name[14] = 0;

    pInfo->Protection = Mask;

    LONG status = HyperCall(mhvCommunicationAddProtection, pInfo);
}

PCHAR
GetModNameFromPath(
    PCHAR ModPath
)
{
    DWORD i = 0;
    DWORD last = 0;
    while (i < strlen(ModPath))
    {
        if (ModPath[i] == '\\')
        {
            last = i + 1;
        }
        i++;
    }

    return &ModPath[last];
}

NTSTATUS
FindExportByRva(
    _In_ HMODULE Module,
    _In_ DWORD Rva,
    _Out_ PCHAR ExportName
)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS64 pNth;
    PIMAGE_DATA_DIRECTORY pData;
    PIMAGE_SECTION_HEADER pSect;
    DWORD nrOfSections;
    PIMAGE_EXPORT_DIRECTORY pExports;
    PDWORD pEat, pRvat;
    PWORD pOrd;
    DWORD i, rvaStart = 0, rvaEnd = 0;

    if (NULL == Module)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    pDos = (PIMAGE_DOS_HEADER)Module;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return STATUS_FILE_CORRUPT_ERROR;
    }

    pNth = (PIMAGE_NT_HEADERS64)(((PBYTE)pDos) + pDos->e_lfanew);
    pData = pNth->OptionalHeader.DataDirectory;

    if (pData[0].VirtualAddress == 0)
    {
        return STATUS_INVALID_ADDRESS;
    }

    pSect = (PIMAGE_SECTION_HEADER)(((PBYTE)pNth) + sizeof(IMAGE_FILE_HEADER) + pNth->FileHeader.SizeOfOptionalHeader + 4);

    pExports = (PIMAGE_EXPORT_DIRECTORY)(((PBYTE)pDos) + pData[0].VirtualAddress);

    for (DWORD i = 0; i < pNth->FileHeader.NumberOfSections; i++)
    {
        //printf("Section %s\n", pSect[i].Name);
        if (pSect[i].VirtualAddress <= pData[0].VirtualAddress && pSect[i].VirtualAddress + pSect[i].Misc.VirtualSize > pData[0].VirtualAddress)
        {
            rvaStart = pSect[i].VirtualAddress;
            rvaEnd = pSect[i].VirtualAddress + pSect[i].Misc.VirtualSize;
        }
    }

    //printf("Found section (%p -> %p)\n", rvaStart, rvaEnd);

    pEat = (PDWORD)(((PBYTE)pDos) + pExports->AddressOfNames);
    pRvat = (PDWORD)(((PBYTE)pDos) + pExports->AddressOfFunctions);
    pOrd = (PWORD)(((PBYTE)pDos) + pExports->AddressOfNameOrdinals);

    DWORD base = pExports->Base;

    //printf("base: %d\n", base);

    for (i = 0; i < pExports->NumberOfNames; i++)
    {
        DWORD currentRva = pRvat[pOrd[i]];
        WORD currentOrdinal = pOrd[i] + base;

        if (pRvat[pOrd[i]] >= rvaStart && pRvat[pOrd[i]] < rvaEnd)
        {
            // Forwarded export
            continue;
        }

        if (pRvat[pOrd[i]] > Rva || pRvat[pOrd[i]] + 30 < Rva)
        {
            continue;
        }

        PCHAR pName = (PCHAR)(((PBYTE)pDos) + pEat[i]);

        for (i = 0; i < min(strlen(pName), 31); i++)
        {
            ExportName[i] = pName[i];
        }
        ExportName[i] = 0;

        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

VOID
GetFunctionByRva(
    PCHAR Module,
    long long Rva,
    PCHAR Out
)
{
    PCHAR my_string = "<unknown>\0";
    DWORD i;

    PCHAR ModName = GetModNameFromPath(Module);

    HMODULE hMod = GetModuleHandleA(ModName);
    NTSTATUS status;

    status = FindExportByRva(hMod, Rva, Out);

    if ((status) != STATUS_SUCCESS)
    {
        for (i = 0; i < strlen(my_string); i++)
        {
            Out[i] = my_string[i];
        }

        Out[i] = 0;
    }    
}


__declspec(dllexport)
LONG
HyperCommGetLatestEvent(
    PEVENT* Event
)
{
    LONG status;
    PEVENT pEvent = (PEVENT)VirtualAlloc(NULL, sizeof(EVENT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    pEvent->Link.Flink = NULL;
    pEvent->Link.Blink = NULL;

    status = HyperCall(mhvCommunicationGetEvent, pEvent);

    *Event = pEvent;

    if (pEvent->Type == 4)
    {
        GetFunctionByRva(pEvent->ModuleAlertEvent.Victim.Name, pEvent->ModuleAlertEvent.Address - pEvent->ModuleAlertEvent.Victim.Start, pEvent->ModuleAlertEvent.FunctionName);
    }

    return status;
}

__declspec(dllexport)
LONG
HyperCommExceptAlert(
    PEVENT Event
)
{
    PALERT_EXCEPTION pException = (PALERT_EXCEPTION)VirtualAlloc(NULL, sizeof(ALERT_EXCEPTION), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    strcpy(pException->AttackerName, Event->ModuleAlertEvent.Attacker.Name);
    strcpy(pException->VictimName, Event->ModuleAlertEvent.Victim.Name);
    strcpy(pException->ProcessName, Event->ModuleAlertEvent.ProcessName);

    pException->NumberOfSignatures = Event->ModuleAlertEvent.NumberOfInstructions - 3;

    if (pException->NumberOfSignatures < 0)
    {
        pException->NumberOfSignatures = Event->ModuleAlertEvent.NumberOfInstructions;
    }

    if (pException->NumberOfSignatures < 4)
    {
        pException->SignaturesNeededToMatch = pException->NumberOfSignatures;
    }
    else
    {
        pException->SignaturesNeededToMatch = pException->NumberOfSignatures / 2;
    }

    for (DWORD i = 0; i < pException->NumberOfSignatures; i++)
    {
        pException->Signatures[i].Mnemonic = Event->ModuleAlertEvent.Instructions[i].Mnemonic;
    }

    return HyperCall(mhvCommunicationAddAlert, pException);
}

__declspec(dllexport)
LONG
HyperCommInjectDLL(
    DWORD Pid
)
{
    HMODULE hKBase;
    HANDLE hProc;
    hKBase = GetModuleHandleA("kernelbase.dll");
    PBYTE pLoad;
    pLoad = (PBYTE)GetProcAddress(hKBase, "LoadLibraryA");
    LPVOID addr;
    DWORD pid = Pid;

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProc == NULL)
    {
        printf("fail open process with pid: %d, %d", pid, GetLastError());
        return 1;
    }

    addr = VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (addr == NULL)
    {
        printf("fail alloc  %d", GetLastError());
        return 2;
    }
    CHAR* buff = "C:\\Users\\root\\Desktop\\HyperDLL.dll";
    SIZE_T ret;

    if (!WriteProcessMemory(hProc, addr, buff, strlen(buff), &ret))
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

__declspec(dllexport)
LONG
HyperCommAddProtectedDll(
    PCHAR Dll
)
{
    return HyperCall(3, Dll);
}


__declspec(dllexport)
LONG
HyperCommRemoveProtectedDll(
    PCHAR Dll
)
{

    return HyperCall(4, Dll);
}