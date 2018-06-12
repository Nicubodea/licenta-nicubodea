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

    //if (strlen(ProcessName) > 14)
    //{
        //ProcessName[14] = 0;
    //}
    strcpy((char*)pInfo->Name, ProcessName);

    pInfo->Name[14] = 0;

    pInfo->Protection = Mask;

    LONG status = HyperCall(mhvCommunicationAddProtection, pInfo);
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

    return 0;
}