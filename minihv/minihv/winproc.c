#include "winproc.h"
#include "guest.h"
#include "alloc.h"
#include "_wdk.h"
#include "minihv.h"
#include "winpe.h"

#define NAME_OFFSET_IN_EPROCESS 0x450
#define PID_OFFSET_IN_EPROCESS 0x2e8
#define CR3_OFFSET_IN_EPROCESS 0x28
#define PEB_OFFSET_IN_EPROCESS 0x3f8
#define VADROOT_OFFSET_IN_EPROCESS 0x620


char* gProtectedProcesses[] = {
    "firefox.exe",
    "chrome.exe"
};

BOOLEAN protect = FALSE;

VOID
MhvInsertProcessInList(
    PPROCESOR Context
) 
{
    
    PMHVPROCESS newProcess = MemAllocContiguosMemory(sizeof(MHVPROCESS));
    QWORD nameOffset = Context->context._rcx + NAME_OFFSET_IN_EPROCESS;
    QWORD cr3 = 0;

    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    if (pGuest.SystemCr3 == 0)
    {
        pGuest.SystemCr3 = cr3;
    }

    PBYTE namePhys = MhvTranslateVa(nameOffset, cr3, NULL);
    memcpys(namePhys, newProcess->Name, 16);

    QWORD cr3Offset = Context->context._rcx + CR3_OFFSET_IN_EPROCESS;
    PQWORD cr3Phys = MhvTranslateVa(cr3Offset, cr3, NULL);
    newProcess->Cr3 = *cr3Phys;

    QWORD pidOffset = Context->context._rcx + PID_OFFSET_IN_EPROCESS;
    PQWORD pidPhys = MhvTranslateVa(pidOffset, cr3, NULL);

    QWORD vadRootOffset = Context->context._rcx + VADROOT_OFFSET_IN_EPROCESS;
    PQWORD vadRootPhys = MhvTranslateVa(vadRootOffset, cr3, NULL);

    newProcess->Pid = *pidPhys;
    newProcess->NumberOfHooks = 0;
    newProcess->NumberOfModules = 0;
    newProcess->VadRoot = *vadRootPhys;
    newProcess->Eprocess = Context->context._rcx;
    newProcess->Protected = FALSE;

    for(DWORD i = 0; i<ARRAYSIZE(gProtectedProcesses); i++)
    {
        if (strcmp(newProcess->Name, gProtectedProcesses[i]) == 0)
        {
            newProcess->Protected = TRUE;

        }
    }

    InitializeListHead(&newProcess->Modules);

    InsertTailList(&pGuest.ProcessList, &newProcess->Link);

    LOG("[WINPROC] Process %s, pid %d with cr3 %x just started! %s", newProcess->Name, newProcess->Pid, newProcess->Cr3, newProcess->Protected ? "PROTECTED" : "NOT PROTECTED");

    if (newProcess->Protected)
    {
        MhvIterateVadList(newProcess);
    }
    gNumberOfActiveProcesses++;

}


VOID
MhvDeleteProcessFromList(
    PPROCESOR Context
)
{
    QWORD cr3 = 0;
    DWORD i = 0;
    QWORD cr3Offset = Context->context._rcx + CR3_OFFSET_IN_EPROCESS;
    PMHVPROCESS pProc;

    pProc = MhvFindProcessByEprocess(Context->context._rcx);
    if (pProc == NULL)
    {
        LOG("[ERROR] Process deleted but does not exist in our list...");
        return;
    }

    LIST_ENTRY * list = pProc->Modules.Flink;

    while (list != &pProc->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;

        RemoveEntryList(&pMod->Link);

        LOG("[INFO] Module %s [%x %x] in Process %d is unloading", pMod->Name, pMod->Start, pMod->End, pMod->Process->Pid);

        MhvDeleteHookByOwner(pMod);

        LOG("[INFO] Module %s unhooked succesfully!", pMod->Name);

        MemFreeContiguosMemory(pMod->Name);
        MemFreeContiguosMemory(pMod);
    }
    
    RemoveEntryList(&pProc->Link);
    
    LOG("[INFO] Process %s (pid = %d; cr3 = %x) terminated!", pProc->Name, pProc->Pid, pProc->Cr3);

    MemFreeContiguosMemory(pProc);

    gNumberOfActiveProcesses--;

}

PMHVPROCESS
MhvFindProcessByCr3(
    QWORD Cr3
)
{

    PLIST_ENTRY list = pGuest.ProcessList.Flink;

    while (list != &pGuest.ProcessList)
    {
        PMHVPROCESS pProc = CONTAINING_RECORD(list, MHVPROCESS, Link);

        if (pProc->Cr3 == Cr3)
        {
            return pProc;
        }
        list = list->Flink;
    }

    return NULL;
}

PMHVPROCESS
MhvFindProcessByEprocess(
    QWORD Eprocess
)
{

    PLIST_ENTRY list = pGuest.ProcessList.Flink;

    while (list != &pGuest.ProcessList)
    {
        PMHVPROCESS pProc = CONTAINING_RECORD(list, MHVPROCESS, Link);

        if (pProc->Eprocess == Eprocess)
        {
            return pProc;
        }
        list = list->Flink;
    }

    return NULL;
}
