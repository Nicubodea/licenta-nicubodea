#include "winproc.h"
#include "guest.h"
#include "alloc.h"
#include "_wdk.h"
#include "minihv.h"
#include "winpe.h"
#include "alert.h"

#define NAME_OFFSET_IN_EPROCESS 0x450
#define PID_OFFSET_IN_EPROCESS 0x2e8
#define CR3_OFFSET_IN_EPROCESS 0x28
#define PEB_OFFSET_IN_EPROCESS 0x3f8
#define VADROOT_OFFSET_IN_EPROCESS 0x620

/*PROTECTION_INFO gProtectedProcesses[] = {
    {"firefox.exe",0x3}
};*/

LIST_ENTRY gProtectedProcesses;
BOOLEAN bProtInitialized = FALSE;

BOOLEAN protect = FALSE;

VOID
MhvProtectProcess(
    PPROTECTION_INFO Protection
)
{
    LIST_ENTRY* list = gProtectedProcesses.Flink;
    DWORD oldFlags = 0;

    while (list != &gProtectedProcesses)
    {
        PPROTECTION_INFO pProt = CONTAINING_RECORD(list, PROTECTION_INFO, Link);
        list = list->Flink;

        if (strcmp(Protection->Name, pProt->Name) == 0)
        {
            oldFlags = pProt->Protection;
            RemoveEntryList(&pProt->Link);
            MemFreeContiguosMemory(pProt);
        }

    }

    LOG("[VMXCOMM] Requested to change protection from process %s from %x to %x", Protection->Name, oldFlags, Protection->Protection);

    if (Protection->Protection)
    {
        InsertTailList(&gProtectedProcesses, &Protection->Link);
    }
}

NTSTATUS
MhvProtectProcessRequest(
    QWORD Address,
    QWORD Cr3
)
{
    PPROTECTION_INFO pProt = MemAllocContiguosMemory(sizeof(PROTECTION_INFO));
    if (NULL == pProt)
    {
        LOG("[INFO] Null pointer is coming to you");
    }

    memset_s(pProt, 0, sizeof(PROTECTION_INFO));

    PPROTECTION_INFO pGuestProt = MhvTranslateVa(Address, Cr3, NULL);

    pGuestProt->Name[14] = 0;

    *pProt = *pGuestProt;

    MhvProtectProcess(pProt);

    return STATUS_SUCCESS;
}


NTSTATUS
MhvInsertProcessInList(
    PPROCESOR Context
) 
{
    
    if (!bProtInitialized)
    {
        InitializeListHead(&gProtectedProcesses);
        bProtInitialized = TRUE;
    }

    PMHVPROCESS newProcess = MemAllocContiguosMemory(sizeof(MHVPROCESS));
    if (NULL == newProcess)
    {
        LOG("[INFO] Null pointer is coming to you");
    }
    memset_s(newProcess, 0, sizeof(MHVPROCESS));

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
    newProcess->ProtectionInfo = 0;

    LIST_ENTRY* list = gProtectedProcesses.Flink;

    while (list != &gProtectedProcesses)
    {
        PPROTECTION_INFO pProt = CONTAINING_RECORD(list, PROTECTION_INFO, Link);
        list = list->Flink;

        if(strcmp(newProcess->Name, pProt->Name) == 0)
        {
            newProcess->ProtectionInfo = pProt->Protection;

        }

    }

    if (strcmp(newProcess->Name, "introum_detour") == 0)
    {
        MemFreeContiguosMemory(newProcess);

        return STATUS_UNSUCCESSFUL;
    }


    InitializeListHead(&newProcess->Modules);

    InsertTailList(&pGuest.ProcessList, &newProcess->Link);

    LOG("[WINPROC] Process %s, pid %d with cr3 %x eproc %x just started! %s", newProcess->Name, newProcess->Pid, newProcess->Cr3, newProcess->Eprocess, newProcess->ProtectionInfo ? "PROTECTED" : "NOT PROTECTED");
    
    MhvCreateProcessCreationEvent(newProcess);

    if (newProcess->ProtectionInfo)
    {
        MhvIterateVadList(newProcess);
    }

    gNumberOfActiveProcesses++;

   

    return STATUS_SUCCESS;

}


NTSTATUS
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
        return STATUS_SUCCESS;
    }

    LIST_ENTRY * list = pProc->Modules.Flink;

    while (list != &pProc->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;

        RemoveEntryList(&pMod->Link);

        MhvDeleteHookByOwner(pMod);

        MemFreeContiguosMemory(pMod->Name);
        MemFreeContiguosMemory(pMod);
    }
    
    RemoveEntryList(&pProc->Link);
    
    LOG("[INFO] Process %s (pid = %d; cr3 = %x, eproc %x) terminated!", pProc->Name, pProc->Pid, pProc->Cr3, pProc->Eprocess);

    MhvCreateProcessTerminationEvent(pProc);

    MemFreeContiguosMemory(pProc);

    gNumberOfActiveProcesses--;

    return STATUS_SUCCESS;

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
