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


PMHVMODULE
MhvGetModuleByAddress(
    PMHVPROCESS Process,
    QWORD Address
)
{
    LIST_ENTRY* list = Process->Modules.Flink;

    while (list != &Process->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;
        if (pMod->Start <= Address && pMod->End > Address)
        {
            return pMod;
        }
    }

    return NULL;
}

PMHVMODULE
MhvGetModuleData(
    PMHVPROCESS Process,
    QWORD Start,
    QWORD End,
    PBYTE Name,
    WORD NameLength
)
{
    QWORD restOfPage = (((QWORD)Name + 0x1000) & 0xFFFFFFFFFFFFF000) - (QWORD)Name;
    PBYTE name = MemAllocContiguosMemory(min(NameLength / 2 + 1, restOfPage));
    PMHVMODULE pMod = MemAllocContiguosMemory(sizeof(MHVMODULE));

    int j = 0;
    for (DWORD i = 0; i < min(NameLength, restOfPage); i += 2)
    {
        name[j] = Name[i];
        j++;
    }

    name[j] = 0;

    pMod->Name = name;
    pMod->End = End;
    pMod->Start = Start;
    pMod->Process = Process;

    return pMod;
}

#define min(a,b) ((a) > (b) ? (a) : (b))

VOID
MhvIterateVadTree(
    QWORD Node,
    DWORD Level,
    PMHVPROCESS Process
)
{
    if (Node == 0 || Node )
    {
        return;
    }

    
    MMVAD_SHORT64 pVad = { 0 };

    MhvMemRead(Node, sizeof(MMVAD_SHORT64), pGuest.SystemCr3, &pVad);

    LOG("goto left -> %x", pVad.Left);
    MhvIterateVadTree(pVad.Left, Level + 1, Process);

    //if (Level != 0)
    //{
        QWORD start = pVad.StartingVpn;
        QWORD startHigh = pVad.StartingVpnHigh;
        QWORD finish = pVad.EndingVpn;
        QWORD finishHigh = pVad.EndingVpnHigh;
        WORD type = pVad.VadFlags.VadType & 0xFFFF;
        QWORD rsp = GetRsp();

        /*LOG("[VAD] %x -> [%x, %x] -> %x RSP: %x", Node,
            (QWORD)start | (startHigh << 32),
            (QWORD)finish | (finishHigh << 32),
            type, rsp);
        */
        if (type == 2)
        {
            MhvGetVadName(&pVad,
                Process);
        }
    //}
        LOG("goto right -> %x", pVad.Right);
    MhvIterateVadTree(pVad.Right, Level + 1, Process);

}


VOID
MhvReiterateProcessModules(

)
{
    
    LIST_ENTRY* list = pGuest.ProcessList.Flink;
    while (list != &pGuest.ProcessList)
    {
        PMHVPROCESS pProc = CONTAINING_RECORD(list, MHVPROCESS, Link);

        list = list->Flink;

        LOG("[PROC-LIST] %s -> %d %x; vad root = %x", pProc->Name, pProc->Pid, pProc->Cr3, pProc->VadRoot);

        MhvIterateVadTree(pProc->VadRoot, 0, pProc);

    }
}


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

    // assume every process is protected for now
    newProcess->Protected = TRUE;

    InitializeListHead(&newProcess->Modules);

    InsertTailList(&pGuest.ProcessList, &newProcess->Link);


    LOG("[WINPROC] Process %s, pid %d with cr3 %x just started!", newProcess->Name, newProcess->Pid, newProcess->Cr3);

    //MhvIterateVadTree(newProcess->VadRoot, 0, newProcess);

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
    //PQWORD cr3Phys;
    PMHVPROCESS pProc;
    
    //__vmx_vmread(VMX_GUEST_CR3, &cr3);
    //cr3Phys = MhvTranslateVa(cr3Offset, cr3, NULL);

    pProc = MhvFindProcessByEprocess(Context->context._rcx);
    if (pProc == NULL)
    {
        LOG("[ERROR] Process deleted but does not exist in our list...");
        return;
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
