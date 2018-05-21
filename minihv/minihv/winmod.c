#include "guest.h"
#include "winmod.h"
#include "ntstatus.h"
#include "minihv.h"
#include "vmxhook.h"
#include "structures.h"
#include "winproc.h"
#include "alloc.h"

NTSTATUS
Kernel32Written(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    LOG("I was written :((((");
}

VOID
MhvInsertModuleInListIfNotExistent(
    PMHVPROCESS Process,
    QWORD Start,
    QWORD End,
    PBYTE Name,
    WORD NameLength
)
{
    BOOLEAN found = FALSE;
    LIST_ENTRY* list = Process->Modules.Flink;

    if (!found)
    {
        PBYTE name = MemAllocContiguosMemory(NameLength / 2 + 2);
        PMHVMODULE pMod = MemAllocContiguosMemory(sizeof(MHVMODULE));

        int j = 0;
        for (DWORD i = 0; i < NameLength; i += 2)
        {
            name[j] = Name[i];
            j++;
        }

        name[j] = 0;

        pMod->Name = name;
        pMod->End = End;
        pMod->Start = Start;
        pMod->Process = Process;

        LOG("[Process %s] Module %s just loaded at [%x -> %x]", Process->Name, pMod->Name, pMod->Start, pMod->End);

        InsertTailList(&(Process->Modules), &(pMod->Link));

        if (Process->Name[0] == 'i' && Process->Name[1] == 'n' && Process->Name[2] == 't' && Process->Name[3] == 'r')
        {
            if (pMod->Name[24] == '3')
            {
                LOG("hooking kernel32!!!")
                MhvCreateEptHook(pGuest.Vcpu, MhvTranslateVa(pMod->Start, Process->Cr3, NULL), EPT_WRITE_RIGHT, Process->Cr3, pMod->Start,
                    Kernel32Written, NULL, PAGE_SIZE);
            }
        }
    }
}


BYTE nameString[0x1000];

VOID
MhvGetVadName(
    PMMVAD_SHORT64 Vad,
    PMHVPROCESS Process,
    QWORD Cr3
)
{

    PBYTE ctlArea, fileObject;
    WORD nameLength;
    QWORD nameGva;

    MhvMemRead(Vad->Subsection, 8, Cr3, &ctlArea);

    MhvMemRead(ctlArea + 0x40, 8, Cr3, &fileObject);

    fileObject = ((QWORD) fileObject) & 0xFFFFFFFFFFFFFFF0;

    MhvMemRead(fileObject + 0x58, 2, Cr3, &nameLength);

    MhvMemRead(fileObject + 0x60, 8, Cr3, &nameGva);

    MhvMemRead(nameGva, nameLength, Cr3, nameString);

    QWORD s1 = Vad->StartingVpn;
    QWORD s2 = Vad->StartingVpnHigh;
    QWORD f1 = Vad->EndingVpn;
    QWORD f2 = Vad->EndingVpnHigh;

    QWORD start = (s1 | (s2 << 32)) << 12;

    QWORD finish = (f1 | (f2 << 32)) << 12;

    MhvInsertModuleInListIfNotExistent(Process, start, finish, nameString, nameLength);

}

VOID
MhvIterateVadList(
    PMHVPROCESS Process
)
{

}

BOOLEAN bGata = TRUE;
BYTE pagini[0x1500];

VOID
MhvNewModuleLoaded(
    PPROCESOR Context
)
{
    QWORD cr3;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    LOG("[WINMOD] VadGva: %x, Cr3: %x", Context->context._rcx, cr3);

    MMVAD_SHORT64 pVad = { 0 };
    
    //MhvMemRead(Context->context._rcx, sizeof(MMVAD_SHORT64), cr3, &pVad);

    QWORD currentCr3 = pGuest.SystemCr3;

    if (currentCr3 == 0)
    {
        currentCr3 = cr3;
    }


    MhvMemRead(Context->context._rcx, sizeof(MMVAD_SHORT64), currentCr3, &pVad);

    PMHVPROCESS pProc = MhvFindProcessByCr3(cr3);

    if (NULL == pProc)
    {
        LOG("[INFO] No process is pointed by cr3!");
        return;
    }

    if (pVad.VadFlags.VadType == 2)
    {
        MhvGetVadName(&pVad, pProc, currentCr3);
    }

    
}

NTSTATUS
MhvModuleFullyLoaded(
    PVOID Processor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    PEPT_HOOK pHook = Hook;
    PBYTE imgNamePhysAddr = pHook->GuestPhysicalAddress | pHook->Offset;
    DWORD i;
    QWORD k;
    PUM_MODULE Module = NULL;
    PMHVPROCESS pProcess = NULL;
    QWORD cr3 = pHook->Cr3;
    MhvEptPurgeHook(Processor, pHook->GuestPhysicalAddress | pHook->Offset, FALSE);
    
    //pProcess = &gProcesses[MhvFindProcessByCr3(cr3)];

    //if (MhvFindProcessByCr3(Cr3) == -1)
    //{
        LOG("[CRITICAL] Cr3 = %x", cr3);
    //}

    //PQWORD modBase = imgNamePhysAddr - 0x20;

        //Module = &(pProcess->Modules[pProcess->NumberOfModules-1]);


        
    if (Module == NULL)
    {
        LOG("[ERROR] Could not find module with base %x in process %s!!!", Module->ModuleBase, pProcess->Name);
        return STATUS_NOT_FOUND;
    }
    i = 0;
    k = 0;
    while (imgNamePhysAddr[i] != 0 || imgNamePhysAddr[i + 1] != 0)
    {
        Module->Name[k] = imgNamePhysAddr[i];
        i += 2;
        k++;
    }
    Module->Name[k] = 0;
    Module->NameSize = k;

    LOG("[WINMOD] <Process %s> Module %s loaded at %x with size %x", pProcess->Name, 
        Module->Name, Module->ModuleBase, Module->ModuleSize);

}

NTSTATUS
MhvGetModFromWrittenEntry(
    PVOID Processor,
    QWORD Entry,
    QWORD Cr3,
    UM_MODULE* Module
)
{
    if (Entry == 0)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (Cr3 == 0)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (Module == NULL)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    PPROCESOR pProc = Processor;
    PBYTE pPhysEntry = MhvTranslateVa(Entry, Cr3, NULL);
    DWORD i = 0, k = 0;

    if (pPhysEntry == 0)
    {
        LOG("[ERROR] Cannot map LDR_DATA_TABLE_ENTRY %x into %x", Entry, Cr3);
        return STATUS_NOT_FOUND;
    }

    QWORD imgBase = *((PQWORD)(pPhysEntry + 0x30));
    QWORD imgSize = *((PQWORD)(pPhysEntry + 0x40));
    QWORD imgNameAddr = *((PQWORD)(pPhysEntry + 0x50));

    PBYTE imgNamePhysAddr = MhvTranslateVa(imgNameAddr, Cr3, NULL);

    Module->ModuleBase = imgBase;
    Module->ModuleSize = imgSize;

    LOG("[-->WINMOD HOOKS<--] CR3: %x imgNameAddr = %x", Cr3, imgNameAddr);
    LOG("[-->WINMOD HOOKS<--] CR3: %x imgNameAddrPhys = %x", Cr3, imgNamePhysAddr);

    if (imgNamePhysAddr[0] == 0 && imgNamePhysAddr[1] == 0)
    {
        /*MhvEptMakeHook(
            pProc,
            imgNamePhysAddr,
            EPT_WRITE_RIGHT,
            Cr3,
            imgNameAddr,
            NULL,
            MhvModuleFullyLoaded
        );*/
        return STATUS_SUCCESS;
    }

    

    while (imgNamePhysAddr[i] != 0 || imgNamePhysAddr[i + 1] != 0)
    {
        Module->Name[k] = imgNamePhysAddr[i];
        i += 2;
        k++;
    }
    Module->Name[k] = 0;
    Module->NameSize = k;

    LOG("[WINMOD-WOW] Module %s LOADED!!!", Module->Name);
    
    return STATUS_SUCCESS;
}