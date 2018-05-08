#include "winmod.h"
#include "ntstatus.h"
#include "minihv.h"
#include "vmxhook.h"
#include "structures.h"
#include "winproc.h"

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
    MhvEptPurgeHook(Processor, pHook->GuestPhysicalAddress | pHook->Offset);
    
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
        MhvEptMakeHook(
            pProc,
            imgNamePhysAddr,
            EPT_WRITE_RIGHT,
            Cr3,
            imgNameAddr,
            NULL,
            MhvModuleFullyLoaded
        );
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