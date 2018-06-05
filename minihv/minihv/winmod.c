#include "guest.h"
#include "winmod.h"
#include "ntstatus.h"
#include "minihv.h"
#include "vmxhook.h"
#include "structures.h"
#include "winproc.h"
#include "alloc.h"
#include "winpe.h"
#include "Zydis/Zydis.h"

PMHVMODULE
MhvFindModuleByRip(
    QWORD Rip,
    PMHVPROCESS Process
)
{
    LIST_ENTRY* list = Process->Modules.Flink;

    while (list != &Process->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;

        if (pMod->Start <= Rip && pMod->End >= Rip)
        {
            return pMod;
        }
    }
    return NULL;
}

PCHAR
MhvGetNameFromPath(
    PCHAR Path
)
{
    PCHAR init = Path;
    DWORD i = 0;
    DWORD last;
    while (Path[i] != 0)
    {
        if (Path[i] == '\\')
        {
            last = i;
        }
        i++;
    }

    return &init[last+1];
}

NTSTATUS
MhvModHandleWrite(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    PEPT_HOOK pHook = Hook;
    QWORD address;

    __vmx_vmread(VMX_GUEST_LINEAR_ADDRESS, &address);

    PMHVPROCESS pProc = MhvFindProcessByCr3(Cr3);
    if (pProc == NULL)
    {
        PMHVMODULE pMod = pHook->Owner;
        if (pMod == NULL)
        {
            LOG("[ERROR] Ept violation on %x came from nowhere!");

            return STATUS_SUCCESS;
        }
        pProc = pMod->Process;

        // ugliest hack in the world
        pProc->Cr3 = Cr3;
    }


    PMHVMODULE pModVictim = pHook->Owner;
    PMHVMODULE pModAttacker = MhvFindModuleByRip(Rip, pProc);


    //MemDumpAllocStats();

    if (pModAttacker != NULL)
    {
        //LOG("[INFO] %s ", MhvGetNameFromPath(pModAttacker->Name));
        if (strcmp(MhvGetNameFromPath(pModAttacker->Name), "ntdll.dll") == 0)
        {
            return STATUS_SUCCESS;
        }

        if (strcmp(MhvGetNameFromPath(pModAttacker->Name), MhvGetNameFromPath(pModVictim->Name)) == 0)
        {
            return STATUS_SUCCESS;
        }
    }

   

    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~ALERT~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    LOG("Process -> %s Pid %d Cr3 %x", pProc->Name, pProc->Pid, pProc->Cr3);
    LOG("Attacker -> %s RIP %x", pModAttacker == NULL ? "<unknown>" : pModAttacker->Name, Rip);
    LOG("Victim -> %s address %x", pModVictim->Name, address);
    LOG("[INFO] Hook @ %x physical: %x virtual: %x, offset: %x", pHook, pHook->GuestPhysicalAddress, pHook->GuestLinearAddress, pHook->Offset);
    LOG("[INFO] Dumping instructions from %x", Rip);



    return STATUS_SUCCESS;
}

VOID
MhvHandleModuleUnload(
    PPROCESOR Context
)
{
    QWORD cr3, start, end;
    PMHVPROCESS pProc;

    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    start = Context->context._rcx;
    end = Context->context._rdx + 1;

    pProc = MhvFindProcessByCr3(cr3);

    if (pProc == NULL)
    {
        //LOG("[ERROR] No process with CR3 found!");
        return;
    }

    // we are not interested in unprotected processes
    if (!pProc->Protected)
    {
        return;
    }

    LIST_ENTRY* list = pProc->Modules.Flink;
    PMHVMODULE pModFound = NULL;

    while (list != &pProc->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;

        if (pMod->Start == start && pMod->End == end)
        {
            pModFound = pMod;
            break;
        }

    }

    if (pModFound == NULL)
    {
        return;
    }
    
    RemoveEntryList(&pModFound->Link);
    
    LOG("[INFO] Module %s [%x %x] in Process %d is unloading", pModFound->Name, pModFound->Start, pModFound->End, pModFound->Process->Pid);

    MhvDeleteHookByOwner(pModFound);

    LOG("[INFO] Module %s unhooked succesfully!", pModFound->Name);

    MemFreeContiguosMemory(pModFound->Name);
    MemFreeContiguosMemory(pModFound);

}

VOID
MhvHookModule(
    PMHVMODULE Module
)
{

    IMAGE_DOS_HEADER dos = { 0 };
    IMAGE_NT_HEADERS64 nth = { 0 };
    IMAGE_SECTION_HEADER sec = { 0 };
    NTSTATUS status;

    QWORD cr3 = Module->Process->Cr3;

    status = MhvMemRead(Module->Start, 
        sizeof(IMAGE_DOS_HEADER), 
        cr3, 
        &dos);

    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead status: 0x%x", status);
        return;
    }

    //LOG("[INFO] Signature is: %x, e_lfanew: %x", dos.e_magic, dos.e_lfanew)

    QWORD ntHeaderGva = Module->Start + dos.e_lfanew;

    status = MhvMemRead(ntHeaderGva, sizeof(IMAGE_DOS_HEADER), cr3, &nth);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead status: 0x%x", status);
        return;
    }

    QWORD sectionRva = Module->Start + dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + nth.FileHeader.SizeOfOptionalHeader + sizeof(nth.Signature);
    

    for (DWORD i = 0; i < nth.FileHeader.NumberOfSections; i++)
    {
        status = MhvMemRead(sectionRva,
            sizeof(IMAGE_SECTION_HEADER),
            cr3,
            &sec);

        if (!NT_SUCCESS(status))
        {
            LOG("[ERROR] MhvMemRead status: 0x%x", status);
            return;
        }

        if ((sec.Characteristics & 0x80000000) == 0 && (sec.Characteristics & 0x02000000) == 0)
        {
            QWORD rvaStart = sec.VirtualAddress & 0xFFFFFFFF;
            QWORD rvaEnd = (sec.VirtualAddress + sec.Misc.VirtualSize) & 0xFFFFFFFF;

            LOG("[INFO] Hooking section %s [%x -> %x]", sec.Name, rvaStart, rvaEnd);

            for (DWORD page = rvaStart; page < rvaEnd; page += PAGE_SIZE)
            {
               
                QWORD rvaCurrent = Module->Start + page;
                QWORD sz = PAGE_SIZE;
                
                if (page == (rvaEnd & (~0xFFF)) && (rvaEnd & 0xFFF) != 0)
                {
                    sz = rvaEnd & 0xFFF;
                }

                //LOG("[INFO] Hooking page %x sz %x", rvaCurrent, sz);

                PEPT_HOOK pHook = MhvCreateEptHook(pGuest.Vcpu,
                    MhvTranslateVa(rvaCurrent, cr3, NULL),
                    EPT_WRITE_RIGHT,
                    cr3,
                    rvaCurrent,
                    MhvModHandleWrite,
                    NULL,
                    sz,
                    FALSE
                );

                pHook->Owner = Module;
            }

        }

        sectionRva += sizeof(IMAGE_SECTION_HEADER);
    }



}


NTSTATUS
MhvModReadyToHook(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    PMHVPROCESS pProc = MhvFindProcessByCr3(Cr3);
    PEPT_HOOK pHook = Hook;
    PMHVMODULE foundMod = NULL;

    if (pProc == NULL)
    {
        LOG("[ERROR] Process could not be found for module!");
        return STATUS_SUCCESS;
    }

    LIST_ENTRY* list = pProc->Modules.Flink;

    while (list != &pProc->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;

        if (pMod->Start == pHook->GuestLinearAddress)
        {
            foundMod = pMod;
            break;
        }
    }

    if (foundMod != NULL)
    {
        LOG("[INFO] (proc %s, %d) Module @%x %s [%x %x] is ready to be hooked, headers in memory!", pProc->Name, pProc->Pid, foundMod, foundMod->Name, foundMod->Start, foundMod->End);
        MhvDeleteHookHierarchy(pHook);
        MhvHookModule(foundMod);
    }

    return STATUS_SUCCESS;
}

char* gProtectedModules[] = {
    "\\Windows\\System32\\ntdll.dll",
    "\\Windows\\System32\\kernel32.dll",
    "\\Windows\\System32\\KernelBase.dll"
};


BOOLEAN 
MhvIsModuleProtected(
    PMHVPROCESS Process,
    PMHVMODULE Module
)
{
    if (!Process->Protected)
    {
        return FALSE;
    }

    for (DWORD i = 0; i < ARRAYSIZE(gProtectedModules); i++)
    {
        if (strcmp(Module->Name, gProtectedModules[i]) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;

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

    while (list != &Process->Modules)
    {
        PMHVMODULE pMod = CONTAINING_RECORD(list, MHVMODULE, Link);

        list = list->Flink;

        if (pMod->Start == Start && pMod->End == End)
        {
            found = TRUE;
            break;
        }
    }

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
        InitializeListHead(&pMod->Hooks);

        LOG("[Process %s] Module %s just loaded at [%x -> %x]", Process->Name, pMod->Name, pMod->Start, pMod->End);

        InsertTailList(&(Process->Modules), &(pMod->Link));

        // at this point we don't care anymore for this module if it is not protected...
        if (!MhvIsModuleProtected(Process, pMod))
        {
            return;
        }

        PBYTE pSig = MhvTranslateVa(pMod->Start, Process->Cr3, NULL);

        if (pSig != NULL && pSig[0] == 'M' && pSig[1] == 'Z')
        {
            LOG("[INFO] (proc %s, %d) Module @%x %x %s [%x %x] is ready to be hooked, headers in memory!", Process->Name, Process->Pid, pMod, pMod->Name, pMod->Start, pMod->End);
            MhvHookModule(pMod);
            return;
        }

        PEPT_HOOK pHook = MhvCreateEptHook(pGuest.Vcpu,
            MhvTranslateVa(pMod->Start, Process->Cr3, NULL),
            EPT_WRITE_RIGHT,
            Process->Cr3,
            pMod->Start,
            NULL,
            MhvModReadyToHook,
            PAGE_SIZE,
            TRUE
        );

        // we got to set the hook Owner to this current module so that we know that 
        pHook->Owner = pMod;
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
MhvIterateVadsRecursively(
    QWORD Node,
    PMHVPROCESS Process
)
{
    if (Node == 0)
    {
        return;
    }

    QWORD cr3;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    MMVAD_SHORT64 pVad = { 0 };
    QWORD currentCr3 = pGuest.SystemCr3;

    if (currentCr3 == 0)
    {
        currentCr3 = cr3;
    }

    MhvMemRead(Node, sizeof(MMVAD_SHORT64), currentCr3, &pVad);

    if (pVad.Left != 0)
    {
        MhvIterateVadsRecursively(pVad.Left, Process);
    }

    if (pVad.VadFlags.VadType == 2)
    {
        MhvGetVadName(&pVad, Process, currentCr3);
    }

    if (pVad.Right != 0)
    {
        MhvIterateVadsRecursively(pVad.Right, Process);
    }
}

VOID
MhvIterateVadList(
    PMHVPROCESS Process
)
{
    MhvIterateVadsRecursively(Process->VadRoot, Process);
}


VOID
MhvNewModuleLoaded(
    PPROCESOR Context
)
{
    QWORD cr3;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    MMVAD_SHORT64 pVad = { 0 };

    QWORD currentCr3 = pGuest.SystemCr3;

    if (currentCr3 == 0)
    {
        currentCr3 = cr3;
    }

    PMHVPROCESS pProc = MhvFindProcessByCr3(cr3);

    if (NULL == pProc)
    {
        // probably process not yet loaded
        return;
    }

    if (!pProc->Protected)
    {
        return;
    }

    MhvMemRead(Context->context._rcx, sizeof(MMVAD_SHORT64), currentCr3, &pVad);

    if (pVad.VadFlags.VadType == 2)
    {
        MhvGetVadName(&pVad, pProc, currentCr3);
    }  
}
