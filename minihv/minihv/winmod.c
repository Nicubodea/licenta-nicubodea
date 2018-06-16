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
#include "alert.h"
#include "vmxcomm.h"

VOID
MhvFindFunctionByAddress(
    PMHVMODULE Module,
    QWORD Address
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

    status = MhvMemRead(ntHeaderGva, sizeof(IMAGE_NT_HEADERS64), cr3, &nth);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead status: 0x%x", status);
        return;
    }

    QWORD sectionRva = Module->Start + dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + nth.FileHeader.SizeOfOptionalHeader + sizeof(nth.Signature);



    IMAGE_EXPORT_DIRECTORY exports;

    LOG("[INFO] %x %x", nth.OptionalHeader.DataDirectory[0].VirtualAddress, nth.OptionalHeader.DataDirectory[0].Size);
    status = MhvMemRead(Module->Start + nth.OptionalHeader.DataDirectory[0].VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), cr3, &exports);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead status: 0x%x", status);
        return;
    }

    QWORD rvaStart = 0, rvaEnd = 0;


    for (DWORD i = 0; i < nth.FileHeader.NumberOfSections; i++)
    {
        status = MhvMemRead(sectionRva,
            sizeof(IMAGE_SECTION_HEADER),
            cr3,
            &sec);

        if (!NT_SUCCESS(status))
        {
            LOG("[ERROR] MhvMemRead status: 0x%x", status);
            continue;
        }

        if (sec.VirtualAddress <= nth.OptionalHeader.DataDirectory[0].VirtualAddress && sec.VirtualAddress + sec.Misc.VirtualSize > nth.OptionalHeader.DataDirectory[0].VirtualAddress)
        {
            rvaStart = sec.VirtualAddress;
            rvaEnd = sec.VirtualAddress + sec.Misc.VirtualSize;
        }

        sectionRva += sizeof(IMAGE_SECTION_HEADER);
    }

    LOG("[INFO] rvaStart is %x, rvaEnd is %x", rvaStart, rvaEnd);

    DWORD rvas = exports.AddressOfFunctions;
    DWORD ords = exports.AddressOfNameOrdinals;
    DWORD names = exports.AddressOfNames;

    BOOLEAN bFound = FALSE;

    LOG("[INFO] rva table @ %x, ordinal @ %x, names @ %x, number of names %x", rvas, ords, names, exports.NumberOfNames);

    for (DWORD i = 0; i < exports.NumberOfNames; i++)
    {
        WORD currentOrdinal;
        DWORD currentRva;
        DWORD currentNameRva;

        LOG("[INFO] Reading ordinal from address %x", Module->Start + ords + i * sizeof(WORD));
        status = MhvMemRead(Module->Start + ords + i * sizeof(WORD), sizeof(WORD), cr3, &currentOrdinal);
        if (!NT_SUCCESS(status))
        {
            //LOG("[ERROR] MhvMemRead status: 0x%x", status);
            continue;
        }


        LOG("[INFO] Reading rva from address %x", Module->Start + rvas + currentOrdinal * sizeof(DWORD));
        status = MhvMemRead(Module->Start + rvas + currentOrdinal * sizeof(DWORD), sizeof(DWORD), cr3, &currentRva);
        if (!NT_SUCCESS(status))
        {
            //LOG("[ERROR] MhvMemRead status: 0x%x", status);
            continue;
        }

        if (currentRva + Module->Start <= Address && currentRva + Module->Start >= Address + 32)
        {
            
            LOG("[INFO] Reading name RVA from address %x", Module->Start + names + i * sizeof(DWORD));
            bFound = TRUE;
            status = MhvMemRead(Module->Start + names + i * sizeof(DWORD), sizeof(DWORD), cr3, &currentNameRva);
            if (!NT_SUCCESS(status))
            {
                LOG("[ERROR] MhvMemRead status: 0x%x", status);
                continue;
            }

            LOG("[INFO] Name rva is %x, reading from %x", currentNameRva, Module->Start + currentNameRva);
            BYTE FunctionName[20];

            status = MhvMemRead(Module->Start + currentNameRva, 20, cr3, FunctionName);

            if (!NT_SUCCESS(status))
            {
                LOG("[ERROR] MhvMemRead status: 0x%x", status);
                continue;
            }

            LOG("[INFO] Function is %s", FunctionName);
        }

    }
    
    if (!bFound)
    {
        LOG("[INFO] Function was not found");
    }
    
}

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
    DWORD last = 0;
    while (Path[i] != 0)
    {
        if (Path[i] == '\\')
        {
            last = i;
        }
        i++;
    }
    if (last == 0)
    {
        last--;
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
    NTSTATUS status;

    //__vmx_vmread(VMX_GUEST_LINEAR_ADDRESS, &address);

    address = pHook->GuestLinearAddress + (((QWORD)Context) & 0xFFF);

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
            return STATUS_SUCCESS_DISABLE_INTERRUPTS;
        }

        if (strcmp(MhvGetNameFromPath(pModAttacker->Name), MhvGetNameFromPath(pModVictim->Name)) == 0)
        {
            return STATUS_SUCCESS_DISABLE_INTERRUPTS;
        }
    }

    //MhvFindFunctionByAddress(pModVictim, address);

    PEVENT evt = MhvCreateModuleAlert(pModAttacker, pModVictim, Rip, address);

    status = MhvExceptAlert(evt);

    if (NT_SUCCESS(status))
    {
        LOG("[INFO] Alert succesfully excepted!");

        RemoveEntryList(&evt->Link);

        MemFreeContiguosMemory(evt);

        return STATUS_SUCCESS_DISABLE_INTERRUPTS;
    }

    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~ALERT~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    LOG("Process -> %s Pid %d Cr3 %x", pProc->Name, pProc->Pid, pProc->Cr3);
    LOG("Attacker -> %s RIP %x", pModAttacker == NULL ? "<unknown>" : pModAttacker->Name, Rip);
    LOG("Victim -> %s address %x", pModVictim->Name, address);
    LOG("[INFO] Hook @ %x physical: %x virtual: %x, offset: %x", pHook, pHook->GuestPhysicalAddress, pHook->GuestLinearAddress, pHook->Offset);
    LOG("[INFO] Dumping instructions from %x", Rip);

    QWORD currentRip = Rip;

    for (DWORD i = 0; i < evt->ModuleAlertEvent.NumberOfInstructions; i++)
    {
        LOG("[INFO] %x: %s : %s (%d)", currentRip, evt->ModuleAlertEvent.Instructions[i].Instruction, ZydisMnemonicGetString(evt->ModuleAlertEvent.Instructions[i].Mnemonic), evt->ModuleAlertEvent.Instructions[i].Mnemonic);
        currentRip += evt->ModuleAlertEvent.Instructions[i].Length;
    }

    BOOLEAN shouldAllow = !!(pProc->ProtectionInfo & 0x10);

    LOG("[INFO] Current process has %s protection, will %s the writing!", shouldAllow ? "ALLOW" : "NOT ALLOW", shouldAllow ? "not block" : "block");

    if (shouldAllow)
    {
        evt->ModuleAlertEvent.Action = mhvActionAllowed;

        return STATUS_SUCCESS_DISABLE_INTERRUPTS;
    }

    evt->ModuleAlertEvent.Action = mhvActionNotAllowed;

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
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
        return STATUS_SUCCESS;
    }

    // we are not interested in unprotected processes
    if (!pProc->ProtectionInfo)
    {
        return STATUS_SUCCESS;
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
        return STATUS_SUCCESS;
    }
    
    RemoveEntryList(&pModFound->Link);
    
    LOG("[INFO] Module %s [%x %x] in Process %d is unloading", pModFound->Name, pModFound->Start, pModFound->End, pModFound->Process->Pid);

    MhvCreateModuleUnloadEvent(pModFound);

    MhvDeleteHookByOwner(pModFound);

    LOG("[INFO] Module %s unhooked succesfully!", pModFound->Name);

    MemFreeContiguosMemory(pModFound->Name);
    MemFreeContiguosMemory(pModFound);

    return STATUS_SUCCESS;
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

    //MhvFindFunctionByAddress(Module, NULL);

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

MOD_PROTECTION_INFO gProtectedModules[] = {
    {"\\Windows\\System32\\ntdll.dll", 0x1},
    {"\\Windows\\System32\\kernel32.dll", 0x2},
    {"\\Windows\\System32\\KernelBase.dll", 0x4}
};


NTSTATUS
MhvModBlockDll(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    PEPT_HOOK pHook = Hook;
    PBYTE p = MhvTranslateVa(pHook->GuestLinearAddress, Cr3, NULL);
    PMHVMODULE pMod = pHook->Owner;
    PMHVPROCESS pProc = pMod->Process;
    PEVENT pEvent = MhvCreateDllBlockEvent(pProc, pMod->Name);

    LOG("[INFO] Blocked module load %s detected in process %s (%d)", pMod->Name, pProc->Name, pProc->Pid);
    if ((pProc->ProtectionInfo & 0x10) == 0)
    {
        p[0] = 'B';
        p[1] = 'L';
        pEvent->DllBlockEvent.Action = mhvActionNotAllowed;
        LOG("[INFO] Will block!");
    }
    else
    {
        LOG("[INFO] Will allow!");
        pEvent->DllBlockEvent.Action = mhvActionAllowed;
    }

    MhvDeleteHookHierarchy(pHook);
    return STATUS_SUCCESS;
}

BOOLEAN 
MhvIsModuleProtected(
    PMHVPROCESS Process,
    PMHVMODULE Module
)
{
    if (!Process->ProtectionInfo)
    {
        return FALSE;
    }

    for (DWORD i = 0; i < ARRAYSIZE(gProtectedModules); i++)
    {
        if (strcmp(Module->Name, gProtectedModules[i].Name) == 0)
        {
            if ((Process->ProtectionInfo & gProtectedModules[i].Protection) != 0)
            {
                return TRUE;
            }
        }
    }

    return FALSE;

}



NTSTATUS
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
        if (NULL == name)
        {
            LOG("[INFO] Null pointer is coming to you");
        }
        memset_s(name, 0, NameLength / 2 + 1);
        PMHVMODULE pMod = MemAllocContiguosMemory(sizeof(MHVMODULE));
        if (NULL == pMod)
        {
            LOG("[INFO] Null pointer is coming to you");
        }
        memset_s(pMod, 0, sizeof(MHVMODULE));

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

        if (MhvIsModuleBlocked(pMod->Name, Process))       
        {
            LOG("[INFO] Module %s is blocked, will hook...", pMod->Name);

            PEPT_HOOK pHook = MhvCreateEptHook(pGuest.Vcpu,
                MhvTranslateVa(pMod->Start, Process->Cr3, NULL),
                EPT_WRITE_RIGHT,
                Process->Cr3,
                pMod->Start,
                NULL,
                MhvModBlockDll,
                PAGE_SIZE,
                TRUE
            );
            pHook->Owner = pMod;

            if ((Process->ProtectionInfo & 0x10) == 0)
            {
                return STATUS_SUCCESS;
            }
        }

        InitializeListHead(&pMod->Hooks);

        LOG("[Process %s] Module %s just loaded at [%x -> %x]", Process->Name, pMod->Name, pMod->Start, pMod->End);

        InsertTailList(&(Process->Modules), &(pMod->Link));

        MhvCreateModuleLoadEvent(pMod);

        // at this point we don't care anymore for this module if it is not protected...
        if (!MhvIsModuleProtected(Process, pMod))
        {
            return STATUS_SUCCESS;
        }

        PBYTE pSig = MhvTranslateVa(pMod->Start, Process->Cr3, NULL);

        if (pSig != NULL && pSig[0] == 'M' && pSig[1] == 'Z')
        {
            LOG("[INFO] (proc %s, %d) Module @%x %x %s [%x %x] is ready to be hooked, headers in memory!", Process->Name, Process->Pid, pMod, pMod->Name, pMod->Start, pMod->End);
            MhvHookModule(pMod);
            return STATUS_SUCCESS;
        }
        else if (pSig != NULL)
        {
            LOG("[INFO] module %s is mapped but signature does not match!", pMod->Name);
            return STATUS_SUCCESS;
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

    return STATUS_SUCCESS;
}


BYTE nameString[0x1000];

NTSTATUS
MhvGetVadName(
    PMMVAD_SHORT64 Vad,
    PMHVPROCESS Process,
    QWORD Cr3
)
{

    PBYTE ctlArea, fileObject;
    WORD nameLength;
    QWORD nameGva;
    NTSTATUS status;

    status = MhvMemRead(Vad->Subsection, 8, Cr3, &ctlArea);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed at addres %x", Vad->Subsection);
        return STATUS_SUCCESS;
    }

    status = MhvMemRead(ctlArea + 0x40, 8, Cr3, &fileObject);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed at addres %x", ctlArea + 0x40);
        return STATUS_SUCCESS;
    }

    fileObject = ((QWORD) fileObject) & 0xFFFFFFFFFFFFFFF0;

    status = MhvMemRead(fileObject + 0x58, 2, Cr3, &nameLength);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed at addres %x", fileObject + 0x58);
        return STATUS_SUCCESS;
    }

    MhvMemRead(fileObject + 0x60, 8, Cr3, &nameGva);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed at addres %x", fileObject + 0x60);
        return STATUS_SUCCESS;
    }

    status = MhvMemRead(nameGva, nameLength, Cr3, nameString);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed at addres %x", nameGva);
        return STATUS_SUCCESS;
    }

    QWORD s1 = Vad->StartingVpn;
    QWORD s2 = Vad->StartingVpnHigh;
    QWORD f1 = Vad->EndingVpn;
    QWORD f2 = Vad->EndingVpnHigh;

    QWORD start = (s1 | (s2 << 32)) << 12;

    QWORD finish = (f1 | (f2 << 32)) << 12;

    //LOG("[INFO] start %x end %x namelength %x", start, finish, nameLength);

    return MhvInsertModuleInListIfNotExistent(Process, start, finish, nameString, nameLength);

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
    NTSTATUS status;
    status = MhvMemRead(Node, sizeof(MMVAD_SHORT64), currentCr3, &pVad);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed on reading %x", Node);
        return;
    }

    if (pVad.Right != 0)
    {
        MhvIterateVadsRecursively(pVad.Right, Process);
    }

    if (pVad.VadFlags.VadType == 2)
    {
        MhvGetVadName(&pVad, Process, currentCr3);
    }

    if (pVad.Left != 0)
    {
        MhvIterateVadsRecursively(pVad.Left, Process);
    }


}

VOID
MhvIterateVadList(
    PMHVPROCESS Process
)
{
    MhvIterateVadsRecursively(Process->VadRoot, Process);
}


NTSTATUS
MhvNewModuleLoaded(
    PPROCESOR Context
)
{
    NTSTATUS status;
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
        return STATUS_SUCCESS;
    }

    if (!pProc->ProtectionInfo)
    {
        return STATUS_SUCCESS;
    }

    status = MhvMemRead(Context->context._rcx, sizeof(MMVAD_SHORT64), currentCr3, &pVad);
    if (!NT_SUCCESS(status))
    {
        LOG("[ERROR] MhvMemRead failed on address %x", Context->context._rcx);
        return STATUS_SUCCESS;
    }

    if (pVad.VadFlags.VadType == 2)
    {
        return MhvGetVadName(&pVad, pProc, currentCr3);
    }
    
    return STATUS_SUCCESS;
}
