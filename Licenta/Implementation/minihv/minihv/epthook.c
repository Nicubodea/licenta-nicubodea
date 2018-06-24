#include "guest.h"
#include "epthook.h"
#include "structures.h"
#include "vmcsdef.h"
#include "winproc.h"
#include "winmod.h"

#define max(a,b) a>b?a:b;

#define PML4_INDEX(Va) (((Va) & 0x0000ff8000000000) >> 39)
#define PDP_INDEX(Va) (((Va) & 0x0000007fc0000000) >> 30)
#define PD_INDEX(Va) (((Va) & 0x000000003fe00000) >> 21)
#define PT_INDEX(Va) (((Va) & 0x00000000001ff000) >> 12)
#define CLEAN_PHYS_ADDR(Addr) ((Addr) & 0x000FFFFFFFFFF000)

VOID
MhvHandleEptViolation(
    PVOID Processor
)
{
    PPROCESOR proc = Processor;
    QWORD linearAddr = 0;
    QWORD cr3 = 0;
    QWORD rip = 0;
    QWORD phys;
    QWORD action = 1;
    BOOLEAN found = FALSE;

    __vmx_vmread(VMX_GUEST_LINEAR_ADDRESS, &linearAddr);
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    __vmx_vmread(VMX_GUEST_RIP, &rip);
    QWORD eptp;
    __vmx_vmread(VMX_EPT_POINTER, &eptp);

    phys = MhvTranslateVa(linearAddr, cr3, NULL);

    BOOLEAN disableInterrupts = FALSE;

    QWORD qualification = 0;

    __vmx_vmread(VMX_EXIT_QUALIFICATION, &qualification);

    QWORD realAddress;
    __vmx_vmread(0x2400, &realAddress);

    
    LIST_ENTRY* list = pGuest.EptHooksList.Flink;

    if (realAddress != phys)
    {
        // Vmware mangles the GLA ......
        linearAddr = NULL;
        phys = realAddress;

    }

    PEPT_POINTER ept = CLEAN_PHYS_ADDR((QWORD)eptp);
    PEPT_PML4_ENTRY* pml4 = CLEAN_PHYS_ADDR((QWORD)ept->PdpeArray);
    PEPT_PDPE_ENTRY* pdpe = ((PEPT_PML4_ENTRY)CLEAN_PHYS_ADDR((QWORD)pml4[0]))->PdeArray;
    PEPT_PDE_ENTRY* pde = ((PEPT_PDPE_ENTRY)CLEAN_PHYS_ADDR((QWORD)pdpe[PDP_INDEX(phys)]))->PteArray;

    QWORD* pt = ((PEPT_PDE_ENTRY)CLEAN_PHYS_ADDR((QWORD)pde[PD_INDEX(phys)]))->PhysicalAddress;

    QWORD pte = pt[PT_INDEX(phys)];

    //LOG("[EPT VIOLATION] physical %x, rip %x", phys, rip);

    MemDumpAllocStats();

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if ((pHook->Flags & 0x10) != 0 || (pHook->Flags & 0x40) != 0)
        {
            continue;
        }


        if (((pHook->GuestLinearAddress & (~0xFFF)) == (linearAddr & (~0xFFF)) || pHook->GuestLinearAddress == NULL || linearAddr == NULL) &&
            pHook->GuestPhysicalAddress == (phys & (~0xFFF)) &&
            pHook->Offset <= (phys & 0xFFF) && pHook->Offset + pHook->Size > ((phys & 0xFFF))
            )
        {
            if (pHook->PreActionCallback == NULL)
            {
                // we should also have hooks with only post action callbacks
                continue;
            }
            //LOG("[INFO] calling preCallback");
            //LOG("[INFO] Calling PRECALLBACK on Hook @ %x with GLA: %x physical %x offset %x size %x flags %x", pHook, pHook->GuestLinearAddress, pHook->GuestPhysicalAddress, pHook->Offset, pHook->Size, pHook->Flags);

            NTSTATUS status = pHook->PreActionCallback(Processor, pHook, rip, cr3, phys);

            //LOG("[INFO] Pre callback returned %x", status);

            found = TRUE;
            if (status == STATUS_SUCCESS)
            {
                action = min(action, 1);
            }
            else if (status == STATUS_SUCCESS_DISABLE_INTERRUPTS)
            {
                action = min(action, 1);
                disableInterrupts = TRUE;
            }
            else
            {
                action = 0;
            }
        }

    }

    if (action || !found)
    {

        //__vmx_invept();

        //LOG("[INFO] Will use MTF as callback returned TRUE or no callback was found!");
        __vmx_vmwrite(VMX_EPT_POINTER, ((QWORD)proc->FullRightsEptPointer | EPT_4LEVELS_POINTER));

        __writecr3(__readcr3());

        //replace with monitor trap flag here...
        QWORD rflags = 0;
        proc->LastInterruptDisabled = FALSE;
        proc->LastSTIDisabled = FALSE;
        proc->LastMOVSSDisabled = FALSE;
        
        if (disableInterrupts)
        {
            __vmx_vmread(VMX_GUEST_RFLAGS, &rflags);

            if ((rflags & (1 << 9)) != 0)
            {
                rflags &= ~(1 << 9);
                __vmx_vmwrite(VMX_GUEST_RFLAGS, rflags);
                proc->LastInterruptDisabled = TRUE;
            }

            QWORD interruptState = 0;
            __vmx_vmread(VMX_GUEST_INTERUPT_STATE, &interruptState);

            if ((interruptState & 1) != 0)
            {
                interruptState &= (~1);
                proc->LastSTIDisabled = TRUE;
            }


            if ((interruptState & 2) != 0)
            {
                interruptState &= (~2);
                proc->LastMOVSSDisabled = TRUE;
            }

            __vmx_vmwrite(VMX_GUEST_INTERUPT_STATE, interruptState);
        }

        // activate the MTF
        QWORD procControls = 0;
        __vmx_vmread(VMX_PROC_CONTROLS_FIELD, &procControls);
        procControls |= (1 << 27);
        __vmx_vmwrite(VMX_PROC_CONTROLS_FIELD, procControls);

        proc->LastGLA = linearAddr;
        if (linearAddr == 0)
        {
            proc->InvalidGLA = TRUE;
            proc->LastGPA = phys;
        }

        MyInvEpt(2, NULL);
    }
    else
    {
        QWORD instrLength;
        __vmx_vmread(VMX_EXIT_INSTRUCTION_LENGTH, &instrLength);
        rip += instrLength;
        __vmx_vmwrite(VMX_GUEST_RIP, rip);
    }


    return;
}