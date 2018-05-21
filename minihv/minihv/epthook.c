#include "guest.h"
#include "epthook.h"
#include "structures.h"
#include "vmcsdef.h"
#include "winproc.h"
#include "winmod.h"


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

    __vmx_vmread(VMX_GUEST_LINEAR_ADDRESS, &linearAddr);
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    __vmx_vmread(VMX_GUEST_RIP, &rip);

    phys = MhvTranslateVa(linearAddr, cr3, NULL);


    //LOG("[INFO] Ept violation from %x on %x", rip, linearAddr);

    LIST_ENTRY* list = pGuest.EptHooksList.Flink;

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if ((pHook->GuestLinearAddress == (linearAddr & (~0xFFF)) || pHook->GuestLinearAddress == NULL) &&
            pHook->GuestPhysicalAddress == (phys & (~0xFFF)) &&
            (pHook->Cr3 == cr3 || pHook->Cr3 == NULL) &&
            pHook->Offset >= (phys & 0xFFF) && pHook->Offset < ((phys & 0xFFF) + pHook->Size)
            )
        {
            if (pHook->PreActionCallback == NULL)
            {
                // we should also have hooks with only post action callbacks
                action = 1;
                break;
            }
            //LOG("[INFO] calling preCallback");
            NTSTATUS status = pHook->PreActionCallback(Processor, pHook, rip, cr3, NULL);
            if (status == STATUS_SUCCESS)
            {
                action = 1;
            }
            else
            {
                action = 0;
            }
        }

    }

    if (action)
    {

        //LOG("[INFO] Will use MTF as callback returned TRUE or no callback was found!");
        __vmx_vmwrite(VMX_EPT_POINTER, ((QWORD)proc->FullRightsEptPointer | EPT_4LEVELS_POINTER));

        //replace with monitor trap flag here...
        QWORD rflags = 0;
        proc->LastInterruptDisabled = FALSE;

        
        __vmx_vmread(VMX_GUEST_RFLAGS, &rflags);

        if ((rflags & (1 << 9)) != 0)
        {
            rflags &= ~(1 << 9);
            __vmx_vmwrite(VMX_GUEST_RFLAGS, rflags);
            proc->LastInterruptDisabled = TRUE;
        }

        // activate the MTF
        QWORD procControls = 0;
        __vmx_vmread(VMX_PROC_CONTROLS_FIELD, &procControls);
        procControls |= (1 << 27);
        __vmx_vmwrite(VMX_PROC_CONTROLS_FIELD, procControls);

        __vmx_vmwrite(VMX_GUEST_INTERUPT_STATE, 0);

        proc->LastGLA = linearAddr;
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