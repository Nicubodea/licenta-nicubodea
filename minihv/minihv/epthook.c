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

    for (DWORD i = 0; i < gNumberOfEptHooks; i++)
    {
        if (gEptHooks[i].GuestLinearAddress == (linearAddr & (~0xFFF)) &&
            gEptHooks[i].GuestPhysicalAddress == (phys & (~0xFFF)) &&
            gEptHooks[i].Cr3 == cr3 &&
            gEptHooks[i].Offset == (phys & 0xFFF)
            )
        {
            if (gEptHooks[i].PreActionCallback == NULL)
            {
                // we should also have hooks with only post action callbacks
                action = 1;
                break;
            }
            NTSTATUS status = gEptHooks[i].PreActionCallback(Processor, &gEptHooks[i], rip, cr3, NULL);
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