#include "guest.h"
#include "vmxmtf.h"
#include "structures.h"
#include "vmxop.h"
#include "vmxept.h"

#define FLAG_SWAP 0x20

VOID
MhvHandleMTF(
    PVOID Processor
) 
{
    PPROCESOR pProc = Processor;
    QWORD cr3 = 0;
    QWORD rip = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    __vmx_vmread(VMX_GUEST_RIP, &rip);
    PQWORD physLinearAddr = MhvTranslateVa(pProc->LastGLA, cr3, NULL);

    QWORD procControls = 0;
    __vmx_vmread(VMX_PROC_CONTROLS_FIELD, &procControls);
    procControls &= ~(1 << 27);
    __vmx_vmwrite(VMX_PROC_CONTROLS_FIELD, procControls);

    if (pProc->LastInterruptDisabled)
    {
        pProc->LastInterruptDisabled = FALSE;
        
        QWORD rflags = 0; 
        __vmx_vmread(VMX_GUEST_RFLAGS, &rflags);
        rflags |= (1 << 9);
        __vmx_vmwrite(VMX_GUEST_RFLAGS, rflags);
    }

    if (pProc->LastSTIDisabled)
    {
        pProc->LastSTIDisabled = FALSE;

        QWORD interState = 0;

        __vmx_vmread(VMX_GUEST_INTERUPT_STATE, &interState);

        interState |= 1;

        __vmx_vmwrite(VMX_GUEST_INTERUPT_STATE, interState);
    }

    /*
    if (pProc->LastMOVSSDisabled)
    {

        pProc->LastMOVSSDisabled = FALSE;

        QWORD interState = 0;

        __vmx_vmread(VMX_GUEST_INTERUPT_STATE, &interState);

        interState |= 2;

        __vmx_vmwrite(VMX_GUEST_INTERUPT_STATE, interState);
    }
    */
    __vmx_vmwrite(VMX_EPT_POINTER, pProc->EptPointer);

    __writecr3(__readcr3());

    LIST_ENTRY* list = pGuest.EptHooksList.Flink;

    if (pProc->InvalidGLA)
    {
        physLinearAddr = pProc->LastGPA;
        pProc->InvalidGLA = FALSE;
    }

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if ((pHook->Flags & 0x10) != 0 || (pHook->Flags & 0x40) != 0)
        {
            continue;
        }

        if (((pHook->GuestLinearAddress & (~0xFFF)) == (pProc->LastGLA & (~0xFFF)) || pProc->LastGLA == NULL || pHook->GuestLinearAddress == NULL) &&
            pHook->GuestPhysicalAddress == ((QWORD)physLinearAddr & (~0xFFF)) &&
            pHook->Offset <= ((QWORD)physLinearAddr & 0xFFF) &&
            pHook->Offset + pHook->Size > ((QWORD)physLinearAddr & 0xFFF)
            )
        {

            if (pHook->PostActionCallback != NULL)
            {
                //LOG("[INFO] Calling POST callback!");
                pHook->PostActionCallback(pProc, pHook, rip, cr3, physLinearAddr);

            }

            if (pHook->LinkHook && (pHook->LinkHook->Flags & FLAG_SWAP) != 0 && (pHook->LinkHook->Flags & 0x10) == 0)
            {
                //LOG("[CALLING SWAP CALLBACK]");
                pHook->LinkHook->PostActionCallback(pProc, pHook->LinkHook, rip, cr3, physLinearAddr);
            }
        }

    }

    MyInvEpt(2, NULL);
}