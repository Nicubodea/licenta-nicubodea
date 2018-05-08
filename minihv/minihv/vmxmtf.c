#include "vmxmtf.h"
#include "structures.h"
#include "vmxop.h"
#include "vmxept.h"
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

    __vmx_vmwrite(VMX_EPT_POINTER, pProc->EptPointer);

    for (DWORD i = 0; i < gNumberOfEptHooks; i++)
    {
        if (gEptHooks[i].Offset == (pProc->LastGLA & 0xFFF) 
            && ((QWORD)physLinearAddr & (~0xFFF)) == gEptHooks[i].GuestPhysicalAddress)
        {
            gEptHooks[i].PostActionCallback(pProc, &gEptHooks[i], rip, cr3, *physLinearAddr);
        }
    }

}