#include "vmxcomm.h"
#include "vmxop.h"
#include "alert.h"
#include "winproc.h"

NTSTATUS
MhvHandleInterfaceComm(
    PPROCESOR Processor
)
{
    QWORD cr3;
    PBYTE mapping;
    NTSTATUS status;

    if (Processor->context._rbx != 0xb0dea)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (Processor->context._rcx != mhvCommunicationAddProtection &&
        Processor->context._rcx != mhvCommunicationGetEvent &&
        Processor->context._rcx != mhvCommunicationAddAlert) {
        return STATUS_UNSUCCESSFUL;
    }

    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    mapping = MhvTranslateVa(Processor->context._rdx, cr3, NULL);
    if (mapping == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (Processor->context._rcx == mhvCommunicationGetEvent)
    {
        status = MhvGetFirstEvent(Processor->context._rdx, cr3);
        Processor->context._rax = status;
    }

    if (Processor->context._rcx == mhvCommunicationAddAlert)
    {
        status = MhvExceptNewAlertRequest(Processor->context._rdx, cr3);
        Processor->context._rax = status;
    }

    if (Processor->context._rcx == mhvCommunicationAddProtection)
    {
        status = MhvProtectProcessRequest(Processor->context._rdx, cr3);
        Processor->context._rax = status;
    }

    return STATUS_SUCCESS;
}