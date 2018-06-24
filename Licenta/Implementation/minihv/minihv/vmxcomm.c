#include "vmxcomm.h"
#include "vmxop.h"
#include "alert.h"
#include "winproc.h"
#include "alloc.h"
#include "winmod.h"

typedef struct _BLOCKED_DLL {
    LIST_ENTRY Link;
    BYTE       Name[256];
} BLOCKED_DLL, *PBLOCKED_DLL;

LIST_ENTRY gBlockedDlls;
BOOLEAN bBlockedDllsInitialized = FALSE;

BOOLEAN
MhvIsModuleBlocked(
    PCHAR DllName,
    PMHVPROCESS Process
) 
{
    if (!bBlockedDllsInitialized)
    {
        bBlockedDllsInitialized = TRUE;
        InitializeListHead(&gBlockedDlls);
    }

    if ((Process->ProtectionInfo & 0x20) == 0)
    {
        return FALSE;
    }

    LIST_ENTRY* list = gBlockedDlls.Flink;
    while (list != &gBlockedDlls)
    {
        PBLOCKED_DLL pDll = CONTAINING_RECORD(list, BLOCKED_DLL, Link);

        list = list->Flink;

        if (strcmp(pDll->Name, MhvGetNameFromPath(DllName)) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;

}

NTSTATUS
MhvHandleVerifyIfDllBlocked(
    QWORD DllAddress,
    QWORD Cr3
)
{
    return STATUS_SUCCESS;

}

NTSTATUS
MhvAddBlockedDll(
    QWORD DllAddress,
    QWORD Cr3
)
{
    if (!bBlockedDllsInitialized)
    {
        bBlockedDllsInitialized = TRUE;
        InitializeListHead(&gBlockedDlls);
    }

    PBLOCKED_DLL pDll = MemAllocContiguosMemory(sizeof(BLOCKED_DLL));
    if (NULL == pDll)
    {
        LOG("[INFO] Null pointer is coming to you");
    }
    memset_s(pDll, 0, sizeof(BLOCKED_DLL));
    
    MhvMemRead(DllAddress, 256, Cr3, pDll->Name);

    InsertTailList(&gBlockedDlls, &pDll->Link);

    LOG("[INFO] Adding blocked dll %s", pDll->Name);

    return STATUS_SUCCESS;
}

NTSTATUS
MhvRemoveBlockedDll(
    QWORD DllAddress,
    QWORD Cr3
)
{
    if (!bBlockedDllsInitialized)
    {
        bBlockedDllsInitialized = TRUE;
        InitializeListHead(&gBlockedDlls);
    }

    BOOLEAN bFound = FALSE;
    BYTE currentName[256] = { 0 };

    MhvMemRead(DllAddress, 256, Cr3, currentName);

    LIST_ENTRY* list = gBlockedDlls.Flink;
    while (list != &gBlockedDlls)
    {
        PBLOCKED_DLL pDll = CONTAINING_RECORD(list, BLOCKED_DLL, Link);

        list = list->Flink;

        if (strcmp(pDll->Name, currentName) == 0)
        {
            LOG("[INFO] Removing blocked DLL %s", pDll->Name);
            RemoveEntryList(&pDll->Link);
            MemFreeContiguosMemory(pDll);
            //return STATUS_SUCCESS;
            bFound = TRUE;
        }

    }

    if (!bFound)
    {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
MhvHandleInterfaceComm(
    PPROCESOR Processor
)
{
    QWORD cr3;
    PBYTE mapping;
    NTSTATUS status;

    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    if (Processor->context._rbx == 0xb10c)
    {
        status = MhvHandleVerifyIfDllBlocked(Processor->context._rdx, cr3);
        Processor->context._rax = status;
        return STATUS_SUCCESS;
    }

    if (Processor->context._rbx != 0xb0dea)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (Processor->context._rcx != mhvCommunicationAddProtection &&
        Processor->context._rcx != mhvCommunicationGetEvent &&
        Processor->context._rcx != mhvCommunicationAddAlert &&
        Processor->context._rcx != mhvCommunicationAddBlockedDll &&
        Processor->context._rcx != mhvCommunicationRemoveBlockedDll) {
        return STATUS_UNSUCCESSFUL;
    }

    

    mapping = MhvTranslateVa(Processor->context._rdx, cr3, NULL);
    if (mapping == 0)
    {
        LOG("[INFO] Given RDX %x not present in memory!", Processor->context._rdx);
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
    if (Processor->context._rcx == mhvCommunicationAddBlockedDll)
    {
        status = MhvAddBlockedDll(Processor->context._rdx, cr3);
        Processor->context._rax = status;
    }
    if (Processor->context._rcx == mhvCommunicationRemoveBlockedDll)
    {
        status = MhvRemoveBlockedDll(Processor->context._rdx, cr3);
        Processor->context._rax = status;
    }

    return STATUS_SUCCESS;
}