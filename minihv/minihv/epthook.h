#ifndef _EPTHOOK_H
#define _EPTHOOK_H
#include "minihv.h"
#include "ntstatus.h"
#include "acpica.h"

typedef NTSTATUS
(*PFUNC_EptCallback)(
    PVOID Processor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
    );

typedef struct _EPT_HOOK
{
    QWORD GuestLinearAddress;
    QWORD GuestPhysicalAddress;
    QWORD Cr3;
    QWORD Offset;
    PFUNC_EptCallback PostActionCallback;
    PFUNC_EptCallback PreActionCallback;
    QWORD TimesCalled;
} EPT_HOOK, *PEPT_HOOK;

VOID
MhvHandleEptViolation(
    PVOID Processor
);

NTSTATUS
MhvLdrWrittenCallback(
    PVOID Processor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
);

NTSTATUS
MhvLdrAboutToBeWritten(
    PVOID Processor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
);


EPT_HOOK gEptHooks[1000];
QWORD gNumberOfEptHooks;
ACPI_SPINLOCK gEptLock;

#endif