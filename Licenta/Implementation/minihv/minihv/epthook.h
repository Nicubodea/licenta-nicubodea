#ifndef _EPTHOOK_H
#define _EPTHOOK_H
#include "minihv.h"
#include "ntstatus.h"
#include "acpica.h"
#include "_wdk.h"

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
    LIST_ENTRY Link;
    QWORD GuestLinearAddress;
    QWORD GuestPhysicalAddress;
    QWORD Cr3;
    QWORD Offset;
    PFUNC_EptCallback PostActionCallback;
    PFUNC_EptCallback PreActionCallback;
    QWORD TimesCalled;
    QWORD Flags;
    QWORD AccessHooked;
    QWORD Size;
    QWORD WhatIsThere;
    struct _EPT_HOOK* LinkHook;
    struct _EPT_HOOK* ParentHook;

    PVOID Owner;
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

ACPI_SPINLOCK gEptLock;

#endif