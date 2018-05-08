#ifndef _VMXHOOH_H
#define _VMXHOOK_H
#include "ntstatus.h"
#include "structures.h"
#include "_wdk.h"
VOID
MhvHookFunctionsInMemory(
    VOID
);

QWORD 
MhvFindKernelBase(
    QWORD Start
);

NTSTATUS
MhvVerifyIfHookAndNotify(
    QWORD Rip
);

typedef VOID
(*PEMU_Callback)(
    PPROCESOR Processor
    );

typedef struct _API_SIGNATURE {
    BYTE Name[64];
    DWORD SigLength;
    WORD Signature[0x64];
    PEMU_Callback EmuCallback;
    PEMU_Callback ExecCallback;
} API_SIGNATURE, *PAPI_SIGNATURE;



typedef struct _HOOK {
    LIST_ENTRY Link;
    BYTE Name[64];
    QWORD Rip;
    PEMU_Callback Callback;
    PEMU_Callback CalledCallback;
} HOOK, *PHOOK;

QWORD gNumberOfHooks;

#define NR_OF_SIGNATURES 4
#endif