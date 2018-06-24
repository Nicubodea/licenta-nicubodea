#pragma once
#include "structures.h"
#include "_wdk.h"

typedef struct _GUEST
{
    PROCESSOR* Vcpu;
    DWORD NumberOfVcpu;

    LIST_ENTRY EptHooksList;
    LIST_ENTRY ToAppendHooks;
    LIST_ENTRY PtHookList;
    LIST_ENTRY ProcessList;
    LIST_ENTRY ApiHookList;
    LIST_ENTRY ExceptionsList;
    PEPT_HOOK ToDelete[100];
    DWORD     NrToDelete;
    QWORD SystemCr3;

    VOID* GlobalLock;

} GUEST, *PGUEST;


GUEST pGuest;

VOID
MhvInitGuestState();