#pragma once
#include <windows.h>
#include "exports.h"

typedef unsigned __int64 QWORD;

typedef struct _HOOK_DATA
{
    EXPORT* Export;
    HMODULE Module;
    PBYTE OriginalCode;
    PBYTE UnpatchedCode;
    DWORD NumberOfBytesPatched;
    QWORD JumpAddress;
    BYTE HookOrdinal;
    PBYTE OriginalAddress;
} HOOK_DATA, *PHOOK_DATA;


NTSTATUS
AvxEstablishApiHook(
    _In_ EXPORT* Export,
    _In_ HMODULE Module,
    _Out_ PHOOK_DATA* Hook,
    _In_ BYTE HookOrdinal
);

NTSTATUS
AvxPurgeApiHook(
    PHOOK_DATA HookData
);

extern "C" VOID
HandleFunctionCall(
    QWORD* StackFrame
);


VOID AvxNewHookCall(
    PHOOK_DATA Hook
);