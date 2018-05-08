#pragma once
#include <windows.h>

typedef struct _EXPORT
{
    CHAR ExportName[MAX_PATH];
    DWORD ExportRVA;
    BOOLEAN IsForwarded;
    WORD ExportOrdinal;
} EXPORT, *PEXPORT;

NTSTATUS
AvxFindAllExports(
    _In_ HMODULE Module,
    _Out_ DWORD* NumberOfExports,
    _Out_ PEXPORT* Exports
    );

NTSTATUS
AvxReleaseExports(
    _In_ PEXPORT* Exports
);