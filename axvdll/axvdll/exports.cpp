#include "exports.h"
#include <ntstatus.h>
#include <stdio.h>

NTSTATUS
AvxFindAllExports(
    _In_ HMODULE Module,
    _Out_ DWORD* NumberOfExports,
    _Out_ PEXPORT* Exports
)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS64 pNth;
    PIMAGE_DATA_DIRECTORY pData;
    PIMAGE_SECTION_HEADER pSect;
    DWORD nrOfSections;
    PIMAGE_EXPORT_DIRECTORY pExports;
    PDWORD pEat, pRvat;
    PWORD pOrd;
    DWORD i, rvaStart = 0, rvaEnd = 0;

    if (NULL == Module)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (NULL == NumberOfExports)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Exports)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    pDos = (PIMAGE_DOS_HEADER)Module;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return STATUS_FILE_CORRUPT_ERROR;
    }

    pNth = (PIMAGE_NT_HEADERS64)(((PBYTE)pDos) + pDos->e_lfanew);
    pData = pNth->OptionalHeader.DataDirectory;

    if (pData[0].VirtualAddress == 0)
    {
        return STATUS_INVALID_ADDRESS;
    }

    pSect = (PIMAGE_SECTION_HEADER)(((PBYTE)pNth) + sizeof(IMAGE_FILE_HEADER) + pNth->FileHeader.SizeOfOptionalHeader + 4);

    pExports = (PIMAGE_EXPORT_DIRECTORY)(((PBYTE)pDos) + pData[0].VirtualAddress);

    for (DWORD i = 0; i < pNth->FileHeader.NumberOfSections; i++)
    {
        //printf("Section %s\n", pSect[i].Name);
        if (pSect[i].VirtualAddress <= pData[0].VirtualAddress && pSect[i].VirtualAddress + pSect[i].Misc.VirtualSize > pData[0].VirtualAddress)
        {
            rvaStart = pSect[i].VirtualAddress;
            rvaEnd = pSect[i].VirtualAddress + pSect[i].Misc.VirtualSize;
        }
    }

    //printf("Found section (%p -> %p)\n", rvaStart, rvaEnd);

    pEat = (PDWORD)(((PBYTE)pDos) + pExports->AddressOfNames);
    pRvat = (PDWORD)(((PBYTE)pDos) + pExports->AddressOfFunctions);
    pOrd = (PWORD)(((PBYTE)pDos) + pExports->AddressOfNameOrdinals);

    *NumberOfExports = pExports->NumberOfNames;

    *Exports = (PEXPORT)malloc(sizeof(EXPORT) * (*NumberOfExports));
    DWORD base = pExports->Base;

    //printf("base: %d\n", base);

    for (i = 0; i < pExports->NumberOfNames; i++)
    {
        (*Exports)[i].ExportRVA = pRvat[pOrd[i]];
        (*Exports)[i].ExportOrdinal = pOrd[i] + base;
        (*Exports)[i].IsForwarded = FALSE;

        if (pRvat[pOrd[i]] >= rvaStart && pRvat[pOrd[i]] < rvaEnd)
        {
            (*Exports)[i].IsForwarded = TRUE;
        }

        PCHAR pName = (PCHAR)(((PBYTE)pDos) + pEat[i]);

        strcpy_s((*Exports)[i].ExportName, MAX_PATH, pName);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
AvxReleaseExports(
    _In_ PEXPORT* Exports
)
{
    free(*Exports);
    return STATUS_SUCCESS;
}