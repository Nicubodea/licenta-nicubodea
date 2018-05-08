#ifndef _VMXEPT_H
#define _VMXEPT_H
#include "minihv.h"
#include "epthook.h"
#define EPT_TABLE_ENTRIES_SIZE      512
#define EPT_4LEVELS_POINTER         0x18

#define EPT_FULL_RIGHTS             0x7
#define EPT_READ_RIGHT              0x1
#define EPT_WRITE_RIGHT             0x2
#define EPT_EXEC_RIGHT              0x4

typedef struct _EPT_PDE_ENTRY {
    QWORD PhysicalAddress[EPT_TABLE_ENTRIES_SIZE];
} EPT_PDE_ENTRY, *PEPT_PDE_ENTRY;

typedef struct _EPT_PDPE_ENTRY {
    PEPT_PDE_ENTRY PteArray[EPT_TABLE_ENTRIES_SIZE];
} EPT_PDPE_ENTRY, *PEPT_PDPE_ENTRY;

typedef struct _EPT_PML4_ENTRY {
    PEPT_PDPE_ENTRY PdeArray[EPT_TABLE_ENTRIES_SIZE];
} EPT_PML4_ENTRY, *PEPT_PML4_ENTRY;

typedef struct _EPT_PML4_POINTER
{
    PEPT_PML4_ENTRY PdpeArray[EPT_TABLE_ENTRIES_SIZE];
} EPT_POINTER, *PEPT_POINTER;


PEPT_POINTER
MhvMakeEpt(
);

PEPT_HOOK
MhvEptMakeHook(
    PVOID               Procesor,
    QWORD               PhysPage,
    QWORD               AccessHooked,
    QWORD               Cr3,
    QWORD               GLA,
    PFUNC_EptCallback   PreCallback,
    PFUNC_EptCallback   PostCallback

);

VOID
MhvEptPurgeHook(
    PVOID       Procesor,
    QWORD       PhysPage
);

#endif