#ifndef _WINMOD_H
#define _WINMOD_H

#include "minihv.h"
#include "ntstatus.h"

typedef struct _UM_MODULE {
    BYTE Name[256];
    QWORD ModuleBase;
    QWORD ModuleSize;
    QWORD NameSize;
} UM_MODULE, *PUM_MODULE;

NTSTATUS
MhvGetModFromWrittenEntry(
    PVOID Processor,
    QWORD Entry,
    QWORD Cr3,
    UM_MODULE* Module
);
#endif