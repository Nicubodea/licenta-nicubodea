#pragma once
#include "minihv.h"
#include "structures.h"
#include "winproc.h"

NTSTATUS
MhvHandleInterfaceComm(
    PPROCESOR Processor
);

typedef enum _COMM_TYPE {
    mhvCommunicationAddProtection,
    mhvCommunicationGetEvent,
    mhvCommunicationAddAlert,
    mhvCommunicationAddBlockedDll,
    mhvCommunicationRemoveBlockedDll
} COMM_TYPE;

BOOLEAN
MhvIsModuleBlocked(
    PCHAR DllName,
    PMHVPROCESS Process
);