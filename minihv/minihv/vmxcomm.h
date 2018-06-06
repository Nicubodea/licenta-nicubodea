#pragma once
#include "minihv.h"
#include "structures.h"

NTSTATUS
MhvHandleInterfaceComm(
    PPROCESOR Processor
);

typedef enum _COMM_TYPE {
    mhvCommunicationAddProtection,
    mhvCommunicationGetEvent,
    mhvCommunicationAddAlert
} COMM_TYPE;