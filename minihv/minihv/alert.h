#pragma once

#include "minihv.h"
#include "Zydis/Zydis.h"
#include "winproc.h"

typedef enum _EVENTTYPE {
    mhvEventProcessCreate,
    mhvEventProcessTerminate,
    mhvEventModuleLoad,
    mhvEventModuleUnload,
    mhvEventModuleAlert
} EVENTTYPE;

typedef struct _EVENT_PROCESS_CREATE {
    BYTE Name[16];
    QWORD Cr3;
    QWORD Pid;
    QWORD Eprocess;
} EVENT_PROCESS_CREATE, *PEVENT_PROCESS_CREATE;

typedef struct _EVENT_PROCESS_TERMINATE {
    BYTE Name[16];
    QWORD Cr3;
    QWORD Pid;
    QWORD Eprocess;
} EVENT_PROCESS_TERMINATE, *PEVENT_PROCESS_TERMINATE;

typedef struct _EVENT_MODULE {
    BYTE Name[256];
    QWORD Start;
    QWORD End;
} EVENT_MODULE, *PEVENT_MODULE;

typedef struct _EVENT_MODULE_LOAD {
    EVENT_MODULE Module;
    BYTE ProcessName[16];
    QWORD Pid;
} EVENT_MODULE_LOAD, *PEVENT_MODULE_LOAD;

typedef struct _EVENT_MODULE_UNLOAD {
    EVENT_MODULE Module;
    BYTE ProcessName[16];
    QWORD Pid;
} EVENT_MODULE_UNLOAD, *PEVENT_MODULE_UNLOAD;

typedef struct _EVENT_INSTRUCTION {
    ZydisMnemonic Mnemonic;
    BYTE Instruction[128];
    DWORD Length;
} EVENT_INSTRUCTION, *PEVENT_INSTRUCTION;

typedef struct _EVENT_MODULE_ALERT {
    EVENT_MODULE Attacker;
    EVENT_MODULE Victim;
    QWORD Rip;
    QWORD Address;
    BYTE ProcessName[16];
    QWORD Pid;
    EVENT_INSTRUCTION Instructions[10];
    DWORD NumberOfInstructions;

} EVENT_MODULE_ALERT, *PEVENT_MODULE_ALERT;

typedef struct _EVENT {
    LIST_ENTRY Link;
    EVENTTYPE Type;
    union {
        EVENT_PROCESS_CREATE ProcessCreateEvent;
        EVENT_PROCESS_TERMINATE ProcessTerminateEvent;
        EVENT_MODULE_LOAD ModuleLoadEvent;
        EVENT_MODULE_UNLOAD ModuleUnloadEvent;
        EVENT_MODULE_ALERT ModuleAlertEvent;
    };
} EVENT, *PEVENT;

typedef struct _ALERT_EXCEPTION_SIGNATURE {
    ZydisMnemonic Mnemonic;
} ALERT_EXCEPTION_SIGNATURE, *PALERT_EXCEPTION_SIGNATURE;

typedef struct _ALERT_EXCEPTION {
    LIST_ENTRY Link;

    BYTE ProcessName[16];
    BYTE VictimName[256];
    BYTE AttackerName[256];

    ALERT_EXCEPTION_SIGNATURE Signatures[10];
    DWORD NumberOfSignatures;
    DWORD SignaturesNeededToMatch;

} ALERT_EXCEPTION, *PALERT_EXCEPTION;

PEVENT
MhvCreateProcessCreationEvent(
    PMHVPROCESS Process
);

PEVENT
MhvCreateProcessTerminationEvent(
    PMHVPROCESS Process
);

PEVENT
MhvCreateModuleLoadEvent(
    PMHVMODULE Module
);

PEVENT
MhvCreateModuleUnloadEvent(
    PMHVMODULE Module
);

PEVENT
MhvCreateModuleAlert(
    PMHVMODULE Attacker,
    PMHVMODULE Victim,
    QWORD Rip,
    QWORD Address
);

VOID
MhvEnqueueEvent(
    PEVENT Event
);

NTSTATUS
MhvGetFirstEvent(
    QWORD Address,
    QWORD Cr3
);

NTSTATUS
MhvExceptAlert(
    PEVENT Event
);


NTSTATUS
MhvExceptNewAlertRequest(
    QWORD Address,
    QWORD Cr3
);