#ifndef _WINPROC_H
#define _WINPROC_H
#include "minihv.h"
#include "vmxop.h"
#include "winmod.h"
#include "_wdk.h"

typedef struct _PROTECTION_INFO 
{
    LIST_ENTRY Link;
    BYTE Name[16];
    DWORD Protection;
} PROTECTION_INFO, *PPROTECTION_INFO;

typedef struct _MOD_PROTECTION_INFO
{
    BYTE* Name;
    DWORD Protection;
} MOD_PROTECTION_INFO, *PMOD_PROTECTION_INFO;

typedef struct _MHVPROCESS
{
    LIST_ENTRY Link;
    BYTE Name[16];
    QWORD Cr3;
    QWORD Pid;
    QWORD VadRoot;
    LIST_ENTRY ProcessHooks;
    QWORD NumberOfHooks;
    LIST_ENTRY Modules;
    QWORD NumberOfModules;
    DWORD ProtectionInfo;
    QWORD Eprocess;
} MHVPROCESS, *PMHVPROCESS;


typedef struct _MHVMODULE
{
    LIST_ENTRY Link;
    PBYTE Name;
    PMHVPROCESS Process;
    QWORD Start;
    QWORD End;
    LIST_ENTRY Hooks;
} MHVMODULE, *PMHVMODULE;

typedef struct _PEB64
{
    BYTE        Reserved1[2];
    BYTE        BeingDebugged;
    BYTE        Reserved2[1];
    QWORD       Reserved3[2];           // PVOID
    QWORD       Ldr;                    // PPEB_LDR_DATA
    QWORD       ProcessParameters;      // PRTL_USER_PROCESS_PARAMETERS
    QWORD       Reserved4[3];           // PVOID
    QWORD       AtlThunkSListPtr;       // PVOID
    QWORD       Reserved5;              // PVOID
    DWORD       Reserved6;
    QWORD       Reserved7;              // PVOID
    DWORD       Reserved8;
    DWORD       AtlThunkSListPtr32;
    QWORD       Reserved9[45];          // PVOID
    BYTE        Reserved10[96];
    QWORD       PostProcessInitRoutine; // PPS_POST_PROCESS_INIT_ROUTINE
    BYTE        Reserved11[128];
    QWORD       Reserved12[1];          // PVOID
    DWORD       SessionId;
} PEB64, *PPEB64;

DWORD gNumberOfActiveProcesses;


PMHVMODULE
MhvGetModuleByAddress(
    PMHVPROCESS Process,
    QWORD Address
);

VOID
MhvReiterateProcessModules(

);

NTSTATUS
MhvInsertProcessInList(
    PPROCESOR Context
);

NTSTATUS
MhvDeleteProcessFromList(
    PPROCESOR Context
);

PMHVPROCESS
MhvFindProcessByCr3(
    QWORD Cr3
);

PMHVPROCESS
MhvFindProcessByEprocess(
    QWORD Eprocess
);

NTSTATUS
MhvProtectProcessRequest(
    QWORD Address,
    QWORD Cr3
);

#endif