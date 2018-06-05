#ifndef _WINMOD_H
#define _WINMOD_H


#include "minihv.h"
#include "ntstatus.h"
#include "structures.h"
#include "winproc.h"

typedef struct _MMVAD_SHORT64
{
    QWORD           Left;
    QWORD           Right;
    QWORD           ParentValue;

    DWORD           StartingVpn;
    DWORD           EndingVpn;
    BYTE            StartingVpnHigh;
    BYTE            EndingVpnHigh;

    BYTE            CommitChargeHigh;
    BYTE            SpareNT64VadUChar;

    DWORD           ReferenceCount;
    QWORD           PushLock;

    struct
    {
        DWORD       VadType : 3;
        DWORD       Protection : 5;
        DWORD       PreferredNode : 6;
        DWORD       NoChange : 1;
        DWORD       PrivateMemory : 1;
        DWORD       PrivateFixup : 1;
        DWORD       ManySubsections : 1;
        DWORD       Enclave : 1;
        DWORD       DeleteInProgress : 1;
        DWORD       PageSize64K : 1;
        DWORD       Spare : 11;
    } VadFlags;

    struct
    {
        DWORD       CommitCharge : 31;
        DWORD       MemCommit : 1;
    } VadFlags1;

    QWORD           EventList;
    QWORD           VadFlags2;
    QWORD           Subsection;

} MMVAD_SHORT64, *PMMVAD_SHORT64;


VOID
MhvNewModuleLoaded(
    PPROCESOR Context
);

VOID
MhvIterateVadList(
    struct _MHVPROCESS* Process
);

VOID
MhvHandleModuleUnload(
    PPROCESOR Context
);
#endif