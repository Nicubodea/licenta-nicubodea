#ifndef _VMXOP_H
#define _VMXOP_H
#define WINDBG
#include "vmcsdef.h"
#include "acpica.h"
#include "minihv.h"
#include "stdio_n.h"
#include "structures.h"

/*
Memory type range registers structures
*/
extern MTR gMtrrs[196];
extern DWORD gNrMtrrs;

/*
Physical processors structures
*/
extern PROCESSOR gProcessors[];
extern DWORD gNumberOfProcessors;

extern QWORD globalPagingTable;

/*
E820 memory map structures
*/
extern PMEMORYMAP gE820Map[];
extern DWORD gE820Entries;

PQWORD
MhvTranslateVa(
    QWORD Rip,
    QWORD Cr3,
    BOOLEAN *Writable
);

NTSTATUS
MhvMemRead(
    QWORD Address,
    QWORD Size,
    QWORD Cr3,
    PVOID Buffer
);

/*
Get the physical address of a 1T translated address
*/
PQWORD GetPhysicalAddr(PQWORD x);
/*
Extern assembly function to go to 16 bits from 64 bits
*/
extern void JumpToMBR();
/*
Extern assembly function to get the address of the structure corresponding to current pcpu
*/
extern QWORD getFs();
/*
Initialise controls
*/
void MhvInitControls();
/*
Exit VMX operation
*/
void MhvEndVmx();
/*
Initialise host state vmcs
*/
void MhvInitHost(PROCESSOR CurrentProc);
/*
Initialise guest state vmcs
*/
void MhvInitGuest(PROCESSOR CurrentProc);
/*
Handle exits caused by mov to cr3 or mov from cr3
*/
void MhvHandleCr3Exit(PROCESSOR *CurrentProc);
/*
Saves the current state, then gives control to a handle corresponding to current vm exit
*/
void MhvGeneralHandler();
/*
Makes the extended page table, also consulting the MTRRs
*/
//void MhvMakeEpt();
/*
Function to get the current processor id
*/
DWORD MhvGetProcessorId();
/*
Function for aps to go to 16 bits
*/
void doNothing();
/*
Dumps the VMCS, used for debug reasons
*/
void dbgDumpVmcs();
/*
Function for bsp to go to 16 bits
*/
void doBsp();
/*
Function to make the MTRR structures
*/
void MhvMakeMtrr();
// current ept pointer

extern PQWORD EptPointer;
extern DWORD eptDone;
extern DWORD notDone;

extern QWORD gBufferZone;
extern ACPI_SPINLOCK EptLock;

#endif