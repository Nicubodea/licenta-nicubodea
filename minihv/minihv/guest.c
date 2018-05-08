#include "guest.h"
#include "stdio_n.h"

extern PROCESSOR gProcessors[];
extern int gNumberOfProcessors;

VOID
MhvInitGuestState()
{
    pGuest.Vcpu = gProcessors;
    pGuest.NumberOfVcpu = gNumberOfProcessors;
    AcpiOsCreateLock(&pGuest.GlobalLock);
    InitializeListHead(&pGuest.ApiHookList);
    InitializeListHead(&pGuest.EptHooksList);
    InitializeListHead(&pGuest.PtHookList);
    InitializeListHead(&pGuest.ProcessList);
    InitializeListHead(&pGuest.ExceptionsList);
}