#include "acpica.h"

extern void acquireLock(void* Handle);
extern void releaseLock(void* Handle);


#define ACPI_NO_UNIT_LIMIT          ((UINT32) -1)
#define ACPI_MUTEX_SEM              1


#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsMapMemory
void *
AcpiOsMapMemory(
    ACPI_PHYSICAL_ADDRESS   Where,
    ACPI_SIZE               Length)
{
    if (Where < 32 * 1024 * 1024 || Where > 0x10000000000)
    {
        return (void*)Where;
    }
    else
    {
        return (void*)(0x10000000000 + Where - 32 * 1024 * 1024);
    }
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsUnmapMemory
void
AcpiOsUnmapMemory(
    void                    *LogicalAddress,
    ACPI_SIZE               Size)
{
    if (LogicalAddress < (void*)0x10000000000)
        return;
}
#endif






/*
* OSL Initialization and shutdown primitives
*/

ACPI_STATUS
AcpiOsInitialize(
    void)
{
    return 0;
}



ACPI_STATUS
AcpiOsTerminate(
    void)
{
    return 0;
}


/*
* ACPI Table interfaces
*/

ACPI_PHYSICAL_ADDRESS
AcpiOsGetRootPointer(
    void)
{

    ACPI_PHYSICAL_ADDRESS  Ret;
    Ret = 0;
    AcpiFindRootPointer(&Ret);
    return Ret;
}

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsPredefinedOverride
ACPI_STATUS
AcpiOsPredefinedOverride(
    const ACPI_PREDEFINED_NAMES *InitVal,
    ACPI_STRING                 *NewVal)
{
    *NewVal = NULL;
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsTableOverride
ACPI_STATUS
AcpiOsTableOverride(
    ACPI_TABLE_HEADER       *ExistingTable,
    ACPI_TABLE_HEADER       **NewTable)
{
    *NewTable = AcpiOsAllocate(ExistingTable->Length);
    for (UINT32 i = 0; i < ExistingTable->Length; i++)
        *((*NewTable) + i) = *(ExistingTable + i);
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsPhysicalTableOverride
ACPI_STATUS
AcpiOsPhysicalTableOverride(
    ACPI_TABLE_HEADER       *ExistingTable,
    ACPI_PHYSICAL_ADDRESS   *NewAddress,
    UINT32                  *NewTableLength)
{
    *NewAddress = NULL;
    return 0;
}
#endif


/*
* Spinlock primitives
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsCreateLock
ACPI_STATUS
AcpiOsCreateLock(
    ACPI_SPINLOCK           *OutHandle)
{
    *OutHandle = AcpiOsAllocate(-1);
    *((__int64*)*OutHandle) = 0;
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsDeleteLock
void
AcpiOsDeleteLock(
    ACPI_SPINLOCK           Handle)
{
    return;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsAcquireLock
ACPI_CPU_FLAGS
AcpiOsAcquireLock(
    ACPI_SPINLOCK           Handle)
{
    acquireLock(Handle);
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReleaseLock
void
AcpiOsReleaseLock(
    ACPI_SPINLOCK           Handle,
    ACPI_CPU_FLAGS          Flags)
{
    releaseLock(Handle);
    return;
}
#endif


/*
* Semaphore primitives
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsCreateSemaphore
ACPI_STATUS
AcpiOsCreateSemaphore(
    UINT32                  MaxUnits,
    UINT32                  InitialUnits,
    ACPI_SEMAPHORE          *OutHandle)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsDeleteSemaphore
ACPI_STATUS
AcpiOsDeleteSemaphore(
    ACPI_SEMAPHORE          Handle)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWaitSemaphore
ACPI_STATUS
AcpiOsWaitSemaphore(
    ACPI_SEMAPHORE          Handle,
    UINT32                  Units,
    UINT16                  Timeout)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsSignalSemaphore
ACPI_STATUS
AcpiOsSignalSemaphore(
    ACPI_SEMAPHORE          Handle,
    UINT32                  Units)
{
    return 0;
}
#endif


/*
* Mutex primitives. May be configured to use semaphores instead via
* ACPI_MUTEX_TYPE (see platform/acenv.h)
*/
ACPI_STATUS
AcpiOsCreateMutex(
    ACPI_MUTEX              *OutHandle)
{
    return 0;
    *OutHandle = AcpiOsAllocate(sizeof(ACPI_MUTEX));
    return 0;
}



void
AcpiOsDeleteMutex(
    ACPI_MUTEX              Handle)
{
    return;
}



ACPI_STATUS
AcpiOsAcquireMutex(
    ACPI_MUTEX              Handle,
    UINT16                  Timeout)
{
    return 0;
    if (Timeout == 0xFFFF)
    {
        acquireLock(Handle);
    }
    return 0;
}

void
AcpiOsReleaseMutex(
    ACPI_MUTEX              Handle)
{
    return;
    releaseLock(Handle);
}


/*
* Memory allocation and mapping
*/
//let's say HEAP is from 0x3000000
extern ACPI_SPINLOCK allocLock;
extern int doneAcpica;
unsigned __int64 HeapBegin = 0x10001000000;
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsAllocate
void *
AcpiOsAllocate(
    ACPI_SIZE               Size)
{
    if (Size == -1)
    {
        Size = sizeof(ACPI_SPINLOCK);
        int allocr = 0;
        if (Size % 0x1000 == 0)
        {
            allocr = (int)Size / 0x1000;
        }
        else
        {
            allocr = (int)Size / 0x1000 + 1;
        }
        void* alloc = (void*)HeapBegin;
        HeapBegin += allocr * 0x1000;
        return alloc;
    }
    if(doneAcpica == 1)
        AcpiOsAcquireLock(allocLock);
    int allocr = 0;
    if (Size % 0x1000 == 0)
    {
        allocr = (int)Size / 0x1000;
    }
    else
    {
        allocr = (int)Size / 0x1000 + 1;
    }
    void* alloc = (void*)HeapBegin;
    HeapBegin += allocr * 0x1000;
    if(doneAcpica == 1)
        AcpiOsReleaseLock(allocLock, 0);
    return alloc;

}
#endif



#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsFree
void
AcpiOsFree(
    void *                  Memory)
{
    return;
}
#endif


#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetPhysicalAddress
ACPI_STATUS
AcpiOsGetPhysicalAddress(
    void                    *LogicalAddress,
    ACPI_PHYSICAL_ADDRESS   *PhysicalAddress)
{
    *PhysicalAddress = ((__int64)LogicalAddress - 0x10000000000 + 32 * 1024 * 1024);
    return 0;
}
#endif

#define ACPI_USE_LOCAL_CACHE

/*
* Interrupt handlers
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsInstallInterruptHandler
ACPI_STATUS
AcpiOsInstallInterruptHandler(
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine,
    void                    *Context)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsRemoveInterruptHandler
ACPI_STATUS
AcpiOsRemoveInterruptHandler(
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine)
{
    return 0;
}
#endif


/*
* Threads and Scheduling
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetThreadId
ACPI_THREAD_ID
AcpiOsGetThreadId(
    void)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsExecute
ACPI_STATUS
AcpiOsExecute(
    ACPI_EXECUTE_TYPE       Type,
    ACPI_OSD_EXEC_CALLBACK  Function,
    void                    *Context)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWaitEventsComplete
void
AcpiOsWaitEventsComplete(
    void)
{
    return;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsSleep
void
AcpiOsSleep(
    UINT64                  Milliseconds)
{
    return;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsStall
void
AcpiOsStall(
    UINT32                  Microseconds)
{
    return;
}
#endif


/*
* Platform and hardware-independent I/O interfaces
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReadPort
ACPI_STATUS
AcpiOsReadPort(
    ACPI_IO_ADDRESS         Address,
    UINT32                  *Value,
    UINT32                  Width)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWritePort
ACPI_STATUS
AcpiOsWritePort(
    ACPI_IO_ADDRESS         Address,
    UINT32                  Value,
    UINT32                  Width)
{
    return 0;
}
#endif


/*
* Platform and hardware-independent physical memory interfaces
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReadMemory
ACPI_STATUS
AcpiOsReadMemory(
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  *Value,
    UINT32                  Width)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWriteMemory
ACPI_STATUS
AcpiOsWriteMemory(
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  Value,
    UINT32                  Width)
{
    return 0;
}
#endif


/*
* Platform and hardware-independent PCI configuration space access
* Note: Can't use "Register" as a parameter, changed to "Reg" --
* certain compilers complain.
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReadPciConfiguration
ACPI_STATUS
AcpiOsReadPciConfiguration(
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  *Value,
    UINT32                  Width)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWritePciConfiguration
ACPI_STATUS
AcpiOsWritePciConfiguration(
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  Value,
    UINT32                  Width)
{
    return 0;
}
#endif


/*
* Miscellaneous
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReadable
BOOLEAN
AcpiOsReadable(
    void                    *Pointer,
    ACPI_SIZE               Length)
{
    return 1;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWritable
BOOLEAN
AcpiOsWritable(
    void                    *Pointer,
    ACPI_SIZE               Length)
{
    return 1;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetTimer
UINT64
AcpiOsGetTimer(
    void)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsSignal
ACPI_STATUS
AcpiOsSignal(
    UINT32                  Function,
    void                    *Info)
{
    return 0;
}
#endif


/*
* Debug print routines
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsPrintf
void ACPI_INTERNAL_VAR_XFACE
AcpiOsPrintf(
    const char              *Format,
    ...)
{
    return;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsVprintf
void
AcpiOsVprintf(
    const char              *Format,
    va_list                 Args)
{
    return;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsRedirectOutput
void
AcpiOsRedirectOutput(
    void                    *Destination)
{
    return;
}
#endif


/*
* Debug input
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetLine
ACPI_STATUS
AcpiOsGetLine(
    char                    *Buffer,
    UINT32                  BufferLength,
    UINT32                  *BytesRead)
{
    return 0;
}
#endif


/*
* Obtain ACPI table(s)
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetTableByName
ACPI_STATUS
AcpiOsGetTableByName(
    char                    *Signature,
    UINT32                  Instance,
    ACPI_TABLE_HEADER       **Table,
    ACPI_PHYSICAL_ADDRESS   *Address)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetTableByIndex
ACPI_STATUS
AcpiOsGetTableByIndex(
    UINT32                  Index,
    ACPI_TABLE_HEADER       **Table,
    UINT32                  *Instance,
    ACPI_PHYSICAL_ADDRESS   *Address)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetTableByAddress
ACPI_STATUS
AcpiOsGetTableByAddress(
    ACPI_PHYSICAL_ADDRESS   Address,
    ACPI_TABLE_HEADER       **Table)
{
    return 0;
}
#endif


/*
* Directory manipulation
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsOpenDirectory
void *
AcpiOsOpenDirectory(
    char                    *Pathname,
    char                    *WildcardSpec,
    char                    RequestedFileType)
{
    return NULL;
}
#endif

/* RequesteFileType values */

#define REQUEST_FILE_ONLY                   0
#define REQUEST_DIR_ONLY                    1


#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetNextFilename
char *
AcpiOsGetNextFilename(
    void                    *DirHandle)
{
    return NULL;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsCloseDirectory
void
AcpiOsCloseDirectory(
    void                    *DirHandle)
{
    return;
}
#endif


/*
* File I/O and related support
*/
#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsOpenFile
ACPI_FILE
AcpiOsOpenFile(
    const char              *Path,
    UINT8                   Modes)
{
    return NULL;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsCloseFile
void
AcpiOsCloseFile(
    ACPI_FILE               File)
{
    return;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReadFile
int
AcpiOsReadFile(
    ACPI_FILE               File,
    void                    *Buffer,
    ACPI_SIZE               Size,
    ACPI_SIZE               Count)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWriteFile
int
AcpiOsWriteFile(
    ACPI_FILE               File,
    void                    *Buffer,
    ACPI_SIZE               Size,
    ACPI_SIZE               Count)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsGetFileOffset
long
AcpiOsGetFileOffset(
    ACPI_FILE               File)
{
    return 0;
}
#endif

#ifndef ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsSetFileOffset
ACPI_STATUS
AcpiOsSetFileOffset(
    ACPI_FILE               File,
    long                    Offset,
    UINT8                   From)
{
    return 0;
}
#endif

