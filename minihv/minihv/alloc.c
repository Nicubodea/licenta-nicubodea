#include "minihv.h"
#include "acpica.h"
#include "alloc.h"
#include "stdio_n.h"

extern QWORD HeapBegin;



VOID
MemDumpAllocStats()
{
    QWORD current = GetPhysicalAddr(HeapBegin);
    QWORD first = GetPhysicalAddr(0x10001000000);
    QWORD rsp = GetRsp();
    LOG("[HEAP STATS] Heap at: %x, First: %x, Allocated: %x, rsp: %x", current, first, current - first, rsp);
}

VOID*
MemAllocContiguosMemory(
    DWORD Size
)
{

    VOID* toRet = (VOID*)HeapBegin;

    HeapBegin += Size;
    while (HeapBegin % 8 != 0)
    {
        HeapBegin += 1;
    }

    return toRet;
}

VOID
MemFreeContiguosMemory(
    PVOID Memaddr
)
{
    return;
}