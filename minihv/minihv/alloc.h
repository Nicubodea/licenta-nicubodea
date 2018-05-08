#ifndef _ALLOC_H_
#define _ALLOC_H_

#include "minihv.h"
#include "acpica.h"

extern QWORD HeapBegin;

VOID
MemDumpAllocStats()
{
    QWORD current = GetPhysicalAddr(HeapBegin);
    QWORD first = GetPhysicalAddr(0x10001000000);

    LOG("[HEAP STATS] Heap at: %x, First: %x, Allocated: %x", current, first, current-first);
}

VOID*
MemAllocContiguosMemory(
    DWORD Size
)
{

    VOID* toRet = (VOID*)HeapBegin;

    HeapBegin += Size;

    return toRet;
}

VOID
MemFreeContiguosMemory(
    PVOID Memaddr
)
{
    return;
}


#endif