#ifndef _ALLOC_H_
#define _ALLOC_H_





VOID
MemDumpAllocStats();

VOID*
MemAllocContiguosMemory(
    DWORD Size
);
VOID
MemFreeContiguosMemory(
    PVOID Memaddr
);

VOID
MemInitHeap();


#endif