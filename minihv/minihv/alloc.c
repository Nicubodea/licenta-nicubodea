#include "minihv.h"
#include "acpica.h"
#include "alloc.h"
#include "stdio_n.h"
#include "heap.h"

extern QWORD HeapBegin;

heap_t *heap;

VOID
MemInitHeap()
{
    DWORD i;
    heap = AcpiOsAllocate(sizeof(heap_t));
    memset(heap, 0, sizeof(heap_t));

    void *region = GetPhysicalAddr(AcpiOsAllocate(HEAP_INIT_SIZE));

    LOG("[INFO] region = %x, size = %x", region, HEAP_INIT_SIZE);
    memset(region, 0, HEAP_MAX_SIZE);

    for (i = 0; i < BIN_COUNT; i++) {
        heap->bins[i] = GetPhysicalAddr(AcpiOsAllocate(sizeof(bin_t)));
        memset(heap->bins[i], 0, sizeof(bin_t));
    }

    init_heap(heap, (long)region);

}


VOID
MemDumpAllocStats()
{
    /*QWORD current = GetPhysicalAddr(HeapBegin);
    QWORD first = GetPhysicalAddr(0x10001000000);
    QWORD rsp = GetRsp();
    LOG("[HEAP STATS] Heap at: %x, First: %x, Allocated: %x, rsp: %x", current, first, current - first, rsp);
    */
}

VOID*
MemAllocContiguosMemory(
    DWORD Size
)
{
    /*
    VOID* toRet = (VOID*)HeapBegin;

    HeapBegin += Size;
    while (HeapBegin % 8 != 0)
    {
        HeapBegin += 1;
    }

    return toRet;*/
    Size = Size & 0xFFFFFFFF;

    while (Size % 8 != 0)
    {
        Size++;
    }

    PVOID toRet = heap_alloc(heap, Size);
    //LOG("[alloc] allocated to %x size %x", toRet, Size);

    return toRet;
}

VOID
MemFreeContiguosMemory(
    PVOID Memaddr
)
{
    heap_free(heap, Memaddr);
}