#include "_wdk.h"


PLIST_ENTRY ExInterlockedInsertHeadList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY ListEntry,
    ACPI_SPINLOCK* Lock
)
{
    if (!IsListEmpty(ListHead))
    {
        AcpiOsAcquireLock(*Lock);
        PLIST_ENTRY old = ListHead->Flink;
        ListHead->Flink = ListEntry;
        old->Blink = ListEntry;
        ListEntry->Flink = old;
        ListEntry->Blink = ListHead;
        AcpiOsReleaseLock(*Lock, 0);
        return old;
    }
    return NULL;
}

PLIST_ENTRY ExInterlockedInsertTailList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY ListEntry,
    ACPI_SPINLOCK* Lock
)
{
    if (!IsListEmpty(ListHead))
    {
        AcpiOsAcquireLock(*Lock);
        PLIST_ENTRY old = ListHead->Blink;
        ListHead->Blink = ListEntry;
        ListEntry->Blink = old;
        ListEntry->Flink = ListHead;
        old->Flink = ListEntry;
        AcpiOsReleaseLock(*Lock, 0);
        return old;
    }
    return NULL;
}

PLIST_ENTRY ExInterlockedRemoveHeadList(
    PLIST_ENTRY ListHead,
    ACPI_SPINLOCK* Lock
)
{
    if (!IsListEmpty(ListHead))
    {
        AcpiOsAcquireLock(*Lock);
        PLIST_ENTRY flink = ListHead->Flink;
        ListHead->Flink = flink->Flink;
        flink->Flink->Blink = ListHead;
        AcpiOsReleaseLock(*Lock, 0);
        return flink;
    }
    return NULL;
}

