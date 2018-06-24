#include "_wdk.h"

VOID 
InitializeListHead(
    PLIST_ENTRY ListHead
)
{
    ListHead->Blink = ListHead;
    ListHead->Flink = ListHead;
}

VOID 
InsertHeadList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry
) 
{
    PLIST_ENTRY old = ListHead->Flink;
    ListHead->Flink = Entry;
    old->Blink = Entry;
    Entry->Flink = old;
    Entry->Blink = ListHead;
}

VOID 
InsertTailList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry
)
{
    PLIST_ENTRY old = ListHead->Blink;
    ListHead->Blink = Entry;
    Entry->Blink = old;
    Entry->Flink = ListHead;
    old->Flink = Entry;
}

BOOLEAN 
IsListEmpty(
    const LIST_ENTRY *ListHead
)
{
    return ListHead->Flink == ListHead;
}

BOOLEAN 
RemoveEntryList(
    PLIST_ENTRY Entry
)
{
    PLIST_ENTRY last_blink = Entry->Blink;
    PLIST_ENTRY last_flink = Entry->Flink;
    last_blink->Flink = last_flink;
    last_flink->Blink = last_blink;
    return IsListEmpty(last_flink);
}

PLIST_ENTRY 
RemoveHeadList(
    PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY flink = ListHead->Flink;
    ListHead->Flink = flink->Flink;
    flink->Flink->Blink = ListHead;
    return ListHead;
}

PLIST_ENTRY 
RemoveTailList(
    PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY blink = ListHead->Blink;
    ListHead->Blink = blink->Blink;
    blink->Blink->Flink = ListHead;
    return ListHead;
}
