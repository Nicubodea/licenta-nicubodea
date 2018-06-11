#include "alert.h"
#include "alloc.h"
#include "stdio_n.h"

LIST_ENTRY gEventList;
LIST_ENTRY gExceptions;
BOOLEAN bInitialized = FALSE;
BOOLEAN bExceptInitialized = FALSE;

#define min(a,b) (a>b)?(b):(a)

PEVENT
MhvCreateProcessCreationEvent(
    PMHVPROCESS Process
)
{
    if (!bInitialized)
    {
        InitializeListHead(&gEventList);
        bInitialized = TRUE;
    }

    PEVENT pEvent = MemAllocContiguosMemory(sizeof(EVENT));
    
    memset_s(pEvent, 0, sizeof(EVENT));

    pEvent->Type = mhvEventProcessCreate;

    pEvent->ProcessCreateEvent.Cr3 = Process->Cr3;
    pEvent->ProcessCreateEvent.Eprocess = Process->Eprocess;
    memcpy_s(pEvent->ProcessCreateEvent.Name, Process->Name, 16);
    pEvent->ProcessCreateEvent.Pid = Process->Pid;

    pEvent->Protection = Process->ProtectionInfo;

    MhvEnqueueEvent(pEvent);
    
    return pEvent;
}

PEVENT
MhvCreateProcessTerminationEvent(
    PMHVPROCESS Process
)
{
    if (!bInitialized)
    {
        InitializeListHead(&gEventList);
        bInitialized = TRUE;
    }

    PEVENT pEvent = MemAllocContiguosMemory(sizeof(EVENT));
    memset_s(pEvent, 0, sizeof(EVENT));

    pEvent->Type = mhvEventProcessTerminate;

    pEvent->ProcessTerminateEvent.Cr3 = Process->Cr3;
    pEvent->ProcessTerminateEvent.Eprocess = Process->Eprocess;
    memcpy_s(pEvent->ProcessTerminateEvent.Name, Process->Name, 16);
    pEvent->ProcessTerminateEvent.Pid = Process->Pid;

    pEvent->Protection = Process->ProtectionInfo;

    MhvEnqueueEvent(pEvent);

    return pEvent;
}

PEVENT
MhvCreateModuleLoadEvent(
    PMHVMODULE Module
)
{
    if (!bInitialized)
    {
        InitializeListHead(&gEventList);
        bInitialized = TRUE;
    }

    PEVENT pEvent = MemAllocContiguosMemory(sizeof(EVENT));
    memset_s(pEvent, 0, sizeof(EVENT));

    pEvent->Type = mhvEventModuleLoad;

    pEvent->ModuleLoadEvent.Pid = Module->Process->Pid;
    memcpy_s(pEvent->ModuleLoadEvent.ProcessName, Module->Process->Name, 16);

    pEvent->ModuleLoadEvent.Module.Start = Module->Start;
    pEvent->ModuleLoadEvent.Module.End = Module->End;
    memcpy_s(pEvent->ModuleLoadEvent.Module.Name, Module->Name, min(strlen(Module->Name),256));

    pEvent->Protection = Module->Process->ProtectionInfo;

    MhvEnqueueEvent(pEvent);

    return pEvent;
}

PEVENT
MhvCreateModuleUnloadEvent(
    PMHVMODULE Module
)
{
    if (!bInitialized)
    {
        InitializeListHead(&gEventList);
        bInitialized = TRUE;
    }

    PEVENT pEvent = MemAllocContiguosMemory(sizeof(EVENT));
    memset_s(pEvent, 0, sizeof(EVENT));

    pEvent->Type = mhvEventModuleUnload;

    pEvent->ModuleUnloadEvent.Pid = Module->Process->Pid;
    memcpy_s(pEvent->ModuleUnloadEvent.ProcessName, Module->Process->Name, 16);

    pEvent->ModuleUnloadEvent.Module.Start = Module->Start;
    pEvent->ModuleUnloadEvent.Module.End = Module->End;
    memcpy_s(pEvent->ModuleUnloadEvent.Module.Name, Module->Name, strlen(Module->Name));


    pEvent->Protection = Module->Process->ProtectionInfo;

    MhvEnqueueEvent(pEvent);

    return pEvent;
}

PEVENT
MhvCreateModuleAlert(
    PMHVMODULE Attacker,
    PMHVMODULE Victim,
    QWORD Rip,
    QWORD Address
)
{
    if (!bInitialized)
    {
        InitializeListHead(&gEventList);
        bInitialized = TRUE;
    }

    PEVENT pEvent = MemAllocContiguosMemory(sizeof(EVENT));
    memset_s(pEvent, 0, sizeof(EVENT));

    pEvent->Type = mhvEventModuleAlert;

    pEvent->ModuleAlertEvent.Address = Address;
    pEvent->ModuleAlertEvent.Rip = Rip;

    pEvent->ModuleAlertEvent.Pid = Victim->Process->Pid;
    memcpy_s(pEvent->ModuleAlertEvent.ProcessName, Victim->Process->Name, 16);

    if (Attacker == NULL)
    {
        pEvent->ModuleAlertEvent.Attacker.End = 0;
        pEvent->ModuleAlertEvent.Attacker.Start = 0;
        memcpy_s(pEvent->ModuleAlertEvent.Attacker.Name, "<unknown>", sizeof("<unknown>"));
    }
    else
    {
        pEvent->ModuleAlertEvent.Attacker.End = Attacker->End;
        pEvent->ModuleAlertEvent.Attacker.Start = Attacker->Start;
        memcpy_s(pEvent->ModuleAlertEvent.Attacker.Name, Attacker->Name, strlen(Attacker->Name));
    }

    pEvent->ModuleAlertEvent.Victim.Start = Victim->Start;
    pEvent->ModuleAlertEvent.Victim.End = Victim->End;
    memcpy_s(pEvent->ModuleAlertEvent.Victim.Name, Victim->Name, strlen(Victim->Name));

    ZydisStatus status;

    ZydisDecoder decoder;
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    if (!ZYDIS_SUCCESS(status))
    {
        LOG("[ERROR] Decoder failed to be inited!");
    }
    ZydisDecodedInstruction instrux;

    PBYTE current = MhvTranslateVa(Rip, Victim->Process->Cr3, NULL);
    QWORD currentRip = Rip;
    DWORD i;
    for (i = 0; i < 10; i++)
    {
        if (((currentRip + 16) & (~0xFFF)) != (Rip & (~0xFFF)))
        {
            break;
        }

        status = ZydisDecoderDecodeBuffer(&decoder, current, 16, currentRip, &instrux);

        if (!ZYDIS_SUCCESS(status))
        {
            LOG("[ERROR] Error decode buffer");
            break;
        }

        ZydisFormatter formatter;

        if (!ZYDIS_SUCCESS((status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) ||

            !ZYDIS_SUCCESS((status = ZydisFormatterSetProperty(&formatter,

                ZYDIS_FORMATTER_PROP_FORCE_MEMSEG, ZYDIS_TRUE))) ||

            !ZYDIS_SUCCESS((status = ZydisFormatterSetProperty(&formatter,

                ZYDIS_FORMATTER_PROP_FORCE_MEMSIZE, ZYDIS_TRUE))))

        {

            LOG("[ERROR] ZyDis formatter error");
        }

        char buffer[128];

        ZydisFormatterFormatInstruction(&formatter, &instrux, &buffer[0], sizeof(buffer));

        memcpy_s(pEvent->ModuleAlertEvent.Instructions[i].Instruction, buffer, strlen(buffer));

        pEvent->ModuleAlertEvent.Instructions[i].Mnemonic = instrux.mnemonic;
        
        pEvent->ModuleAlertEvent.Instructions[i].Length = instrux.length;

        currentRip += instrux.length;
        current += instrux.length;
    }

    pEvent->ModuleAlertEvent.NumberOfInstructions = i;

    pEvent->Protection = Victim->Process->ProtectionInfo;
    
    MhvEnqueueEvent(pEvent);

    return pEvent;
}

VOID
MhvEnqueueEvent(
    PEVENT Event
)
{
    InsertTailList(&gEventList, &Event->Link);
}

NTSTATUS
MhvGetFirstEvent(
    QWORD Address,
    QWORD Cr3
)
{
    if (IsListEmpty(&gEventList))
    {
        return STATUS_UNSUCCESSFUL;
    }

    PEVENT pEvent = CONTAINING_RECORD(gEventList.Flink, EVENT, Link);
    
    PEVENT pGuestBuffer = MhvTranslateVa(Address, Cr3, NULL);

    *pGuestBuffer = *pEvent;

    RemoveEntryList(&pEvent->Link);

    MemFreeContiguosMemory(pEvent);

    return STATUS_SUCCESS;
}

BOOLEAN
MhvMatchException(
    PEVENT Event,
    PALERT_EXCEPTION Exception
)
{
    if (strcmp(Event->ModuleAlertEvent.ProcessName, Exception->ProcessName) != 0)
    {
        return FALSE;
    }

    if (strcmp(Event->ModuleAlertEvent.Victim.Name, Exception->VictimName) != 0)
    {
        return FALSE;
    }

    if (strcmp(Event->ModuleAlertEvent.Attacker.Name, Exception->AttackerName) != 0)
    {
        return FALSE;
    }

    if (Exception->NumberOfSignatures > Event->ModuleAlertEvent.NumberOfInstructions)
    {
        return FALSE;
    }

    for (DWORD i = 0; i < Event->ModuleAlertEvent.NumberOfInstructions - Exception->NumberOfSignatures; i++)
    {
        DWORD nrOfMatches = 0;
        for (DWORD j = i; j < i + Exception->NumberOfSignatures; j++)
        {
            if (Event->ModuleAlertEvent.Instructions[j].Mnemonic == Exception->Signatures[j - i].Mnemonic)
            {
                nrOfMatches++;
            }
        }

        if (nrOfMatches >= Exception->SignaturesNeededToMatch)
        {
            return TRUE;
        }
    }

    return FALSE;

}


VOID
MhvTestDummyException(

)
{
    PALERT_EXCEPTION pException = MemAllocContiguosMemory(sizeof(ALERT_EXCEPTION));

    memcpy_s(pException->AttackerName, "\\Program Files\\Mozilla Firefox\\mozglue.dll", sizeof("\\Program Files\\Mozilla Firefox\\mozglue.dll"));
    memcpy_s(pException->VictimName, "\\Windows\\System32\\ntdll.dll", sizeof("\\Windows\\System32\\ntdll.dll"));

    memcpy_s(pException->ProcessName, "firefox.exe", sizeof("firefox.exe"));

    pException->NumberOfSignatures = 7;
    pException->SignaturesNeededToMatch = 3;

    pException->Signatures[0].Mnemonic = 412;
    pException->Signatures[1].Mnemonic = 412;
    pException->Signatures[2].Mnemonic = 412;
    pException->Signatures[3].Mnemonic = 375;
    pException->Signatures[4].Mnemonic = 59;
    pException->Signatures[5].Mnemonic = 375;
    pException->Signatures[6].Mnemonic = 59;

    InsertTailList(&gExceptions, &pException->Link);
}


NTSTATUS
MhvExceptAlert(
    PEVENT Event
)
{
    if (!bExceptInitialized)
    {
        InitializeListHead(&gExceptions);
        bExceptInitialized = TRUE;
    }

    LIST_ENTRY* list = gExceptions.Flink;

    while (list != &gExceptions)
    {
        PALERT_EXCEPTION pException = CONTAINING_RECORD(list, ALERT_EXCEPTION, Link);

        list = list->Flink;

        if (MhvMatchException(Event, pException))
        {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
MhvExceptNewAlertRequest(
    QWORD Address,
    QWORD Cr3
)
{
    if (!bExceptInitialized)
    {
        InitializeListHead(&gExceptions);
        bExceptInitialized = TRUE;
    }

    PALERT_EXCEPTION pException = MemAllocContiguosMemory(sizeof(ALERT_EXCEPTION));

    PALERT_EXCEPTION pGuestException = MhvTranslateVa(Address, Cr3, NULL);

    *pException = *pGuestException;

    LOG("[INFO] Requested to add new exception on %s from %s to %s", pException->ProcessName, pException->AttackerName, pException->VictimName);

    InsertTailList(&gExceptions, &pException->Link);

    return STATUS_SUCCESS;

}