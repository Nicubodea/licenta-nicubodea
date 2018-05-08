#include "hooker.h"
#include <ntstatus.h>
#include "Zydis/Zydis.h"
#include <stdio.h>
#include <vector>
#include "communication.h"

extern ZydisDecoder gZydisDecoder;

extern std::vector<PHOOK_DATA> gHooks;

extern "C" void GenericHookHandler();
extern "C" void EmuBuffer();
extern "C" void releaseLock();

extern BOOLEAN gHooksEstablished;

NTSTATUS
AvxEstablishApiHook(
    _In_ EXPORT* Export,
    _In_ HMODULE Module,
    _Out_ PHOOK_DATA* Hook,
    _In_ BYTE HookOrdinal
)
{
    if (NULL == Export)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (NULL == Module)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (NULL == Hook)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (Export->IsForwarded)
    {
        printf("[ERROR] Export %s is forwarded!\n", Export->ExportName);
        return STATUS_INVALID_PARAMETER_1;
    }

    PHOOK_DATA pHookData;
    DWORD neededHookSize = 12; // push hook ordinal and jump to detour
    DWORD i;
    PBYTE originalFunc;
    DWORD old;
    
    pHookData = (PHOOK_DATA)malloc(sizeof(HOOK_DATA));
    pHookData->Export = Export;
    pHookData->Module = Module;
    pHookData->HookOrdinal = HookOrdinal;

    originalFunc = ((PBYTE)Module) + Export->ExportRVA;
    pHookData->OriginalAddress = originalFunc;

    i = 0;
    while (i < neededHookSize)
    {
        ZydisDecodedInstruction instrux;
        ZydisStatus status;

        status = ZydisDecoderDecodeBuffer(&gZydisDecoder, originalFunc + i, 16, (long long)originalFunc + i, &instrux);
        if (!ZYDIS_SUCCESS(status))
        {
            printf("Zydis returned on %s: 0x%08x!\n", pHookData->Export->ExportName, status);
            //return status;
        }

        if (instrux.mnemonic >= ZYDIS_MNEMONIC_JB && instrux.mnemonic <= ZYDIS_MNEMONIC_JZ)
        {
            free(pHookData);
            return 1;
        }
        i += instrux.length;
    }

    pHookData->UnpatchedCode = (PBYTE)malloc(sizeof(BYTE) * i);
    pHookData->NumberOfBytesPatched = i;

    memcpy(pHookData->UnpatchedCode, originalFunc, i);

    // now handle the RipRelative instructions
    i = 0;
    while (i < neededHookSize)
    {
        ZydisDecodedInstruction instrux;
        ZydisStatus status;
        
        status = ZydisDecoderDecodeBuffer(&gZydisDecoder, originalFunc + i, 16, (long long)originalFunc + i, &instrux);
        if (!ZYDIS_SUCCESS(status))
        {
            printf("Zydis returned on %s: 0x%08x!\n", pHookData->Export->ExportName, status);
            //return status;
        }
        for (int j = 0; j < instrux.operandCount; j++)
        {
            if (instrux.operands[j].mem.base == ZYDIS_REGISTER_RIP)
            {
                free(pHookData);
                return 1;
                //printf("[WARNING] rip relative instrux on %s\n", Export->ExportName);
                VirtualProtect(originalFunc + i + instrux.length - 4, 4, PAGE_EXECUTE_READWRITE, &old);
                *(PDWORD)(originalFunc + i + instrux.length - 4) += (DWORD)((QWORD)originalFunc - (QWORD)GenericHookHandler - instrux.length + 4);
                VirtualProtect(originalFunc + i + instrux.length - 4, 4, old, &old);
            }
        }

        i += instrux.length;
    }
    
    pHookData->OriginalCode = (PBYTE)malloc(sizeof(BYTE) * i);
    memcpy(pHookData->OriginalCode, originalFunc, i);
    
    pHookData->JumpAddress = (QWORD)originalFunc + 7;

    VirtualProtect(originalFunc, pHookData->NumberOfBytesPatched, PAGE_EXECUTE_READWRITE, &old);

    DWORD q = (DWORD)((QWORD)GenericHookHandler - (QWORD)originalFunc - 7);

    gHooks.push_back(pHookData);

    // now that we inited the hook data, it's time to patch instructions

    DWORD q2 = (DWORD)((QWORD)releaseLock - (QWORD)originalFunc - neededHookSize);

    originalFunc[0] = 0x6a;
    originalFunc[1] = HookOrdinal;
    originalFunc[2] = 0xe9;
    originalFunc[3] = (DWORD)q & 0xFF;
    originalFunc[4] = ((DWORD)q >> 8) & 0xFF;
    originalFunc[5] = ((DWORD)q >> 16) & 0xFF;
    originalFunc[6] = ((DWORD)q >> 24) & 0xFF;
    originalFunc[7] = 0xe8;
    originalFunc[8] = (DWORD)q2 & 0xFF;
    originalFunc[9] = ((DWORD)q2 >> 8) & 0xFF;
    originalFunc[10] = ((DWORD)q2 >> 16) & 0xFF;
    originalFunc[11] = ((DWORD)q2 >> 24) & 0xFF;

    // fill with NOPs
    for (i = neededHookSize; i < pHookData->NumberOfBytesPatched; i++)
    {
        originalFunc[i] = 0x90;
    }

    VirtualProtect(originalFunc, pHookData->NumberOfBytesPatched, old, &old);

    //printf("[INFO] Succesfully patched %s\n", Export->ExportName);

    *Hook = pHookData;

    return STATUS_SUCCESS;
}

NTSTATUS
AvxPurgeApiHook(
    PHOOK_DATA HookData
)
{
    DWORD old;

    VirtualProtect(HookData->OriginalAddress, HookData->NumberOfBytesPatched, PAGE_EXECUTE_READWRITE, &old);
    memcpy(HookData->OriginalAddress, HookData->UnpatchedCode, HookData->NumberOfBytesPatched);
    VirtualProtect(HookData->OriginalAddress, HookData->NumberOfBytesPatched, old, &old);
    
    free(HookData->OriginalCode);
    free(HookData->UnpatchedCode);
    free(HookData);

    return STATUS_SUCCESS;
}

std::vector<PHOOK_DATA> vExportsCalled;

VOID
HandleFunctionCall(
    QWORD* StackFrame
)
{
    QWORD hookOrdinal = StackFrame[17]; // always the same
    DWORD i;
    PHOOK_DATA hook = NULL;
    DWORD sz = gHooks.size();

    //printf("[INFO] Ordinal %d\n", hookOrdinal & 0xFF);

    for (i = 0; i < gHooks.size(); i++)
    {
        if (gHooks[i]->HookOrdinal == (hookOrdinal & 0xFF))
        {
            hook = gHooks[i];
        }
    }
    
    if (hook == NULL)
    {
        __debugbreak();
        // not found, god knows...
        return;
    }

    //printf("%s called!\n", hook->Export->ExportName);
    if (gHooksEstablished)
    {
        AvxNewHookCall(hook);
    }
    // now write the emu buffer and hope for the best

    PBYTE pEmu = (PBYTE)EmuBuffer;

    // refill emu buffer with nops...
    for (i = 0; i < 60; i++)
    {
        pEmu[i] = 0x90;
    }

    for (i = 0; i < hook->NumberOfBytesPatched; i++)
    {
        pEmu[i] = hook->OriginalCode[i];
    }

    DWORD q = (DWORD)(hook->JumpAddress - (QWORD)pEmu - hook->NumberOfBytesPatched - 5);
    DWORD p = i;

    DWORD q2 = (DWORD)((QWORD)releaseLock - (QWORD)pEmu - hook->NumberOfBytesPatched - 5);

   

    pEmu[p] = 0xe9;
    pEmu[p + 1] = (DWORD)q & 0xFF;
    pEmu[p + 2] = ((DWORD)q >> 8) & 0xFF;
    pEmu[p + 3] = ((DWORD)q >> 16) & 0xFF;
    pEmu[p + 4] = ((DWORD)q >> 24) & 0xFF;
    //pEmu[p + 5] = 0xe9;
    //pEmu[p + 6] = (DWORD)q & 0xFF;
    //pEmu[p + 7] = ((DWORD)q >> 8) & 0xFF;
    //pEmu[p + 8] = ((DWORD)q >> 16) & 0xFF;
    //pEmu[p + 9] = ((DWORD)q >> 24) & 0xFF;

}

//DWORD gNr = 0;
//PEXPORT gExpo[500000];

extern SOCKET gSocket;

VOID AvxNewHookCall(
    PHOOK_DATA Hook
)
{
    /*if (vExportsCalled.size() > 30)
    {
        vExportsCalled.erase(vExportsCalled.begin());
    }
    */
    vExportsCalled.push_back(Hook);

    if (vExportsCalled.size() == 30)
    {
        std::vector<DWORD> ordinals;
        for (DWORD i = 0; i < vExportsCalled.size(); i++)
        {
            ordinals.push_back(vExportsCalled[i]->HookOrdinal);
        }
        NTSTATUS status = AvxCommSendBuffer(gSocket, ordinals);
        if (status != 0)
        {
            /*releaseLock();
            gHooksEstablished = FALSE;
            for (DWORD i = 0; i < gHooks.size(); i++)
            {
                AvxPurgeApiHook(gHooks[i]);
            }
            gHooks.clear();
            // ugly exit, but we are hooked.
            PBYTE p = 0;
            *p = 1;*/
        }
    }
}