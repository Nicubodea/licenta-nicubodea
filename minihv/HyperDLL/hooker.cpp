#include "hooker.h"
#include <ntstatus.h>
#include "Zydis/Zydis.h"
#include <stdio.h>
#include <vector>

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
    DWORD neededHookSize = 5; // jmp to detour
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

    originalFunc[0] = 0xe9;
    originalFunc[1] = (DWORD)q & 0xFF;
    originalFunc[2] = ((DWORD)q >> 8) & 0xFF;
    originalFunc[3] = ((DWORD)q >> 16) & 0xFF;
    originalFunc[4] = ((DWORD)q >> 24) & 0xFF;

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