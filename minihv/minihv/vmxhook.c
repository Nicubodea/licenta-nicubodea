#include "minihv.h"
#include "vmxhook.h"
#include "vmcsdef.h"
#include "vmxop.h"
#include "winpe.h"
#include "ntstatus.h"
#include "winproc.h"
#include "guest.h"

VOID
_Emu1(PPROCESOR Processor) {

    QWORD rsp;
    __vmx_vmread(VMX_GUEST_RSP, &rsp);
    rsp += 0x18;
    QWORD cr3 = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    PDWORD writeAddr = MhvTranslateVa(rsp, cr3, NULL);
    writeAddr[0] = Processor->context._r8 & 0xFFFFFFFF;

}

VOID
_Emu2(PPROCESOR Processor) {
    QWORD rsp;
    __vmx_vmread(VMX_GUEST_RSP, &rsp);
    rsp += 0x20;
    QWORD cr3 = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    PDWORD writeAddr = MhvTranslateVa(rsp, cr3, NULL);
    writeAddr[0] = Processor->context._r9 & 0xFFFFFFFF;

}

VOID
_Emu4(PPROCESOR Processor) {
    QWORD rsp;
    __vmx_vmread(VMX_GUEST_RSP, &rsp);
    rsp += 0x18;
    QWORD cr3 = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    PDWORD writeAddr = MhvTranslateVa(rsp, cr3, NULL);
    writeAddr[0] = Processor->context._r8 & 0xFFFFFFFF;

}

VOID
_Emu3(PPROCESOR Processor) {

    QWORD rsp;
    __vmx_vmread(VMX_GUEST_RSP, &rsp);
    rsp += 0x10;
    QWORD cr3 = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    PQWORD writeAddr = MhvTranslateVa(rsp, cr3, NULL);
    writeAddr[0] = Processor->context._rbx;

}

VOID
_Emu5(PPROCESOR Processor) {

    QWORD rsp;
    __vmx_vmread(VMX_GUEST_RSP, &rsp);
    rsp += 0x18;
    QWORD cr3 = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    PQWORD writeAddr = MhvTranslateVa(rsp, cr3, NULL);
    writeAddr[0] = Processor->context._rbx;

}

API_SIGNATURE gHookSignatures[NR_OF_SIGNATURES] = {
    {
        "PspInsertProcess",
        0x60,
        {
            0x44, 0x89, 0x44, 0x24, 0x200,                   // mov     dword ptr [rsp+18h],r8d
            0x53,                                           // push    rbx
            0x55,                                           // push    rbp
            0x56,                                           // push    rsi
            0x57,                                           // push    rdi
            0x41, 0x54,                                     // push    r12
            0x41, 0x55,                                     // push    r13
            0x41, 0x56,                                     // push    r14
            0x48, 0x83, 0xec, 0x200,                         // sub     rsp,40h
            0x65, 0x4c, 0x8b, 0x34, 0x25, 0x200, 0x200, 0x00, 0x00, // mov   r14,qword ptr gs:[188h]
            0x48, 0x8b, 0xf2,                               // mov     rsi,rdx
            0x4c, 0x8b, 0x91, 0x200, 0x200, 0x00, 0x00,       // mov     r10,qword ptr [rcx+418h]
            0x48, 0x8b, 0xd9,                               // mov     rbx,rcx
            0x8b, 0x81, 0x200, 0x200, 0x00, 0x00,             // mov     eax,dword ptr [rcx+2E8h]
            0x33, 0xd2,                                     // xor     edx,edx
            0xb9, 0x200, 0x00, 0x00, 0x00,                   // mov     ecx,85h
            0x45, 0x8b, 0xe1,                               // mov     r12d,r9d
            0x4d, 0x8b, 0xae, 0x200, 0x00, 0x00, 0x00,       // mov     r13,qword ptr [r14+0B8h]
            0x41, 0x89, 0x42, 0x200,                         // mov     dword ptr [r10+28h],eax
            0xe8, 0x200, 0x200, 0x00, 0x00,                   // call    nt!SeAuditingWithTokenForSubcategory (fffff800`55005cd8)
            0x84, 0xc0,                                     // test    al,al
            0x0f, 0x85, 0x200, 0x200, 0x00, 0x00,             // jne     nt!PspInsertProcess+0x234 (fffff800`55004fc4)
            0x48, 0x85, 0xf6,                               // test    rsi,rsi
            0x74, 0x200,                                     // je      nt!PspInsertProcess+0x7e (fffff800`55004e0e)
            0x48, 0x8b, 0x86, 0x200, 0x200, 0x00, 0x00,       // mov     rax,qword ptr [rsi+3B0h]
            0x48, 0x85, 0xc0,                               // test    rax,rax
        },
        _Emu1,
        MhvInsertProcessInList
    },
    {
        "PspInsertProcess",
        0x51,
        {
            0x44, 0x89, 0x4C, 0x24, 0x200,                           // mov     dword ptr [rsp+20h],r9d
            0x44, 0x89, 0x44, 0x24, 0x200,                           // mov     dword ptr [rsp+18h],r8d
            0x53,                                                   // push    rbx
            0x55,                                                   // push    rbp
            0x56,                                                   // push    rsi
            0x57,                                                   // push    rdi
            0x41, 0x55,                                             // push    r13
            0x41, 0x56,                                             // push    r14
            0x41, 0x57,                                             // push    r15
            0x48, 0x83, 0xEC, 0x60,                                 // sub     rsp,60h
            0x65, 0x4C, 0x8B, 0x3C, 0x25, 0x200, 0x200, 0x00, 0x00,   // mov     r15,qword ptr gs:[188h]
            0x48, 0x8B, 0xEA,                                       // mov     rbp,rdx
            0x4C, 0x8B, 0x91, 0x200, 0x200, 0x00, 0x00,               // mov     r10,qword ptr [rcx+418h]
            0x48, 0x8B, 0xF9,                                       // mov     rdi,rcx
            0x8B, 0x81, 0x200, 0x200, 0x00, 0x00,                     // mov     eax,dword ptr [rcx+2E0h]
            0x33, 0xD2,                                             // xor     edx,edx
            0xB9, 0x200, 0x00, 0x00, 0x00,                           // mov     ecx,85h
            0x41, 0x8B, 0xF1,                                       // mov     esi,r9d
            0x4D, 0x8B, 0xAF, 0x200, 0x00, 0x00, 0x00,               // mov     r13,qword ptr [r15+0B8h]
            0x41, 0x89, 0x42, 0x200,                                 // mov     dword ptr [r10+28h],eax
            0xE8, 0x200, 0x200, 0x00, 0x00,                           // call    nt!SeAuditingWithTokenForSubcategory (fffff803`216da7c0)
            0x45, 0x33, 0xF6                                        // xor     r14d,r14d
        },
        _Emu2,
        MhvInsertProcessInList
    },
    {
        "PspInsertProcess",
        0x60,
        {
            0x44, 0x89, 0x44, 0x24, 0x200,                   // mov     dword ptr [rsp+18h],r8d
            0x53,                                           // push    rbx
            0x55,                                           // push    rbp
            0x56,                                           // push    rsi
            0x57,                                           // push    rdi
            0x41, 0x54,                                     // push    r12
            0x41, 0x55,                                     // push    r13
            0x41, 0x56,                                     // push    r14
            0x48, 0x83, 0xec, 0x200,                         // sub     rsp,40h
            0x65, 0x4c, 0x8b, 0x34, 0x25, 0x88, 0x01, 0x00, 0x00, // mov   r14,qword ptr gs:[188h]
            0x48, 0x8b, 0xf2,                               // mov     rsi,rdx
            0x4c, 0x8b, 0x91, 0x200, 0x200, 0x200, 0x200,       // mov     r10,qword ptr [rcx+418h]
            0x48, 0x8b, 0xd9,                               // mov     rbx,rcx
            0x8b, 0x81, 0x200, 0x200, 0x00, 0x00,             // mov     eax,dword ptr [rcx+2E8h]
            0x33, 0xd2,                                     // xor     edx,edx
            0xb9, 0x200, 0x200, 0x200, 0x200,                   // mov     ecx,85h
            0x45, 0x8b, 0xe1,                               // mov     r12d,r9d
            0x4d, 0x8b, 0xae, 0x200, 0x00, 0x00, 0x00,       // mov     r13,qword ptr [r14+0B8h]
            0x41, 0x89, 0x42, 0x200,                         // mov     dword ptr [r10+28h],eax
            0xe8, 0x200, 0x200, 0x200, 0x200,                   // call    nt!SeAuditingWithTokenForSubcategory (fffff801`c8ad276c)
            0x84, 0xc0,                                     // test    al,al
            0x0f, 0x85, 0x200, 0x200, 0x200, 0x200,             // jne     nt!PspInsertProcess+0x241 (fffff801`c8ad1a49)
            0x48, 0x85, 0xf6,                               // test    rsi,rsi
            0x74, 0x200,                                     // je      nt!PspInsertProcess+0x7e (fffff801`c8ad1886)
            0x48, 0x8b, 0x86, 0x200, 0x200, 0x200, 0x200,       // mov     rax,qword ptr [rsi+3B0h]
            0x48, 0x85, 0xc0,                               // test    rax,rax
        },
    _Emu4,
    MhvInsertProcessInList
    },
    {
        "PspProcessDelete",
        0x63,
        {
            0x48, 0x89, 0x5c, 0x24, 0x200,                   // mov     qword ptr [rsp+10h],rbx
            0x48, 0x89, 0x74, 0x24, 0x200,                   // mov     qword ptr [rsp+18h],rsi
            0x55,                                           // push    rbp
            0x57,                                           // push    rdi
            0x41, 0x55,                                     // push    r13
            0x41, 0x56,                                     // push    r14
            0x41, 0x57,                                     // push    r15
            0x48, 0x8b, 0xec,                               // mov     rbp,rsp
            0x48, 0x83, 0xec, 0x200,                         // sub     rsp,70h
            0x48, 0x8b, 0x05, 0x200, 0x200, 0x200, 0x200,       // mov     rax,qword ptr [nt!_security_cookie (fffff802`da8da108)]
            0x48, 0x33, 0xc4,                               // xor     rax,rsp
            0x48, 0x89, 0x45, 0x200,                         // mov     qword ptr [rbp-8],rax
            0x0f, 0xba, 0xb1, 0x200, 0x200, 0x00, 0x00, 0x200, // btr     dword ptr [rcx+304h],1Ah
            0x48, 0x8d, 0x99, 0x200, 0x200, 0x00, 0x00,       // lea     rbx,[rcx+2F0h]
            0x65, 0x48, 0x8b, 0x34, 0x25, 0x200, 0x200, 0x00, 0x00, // mov   rsi,qword ptr gs:[188h]
            0x45, 0x33, 0xff,                               // xor     r15d,r15d
            0x48, 0x8b, 0xf9,                               // mov     rdi,rcx
            0x4c, 0x39, 0x3b,                               // cmp     qword ptr [rbx],r15
            0x74, 0x200,                                     // je      nt!PspProcessDelete+0x7b (fffff802`daa36cd3)
            0x48, 0x8b, 0xce,                               // mov     rcx,rsi
            0xe8, 0x200, 0x200, 0x200, 0x200,                   // call    nt!PspLockProcessListExclusive (fffff802`da6bdb0c)
            0x48, 0x8b, 0x0b,                               // mov     rcx,qword ptr [rbx]
            0x48, 0x8b, 0x43, 0x200,                         // mov     rax,qword ptr [rbx+8]
            0x48, 0x39, 0x59, 0x200,                         // cmp     qword ptr [rcx+8],rbx
            0x0f, 0x85, 0x200, 0x200, 0x200, 0x00,             // jne     nt! ?? ::NNGAKEGL::`string'+0x27d68 (fffff802`dab8bf38)
        },
        _Emu3,
        MhvDeleteProcessFromList
    },
    {
        "MiGetWsAndInsertVad",
        0x64,
        {
            0x48, 0x89, 0x5c, 0x24, 0x200,                   // mov     qword ptr [rsp+18h],rbx
            0x48, 0x89, 0x74, 0x24, 0x200,                   // mov     qword ptr [rsp+20h],rsi
            0x57,                                           // push    rdi
            0x48, 0x83, 0xec, 0x200,                         // sub     rsp,20h
            0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, // mov   rax,qword ptr gs:[188h]
            0x48, 0x8b, 0xf1,                               // mov     rsi,rcx
            0x48, 0x89, 0x6c, 0x24, 0x200,                   // mov     qword ptr [rsp+30h],rbp
            0x48, 0x8b, 0xb8, 0x200, 0x00, 0x00, 0x00,       // mov     rdi,qword ptr [rax+0B8h]
            0x0f, 0xb6, 0x87, 0x200, 0x200, 0x00, 0x00,       // movzx   eax,byte ptr [rdi+5B8h]
            0x24, 0x07,                                     // and     al,7
            0x48, 0x8d, 0x9f, 0x200, 0x200, 0x00, 0x00,       // lea     rbx,[rdi+500h]
            0x3c, 0x02,                                     // cmp     al,2
            0x0f, 0x84, 0x200, 0x200, 0x200, 0x200,             // je      nt! ?? ::FNODOBFM::`string'+0x1b17c (fffff800`8d7fd33c)
            0x48, 0x8d, 0x8b, 0x200, 0x00, 0x00, 0x00,       // lea     rcx,[rbx+0C0h]
            0x44, 0x0f, 0x20, 0xc5,                         // mov     rbp,cr8
            0xb8, 0x02, 0x00, 0x00, 0x00,                   // mov     eax,2
            0x44, 0x0f, 0x22, 0xc0,                         // mov     cr8,rax
            0xf6, 0x05, 0x200, 0x200, 0x200, 0x200, 0x200,       // test    byte ptr [nt!PerfGlobalGroupMask+0x6 (fffff800`8da31286)],21h
            0x40, 0x0f, 0xb6, 0xd5,                         // movzx   edx,bpl
            0x0f, 0x85, 0x200, 0x200, 0x200, 0x200,             // jne     nt! ?? ::FNODOBFM::`string'+0x1b188 (fffff800`8d7fd348)
        },
        _Emu5,
        MhvNewModuleLoaded
    },

};

VOID
MhvEstablishApiHook(
    QWORD Rip
) 
{
    QWORD cr3 = 0;
    PBYTE writeAddr;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    
    writeAddr = MhvTranslateVa(Rip, cr3, NULL);
    writeAddr[0] = 0x0f;
    writeAddr[1] = 0x01;
    writeAddr[2] = 0xc1;
    writeAddr[3] = 0x90;
    writeAddr[4] = 0x90;
}

QWORD
MhvFindFunctionInSection(
    PAPI_SIGNATURE Signature,
    QWORD SectionStart,
    QWORD SectionSize
)
{
    QWORD page;
    QWORD cr3 = 0;
    QWORD j;

    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    for (page = SectionStart; page < SectionStart + SectionSize; page += 0x1000)
    {
        PBYTE phys = MhvTranslateVa(page, cr3, NULL);
        if (phys == 0)
        {
            continue;
        }
        for (j = 0; j < 0x1000 - Signature->SigLength; j++)
        {
            DWORD k = 0, l = j;
            while ((k < Signature->SigLength && phys[l] == Signature->Signature[k]) 
                || Signature->Signature[k] == 0x200)
            {
                l++;
                k++;
            }
            if (k == Signature->SigLength)
            {
                return page + j;
            }
        }
    }
    return 0;
}


VOID
MhvInsertNewHook(
    QWORD ApiIndex,
    QWORD Rip
)
{
    
    PHOOK pNewHook = MemAllocContiguosMemory(sizeof(HOOK));
    memcpys(gHookSignatures[ApiIndex].Name, pNewHook->Name, 30);
    pNewHook->Rip = Rip;
    pNewHook->Callback = gHookSignatures[ApiIndex].EmuCallback;
    pNewHook->CalledCallback = gHookSignatures[ApiIndex].ExecCallback;

    InsertTailList(&pGuest.ApiHookList, &pNewHook->Link);
}

VOID
MhvHookFunctionsInMemory(
    
)
{
    DWORD procId = MhvGetProcessorId();
    QWORD cr3 = 0;
    QWORD kernelMap = 0;
 
    gNumberOfHooks = 0;
    
    __vmx_vmread(VMX_GUEST_CR3, &cr3);

    kernelMap = MhvTranslateVa(gProcessors[procId].KernelBase, cr3, NULL);
    
    PIMAGE_DOS_HEADER dosHeader = kernelMap;
   
    PIMAGE_NT_HEADERS64 ntHeader = MhvTranslateVa(gProcessors[procId].KernelBase + dosHeader->e_lfanew,
        cr3, 
        NULL);

    DWORD szOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
    DWORD nrSections = ntHeader->FileHeader.NumberOfSections;

    QWORD firstSectionHeader = gProcessors[procId].KernelBase + sizeof(IMAGE_DOS_HEADER) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + szOptionalHeader;

    for (DWORD i = 0; i < nrSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = MhvTranslateVa(firstSectionHeader, cr3, NULL);
        BOOLEAN bFound = FALSE;
        QWORD function;
        for (DWORD j = 0; j < NR_OF_SIGNATURES; j++)
        {
            function = MhvFindFunctionInSection(&gHookSignatures[j],
                gProcessors[procId].KernelBase + sectionHeader->VirtualAddress,
                sectionHeader->Misc.VirtualSize);
            if (function != 0)
            {
                MhvInsertNewHook(j, function);
                MhvEstablishApiHook(function);
                LOG("[INFO] Found function %s at %x!", gHookSignatures[j].Name, function);
            }
        }

        firstSectionHeader += sizeof(IMAGE_SECTION_HEADER);
    }
    
    
    
}


NTSTATUS
MhvVerifyIfHookAndNotify(
    QWORD Rip
) 
{
    DWORD i = 0;
    DWORD procId;
    PLIST_ENTRY list = pGuest.ApiHookList.Flink;

    while (list != &pGuest.ApiHookList)
    {
        PHOOK pHook = CONTAINING_RECORD(list, HOOK, Link);
        
        if (pHook->Rip == Rip)
        {
            pHook->CalledCallback(&gProcessors[MhvGetProcessorId()]);
            pHook->Callback(&gProcessors[MhvGetProcessorId()]);
            return STATUS_SUCCESS;
        }
        list = list->Flink;
    }

    return STATUS_NOT_FOUND;
}


QWORD
MhvFindKernelBase(
    QWORD Start
) 
{
    QWORD currentPage = Start & ~0xFFF;
    QWORD cr3 = 0;
    QWORD pagesWalked = 0;

    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    BOOLEAN found = FALSE;
    while (!found && pagesWalked < 1000)
    {
        PBYTE currentTrans = MhvTranslateVa(currentPage, cr3, NULL);
        if (currentTrans != 0 && currentTrans[0] == 'M' && currentTrans[1] == 'Z')
        {
            LOG("[INFO] Found kernel base at %x", currentPage);
            return currentPage;
        }
        currentPage -= 0x1000;
        pagesWalked++;
    }
    LOG("[ERROR] Kernel not found!");
    return 0;
}