#include "guest.h"
#include "vmxept.h"
#include "structures.h"
#include "acpica.h"
#include "vmxop.h"
#include "epthook.h"
#include "alloc.h"


#define PML4_INDEX(Va) (((Va) & 0x0000ff8000000000) >> 39)
#define PDP_INDEX(Va) (((Va) & 0x0000007fc0000000) >> 30)
#define PD_INDEX(Va) (((Va) & 0x000000003fe00000) >> 21)
#define PT_INDEX(Va) (((Va) & 0x00000000001ff000) >> 12)
#define CLEAN_PHYS_ADDR(Addr) ((Addr) & 0x000FFFFFFFFFF000)
#define PTE_BITS(Addr) ((Addr) & 0x000FFFFFFFFFF081)

#define FLAG_NORMAL_HOOK 0
#define FLAG_PML4_HOOK 1
#define FLAG_PDPTE_HOOK 2
#define FLAG_PDE_HOOK 3
#define FLAG_PT_HOOK 4
#define FLAG_NOT_ACTIVE 0x10
#define FLAG_SWAP       0x20
#define FLAG_DELETED    0x40

VOID
MhvDumpEptHooks(

)
{
    LIST_ENTRY* list = pGuest.EptHooksList.Flink;

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        LOG("[DMP-HOOK] Dumping existent Hook @ %x -> %x %x %x", pHook, pHook->GuestPhysicalAddress, pHook->Offset, pHook->Flags);

    }

}

VOID
MhvDeleteHookByOwner(
    PVOID Owner
)
{
    LIST_ENTRY* list = pGuest.EptHooksList.Flink;


    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;
        
        if (pHook->Owner == Owner)
        {
            //LOG("[INFO] Deleting hook on %x gva %x offset %x flags %x", pHook->GuestPhysicalAddress, pHook->GuestLinearAddress, pHook->Offset, pHook->Flags);
            MhvDeleteHookHierarchy(pHook);
        }
    }
}


VOID
MhvDeleteHookHierarchy(
    PEPT_HOOK Hook
)
{
    
    while (Hook->ParentHook != NULL)
    {
        //LOG("[Hook] %x -> parent hook -> %x", Hook, Hook->ParentHook);
        //LOG("[INFO] Deleting hook on %x gva %x offset %x flags %x", Hook->GuestPhysicalAddress, Hook->GuestLinearAddress, Hook->Offset, Hook->Flags);

        PEPT_HOOK saved = Hook->ParentHook;
        MhvEptDeleteHook(Hook, pGuest.Vcpu);
        Hook = saved;
    }


    //LOG("[Hook] finally deleting hook %x", Hook);
    //LOG("[INFO] Deleting hook on %x gva %x offset %x flags %x", Hook->GuestPhysicalAddress, Hook->GuestLinearAddress, Hook->Offset, Hook->Flags);
    MhvEptDeleteHook(Hook, pGuest.Vcpu);
}

NTSTATUS
MhvSwapCallback(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    PEPT_HOOK pHook = ((PEPT_HOOK)Hook);
    PQWORD old = ((PBYTE)pHook->GuestPhysicalAddress) + pHook->Offset;
    PPROCESOR Processor = Procesor;

    //LOG("[INFO] PT written: @%x -> new: %x, flags: %d", pHook->GuestPhysicalAddress + pHook->Offset, *old, pHook->Flags);

    //LOG("[INFO] PT hook, remake the hook");
    
    if ((pHook->Flags & FLAG_NOT_ACTIVE) == 0 && PTE_BITS(*old) == PTE_BITS(pHook->WhatIsThere))

    {
        //LOG("[INFO] Hook is active and old is active and is the same with new, will return %x %x", *old, pHook->WhatIsThere);
        return STATUS_SUCCESS;
    }

    //LOG("[INFO] PT was written: %x", pHook->GuestPhysicalAddress + pHook->Offset);
    //LOG("[INFO] Swap callback: new @%x: %x, old: %x, flags: %x", pHook->GuestPhysicalAddress + pHook->Offset, *old, pHook->WhatIsThere, pHook->Flags);

    pHook->WhatIsThere = *old;

    PEPT_HOOK pHooks = pHook->LinkHook;
    QWORD cflag = pHook->Flags & 0xF;
    EPT_HOOK lastHooks[5];
    DWORD lastflag = 5;
    while (cflag < 5)
    {
        lastHooks[cflag] = *pHooks;
        PEPT_HOOK saved = pHooks->LinkHook;
        MhvEptDeleteHook(pHooks, Procesor);
        pHooks = saved;
        cflag++;
    }

    cflag = pHook->Flags;
    BOOLEAN isActive = TRUE;

    while (cflag < 5)
    {
        old = ((PBYTE)pHook->GuestPhysicalAddress) + pHook->Offset;
        DWORD currentFlags = lastHooks[cflag].Flags;
        if (!isActive || pHook->GuestPhysicalAddress == 0 || (((*old) & 1) != 1))
        {
            //LOG("[INFO] marking hook as not active!");
            currentFlags |= FLAG_NOT_ACTIVE;
            isActive = FALSE;
        }
        else if ((lastHooks[cflag].Flags & FLAG_NOT_ACTIVE) == FLAG_NOT_ACTIVE)
        {
            //LOG("[INFO] old == %x", *old);
            //LOG("[INFO] marking hook as active!");
            currentFlags &= ~FLAG_NOT_ACTIVE;
        }
        pHook->LinkHook = MhvEptMakeHook(Procesor, 
            isActive? CLEAN_PHYS_ADDR(*old) + lastHooks[cflag].Offset : 0 + lastHooks[cflag].Offset, 
            lastHooks[cflag].AccessHooked, 
            lastHooks[cflag].Cr3, 
            lastHooks[cflag].GuestLinearAddress, 
            lastHooks[cflag].PreActionCallback, 
            lastHooks[cflag].PostActionCallback, 
            currentFlags, 
            lastHooks[cflag].Size);
        pHook->LinkHook->Owner = lastHooks[cflag].Owner;
        if (pHook->LinkHook->Owner != NULL)
        {
            //LOG("[INFO] For swapped hook %x the new owner is %x", pHook->LinkHook, pHook->LinkHook->Owner);
        }
        pHook->LinkHook->ParentHook = pHook;
        pHook = pHook->LinkHook;
        cflag++;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
MhvSwapBeforeCallback(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    PEPT_HOOK pHook = ((PEPT_HOOK)Hook);
    PQWORD old = ((PBYTE)pHook->GuestPhysicalAddress) + pHook->Offset;
    PPROCESOR Processor = Procesor;

    //LOG("[INFO] PT hook: @%x -> old: %x, flags: %d", pHook->GuestPhysicalAddress + pHook->Offset, *old, pHook->Flags);

    //if (pHook->Flags == FLAG_PDE_HOOK)
    //{
        //LOG("[INFO] Pt Hook -> purging hook...");
        //MhvEptPurgeHook(Procesor, CLEAN_PHYS_ADDR(*old), TRUE);
        Processor->OldPTE = *old;
    //}

    return STATUS_SUCCESS;

}

PEPT_HOOK
MhvCreateEptHook(
    PVOID Procesor,
    QWORD PhysPage,
    QWORD AccessHooked,
    QWORD Cr3,
    QWORD Gla,
    PFUNC_EptCallback   PreCallback,
    PFUNC_EptCallback   PostCallback,
    QWORD Size,
    BOOLEAN IsSwapIn
)
{

    PQWORD pml4, pdpte, pde;
    PQWORD phys;
    PBYTE realPhys;
    pml4 = Cr3;
    
    PEPT_HOOK pHookPml = MhvEptMakeHook(Procesor, pml4 + PML4_INDEX(Gla), EPT_WRITE_RIGHT, NULL, NULL, MhvSwapBeforeCallback, MhvSwapCallback, FLAG_PML4_HOOK, 8);

    pdpte = CLEAN_PHYS_ADDR(pml4[PML4_INDEX(Gla)]);

    PEPT_HOOK pHookPdpte = MhvEptMakeHook(Procesor, pdpte + PDP_INDEX(Gla), EPT_WRITE_RIGHT, NULL, NULL, MhvSwapBeforeCallback, MhvSwapCallback, pdpte == 0 ? FLAG_NOT_ACTIVE | FLAG_PDPTE_HOOK : FLAG_PDPTE_HOOK, 8);

    pHookPml->LinkHook = pHookPdpte;
    pHookPml->ParentHook = NULL;

    pHookPdpte->ParentHook = pHookPml;

    pde = pdpte == 0 ? 0 : CLEAN_PHYS_ADDR(pdpte[PDP_INDEX(Gla)]);

    PEPT_HOOK pHookPde = MhvEptMakeHook(Procesor, pde + PD_INDEX(Gla), EPT_WRITE_RIGHT, NULL, NULL, MhvSwapBeforeCallback, MhvSwapCallback, pde == 0 ? FLAG_NOT_ACTIVE | FLAG_PDE_HOOK : FLAG_PDE_HOOK, 8);

    pHookPdpte->LinkHook = pHookPde;
    pHookPde->ParentHook = pHookPdpte;

    phys = pde == 0 ? 0 : CLEAN_PHYS_ADDR(pde[PD_INDEX(Gla)]);

    PEPT_HOOK pHookPt = MhvEptMakeHook(Procesor, phys + PT_INDEX(Gla), EPT_WRITE_RIGHT, NULL, NULL, MhvSwapBeforeCallback, MhvSwapCallback, phys == 0? FLAG_NOT_ACTIVE | FLAG_PT_HOOK : FLAG_PT_HOOK, 8);

    pHookPde->LinkHook = pHookPt;
    pHookPt->ParentHook = pHookPde;

    realPhys = phys == 0 ? 0 : CLEAN_PHYS_ADDR(phys[PT_INDEX(Gla)]);

    PEPT_HOOK pRealHook = MhvEptMakeHook(Procesor, realPhys + (PhysPage & 0xFFF), AccessHooked, Cr3, Gla, PreCallback, PostCallback, CLEAN_PHYS_ADDR(PhysPage) == 0 ? FLAG_NOT_ACTIVE | FLAG_NORMAL_HOOK : FLAG_NORMAL_HOOK, Size);

    if (IsSwapIn)
    {
        pRealHook->Flags |= FLAG_SWAP;
    }

    pHookPt->LinkHook = pRealHook;
    pRealHook->ParentHook = pHookPt;

    //LOG("[INFO] Pml %x -> Pdpte %x -> Pde %x -> Pt %x -> real %x", pHookPml, pHookPdpte, pHookPde, pHookPt, pRealHook);

    return pRealHook;
}

PEPT_HOOK
MhvEptMakeHook(
    PVOID               Procesor,
    QWORD               PhysPage,
    QWORD               AccessHooked,
    QWORD               Cr3,
    QWORD               GLA,
    PFUNC_EptCallback   PreCallback,
    PFUNC_EptCallback   PostCallback,
    QWORD               Flags,
    QWORD               Size

)
{
    PPROCESOR Processor = Procesor;
    PEPT_HOOK toReturn = NULL;

    PEPT_POINTER eptPointer = CLEAN_PHYS_ADDR((QWORD)Processor->EptPointer);

    PEPT_PML4_ENTRY pml4Entry = CLEAN_PHYS_ADDR((QWORD)eptPointer->PdpeArray[PML4_INDEX(PhysPage)]);

    PEPT_PDPE_ENTRY pdpeEntry = CLEAN_PHYS_ADDR((QWORD)pml4Entry->PdeArray[PDP_INDEX(PhysPage)]);

    PEPT_PDE_ENTRY pdeEntry = CLEAN_PHYS_ADDR((QWORD)pdpeEntry->PteArray[PD_INDEX(PhysPage)]);
    //LOG("[EPT-MAKE-HOOK] Entered");
    //AcpiOsAcquireLock(gEptLock);


    //LOG("[INFO] Creating Hook on GLA %x GPA %x ept: %x -> %x -> %x -> %x, Flags: %x, size: %x", GLA, PhysPage, eptPointer->PdpeArray[PML4_INDEX(PhysPage)], pml4Entry->PdeArray[PDP_INDEX(PhysPage)], pdpeEntry->PteArray[PD_INDEX(PhysPage)], pdeEntry->PhysicalAddress[PT_INDEX(PhysPage)], Flags, Size);

    PEPT_HOOK newEptHook = MemAllocContiguosMemory(sizeof(EPT_HOOK));
    QWORD cr3 = 0;
    

    newEptHook->Offset = PhysPage & 0xFFF;
    newEptHook->Cr3 = Cr3;
    newEptHook->GuestLinearAddress = GLA;
    newEptHook->GuestPhysicalAddress = CLEAN_PHYS_ADDR(PhysPage);
    newEptHook->PreActionCallback = PreCallback;
    newEptHook->PostActionCallback = PostCallback;
    newEptHook->AccessHooked = AccessHooked;
    newEptHook->TimesCalled = 0;
    newEptHook->Flags = Flags;
    newEptHook->Size = Size;
    newEptHook->LinkHook = NULL;
    newEptHook->Owner = NULL;

    if ((Flags & FLAG_NOT_ACTIVE) != FLAG_NOT_ACTIVE)
    {
        pdeEntry->PhysicalAddress[PT_INDEX(PhysPage)] &= ~AccessHooked;
        newEptHook->WhatIsThere = *(PQWORD)PhysPage;
        MyInvEpt(2, NULL);
    }

    InsertTailList(&pGuest.ToAppendHooks, &newEptHook->Link);

    return newEptHook;
}

VOID
MhvEptPurgeHookFromEpt(
    PEPT_HOOK Hook,
    PVOID Procesor
)
{
    QWORD PhysPage = Hook->GuestPhysicalAddress + Hook->Offset;

    PPROCESOR Processor = Procesor;

    PEPT_POINTER eptPointer = CLEAN_PHYS_ADDR((QWORD)Processor->EptPointer);

    PEPT_PML4_ENTRY pml4Entry = CLEAN_PHYS_ADDR((QWORD)eptPointer->PdpeArray[PML4_INDEX(PhysPage)]);

    PEPT_PDPE_ENTRY pdpeEntry = CLEAN_PHYS_ADDR((QWORD)pml4Entry->PdeArray[PDP_INDEX(PhysPage)]);

    PEPT_PDE_ENTRY pdeEntry = CLEAN_PHYS_ADDR((QWORD)pdpeEntry->PteArray[PD_INDEX(PhysPage)]);

    //AcpiOsAcquireLock(gEptLock);
    DWORD refCnt = 0;

    LIST_ENTRY* list = pGuest.EptHooksList.Flink;

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if (pHook->GuestPhysicalAddress == CLEAN_PHYS_ADDR(PhysPage) && (pHook->Flags & FLAG_NOT_ACTIVE) == 0)
        {
            refCnt++;
        }
    }

    if ((Hook->Flags & FLAG_NOT_ACTIVE) == 0 || Hook->GuestPhysicalAddress != 0)
    {
        if (refCnt <= 1)
        {
            // don't delete page hook only if the last one!!!
            //LOG("[INFO] Hook @ %x -> gva %x offset %x flags %x will be purged!", Hook->GuestPhysicalAddress, Hook->GuestLinearAddress, Hook->Offset, Hook->Flags);
            pdeEntry->PhysicalAddress[PT_INDEX(PhysPage)] |= EPT_FULL_RIGHTS;
            MyInvEpt(2, NULL);
        }
        else
        {
            //LOG("[INFO] Still keeping hook as refCnt = %x", refCnt);
        }
    }
}

VOID MhvEptDeleteHook(
    PEPT_HOOK Hook,
    PVOID Procesor
)
{
    if (Hook != NULL)
    {
        Hook->Owner = NULL; // orphan :(

        Hook->Flags |= FLAG_NOT_ACTIVE | FLAG_DELETED;
    }
}

VOID
MhvEptPurgeHook(
    PVOID       Procesor,
    QWORD       PhysPage,
    BOOLEAN     PurgePDE
)
{
    PPROCESOR Processor = Procesor;
    PEPT_POINTER eptPointer = CLEAN_PHYS_ADDR((QWORD)Processor->EptPointer);

    PEPT_PML4_ENTRY pml4Entry = CLEAN_PHYS_ADDR((QWORD)eptPointer->PdpeArray[PML4_INDEX(PhysPage)]);

    PEPT_PDPE_ENTRY pdpeEntry = CLEAN_PHYS_ADDR((QWORD)pml4Entry->PdeArray[PDP_INDEX(PhysPage)]);

    PEPT_PDE_ENTRY pdeEntry = CLEAN_PHYS_ADDR((QWORD)pdpeEntry->PteArray[PD_INDEX(PhysPage)]);

    //AcpiOsAcquireLock(gEptLock);
    DWORD refCnt = 0;

    LIST_ENTRY* list = pGuest.EptHooksList.Flink;

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if (pHook->GuestPhysicalAddress == CLEAN_PHYS_ADDR(PhysPage))
        {
            refCnt++;
        }
    }
   
    if (refCnt <= 1)
    {
        // don't delete page hook only if the last one!!!
        pdeEntry->PhysicalAddress[PT_INDEX(PhysPage)] |= EPT_FULL_RIGHTS;
    }
    else
    {
        //LOG("[INFO] Still keeping hook as refCnt = %x", refCnt);
    }

    PEPT_HOOK toDelete = NULL;

    list = pGuest.EptHooksList.Flink;

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if (pHook->GuestPhysicalAddress == CLEAN_PHYS_ADDR(PhysPage) &&
            (pHook->Offset == (PhysPage & 0xFFF)))
        {
            toDelete = pHook;
            break;
        }
    }

    if (toDelete != NULL)
    {
        RemoveEntryList(&toDelete->Link);
    }
    else
    {
        LOG("[WTF???]");
    }
}


VOID
MhvEptMakeFullRightsForEpt(
    PEPT_POINTER Ept
)
{
    DWORD i, j, k;

    for (i = 0; i < EPT_TABLE_ENTRIES_SIZE; i++)
    {
        if (Ept->PdpeArray[i] == 0)
        {
            continue;
        }
        //LOG("--> ENTRY LEVEL 1: %x", Ept->PdpeArray[i]);
        for (j = 0; j < EPT_TABLE_ENTRIES_SIZE; j++)
        {
            if (Ept->PdpeArray[i]->PdeArray[j] == 0)
            {
                continue;
            }
            //LOG("-----> ENTRY LEVEL 2: %x", Ept->PdpeArray[i]->PdeArray[j]);
            for (k = 0; k < EPT_TABLE_ENTRIES_SIZE; k++)
            {
                if (Ept->PdpeArray[i]->PdeArray[j]->PteArray[k] == 0)
                {
                    continue;
                }

                //LOG("----------> ENTRY LEVEL 3: %x", Ept->PdpeArray[i]->PdeArray[j]->PteArray[k]);
                (QWORD)(Ept->PdpeArray[i]->PdeArray[j]->PteArray[k]) |= EPT_FULL_RIGHTS;
            }

            (QWORD)(Ept->PdpeArray[i]->PdeArray[j]) |= EPT_FULL_RIGHTS;
        }
        
        (QWORD)(Ept->PdpeArray[i]) |= EPT_FULL_RIGHTS;
    }

}

MhvDumpEpt(PEPT_POINTER Ept)
{
    int i, j, k, t;
    for (i = 0; i < 512; i++)
    {
        LOG("---> Level %d", i);
        QWORD old = Ept->PdpeArray[i];
        (QWORD)Ept->PdpeArray[i] &= ~0x3F;
        for (j = 0; j < 512; j++)
        {
            LOG("------> Level %d", j);
            QWORD old2 = Ept->PdpeArray[i]->PdeArray[j];
            (QWORD)Ept->PdpeArray[i]->PdeArray[j] &= ~0x3F;

            for (k = 0; k < 512; k++)
            {
                QWORD old3 = Ept->PdpeArray[i]->PdeArray[j];
                (QWORD)Ept->PdpeArray[i]->PdeArray[j]->PteArray[k] &= ~0x3F;
                LOG("---------> Level %d", k);

                for (t = 0; t < 512; t++)
                {
                    LOG("------------> Level %d, entry %x", t,Ept->PdpeArray[i]->PdeArray[j]->PteArray[k]->PhysicalAddress[t]);

                }

                (QWORD)Ept->PdpeArray[i]->PdeArray[j]->PteArray[k] = old3;
            }
            
            (QWORD)Ept->PdpeArray[i]->PdeArray[j] = old2;
        }

        (QWORD)Ept->PdpeArray[i] = old;
    }


}

BOOLEAN b = FALSE;

PEPT_POINTER
MhvMakeEpt(
)
{
    PEPT_POINTER eptPointer = NULL;
    QWORD eptPageCap = 0;
    PEPT_PDPE_ENTRY currentPDPE;
    QWORD currentAddr = 0x0;
    DWORD pm = 0;
    DWORD lastI = 1;
    QWORD lastAlloc;

    if (gNrMtrrs == 0)
    {
        MhvMakeMtrr();
    }

    eptPointer = AcpiOsAllocate(PAGE_SIZE);
    eptPointer = GetPhysicalAddr(eptPointer);

    PEPT_PML4_ENTRY pml4 = AcpiOsAllocate(PAGE_SIZE);
    pml4 = GetPhysicalAddr(pml4);
    
    // get max nr of pages to be mapped into ept
    eptPageCap = gE820Map[gE820Entries - 1]->_start + gE820Map[gE820Entries - 1]->_length;

    eptPointer->PdpeArray[0] = (QWORD)pml4;

    for (DWORD i = 1; i < 512; i++)
    {
        eptPointer->PdpeArray[i] = 0x0;
    }

    for (DWORD i = 0; i < 512; i++)
    {
        pml4->PdeArray[i] = 0x0;
    }
    
    for (DWORD i = 1; currentAddr < eptPageCap; i++)
    {
        currentPDPE = AcpiOsAllocate(PAGE_SIZE);
        currentPDPE = GetPhysicalAddr(currentPDPE);
        for (DWORD j = 0; j < 512; j++)
        {
            currentPDPE->PteArray[j] = 0;
        }

        pml4->PdeArray[i - 1] = currentPDPE;
        PEPT_PDE_ENTRY currentPDE;
        for (DWORD j = 1; j <= 512 && currentAddr < eptPageCap; j++)
        {
            currentPDE = AcpiOsAllocate(PAGE_SIZE);
            currentPDE = GetPhysicalAddr(currentPDE);
            lastAlloc = currentPDE;
            
            for (DWORD k = 0; k < 512; k++)
            {
                currentPDE->PhysicalAddress[k] = 0;
            }
            
            currentPDPE->PteArray[j - 1] = currentPDE;

            sizeof(EPT_PDE_ENTRY);

            for (DWORD k = 1; k <= 512 && currentAddr < eptPageCap; k++)
            {
                DWORD found = 0;
                if (currentAddr < 1024 * 1024)
                {
                    for (pm = 0; pm < gNrMtrrs; pm++)
                    {
                        if (0 == gMtrrs[pm].MtrType)
                        {
                            if (currentAddr >= gMtrrs[pm].PhysBase && currentAddr <= gMtrrs[pm].Range)
                            {
                                currentPDE->PhysicalAddress[k-1] = ((currentAddr | EPT_FULL_RIGHTS) | (gMtrrs[pm].MemoryType << 3));
                                found = 1;
                                break;
                            }

                        }
                    }
                }
                if (currentAddr >= 1024 * 1024)
                {

                    for (pm = 0; pm < gNrMtrrs; pm++)
                    {
                        if (1 == gMtrrs[pm].MtrType)
                        {
                            if ((currentAddr & gMtrrs[pm].PhysMask) == (gMtrrs[pm].PhysBase & gMtrrs[pm].PhysMask))
                            {
                                if (found)
                                {
                                    if ((((currentPDE->PhysicalAddress[k-1]) & 0x38) >> 3) > gMtrrs[pm].MemoryType)
                                    {
                                        currentPDE->PhysicalAddress[k-1] = ((currentAddr | EPT_FULL_RIGHTS) | (gMtrrs[pm].MemoryType << 3));
                                        continue;
                                    }
                                }
                                currentPDE->PhysicalAddress[k-1] = ((currentAddr | EPT_FULL_RIGHTS) | (gMtrrs[pm].MemoryType << 3));
                                found = 1;
                            }
                        }
                    }
                }
                if (!found)
                {
                    currentPDE->PhysicalAddress[k-1] = ((currentAddr | EPT_FULL_RIGHTS)); // uncachable
                }
                currentAddr += PAGE_SIZE;
            }

        }
        lastI = i;
    }

    //MhvDumpEpt(eptPointer);

    LOG("[INFO] last = %x, lastI = %d", lastAlloc, lastI);

    //LOG("[INFO] Making rights for ept");
    MhvEptMakeFullRightsForEpt(eptPointer);

    if (!b)
    {
        //MhvDumpEpt(eptPointer);
    }

    b = TRUE;
    return eptPointer;

}