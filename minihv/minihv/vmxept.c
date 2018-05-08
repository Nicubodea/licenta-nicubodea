#include "vmxept.h"
#include "structures.h"
#include "acpica.h"
#include "vmxop.h"
#include "epthook.h"

#define PML4_INDEX(Va) (((Va) & 0x0000ff8000000000) >> 39)
#define PDP_INDEX(Va) (((Va) & 0x0000007fc0000000) >> 30)
#define PD_INDEX(Va) (((Va) & 0x000000003fe00000) >> 21)
#define PT_INDEX(Va) (((Va) & 0x00000000001ff000) >> 12)
#define CLEAN_PHYS_ADDR(Addr) ((Addr) & 0x000FFFFFFFFFF000)

VOID
MhvInitEptHooksModule(

)
{

}

PEPT_HOOK
MhvEptMakeHook(
    PVOID               Procesor,
    QWORD               PhysPage,
    QWORD               AccessHooked,
    QWORD               Cr3,
    QWORD               GLA,
    PFUNC_EptCallback   PreCallback,
    PFUNC_EptCallback   PostCallback

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

    pdeEntry->PhysicalAddress[PT_INDEX(PhysPage)] &= ~AccessHooked;
    EPT_HOOK newEptHook;
    QWORD cr3 = 0;

    newEptHook.Offset = PhysPage & 0xFFF;
    newEptHook.Cr3 = Cr3;
    newEptHook.GuestLinearAddress = CLEAN_PHYS_ADDR(GLA);
    newEptHook.GuestPhysicalAddress = CLEAN_PHYS_ADDR(PhysPage);
    newEptHook.PreActionCallback = PreCallback;
    newEptHook.PostActionCallback = PostCallback;
    newEptHook.TimesCalled = 0;

    // TODO: linked list
    gEptHooks[gNumberOfEptHooks] = newEptHook;

    gNumberOfEptHooks++;

    toReturn = &gEptHooks[gNumberOfEptHooks - 1];

    return toReturn;
}

VOID
MhvEptPurgeHook(
    PVOID       Procesor,
    QWORD       PhysPage
)
{
    PPROCESOR Processor = Procesor;
    PEPT_POINTER eptPointer = CLEAN_PHYS_ADDR((QWORD)Processor->EptPointer);

    PEPT_PML4_ENTRY pml4Entry = CLEAN_PHYS_ADDR((QWORD)eptPointer->PdpeArray[PML4_INDEX(PhysPage)]);

    PEPT_PDPE_ENTRY pdpeEntry = CLEAN_PHYS_ADDR((QWORD)pml4Entry->PdeArray[PDP_INDEX(PhysPage)]);

    PEPT_PDE_ENTRY pdeEntry = CLEAN_PHYS_ADDR((QWORD)pdpeEntry->PteArray[PD_INDEX(PhysPage)]);

    //AcpiOsAcquireLock(gEptLock);
    DWORD refCnt = 0;
    for (DWORD i = 0; i < gNumberOfEptHooks; i++)
    {
        if (gEptHooks[i].GuestPhysicalAddress == CLEAN_PHYS_ADDR(PhysPage))
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
        LOG("[INFO] Still keeping hook as refCnt = %x", refCnt);
    }
    DWORD hookIndex = gNumberOfEptHooks;
    for (DWORD i = 0; i < gNumberOfEptHooks; i++)
    {
        if (gEptHooks[i].GuestPhysicalAddress == CLEAN_PHYS_ADDR(PhysPage) &&
            gEptHooks[i].Offset == (PhysPage & 0xFFF))
        {
            LOG("[HK-DMP] Deleting hook ---> %x offset %x", gEptHooks[i].GuestPhysicalAddress, gEptHooks[i].Offset);
            hookIndex = i;
            break;
        }
    }
    for (DWORD i = hookIndex; i < gNumberOfEptHooks - 1; i++)
    {
        gEptHooks[i] = gEptHooks[i + 1];
    }
    if (hookIndex != gNumberOfEptHooks)
    {
        gNumberOfEptHooks--;
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
        for (j = 0; j < 512; j++)
        {
            LOG("------> Level %d", j);

            for (k = 0; k < 512; k++)
            {
                LOG("---------> Level %d", k);

                for (t = 0; t < 512; t++)
                {
                    LOG("------------> Level %d, entry %x", t,Ept->PdpeArray[i]->PdeArray[j]->PteArray[k]->PhysicalAddress[t]);

                }

            }
            
        }
    }


}

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

    LOG("[INFO] last = %x", lastAlloc);

    LOG("[INFO] Making rights for ept");
    MhvEptMakeFullRightsForEpt(eptPointer);

    return eptPointer;

}