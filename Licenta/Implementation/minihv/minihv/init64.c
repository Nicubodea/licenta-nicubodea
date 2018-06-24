#include "minihv.h"
#include "stdio_n.h"
#include "acpica.h"
#include "structures.h"
extern void write_to_port(int a, int b);
extern int read_from_port(int port);
extern void increase_stack();

PMEMORYMAP gE820Map[288];
__int64 gBufferZone = 0;

QWORD globalPagingTable = 0;
void WaitForOtherProcessors()
{
    for (int i = 0; i < 5000000; i++)
    {
        continue;
    }
}

typedef struct _IDT
{
    WORD Length;
    DWORD Base;
} IDT, *PIDT;


typedef struct _DEVICE
{
    __int16     VendorID;
    __int16     DeviceID;
    __int8      Class;
    __int8      Subclass;
    __int8      ProgIF;
} DEVICE, *PDEVICE;


DEVICE gDevices[1024];
int gNumberOfDevices = 0, gE820Entries = 0;

int doneAcpica = 0;


PROCESSOR gProcessors[128];
int gNumberOfProcessors = 0;


void ClearScreen()
{
    PBYTE addr = (PBYTE)0x000B8000;
    int i;
    for (i = 0; i <= 2000; i++)
    {
        sprintf_f(addr, (PBYTE)" ", NULL);
        addr++;
        sprintf_f(addr, (PBYTE)"\7", NULL);
        addr++;
    }
}

void MakeFullPaging()
{
    QWORD PML4, First512GB, e820PageCap, currentPage, currentPML4e, currentPDPTE, mask512Gb;
    DWORD i, j, k;
    
    currentPage = 0;
    e820PageCap = 0;
    PML4 = AcpiOsAllocate(4096);
    PML4 += 0x2000000 - 0x10000000000;
    First512GB = AcpiOsAllocate(4096);
    First512GB += 0x2000000 - 0x10000000000;
    mask512Gb = First512GB;
    for (i = 0; i < gE820Entries; i++)
    {
        if(gE820Map[i]->_start + gE820Map[i]->_length > e820PageCap)
            e820PageCap = gE820Map[i]->_start + gE820Map[i]->_length;
    }
    for (i = 0; currentPage < e820PageCap; i++)
    {
        currentPML4e = AcpiOsAllocate(4096);
        currentPML4e += 0x2000000 - 0x10000000000;
        *(PQWORD)First512GB = currentPML4e | 0x7;
        for (j = 0; j < 512; j++)
        {
            currentPDPTE = AcpiOsAllocate(4096);
            currentPDPTE += 0x2000000 - 0x10000000000;
            *(PQWORD)currentPML4e = currentPDPTE | 0x7;
            for (k = 0; k < 512; k++)
            {
                *(PQWORD)currentPDPTE = currentPage | 0x7;
                currentPage += 0x1000;
                currentPDPTE += 8;
            }
            currentPML4e += 8;
        }
        First512GB += 8;

    }
    *(PQWORD)PML4 = mask512Gb | 0x7;
    // paging virtual space > 1 TB
    PML4 += 16;
    currentPage = 0x2000000;
    First512GB = AcpiOsAllocate(4096);
    First512GB += 0x2000000 - 0x10000000000;
    mask512Gb = First512GB;
    for (i = 0; currentPage < e820PageCap; i++)
    {
        currentPML4e = AcpiOsAllocate(4096);
        currentPML4e += 0x2000000 - 0x10000000000;
        *(PQWORD)First512GB = currentPML4e | 0x7;
        for (j = 0; j < 512; j++)
        {
            currentPDPTE = AcpiOsAllocate(4096);
            currentPDPTE += 0x2000000 - 0x10000000000;
            *(PQWORD)currentPML4e = currentPDPTE | 0x7;
            for (k = 0; k < 512; k++)
            {
                *(PQWORD)currentPDPTE = currentPage | 0x7;
                currentPage += 0x1000;
                currentPDPTE += 8;
            }
            currentPML4e += 8;
        }
        First512GB += 8;
    }
    *(PQWORD)PML4 = mask512Gb | 0x7;
    __writecr3(PML4);
    globalPagingTable = PML4;

}





unsigned int GetVendors(unsigned __int8 bus, unsigned __int8 slot, unsigned __int8 func)
{
    unsigned int bbus = (unsigned int)bus;
    unsigned int bslot = (unsigned int)slot;
    unsigned int bfunc = (unsigned int)func;
    //get vendor for a given bus, slot, function
    //see documentation in function get_info for address query calculation
    unsigned int addr = 0;
    addr = (unsigned int)((bbus << 16) | (bslot << 11) | (bfunc << 8) | (0x80000000)) | addr;
    write_to_port(0xCF8, addr);
    unsigned int ans = read_from_port(0xCFC);
    ans = (ans & 0xffff);

    return ans;

}

unsigned int GetInfo(unsigned __int8 bus, unsigned __int8 slot, unsigned __int8 func, unsigned __int8 offset)
{
    //transform bus, slot, func into 32 bit words (completion with 0)
    unsigned int bbus = (unsigned int)bus;
    unsigned int bslot = (unsigned int)slot;
    unsigned int bfunc = (unsigned int)func;
    unsigned int addr = 0;
    //transform current address
    //bbus is an 8 bit value (0-255)    from bits 22-16
    //bslot is a 5 bit value (0-31)     from bits 15-11
    //bfunc is a 3 bit value (0-7)      from bits 10-8
    //offset is an 8 bit value (0-256)  from bits 7-0
        //offset is and 0xfc because the last 2 bits must be 0 (see address format OS DEV)
        //0x8000000 is for setting the enable bit
    addr = (unsigned int)((bbus << 16) | (bslot << 11) | (bfunc << 8) | (offset & 0xfc) | (0x80000000)) | addr;
    write_to_port(0xCF8, addr); //write address
    unsigned int ans = read_from_port(0xCFC); //get answer
    if (0 == (offset & 2)) //if the lower 16 bits are needed (last 2 bits of offset are now taken into consideration)
        ans = (ans & 0xffff);
    else
        ans = ((ans >> 16) & 0xffff); // upper 16 bits are needed

    return ans;

}


void VerifyCurrentVendor(unsigned __int8 bus, unsigned __int8 slot, int vend)
{
    // get device for current vendor
    int device = GetInfo(bus, slot, 0, 2);
    //get header for current vendor
    int header = GetInfo(bus, slot, 0, 0x0E);
    header = (header & 0xFF);
    //get class attribute
    int cls = GetInfo(bus, slot, 0, 0x0B);
    cls = (cls & 0xFF);
    //get subclass attribute
    int scls = GetInfo(bus, slot, 0, 0x0A);
    scls = (scls & 0xFF);
    //get program if attribute
    int prif = GetInfo(bus, slot, 0, 0x09);
    prif = (prif & 0xFF);
    //add current device to the list of devices
    gDevices[gNumberOfDevices].VendorID     = (__int16) vend;
    gDevices[gNumberOfDevices].DeviceID     = (__int16) device;
    gDevices[gNumberOfDevices].Class        = (__int8)  cls;
    gDevices[gNumberOfDevices].Subclass     = (__int8)  scls;
    gDevices[gNumberOfDevices].ProgIF       = (__int8)  prif;
    gNumberOfDevices++;
    //if it is multifunction
    if ((header & 0x80) != 0)
    {
        //go into the functions
        for (unsigned __int8 function = 1; function < 8; function++)
        {
            //get vendor for current function
            int vendor = GetVendors(bus, slot, function);
            vendor = (vendor & 0xffff);
            //if valid vendor
            if (vendor != 0xffff)
            {
                //get device, class, subclass, and program info
                device = GetInfo(bus, slot, function, 2);
                cls = GetInfo(bus, slot, function, 0x0B);
                cls = (cls & 0xFF);
                scls = GetInfo(bus, slot, function, 0x0A);
                scls = (scls & 0xFF);
                prif = GetInfo(bus, slot, function, 0x09);
                prif = (prif & 0xFF);
                //add new device into the list
                gDevices[gNumberOfDevices].VendorID     = (__int16) vend;
                gDevices[gNumberOfDevices].DeviceID     = (__int16) device;
                gDevices[gNumberOfDevices].Class        = (__int8)  cls;
                gDevices[gNumberOfDevices].Subclass     = (__int8)  scls;
                gDevices[gNumberOfDevices].ProgIF       = (__int8)  prif;
                gNumberOfDevices++;

            }
        }
    }
}

ACPI_MUTEX gMutex;
ACPI_MUTEX allocMutex;
ACPI_SPINLOCK allocLock;
ACPI_SPINLOCK EptLock;
int TestSpinLock(void)
{
    int i;
    
    for (i = 0; i < 1024; i++)
    {
        AcpiOsAcquireMutex(gMutex, -1);
        int x=*((int*)0x7020);
        x++;
        *((int*)0x7020) = x;
        AcpiOsReleaseMutex(gMutex);
    }
    return 0;
}



int Init64(void)
{
    //
    // let's try to do a RDTSC demo...
    //
    AcpiOsCreateLock(&allocLock);
    AcpiOsCreateLock(&EptLock);
    AcpiOsCreateMutex(&gMutex);
#pragma warning(suppress:4127)  // conditional expression is constant

    ClearScreen();
    printf((PBYTE)"miniHV protection by handling hardware interrupts\n", NULL);

    //LOG("STARTED");
    LOG("Test");
    void* argv[5];
    int y;
    // KERNEL_BASE + 0x500 = DWORD - number of entries
    y = *((int*)0x0000010000000500);
    gE820Entries = y;
    long long sd = 12384981142;
    // KERNEL_BASE + 0x504 = start entries of 24 bytes each
    unsigned __int64 addr_start_e820 = 0x0000010000000504, i;

    //LOG("Starting e820 map");
    for (i = 0; i < 288; i++)
    {
        gE820Map[i] = (PMEMORYMAP)(unsigned __int64)addr_start_e820;
        addr_start_e820 += 24;
    }
    for (__int64 addr = 0x4C00; addr < 0x5000; addr+=8)
    {
        *(__int64*)addr = 0;
    }
    //LOG("E820 map loaded");
    argv[0] = (void*)&y;
    //LOG("Getting devices");
    for (int bus = 0; bus < 256; bus++)
    {
        for (int slot = 0; slot < 32; slot++)
        {
            unsigned int vendor;
            vendor = GetVendors((unsigned __int8)bus, (unsigned __int8)slot, 0);
            vendor = (vendor & 0xffff);
            int x = vendor & 0xffff;
            
            if (x != 0xffff)
            {
                VerifyCurrentVendor((unsigned __int8)bus, (unsigned __int8)slot, x);
            }
            
        }
    }
    LOG("[INFO] Finished devices");
    int mb200   = 1024 * 1024 * 512;
    int mb32 = 1024 * 1024 * 32;
    unsigned __int64 auxLength;
    LOG("[INFO] Allocating memory for minihv");
    for (i = 0; i < gE820Entries; i++)
    {
        if (gE820Map[i]->_start <= mb32 && 
            gE820Map[i]->_start + gE820Map[i]->_length > mb32)
        {
            if (gE820Map[i]->_start == mb32)
            {
                gE820Map[i]->_start = mb32 + mb200; //we assume 200 mb continously space is avalaible after 200 mb
                gE820Map[i]->_length = gE820Map[i]->_length - mb200;
            }
            else
            {
                auxLength = gE820Map[i]->_length;
                gE820Map[i]->_length = mb32 - gE820Map[i]->_start;
                
                gE820Map[gE820Entries]->_start = mb32 + mb200;
                gE820Map[gE820Entries]->_length = auxLength - gE820Map[i]->_length - mb200;
                gE820Map[gE820Entries]->type = 1;
                gE820Map[gE820Entries]->optional = 1;
                gE820Entries++;
            }
            //insert the new allocated region
            gE820Map[gE820Entries]->_start = mb32;
            gE820Map[gE820Entries]->_length = mb200;
            gE820Map[gE820Entries]->type = 2;
            gE820Map[gE820Entries]->optional = 1;
            gE820Entries++;
            break;
        }
    }
    //LOG("Allocated %d memory starting from %d", mb200, mb32);
    //LOG("Making additional paging");
    __int64* pd_address;
    __int64 start_address;
    // map first 1gb so that allocation can have place when making page tables
    pd_address = ((__int64*)0x0000010000005000);
    __int64 back = (*(pd_address));
    start_address = 0x0000087;
    for (; pd_address < (__int64*)0x0000010000005FFF; start_address += 0x200000LL)
    {
        (*pd_address) = start_address;
        pd_address++;
    }
 

    MakeFullPaging();

    //LOG("Finished PML4");
    //LOG("Stack increased");
    increase_stack();
    //LOG("ACPICA init started");
    AcpiInitializeTables(NULL, 16, 1);
    
    //ACPI_STATUS zzz = AcpiInitializeSubsystem();
    
    
    AcpiLoadTables();

    //LOG("ACPICA init finished");
    //table are loaded
    //proceed taking MADT (a.k.a APIC)
    __int64 madt;
    ACPI_TABLE_MADT* madtTable;
    UINT32 LocalApicAddress;
    ACPI_TABLE_HEADER* madtHeader;
    AcpiGetTable("APIC", 0, &madtHeader);
   
    madt = (__int64)madtHeader;
    madtTable = madtHeader;
    LocalApicAddress = madtTable->Address;
    
    int ptr = madtHeader->Length;
    UINT32 addr = (UINT32)0x2C;
    for (; addr < madtHeader->Length;)
    {
        BYTE entryType = *(PBYTE)(madt + addr);
        addr++;
        BYTE recordLength = *(PBYTE)(madt + addr);
        addr++;
        if (entryType != 0)
        {
            addr += recordLength - 2;
            continue;
        }
        BYTE acpicpuid = *(PBYTE)(madt + addr);
        addr++;
        BYTE apicid = *(PBYTE)(madt + addr);
        addr++;
        INT32 flags = *(INT32*)(madt + addr);
        addr += 4;
        if (1 == flags)
        {
            gProcessors[gNumberOfProcessors].cpuid = acpicpuid;
            gProcessors[gNumberOfProcessors].apic = apicid;
            gNumberOfProcessors++;

        }
    }
    
    
    LOG("[INFO] Processors interrogated from MADT table");
    LOG("[INFO] Starting processors");
    int Stack_32_Pointer = 0x2C00000;
    __int64 Stack_64_Pointer = 0x10000000000 + 0xC00000;
    __int8* pntr_gdtr = 0x900;
    __int8* pntr_new = 0x1000;
    for (i = 1; i <= 100; i++)
    {
        *(pntr_new) = *(pntr_gdtr);
        pntr_new++;
        pntr_gdtr++;
    }

    for (i = 0; i < gNumberOfProcessors; i++)
    {
        printf("PCPU: %d - APIC ID: %d\n", gProcessors[i].cpuid, gProcessors[i].apic);
    }

    int mask;
    //LOG("Number of processors: %d", gNumberOfProcessors);
    for (i = 1; i < gNumberOfProcessors; i++)
    {
        __int32* lapi = (int*)((UINT32)LocalApicAddress & 0xFFFFFFFF);
        // Initialise LAPIC
        *((int*)0xFEE00350) = (int)0x08700;
        *((int*)0xFEE00360) = (int)0x00400;
        *((int*)0xFEE00370) = (int)0x10000;
        *((int*)0xFEE000F0) = (int)0x1FF;
        //put processor apic in 0x310 register
        
        mask = (gProcessors[i].apic << 24);
        *((int*)0xFEE00310) = (int)mask;
        
        //Put stack
        *((int*)0x7000) = Stack_32_Pointer;
        *((__int64*)0x7004) = Stack_64_Pointer;
        
        //INIT
        mask = 0x2F | (5 << 8) | (1 << 14) | (0 << 15) | (0 << 18) | (0 << 19) | (1 << 12);
        *((int*)0xFEE00300) = mask;
        while ((*((int*)0xFEE00300) & (1 << 12)) != 0); //wait for interrupt to be delivered
        
        //SIPI
        mask = (gProcessors[i].apic << 24);
        *((int*)0xFEE00310) = (int)mask;
        mask = 0x6 | (6 << 8) | (1 << 14) | (0 << 15) | (0 << 18) | (0 << 19) | (1 << 12); // send sipi
        *((int*)0xFEE00300) = mask;
        while ((*((int*)0xFEE00300) + 0x300) & (1 << 12)); //wait for interrupt to be delivered
        //SIPI
        mask = (gProcessors[i].apic << 24);
        *((int*)0xFEE00310) = (int)mask;
        mask = 0x6 | (6 << 8) | (1 << 14) | (0 << 15) | (0 << 18) | (0 << 19) | (1 << 12); // send second sipi
        *((int*)0xFEE00300) = mask;
        while (*((int*)0xFEE00300) & (1 << 12)); //wait for interrupt to be delivered
        ////LOG("CPU open");
        gProcessors[i].stack_base = Stack_64_Pointer;
        gProcessors[i].stack_size = 0x3000;
        Stack_32_Pointer += 0x3000;
        Stack_64_Pointer += 0x3000;
        gProcessors[i].data_zone = AcpiOsAllocate(4096);
        gProcessors[i].msr_area = AcpiOsAllocate(8192);
        gProcessors[i].vmxon = AcpiOsAllocate(4096);
        gProcessors[i].vmcs = AcpiOsAllocate(4096);
        gProcessors[i].isBsp = 0;
        //LOG("Processor %d started with stack at %l", i, Stack_64_Pointer);
        //Wait a little bit so that the processor will go into 64 bits => no concurence problems as we don't have any sync mechanism yet
        WaitForOtherProcessors();
        //now verify memory
    }
    doneAcpica = 1;
    WaitForOtherProcessors();
    
    // hook using vmcall - tbd
    
    MhvGuestHook15();
    
    LOG("[INFO] Hooking int 0x15 (Memory Map Hooking)");
    //Hookint15h();

    int size = 0x1000;
    int location = 0x4800;
    // Add 4kb location
    for (i = 0; i < gE820Entries; i++)
    {
        if (gE820Map[i]->_start <= location &&
            gE820Map[i]->_start + gE820Map[i]->_length > location)
        {
            if (gE820Map[i]->_start == location)
            {
                gE820Map[i]->_start = location + size; //we assume 200 mb continously space is avalaible after 200 mb
                gE820Map[i]->_length = gE820Map[i]->_length - size;
            }
            else
            {
                auxLength = gE820Map[i]->_length;
                gE820Map[i]->_length = location - gE820Map[i]->_start;

                gE820Map[gE820Entries]->_start = location + size;
                gE820Map[gE820Entries]->_length = auxLength - gE820Map[i]->_length - size;
                gE820Map[gE820Entries]->type = 1;
                gE820Map[gE820Entries]->optional = 1;
                gE820Entries++;
            }
            //insert the new allocated region
            gE820Map[gE820Entries]->_start = location;
            gE820Map[gE820Entries]->_length = size;
            gE820Map[gE820Entries]->type = 2;
            gE820Map[gE820Entries]->optional = 1;
            gE820Entries++;
            break;
        }
    }


    LOG("[INFO] Starting synchronizing mechanism test");
    gBufferZone = AcpiOsAllocate(0x1000);
    gBufferZone += 0x2000000;
    gBufferZone -= 0x10000000000;
    for (i = 1; i < gNumberOfProcessors; i++)
    {
        //start quicktest for processor synchronization
        mask = (gProcessors[i].apic << 24);
        *((int*)0xFEE00310) = (int)mask;
        mask = 0 | (4 << 8) | (0 << 14) | (0 << 15) | (0 << 18) | (0 << 19) | (1 << 12);
        *((int*)0xFEE00300) = mask;
        while ((*((int*)0xFEE00300) & (1 << 12)) != 0); //wait for interrupt to be delivered
        WaitForOtherProcessors();
        mask = (gProcessors[i].apic << 24);
        *((int*)0xFEE00310) = (int)mask;
        mask = 0x1F | (4 << 8) | (0 << 14) | (0 << 15) | (0 << 18) | (0 << 19) | (1 << 12);
        *((int*)0xFEE00300) = mask;
        while ((*((int*)0xFEE00300) & (1 << 12)) != 0); //wait for interrupt to be delivered
        WaitForOtherProcessors();
    }
    LOG("[INFO] Sync test succeeded");
    int j;
    for (i = 0; i < gE820Entries; i++)
    {
        for (j = i + 1; j < gE820Entries; j++)
        {
            if (gE820Map[i]->_start > gE820Map[j]->_start)
            {
                PMEMORYMAP aux = gE820Map[i];
                gE820Map[i] = gE820Map[j];
                gE820Map[j] = aux;
            }
        }
    }
    LOG("[INFO] Putting memory map under 1 MB so that int15 Hook can get our entries");
    PMEMORYMAP addressE820 = 0x4C00;
    for (i = 0; i < gE820Entries; i++)
    {
        LOG("[INFO] E820 Map Entry %d:", i);
        LOG("[INFO]      Start:    %x", gE820Map[i]->_start);
        LOG("[INFO]      Length:   %x", gE820Map[i]->_length);
        LOG("[INFO]      Type:     %d", gE820Map[i]->type);
        LOG("[INFO]      Optional: %d", gE820Map[i]->optional);
        *((__int64*)addressE820) = gE820Map[i]->_start;
        (__int64*)addressE820 = (__int64*)addressE820 + 1;
        *((__int64*)addressE820) = gE820Map[i]->_length;
        (__int64*)addressE820 = (__int64*)addressE820 + 1;
        *((__int32*)addressE820) = gE820Map[i]->type;
        (__int32*)addressE820 = (__int32*)addressE820 + 1;
        *((__int32*)addressE820) = gE820Map[i]->optional;
        (__int32*)addressE820 = (__int32*)addressE820 + 1;
        
    }

    LOG("[INFO] Finally pre-init BSP processor");
    gProcessors[0].isBsp = 1;
    gProcessors[0].apic = gProcessors[0].cpuid = 0;
    gProcessors[0].data_zone = AcpiOsAllocate(4096);
    gProcessors[0].vmxon = AcpiOsAllocate(4096);
    gProcessors[0].vmcs = AcpiOsAllocate(4096);
    gProcessors[0].msr_area = AcpiOsAllocate(8192);
    LOG("[INFO] Starting vmx in BSP (PCPU 0)");
    WaitForOtherProcessors();

    
    MhvStartVmx();

    while (TRUE)
    {
        volatile QWORD temp;
        temp = __rdtsc();
        
        if (temp == 0)
        {
            temp = 1;
        }
        
    }
    return 0;
}
