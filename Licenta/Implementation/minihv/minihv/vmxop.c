
#include "vmxop.h"
#include "vmxhook.h"
#include "ntstatus.h"
#include "vmxept.h"
#include "epthook.h"
#include "vmxmtf.h"
#include "winproc.h"
#include "guest.h"
#include "except.h"
#include "Zydis/Zydis.h"
#include "vmxcomm.h"

MTR gMtrrs[196];
DWORD gNrMtrrs = 0;

PQWORD EptPointer = 0;
DWORD eptDone = 0, notDone = 1;

extern void Hook_VMExit();

PQWORD GetPhysicalAddr(PQWORD x)
{
    return (PQWORD)((QWORD)x - 0x10000000000 + 0x2000000);
}

WORD gInt15Base = 0, gInt15Segment = 0;
DWORD gOsVersionMBR = 0;

void MhvGuestHook15()
{
    gInt15Base = *(PWORD)(0x15 * 4);
    gInt15Segment = *(PWORD)(0x15 * 4 + 2);
    for (BYTE i = 0; i < 0x30; i++)
    {
        *((PBYTE)0x5100 + i) = *((PBYTE)(Hook_VMExit) + i);
    }
    *(PWORD)(0x15 * 4) = 0x5100;
    *(PWORD)(0x15 * 4 + 2) = 0;
}


void MhvHandleXsetbv()
{
    
    QWORD rip;
    QWORD instructionLength;
    __vmx_vmread(VMX_EXIT_INSTRUCTION_LENGTH, &instructionLength);
    __vmx_vmread(VMX_GUEST_RIP, &rip);
    rip += instructionLength; 
    __vmx_vmwrite(VMX_GUEST_RIP, rip);
    DWORD procId = MhvGetProcessorId();
    LOG("[INFO] xsetbv received on VCPU %d", procId);
    DWORD xcr = gProcessors[procId].context._rcx & 0xFFFFFFFF;
    QWORD val = ((gProcessors[procId].context._rdx & 0xFFFFFFFF)<<32) | (gProcessors[procId].context._rax & 0xFFFFFFFF);
    if (xcr != 0)
        LOG("FAIL XSETBV");
    __xsetbv(xcr, val);
}

void MhvEndVmx()
{
    DWORD procId = MhvGetProcessorId();
    QWORD vmcsRegion = gProcessors[procId].vmcs;
    __vmx_vmclear(&vmcsRegion);
    __vmx_off();
    LOG("Exited VMX Operation");
    return;
}


void MhvHandleCpuid()
{

    QWORD mask = 0;
    QWORD rip;
    QWORD instructionLength;
    __vmx_vmread(VMX_EXIT_INSTRUCTION_LENGTH, &instructionLength);
    __vmx_vmread(VMX_GUEST_RIP, &rip);
    rip += instructionLength;
    __vmx_vmwrite(VMX_GUEST_RIP, rip);
    DWORD procId = MhvGetProcessorId();
    DWORD cpinfo[4];
    DWORD eax = (gProcessors[procId].context._rax & 0xFFFFFFFF);
    DWORD ecx = (gProcessors[procId].context._rcx & 0xFFFFFFFF);
    __cpuidex(cpinfo, eax, ecx);
    
    gProcessors[procId].context._rax = cpinfo[0];
    gProcessors[procId].context._rbx = cpinfo[1];
    gProcessors[procId].context._rcx = cpinfo[2];
    gProcessors[procId].context._rdx = cpinfo[3];
    if (eax == 1)
    {
        gProcessors[procId].context._rcx |= (1 << 27);
        mask = (1 << 31);
        mask = ~mask;
        gProcessors[procId].context._rcx &= mask;
    }

   
}

DWORD MhvGetProcessorId()
{

    DWORD info[4];
    DWORD function = 0x1;
    DWORD currentProcessorId, i;
    __cpuid(info, function);
    currentProcessorId = info[1] & 0xFF000000;
    currentProcessorId >>= 24;
    for (i = 0; i < gNumberOfProcessors; i++)
    {
        if (gProcessors[i].apic == currentProcessorId)
        {
            return i;
        }
    }
    return 0;
}

void getCurrentContext(DWORD id)
{
    PQWORD x = &(gProcessors[id]);
    SaveZone(&(gProcessors[id]));
}


/*
Vmx Start function for processors
*/
void MhvStartVmx()
{
    void* argv[3];
    
    DWORD procId = MhvGetProcessorId();
    QWORD actualcr4;
    QWORD actualcr0;
    QWORD vmxonRegion;
    DWORD msr_version;
    QWORD vmcsRegion;

    if (procId != 0)
    {
        __writecr3(globalPagingTable);
    }

    getCurrentContext(procId);
    SaveGeneralRegs();

    LOG("[INFO] Processor %d starting vmx", procId);

    Disablea20();
    
    LOG("[INFO] Writing bit 5 of CR0");
    actualcr0 = __readcr0();
    actualcr0 |= (1 << 5);
    __writecr0(actualcr0);
    LOG("[INFO] CR0 written: %d", actualcr0);
    
    actualcr4 = __readcr4();
    if (actualcr4 & (~(1 << 13)) == 0)
    {
        LOG("[CRITICAL] VMX Operation cannot be done");
        __halt();
    }

    actualcr4 |= (1 << 13);
    __writecr4(actualcr4);
    LOG("[INFO] CR4 written for supporting VMXE: %d", actualcr4);

    LOG("[INFO] Making vmxon region physical");
    vmxonRegion = GetPhysicalAddr(gProcessors[procId].vmxon); 
    gProcessors[procId].vmxon = vmxonRegion;
   
    LOG("[INFO] Writing version to VMXON region");
    msr_version = __readmsr(0x480);
    *((PDWORD)vmxonRegion) = msr_version;
    
    __vmx_on(&vmxonRegion);
    LOG("[INFO] Finally called VMXON on processor %d", procId);

    LOG("[INFO] Making VMCS region physical");
    vmcsRegion = GetPhysicalAddr(gProcessors[procId].vmcs);
    gProcessors[procId].vmcs = vmcsRegion;

    LOG("[INFO] Writing version to VMCS region");
    *((PDWORD)vmcsRegion) = msr_version;

    __vmx_vmclear(&vmcsRegion);
    LOG("[INFO] VMCLEAR was succesful!", vmcsRegion);

    __vmx_vmptrld(&vmcsRegion);
    LOG("[INFO] PTRLD was succesful!");

    // initialize vmcs
    LOG("[INFO] Starting initializing of VMCS for PCPU %d", procId);
    LOG("[INFO] Initializing controls on PCPU (%d)", procId);
    MhvInitControls();

    LOG("[INFO] Initializing host-state area on PCPU (%d)", procId);
    MhvInitHost(gProcessors[procId]);

    // guest initialization
    LOG("[INFO] Initializing guest-state area on PCPU (%d)", procId);
    MhvInitGuest(gProcessors[procId]);
    
    
    // Bsp is going to load the mbr
    if (procId == 0)
    {
        void(*return_f)() = doBsp;
        QWORD entry = return_f;
        LOG("[INFO] (BSP): Guest RIP (%x)", entry);
        __vmx_vmwrite(VMX_GUEST_RIP, entry);
        __vmx_vmwrite(VMX_GUEST_ACTIVITY_STATE, VMX_ACTIVITY_STATE_ACTIVE);
        printf("VMX KERNEL SUCCESFULY LOADED!\n");
        printf("Starting guest...");
    }
    else
    {
        //ap's will go in 16 bits then in halt state
        void(*return_f)() = doNothing;
        QWORD entry = return_f;
        LOG("[INFO] (AP %d): Guest RIP (%x)", procId, entry);
        __vmx_vmwrite(VMX_GUEST_RIP, entry);
        __vmx_vmwrite(VMX_GUEST_ACTIVITY_STATE, VMX_ACTIVITY_STATE_ACTIVE);
    }
    // ept making
    if (EptPointer == 0 && procId == 0)
    {
        LOG("[INFO] (BSP): Making EPT");
        EptPointer = (PQWORD)MhvMakeEpt();

        gProcessors[procId].EptPointer = (QWORD)EptPointer | EPT_4LEVELS_POINTER;

        PEPT_POINTER fullRights = MhvMakeEpt();
        LOG("[INFO] (BSP): Done making ept!");
        gProcessors[procId].FullRightsEptPointer = (QWORD)fullRights | EPT_4LEVELS_POINTER;

        __vmx_vmwrite(VMX_EPT_POINTER, gProcessors[procId].EptPointer);
        eptDone = 1;
    }
    else
    {
        LOG("[INFO] (AP %d): Waiting for BSP to finish EPT", procId);
        while (!eptDone);
        LOG("[INFO] (AP %d): Will now load the EPT!", procId);
        gProcessors[procId].EptPointer = gProcessors[0].EptPointer;
        gProcessors[procId].FullRightsEptPointer = gProcessors[0].FullRightsEptPointer;
        __vmx_vmwrite(VMX_EPT_POINTER, gProcessors[procId].EptPointer);
    }
   

    MemInitHeap();
    // init our internal guest state.
    if (procId == 0)
    {
        MhvInitGuestState();
    }

    LOG("[INFO] (%d) Will launch into guest!", procId);
    //launch 
    __vmx_vmlaunch();
    //failed vm launch
    QWORD vm_inst;
    __vmx_vmread(0x4400, &vm_inst);
    LOG("VM Launch Failed with Error Code: %d", vm_inst);
    dbgDumpVmcs();
}

void MhvInitControls()
{
    QWORD basic = __readmsr(VMX_IA32_BASIC_MSR);
    QWORD pinControls = 0;
    QWORD msrpin;
    QWORD procControls = 0;
    QWORD msrproc;
    DWORD msr_pin_low;
    QWORD mpl;
    DWORD msr_pin_high;
    QWORD mph;

    if ((basic & (1LL << VMX_BASIC_TRUE_SUPPORT)) != 0)
    {
        msrpin = __readmsr(VMX_IA32_PINBASED_TRUE_MSR);
    }
    else
    {
        msrpin = __readmsr(VMX_IA32_PINBASED_MSR);
    }
    //LOG("[INFO] MSR PIN TRUE: %x", msrpin);

    msr_pin_low = (msrpin & 0xFFFFFFFF);
    mpl = msr_pin_low;
    //LOG("[INFO] MSR PIN TRUE LOW: %x", mpl);

    msr_pin_high = ((msrpin & 0xFFFFFFFF00000000) >> 32);
    mph = msr_pin_high;
    //LOG("[INFO] MSR PIN TRUE HIGH: %x", mph);

    pinControls |= msr_pin_low;
    pinControls &= msr_pin_high;
    if (MhvGetProcessorId() == 0)
    {
        LOG("[INFO] Pin controls: %x", pinControls);
    }

    __vmx_vmwrite(VMX_PIN_CONTROLS_FIELD, pinControls);
    
    //Processor Based
    if ((basic & (1LL << VMX_BASIC_TRUE_SUPPORT)) != 0)
    {
        msrproc = __readmsr(VMX_IA32_PROCBASED_TRUE_MSR);
    }
    else
    {
        msrproc = __readmsr(VMX_IA32_PROCBASED_MSR);
    }
    
    DWORD msr_proc_low = (msrproc & 0xFFFFFFFF);
    mpl = msr_proc_low;
    
    DWORD msr_proc_high = ((msrproc & 0xFFFFFFFF00000000) >> 32);
    mph = msr_proc_high;


    //LOG("[INFO] (%d): Will activate by default SECONDARY and MSR BITMAPS", MhvGetProcessorId());
    procControls |= (1 << VMX_PROC_ACTIVATE_SECONDARY);
    procControls |= (1 << VMX_PROC_USE_MSR_BITMAPS);

    //procControls |= (1 << VMX_PROC_CR3_LOAD_EXITING);
    //procControls |= (1 << VMX_PROC_CR3_STORE_EXITING);
    procControls |= msr_proc_low;
    procControls &= msr_proc_high;
    if ((procControls & (1 << VMX_PROC_ACTIVATE_SECONDARY)) == 0)
    {
        printf("[CRITICAL] This computer does not support Activate Secondary Processor Based capability, hypervisor will exit");
        MhvEndVmx();
    }
    if ((procControls & (1 << VMX_PROC_USE_MSR_BITMAPS)) == 0)
    {
        printf("[CRITICAL] This computer does not support Use MSR Bitmaps Processor Based capability, hypervisor will exit");
        MhvEndVmx();
    }
    //check if controls are ok....
    if (MhvGetProcessorId() == 0)
    {
        LOG("[INFO] Primary processor controls: %x", procControls);
    }
    __vmx_vmwrite(VMX_PROC_CONTROLS_FIELD, procControls);

    //Secondary processor based
    QWORD secProc = 0;
    QWORD msrproc2 = __readmsr(VMX_IA32_PROCBASED2_MSR);

    DWORD msr_proc2_low = (msrproc2 & 0xFFFFFFFF);
    mpl = msr_proc2_low;

    DWORD msr_proc2_high = ((msrproc2 & 0xFFFFFFFF00000000) >> 32);
    mph = msr_proc2_high;

    secProc |= msr_proc2_low;
    secProc &= msr_proc2_high;

    secProc |= (1 << VMX_SECPROC_ENABLE_EPT);
    secProc |= (1 << VMX_SECPROC_ENABLE_RDTSCP);
    secProc |= (1 << VMX_SECPROC_UNRESTRICTED_GUEST);
    //secProc |= (1 << VMX_SECPROC_ENABLE_INVPCID);
    secProc |= msr_proc2_low;
    secProc &= msr_proc2_high;
    if ((secProc & (1 << VMX_SECPROC_ENABLE_EPT)) == 0)
    {
        printf("[CRITICAL] This computer does not support Enable EPT Secondary Processor Based capability, hypervisor will exit");
        MhvEndVmx();
    }
    if ((secProc & (1 << VMX_SECPROC_ENABLE_RDTSCP)) == 0)
    {
        printf("[CRITICAL] This computer does not support Enable RDTSCP Secondary Processor Based capability, hypervisor will exit");
        MhvEndVmx();
    }
    if ((secProc & (1 << VMX_SECPROC_UNRESTRICTED_GUEST)) == 0)
    {
        printf("[CRITICAL] This computer does not support Unrestricted Guest Secondary Processor Based capability, hypervisor will exit");
        MhvEndVmx();
    }
    //check if controls are ok...
    if (MhvGetProcessorId() == 0)
    {
        LOG("[INFO] Secondary processor controls: %x", secProc);
    }
    __vmx_vmwrite(VMX_PROC_SECONDARY_CONTROLS, secProc);
    //LOG("[INFO] (%d): Current secondary processor controls: %d\n", MhvGetProcessorId(), secProc);

    //VM Exit controls
    QWORD exitControls = 0;
    QWORD msrexit;
    if ((basic & (1LL << VMX_BASIC_TRUE_SUPPORT)) != 0) // check true support
    {
        msrexit = __readmsr(VMX_IA32_EXIT_TRUE_MSR);
    }
    else
    {
        msrexit = __readmsr(VMX_IA32_EXIT_MSR);
    }
    DWORD msr_exit_low = (msrexit & 0xFFFFFFFF);
    mpl = msr_exit_low;
    DWORD msr_exit_high = ((msrexit & 0xFFFFFFFF00000000) >> 32);
    mph = msr_exit_high;

    exitControls |= (1 << VMX_EXCTRL_INT_ON_EXIT);
    exitControls |= (1 << VMX_EXCTRL_HOST_ADDR_SPACESIZE);
    exitControls |= msr_exit_low;
    exitControls &= msr_exit_high;
    if ((exitControls & (1 << VMX_EXCTRL_HOST_ADDR_SPACESIZE)) == 0)
    {
        printf("[CRITICAL] This computer does not support Host Adress Space Size Exit capability, hypervisor will exit");
        MhvEndVmx();
    }
    // check if controls are ok
    if (MhvGetProcessorId() == 0)
    {
        LOG("[INFO] Exit controls: %x", exitControls);
    }
    __vmx_vmwrite(VMX_EXIT_CONTROLS, exitControls);

    //VM Entry Controls
    QWORD entryControls = 0;
    QWORD msrentry;
    if ((basic & (1LL << VMX_BASIC_TRUE_SUPPORT)) != 0) // check true support
        msrentry = __readmsr(VMX_IA32_ENTRY_TRUE_MSR);
    else
        msrentry = __readmsr(VMX_IA32_ENTRY_MSR);

    DWORD msr_entry_low = (msrentry & 0xFFFFFFFF);
    mpl = msr_entry_low;

    DWORD msr_entry_high = ((msrentry & 0xFFFFFFFF00000000) >> 32);
    mph = msr_entry_high;

    entryControls |= (1 << VMX_ENTRY_IA32e_MODE_GUEST);
    //entryControls |= (1 << VMX_ENTRY_LOAD_IA32_EFER);
    entryControls |= msr_entry_low;
    entryControls &= msr_entry_high;
    if ((entryControls & (1 << VMX_ENTRY_IA32e_MODE_GUEST)) == 0)
    {
        printf("[CRITICAL] This computer does not support IA32e Mode Guest Entry capability, hypervisor will exit");
        MhvEndVmx();
    }
    // check if controls are ok ...
    if (MhvGetProcessorId() == 0)
    {
        LOG("[INFO] Entry controls: %x", entryControls);
    }
    __vmx_vmwrite(VMX_ENTRY_CONTROLS, entryControls);
    
    //Cr0, cr4 guesthost masks and read shadows
    __vmx_vmwrite(VMX_CR0_GUESTHOST_MASK, 0);
    __vmx_vmwrite(VMX_CR0_READ_SHADOW, 0);
    __vmx_vmwrite(VMX_CR4_GUESTHOST_MASK, 0);
    __vmx_vmwrite(VMX_CR4_READ_SHADOW, 0);
    
    // make defines
    __vmx_vmwrite(VMX_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMX_EXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMX_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMX_ENTRY_INTERRUPTION_INFO, 0);
    __vmx_vmwrite(VMX_ENTRY_EXCEPTION_ERROR, 0);
    __vmx_vmwrite(VMX_ENTRY_INSTRUCTION_LENGTH, 0);
    __vmx_vmwrite(VMX_PAGE_FAULT_ERROR_MASK, 0);
    __vmx_vmwrite(VMX_PAGE_FAULT_ERROR_MATCH, 0xFFFFFFFF);
    __vmx_vmwrite(VMX_EXCEPTION_BITMAP, (1<<VMX_ENABLE_PAGE_FAULT)); // enable page fault exit, it will be handled by the os because of the page fault bitmaps


    DWORD currentProcessor = MhvGetProcessorId();
    //gProcessors[currentProcessor].msr_area = msr;
    
    PBYTE msr = GetPhysicalAddr(gProcessors[currentProcessor].msr_area);

    for (DWORD i = 0; i < 0x1000; i++)
    {
        msr[i] = 0;
    }
    LOG("[INFO] (VCPU %d) MSR Area pointer (%x)", currentProcessor, msr);
    __vmx_vmwrite(VMX_MSR_BITMAP, msr);
    // free address in the minihv kernel filled with 0
    //if (currentProcessor == 0) {
        // do proper hook please
        *(((PBYTE)msr) + 3072 + 0x80 / 0x8) = 0x04;
    //}
    __vmx_vmwrite(VMX_CR3_TARGET_COUNT, 0);


}

void MhvInitHost(PROCESSOR CurrentProc)
{
    __vmx_vmwrite(VMX_HOST_ES_SEL, 0x10);
    
    __vmx_vmwrite(VMX_HOST_SS_SEL, 0x10);
    __vmx_vmwrite(VMX_HOST_DS_SEL, 0x10);
    __vmx_vmwrite(VMX_HOST_FS_SEL, 0x10);
    __vmx_vmwrite(VMX_HOST_GS_SEL, 0x10);
    __vmx_vmwrite(VMX_HOST_TR_SEL, 0x10);
    QWORD hostCr0 = __readcr0();
    __vmx_vmwrite(VMX_HOST_CR0, hostCr0);
    QWORD hostCr3 = __readcr3();
    __vmx_vmwrite(VMX_HOST_CR3, hostCr3);
    QWORD hostCr4 = __readcr4();
    __vmx_vmwrite(VMX_HOST_CR4, hostCr4);
    
    __vmx_vmwrite(VMX_HOST_GDTR, GDT_TABLE_ADDRESS);
    __vmx_vmwrite(VMX_HOST_IDTR, IDT_TABLE_ADDRESS + 0x100);
    __vmx_vmwrite(VMX_HOST_SYSENTER_ESP, 0);
    __vmx_vmwrite(VMX_HOST_SYSENTER_EIP, 0);
    QWORD x = getFs();
    __vmx_vmwrite(VMX_HOST_FS_BASE, x);
    __vmx_vmwrite(VMX_HOST_GS_BASE, 0);
    __vmx_vmwrite(VMX_HOST_TR_BASE, 0);
    __vmx_vmwrite(VMX_HOST_RSP, 0xC000000);
    __vmx_vmwrite(VMX_HOST_CS_SEL, 0x8);
    void(*return_f)() = MhvGeneralHandler;
    QWORD entry = return_f;

    
    __vmx_vmwrite(VMX_HOST_RIP, entry);



}

void 
MhvMakeMtrr()
{

    QWORD msr1;
    QWORD msr2;
    msr1 = __readmsr(0x250);
    QWORD address;
    address = 0;
    QWORD mask = 0xFF;
    for (QWORD i = 1; i <= 8; i++)
    {
        gMtrrs[gNrMtrrs].MtrType = 0;
        gMtrrs[gNrMtrrs].PhysBase = address;
        gMtrrs[gNrMtrrs].Range = address + 0xFFFF;
        gMtrrs[gNrMtrrs].MemoryType = (msr1 & mask) >> ((i - 1) * 8);
        mask <<= 8;
        address += 0x10000;
        gNrMtrrs++;
    }

    for (QWORD i = 0; i < 2; i++)
    {
        mask = 0xFF;
        msr1 = __readmsr(0x258 + i);
        for (QWORD j = 1; j <= 8; j++)
        {
            gMtrrs[gNrMtrrs].MtrType = 0;
            gMtrrs[gNrMtrrs].PhysBase = address;
            gMtrrs[gNrMtrrs].Range = address + 0x3FFF;
            gMtrrs[gNrMtrrs].MemoryType = (msr1 & mask) >> ((j - 1) * 8);
            mask <<= 8;
            address += 0x4000;
            gNrMtrrs++;
        }
    }
    for (QWORD i = 0; i < 8; i++)
    {
        mask = 0xFF;
        msr1 = __readmsr(0x268 + i);
        for (QWORD j = 1; j <= 8; j++)
        {
            gMtrrs[gNrMtrrs].MtrType = 0;
            gMtrrs[gNrMtrrs].PhysBase = address;
            gMtrrs[gNrMtrrs].Range = address + 0xFFF;
            gMtrrs[gNrMtrrs].MemoryType = (msr1 & mask) >> ((j-1)*8);
            mask <<= 8;
            address += 0x1000;
            gNrMtrrs++;
        }
    }
    for (QWORD i = 0; i <= 7; i++)
    {
        
        msr1 = __readmsr(2*i+0x200);
        msr2 = __readmsr(2*i+0x201);
        if (((msr2 & 0xFFF) & 0x800) == 0)
            continue;
        gMtrrs[gNrMtrrs].MemoryType = msr1 & 0xFF;
        gMtrrs[gNrMtrrs].PhysBase = (msr1 & 0x000000FFFFFFF000);
        gMtrrs[gNrMtrrs].PhysMask = (msr2 & 0x000000FFFFFFF000);
        gMtrrs[gNrMtrrs].MtrType = 1;
        gNrMtrrs++;
    }
    
   
}



void MhvMakeEptOLD()
{
    PQWORD eptPointer = AcpiOsAllocate(4096);
    QWORD eptPageCap = 0;
    MhvMakeMtrr();
    for (DWORD i = 0; i < gNrMtrrs; i++)
    {
        LOG("[MTRR-DUMP] MSR: %x, Type: %x, Base: %x, Range: %x, Mask: %x, Memory: %x", i, gMtrrs[i].MtrType, gMtrrs[i].PhysBase, gMtrrs[i].Range, gMtrrs[i].PhysMask, gMtrrs[i].MemoryType);
    }
    eptPointer = GetPhysicalAddr(eptPointer);
    
    (QWORD)eptPointer += 0x18;
    EptPointer = eptPointer;
    __vmx_vmwrite(VMX_EPT_POINTER, ((QWORD)eptPointer));
    
    PQWORD pml4 = AcpiOsAllocate(4096);
    pml4 = GetPhysicalAddr(pml4);
    (QWORD)pml4 += 7;
    (QWORD)eptPointer -= 0x18;
    eptPageCap = gE820Map[gE820Entries - 1]->_start + gE820Map[gE820Entries - 1]->_length;
    *eptPointer = pml4;
    PQWORD ptp = eptPointer;
    ptp++;
    for (DWORD i = 1; i < 512; i++)
    {
        *ptp = 0x0;
        ptp++;
    }
    (QWORD)pml4 -= 7;
    PQWORD currentPML;// = 0x07;
    QWORD currentAddr = 0x0;
    DWORD pm = 0;
    for (DWORD i = 1; currentAddr < eptPageCap; i++)
    {
        currentPML = AcpiOsAllocate(4096);
        currentPML = GetPhysicalAddr(currentPML);
        *pml4 = ((QWORD)currentPML | 0x7);
        PQWORD currentPDPTE;
        for (DWORD j = 1; j <= 512 && currentAddr < eptPageCap; j++)
        {
            currentPDPTE = AcpiOsAllocate(4096);
            currentPDPTE = GetPhysicalAddr(currentPDPTE);
            *currentPML = ((QWORD)currentPDPTE | 0x7);

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
                                *currentPDPTE = ((currentAddr | 0x7) | (gMtrrs[pm].MemoryType << 3));
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
                                    if ((((*currentPDPTE) & 0x38) >> 3) > gMtrrs[pm].MemoryType)
                                    {
                                        *currentPDPTE = ((currentAddr | 0x7) | (gMtrrs[pm].MemoryType << 3));
                                        continue;
                                    }
                                }
                                *currentPDPTE = ((currentAddr | 0x7) | (gMtrrs[pm].MemoryType << 3));
                                found = 1;
                            }
                        }
                    }
                }
                if (!found)
                {
                    *currentPDPTE = ((currentAddr | 0x7)); // uncachable
                }
                currentAddr += 0x1000;
                currentPDPTE++;
            }
            currentPML++;
        }
        pml4++;
    }
    for (DWORD i = 10; i <= 512; i++)
    {
        *pml4 = 0x0;
        pml4++;
    }
    eptDone = 1;
}

void MhvInitGuest(PROCESSOR CurrentProc)
{
    QWORD currentEfer;
    
    currentEfer = __readmsr(VMX_IA32_EFER);
    currentEfer |= (1 << 10);
    __writemsr(VMX_IA32_EFER, currentEfer);
    __vmx_vmwrite(VMX_GUEST_ES_SEL, 0x10);
    __vmx_vmwrite(VMX_GUEST_SS_SEL, 0x10);
    __vmx_vmwrite(VMX_GUEST_DS_SEL, 0x10);
    __vmx_vmwrite(VMX_GUEST_FS_SEL, 0x10);
    __vmx_vmwrite(VMX_GUEST_GS_SEL, 0x10);
    __vmx_vmwrite(VMX_GUEST_TR_SEL, 0x10);
    QWORD currentCr3 = __readcr3();
    __vmx_vmwrite(VMX_GUEST_CR3, currentCr3);
    QWORD currentCr0 = __readcr0();
    __vmx_vmwrite(VMX_GUEST_CR0, currentCr0);
    QWORD currentCr4 = __readcr4();
    currentCr4 |= (1 << 13);
    currentCr4 |= (1 << 18);
    __vmx_vmwrite(VMX_GUEST_CR4, currentCr4);

    __vmx_vmwrite(VMX_GUEST_TR_ATTR, 0x8B);
    __vmx_vmwrite(VMX_GUEST_TR_LIMIT, 0xff);
    __vmx_vmwrite(VMX_GUEST_LDTR_ATTR, 0x10000);

    __vmx_vmwrite(VMX_GUEST_SS_ATTR, 0xA093);
    __vmx_vmwrite(VMX_GUEST_DS_ATTR, 0xA093);
    __vmx_vmwrite(VMX_GUEST_ES_ATTR, 0xA093);
    __vmx_vmwrite(VMX_GUEST_FS_ATTR, 0xA093);
    __vmx_vmwrite(VMX_GUEST_GS_ATTR, 0xA093);


    __vmx_vmwrite(VMX_GUEST_SS_LIMIT, -1);
    __vmx_vmwrite(VMX_GUEST_ES_LIMIT, -1);
    __vmx_vmwrite(VMX_GUEST_DS_LIMIT, -1);
    __vmx_vmwrite(VMX_GUEST_FS_LIMIT, -1);
    __vmx_vmwrite(VMX_GUEST_GS_LIMIT, -1);
    __vmx_vmwrite(VMX_GUEST_GDTR_LIMIT, 0x30);
    __vmx_vmwrite(VMX_GUEST_IDTR_LIMIT, 0x3FF); // idtr limit

    __vmx_vmwrite(VMX_GUEST_SYSENTER_ESP, KERNEL_BASE + 0xA000);
    __vmx_vmwrite(VMX_GUEST_SYSENTER_EIP, KERNEL_BASE + 0xC000);

    __vmx_vmwrite(VMX_GUEST_DR7, 0x400);
    __vmx_vmwrite(VMX_GUEST_GDTR, GDT_TABLE_ADDRESS);
    __vmx_vmwrite(VMX_GUEST_CS_LIMIT, -1);
    __vmx_vmwrite(VMX_GUEST_CS_ATTR, 0xA09B);
    __vmx_vmwrite(VMX_GUEST_CS_SEL, 0x8);
    __vmx_vmwrite(VMX_GUEST_RSP, 0x8000);
    __vmx_vmwrite(VMX_GUEST_IDTR, KERNEL_BASE + 0xA400); // idtr


    __vmx_vmwrite(VMX_GUEST_RFLAGS, 2);

    __vmx_vmwrite(VMX_GUEST_VMCS_LINKP, -1);
    __vmx_vmwrite(VMX_GUEST_VMCS_LINKP_HIGH, -1);
    __vmx_vmwrite(VMX_GUEST_INTERUPT_STATE, 0);
    __vmx_vmwrite(VMX_GUEST_PENDING_DEBUG, 0);

    __vmx_vmwrite(VMX_GUEST_ES_BASE, 0);
    __vmx_vmwrite(VMX_GUEST_SS_BASE, 0);
    __vmx_vmwrite(VMX_GUEST_CS_BASE, 0);
    __vmx_vmwrite(VMX_GUEST_DS_BASE, 0);
    __vmx_vmwrite(VMX_GUEST_FS_BASE, 0);
    __vmx_vmwrite(VMX_GUEST_GS_BASE, 0);
    __vmx_vmwrite(VMX_GUEST_TR_BASE, 0);

    QWORD MSR = __readmsr(VMX_IA32_DEBUGCTL);
    QWORD status = __vmx_vmwrite(VMX_GUEST_MSR_DEBUGCTL_FULL, MSR);

    MSR = __ull_rshift(MSR, 32);
    status = __vmx_vmwrite(VMX_GUEST_MSR_DEBUGCTL_HIGH, MSR);

    MSR = __readmsr(VMX_IA32_PERF_GLOBAL_CTRL);
    status = __vmx_vmwrite(VMX_GUEST_MSR_PERFGLOBAL_FULL, MSR);

    MSR = __ull_rshift(MSR, 32);
    status = __vmx_vmwrite(VMX_GUEST_MSR_PERFGLOBAL_HIGH, MSR);

    MSR = __readmsr(VMX_IA32_PAT);
    status = __vmx_vmwrite(VMX_GUEST_MSR_PAT_FULL, MSR);

    MSR = __ull_rshift(MSR, 32);
    status = __vmx_vmwrite(VMX_GUEST_MSR_PAT_HIGH, MSR);

    MSR = __readmsr(VMX_IA32_EFER);
    status = __vmx_vmwrite(VMX_GUEST_MSR_EFER_FULL, MSR);

    MSR = __ull_rshift(MSR, 32);
    status = __vmx_vmwrite(VMX_GUEST_MSR_EFER_HIGH, MSR);

}
void doNothing()
{
    __halt();
    JumpToMBR(1);
    
}

void doBsp()
{
    JumpToMBR(0);
    while (1);
}



PQWORD DbgDumpVirtualSpace(
    PQWORD Pml4
)
{
    DWORD i;
    for (i = 0; i < 0x1000; i++)
    {
        LOG("[VA DUMP] Index %d: %x", i, Pml4[i]);
    }
}

#define PML4_INDEX(Va) (((Va) & 0x0000ff8000000000) >> 39)
#define PDP_INDEX(Va) (((Va) & 0x0000007fc0000000) >> 30)
#define PD_INDEX(Va) (((Va) & 0x000000003fe00000) >> 21)
#define PT_INDEX(Va) (((Va) & 0x00000000001ff000) >> 12)
#define CLEAN_PHYS_ADDR(Addr) ((Addr) & 0x000FFFFFFFFFF000)

#define PAGE_BIT_P 1
#define PAGE_BIT_PS 0x80
#define PAGE_BIT_W (1<<11)

NTSTATUS
MhvMemRead(
    QWORD Address,
    QWORD Size,
    QWORD Cr3,
    PVOID Buffer
)
{
    PBYTE firstPage;
    PBYTE secondPage;
    BOOLEAN onePage = TRUE;
    PBYTE buff = Buffer;

    firstPage = MhvTranslateVa(Address & (~0xFFF), Cr3, NULL);

    if (firstPage == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if ((Address & (~0xFFF)) != ((Address + Size) & (~0xFFF)))
    {
        secondPage = MhvTranslateVa((Address + Size) & (~0xFFF), Cr3, NULL);
        if (secondPage == 0)
        {
            return STATUS_UNSUCCESSFUL;
        }
        onePage = FALSE;
    }

    DWORD cnt = 0;
    for (DWORD i = (Address & 0xFFF); cnt < Size && i < PAGE_SIZE; i++, cnt++)
    {
        buff[cnt] = firstPage[i];
    }

    for (DWORD i = 0; cnt < Size; i++, cnt++)
    {
        buff[cnt] = secondPage[i];
    }

    return STATUS_SUCCESS;
}

PQWORD
MhvTranslateVa(
    QWORD Rip,
    QWORD Cr3,
    BOOLEAN *Writable
)
{
    QWORD currentAddr = 0;
    PQWORD pPml4 = CLEAN_PHYS_ADDR(Cr3);
    DWORD iPml4 = PML4_INDEX(Rip);
    PQWORD pPdp;
    DWORD iPdp = PDP_INDEX(Rip);
    PQWORD pPd;
    DWORD iPd = PD_INDEX(Rip);
    PQWORD pPt;
    DWORD iPt = PT_INDEX(Rip);
    
    pPdp = CLEAN_PHYS_ADDR(pPml4[iPml4]);

    if (((QWORD)pPml4[iPml4] & PAGE_BIT_P) == 0)
    {
        return 0;
    }

    pPd = CLEAN_PHYS_ADDR(pPdp[iPdp]);


    if (((QWORD)pPdp[iPdp] & PAGE_BIT_P) == 0)
    {
        return 0;
    }

    if (Writable != NULL && !(*Writable))
    {
        *Writable = ((pPdp[iPdp] & PAGE_BIT_W) >> 11);
    }

    if ((pPdp[iPdp] & PAGE_BIT_PS) != 0)
    {
        return ((QWORD)pPd & (~0x3FFFFFFF)) + (Rip & 0x3FFFFFFF);
    }

    pPt = CLEAN_PHYS_ADDR(pPd[iPd]);
    if (((QWORD)pPd[iPd] & PAGE_BIT_P) == 0)
    {
        return 0;
    }

    if (Writable != NULL && !(*Writable))
    {
        *Writable = ((pPd[iPd] & PAGE_BIT_W) >> 11);
    }

    if ((pPd[iPd] & PAGE_BIT_PS) != 0)
    {
        return ((QWORD)pPt & (~0x1FFFFF)) + (Rip & 0x1FFFFF);
    }

    if (((QWORD)pPt[iPt] & PAGE_BIT_P) == 0)
    {
        return 0;
    }
    if (Writable != NULL && !(*Writable))
    {
        *Writable = ((pPt[iPt] & PAGE_BIT_W) >> 11);
    }
    return CLEAN_PHYS_ADDR(pPt[iPt]) | (Rip & 0xFFF);
    


}

DWORD index = 0;

#define IS_KERNEL_ADDR(x) (((x) & 0xFFFFF00000000000) != 0)




void MhvHandleInterrupt() {

    DWORD procId = MhvGetProcessorId();

    QWORD interrupt;

    __vmx_vmread(VMX_INTERRUPT_INFORMATION, &interrupt);
    BYTE vector = interrupt & 0xFF;
    QWORD reason = 0, qualif = 0, errcode = 0;
    if (vector == 14)
    {

        QWORD rip = 0, cr3 = 0, cr2 = 0;

        __vmx_vmread(VMX_GUEST_RIP, &rip);
        __vmx_vmread(VMX_GUEST_CR3, &cr3);
        __vmx_vmread(VMX_EXIT_QUALIFICATION, &cr2);

        gProcessors[procId].context._cr2 = cr2;
        __vmx_vmread(0x4406, &errcode);

        BOOLEAN isWrite = 0;
        QWORD addr = MhvTranslateVa(cr2, cr3, &isWrite);
        if (addr == 0)
        {
            goto except;
        }
        if (IS_KERNEL_ADDR(rip) && IS_KERNEL_ADDR(cr2))
        {
            goto except;
        }
        if (isWrite && !IS_KERNEL_ADDR(rip))
        {
            //LOG("[INFO] Something sneaky is happening :P");
            //LOG("[INFO] (VCPU %d) A page fault has been issued from RIP (%x) CR3 (%x) for page (%x), error code: (%x)", procId, rip, cr3, cr2, errcode);
            
            goto block;
        }
        else
        {
            goto except;
        }
    block:

        {
            /*LOG("[HERE] We are here!");
            MemDumpAllocStats();
            PMHVPROCESS pProc = MhvFindProcessByCr3(cr3);
            if (pProc == NULL)
            {
                LOG("[HERE] Proc not found");
                goto except;
            }
            
            PMHVMODULE pModOriginator = MhvGetModuleByAddress(pProc, rip);
            PMHVMODULE pModVictim = MhvGetModuleByAddress(pProc, cr2);

            if (pModOriginator == NULL || pModVictim == NULL)
            {
                LOG("[INFO] Reiterating...");
                MhvReiterateProcessModules();
                LOG("[INFO] Reiterated!");
                pModOriginator = MhvGetModuleByAddress(pProc, rip);
                pModVictim = MhvGetModuleByAddress(pProc, cr2);
            }

            // we are not interested in WP pages which are not part of modules.
            if (pModVictim == NULL)
            {
                LOG("[HERE] PMod not found");
                goto except;
            }

            if (pProc->Protected == FALSE)
            {
                goto except;
            }

            BOOLEAN isExcepted = MhvExcept(pProc, pModOriginator, pModVictim);

            if (isExcepted)
            {
                goto except;
            }

            LOG("--------------------------------------------ALERT--------------------------------------------");
            LOG("[ALERT] Rip: <%x>, CR3: <%x>, CR2: <%x>", rip, cr3, cr2);

            LOG("[ALERT] Process: %s has been the subject of an illegal operation", pProc != NULL ? pProc->Name : "<not found>");

            LOG("[ALERT] Module: %s has tried to make an illegal operation", pModOriginator != NULL ? pModOriginator->Name : "<not found>");
            LOG("[ALERT] Module: %s has been the victim of an illegal operation", pModVictim != NULL ? pModVictim->Name : "<not found>");

            // except everything for now;
        

            __vmx_vmwrite(VMX_ENTRY_INTERRUPTION_INFO, (14) | (3 << 8) | (1 << 11) | (1 << 31));
            __vmx_vmwrite(VMX_ENTRY_EXCEPTION_ERROR, errcode);
            goto exit;
            */
        except:;
        }

        /*
        QWORD instructionLength = 0;
        __vmx_vmread(VMX_EXIT_INSTRUCTION_LENGTH, &instructionLength);
        __vmx_vmwrite(VMX_GUEST_RIP, rip + instructionLength);
        PBYTE adresa = MhvTranslateVa(rip + instructionLength, cr3, NULL);
        adresa[0] = 0x0f;
        adresa[1] = 0x0b;
        */
    }
    else
    {
        LOG("[INFO] (VCPU %d) Interrupt %d received, will re-inject", procId, vector);
        if (vector == 3)
        {
            __vmx_vmwrite(VMX_ENTRY_INTERRUPTION_INFO, 3 | (6 << 8) | (1 << 31));
            __vmx_vmwrite(VMX_ENTRY_INSTRUCTION_LENGTH, 1);
        }
        else if (vector == 2)
        {
            __vmx_vmwrite(VMX_ENTRY_INTERRUPTION_INFO, 2 | (2 << 8) | (1 << 31));
        }
        else
        {
            __vmx_vmwrite(VMX_ENTRY_INTERRUPTION_INFO, vector | (3 << 8) | (1 << 11) | (1 << 31));
        }

    }
    exit:
    return;

}


NTSTATUS
MhvHandleKernWrite(
    PVOID Procesor,
    PVOID Hook,
    QWORD Rip,
    QWORD Cr3,
    PVOID Context
)
{
    LOG("[INFO] someone writing on the kernel...");
    return STATUS_UNSUCCESSFUL;
}


void MhvInitHook() {

    __vmx_vmwrite(VMX_PAGE_FAULT_ERROR_MASK, 0x0);
    __vmx_vmwrite(VMX_PAGE_FAULT_ERROR_MATCH, 0x0);
    //__vmx_vmwrite(VMX_EXCEPTION_BITMAP, (1 << VMX_ENABLE_PAGE_FAULT) | (1<<3));
    __vmx_vmwrite(VMX_EXCEPTION_BITMAP, (1<<3));
    QWORD idtr = 0;
    __vmx_vmread(VMX_GUEST_IDTR, &idtr);
   
    DWORD procId = MhvGetProcessorId();
    LOG("[INFO] (VCPU %d) IDTR %x", procId, idtr);
    
    QWORD cr3 = 0;
    __vmx_vmread(VMX_GUEST_CR3, &cr3);
    LOG("[INFO] (VCPU %d) Current cr3: %x", procId, cr3);

    
    if (idtr == 0)
    {
        LOG("[INFO] IDT not yet written on (VCPU %d)", procId);
        return;
    }
    PIDTR idtr2 = idtr;
    gProcessors[procId].idt = MhvTranslateVa(idtr, cr3, NULL);

    LOG("[INFO] (procId: %d) IDT Found at (%x)", procId, idtr);
    if (procId == 0)
    {
        DWORD i;
        for (i = 0; i < 20; i++)
        {
            ISR hpa = gProcessors[procId].idt[i];

            QWORD address1 = hpa.bits32_63;
            address1 <<= 32;
            QWORD address2 = hpa.bits16_31;
            address2 <<= 16;
            QWORD address = address1 + address2 + hpa.bits0_15;

            LOG("[INFO] (procId: %d) IDT entry %d points to (%x)", procId, i, address);
        }
    }
    if (procId == 0)
    {

        gProcessors[0].KernelBase = MhvFindKernelBase(gProcessors[procId].syscall);
        DWORD i;
        for (i = 1; i < gNumberOfProcessors; i++)
        {
            gProcessors[i].KernelBase = gProcessors[0].KernelBase;
        }

        /*
        MhvCreateEptHook(&gProcessors[0],
            MhvTranslateVa(gProcessors[procId].KernelBase, cr3, NULL),
            EPT_WRITE_RIGHT,
            cr3,
            gProcessors[procId].KernelBase,
            MhvHandleKernWrite,
            NULL,
            PAGE_SIZE,
            FALSE
        );
        
        MhvCreateEptHook(&gProcessors[0],
            MhvTranslateVa(gProcessors[procId].KernelBase + 0x1000, cr3, NULL),
            EPT_WRITE_RIGHT,
            cr3,
            gProcessors[procId].KernelBase + 0x1000,
            MhvHandleKernWrite,
            NULL,
            PAGE_SIZE,
            FALSE
        );
        */
        MhvHookFunctionsInMemory();
        ZydisStatus status;

        ZydisDecoder decoder;
        status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
        if (!ZYDIS_SUCCESS(status))
        {
            LOG("[INFO] Decoder failed to be inited!");
            goto exit;
        }
        ZydisDecodedInstruction instrux;

        LOG("[INFO] Decoder inited!");
        PQWORD x = MhvTranslateVa(gProcessors[procId].syscall, cr3, NULL);

        LOG("[INFO] Translation: %x -> %x", gProcessors[procId], x);

        status = ZydisDecoderDecodeBuffer(&decoder, x, 16, gProcessors[procId].syscall, &instrux);
        
        if (!ZYDIS_SUCCESS(status))
        {
            LOG("[INFO] Error decode buffer");
            goto exit;
        }

        LOG("[INFO] Decoded buffer! instrux length: %d", instrux.length);

        ZydisFormatter formatter;

        if (!ZYDIS_SUCCESS((status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) ||

            !ZYDIS_SUCCESS((status = ZydisFormatterSetProperty(&formatter,

                ZYDIS_FORMATTER_PROP_FORCE_MEMSEG, ZYDIS_TRUE))) ||

            !ZYDIS_SUCCESS((status = ZydisFormatterSetProperty(&formatter,

                ZYDIS_FORMATTER_PROP_FORCE_MEMSIZE, ZYDIS_TRUE))))

        {

            LOG("[ERROR] ZyDis formatter error");
            goto exit;
        }

        char buffer[256];

        LOG("[INFO] About to format instrux!");

        ZydisFormatterFormatInstruction(&formatter, &instrux, &buffer[0], sizeof(buffer));

        
        LOG("Syscall: %s", &buffer[0]);
    exit:;
        //AcpiOsCreateLock(&gEptLock);
    }
}


void MhvHandleVmCall(DWORD procId, QWORD rip)
{
    
    QWORD newrip = 0;
    NTSTATUS status;
    status = MhvVerifyIfHookAndNotify(rip);
    if (status == STATUS_SUCCESS)
    {
        goto cleanup_and_exit;
    }

    status = MhvHandleInterfaceComm(&gProcessors[procId]);
    if (status == STATUS_SUCCESS)
    {
        goto cleanup_and_exit;
    }

    LOG("[VMCALL] procId: %d, rip: %x", procId, rip);
    if ((gProcessors[procId].context._rcx & 0xFF) == 0xFE)
    {
        LOG("[VMCALL] We're in our vmcall");
        if (0 == procId)
        {
            __int64 entryControls, exitControls;
            __vmx_vmread(VMX_ENTRY_CONTROLS, &entryControls);
            entryControls |= (1 << VMX_ENTRY_LOAD_IA32_EFER);
            __vmx_vmwrite(VMX_ENTRY_CONTROLS, entryControls);

            __vmx_vmread(VMX_EXIT_CONTROLS, &exitControls);
            exitControls |= (1 << VMX_EXCTRL_SAVE_IA32_EFER);
            __vmx_vmwrite(VMX_EXIT_CONTROLS, exitControls);

            __vmx_vmwrite(VMX_GUEST_IA32_EFER_LOW, 0);

            goto cleanup_and_exit;
        }

        __int64 entryControls, exitControls;
        __vmx_vmread(VMX_ENTRY_CONTROLS, &entryControls);
        entryControls |= (1 << VMX_ENTRY_LOAD_IA32_EFER);
        __vmx_vmwrite(VMX_ENTRY_CONTROLS, entryControls);

        __vmx_vmread(VMX_EXIT_CONTROLS, &exitControls);
        exitControls |= (1 << VMX_EXCTRL_SAVE_IA32_EFER);
        __vmx_vmwrite(VMX_EXIT_CONTROLS, exitControls);

        __vmx_vmwrite(VMX_GUEST_IA32_EFER_LOW, 0);

        //processor is in 16 bits, now will be put on halt state
        __vmx_vmwrite(VMX_GUEST_ACTIVITY_STATE, VMX_ACTIVITY_STATE_HALT);
        goto cleanup_and_exit;

    }
    else if ((gProcessors[procId].context._rcx & 0xFF) == 0xFF)
    {
        if ((gProcessors[procId].context._rbx & 0xFFFFFFFF) == 0)
        {
            index = 0;
        }
        LOG("[INFO-E820] Called on VCPU (%d) current index (%d)", procId, index);

        QWORD es_base = 0;
        QWORD flags = 0;

        __vmx_vmread(VMX_GUEST_ES_SEL, &es_base);
        es_base <<= 4;
        *(PQWORD)(es_base + (gProcessors[procId].context._rdi & 0xffff)) = gE820Map[index]->_start;
        *(((PQWORD)(es_base + (gProcessors[procId].context._rdi & 0xffff))) + 1) = gE820Map[index]->_length;
        *(((PDWORD)(es_base + (gProcessors[procId].context._rdi & 0xffff))) + 4) = gE820Map[index]->type;
        *(((PDWORD)(es_base + (gProcessors[procId].context._rdi & 0xffff))) + 5) = 1;
        
        index++;
        
        gProcessors[procId].context._rcx = 24;
        gProcessors[procId].context._rax = 0x0534D4150;
        gProcessors[procId].context._rbx = 1;
        
        // carry flag OFF
        __vmx_vmread(VMX_GUEST_RFLAGS, &flags);
        flags &= (~1);
        __vmx_vmwrite(VMX_GUEST_RFLAGS, flags);

        if (index == gE820Entries)
        {
            gProcessors[procId].context._rbx = 0;
            // carry flag ON
            __vmx_vmread(VMX_GUEST_RFLAGS, &flags);
            flags |= 1;
            __vmx_vmwrite(VMX_GUEST_RFLAGS, flags);

            index = 0;
        }
        goto cleanup_and_exit;
       
    }
    LOG("[INFO] Delivering #UD for unwanted vmcall!");
    __vmx_vmwrite(VMX_ENTRY_INTERRUPTION_INFO, (6) | (3 << 8) | (1 << 11) | (1 << 31));
    __vmx_vmwrite(VMX_ENTRY_EXCEPTION_ERROR, 0);
    return;
cleanup_and_exit:
    // rip could have been changed in callbacks, so get the new rip
    __vmx_vmread(VMX_GUEST_RIP, &newrip);
    __vmx_vmwrite(VMX_GUEST_RIP, newrip + 3);
    return;
}

void MhvGeneralHandler()
{
    SaveGeneralRegs();
    QWORD exitReason;
   
    __vmx_vmread(VMX_EXIT_REASON, &exitReason);
    
    if (VMX_EXIT_INIT == exitReason)
    {
        // sets the processor on "wait for sipi state"
        //__vmx_vmwrite(VMX_GUEST_ACTIVITY_STATE, VMX_ACTIVITY_STATE_WAIT_FOR_SIPI);
        //__vmx_vmresume();
        __halt();
    }

    else if (VMX_EXIT_SIPI == exitReason)
    {
        QWORD exqual;
        __vmx_vmread(VMX_EXIT_QUALIFICATION, &exqual);
        
        //for VMWare (exit qualification is 0 on vmware)
        if (exqual != 0)
        {
            // set the current rip, cs base and sel to the sipi vector value
            exqual = (exqual << 8);
            __vmx_vmwrite(VMX_GUEST_ACTIVITY_STATE, VMX_ACTIVITY_STATE_ACTIVE);
            __vmx_vmwrite(VMX_GUEST_RIP, 0);
            __vmx_vmwrite(VMX_GUEST_CS_BASE, exqual<<4);
            __vmx_vmwrite(VMX_GUEST_CS_SEL, exqual);
            __vmx_vmresume();
            
        }
        else
        {
            // processor is on halt state if vmware
            __vmx_vmwrite(VMX_GUEST_ACTIVITY_STATE, VMX_ACTIVITY_STATE_HALT);
            __vmx_vmresume();
        }

    }
    // get processor id
    DWORD procId = MhvGetProcessorId();
#if !defined(WINDBG)
    LOG("Exit reason: %d, CPU Id: %d", exitReason, procId);
#endif

    //AcpiOsAcquireLock(pGuest.GlobalLock);
    //LOG("[INFO] (VCPU %d) vm exit reason: %d", procId, exitReason);

    pGuest.NrToDelete = 0;

    if (VMX_EXIT_VMCALL == exitReason)
    {

        QWORD rip;
        __vmx_vmread(VMX_GUEST_RIP, &rip);
        DWORD procId = MhvGetProcessorId();
        MhvHandleVmCall(procId, rip);

    }
    else if (VMX_EXIT_TRIPLE_FAULT == exitReason)
    {
        // triple fault = unrecoverable => vmcs is dumped
        QWORD rip, cls, cr3;
        __vmx_vmread(VMX_GUEST_RIP, &rip);
        __vmx_vmread(VMX_GUEST_CS_SEL, &cls);
        __vmx_vmread(VMX_GUEST_CR3, &cr3);
        LOG("INSTRUCTION: %x %x", *(__int64*)rip, *(__int64*)(rip+8));
        LOG("RAX: %x", gProcessors[procId].context._rax);
        LOG("RBX: %x", gProcessors[procId].context._rbx);
        LOG("RCX: %x %x", gProcessors[procId].context._rcx, MhvTranslateVa(gProcessors[procId].context._rcx, cr3, NULL));
        LOG("RDX: %x", gProcessors[procId].context._rdx);
        __int64 efer;
        efer = __readmsr(VMX_IA32_EFER);
        LOG("IA32_EFER: %x", efer);
        dbgDumpVmcs();
        __halt();
    }
    else if (VMX_EXIT_CR_ACCESS == exitReason)
    {
        //MhvHandleCr3Exit(&gProcessors[procId]);
        __halt();
    }
    else if (VMX_EXIT_CPUID == exitReason)
    {
        MhvHandleCpuid();
    }
    else if (VMX_EXIT_XSETBV == exitReason)
    {
        gProcessors[procId].xsetbvCount++;
        MhvHandleXsetbv();
    }
    else if (VMX_EXIT_RDMSR == exitReason)
    {
        // Read msr handler (assembly) - not used anymore
        HandleMSR(gProcessors[procId].msr_area);
    }
    else if (VMX_EXIT_WRMSR == exitReason)
    {
        
        PBYTE msr = GetPhysicalAddr(gProcessors[MhvGetProcessorId()].msr_area);
        *(((PBYTE)msr) + 3072 + 0x80 / 0x8) = 0x0;
        
        QWORD syscall = ((gProcessors[MhvGetProcessorId()].context._rdx & 0xffffffff) << 32) | (gProcessors[MhvGetProcessorId()].context._rax & 0xffffffff);
        
        LOG("[INFO] (VCPU %d) SYSCALL written: %x", procId, syscall);
        gProcessors[MhvGetProcessorId()].syscall = syscall;
        int cnt = 0;
        for (int i = 0; i < gNumberOfProcessors; i++)
        {
            if (gProcessors[i].syscall != 0)
            {
                cnt++;
            }
        }
        if (cnt == gNumberOfProcessors)
        {
            LOG("[INFO] SYSCALL written on all CPUS(%d/%d)", cnt, gNumberOfProcessors);
        }
        
        LOG("[INFO] (VCPU %d) Will begin hooking", procId);
        MhvInitHook();
       
    }
    else if (VMX_EXIT_NMI == exitReason)
    {
        MhvHandleInterrupt();
    }
    else if (VMX_EXIT_EPT_VIOLATION == exitReason)
    {
        MhvHandleEptViolation(&gProcessors[MhvGetProcessorId()]);
    }
    else if (VMX_EXIT_MONITOR_TF == exitReason)
    {
        MhvHandleMTF(&gProcessors[MhvGetProcessorId()]);
    }
    else if (exitReason <= 64)
    {
        LOG("[CRITICAL] (VCPU %d) EXIT REASON: %d", procId, exitReason);
        dbgDumpVmcs();
        __halt();
    }

    // commit the deleted hooks
    LIST_ENTRY* list;
    

    list = pGuest.ToAppendHooks.Flink;

    while (list != &pGuest.ToAppendHooks)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        RemoveEntryList(&pHook->Link);
        InsertTailList(&pGuest.EptHooksList, &pHook->Link);
    }

    list = pGuest.EptHooksList.Flink;

    while (list != &pGuest.EptHooksList)
    {
        PEPT_HOOK pHook = CONTAINING_RECORD(list, EPT_HOOK, Link);

        list = list->Flink;

        if ((pHook->Flags & 0x40) != 0)
        {
            //LOG("[INFO] Deleting hook @ x on physical page %x, offset %x", pHook, pHook->GuestPhysicalAddress, pHook->Offset);
            MhvEptPurgeHookFromEpt(pHook, pGuest.Vcpu);
            RemoveEntryList(&pHook->Link);
            MemFreeContiguosMemory(pHook);
        }
    }


    //AcpiOsReleaseLock(pGuest.GlobalLock, 0);
    //LOG("[INFO] (VCPU %d) vm entry again", procId);
    GetGeneralRegs();
    __vmx_vmresume();
    LOG("[CRITICAL] Failed to resume after VMCALL on memory map");
    dbgDumpVmcs();
    __halt();
}

#define dbgDumpVmcsField(x) \
{ \
    QWORD y; \
    if(0 == __vmx_vmread((x), &y)) \
    { \
    LOG("%s: %x", #x, y); \
    } \
}



void dbgDumpVmcs()
{
    dbgDumpVmcsField(VMX_PIN_CONTROLS_FIELD);
    dbgDumpVmcsField(VMX_PROC_CONTROLS_FIELD);
    dbgDumpVmcsField(VMX_PROC_SECONDARY_CONTROLS);
    dbgDumpVmcsField(VMX_EXIT_CONTROLS);
    dbgDumpVmcsField(VMX_ENTRY_CONTROLS);
    dbgDumpVmcsField(VMX_CR0_GUESTHOST_MASK);
    dbgDumpVmcsField(VMX_CR0_READ_SHADOW);
    dbgDumpVmcsField(VMX_CR4_GUESTHOST_MASK);
    dbgDumpVmcsField(VMX_CR4_READ_SHADOW);
    dbgDumpVmcsField(VMX_EXCEPTION_BITMAP);
    dbgDumpVmcsField(VMX_MSR_BITMAP);
    dbgDumpVmcsField(VMX_CR3_TARGET_COUNT);
    dbgDumpVmcsField(VMX_CR3_TARGET_0);
    dbgDumpVmcsField(VMX_CR3_TARGET_1);
    dbgDumpVmcsField(VMX_CR3_TARGET_2);
    dbgDumpVmcsField(VMX_CR3_TARGET_3);
    dbgDumpVmcsField(VMX_HOST_ES_SEL);
    dbgDumpVmcsField(VMX_HOST_SS_SEL);
    dbgDumpVmcsField(VMX_HOST_DS_SEL);
    dbgDumpVmcsField(VMX_HOST_FS_SEL);
    dbgDumpVmcsField(VMX_HOST_GS_SEL);
    dbgDumpVmcsField(VMX_HOST_TR_SEL);
    dbgDumpVmcsField(VMX_HOST_CR0);
    dbgDumpVmcsField(VMX_HOST_CR3);
    dbgDumpVmcsField(VMX_HOST_CR4);
    dbgDumpVmcsField(VMX_HOST_GDTR);
    dbgDumpVmcsField(VMX_HOST_IDTR);
    dbgDumpVmcsField(VMX_HOST_SYSENTER_ESP);
    dbgDumpVmcsField(VMX_HOST_SYSENTER_EIP);
    dbgDumpVmcsField(VMX_HOST_FS_BASE);
    dbgDumpVmcsField(VMX_HOST_GS_BASE);
    dbgDumpVmcsField(VMX_HOST_TR_BASE);
    dbgDumpVmcsField(VMX_HOST_RSP);
    dbgDumpVmcsField(VMX_HOST_CS_SEL);
    dbgDumpVmcsField(VMX_HOST_RIP);
    dbgDumpVmcsField(VMX_IA32_EFER);
    dbgDumpVmcsField(VMX_GUEST_ES_SEL);
    dbgDumpVmcsField(VMX_GUEST_SS_SEL);
    dbgDumpVmcsField(VMX_GUEST_DS_SEL);
    dbgDumpVmcsField(VMX_GUEST_FS_SEL);
    dbgDumpVmcsField(VMX_GUEST_GS_SEL);
    dbgDumpVmcsField(VMX_GUEST_TR_SEL);
    dbgDumpVmcsField(VMX_GUEST_CR3);
    dbgDumpVmcsField(VMX_GUEST_CR0);
    dbgDumpVmcsField(VMX_GUEST_CR4);
    dbgDumpVmcsField(VMX_GUEST_TR_ATTR);
    dbgDumpVmcsField(VMX_GUEST_TR_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_LDTR_ATTR);
    dbgDumpVmcsField(VMX_GUEST_SS_ATTR);
    dbgDumpVmcsField(VMX_GUEST_DS_ATTR);
    dbgDumpVmcsField(VMX_GUEST_ES_ATTR);
    dbgDumpVmcsField(VMX_GUEST_FS_ATTR);
    dbgDumpVmcsField(VMX_GUEST_GS_ATTR);
    dbgDumpVmcsField(VMX_GUEST_SS_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_ES_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_DS_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_FS_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_GS_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_GDTR_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_SYSENTER_ESP);
    dbgDumpVmcsField(VMX_GUEST_SYSENTER_EIP);
    dbgDumpVmcsField(VMX_GUEST_DR7);
    dbgDumpVmcsField(VMX_GUEST_GDTR);
    dbgDumpVmcsField(VMX_GUEST_CS_LIMIT);
    dbgDumpVmcsField(VMX_GUEST_CS_ATTR);
    dbgDumpVmcsField(VMX_GUEST_CS_SEL);
    dbgDumpVmcsField(VMX_GUEST_RSP);
    dbgDumpVmcsField(VMX_GUEST_RIP);
    dbgDumpVmcsField(VMX_GUEST_ACTIVITY_STATE);
    dbgDumpVmcsField(VMX_GUEST_INTERUPT_STATE);
    dbgDumpVmcsField(VMX_GUEST_PENDING_DEBUG);
    dbgDumpVmcsField(VMX_GUEST_VMCS_LINKP);
    dbgDumpVmcsField(VMX_GUEST_VMCS_LINKP_HIGH);
    dbgDumpVmcsField(VMX_GUEST_IA32_EFER_LOW);
    dbgDumpVmcsField(VMX_GUEST_IA32_EFER_HIGH);
    dbgDumpVmcsField(VMX_GUEST_ES_BASE);
    dbgDumpVmcsField(VMX_GUEST_CS_BASE);
    dbgDumpVmcsField(VMX_GUEST_SS_BASE);
    dbgDumpVmcsField(VMX_GUEST_DS_BASE);
    dbgDumpVmcsField(VMX_GUEST_FS_BASE);
    dbgDumpVmcsField(VMX_GUEST_GS_BASE);
    dbgDumpVmcsField(VMX_GUEST_TR_BASE);
    dbgDumpVmcsField(VMX_GUEST_RFLAGS);
    dbgDumpVmcsField(VMX_INTERRUPT_INFORMATION);
    dbgDumpVmcsField(VMX_GUEST_MSR_DEBUGCTL_FULL);
    dbgDumpVmcsField(VMX_GUEST_MSR_DEBUGCTL_HIGH);
    dbgDumpVmcsField(VMX_GUEST_MSR_PERFGLOBAL_FULL);
    dbgDumpVmcsField(VMX_GUEST_MSR_PERFGLOBAL_HIGH);
    dbgDumpVmcsField(VMX_GUEST_MSR_PAT_FULL);
    dbgDumpVmcsField(VMX_GUEST_MSR_PAT_HIGH);
    dbgDumpVmcsField(VMX_GUEST_MSR_EFER_FULL);
    dbgDumpVmcsField(VMX_GUEST_MSR_EFER_HIGH);
}

/*
Cr3 exit handler => at the beggining I set the CR3 Exit controls to 1, so I had to use this handler
*/
void MhvHandleCr3Exit(PROCESSOR *CurrentProc)
{
    QWORD exqual;
    __vmx_vmread(VMX_EXIT_QUALIFICATION, &exqual);
    QWORD instructionLength;
    __vmx_vmread(VMX_EXIT_INSTRUCTION_LENGTH, &instructionLength);
    QWORD rip;
    __vmx_vmread(VMX_GUEST_RIP, &rip);
    rip += instructionLength;
    __vmx_vmwrite(VMX_GUEST_RIP, rip);

    if (3 == (exqual & 0xF)) // cr3
    {
        QWORD accessType = (exqual & 0x30)>>4;
        QWORD regUsed = (exqual & 0xF00)>>8;
        if (0 == accessType)
        {
            LOG("Move to cr3");
            if (0 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._rax);
            }
            if (1 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._rcx);
            }
            if (2 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._rdx);
            }
            if (3 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._rbx);
            }
            if (6 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._rsi);
            }
            if (7 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._rdi);
            }
            if (8 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._r8);
            }
            if (9 == regUsed)
            {
                __vmx_vmwrite(VMX_GUEST_CR3, CurrentProc->context._r9);
            }
        }
        if (1 == accessType)
        {
            QWORD currentCr3; 
            __vmx_vmread(VMX_GUEST_CR3, &currentCr3);
            if (0 == regUsed)
            {
                CurrentProc->context._rax = currentCr3;
            }
            if (1 == regUsed)
            {
                CurrentProc->context._rcx = currentCr3;
            }
            if (2 == regUsed)
            {
                CurrentProc->context._rdx = currentCr3;
            }
            if (3 == regUsed)
            {
                CurrentProc->context._rbx = currentCr3;
            }
            if (6 == regUsed)
            {
                CurrentProc->context._rsi = currentCr3;
            }
            if (7 == regUsed)
            {
                CurrentProc->context._rdi = currentCr3;
            }
            if (8 == regUsed)
            {
                CurrentProc->context._r8 = currentCr3;
            }
            if (9 == regUsed)
            {
                CurrentProc->context._r9 = currentCr3;
            }
            
        }
    }
    else
    {
        LOG("Unhandled CR access");
        __halt();
    }


}