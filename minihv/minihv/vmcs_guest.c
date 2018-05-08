#include "VMCS_encoding.h"
#include "vmcs_init_guest.h"
#include "vmxop.h"

#define SHIFT_32 0x31

#define  VM_INSTRUCTION_ERROR  0x00004400

#define DR7               0x7

#define DATA64_SEL	0x10
#define CODE64_SEL	0x08

void VMCS_init_guest()
{
    unsigned __int64 CRX;
    unsigned __int64 DRX;
    unsigned __int64 RFLAGS;
    unsigned __int64 MSR;
    unsigned __int8 status;

    /* set -> CR0 */
    CRX = __readcr0();
    status = __vmx_vmwrite(GUEST_CR0, CRX);
    //CheckVMWriteStatus(status, "GUEST_CR0");

    /* set -> CR3 */
    CRX = __readcr3();
    status = __vmx_vmwrite(GUEST_CR3, CRX);
    //CheckVMWriteStatus(status, "GUEST_CR3");

    /* set -> CR4 */
    CRX = __readcr4();
    status = __vmx_vmwrite(GUEST_CR4, CRX);
    //CheckVMWriteStatus(status, "GUEST_CR4");

    /* set -> DR7 */
    DRX = __readdr(DR7);
    status = __vmx_vmwrite(GUEST_DR7, DRX);
    //CheckVMWriteStatus(status, "GUEST_DR7");

    /* set -> RIP */
    void(*return_f)() = testMbr;
    __int64 entry = return_f;
    status = __vmx_vmwrite(GUEST_RIP, entry);
    //CheckVMWriteStatus(status, "GUEST_RIP");

    /* set -> RSP */
    status = __vmx_vmwrite(GUEST_RSP, 0xA000000);
    //CheckVMWriteStatus(status, "GUEST_RSP");

    /* set -> RFLAGS */
    RFLAGS = __readeflags();
    status = __vmx_vmwrite(GUEST_RFLAGS, 0x2);
    //CheckVMWriteStatus(status, "GUEST_RFLAGS");

    /* set -> CS selector */
    status = __vmx_vmwrite(GUEST_CS_SELECTOR, CODE64_SEL);
    //CheckVMWriteStatus(status, "GUEST_CS_SELECTOR");


    /* set -> ES selector */
    status = __vmx_vmwrite(GUEST_ES_SELECTOR, DATA64_SEL);
    //CheckVMWriteStatus(status, "GUEST_ES_SELECTOR");


    /* set -> SS selector */
    status = __vmx_vmwrite(GUEST_SS_SELECTOR, DATA64_SEL);
    //CheckVMWriteStatus(status, "GUEST_SS_SELECTOR");


    /* set -> DS selector */
    status = __vmx_vmwrite(GUEST_DS_SELECTOR, DATA64_SEL);
    //CheckVMWriteStatus(status, "GUEST_DS_SELECTOR");

    /* set -> FS selector */
    status = __vmx_vmwrite(GUEST_FS_SELECTOR, DATA64_SEL);
    //CheckVMWriteStatus(status, "GUEST_FS_SELECTOR");

    /* set -> GS selector */
    status = __vmx_vmwrite(GUEST_GS_SELECTOR, DATA64_SEL);
    //CheckVMWriteStatus(status, "GUEST_GS_SELECTOR");

    /* set -> LDTR selector */
    status = __vmx_vmwrite(GUEST_LDTR_SELECTOR, 0x0);// <--------- unusable
    //CheckVMWriteStatus(status, "GUEST_LDTR_SELECTOR");

    /* set -> TR selector */
    status = __vmx_vmwrite(GUEST_TR_SELECTOR, DATA64_SEL);
    //CheckVMWriteStatus(status, "GUEST_TR_SELECTOR");


    /************************************************************************/
    /*                                                                      */
    /************************************************************************/
    /* set -> CS limit */
    status = __vmx_vmwrite(GUEST_CS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_CS_LIMIT");


    /* set -> ES limit */
    status = __vmx_vmwrite(GUEST_ES_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_ES_LIMIT");


    /* set -> SS limit */
    status = __vmx_vmwrite(GUEST_SS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_SS_LIMIT");


    /* set -> DS limit */
    status = __vmx_vmwrite(GUEST_DS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_DS_LIMIT");

    /* set -> FS limit */
    status = __vmx_vmwrite(GUEST_FS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_FS_LIMIT");

    /* set -> GS limit */
    status = __vmx_vmwrite(GUEST_GS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_GS_LIMIT");

    /* set -> LDTR limit */
    status = __vmx_vmwrite(GUEST_LDTR_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_LDTR_LIMIT");

    /* set -> TR limit */
    status = __vmx_vmwrite(GUEST_TR_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_TR_LIMIT");

    /************************************************************************/
    /* base address                                                         */
    /************************************************************************/
    /* set -> CS base address  */
    status = __vmx_vmwrite(GUEST_CS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_CS_BASE");


    /* set -> ES base address  */
    status = __vmx_vmwrite(GUEST_ES_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_ES_BASE");


    /* set -> SS base address  */
    status = __vmx_vmwrite(GUEST_SS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_SS_BASE");


    /* set -> DS base address  */
    status = __vmx_vmwrite(GUEST_DS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_DS_BASE");

    /* set -> FS base address  */
    status = __vmx_vmwrite(GUEST_FS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_FS_BASE");

    /* set -> GS base address  */
    status = __vmx_vmwrite(GUEST_GS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_GS_BASE");

    /* set -> LDTR base address  */
    status = __vmx_vmwrite(GUEST_LDTR_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_LDTR_BASE");

    /* set -> TR base address  */
    status = __vmx_vmwrite(GUEST_TR_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_TR_BASE");

    /************************************************************************/
    /* access rights                                                        */
    /************************************************************************/
    /* set -> CS access rights  */
    status = __vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, 0xA093);
    //CheckVMWriteStatus(status, "GUEST_CS_ACCESS_RIGHTS");


    /* set -> ES access rights  */
    status = __vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS, 0xc091);
    //CheckVMWriteStatus(status, "GUEST_ES_ACCESS_RIGHTS");


    /* set -> SS access rights  */
    status = __vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS, 0xc093);
    //CheckVMWriteStatus(status, "GUEST_SS_ACCESS_RIGHTS");


    /* set -> DS access rights  */
    status = __vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS, 0xc091);
    //CheckVMWriteStatus(status, "GUEST_DS_ACCESS_RIGHTS");

    /* set -> FS access rights  */
    status = __vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS, 0xc091);
    //CheckVMWriteStatus(status, "GUEST_FS_ACCESS_RIGHTS");

    /* set -> GS access rights  */
    status = __vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS, 0xc091);
    //CheckVMWriteStatus(status, "GUEST_GS_ACCESS_RIGHTS");

    /* set -> LDTR access rights  */
    status = __vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
    //CheckVMWriteStatus(status, "GUEST_LDTR_ACCESS_RIGHTS");

    /* set -> TR access rights  */
    status = __vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, 0x808B);
    //CheckVMWriteStatus(status, "GUEST_TR_ACCESS_RIGHTS");

    /************************************************************************/
    /* GDTR/IDTR                                                            */
    /************************************************************************/
    status = __vmx_vmwrite(GUEST_GDTR_BASE, 0x20004C0);
    //CheckVMWriteStatus(status, "GUEST_GDTR_BASE");
    status = __vmx_vmwrite(GUEST_GDTR_LIMIT, 0x18);
    //CheckVMWriteStatus(status, "GUEST_GDTR_LIMIT");

    status = __vmx_vmwrite(GUEST_IDTR_BASE, 0x0); //0x13A2
    //CheckVMWriteStatus(status, "GUEST_IDTR_BASE");
    status = __vmx_vmwrite(GUEST_IDTR_LIMIT, 0x3ff); //0x200
    //CheckVMWriteStatus(status, "GUEST_IDTR_LIMIT");

    /************************************************************************/
    /* MSRs                                                                 */
    /************************************************************************/

    /* set -> IA32_DEBUGCTL*/
    MSR = __readmsr(IA32_DEBUGCTL);
    status = __vmx_vmwrite(GUEST_IA32_DEBUGCTL_FULL, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_DEBUGCTL_FULL");

    MSR = __ull_rshift(MSR, SHIFT_32);
    status = __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_DEBUGCTL_HIGH");


    /* set -> IA32_SYSENTER_CS */
    MSR = __readmsr(IA32_SYSENTER_CS);
    status = __vmx_vmwrite(GUEST_IA32_SYSENTER_CS, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_SYSENTER_CS");

    /* set -> IA32_SYSENTER_ESP */
    MSR = __readmsr(IA32_SYSENTER_ESP);
    status = __vmx_vmwrite(GUEST_IA32_SYSENTER_ESP, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_SYSENTER_ESP");

    /* set -> IA32_SYSENTER_EIP */
    MSR = __readmsr(IA32_SYSENTER_EIP);
    status = __vmx_vmwrite(GUEST_IA32_SYSENTER_EIP, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_SYSENTER_EIP");

    /* set -> IA32_PERF_GLOBAL_CTRL*/
    MSR = __readmsr(IA32_PERF_GLOBAL_CTRL);
    status = __vmx_vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL_FULL, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_PERF_GLOBAL_CTRL_FULL");

    MSR = __ull_rshift(MSR, SHIFT_32);
    status = __vmx_vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL_HIGH, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_PERF_GLOBAL_CTRL_HIGH");

    /* set -> IA32_PAT */
    MSR = __readmsr(IA32_PAT);
    status = __vmx_vmwrite(GUEST_IA32_PAT_FULL, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_PAT_FULL");

    MSR = __ull_rshift(MSR, SHIFT_32);
    status = __vmx_vmwrite(GUEST_IA32_PAT_HIGH, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_PAT_HIGH");

    /* set -> IA32_EFER */
    MSR = __readmsr(IA32_EFER);
    status = __vmx_vmwrite(GUEST_IA32_EFER_FULL, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_EFER_FULL");

    MSR = __ull_rshift(MSR, SHIFT_32);
    status = __vmx_vmwrite(GUEST_IA32_EFER_HIGH, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_EFER_HIGH");


    /* set -> IA32_BNDCFGS */
    MSR = __readmsr(IA32_BNDCFGS);
    status = __vmx_vmwrite(GUEST_IA32_BNDCFGS_FULL, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_BNDCFGS_FULL");

    MSR = __ull_rshift(MSR, SHIFT_32);
    status = __vmx_vmwrite(GUEST_IA32_BNDCFGS_HIGH, MSR);
    //CheckVMWriteStatus(status, "GUEST_IA32_BNDCFGS_HIGH");

    status = __vmx_vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, 0x0);
    //CheckVMWriteStatus(status, "VMCS_32BIT_GUEST_ACTIVITY_STATE");

    status = __vmx_vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE, 0x0);
    //CheckVMWriteStatus(status, "VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE");

    status = __vmx_vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0x0);
    //CheckVMWriteStatus(status, "VMCS_GUEST_PENDING_DBG_EXCEPTIONS");

    status = __vmx_vmwrite(VMCS_64BIT_GUEST_LINK_POINTER, 0xFFFFFFFF);
    //CheckVMWriteStatus(status, "VMCS_64BIT_GUEST_LINK_POINTER");

    status = __vmx_vmwrite(VMCS_64BIT_GUEST_LINK_POINTER_HI, 0xFFFFFFFF);
    //CheckVMWriteStatus(status, "VMCS_64BIT_GUEST_LINK_POINTER_HI");
}

#define SELECTOR 0x0

void VMCS_init_guest16Bits(__int64 start)
{
    unsigned __int64 CRX;
    unsigned __int64 DRX;
    unsigned __int64 RFLAGS;
    unsigned __int64 MSR;
    unsigned __int8 status;

    /* set -> CR0 */
    CRX = __readcr0();

    CRX = __readmsr(0x487); // fixed
    CRX = CRX | 0x80000021;
    status = __vmx_vmwrite(GUEST_CR0, 0x60000030);
    //CheckVMWriteStatus(status, "GUEST_CR0");

    /* set -> CR3 */
    CRX = __readcr3();
    status = __vmx_vmwrite(GUEST_CR3, 0x0);
    //CheckVMWriteStatus(status, "GUEST_CR3");

    /* set -> CR4 */
    CRX = __readcr4();

    CRX = __readmsr(0x489); // fixed
    CRX = CRX | 0x2000;
    status = __vmx_vmwrite(GUEST_CR4, 0x2000);
    //CheckVMWriteStatus(status, "GUEST_CR4");

    /* set -> DR7 */
    DRX = __readdr(DR7);
    status = __vmx_vmwrite(GUEST_DR7, DRX);
    //CheckVMWriteStatus(status, "GUEST_DR7");

    /* set -> RIP */
    status = __vmx_vmwrite(GUEST_RIP, start<<12);
    //CheckVMWriteStatus(status, "GUEST_RIP");

    /* set -> RSP */
    status = __vmx_vmwrite(GUEST_RSP, 0x0);
    //CheckVMWriteStatus(status, "GUEST_RSP");

    /* set -> RFLAGS */
    RFLAGS = __readeflags();
    RFLAGS = 0x2;
    RFLAGS = RFLAGS | 0x20000;
    status = __vmx_vmwrite(GUEST_RFLAGS, 0x02);
    //CheckVMWriteStatus(status, "GUEST_RFLAGS");

    /* set -> CS selector */
    status = __vmx_vmwrite(GUEST_CS_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_CS_SELECTOR");


    /* set -> ES selector */
    status = __vmx_vmwrite(GUEST_ES_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_ES_SELECTOR");


    /* set -> SS selector */
    status = __vmx_vmwrite(GUEST_SS_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_SS_SELECTOR");


    /* set -> DS selector */
    status = __vmx_vmwrite(GUEST_DS_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_DS_SELECTOR");

    /* set -> FS selector */
    status = __vmx_vmwrite(GUEST_FS_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_FS_SELECTOR");

    /* set -> GS selector */
    status = __vmx_vmwrite(GUEST_GS_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_GS_SELECTOR");

    /* set -> LDTR selector */
    status = __vmx_vmwrite(GUEST_LDTR_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_LDTR_SELECTOR");

    /* set -> TR selector */
    status = __vmx_vmwrite(GUEST_TR_SELECTOR, SELECTOR);
    //CheckVMWriteStatus(status, "GUEST_TR_SELECTOR");


    /************************************************************************/
    /*                                                                      */
    /************************************************************************/
    /* set -> CS limit */
    status = __vmx_vmwrite(GUEST_CS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_CS_LIMIT");


    /* set -> ES limit */
    status = __vmx_vmwrite(GUEST_ES_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_ES_LIMIT");


    /* set -> SS limit */
    status = __vmx_vmwrite(GUEST_SS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_SS_LIMIT");


    /* set -> DS limit */
    status = __vmx_vmwrite(GUEST_DS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_DS_LIMIT");

    /* set -> FS limit */
    status = __vmx_vmwrite(GUEST_FS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_FS_LIMIT");

    /* set -> GS limit */
    status = __vmx_vmwrite(GUEST_GS_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_GS_LIMIT");

    /* set -> LDTR limit */
    status = __vmx_vmwrite(GUEST_LDTR_LIMIT, 0xffffffff);
    //CheckVMWriteStatus(status, "GUEST_LDTR_LIMIT");

    /* set -> TR limit */
    status = __vmx_vmwrite(GUEST_TR_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_TR_LIMIT");

    /************************************************************************/
    /* base address                                                         */
    /************************************************************************/
    /* set -> CS base address  */
    status = __vmx_vmwrite(GUEST_CS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_CS_BASE");


    /* set -> ES base address  */
    status = __vmx_vmwrite(GUEST_ES_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_ES_BASE");


    /* set -> SS base address  */
    status = __vmx_vmwrite(GUEST_SS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_SS_BASE");


    /* set -> DS base address  */
    status = __vmx_vmwrite(GUEST_DS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_DS_BASE");

    /* set -> FS base address  */
    status = __vmx_vmwrite(GUEST_FS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_FS_BASE");

    /* set -> GS base address  */
    status = __vmx_vmwrite(GUEST_GS_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_GS_BASE");

    /* set -> LDTR base address  */
    status = __vmx_vmwrite(GUEST_LDTR_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_LDTR_BASE");

    /* set -> TR base address  */
    status = __vmx_vmwrite(GUEST_TR_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_TR_BASE");

    /************************************************************************/
    /* access rights                                                        */
    /************************************************************************/
    /* set -> CS access rights  */
    status = __vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, 0x93);
    //CheckVMWriteStatus(status, "GUEST_CS_ACCESS_RIGHTS");


    /* set -> ES access rights  */
    status = __vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS, 0x93);
    //CheckVMWriteStatus(status, "GUEST_ES_ACCESS_RIGHTS");


    /* set -> SS access rights  */
    status = __vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS, 0x93);
    //CheckVMWriteStatus(status, "GUEST_SS_ACCESS_RIGHTS");


    /* set -> DS access rights  */
    status = __vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS, 0x93);
    //CheckVMWriteStatus(status, "GUEST_DS_ACCESS_RIGHTS");

    /* set -> FS access rights  */
    status = __vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS, 0x93);
    //CheckVMWriteStatus(status, "GUEST_FS_ACCESS_RIGHTS");

    /* set -> GS access rights  */
    status = __vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS, 0x93);
    //CheckVMWriteStatus(status, "GUEST_GS_ACCESS_RIGHTS");

    /* set -> LDTR access rights  */
    status = __vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
    //CheckVMWriteStatus(status, "GUEST_LDTR_ACCESS_RIGHTS");

    /* set -> TR access rights  */
    status = __vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, 0x8083);
    //CheckVMWriteStatus(status, "GUEST_TR_ACCESS_RIGHTS");

    /************************************************************************/
    /* GDTR/IDTR                                                            */
    /************************************************************************/
    status = __vmx_vmwrite(GUEST_GDTR_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_GDTR_BASE");
    status = __vmx_vmwrite(GUEST_GDTR_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_GDTR_LIMIT");

    status = __vmx_vmwrite(GUEST_IDTR_BASE, 0x0);
    //CheckVMWriteStatus(status, "GUEST_IDTR_BASE");
    status = __vmx_vmwrite(GUEST_IDTR_LIMIT, 0xFFFF);
    //CheckVMWriteStatus(status, "GUEST_IDTR_LIMIT");

}