#ifndef _VMCSDEF_H
#define _VMCSDEF_H
/*
EXIT REASONS
*/
#define         VMX_EXIT_REASON                 0x4402

#define         VMX_EXIT_NMI                    0
#define         VMX_EXIT_EXTERNAL_INTERRUPT     1
#define         VMX_EXIT_TRIPLE_FAULT           2
#define         VMX_EXIT_INIT                   3
#define         VMX_EXIT_SIPI                   4
#define         VMX_EXIT_IO_SMI                 5
#define         VMX_EXIT_OTHER_SMI              6
#define         VMX_EXIT_INT_WINDOW             7
#define         VMX_EXIT_NMI_WINDOW             8
#define         VMX_EXIT_TASK_SWITCH            9
#define         VMX_EXIT_CPUID                  10
#define         VMX_EXIT_GETSEC                 11
#define         VMX_EXIT_HLT                    12
#define         VMX_EXIT_INVD                   13
#define         VMX_EXIT_INVLPG                 14
#define         VMX_EXIT_RDPMC                  15
#define         VMX_EXIT_RDTSC                  16
#define         VMX_EXIT_RSM                    17
#define         VMX_EXIT_VMCALL                 18
#define         VMX_EXIT_VMCLEAR                19
#define         VMX_EXIT_VMLAUNCH               20
#define         VMX_EXIT_VMPTRLD                21
#define         VMX_EXIT_VMPTRST                22
#define         VMX_EXIT_VMREAD                 23
#define         VMX_EXIT_VMRESUME               24
#define         VMX_EXIT_VMWRITE                25
#define         VMX_EXIT_VMXOFF                 26
#define         VMX_EXIT_VMXON                  27
#define         VMX_EXIT_CR_ACCESS              28
#define         VMX_EXIT_MOV_DR                 29
#define         VMX_EXIT_IO                     30
#define         VMX_EXIT_RDMSR                  31
#define         VMX_EXIT_WRMSR                  32
#define         VMX_EXIT_EFAIL_INVALID_GUEST    33
#define         VMX_EXIT_EFAIL_INVALID_MSR      34
#define         VMX_EXIT_MWAIT                  36
#define         VMX_EXIT_MONITOR_TF             37
#define         VMX_EXIT_MONITOR                39
#define         VMX_EXIT_PAUSE                  40
#define         VMX_EXIT_EFAIL_MCHECK           41
#define         VMX_EXIT_TPR_THRESHOLD          43
#define         VMX_EXIT_APIC_ACCESS            44
#define         VMX_EXIT_VIRTUALIZED_EOI        45
#define         VMX_EXIT_GDTR_IDTR              46
#define         VMX_EXIT_LDTR_TR                47
#define         VMX_EXIT_EPT_VIOLATION          48
#define         VMX_EXIT_EPT_MISCONFIG          49
#define         VMX_EXIT_INVEPT                 50
#define         VMX_EXIT_RDTSCP                 51
#define         VMX_EXIT_PREEMPTION_EXP         52
#define         VMX_EXIT_INVVPID                53
#define         VMX_EXIT_WBINVD                 54
#define         VMX_EXIT_XSETBV                 55
#define         VMX_EXIT_APIC_WRITE             56
#define         VMX_EXIT_RDRAND                 57
#define         VMX_EXIT_INVPCID                58
#define         VMX_EXIT_VMFUNC                 59
#define         VMX_EXIT_ENCLS                  60
#define         VMX_EXIT_RDSEED                 61
#define         VMX_EXIT_PG_MODIF_LOG_FULL      62
#define         VMX_EXIT_XSAVES                 63
#define         VMX_EXIT_XRSTORS                64


/*
PROCESSOR BASED EXECUTION CONTROLS FLAGS
*/

#define     VMX_PROC_ACTIVATE_SECONDARY         31
#define     VMX_PROC_PAUSE_EXITING              30
#define     VMX_PROC_MONITOR_EXITING            29
#define     VMX_PROC_USE_MSR_BITMAPS            28
#define     VMX_PROC_MONITOR_TF                 27
#define     VMX_PROC_USE_IO_BITMAPS             25
#define     VMX_PROC_UNCONDITIONAL_IO_EXIT      24
#define     VMX_PROC_MOV_DR_EXITING             23
#define     VMX_PROC_NMI_WINDOW_EXITING         22
#define     VMX_PROC_TPR_SHADOW                 21
#define     VMX_PROC_CR8_STORE_EXITING          20
#define     VMX_PROC_CR8_LOAD_EXITING           19
#define     VMX_PROC_CR3_STORE_EXITING          16
#define     VMX_PROC_CR3_LOAD_EXITING           15
#define     VMX_PROC_RDTSC_EXITING              12
#define     VMX_PROC_RDPMC_EXITING              11
#define     VMX_PROC_MWAIT_EXITING              10
#define     VMX_PROC_INVLPG_EXITING             9
#define     VMX_PROC_HLT_EXITING                7
#define     VMX_PROC_TSC_OFFSETING              3
#define     VMX_PROC_INT_WINDOW_EXITING         2

/*
SECONDARY PROCESSOR BASED EXECUTION CONTROL FLAGS
*/
#define     VMX_SECPROC_EPT_VIOLATION_VE        18
#define     VMX_SECPROC_VMCS_SHADOWING          14
#define     VMX_SECPROC_ENABLE_VMFUNC           13
#define     VMX_SECPROC_ENABLE_INVPCID          12
#define     VMX_SECPROC_RDRAND_EXITING          11
#define     VMX_SECPROC_PAUSELOOP_EXITING       10
#define     VMX_SECPROC_VINT_DELIVERY           9
#define     VMX_SECPROC_APIC_VIRTUALIZATION     8
#define     VMX_SECPROC_UNRESTRICTED_GUEST      7
#define     VMX_SECPROC_WBINVD_EXITING          6
#define     VMX_SECPROC_ENABLE_VPID             5
#define     VMX_SECPROC_VIRTUALIZE_X2APIC       4
#define     VMX_SECPROC_ENABLE_RDTSCP           3
#define     VMX_SECPROC_DESC_EXITING            2
#define     VMX_SECPROC_ENABLE_EPT              1
#define     VMX_SECPROC_VIRTUALIZE_APIC         0


/*
PIN BASED EXECUTION CONTROLS FLAGS
*/


#define     VMX_PIN_PROCESS_POSTED_INTS         7
#define     VMX_PIN_ACTIVATE_PREEMPTION         6
#define     VMX_PIN_VIRTUAL_NMIS                5
#define     VMX_PIN_NMI_EXITING                 3
#define     VMX_PIN_EXTERNAL_INT_EXITING        0


/*
VM EXIT CONTROLS FLAGS
*/

#define     VMX_EXCTRL_CONCEAL_VM_EXIT_PT       24
#define     VMX_EXCTRL_CLEAR_BNDCFGS            23
#define     VMX_EXCTRL_SAVE_PREEMPTION          22
#define     VMX_EXCTRL_LOAD_IA32_EFER           21
#define     VMX_EXCTRL_SAVE_IA32_EFER           20
#define     VMX_EXCTRL_LOAD_IA32_PAT            19
#define     VMX_EXCTRL_SAVE_IA32_PAT            18
#define     VMX_EXCTRL_INT_ON_EXIT              15
#define     VMX_EXCTRL_LOAD_PERFGLOBAL          12
#define     VMX_EXCTRL_HOST_ADDR_SPACESIZE      9
#define     VMX_EXCTRL_SAVE_DEBUG_CONTROLS      2

/*

VM ENTRY CONTROLS FLAGS
*/

#define     VMX_ENTRY_CONCEAL_VM_ENTRY_PT       17
#define     VMX_ENTRY_LOAD_BNDCFGS              16
#define     VMX_ENTRY_LOAD_IA32_EFER            15
#define     VMX_ENTRY_LOAD_IA32_PAT             14
#define     VMX_ENTRY_LOAD_PERFGLOBAL           13
#define     VMX_ENTRY_DEACTIVATE_2MONITOR       11
#define     VMX_ENTRY_ENTRY_SMM                 10
#define     VMX_ENTRY_IA32e_MODE_GUEST          9
#define     VMX_ENTRY_LOAD_DEBUG_CONTROLS       2


/*
VM CONTROL FIELDS
*/

#define     VMX_PIN_CONTROLS_FIELD              0x4000
#define     VMX_PROC_CONTROLS_FIELD             0x4002
#define     VMX_PROC_SECONDARY_CONTROLS         0x401E
#define     VMX_EXIT_CONTROLS                   0x400C
#define     VMX_ENTRY_CONTROLS                  0x4012
#define     VMX_CR0_GUESTHOST_MASK              0x6000
#define     VMX_CR0_READ_SHADOW                 0x6004
#define     VMX_CR4_GUESTHOST_MASK              0x6002
#define     VMX_CR4_READ_SHADOW                 0x6006
#define     VMX_EXCEPTION_BITMAP                0x4004
#define     VMX_MSR_BITMAP                      0x2004
#define     VMX_CR3_TARGET_COUNT                0x400A
#define     VMX_CR3_TARGET_0                    0x6008
#define     VMX_CR3_TARGET_1                    0x600A
#define     VMX_CR3_TARGET_2                    0x600C
#define     VMX_CR3_TARGET_3                    0x600E


/*
HOST STATE AREA FIELDS
*/

#define     VMX_HOST_ES_SEL                     0xC00
#define     VMX_HOST_SS_SEL                     0xC04
#define     VMX_HOST_DS_SEL                     0xC06
#define     VMX_HOST_FS_SEL                     0xC08
#define     VMX_HOST_GS_SEL                     0xC0A
#define     VMX_HOST_TR_SEL                     0xC0C
#define     VMX_HOST_CR0                        0x6C00
#define     VMX_HOST_CR3                        0x6C02
#define     VMX_HOST_CR4                        0x6C04
#define     VMX_HOST_GDTR                       0x6C0C
#define     VMX_HOST_IDTR                       0x6C0E
#define     VMX_HOST_SYSENTER_ESP               0x6C10
#define     VMX_HOST_SYSENTER_EIP               0x6C12
#define     VMX_HOST_FS_BASE                    0x6C06
#define     VMX_HOST_GS_BASE                    0x6C08
#define     VMX_HOST_TR_BASE                    0x6C0A
#define     VMX_HOST_RSP                        0x6C14
#define     VMX_HOST_CS_SEL                     0xC02
#define     VMX_HOST_RIP                        0x6C16


/*
Guest state area
*/

#define     VMX_IA32_EFER                       0xC0000080
#define     VMX_GUEST_ES_SEL                    0x800
#define     VMX_GUEST_SS_SEL                    0x804
#define     VMX_GUEST_DS_SEL                    0x806
#define     VMX_GUEST_FS_SEL                    0x808
#define     VMX_GUEST_GS_SEL                    0x80A
#define     VMX_GUEST_TR_SEL                    0x80E
#define     VMX_GUEST_CR3                       0x6802
#define     VMX_GUEST_CR0                       0x6800
#define     VMX_GUEST_CR4                       0x6804
#define     VMX_GUEST_TR_ATTR                   0x4822
#define     VMX_GUEST_TR_LIMIT                  0x480E
#define     VMX_GUEST_LDTR_ATTR                 0x4820
#define     VMX_GUEST_SS_ATTR                   0x4818
#define     VMX_GUEST_DS_ATTR                   0x481A
#define     VMX_GUEST_ES_ATTR                   0x4814
#define     VMX_GUEST_FS_ATTR                   0x481C
#define     VMX_GUEST_GS_ATTR                   0x481E
#define     VMX_GUEST_SS_LIMIT                  0x4804
#define     VMX_GUEST_ES_LIMIT                  0x4800
#define     VMX_GUEST_DS_LIMIT                  0x4806
#define     VMX_GUEST_FS_LIMIT                  0x4808
#define     VMX_GUEST_GS_LIMIT                  0x480A
#define     VMX_GUEST_GDTR_LIMIT                0x4810
#define     VMX_GUEST_SYSENTER_ESP              0x6824
#define     VMX_GUEST_SYSENTER_EIP              0x6826
#define     VMX_GUEST_DR7                       0x681A
#define     VMX_GUEST_GDTR                      0x6816
#define     VMX_GUEST_CS_LIMIT                  0x4802
#define     VMX_GUEST_CS_ATTR                   0x4816
#define     VMX_GUEST_CS_SEL                    0x802
#define     VMX_GUEST_RSP                       0x681C
#define     VMX_GUEST_RIP                       0x681E
#define     VMX_GUEST_ACTIVITY_STATE            0x4826
#define     VMX_GUEST_INTERUPT_STATE            0x4824
#define     VMX_GUEST_PENDING_DEBUG             0x6822
#define     VMX_GUEST_VMCS_LINKP                0x2800
#define     VMX_GUEST_VMCS_LINKP_HIGH           0x2801
#define     VMX_GUEST_IA32_EFER_LOW             0x2806
#define     VMX_GUEST_IA32_EFER_HIGH            0x2807
#define     VMX_GUEST_ES_BASE                   0x6806
#define     VMX_GUEST_CS_BASE                   0x6808
#define     VMX_GUEST_SS_BASE                   0x680A
#define     VMX_GUEST_DS_BASE                   0x680C
#define     VMX_GUEST_FS_BASE                   0x680E
#define     VMX_GUEST_GS_BASE                   0x6810
#define     VMX_GUEST_TR_BASE                   0x6814
#define     VMX_GUEST_RFLAGS                    0x6820
#define     VMX_GUEST_MSR_DEBUGCTL_FULL         0x2802
#define     VMX_GUEST_MSR_DEBUGCTL_HIGH         0x2803
#define     VMX_GUEST_MSR_PERFGLOBAL_FULL       0x2808
#define     VMX_GUEST_MSR_PERFGLOBAL_HIGH       0x2809
#define     VMX_GUEST_MSR_PAT_FULL              0x2804
#define     VMX_GUEST_MSR_PAT_HIGH              0x2805
#define     VMX_GUEST_MSR_EFER_FULL             0x2806
#define     VMX_GUEST_MSR_EFER_HIGH             0x2807
#define     VMX_GUEST_IDTR                      0x6818
#define     VMX_GUEST_IDTR_LIMIT                0x4812
#define     VMX_GUEST_LINEAR_ADDRESS            0x640A


#define     VMX_EXIT_QUALIFICATION              0x6400
#define     VMX_INTERRUPT_INFORMATION           0x4404
#define     VMX_EXIT_MSR_STORE_COUNT            0x400E
#define     VMX_EXIT_MSR_LOAD_COUNT             0x4010
#define     VMX_ENTRY_MSR_LOAD_COUNT            0x4014
#define     VMX_ENTRY_INTERRUPTION_INFO         0x4016
#define     VMX_ENTRY_EXCEPTION_ERROR           0x4018
#define     VMX_ENTRY_INSTRUCTION_LENGTH        0x401A
#define     VMX_PAGE_FAULT_ERROR_MASK           0x4006
#define     VMX_PAGE_FAULT_ERROR_MATCH          0x4008
#define     VMX_EPT_POINTER                     0x201A
#define     VMX_EXIT_INSTRUCTION_LENGTH         0x440C


/*
MSR Defines
*/
#define     VMX_IA32_BASIC_MSR                  0x480
#define     VMX_IA32_PINBASED_MSR               0x481
#define     VMX_IA32_PINBASED_TRUE_MSR          0x48D
#define     VMX_IA32_PROCBASED_MSR              0x482
#define     VMX_IA32_PROCBASED_TRUE_MSR         0x48E
#define     VMX_IA32_PROCBASED2_MSR             0x48B
#define     VMX_IA32_EXIT_MSR                   0x483
#define     VMX_IA32_EXIT_TRUE_MSR              0x48F
#define     VMX_IA32_ENTRY_MSR                  0x484
#define     VMX_IA32_ENTRY_TRUE_MSR             0x490
#define     VMX_IA32_DEBUGCTL                   0x1D9
#define     VMX_IA32_PERF_GLOBAL_CTRL           0x38F
#define     VMX_IA32_PAT                        0x277
#define     VMX_IA32_EFER                       0xC0000080



/*
Activity states
*/

#define     VMX_ACTIVITY_STATE_ACTIVE           0
#define     VMX_ACTIVITY_STATE_HALT             1
#define     VMX_ACTIVITY_STATE_WAIT_FOR_SIPI    3

/*
Miscellaneous defines
*/

#define     VMX_BASIC_TRUE_SUPPORT              55
#define     VMX_ENABLE_PAGE_FAULT               14

#define KERNEL_BASE                         0x2000000
#define GDT_TABLE_ADDRESS                   0x2000000 + 0x4E8
#define IDT_TABLE_ADDRESS                   0x2000000 + 0xA400

#endif