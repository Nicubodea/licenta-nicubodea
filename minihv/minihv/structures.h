#ifndef _STRUCTURES_H
#define _STRUCTURES_H
#include "acpica.h"
#include "vmxept.h"
typedef struct _CONTEXT
{
    __int64 _rax;
    __int64 _rbx;
    __int64 _rcx;
    __int64 _rdx;
    __int64 _rsi;
    __int64 _rdi;
    __int64 _r8;
    __int64 _r9;
    __int64 _r10;
    __int64 _r11;
    __int64 _r12;
    __int64 _r13;
    __int64 _r14;
    __int64 _r15;
    __int64 _rsp;
    __int64 _cr2;
} CONTEXT, *PCONTEXT;



typedef struct _ISR {
    WORD bits0_15; // offset bits 0..15
    WORD selector; // a code segment selector in GDT or LDT
    BYTE ist;       // bits 0..2 holds Interrupt Stack Table offset, rest of bits zero.
    BYTE type_attr; // type and attributes
    WORD bits16_31; // offset bits 16..31
    DWORD bits32_63; // offset bits 32..63
    DWORD zero;     // reserved
} ISR, *PISR;

typedef struct _IDTR
{
    WORD Limit;
    PISR Base;
} IDTR, *PIDTR;


typedef struct _PROCESSOR
{
    CONTEXT         context;
    __int32         cpuid;
    __int32         apic;
    __int64         stack_base;
    __int64         stack_size;
    __int64         current_thread;
    void*           data_zone;
    void*           msr_area;
    BOOLEAN         state; //1 for running ; 0 for wait for sipi
    BOOLEAN         isBsp;
    __int64         vmxon;
    __int64         vmcs;
    __int64         sipi;
    PISR            idt;
    PVOID           syscall;
    __int64         xsetbvCount;
    QWORD           KernelBase;

    PEPT_POINTER    EptPointer;
    PEPT_POINTER    FullRightsEptPointer;

    QWORD           LastGLA;
    BOOLEAN         LastInterruptDisabled;

    QWORD           OldPTE;
    EPT_HOOK        LastHook;
    
} PROCESSOR, *PPROCESOR;

typedef struct _MEMORYMAP
{
    __int64     _start;
    __int64     _length;
    int         type;
    int         optional;
} MEMORYMAP, *PMEMORYMAP;



typedef struct _MTR
{
    __int64 PhysBase;
        __int64 PhysMask;
        __int64 Range;
    __int64 MemoryType;
    __int64 MtrType;
} MTR, *PMTR;

#endif