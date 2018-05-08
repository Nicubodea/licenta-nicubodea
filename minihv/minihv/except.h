#ifndef _EXCEPT_H_
#define _EXCEPT_H_

typedef struct _MHV_EXCEPTION
{
    PBYTE ProcessName;
    PBYTE ModuleOrigName;
    PBYTE ModuleVictimName;
} MHV_EXCEPTION, *PMHV_EXCEPTION;

BOOLEAN
MhvExcept(
    PMHVPROCESS Process,
    PMHVMODULE Originator,
    PMHVMODULE Victim
);

#endif