#ifndef _MINIHV_H_
#define _MINIHV_H_

#ifndef TRUE
#define TRUE                1
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef NULL
#define NULL                0
#endif

#define PAGE_SIZE           0x1000

//
// standard types - define them with explicit length
//
typedef unsigned __int8     BYTE, *PBYTE;
typedef unsigned __int16    WORD, *PWORD;
typedef unsigned __int32    DWORD, *PDWORD;
typedef unsigned __int64    QWORD, *PQWORD;
typedef signed __int8       INT8;
typedef signed __int16      INT16;
typedef signed __int32      INT32;
typedef signed __int64      INT64;
typedef void                VOID;
typedef void*               PVOID;
typedef unsigned __int8     BOOLEAN;
typedef char*               PCHAR;
typedef unsigned long*      ULONG_PTR;
typedef unsigned __int64    size_t;
//
// special TRACE32 macro
//
#define BREAK_INTO_TRACE32(BreakVal)    __outbyte(0xBDB0, (BYTE)(BreakVal))

/// ...

#define ARRAYSIZE(x) (sizeof(x)/sizeof(x[0]))



#endif // _MINIHV_H_

