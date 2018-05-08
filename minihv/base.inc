%ifndef _BASE_INC_
%define _BASE_INC_

;
; list of macros:
; - LIBFN:          import a set of functions from a given dll
; - LIBCALL:        call some external (exported) symbol
; - PROGRAM:        provides quick standard imports and an entry point
; - DATA:           generate a data segment
; - WAITKEY:        print a message and wait for a key
; - NL, LN, nl, ln: expands to a 10, 13 combo (new line character)
;


%macro LIBFN 1-*
;
; dynamic dll imports
; usage: LIBFN dllname, functionName(s)
;
%push libfn
%xdefine     lastLibName    %1
%rep (%0 - 1)
    %rotate 1
    extern %1
    import %1 lastLibName
%endrep
%pop
%endmacro



%macro PROGRAM 0-*
;
; generate some standard imports and specify the entry point
;
    [bits 32]
    LIBFN kernel32.dll, ExitProcess, CreateThread, WaitForSingleObject, ExitThread
    LIBFN msvcrt.dll, printf, _kbhit, _getch, malloc, time, free

    global start

    segment code use32 class=code
    start:
%endmacro

%macro DATA 0-*
;
; generate a data section defaulted to 'data' unless a custom name is given
;
    %if %0 > 0
        segment %1 use32 class=data
    %else
        segment %1 use32 class=data
    %endif
%endmacro


%macro WAITKEY 0
;
; wait for a keypress
;
%ifdef WAITKEY_IMPLEMENTED
    call        WaitKey
%else
%define WAITKEY_IMPLEMENTED
    ; fake a return address on current stack frame
    push        DWORD WaitKey.end
WaitKey:
    pusha
    
    ; print a message first
    call        .message
    db          "Press any key to continue", nl, 0
.message:   
    LIBCALL     printf
    add         esp, 4
    
    ; read one key at a time until the buffer is empty
%%again:    
    LIBCALL     _kbhit
    test        eax, eax
    jz          %%done
    LIBCALL     _getch      ; consume the buffered key code
    jmp         %%again
%%done:

    ; wait / read a key now that the keyboard buffer is empty
    LIBCALL     _getch
    
    popa
    ret
WaitKey.end:
%endif
%endmacro
    
;
; line endings..
;
%define NL 10, 13
%define LN NL
%define nl NL
%define ln NL


;
; indirect memory call for exports
;
%macro LIBCALL 1
    call [%1]
%endmacro

%endif
