// avxtester.cpp : Defines the entry point for the console application.
//
#include <windows.h>
#include <stdio.h>

VOID
DoJob()
{
    for (int i = 0; i < 100; i++)
    {
        CreateFileA("no tengo dinero", 0, 0, NULL, 0, 0, NULL);
    }

    for (int i = 0; i < 100; i++)
    {
        FreeLibrary(0);
    }

    printf("TID: %p", GetCurrentThreadId());
}

int main()
{

    HMODULE hMod = LoadLibraryA("axvdll.dll");

    if (hMod == NULL)
    {
        printf("load: %d", GetLastError());
    }
    
    
    printf("%d\n", GetCurrentProcessId());

    //Sleep(10000);
    printf("%d\n", GetCurrentProcess());
    //__debugbreak();
    //HeapAlloc((HANDLE)-1, 0, 100);
    HANDLE hds[32];
    for (int i = 0; i < 32; i++)
    {
        hds[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DoJob, NULL, 0, NULL);
    }
    
    for (int i = 0; i < 32; i++)
    {
        WaitForSingleObject(hds[i], INFINITE);
    }
    
    return 0;
}

