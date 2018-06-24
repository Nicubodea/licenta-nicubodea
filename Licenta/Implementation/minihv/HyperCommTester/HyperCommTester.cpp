// HyperCommTester.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "structures.h"
#include <time.h>





typedef LONG (* PFUNC_HyperCommAddProtectionToProcess) (
    char* Process,
    int Protection
    );

typedef LONG(*PFUNC_HyperCommGetLatestEvent)(
    PEVENT* Event
    );

typedef LONG(*PFUNC_HyperCommExceptAlert)(
    PEVENT Event
);


PFUNC_HyperCommAddProtectionToProcess pAddProcessFunction;
PFUNC_HyperCommGetLatestEvent pGetEventFunction;
PFUNC_HyperCommExceptAlert pExceptAlertFunction;



double
PerformanceTesting(int flags, int nr)
{
    pAddProcessFunction("introum_dummy.exe", flags);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int i;
    clock_t sumofrdtsc = 0;
    for (i = 0; i < nr; i++)
    {
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));

        si.cb = sizeof(si);


        clock_t start = clock();
        if (!CreateProcessA(NULL, "introum_dummy.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            printf("%d\n", GetLastError());
            break;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        clock_t end = clock();
        sumofrdtsc += end - start;
    }

    return (sumofrdtsc / (double)CLOCKS_PER_SEC);
}

VOID
LogCurrentEvent(
    PEVENT Event
)
{
    if (Event->Type == mhvEventProcessCreate)
    {
        printf("[INFO] Process %s pid %d was created\n", Event->ProcessCreateEvent.Name, Event->ProcessCreateEvent.Pid);
    }
    else if (Event->Type == mhvEventProcessTerminate)
    {
        printf("[INFO] Process %s pid %d was terminated\n", Event->ProcessTerminateEvent.Name, Event->ProcessTerminateEvent.Pid);
    }
    else if (Event->Type == mhvEventModuleLoad)
    {
        printf("[INFO] Module %s was loaded in process %s pid %d\n", Event->ModuleLoadEvent.Module.Name, Event->ModuleLoadEvent.ProcessName, Event->ModuleLoadEvent.Pid);
    }
    else if (Event->Type == mhvEventModuleUnload)
    {
        printf("[INFO] Module %s was unloaded in process %s pid %d\n", Event->ModuleUnloadEvent.Module.Name, Event->ModuleUnloadEvent.ProcessName, Event->ModuleUnloadEvent.Pid);
    }
    else if (Event->Type == mhvEventModuleAlert)
    {
        printf("[WARNING] Writing attempt detected!\n");
        printf("---> Process: %s pid %d\n", Event->ModuleAlertEvent.ProcessName, Event->ModuleAlertEvent.Pid);
        printf("---> Attacker: %s from RIP %p\n", Event->ModuleAlertEvent.Attacker.Name, Event->ModuleAlertEvent.Rip);
        printf("---> Victim: %s at address %p\n", Event->ModuleAlertEvent.Victim.Name, Event->ModuleAlertEvent.Address);

        printf("[WARNING] Dumping %d instructions from attacker code\n", Event->ModuleAlertEvent.NumberOfInstructions);

        long long currentRip = Event->ModuleAlertEvent.Rip;

        for (int i = 0; i < Event->ModuleAlertEvent.NumberOfInstructions; i++)
        {
            printf("---> %p: %s\n", currentRip, Event->ModuleAlertEvent.Instructions[i].Instruction);
            currentRip += Event->ModuleAlertEvent.Instructions[i].Length;
        }

        //pExceptAlertFunction(Event);

    }
}

VOID
EventListener(
    PVOID Arg
) {

    while (true)
    {
        PEVENT currentEvent;

        LONG status = pGetEventFunction(&currentEvent);

        if (status != 0)
        {
            Sleep(2000);
            continue;
        }

        LogCurrentEvent(currentEvent);
    }

}


int main()
{
    HMODULE hMod = LoadLibraryA("HyperComm.dll");

    if (hMod == NULL)
    {
        printf("[ERROR] loading lib %d", GetLastError());
        return 1;
    }

    pAddProcessFunction = (PFUNC_HyperCommAddProtectionToProcess)GetProcAddress(hMod, "HyperCommAddProtectionToProcess");
    pGetEventFunction = (PFUNC_HyperCommGetLatestEvent)GetProcAddress(hMod, "HyperCommGetLatestEvent");
    pExceptAlertFunction = (PFUNC_HyperCommExceptAlert)GetProcAddress(hMod, "HyperCommExceptAlert");

    //pAddProcessFunction("introum_detour", 0x7);
    //pAddProcessFunction("firefox.exe", 0);
    /*
    for (int i = 1; i <= 13; i += 3)
    {
        printf("Flags 0 %d tries: %.4lf\n", i, PerformanceTesting(0, i));

        printf("Flags 1 %d tries: %.4lf\n", i, PerformanceTesting(1, i));

        printf("Flags 3 %d tries: %.4lf\n", i, PerformanceTesting(3, i));

        printf("Flags 7 %d tries: %.4lf\n", i, PerformanceTesting(7, i));
    }
    */



    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EventListener, NULL, 0, NULL);

    while (true)
    {
        CHAR process[32];
        DWORD flags;
        scanf("%s %d", process, &flags);

        printf("[INFO] Will protect %s with flags %d\n", process, flags);

        pAddProcessFunction(process, flags);
    }

    WaitForSingleObject(hThread, INFINITE);
    
}
