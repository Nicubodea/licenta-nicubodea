#pragma once

#include <windows.h>
#include <vector>

typedef LONG NTSTATUS;

NTSTATUS
AvxCommGetConnectionSocket(
    _Out_ SOCKET* Socket
);

NTSTATUS
AvxCommSendBuffer(
    _In_ SOCKET ConnectionSocket,
    _In_ std::vector<DWORD>& Ordinals
);

VOID
AvxCommUninitComm(
    SOCKET* ConnectionSocket
);
