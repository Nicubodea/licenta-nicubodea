

extern "C"
{
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


    // Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
}


#include <windows.h>
#include <ntstatus.h>
#include "communication.h"
#include <vector>

typedef LONG NTSTATUS;

NTSTATUS
AvxCommGetConnectionSocket(
    _Out_ SOCKET* Socket
)
{
    WSADATA             wsaData;
    SOCKET              connectSocket = INVALID_SOCKET;
    struct addrinfo     *result = NULL, *ptr = NULL, hints;
    DWORD               iResult;
    NTSTATUS            status;
    BOOLEAN             bDecideIpFromCompName = FALSE;
    PCHAR               ip = "127.0.0.1";
    PCHAR               port = "50050";

    // Validate the parameters
    if (Socket == NULL)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return STATUS_UNSUCCESSFUL;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(ip, port, &hints, &result);
    if (iResult != 0) {
        WSACleanup();
        return STATUS_UNSUCCESSFUL;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        connectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (connectSocket == INVALID_SOCKET) {
            WSACleanup();
            return STATUS_UNSUCCESSFUL;
        }

        // Connect to server.
        iResult = connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(connectSocket);
            connectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (connectSocket == INVALID_SOCKET) {
        WSACleanup();
        return STATUS_UNSUCCESSFUL;
    }

    *Socket = connectSocket;
    return STATUS_SUCCESS;

}

extern DWORD pid;

NTSTATUS
AvxCommSendBuffer(
    _In_ SOCKET ConnectionSocket,
    _In_ std::vector<DWORD>& Ordinals
)
{
    CHAR        compName[MAX_PATH], message[MAX_PATH], recvMessage[MAX_PATH];
    DWORD       compNameSz, bytesSent, bytesReceived, recvBytes = MAX_PATH;

    DWORD sz = Ordinals.size();
    
    bytesSent = send(ConnectionSocket, (char*)&sz, sizeof(DWORD), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        return STATUS_UNSUCCESSFUL;
    }

    bytesSent = send(ConnectionSocket, (char*)&pid, sizeof(DWORD), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        return STATUS_UNSUCCESSFUL;
    }

    for (DWORD i = 0; i < sz; i++)
    {
        DWORD current = Ordinals[i];
        bytesSent = send(ConnectionSocket, (char*)&current, sizeof(DWORD), 0);
        if (bytesSent == SOCKET_ERROR)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }
    int ans = 0;
    bytesReceived = recv(ConnectionSocket, (char*)&ans, sizeof(DWORD), 0);
    
    if (ans == 1)
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;

}

VOID
AvxCommUninitComm(
    SOCKET* ConnectionSocket
)
{
    if (*ConnectionSocket != INVALID_SOCKET)
    {
        closesocket(*ConnectionSocket);
    }
    WSACleanup();
}