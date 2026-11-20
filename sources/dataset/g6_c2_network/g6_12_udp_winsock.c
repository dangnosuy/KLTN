// SAMPLE: g6_12 | UDPWinsock | Group: C2 Network & Exfiltration
// Technique: UDP Datagram Telemetry via Winsock2
// Compile: x86_64-w64-mingw32-gcc -O2 -o g6_12_udp_winsock.exe g6_12_udp_winsock.c -lws2_32
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
#define BEACON_MSG     "BEACON g6_12_udp_winsock"
#define PROOF_PATH     "C:\\C1_Sandbox\\c1_proof.txt"
#define RECV_BUF_SIZE  4096
#define RECV_TIMEOUT_MS 5000

int main(void) {
    WSADATA  wsaData;
    SOCKET   sock     = INVALID_SOCKET;
    char     recvBuf[RECV_BUF_SIZE];
    int      bytesRecv = 0;
    int      ret       = EXIT_FAILURE;

    /* Initialise Winsock */
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[g6_12] WSAStartup failed: %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }

    /* Create UDP socket */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[g6_12] socket() failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Set receive timeout so we do not block forever if server is down */
    DWORD timeout = RECV_TIMEOUT_MS;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        fprintf(stderr, "[g6_12] setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Set up server address */
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_port        = htons((u_short)C2_PORT);
    server.sin_addr.s_addr = inet_addr(C2_HOST);

    /* Send beacon datagram (UDP is connectionless — no connect needed) */
    int msgLen = (int)strlen(BEACON_MSG);
    if (sendto(sock, BEACON_MSG, msgLen, 0,
               (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR) {
        fprintf(stderr, "[g6_12] sendto() failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Blocking recvfrom — wait for server proof datagram (up to 5 seconds) */
    struct sockaddr_in from;
    int fromLen = sizeof(from);
    memset(&from, 0, sizeof(from));

    bytesRecv = recvfrom(sock, recvBuf, sizeof(recvBuf) - 1, 0,
                         (SOCKADDR *)&from, &fromLen);
    if (bytesRecv == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT) {
            fprintf(stderr, "[g6_12] recvfrom() timed out — server unreachable, no proof written\n");
        } else {
            fprintf(stderr, "[g6_12] recvfrom() failed: %d\n", err);
        }
        goto cleanup;
    }
    if (bytesRecv <= 0) {
        fprintf(stderr, "[g6_12] Empty datagram received — no proof written\n");
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
        fprintf(stderr, "[g6_12] CreateFileA proof failed: %lu\n", GetLastError());
        goto cleanup;
    }
    DWORD written = 0;
    WriteFile(hProof, recvBuf, (DWORD)bytesRecv, &written, NULL);
    CloseHandle(hProof);

    printf("[g6_12] UDP beacon sent; %d bytes received; proof written to %s\n",
           bytesRecv, PROOF_PATH);
    ret = EXIT_SUCCESS;

cleanup:
    if (sock != INVALID_SOCKET) closesocket(sock);
    WSACleanup();
    return ret;
}
