// SAMPLE: g5_07 | RegistryOSQuery | Group: Recon & In-Memory Scraping
// Technique: Windows Registry OS Build & Version Query
// Compile: x86_64-w64-mingw32-gcc -O2 -o g5_07_registry_os_query.exe g5_07_registry_os_query.c

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/c1_proof.h"

#define REG_PATH "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define VAL_BUF  256

static int query_sz(HKEY hKey, const char *name, char *out, DWORD outSz) {
    DWORD dwType = 0;
    DWORD dwSize = outSz;
    LONG  rc = RegQueryValueExA(hKey, name, NULL, &dwType, (LPBYTE)out, &dwSize);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[g5_07] RegQueryValueExA('%s') failed: %ld\n", name, rc);
        out[0] = '\0';
        return 0;  // non-fatal — caller decides
    }
    // Ensure null-termination
    if (dwSize < outSz) out[dwSize] = '\0';
    else                out[outSz - 1] = '\0';
    return 1;
}

int main(void) {
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_PATH, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[g5_07] RegOpenKeyExA failed: %ld\n", rc);
        return EXIT_FAILURE;
    }

    char productName[VAL_BUF]     = {0};
    char buildNumber[VAL_BUF]     = {0};
    char displayVersion[VAL_BUF]  = {0};

    query_sz(hKey, "ProductName",      productName,    sizeof(productName));
    query_sz(hKey, "CurrentBuildNumber", buildNumber,  sizeof(buildNumber));
    query_sz(hKey, "DisplayVersion",   displayVersion, sizeof(displayVersion));

    RegCloseKey(hKey);

    fprintf(stderr, "[g5_07] ProductName: %s | Build: %s | DisplayVersion: %s\n",
            productName, buildNumber, displayVersion);

    // Verification gate: ProductName must be non-empty
    if (productName[0] == '\0') {
        fprintf(stderr, "[g5_07] ProductName empty — aborting proof write\n");
        return EXIT_FAILURE;
    }

    // Encode OS build info in technique field (safe, alphanumeric only)
    char safeVersion[64] = {0};
    int vi = 0;
    for (int i = 0; displayVersion[i] && vi < (int)sizeof(safeVersion) - 1; i++) {
        char c = displayVersion[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') {
            safeVersion[vi++] = c;
        }
    }
    safeVersion[vi] = '\0';

    char technique[128];
    if (safeVersion[0] != '\0') {
        snprintf(technique, sizeof(technique), "RegistryOSQuery_Build%s_%s",
                 buildNumber, safeVersion);
    } else {
        snprintf(technique, sizeof(technique), "RegistryOSQuery_Build%s", buildNumber);
    }

    int wrc = write_c1_proof("g5_07_registry_os_query", technique);
    if (wrc != 0) {
        fprintf(stderr, "[g5_07] write_c1_proof failed: %d\n", wrc);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[g5_07] Proof written — %s\n", technique);
    return EXIT_SUCCESS;
}
