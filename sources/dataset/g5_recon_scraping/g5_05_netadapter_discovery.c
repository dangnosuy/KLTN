// SAMPLE: g5_05 | NetAdapterDiscovery | Group: Recon & In-Memory Scraping
// Technique: Network Adapter Discovery via GetAdaptersInfo (IP Helper API)
// Compile: x86_64-w64-mingw32-gcc -O2 -o g5_05_netadapter_discovery.exe g5_05_netadapter_discovery.c -liphlpapi

#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/c1_proof.h"

int main(void) {
    // First call: get required buffer size
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    IP_ADAPTER_INFO *pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (!pAdapterInfo) {
        fprintf(stderr, "[g5_05] malloc failed\n");
        return EXIT_FAILURE;
    }

    DWORD dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        // Buffer too small — reallocate with the size returned
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (!pAdapterInfo) {
            fprintf(stderr, "[g5_05] malloc (resize) failed\n");
            return EXIT_FAILURE;
        }
        dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        fprintf(stderr, "[g5_05] GetAdaptersInfo failed: %lu\n", dwRetVal);
        free(pAdapterInfo);
        return EXIT_FAILURE;
    }

    // Walk the linked list and count adapters
    int count = 0;
    IP_ADAPTER_INFO *pCurrent = pAdapterInfo;
    while (pCurrent) {
        fprintf(stderr, "[g5_05] Adapter #%d: %s | IP: %s\n",
                count + 1,
                pCurrent->Description,
                pCurrent->IpAddressList.IpAddress.String);
        count++;
        pCurrent = pCurrent->Next;
    }

    free(pAdapterInfo);

    fprintf(stderr, "[g5_05] Total adapters found: %d\n", count);

    // Verification gate
    if (count < 1) {
        fprintf(stderr, "[g5_05] No network adapters found — aborting proof write\n");
        return EXIT_FAILURE;
    }

    // Encode adapter count in technique field
    char technique[64];
    snprintf(technique, sizeof(technique), "NetAdapterDiscovery_N%d", count);

    int rc = write_c1_proof("g5_05_netadapter_discovery", technique);
    if (rc != 0) {
        fprintf(stderr, "[g5_05] write_c1_proof failed: %d\n", rc);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[g5_05] Proof written — %s\n", technique);
    return EXIT_SUCCESS;
}
