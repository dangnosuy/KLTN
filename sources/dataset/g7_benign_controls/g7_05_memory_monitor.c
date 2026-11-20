// SAMPLE: g7_05 | SystemMemoryMonitor | Group: Benign Controls
// Calls GlobalMemoryStatusEx() and GetDiskFreeSpaceExA() to query physical RAM
// (MB) and total disk capacity (GB) on C:\, verifies both > 0, writes proof.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

int main(void)
{
    /* ---- Physical memory ---- */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) {
        fprintf(stderr, "[g7_05] GlobalMemoryStatusEx failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }

    ULONGLONG totalPhysMB = ms.ullTotalPhys / (1024ULL * 1024ULL);
    printf("[g7_05] Total physical memory : %llu MB\n", totalPhysMB);

    if (totalPhysMB == 0) {
        fprintf(stderr, "[g7_05] Reported physical memory is 0 — unexpected.\n");
        return EXIT_FAILURE;
    }

    /* ---- Disk capacity (C:\) ---- */
    ULARGE_INTEGER freeBytesAvailable = {0};
    ULARGE_INTEGER totalBytes         = {0};
    ULARGE_INTEGER totalFreeBytes     = {0};

    if (!GetDiskFreeSpaceExA("C:\\",
                             &freeBytesAvailable,
                             &totalBytes,
                             &totalFreeBytes)) {
        fprintf(stderr, "[g7_05] GetDiskFreeSpaceExA failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }

    ULONGLONG totalDiskGB = totalBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL);
    printf("[g7_05] Total disk capacity (C:) : %llu GB\n", totalDiskGB);

    if (totalDiskGB == 0) {
        fprintf(stderr, "[g7_05] Reported disk capacity is 0 — unexpected.\n");
        return EXIT_FAILURE;
    }

    /* Both values > 0 — write proof */
    write_c1_proof("g7_05_memory_monitor", "SystemMemoryMonitor");
    printf("[g7_05] Memory/disk monitor PASSED. Proof written.\n");
    return EXIT_SUCCESS;
}
