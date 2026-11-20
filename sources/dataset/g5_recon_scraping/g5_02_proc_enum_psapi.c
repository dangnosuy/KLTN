// SAMPLE: g5_02 | ProcEnumPSAPI | Group: Recon & In-Memory Scraping
// Technique: Process Enumeration via PSAPI EnumProcesses
// Compile: x86_64-w64-mingw32-gcc -O2 -o g5_02_proc_enum_psapi.exe g5_02_proc_enum_psapi.c -lpsapi

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

#define MAX_PROCESSES 1024

int main(void) {
    DWORD aProcesses[MAX_PROCESSES];
    DWORD cbNeeded = 0;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        fprintf(stderr, "[g5_02] EnumProcesses failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    // Calculate number of process IDs returned
    int count = (int)(cbNeeded / sizeof(DWORD));

    fprintf(stderr, "[g5_02] Process count (PSAPI): %d\n", count);

    // Verification gate
    if (count <= 0) {
        fprintf(stderr, "[g5_02] No processes returned — aborting proof write\n");
        return EXIT_FAILURE;
    }

    // Encode actual count in technique field
    char technique[64];
    snprintf(technique, sizeof(technique), "ProcEnumPSAPI_N%d", count);

    int rc = write_c1_proof("g5_02_proc_enum_psapi", technique);
    if (rc != 0) {
        fprintf(stderr, "[g5_02] write_c1_proof failed: %d\n", rc);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[g5_02] Proof written — %s\n", technique);
    return EXIT_SUCCESS;
}
