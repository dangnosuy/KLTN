// SAMPLE: g5_04 | SysInfoRecon | Group: Recon & In-Memory Scraping
// Technique: System Architecture & Processor Recon via GetNativeSystemInfo
// Compile: x86_64-w64-mingw32-gcc -O2 -o g5_04_sysinfo_recon.exe g5_04_sysinfo_recon.c

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/c1_proof.h"

static const char *arch_name(WORD arch) {
    switch (arch) {
        case PROCESSOR_ARCHITECTURE_AMD64:   return "x64";
        case PROCESSOR_ARCHITECTURE_INTEL:   return "x86";
        case PROCESSOR_ARCHITECTURE_ARM:     return "ARM";
        case PROCESSOR_ARCHITECTURE_ARM64:   return "ARM64";
        case PROCESSOR_ARCHITECTURE_IA64:    return "IA64";
        default:                             return "Unknown";
    }
}

int main(void) {
    // --- GetNativeSystemInfo ---
    SYSTEM_INFO si;
    memset(&si, 0, sizeof(si));
    GetNativeSystemInfo(&si);

    fprintf(stderr, "[g5_04] Arch: %s | Processors: %lu | PageSize: %lu\n",
            arch_name(si.wProcessorArchitecture),
            (unsigned long)si.dwNumberOfProcessors,
            (unsigned long)si.dwPageSize);

    // Verification gate
    if (si.dwNumberOfProcessors == 0) {
        fprintf(stderr, "[g5_04] dwNumberOfProcessors is 0 — aborting proof write\n");
        return EXIT_FAILURE;
    }

    // --- Recon flavor: ComputerName & UserName ---
    char compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compLen = sizeof(compName);
    if (!GetComputerNameA(compName, &compLen)) {
        fprintf(stderr, "[g5_04] GetComputerNameA failed: %lu\n", GetLastError());
        // Non-fatal — just for recon flavor
        strncpy(compName, "unknown", sizeof(compName) - 1);
    }

    char userName[256] = {0};
    DWORD userLen = sizeof(userName);
    if (!GetUserNameA(userName, &userLen)) {
        fprintf(stderr, "[g5_04] GetUserNameA failed: %lu\n", GetLastError());
        strncpy(userName, "unknown", sizeof(userName) - 1);
    }

    fprintf(stderr, "[g5_04] ComputerName: %s | UserName: %s\n", compName, userName);

    // Build technique string encoding key facts
    char technique[128];
    snprintf(technique, sizeof(technique), "SysInfoRecon_%sCPU%lu",
             arch_name(si.wProcessorArchitecture),
             (unsigned long)si.dwNumberOfProcessors);

    int rc = write_c1_proof("g5_04_sysinfo_recon", technique);
    if (rc != 0) {
        fprintf(stderr, "[g5_04] write_c1_proof failed: %d\n", rc);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[g5_04] Proof written — %s\n", technique);
    return EXIT_SUCCESS;
}
