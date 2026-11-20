// SAMPLE: g5_01 | ProcEnumTH32 | Group: Recon & In-Memory Scraping
// Technique: Process Enumeration via CreateToolhelp32Snapshot
// Compile: x86_64-w64-mingw32-gcc -O2 -o g5_01_proc_enum_th32.exe g5_01_proc_enum_th32.c

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/c1_proof.h"

#define MAX_PROC_NAMES 1024
#define NAME_BUF_SZ    MAX_PATH

int main(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[g5_01] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &pe)) {
        fprintf(stderr, "[g5_01] Process32First failed: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return EXIT_FAILURE;
    }

    // Collect process names into a stack buffer
    char  names[MAX_PROC_NAMES][NAME_BUF_SZ];
    int   count = 0;

    do {
        if (count < MAX_PROC_NAMES) {
            strncpy(names[count], pe.szExeFile, NAME_BUF_SZ - 1);
            names[count][NAME_BUF_SZ - 1] = '\0';
        }
        count++;
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);

    fprintf(stderr, "[g5_01] Process count: %d\n", count);

    // Verification gate: must have at least one process
    if (count <= 0) {
        fprintf(stderr, "[g5_01] No processes found — aborting proof write\n");
        return EXIT_FAILURE;
    }

    // Encode actual count in technique field
    char technique[64];
    snprintf(technique, sizeof(technique), "ProcEnumTH32_N%d", count);

    int rc = write_c1_proof("g5_01_proc_enum_th32", technique);
    if (rc != 0) {
        fprintf(stderr, "[g5_01] write_c1_proof failed: %d\n", rc);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[g5_01] Proof written — %s\n", technique);
    return EXIT_SUCCESS;
}
