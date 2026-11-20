// SAMPLE: g7_01 | FileCRUDOperations | Group: Benign Controls
// Performs Create/Write/Read/Delete on a temp file and verifies byte-for-byte
// correctness before writing the C1 proof signature.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/c1_proof.h"

#define TEMP_FILE   "C:\\C1_Sandbox\\bench_temp.txt"
#define CONTENT     "C1_FILE_CRUD_BENCHMARK_VERIFY_2024"
#define CONTENT_LEN (sizeof(CONTENT) - 1)   /* exclude NUL */

int main(void)
{
    /* ---- CREATE / WRITE ---- */
    HANDLE hFile = CreateFileA(
        TEMP_FILE,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[g7_01] CreateFileA(write) failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    DWORD written = 0;
    if (!WriteFile(hFile, CONTENT, (DWORD)CONTENT_LEN, &written, NULL) ||
        written != (DWORD)CONTENT_LEN) {
        fprintf(stderr, "[g7_01] WriteFile failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }
    CloseHandle(hFile);

    /* ---- READ BACK ---- */
    hFile = CreateFileA(
        TEMP_FILE,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[g7_01] CreateFileA(read) failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    char readBuf[128] = {0};
    DWORD readBytes = 0;
    if (!ReadFile(hFile, readBuf, (DWORD)CONTENT_LEN, &readBytes, NULL)) {
        fprintf(stderr, "[g7_01] ReadFile failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }
    CloseHandle(hFile);

    /* ---- VERIFY byte-for-byte ---- */
    if (readBytes != (DWORD)CONTENT_LEN ||
        memcmp(readBuf, CONTENT, CONTENT_LEN) != 0) {
        fprintf(stderr, "[g7_01] Content mismatch after read-back.\n");
        return EXIT_FAILURE;
    }

    /* ---- DELETE ---- */
    if (!DeleteFileA(TEMP_FILE)) {
        fprintf(stderr, "[g7_01] DeleteFileA failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    /* All 4 ops succeeded — write proof */
    write_c1_proof("g7_01_file_crud", "FileCRUDOperations");
    printf("[g7_01] File CRUD benchmark PASSED. Proof written.\n");
    return EXIT_SUCCESS;
}
