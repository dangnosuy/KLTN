/*
 * c1_proof.h — Shared C1 Verification Proof Writer
 *
 * Thesis: Adaptive Program Transformation for Robustness Evaluation
 *         of Malware Detection Systems
 *
 * PURPOSE:
 *   Every dataset sample writes a proof file to demonstrate its core
 *   behavior has executed successfully. The verifier (Zone 2) reads
 *   this file to classify the run as PASSED_TEST.
 *
 * FORMAT:  SAMPLE_ID|TECHNIQUE|TIMESTAMP|CHECKSUM
 * EXAMPLE: g1_01_local_thread|LocalThreadInjection|1700000125|a3f2b1c4
 *
 * CHECKSUM: CRC32 of (SAMPLE_ID + "|" + decimal_timestamp_string)
 *
 * NOTE: Group 6 (C2) samples do NOT call write_c1_proof() directly.
 *       The mock C2 server generates and sends the full proof string;
 *       the client just fwrite()s the response buffer to c1_proof.txt.
 */

#ifndef C1_PROOF_H
#define C1_PROOF_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Default proof file path — override by defining C1_PROOF_PATH before including */
#ifndef C1_PROOF_PATH
#define C1_PROOF_PATH "C:\\C1_Sandbox\\c1_proof.txt"
#endif

/* ── CRC32 implementation (lookup-table, standard poly 0xEDB88320) ── */
static uint32_t c1_crc32_table[256];
static int c1_crc32_table_ready = 0;

static void c1_build_crc32_table(void) {
    if (c1_crc32_table_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
        c1_crc32_table[i] = crc;
    }
    c1_crc32_table_ready = 1;
}

static uint32_t c1_crc32(const char *data, size_t len) {
    c1_build_crc32_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = c1_crc32_table[(crc ^ (unsigned char)data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/*
 * write_c1_proof()
 *   sample_id  : e.g. "g1_01_local_thread"
 *   technique  : e.g. "LocalThreadInjection"
 *
 * MUST be called from the injected payload / hijacked path / resolved
 * function pointer — NOT from the main injector/host process.
 * (Except Group 4: called from alternative branch; Group 5: called after
 * collecting real recon data; Group 7: called after algorithm completes.)
 */
static inline int write_c1_proof(const char *sample_id, const char *technique) {
    /* 1. Get current UNIX timestamp */
    SYSTEMTIME st;
    FILETIME   ft;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    /* Convert Windows FILETIME (100ns since 1601-01-01) to UNIX epoch */
    uint64_t wt = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t unix_ts = (wt - 116444736000000000ULL) / 10000000ULL;

    /* 2. Build checksum input: "SAMPLE_ID|TIMESTAMP_DECIMAL" */
    char chk_input[256];
    snprintf(chk_input, sizeof(chk_input), "%s|%llu", sample_id, (unsigned long long)unix_ts);
    uint32_t checksum = c1_crc32(chk_input, strlen(chk_input));

    /* 3. Format proof line */
    char proof_line[512];
    int  proof_len = snprintf(proof_line, sizeof(proof_line),
                              "%s|%s|%llu|%08x\n",
                              sample_id, technique,
                              (unsigned long long)unix_ts, checksum);

    /* 4. Write to proof file (overwrite) */
    HANDLE hFile = CreateFileA(
        C1_PROOF_PATH,
        GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    DWORD written = 0;
    BOOL  ok = WriteFile(hFile, proof_line, (DWORD)proof_len, &written, NULL);
    CloseHandle(hFile);
    return (ok && written == (DWORD)proof_len) ? 0 : -2;
}

#endif /* C1_PROOF_H */
