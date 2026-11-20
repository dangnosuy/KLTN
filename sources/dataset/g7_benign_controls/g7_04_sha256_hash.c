// SAMPLE: g7_04 | CryptoAPISHA256 | Group: Benign Controls
// Hashes "C1_THESIS_BENCHMARK_INPUT_2024" via Windows CryptAPI (CALG_SHA_256),
// verifies hash length == 32 bytes, formats first 8 bytes as hex, writes proof.

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/c1_proof.h"

#pragma comment(lib, "advapi32.lib")

#define INPUT_STR   "C1_THESIS_BENCHMARK_INPUT_2024"
#define SHA256_LEN  32

int main(void)
{
    HCRYPTPROV hProv   = 0;
    HCRYPTHASH hHash   = 0;

    /* Acquire a crypto context — CRYPT_VERIFYCONTEXT avoids key-container I/O */
    if (!CryptAcquireContextA(&hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "[g7_04] CryptAcquireContextA failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        fprintf(stderr, "[g7_04] CryptCreateHash failed: %lu\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        return EXIT_FAILURE;
    }

    if (!CryptHashData(hHash, (BYTE *)INPUT_STR,
                       (DWORD)strlen(INPUT_STR), 0)) {
        fprintf(stderr, "[g7_04] CryptHashData failed: %lu\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return EXIT_FAILURE;
    }

    BYTE  hashBytes[SHA256_LEN];
    DWORD hashLen = SHA256_LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
        fprintf(stderr, "[g7_04] CryptGetHashParam failed: %lu\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return EXIT_FAILURE;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    /* Verify hash length */
    if (hashLen != SHA256_LEN) {
        fprintf(stderr, "[g7_04] Unexpected hash length %lu (expected %d).\n",
                hashLen, SHA256_LEN);
        return EXIT_FAILURE;
    }

    /* Format first 8 bytes as hex for display */
    char hexBuf[17] = {0};
    for (int i = 0; i < 8; i++) {
        sprintf(hexBuf + i * 2, "%02x", hashBytes[i]);
    }
    printf("[g7_04] SHA-256 first 8 bytes: %s\n", hexBuf);

    /* Hash verified — write proof */
    write_c1_proof("g7_04_sha256_hash", "CryptoAPISHA256");
    printf("[g7_04] SHA-256 benchmark PASSED. Proof written.\n");
    return EXIT_SUCCESS;
}
