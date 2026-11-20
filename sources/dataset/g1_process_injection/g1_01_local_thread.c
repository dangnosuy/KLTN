// SAMPLE: g1_01 | Classic Local Thread Injection | Group: Process Injection
//
// Description:
//   Allocates an executable RWX memory buffer via VirtualAlloc in the local process,
//   copies position-independent x64 machine code into the allocated page,
//   and executes it via CreateThread.
//
// C1 Verification Rule:
//   Proof file MUST be written by the injected execution context running from
//   the VirtualAlloc'd RWX memory region — NOT directly by main().
//
// Compile (MinGW-w64):
//   x86_64-w64-mingw32-gcc -O2 -o g1_01_local_thread.exe g1_01_local_thread.c

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define SAMPLE_ID      "g1_01_local_thread"
#define TECHNIQUE_NAME "LocalThreadInjection"

// Payload execution context passed to the injected thread
typedef struct _INJECT_CONTEXT {
    int (*pfnWriteProof)(const char *, const char *);
    char sample_id[64];
    char technique[64];
    volatile LONG status;
} INJECT_CONTEXT;

/*
 * Pure x64 machine code stub executed inside the allocated RWX memory region:
 *
 * RCX points to INJECT_CONTEXT.
 * Stub calls pfnWriteProof(sample_id, technique), saves status, and returns 0.
 *
 * Disassembly:
 *   sub rsp, 0x28                     ; 48 83 EC 28
 *   mov rbx, rcx                      ; 48 89 CB
 *   mov rax, [rbx]                    ; 48 8B 03 (pfnWriteProof)
 *   lea rcx, [rbx + 0x08]             ; 48 8D 4B 08 (sample_id)
 *   lea rdx, [rbx + 0x48]             ; 48 8D 53 48 (technique)
 *   call rax                          ; FF D0
 *   mov dword ptr [rbx + 0x88], eax   ; 89 83 88 00 00 00 (status)
 *   add rsp, 0x28                     ; 48 83 C4 28
 *   xor eax, eax                      ; 31 C0
 *   ret                               ; C3
 */
static const unsigned char g_StubX64[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0x89, 0xCB,
    0x48, 0x8B, 0x03,
    0x48, 0x8D, 0x4B, 0x08,
    0x48, 0x8D, 0x53, 0x48,
    0xFF, 0xD0,
    0x89, 0x83, 0x88, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x28,
    0x31, 0xC0,
    0xC3
};

int main(void)
{
    printf("[*] Starting %s (%s)...\n", SAMPLE_ID, TECHNIQUE_NAME);

    // 1. Allocate RWX page in current process
    SIZE_T stubSize = sizeof(g_StubX64);
    LPVOID pAlloc = VirtualAlloc(
        NULL,
        stubSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pAlloc) {
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[+] Allocated RWX region at: 0x%p\n", pAlloc);

    // 2. Copy machine code payload into allocated region
    memcpy(pAlloc, g_StubX64, stubSize);

    // 3. Prepare injection context
    INJECT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pfnWriteProof = write_c1_proof;
    strncpy(ctx.sample_id, SAMPLE_ID, sizeof(ctx.sample_id) - 1);
    strncpy(ctx.technique, TECHNIQUE_NAME, sizeof(ctx.technique) - 1);
    ctx.status = -1;

    // Flush instruction cache for execution safety
    FlushInstructionCache(GetCurrentProcess(), pAlloc, stubSize);

    // 4. Create thread pointing to the allocated RWX buffer
    DWORD threadId = 0;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pAlloc,
        &ctx,
        0,
        &threadId
    );
    if (!hThread) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(pAlloc, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }
    printf("[+] Thread %lu created executing code at 0x%p\n", threadId, pAlloc);

    // 5. Wait for payload execution
    DWORD waitResult = WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    if (waitResult != WAIT_OBJECT_0) {
        fprintf(stderr, "[-] Thread timed out or failed to execute.\n");
        VirtualFree(pAlloc, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    // 6. Verify payload completion
    if (ctx.status != 0) {
        fprintf(stderr, "[-] Injected payload reported failure: status = %ld\n", ctx.status);
        VirtualFree(pAlloc, 0, MEM_RELEASE);
        return EXIT_FAILURE;
    }

    VirtualFree(pAlloc, 0, MEM_RELEASE);
    printf("[+] Local thread injection completed successfully. Proof written by payload.\n");
    return EXIT_SUCCESS;
}
