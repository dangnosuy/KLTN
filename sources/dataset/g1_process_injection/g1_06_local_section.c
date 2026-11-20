// SAMPLE: g1_06 | Local Section Execution | Group: Process Injection
//
// Description:
//   Creates an in-memory file mapping section via CreateFileMappingA with PAGE_EXECUTE_READWRITE,
//   maps a view into the current process with FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
//   copies the execution stub into the mapped section view, and invokes it via CreateThread.
//
// C1 Verification Rule:
//   Proof file MUST be written by the code executing within the mapped section view.
//
// Compile (MinGW-w64):
//   x86_64-w64-mingw32-gcc -O2 -o g1_06_local_section.exe g1_06_local_section.c

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define SAMPLE_ID      "g1_06_local_section"
#define TECHNIQUE_NAME "LocalSectionExecution"

typedef struct _INJECT_CONTEXT {
    int (*pfnWriteProof)(const char *, const char *);
    char sample_id[64];
    char technique[64];
    volatile LONG status;
} INJECT_CONTEXT;

/*
 * x64 machine code stub executed inside the mapped section view.
 * RCX points to INJECT_CONTEXT. Calls pfnWriteProof and saves status.
 */
static const unsigned char g_StubX64[] = {
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
    0x48, 0x89, 0xCB,                   // mov rbx, rcx
    0x48, 0x8B, 0x03,                   // mov rax, [rbx]
    0x48, 0x8D, 0x4B, 0x08,             // lea rcx, [rbx + 0x08]
    0x48, 0x8D, 0x53, 0x48,             // lea rdx, [rbx + 0x48]
    0xFF, 0xD0,                         // call rax
    0x89, 0x83, 0x88, 0x00, 0x00, 0x00, // mov [rbx + 0x88], eax
    0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
    0x31, 0xC0,                         // xor eax, eax
    0xC3                                // ret
};

int main(void)
{
    printf("[*] Starting %s (%s)...\n", SAMPLE_ID, TECHNIQUE_NAME);

    // 1. Create backing section object in pagefile
    const SIZE_T sectionSize = 4096;
    HANDLE hMap = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_EXECUTE_READWRITE,
        0,
        (DWORD)sectionSize,
        NULL
    );
    if (!hMap) {
        fprintf(stderr, "[-] CreateFileMappingA failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[+] Created file mapping section handle: %p\n", hMap);

    // 2. Map view of section with execute permissions
    LPVOID pView = MapViewOfFile(
        hMap,
        FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
        0,
        0,
        sectionSize
    );
    if (!pView) {
        fprintf(stderr, "[-] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hMap);
        return EXIT_FAILURE;
    }
    printf("[+] Mapped section view at: 0x%p\n", pView);

    // 3. Copy machine code payload into mapped section view
    memcpy(pView, g_StubX64, sizeof(g_StubX64));

    // 4. Setup parameter context
    INJECT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pfnWriteProof = write_c1_proof;
    strncpy(ctx.sample_id, SAMPLE_ID, sizeof(ctx.sample_id) - 1);
    strncpy(ctx.technique, TECHNIQUE_NAME, sizeof(ctx.technique) - 1);
    ctx.status = -1;

    FlushInstructionCache(GetCurrentProcess(), pView, sizeof(g_StubX64));

    // 5. Create thread executing inside the mapped section view
    DWORD threadId = 0;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pView,
        &ctx,
        0,
        &threadId
    );
    if (!hThread) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        UnmapViewOfFile(pView);
        CloseHandle(hMap);
        return EXIT_FAILURE;
    }
    printf("[+] Thread %lu running inside section view at 0x%p\n", threadId, pView);

    // 6. Wait for payload execution
    DWORD waitResult = WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    if (waitResult != WAIT_OBJECT_0) {
        fprintf(stderr, "[-] Section thread timed out.\n");
        UnmapViewOfFile(pView);
        CloseHandle(hMap);
        return EXIT_FAILURE;
    }

    if (ctx.status != 0) {
        fprintf(stderr, "[-] Injected section payload reported failure: %ld\n", ctx.status);
        UnmapViewOfFile(pView);
        CloseHandle(hMap);
        return EXIT_FAILURE;
    }

    // 7. Cleanup
    UnmapViewOfFile(pView);
    CloseHandle(hMap);

    printf("[+] Local section injection executed successfully. Proof verified.\n");
    return EXIT_SUCCESS;
}
