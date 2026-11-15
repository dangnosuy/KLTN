#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/*
   Multi-check Anti-Debugging Routine:
   1. Win32 IsDebuggerPresent API + PEB BeingDebugged
   2. CheckRemoteDebuggerPresent API
   3. NtQueryInformationProcess (ProcessDebugPort = 7, ProcessDebugFlags = 0x1f)
   4. RDTSC CPU cycle delta timing check (detects single-stepping / breakpoints)
   Returns 1 if debugger detected, 0 if environment is clean.
*/
static inline int is_debugger_present_multi(void) {
    // Check 1: Win32 API
    if (IsDebuggerPresent()) return 1;

    // Check 2: Remote Debugger Attached
    BOOL remote_debugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) && remote_debugger) {
        return 1;
    }

    // Check 3: PEB check directly on x64
#if defined(_WIN64)
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    if (peb && peb[2] != 0) { // BeingDebugged offset is 2
        return 1;
    }
    // NtGlobalFlag offset at 0xBC (flag 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
    DWORD *nt_global_flag = (DWORD *)(peb + 0xBC);
    if (nt_global_flag && (*nt_global_flag & 0x70)) {
        return 1;
    }
#endif

    // Check 4: NtQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pfnNtQueryInformationProcess pNtQuery = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pNtQuery) {
            DWORD_PTR debug_port = 0;
            if (pNtQuery(GetCurrentProcess(), 7 /* ProcessDebugPort */, &debug_port, sizeof(debug_port), NULL) == 0) {
                if (debug_port != 0) return 1;
            }
            DWORD debug_flags = 0;
            if (pNtQuery(GetCurrentProcess(), 0x1f /* ProcessDebugFlags */, &debug_flags, sizeof(debug_flags), NULL) == 0) {
                if (debug_flags == 0) return 1; // 0 indicates being debugged (normally 1)
            }
        }
    }

    // Check 5: RDTSC timing check (step over takes millions of cycles)
    unsigned long long t1 = __builtin_ia32_rdtsc();
    Sleep(50);
    unsigned long long t2 = __builtin_ia32_rdtsc();
    // 50ms at typical 3GHz is ~150M cycles. If debugger suspended process, delta is much higher.
    // If running under hyper-slow tracer, flag it.
    if ((t2 - t1) > 2000000000ULL) {
        return 1;
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* ANTI_DEBUG_H */
