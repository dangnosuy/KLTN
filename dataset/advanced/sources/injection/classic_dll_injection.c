#include <windows.h>
#include <stdio.h>

int main() {
    char dllPath[MAX_PATH];
    // Resolve absolute path of payload.dll in current directory
    GetFullPathNameA("payload.dll", MAX_PATH, dllPath, NULL);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return 1;
    }
    Sleep(500);

    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID pRemotePath = VirtualAllocEx(pi.hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, pRemotePath, dllPath, pathLen, NULL)) {
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);
    if (hRemoteThread) {
        WaitForSingleObject(hRemoteThread, 3000);
        CloseHandle(hRemoteThread);
    }

    VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
