#include <windows.h>
#include "../common/c1_marker.h"
#include "../common/c1_return_payload.h"

int main(void) {
    HMODULE module = LoadLibraryA("rwx_module.dll");
    if (!module) return 1;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 1;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 1;

    void* target = NULL;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD required = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
        SIZE_T size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        if ((section->Characteristics & required) == required && size >= payload_len) {
            target = (BYTE*)module + section->VirtualAddress;
            break;
        }
    }
    if (!target) return 1;

    c1_reset_marker();
    memcpy(target, payload, payload_len);
    FlushInstructionCache(GetCurrentProcess(), target, payload_len);

    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)target, NULL, 0, NULL);
    if (!thread) return 1;
    if (WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0) {
        CloseHandle(thread);
        return 1;
    }
    CloseHandle(thread);
    return c1_write_marker() && c1_marker_passed() ? 0 : 1;
}
