#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../common/c1_marker.h"
#include "../common/embedded_dll.h"

typedef BOOL(WINAPI *pfn_dll_main)(HINSTANCE, DWORD, LPVOID);

static BOOL raw_range_valid(SIZE_T offset, SIZE_T size) {
    return offset <= embedded_dll_len && size <= embedded_dll_len - offset;
}

static BOOL image_range_valid(const IMAGE_OPTIONAL_HEADER64* optional, DWORD rva, SIZE_T size) {
    return rva <= optional->SizeOfImage && size <= optional->SizeOfImage - rva;
}

static DWORD section_protection(DWORD characteristics) {
    const BOOL executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const BOOL writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    const BOOL readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;

    if (executable && writable) return PAGE_EXECUTE_READWRITE;
    if (executable && readable) return PAGE_EXECUTE_READ;
    if (executable) return PAGE_EXECUTE;
    if (writable) return PAGE_READWRITE;
    if (readable) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

int main(void) {
    BYTE* raw = (BYTE*)embedded_dll;
    BYTE* image = NULL;
    int exit_code = 1;

    if (!raw_range_valid(0, sizeof(IMAGE_DOS_HEADER))) return exit_code;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return exit_code;
    if (!raw_range_valid((SIZE_T)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64))) return exit_code;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return exit_code;
    if (!nt->OptionalHeader.SizeOfImage || !raw_range_valid(0, nt->OptionalHeader.SizeOfHeaders)) return exit_code;

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    SIZE_T section_offset = (SIZE_T)((BYTE*)sections - raw);
    SIZE_T section_bytes = (SIZE_T)nt->FileHeader.NumberOfSections * sizeof(*sections);
    if (!raw_range_valid(section_offset, section_bytes)) return exit_code;

    image = (BYTE*)VirtualAlloc(
        (LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    const IMAGE_DATA_DIRECTORY reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!image && reloc_dir.Size) {
        image = (BYTE*)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!image) return exit_code;

    memcpy(image, raw, nt->OptionalHeader.SizeOfHeaders);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &sections[i];
        SIZE_T section_size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        if (!image_range_valid(&nt->OptionalHeader, section->VirtualAddress, section_size) ||
            !raw_range_valid(section->PointerToRawData, section->SizeOfRawData)) {
            goto cleanup;
        }
        if (section->SizeOfRawData) {
            memcpy(image + section->VirtualAddress, raw + section->PointerToRawData, section->SizeOfRawData);
        }
    }

    LONGLONG delta = (LONGLONG)(image - (BYTE*)(ULONG_PTR)nt->OptionalHeader.ImageBase);
    if (delta) {
        if (!reloc_dir.Size || !image_range_valid(&nt->OptionalHeader, reloc_dir.VirtualAddress, reloc_dir.Size)) {
            goto cleanup;
        }
        SIZE_T consumed = 0;
        while (consumed < reloc_dir.Size) {
            if (reloc_dir.Size - consumed < sizeof(IMAGE_BASE_RELOCATION)) goto cleanup;
            PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(image + reloc_dir.VirtualAddress + consumed);
            if (block->SizeOfBlock < sizeof(*block) || block->SizeOfBlock > reloc_dir.Size - consumed) goto cleanup;

            DWORD count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
            WORD* entries = (WORD*)((BYTE*)block + sizeof(*block));
            for (DWORD i = 0; i < count; i++) {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0x0fff;
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                if (type != IMAGE_REL_BASED_DIR64 || !image_range_valid(&nt->OptionalHeader, block->VirtualAddress + offset, sizeof(ULONGLONG))) {
                    goto cleanup;
                }
                *(ULONGLONG*)(image + block->VirtualAddress + offset) += delta;
            }
            consumed += block->SizeOfBlock;
        }
    }

    const IMAGE_DATA_DIRECTORY import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size) {
        if (!image_range_valid(&nt->OptionalHeader, import_dir.VirtualAddress, import_dir.Size)) goto cleanup;
        for (SIZE_T offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= import_dir.Size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            PIMAGE_IMPORT_DESCRIPTOR descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(image + import_dir.VirtualAddress + offset);
            if (!descriptor->Name) break;
            if (!image_range_valid(&nt->OptionalHeader, descriptor->Name, 1) ||
                !image_range_valid(&nt->OptionalHeader, descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA64))) {
                goto cleanup;
            }
            HMODULE module = LoadLibraryA((LPCSTR)(image + descriptor->Name));
            if (!module) goto cleanup;

            DWORD source_rva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
            for (SIZE_T i = 0; image_range_valid(&nt->OptionalHeader, source_rva + (DWORD)(i * sizeof(IMAGE_THUNK_DATA64)), sizeof(IMAGE_THUNK_DATA64)); i++) {
                PIMAGE_THUNK_DATA64 source = (PIMAGE_THUNK_DATA64)(image + source_rva + i * sizeof(*source));
                PIMAGE_THUNK_DATA64 target = (PIMAGE_THUNK_DATA64)(image + descriptor->FirstThunk + i * sizeof(*target));
                if (!source->u1.AddressOfData) break;

                FARPROC resolved = NULL;
                if (IMAGE_SNAP_BY_ORDINAL64(source->u1.Ordinal)) {
                    resolved = GetProcAddress(module, (LPCSTR)IMAGE_ORDINAL64(source->u1.Ordinal));
                } else if (image_range_valid(&nt->OptionalHeader, (DWORD)source->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(image + source->u1.AddressOfData);
                    resolved = GetProcAddress(module, (LPCSTR)by_name->Name);
                }
                if (!resolved) goto cleanup;
                target->u1.Function = (ULONGLONG)(ULONG_PTR)resolved;
            }
        }
    }

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) goto cleanup;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &sections[i];
        SIZE_T section_size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        DWORD previous = 0;
        if (section_size && !VirtualProtect(image + section->VirtualAddress, section_size, section_protection(section->Characteristics), &previous)) {
            goto cleanup;
        }
    }
    DWORD previous = 0;
    if (!VirtualProtect(image, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &previous)) goto cleanup;
    FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage);

#if defined(_WIN64)
    const IMAGE_DATA_DIRECTORY exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size) {
        if (!image_range_valid(&nt->OptionalHeader, exception_dir.VirtualAddress, exception_dir.Size) ||
            !RtlAddFunctionTable((PRUNTIME_FUNCTION)(image + exception_dir.VirtualAddress),
                                 exception_dir.Size / sizeof(RUNTIME_FUNCTION),
                                 (DWORD64)(ULONG_PTR)image)) {
            goto cleanup;
        }
    }
#endif

    if (!nt->OptionalHeader.AddressOfEntryPoint ||
        !image_range_valid(&nt->OptionalHeader, nt->OptionalHeader.AddressOfEntryPoint, 1)) {
        goto cleanup;
    }
    c1_reset_marker();
    pfn_dll_main entry = (pfn_dll_main)(image + nt->OptionalHeader.AddressOfEntryPoint);
    if (!entry((HINSTANCE)image, DLL_PROCESS_ATTACH, NULL)) goto cleanup;
    for (DWORD waited = 0; waited < 10000 && !c1_marker_passed(); waited += 100) Sleep(100);
    if (!c1_marker_passed()) goto cleanup;

    exit_code = 0;

cleanup:
    if (exit_code && image) VirtualFree(image, 0, MEM_RELEASE);
    return exit_code;
}
