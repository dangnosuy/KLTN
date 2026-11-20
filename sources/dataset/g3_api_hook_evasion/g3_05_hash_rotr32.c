// SAMPLE: g3_05 | PEB Walk + Rotr32 Hash API Resolution | Group: API & Hook Evasion
// Technique: Resolve kernel32 exports by walking PEB->Ldr->InMemoryOrderModuleList,
//            matching export names via Rotr32 (ROR 13) hash comparison.
//            All file I/O for proof uses ONLY the dynamically resolved function pointers.
// Compile:  x86_64-w64-mingw32-gcc -O2 -o g3_05_hash_rotr32.exe g3_05_hash_rotr32.c
//
// Pre-computed Rotr32 target hashes (rotr32_hash("NAME")):
//   CreateFileA             = 0xF5FFE743
//   WriteFile               = 0xD9C2445F
//   CloseHandle             = 0x71F16731
//   GetSystemTimeAsFileTime = 0x4D15DCD5
//   ExitProcess             = 0xEDDD279B
//
// Rotr32 algorithm:
//   rotr32(v, n) = (v >> n) | (v << (32-n))
//   hash = 0; while (*str) hash = rotr32(hash, 13) ^ (unsigned char)*str++;

#include <windows.h>
#include <winternl.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Pre-computed Rotr32 hash constants
// ---------------------------------------------------------------------------
#define HASH_CreateFileA             0xF5FFE743u
#define HASH_WriteFile               0xD9C2445Fu
#define HASH_CloseHandle             0x71F16731u
#define HASH_GetSystemTimeAsFileTime 0x4D15DCD5u
#define HASH_ExitProcess             0xEDDD279Bu

// ---------------------------------------------------------------------------
// Type definitions
// ---------------------------------------------------------------------------
typedef HANDLE (WINAPI *pfnCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pfnWriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pfnCloseHandle_t)(HANDLE);
typedef void   (WINAPI *pfnGetSystemTimeAsFileTime_t)(LPFILETIME);
typedef void   (WINAPI *pfnExitProcess_t)(UINT);

typedef struct {
    pfnCreateFileA_t             pCreateFileA;
    pfnWriteFile_t               pWriteFile;
    pfnCloseHandle_t             pCloseHandle;
    pfnGetSystemTimeAsFileTime_t pGetSystemTimeAsFileTime;
    pfnExitProcess_t             pExitProcess;
} RESOLVED_APIS;

// ---------------------------------------------------------------------------
// No-CRT helpers
// ---------------------------------------------------------------------------
static int manual_strlen(const char *s) {
    int n = 0; while (s[n]) n++; return n;
}

static char *append_str(char *dst, const char *src) {
    while (*src) *dst++ = *src++; return dst;
}

static char *u64_to_dec(uint64_t v, char *buf, int bufsz) {
    buf[bufsz-1] = '\0';
    int i = bufsz-2;
    if (v == 0) { buf[i--] = '0'; }
    else { while (v && i >= 0) { buf[i--] = '0' + (int)(v % 10); v /= 10; } }
    return &buf[i+1];
}

static uint32_t inline_crc32(const char *data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= (unsigned char)data[i];
        for (int b = 0; b < 8; b++) crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return crc ^ 0xFFFFFFFF;
}

static void u32_to_hex(uint32_t v, char out[9]) {
    const char *hex = "0123456789ABCDEF";
    for (int i = 7; i >= 0; i--) { out[i] = hex[v & 0xF]; v >>= 4; }
    out[8] = '\0';
}

// ---------------------------------------------------------------------------
// Rotr32 hash functions
// ---------------------------------------------------------------------------
static inline uint32_t rotr32(uint32_t v, int n) {
    return (v >> n) | (v << (32 - n));
}

static uint32_t rotr32_hash(const char *str) {
    uint32_t hash = 0;
    while (*str) {
        hash = rotr32(hash, 13) ^ (uint32_t)(unsigned char)*str++;
    }
    return hash;
}

// ---------------------------------------------------------------------------
// PEB walk
// ---------------------------------------------------------------------------
static PVOID get_module_base_from_peb(const wchar_t *target_name) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHead  = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pMod->FullDllName.Buffer) {
            WCHAR *name = pMod->FullDllName.Buffer;
            int len = pMod->FullDllName.Length / 2;
            int start = 0;
            for (int i = len-1; i >= 0; i--) {
                if (name[i] == L'\\' || name[i] == L'/') { start = i+1; break; }
            }
            int tlen = 0; while (target_name[tlen]) tlen++;
            int match = (len - start == tlen);
            for (int i = 0; i < tlen && match; i++) {
                wchar_t a = name[start+i]; if (a >= L'A' && a <= L'Z') a += 32;
                wchar_t b = target_name[i]; if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) match = 0;
            }
            if (match) return pMod->DllBase;
        }
        pEntry = pEntry->Flink;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Export resolution by Rotr32 hash
// ---------------------------------------------------------------------------
static PVOID resolve_export_by_hash(PVOID base, uint32_t target_hash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)base + pDos->e_lfanew);
    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + expRVA);
    DWORD *pNames    = (DWORD*)((BYTE*)base + pExp->AddressOfNames);
    WORD  *pOrdinals = (WORD*) ((BYTE*)base + pExp->AddressOfNameOrdinals);
    DWORD *pFuncs    = (DWORD*)((BYTE*)base + pExp->AddressOfFunctions);
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)base + pNames[i]);
        if (rotr32_hash(name) == target_hash) {
            return (PVOID)((BYTE*)base + pFuncs[pOrdinals[i]]);
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Write proof via resolved pointers only
// ---------------------------------------------------------------------------
static void write_proof_via_resolved(const RESOLVED_APIS *api,
                                      const char *sample_id,
                                      const char *technique) {
    FILETIME ft = {0};
    if (api->pGetSystemTimeAsFileTime) api->pGetSystemTimeAsFileTime(&ft);
    uint64_t ts = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    char ts_str[24]; char *ts_p = u64_to_dec(ts, ts_str, sizeof(ts_str));

    char pre[256]; char *p = pre;
    p = append_str(p, sample_id); *p++ = '|';
    p = append_str(p, technique); *p++ = '|';
    p = append_str(p, ts_p); *p = '\0';

    uint32_t csum = inline_crc32(pre, manual_strlen(pre));
    char hex_csum[9]; u32_to_hex(csum, hex_csum);

    char buf[512]; char *bp = buf;
    bp = append_str(bp, pre); *bp++ = '|';
    bp = append_str(bp, hex_csum); *bp++ = '\n'; *bp = '\0';

    HANDLE hF = api->pCreateFileA(
        "C:\\C1_Sandbox\\c1_proof.txt",
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    api->pWriteFile(hF, buf, (DWORD)(bp - buf), &written, NULL);
    api->pCloseHandle(hF);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void) {
    PVOID k32base = get_module_base_from_peb(L"kernel32.dll");
    if (!k32base) return 1;

    RESOLVED_APIS api = {0};
    api.pCreateFileA             = (pfnCreateFileA_t)            resolve_export_by_hash(k32base, HASH_CreateFileA);
    api.pWriteFile               = (pfnWriteFile_t)              resolve_export_by_hash(k32base, HASH_WriteFile);
    api.pCloseHandle             = (pfnCloseHandle_t)            resolve_export_by_hash(k32base, HASH_CloseHandle);
    api.pGetSystemTimeAsFileTime = (pfnGetSystemTimeAsFileTime_t)resolve_export_by_hash(k32base, HASH_GetSystemTimeAsFileTime);
    api.pExitProcess             = (pfnExitProcess_t)            resolve_export_by_hash(k32base, HASH_ExitProcess);

    if (!api.pCreateFileA || !api.pWriteFile || !api.pCloseHandle) return 1;

    write_proof_via_resolved(&api, "g3_05_hash_rotr32", "PEBWalkRotr32HashResolution");

    if (api.pExitProcess) api.pExitProcess(0);
    return 0;
}
