#include <windows.h>
#include "c1_marker.h"

static DWORD WINAPI run_canary(LPVOID unused) {
    (void)unused;
    return c1_write_marker() ? 0 : 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        c1_reset_marker();
        HANDLE thread = CreateThread(NULL, 0, run_canary, NULL, 0, NULL);
        if (!thread) return FALSE;
        CloseHandle(thread);
    }
    return TRUE;
}
