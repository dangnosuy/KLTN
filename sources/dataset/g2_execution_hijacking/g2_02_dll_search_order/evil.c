// SAMPLE: g2_02 | DLL Search Order Hijacking | Group: Execution Hijacking
//
// evil.c — Malicious DLL placed in the DLL search path (CWD).
//   When injector.exe calls LoadLibraryA("evil_version2.dll") with a
//   relative path, Windows DLL search order causes this DLL to be loaded
//   instead of any legitimate version2.dll.
//
// C1 RULE: Proof is written inside DllMain (the HIJACKED EXECUTION PATH).
//          It is NOT written by the injector/main process.
//
// Compile: x86_64-w64-mingw32-gcc -shared -o evil_version2.dll evil.c

#include "../../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hInst;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        /*
         * Hijacked execution path:
         * We are running because injector.exe's LoadLibraryA("evil_version2.dll")
         * resolved to US via DLL search order — the CWD was searched and we
         * were found before any legitimate DLL.
         *
         * Write C1 proof from HERE (the hijacked path), not from the injector.
         */
        int rc = write_c1_proof("g2_02_dll_search_order", "DLLSearchOrderHijack");
        if (rc != 0) {
            /* Best-effort: can't use stderr reliably in DllMain */
            OutputDebugStringA("[evil_version2.dll] write_c1_proof FAILED\n");
        }
    }
    return TRUE;
}
