// SAMPLE: g4_01 | PEB BeingDebugged Flag Detection | Group: Anti-Analysis & Memory Evasion
// Technique: Read PEB.BeingDebugged via GS segment register (__readgsqword(0x60)).
//            In a clean VM (no debugger attached), BeingDebugged == 0 → alternative branch
//            writes proof. Under a debugger, BeingDebugged != 0 → no proof written.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g4_01_peb_debugger.exe g4_01_peb_debugger.c
// Note: Requires Windows x64; uses GS-segment intrinsic (MSVC + MinGW-w64 both support it).

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

int main(void)
{
    // Read PEB pointer from GS:[0x60] (x64 TEB layout)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb == NULL) {
        fprintf(stderr, "[-] Failed to read PEB pointer.\n");
        return EXIT_FAILURE;
    }

    BYTE beingDebugged = pPeb->BeingDebugged;
    fprintf(stderr, "[*] PEB.BeingDebugged = 0x%02X\n", (unsigned int)beingDebugged);

    if (beingDebugged != 0) {
        // Debugger detected — hostile environment; do NOT write proof
        fprintf(stderr, "[-] Debugger detected via PEB.BeingDebugged. Exiting.\n");
        return EXIT_FAILURE;
    } else {
        // Clean environment — alternative (evasion-success) branch writes proof
        fprintf(stderr, "[+] No debugger detected (PEB.BeingDebugged=0). Writing proof.\n");
        if (write_c1_proof("g4_01_peb_debugger", "PEBBeingDebugged_Clean") != 0) {
            fprintf(stderr, "[-] Failed to write proof.\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
}
