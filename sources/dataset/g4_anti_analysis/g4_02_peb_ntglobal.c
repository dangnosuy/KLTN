// SAMPLE: g4_02 | PEB NtGlobalFlag Heap Flag Detection | Group: Anti-Analysis & Memory Evasion
// Technique: Read PEB.NtGlobalFlag at PEB+0xBC (x64). A debugger sets heap debug bits
//            (FLG_HEAP_ENABLE_TAIL_CHECK|FLG_HEAP_ENABLE_FREE_CHECK|FLG_HEAP_VALIDATE_PARAMETERS = 0x70).
//            In a clean VM, NtGlobalFlag & 0x70 == 0 → alternative branch writes proof.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g4_02_peb_ntglobal.exe g4_02_peb_ntglobal.c

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

// NtGlobalFlag sits at PEB offset 0xBC on x64 Windows.
// The winternl.h PEB struct may not expose it directly, so we use a manual offset.
#define PEB_NTGLOBALFLAG_OFFSET 0xBC

// Debugger-set heap flags mask
#define HEAP_DEBUG_FLAGS 0x70U

int main(void)
{
    // Read PEB pointer from GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb == NULL) {
        fprintf(stderr, "[-] Failed to read PEB pointer.\n");
        return EXIT_FAILURE;
    }

    // Read NtGlobalFlag via byte-offset pointer arithmetic
    DWORD ntGlobalFlag = *(DWORD *)((BYTE *)pPeb + PEB_NTGLOBALFLAG_OFFSET);
    fprintf(stderr, "[*] PEB.NtGlobalFlag = 0x%08X\n", ntGlobalFlag);

    if ((ntGlobalFlag & HEAP_DEBUG_FLAGS) != 0) {
        // Heap debug flags set — debugger or analysis tool present; no proof
        fprintf(stderr, "[-] Debugger heap flags detected (NtGlobalFlag=0x%08X). Exiting.\n",
                ntGlobalFlag);
        return EXIT_FAILURE;
    } else {
        // Clean environment — alternative branch writes proof
        fprintf(stderr, "[+] No heap debug flags (NtGlobalFlag=0x%08X). Writing proof.\n",
                ntGlobalFlag);
        if (write_c1_proof("g4_02_peb_ntglobal", "PEBNtGlobalFlag_Clean") != 0) {
            fprintf(stderr, "[-] Failed to write proof.\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
}
