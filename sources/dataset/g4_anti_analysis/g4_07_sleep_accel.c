// SAMPLE: g4_07 | Sandbox Sleep Acceleration Detection | Group: Anti-Analysis & Memory Evasion
// Technique: Sandboxes often fast-forward Sleep() calls to avoid long waits during analysis.
//            Measure wall-clock time before and after Sleep(1000) using GetTickCount64().
//            If elapsed < 500 ms, sleep was accelerated → sandbox likely → no proof.
//            In a clean VM / bare metal, elapsed ≥ 500 ms → alternative branch writes proof.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g4_07_sleep_accel.exe g4_07_sleep_accel.c

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

// If the OS returns in less than this many ms, sleep was accelerated
#define SLEEP_DURATION_MS       1000UL
#define SLEEP_MIN_EXPECTED_MS   500ULL

int main(void)
{
    ULONGLONG t1, t2, elapsed;

    t1 = GetTickCount64();
    Sleep(SLEEP_DURATION_MS);
    t2 = GetTickCount64();

    elapsed = (t2 >= t1) ? (t2 - t1) : 0ULL;
    fprintf(stderr, "[*] Sleep(%lu) elapsed: %llu ms\n",
            SLEEP_DURATION_MS, (unsigned long long)elapsed);

    if (elapsed < SLEEP_MIN_EXPECTED_MS) {
        // Sleep was accelerated — sandbox environment; do NOT write proof
        fprintf(stderr,
                "[-] Sleep acceleration detected (elapsed=%llums < %llums). Sandbox likely.\n",
                (unsigned long long)elapsed,
                (unsigned long long)SLEEP_MIN_EXPECTED_MS);
        return EXIT_FAILURE;
    } else {
        // Sleep ran at real-time speed — alternative (clean) branch writes proof
        fprintf(stderr, "[+] Sleep timing normal (%llums). Writing proof.\n",
                (unsigned long long)elapsed);
        if (write_c1_proof("g4_07_sleep_accel", "SleepAccelCheck_Clean") != 0) {
            fprintf(stderr, "[-] Failed to write proof.\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
}
