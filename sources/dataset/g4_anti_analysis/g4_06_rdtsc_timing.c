// SAMPLE: g4_06 | RDTSC CPU Cycle Delta Detection | Group: Anti-Analysis & Memory Evasion
// Technique: Issue two __rdtsc() reads around a trivial loop. In a clean VM the delta is small
//            (normal instruction throughput). Under a debugger or sandbox that single-steps or
//            instruments every instruction, the delta balloons. Threshold: > 10,000,000 cycles
//            is treated as suspicious. In clean VM delta is small → writes proof.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g4_06_rdtsc_timing.exe g4_06_rdtsc_timing.c

#include <windows.h>
#include <intrin.h>   /* __rdtsc() */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

// Cycles above this threshold indicate debugger single-stepping or sandbox instrumentation
#define RDTSC_SUSPICIOUS_THRESHOLD 10000000ULL

int main(void)
{
    uint64_t t1, t2, delta;
    volatile int x = 0;
    int i;

    t1 = __rdtsc();

    // Trivial work: simple accumulation loop — fast on native, slow under heavy instrumentation
    for (i = 0; i < 100; i++) {
        x += i;
    }

    t2 = __rdtsc();
    (void)x;  /* suppress unused-variable warning */

    // Guard against counter wrap (very unlikely but defensive)
    delta = (t2 >= t1) ? (t2 - t1) : (UINT64_MAX - t1 + t2 + 1);

    fprintf(stderr, "[*] RDTSC delta: %llu cycles\n", (unsigned long long)delta);

    if (delta > RDTSC_SUSPICIOUS_THRESHOLD) {
        // Timing anomaly — possible debugger single-step or sandbox slowdown; no proof
        fprintf(stderr, "[-] Suspicious timing delta (%llu cycles). Possible debugger/sandbox.\n",
                (unsigned long long)delta);
        return EXIT_FAILURE;
    } else {
        // Normal native execution speed — alternative branch writes proof
        fprintf(stderr, "[+] RDTSC timing normal (%llu cycles). Writing proof.\n",
                (unsigned long long)delta);
        if (write_c1_proof("g4_06_rdtsc_timing", "RDTSCTimingCheck_Clean") != 0) {
            fprintf(stderr, "[-] Failed to write proof.\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
}
