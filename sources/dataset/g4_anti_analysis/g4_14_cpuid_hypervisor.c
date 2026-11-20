// SAMPLE: g4_14 | Hypervisor Bit Detection via CPUID | Group: Anti-Analysis & Memory Evasion
// Technique: Issue CPUID with leaf 1. ECX bit 31 is the "hypervisor present" bit.
//            VMware, VirtualBox, Hyper-V and most hypervisors set this bit.
//            Proof is ALWAYS written after a successful CPUID execution; the technique string
//            encodes the detected environment ("Hypervisor_VM_Detected" or "Hypervisor_BM_Detected").
//            This is a recon-success sample: writing proof represents successfully executing
//            the detection technique and determining the environment type.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g4_14_cpuid_hypervisor.exe g4_14_cpuid_hypervisor.c
// Note: MinGW-w64 provides <cpuid.h> with __cpuid(); no extra libs needed.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
#  include <cpuid.h>   /* MinGW-w64: __cpuid(leaf, eax, ebx, ecx, edx) */
#else
#  include <intrin.h>  /* MSVC: __cpuid(int[4], leaf) */
#endif
#include "../shared/c1_proof.h"

// Hypervisor present bit in CPUID leaf 1, ECX
#define HYPERVISOR_BIT 31

int main(void)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

#ifdef __GNUC__
    // MinGW-w64 / GCC: __cpuid(leaf, eax, ebx, ecx, edx)
    __cpuid(1, eax, ebx, ecx, edx);
#else
    // MSVC: __cpuid(int[4], leaf)
    int cpuid_buf[4] = {0};
    __cpuid(cpuid_buf, 1);
    eax = (unsigned int)cpuid_buf[0];
    ebx = (unsigned int)cpuid_buf[1];
    ecx = (unsigned int)cpuid_buf[2];
    edx = (unsigned int)cpuid_buf[3];
#endif

    int hypervisor_bit = (int)((ecx >> HYPERVISOR_BIT) & 1U);
    fprintf(stderr, "[*] CPUID leaf 1: EAX=0x%08X ECX=0x%08X, Hypervisor bit=%d\n",
            eax, ecx, hypervisor_bit);

    // Determine environment label based on hypervisor bit
    const char *env_label = hypervisor_bit ? "Hypervisor_VM_Detected" : "Hypervisor_BM_Detected";

    if (hypervisor_bit) {
        fprintf(stderr, "[+] Hypervisor bit SET — running inside a virtual machine.\n");
    } else {
        fprintf(stderr, "[+] Hypervisor bit CLEAR — appears to be bare metal.\n");
    }

    // Proof is always written: the technique successfully executed and characterised the environment.
    // The verifier checks only that proof exists; the technique string encodes detection result.
    fprintf(stderr, "[+] CPUID executed successfully. Writing proof: %s\n", env_label);
    if (write_c1_proof("g4_14_cpuid_hypervisor", env_label) != 0) {
        fprintf(stderr, "[-] Failed to write proof.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
