// SAMPLE: g2_04 | Vectored Exception Handling (VEH) Hijacking | Group: Execution Hijacking
//
// g2_04_veh_hijack.c — Demonstrates VEH-based execution hijacking.
//
// Flow:
//   1. Register a Vectored Exception Handler (VEH) at the front of the chain.
//   2. RaiseException() with a custom code 0xE0C10001.
//   3. VEH fires — this is the HIJACKED EXECUTION PATH.
//   4. Handler writes the C1 proof (not the main thread normally).
//   5. Handler returns EXCEPTION_CONTINUE_EXECUTION so execution resumes.
//
// C1 RULE: Proof is written inside VehHandler — the hijacked path.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g2_04_veh_hijack.exe g2_04_veh_hijack.c

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* Custom exception code in the customer-defined range (bits 29-30 set = 0xE0xxxxxx) */
#define C1_EXCEPTION_CODE  0xE0C10001UL

/*
 * VehHandler — Vectored Exception Handler (the hijacked execution path).
 *
 * When RaiseException(C1_EXCEPTION_CODE) is called in main(), the OS walks
 * the VEH chain BEFORE any SEH frame.  This handler intercepts the exception,
 * writes the C1 proof, and resumes execution.
 */
static LONG WINAPI VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == C1_EXCEPTION_CODE) {
        /*
         * HIJACKED EXECUTION PATH — we got here because an exception was raised
         * and the VEH chain was redirected to this callback before any normal
         * SEH handler could process it.  The main() code that called
         * RaiseException() is suspended; control is entirely ours.
         */
        int rc = write_c1_proof("g2_04_veh_hijack", "VEHHijacking");
        if (rc != 0) {
            fprintf(stderr, "[veh_hijack] write_c1_proof returned %d\n", rc);
        }
        /*
         * EXCEPTION_CONTINUE_EXECUTION: tells the OS to resume execution at
         * the faulting instruction.  For a software exception raised with
         * RaiseException(), this returns control to the instruction AFTER the
         * RaiseException() call site.
         */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* Not our exception — pass to the next handler */
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    /* ---- Step 1: Register VEH at the front of the chain ---- */
    PVOID hVeh = AddVectoredExceptionHandler(1 /*first*/, VehHandler);
    if (!hVeh) {
        fprintf(stderr, "[veh_hijack] AddVectoredExceptionHandler failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }
    printf("[veh_hijack] VEH registered. Raising custom exception 0x%08lX...\n",
           C1_EXCEPTION_CODE);

    /* ---- Step 2: Raise the exception — VEH fires, proof written there ---- */
    RaiseException(C1_EXCEPTION_CODE, 0 /*flags*/, 0 /*nArgs*/, NULL);

    /*
     * Execution resumes HERE after VehHandler returns EXCEPTION_CONTINUE_EXECUTION.
     * The proof has already been written from within the handler.
     */
    printf("[veh_hijack] Execution resumed after VEH handled the exception.\n");
    printf("[veh_hijack] C1 proof written from VEH callback — VEHHijacking verified.\n");

    /* ---- Cleanup ---- */
    RemoveVectoredExceptionHandler(hVeh);

    return EXIT_SUCCESS;
}
