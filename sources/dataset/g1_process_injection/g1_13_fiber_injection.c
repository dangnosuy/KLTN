// SAMPLE: g1_13 | Fiber Execution Injection | Group: Process Injection
//
// Description:
//   Converts the primary thread into a Windows Fiber, creates a payload fiber
//   using CreateFiber, and diverts thread execution flow using SwitchToFiber.
//   The fiber routine performs execution and switches control back to the primary fiber.
//
// C1 Verification Rule:
//   Proof file MUST be written from within the execution context of the created Fiber.
//
// Compile (MinGW-w64):
//   x86_64-w64-mingw32-gcc -O2 -o g1_13_fiber_injection.exe g1_13_fiber_injection.c

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define SAMPLE_ID      "g1_13_fiber_injection"
#define TECHNIQUE_NAME "FiberExecutionInjection"

static PVOID g_pMainFiber = NULL;

typedef struct _FIBER_CONTEXT {
    int (*pfnWriteProof)(const char *, const char *);
    char sample_id[64];
    char technique[64];
    volatile LONG status;
    volatile LONG executed;
} FIBER_CONTEXT;

// Execution routine for the injected fiber
VOID WINAPI FiberPayloadRoutine(LPVOID lpParam)
{
    FIBER_CONTEXT *ctx = (FIBER_CONTEXT *)lpParam;
    if (ctx && ctx->pfnWriteProof) {
        printf("[+] FiberPayloadRoutine executing on Fiber context!\n");
        // Write the C1 verification proof from within the fiber
        ctx->status = ctx->pfnWriteProof(ctx->sample_id, ctx->technique);
        ctx->executed = 1;
    }

    // Return control back to the primary fiber
    if (g_pMainFiber) {
        printf("[+] Fiber execution completed. Switching back to main fiber...\n");
        SwitchToFiber(g_pMainFiber);
    }
}

int main(void)
{
    printf("[*] Starting %s (%s)...\n", SAMPLE_ID, TECHNIQUE_NAME);

    // 1. Convert current thread to a fiber
    g_pMainFiber = ConvertThreadToFiber(NULL);
    if (!g_pMainFiber) {
        fprintf(stderr, "[-] ConvertThreadToFiber failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[+] Converted main thread to primary fiber: %p\n", g_pMainFiber);

    // 2. Setup fiber parameter context
    FIBER_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pfnWriteProof = write_c1_proof;
    strncpy(ctx.sample_id, SAMPLE_ID, sizeof(ctx.sample_id) - 1);
    strncpy(ctx.technique, TECHNIQUE_NAME, sizeof(ctx.technique) - 1);
    ctx.status = -1;
    ctx.executed = 0;

    // 3. Create the payload execution fiber
    PVOID pPayloadFiber = CreateFiber(0, FiberPayloadRoutine, &ctx);
    if (!pPayloadFiber) {
        fprintf(stderr, "[-] CreateFiber failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[+] Created payload fiber: %p\n", pPayloadFiber);

    // 4. Divert execution to the payload fiber
    printf("[*] Switching execution context to payload fiber...\n");
    SwitchToFiber(pPayloadFiber);

    // 5. Execution resumed here after SwitchToFiber(g_MainFiber) in payload
    printf("[+] Execution returned to primary fiber.\n");

    // 6. Verify payload execution status
    if (ctx.executed != 1 || ctx.status != 0) {
        fprintf(stderr, "[-] Fiber execution verification failed (executed=%ld, status=%ld)\n",
                ctx.executed, ctx.status);
        DeleteFiber(pPayloadFiber);
        return EXIT_FAILURE;
    }

    // 7. Cleanup
    DeleteFiber(pPayloadFiber);
    printf("[+] Fiber injection executed successfully. Proof verified.\n");
    return EXIT_SUCCESS;
}
