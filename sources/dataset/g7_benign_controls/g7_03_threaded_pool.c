// SAMPLE: g7_03 | ThreadedWorkerPool | Group: Benign Controls
// Creates 4 worker threads; each increments a shared LONG counter 1000 times
// via InterlockedIncrement. Main waits for all, verifies counter == 4000.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

#define NUM_THREADS     4
#define INCREMENTS_EACH 1000

static volatile LONG g_counter = 0;

static DWORD WINAPI worker(LPVOID lpParam)
{
    (void)lpParam;
    for (int i = 0; i < INCREMENTS_EACH; i++) {
        InterlockedIncrement(&g_counter);
    }
    return 0;
}

int main(void)
{
    HANDLE threads[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i] = CreateThread(
            NULL,       /* default security */
            0,          /* default stack size */
            worker,
            NULL,
            0,
            NULL
        );
        if (threads[i] == NULL) {
            fprintf(stderr, "[g7_03] CreateThread[%d] failed: %lu\n",
                    i, GetLastError());
            /* Wait for already-started threads before exiting */
            if (i > 0) {
                WaitForMultipleObjects((DWORD)i, threads, TRUE, INFINITE);
                for (int j = 0; j < i; j++) CloseHandle(threads[j]);
            }
            return EXIT_FAILURE;
        }
    }

    /* Wait for all 4 threads to finish */
    DWORD waitResult = WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
    if (waitResult == WAIT_FAILED) {
        fprintf(stderr, "[g7_03] WaitForMultipleObjects failed: %lu\n",
                GetLastError());
        for (int i = 0; i < NUM_THREADS; i++) CloseHandle(threads[i]);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < NUM_THREADS; i++) CloseHandle(threads[i]);

    LONG final = g_counter;
    printf("[g7_03] Final counter = %ld (expected %d)\n",
           final, NUM_THREADS * INCREMENTS_EACH);

    if (final != (LONG)(NUM_THREADS * INCREMENTS_EACH)) {
        fprintf(stderr, "[g7_03] Counter mismatch — thread sync error.\n");
        return EXIT_FAILURE;
    }

    /* Counter verified — write proof */
    write_c1_proof("g7_03_threaded_pool", "ThreadedWorkerPool");
    printf("[g7_03] Threaded pool benchmark PASSED. Proof written.\n");
    return EXIT_SUCCESS;
}
