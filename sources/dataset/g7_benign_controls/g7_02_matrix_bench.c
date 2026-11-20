// SAMPLE: g7_02 | MatrixBenchmarkTrace | Group: Benign Controls
// Allocates two 64x64 int matrices with deterministic fill, multiplies them,
// computes the trace (sum of diagonal), verifies trace != 0, then writes proof.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../shared/c1_proof.h"

#define N 64

int main(void)
{
    /* Allocate on heap to avoid large stack frames */
    int (*A)[N] = (int (*)[N])malloc(sizeof(int) * N * N);
    int (*B)[N] = (int (*)[N])malloc(sizeof(int) * N * N);
    int (*C)[N] = (int (*)[N])calloc(N * N, sizeof(int));

    if (!A || !B || !C) {
        fprintf(stderr, "[g7_02] malloc failed.\n");
        free(A); free(B); free(C);
        return EXIT_FAILURE;
    }

    /* Deterministic fill: A[i][j] = i*64+j, B[i][j] = j*64+i */
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            A[i][j] = i * N + j;
            B[i][j] = j * N + i;
        }
    }

    /* Matrix multiply C = A * B */
    for (int i = 0; i < N; i++) {
        for (int k = 0; k < N; k++) {
            if (A[i][k] == 0) continue;   /* minor optimisation */
            for (int j = 0; j < N; j++) {
                C[i][j] += A[i][k] * B[k][j];
            }
        }
    }

    /* Compute trace = sum of diagonal elements */
    long long trace = 0;
    for (int i = 0; i < N; i++) {
        trace += C[i][i];
    }

    free(A); free(B); free(C);

    if (trace == 0) {
        fprintf(stderr, "[g7_02] Unexpected zero trace — computation error.\n");
        return EXIT_FAILURE;
    }

    printf("[g7_02] Matrix 64x64 multiply complete. Trace = %lld\n", trace);

    /* Computation verified — write proof */
    write_c1_proof("g7_02_matrix_bench", "MatrixBenchmarkTrace");
    printf("[g7_02] Matrix benchmark PASSED. Proof written.\n");
    return EXIT_SUCCESS;
}
