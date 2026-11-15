#ifndef DATASET_FIXTURE_H
#define DATASET_FIXTURE_H
#include <stdio.h>
#include <string.h>
/* Synthetic constant data: no host information or network dependency. */
static int write_fixture(void) {
    const char value[] = "dataset-v2:0123456789abcdef\n";
    FILE *file = fopen("result.txt", "wb");
    if (!file) return 1;
    int ok = fwrite(value, 1, strlen(value), file) == strlen(value);
    if (fclose(file) != 0) ok = 0;
    return ok ? 0 : 1;
}
#endif
