#include "../common/fixture.h"
int main(void) {
    char data[64] = {0};
    const char value[] = "dataset-v2:0123456789abcdef\n";
    if (write_fixture()) return 1;
    FILE *file = fopen("result.txt", "rb");
    if (!file) return 1;
    size_t count = fread(data, 1, sizeof(data), file);
    int failed = ferror(file);
    if (fclose(file)) failed = 1;
    return failed || count != strlen(value) || memcmp(data, value, count) != 0;
}
