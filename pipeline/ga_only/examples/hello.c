#include <stdio.h>

int calculate(int value) {
    return value * 2 + 1;
}

int main(void) {
    printf("%d\n", calculate(10));
    return 0;
}
