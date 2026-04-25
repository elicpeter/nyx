#include <stdlib.h>
#include <stdio.h>

int main() {
    char *input = getenv("USER_NUM");
    long val = strtol(input, NULL, 10);
    printf("Value: %ld\n", val);
    return 0;
}
