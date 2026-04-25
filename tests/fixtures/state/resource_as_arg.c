#include <stdio.h>

void helper(FILE *f) {
    char buf[1024];
    fread(buf, 1, 1024, f);
}

void caller(void) {
    FILE *f = fopen("data.txt", "r");
    helper(f);
    /* f never closed */
}
