#include <stdio.h>

void funcA(void) {
    FILE *f = fopen("a.txt", "r");
    /* f leaked */
}

void funcB(void) {
    FILE *f = fopen("b.txt", "r");
    fclose(f);
}
