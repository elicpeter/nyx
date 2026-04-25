#include <stdio.h>

void outer_function(void) {
    FILE *f = fopen("outer.txt", "r");
    {
        FILE *f = fopen("inner.txt", "r");
        fclose(f);
    }
    /* outer f never closed */
}
