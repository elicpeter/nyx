#include <stdio.h>

/* Open before loop, use inside loop, close after loop.
   The back-edge should not prevent convergence.
   Expected: NO state- findings. */
void loop_clean(void) {
    FILE *f = fopen("data.txt", "r");
    char buf[256];
    int i;
    for (i = 0; i < 10; i++) {
        fread(buf, 1, sizeof(buf), f);
    }
    fclose(f);
}
