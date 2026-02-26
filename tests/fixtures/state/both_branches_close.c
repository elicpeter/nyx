#include <stdio.h>

/* Both branches close f — no leak on any path.
   Expected: NO state- findings. */
void both_close(int cond) {
    FILE *f = fopen("data.txt", "r");
    if (cond) {
        fclose(f);
    } else {
        fclose(f);
    }
}
