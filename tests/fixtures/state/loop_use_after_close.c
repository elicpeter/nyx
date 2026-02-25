#include <stdio.h>

/* Close before the loop, then use inside the loop body.
   The back-edge means the use node joins CLOSED (first iter)
   with CLOSED (back-edge, still CLOSED).  The converged state
   at the fread call is CLOSED → use-after-close.
   Expected: state-use-after-close. */
void loop_use_after_close(void) {
    FILE *f = fopen("data.txt", "r");
    fclose(f);
    char buf[256];
    int i;
    for (i = 0; i < 10; i++) {
        fread(buf, 1, sizeof(buf), f);
    }
}
