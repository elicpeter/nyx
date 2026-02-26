#include <stdio.h>

/* fclose inside a branch, then unconditional fclose after.
   True path:  fclose(OPEN→CLOSED), then fclose(CLOSED) = double close.
   False path: skip inner fclose, then fclose(OPEN→CLOSED) = fine.
   Converged state at the second fclose: OPEN|CLOSED (join).
   Expected: NO state-double-close (conservative: join masks the bug). */
void double_close_branch(int cond) {
    FILE *f = fopen("data.txt", "r");
    if (cond) {
        fclose(f);
    }
    fclose(f);
}
