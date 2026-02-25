#include <stdio.h>

/* fclose in one branch, then unconditional fread after.
   True path:  fclose(f) → fread(CLOSED) = use-after-close.
   False path: fread(OPEN) = fine.
   Converged state at fread: OPEN|CLOSED (join).
   Expected: NO state-use-after-close (conservative: join masks it).
   Expected: state-resource-leak-possible (false path never closes). */
void use_closed_branch(int cond) {
    FILE *f = fopen("data.txt", "r");
    if (cond) {
        fclose(f);
    }
    char buf[256];
    fread(buf, 1, sizeof(buf), f);
}
