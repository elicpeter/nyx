#include <stdio.h>

/* The first fopen result is overwritten by the second fopen.
   The first handle leaks silently because per-variable tracking
   loses the old allocation.  The second handle is properly closed.
   Expected: NO state- findings (known per-variable-tracking limitation). */
void handle_overwrite(void) {
    FILE *f = fopen("a.txt", "r");
    f = fopen("b.txt", "r");
    fclose(f);
}
