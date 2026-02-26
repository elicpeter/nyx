#include <stdio.h>

/* Open, close, then reopen the same variable and close again.
   The second fopen overwrites CLOSED with OPEN; the second fclose
   brings it back to CLOSED.  Clean usage.
   Expected: NO state- findings. */
void reopen_after_close(void) {
    FILE *f = fopen("a.txt", "r");
    fclose(f);
    f = fopen("b.txt", "r");
    fclose(f);
}
