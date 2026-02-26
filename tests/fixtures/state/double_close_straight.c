#include <stdio.h>

/* Straight-line double close — no branching ambiguity.
   The converged state at the second fclose is definitely CLOSED.
   Expected: state-double-close. */
void double_close_straight(void) {
    FILE *f = fopen("data.txt", "r");
    fclose(f);
    fclose(f);
}
