#include <stdio.h>

/* Two separate handles: f1 is closed, f2 is leaked.
   Expected: state-resource-leak for f2, NO state-resource-leak for f1.
   (The finding message should contain "f2".) */
void multiple_handles(void) {
    FILE *f1 = fopen("a.txt", "r");
    FILE *f2 = fopen("b.txt", "r");
    fclose(f1);
    /* f2 never closed */
}
