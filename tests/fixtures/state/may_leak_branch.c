#include <stdio.h>

/* Only the true branch closes f; the false branch leaks.
   Expected: state-resource-leak-possible (NOT state-resource-leak). */
void may_leak(int cond) {
    FILE *f = fopen("data.txt", "r");
    if (cond) {
        fclose(f);
    }
}
