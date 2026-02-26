#include <stdio.h>

/* Early return leaks on the error path; normal path closes.
   Expected: state-resource-leak-possible (may-leak). */
void early_return_leak(int err) {
    FILE *f = fopen("data.txt", "r");
    if (err) {
        return;
    }
    fclose(f);
}
