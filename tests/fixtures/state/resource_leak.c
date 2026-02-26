#include <stdio.h>

void resource_leak_bug() {
    FILE *f = fopen("data.txt", "r");
    if (f == NULL) {
        return;
    }
    // Missing fclose(f) — resource leak
}
