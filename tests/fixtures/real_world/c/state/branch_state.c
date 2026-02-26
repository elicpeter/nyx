#include <stdio.h>

void branch_leak(const char *path, int flag) {
    FILE *f = fopen(path, "r");
    if (flag) {
        char buf[256];
        fgets(buf, sizeof(buf), f);
        fclose(f);
    } else {
        // f leaked in else
    }
}

void both_close(const char *path, int flag) {
    FILE *f = fopen(path, "r");
    if (flag) {
        char buf[256];
        fgets(buf, sizeof(buf), f);
        fclose(f);
    } else {
        fclose(f);
    }
}
