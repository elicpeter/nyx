#include <stdio.h>

void clean_usage() {
    FILE *f = fopen("data.txt", "r");
    char buf[256];
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    // Clean: open, use, close — no bugs
}
