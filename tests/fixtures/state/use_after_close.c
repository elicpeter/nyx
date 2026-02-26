#include <stdio.h>

void use_after_close_bug() {
    FILE *f = fopen("data.txt", "r");
    fclose(f);
    char buf[256];
    fread(buf, 1, sizeof(buf), f);  // BUG: use after close
}
