#include <stdio.h>

void loop_reopen(void) {
    int i;
    for (i = 0; i < 3; i++) {
        FILE *f = fopen("data.txt", "r");
        char buf[64];
        fread(buf, 1, 64, f);
        fclose(f);
    }
}
