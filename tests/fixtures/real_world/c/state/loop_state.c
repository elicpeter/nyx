#include <stdio.h>

void loop_leak() {
    int i;
    for (i = 0; i < 10; i++) {
        FILE *f = fopen("/tmp/test", "r");
        char buf[256];
        fgets(buf, sizeof(buf), f);
        // f leaked each iteration!
    }
}

void loop_close() {
    int i;
    for (i = 0; i < 10; i++) {
        FILE *f = fopen("/tmp/test", "r");
        char buf[256];
        fgets(buf, sizeof(buf), f);
        fclose(f);
    }
}
