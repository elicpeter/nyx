#include <cstdio>

void leak() {
    FILE *f = fopen("/tmp/test", "r");
    char buf[256];
    fgets(buf, sizeof(buf), f);
}

void clean() {
    FILE *f = fopen("/tmp/test", "r");
    char buf[256];
    fgets(buf, sizeof(buf), f);
    fclose(f);
}

void double_close() {
    FILE *f = fopen("/tmp/test", "r");
    fclose(f);
    fclose(f);
}

void use_after_close() {
    FILE *f = fopen("/tmp/test", "r");
    fclose(f);
    char buf[256];
    fgets(buf, sizeof(buf), f);
}
