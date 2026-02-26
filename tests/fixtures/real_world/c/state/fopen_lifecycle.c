#include <stdio.h>

void read_leak(const char *path) {
    FILE *f = fopen(path, "r");
    char buf[256];
    fgets(buf, sizeof(buf), f);
}

void read_close(const char *path) {
    FILE *f = fopen(path, "r");
    char buf[256];
    fgets(buf, sizeof(buf), f);
    fclose(f);
}

void double_close(const char *path) {
    FILE *f = fopen(path, "r");
    fclose(f);
    fclose(f);
}

void use_after_close(const char *path) {
    FILE *f = fopen(path, "r");
    fclose(f);
    char buf[256];
    fgets(buf, sizeof(buf), f);
}
