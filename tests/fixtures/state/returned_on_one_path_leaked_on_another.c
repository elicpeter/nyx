#include <stdio.h>

FILE *maybe_open(const char *path, int flag) {
    FILE *f = fopen(path, "r");
    if (flag) {
        return f;
    }
    return NULL;
}
