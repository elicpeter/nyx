#include <stdio.h>

FILE *broken_open(const char *path) {
    FILE *f = fopen(path, "r");
    return NULL;
}
