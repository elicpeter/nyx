#include <stdio.h>

FILE *open_file(const char *path) {
    FILE *f = fopen(path, "r");
    return f;
}
