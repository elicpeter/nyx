#include <stdio.h>

int process_file(const char *path) {
    FILE *f = fopen(path, "r");
    char buf[1024];
    fread(buf, 1, 1024, f);
    return 0;
}
