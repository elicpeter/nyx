#include <stdio.h>
#include <stdlib.h>

int process_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;

    char buf[256];
    if (fgets(buf, sizeof(buf), f) == NULL) {
        return -2;  // f leaked!
    }

    fclose(f);
    return 0;
}

int process_file_safe(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;

    char buf[256];
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return -2;
    }

    fclose(f);
    return 0;
}
