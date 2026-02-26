#include <stdio.h>
#include <stdlib.h>

void write_config() {
    char *path = getenv("CONFIG_PATH");
    FILE *f = fopen(path, "w");
    fprintf(f, "config data\n");
    fclose(f);
}
