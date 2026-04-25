#include <stdlib.h>
#include <stdio.h>

int main() {
    char *path = getenv("FILE_PATH");
    FILE *fp = fopen(path, "r");
    fclose(fp);
    return 0;
}
