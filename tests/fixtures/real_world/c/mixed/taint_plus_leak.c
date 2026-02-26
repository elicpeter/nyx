#include <stdio.h>
#include <stdlib.h>

void process_env() {
    char *path = getenv("USER_PATH");
    FILE *f = fopen(path, "r");
    char buf[1024];
    fgets(buf, sizeof(buf), f);
    printf("%s", buf);
    // Both: taint (getenv -> fopen) and resource leak (f not closed)
}
