#include <stdlib.h>

void double_free_bug(int flag) {
    char *buf = malloc(256);
    if (flag) {
        free(buf);
    }
    free(buf);  // double free if flag was true
}

void conditional_free_safe(int flag) {
    char *buf = malloc(256);
    if (flag) {
        free(buf);
        buf = NULL;
    }
    if (buf != NULL) {
        free(buf);
    }
}
