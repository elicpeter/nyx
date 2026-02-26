#include <stdlib.h>
#include <string.h>

void alloc_leak() {
    char *buf = malloc(1024);
    strcpy(buf, "hello");
}

void alloc_free() {
    char *buf = malloc(1024);
    strcpy(buf, "hello");
    free(buf);
}

void double_free() {
    char *buf = malloc(1024);
    free(buf);
    free(buf);
}

void use_after_free() {
    char *buf = malloc(1024);
    free(buf);
    strcpy(buf, "oops");
}
