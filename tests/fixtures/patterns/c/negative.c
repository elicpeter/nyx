/* Negative fixture: none of these should trigger security patterns. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_snprintf(const char *name) {
    char buf[128];
    snprintf(buf, sizeof(buf), "Hello %s", name);
}

void safe_strncpy(const char *src) {
    char dst[32];
    strncpy(dst, src, sizeof(dst) - 1);
    dst[sizeof(dst) - 1] = '\0';
}

void safe_fgets() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
}

void safe_printf_literal() {
    printf("Hello %s\n", "world");
}
