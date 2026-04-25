/* c-safe-015: status-code-returning sanitiser (C-natural failure idiom). */
#include <stdio.h>
#include <string.h>

int sanitize_path(const char *in, char *out, size_t n) {
    if (strstr(in, "..") != NULL || in[0] == '/' || in[0] == '\\') {
        return -1;
    }
    strncpy(out, in, n - 1);
    out[n - 1] = '\0';
    return 0;
}

void handle(const char *user_path) {
    char safe[256];
    if (sanitize_path(user_path, safe, sizeof(safe)) != 0) {
        return;
    }
    FILE *f = fopen(safe, "r");
    if (f) fclose(f);
}
