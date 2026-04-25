/* c-safe-014: direct-return path sanitiser using strstr. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *sanitize_path(const char *s) {
    if (strstr(s, "..") != NULL || s[0] == '/' || s[0] == '\\') {
        return "";
    }
    return s;
}

void handle(const char *user_path) {
    const char *safe = sanitize_path(user_path);
    FILE *f = fopen(safe, "r");
    if (f) fclose(f);
}
