/* c-safe-016: cross-function bool-returning validator with rejection. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

bool validate_no_dotdot(const char *s) {
    return strstr(s, "..") == NULL && s[0] != '/' && s[0] != '\\';
}

void handle(const char *user_path) {
    if (!validate_no_dotdot(user_path)) {
        return;
    }
    FILE *f = fopen(user_path, "r");
    if (f) fclose(f);
}
