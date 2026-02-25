#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ───── Safe string handling ─────
 * Demonstrates proper bounded operations that should NOT trigger findings.
 */

/* SAFE: uses snprintf with explicit size limit */
void safe_format_message(const char *user, char *out, size_t out_size) {
    snprintf(out, out_size, "Hello, %s! Welcome back.", user);
}

/* SAFE: uses strncpy with explicit length */
void safe_copy_path(const char *src, char *dst, size_t dst_size) {
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

/* SAFE: uses fgets with proper buffer size, no dangerous operations */
void safe_read_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        /* Just log the line, no shell execution */
        printf("Config: %s", line);
    }
    fclose(f);
}

/* SAFE: pure computation, no external input */
int safe_calculate_checksum(const unsigned char *data, size_t len) {
    int sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (sum + data[i]) & 0xFFFF;
    }
    return sum;
}

/* SAFE: hardcoded command, no taint from environment */
void safe_list_directory(void) {
    system("ls -la /var/log");
}
