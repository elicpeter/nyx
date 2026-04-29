/* Vulnerable counterpart for `safe_strcpy_literal_src.c` — Layer D must
 * NOT suppress when the source argument is a non-literal that could
 * carry attacker-controlled length.  Distilled from a typical CLI shape:
 * argv[1] is unbounded user input.  The strcpy here is the canonical
 * `c.memory.strcpy` finding the pattern rule is meant to catch. */
#include <string.h>

void copy_user(char *dst, char **argv) {
    strcpy(dst, argv[1]);
}
