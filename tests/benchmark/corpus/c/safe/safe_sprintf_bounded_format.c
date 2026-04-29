/* Distilled from postgres `datetime.c::EncodeDateTime` — `sprintf` with
 * a literal format string that uses only width/precision-bounded
 * specifiers contributes statically-bounded length, so it cannot
 * overflow due to attacker input.  Layer D suppression accepts:
 *   - format strings with no `%s` at all (numeric / char specifiers)
 *   - format strings whose `%s` is precision-bounded (`%.*s`, `%.5s`)
 *
 * Bare `%s` (`sprintf(buf, "%s", x)`) is intentionally NOT suppressed —
 * see `cpp/buffer_overflow/buffer_sprintf.cpp` for the vulnerable
 * counterpart. */
#include <stdio.h>

#define MAXTZLEN 10

void emit_int(char *cp, long long value, char units) {
    /* Numeric-only specifier — bounded by integer-length budget. */
    sprintf(cp, "%lld%c", value, units);
}

void emit_tz(char *str, const char *tzn) {
    /* Precision-bounded `%.*s` — output capped at MAXTZLEN bytes. */
    sprintf(str, " %.*s", MAXTZLEN, tzn);
}

void emit_static(char *buf) {
    sprintf(buf, "fixed=%d/%c", 42, 'X');
}
