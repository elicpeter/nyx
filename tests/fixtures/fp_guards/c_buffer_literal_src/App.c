/* FP guard — C/C++ buffer-overflow pattern rules over-fire on calls
 * whose source / format-string argument is a literal whose contributed
 * length is statically bounded.  Pinned from a 938-finding cluster on
 * postgres (`pg_prewarm/autoprewarm.c`, `formatting.c::DCH_a_m`,
 * `datetime.c::EncodeDateTime`).
 *
 * See `tests/benchmark/corpus/c/safe/safe_strcpy_literal_src.c` and
 * `safe_sprintf_bounded_format.c` for the per-corpus siblings, and
 * `buffer_strcpy_user_arg.c` for the vulnerable counterpart that must
 * still fire. */
#include <stdio.h>
#include <string.h>

struct Worker {
    char name[96];
};

#define A_M_STR "a.m."
#define P_M_STR "p.m."
#define MAXTZLEN 10

void register_worker(struct Worker *w) {
    strcpy(w->name, "autoprewarm");
}

void format_meridian(char *s, int hour) {
    strcpy(s, (hour >= 12) ? P_M_STR : A_M_STR);
}

void emit_int(char *cp, long long value) {
    sprintf(cp, "%lld", value);
}

void emit_tz(char *str, const char *tzn) {
    sprintf(str, " %.*s", MAXTZLEN, tzn);
}

void append_marker(char *dst) {
    strcat(dst, " (done)");
}
