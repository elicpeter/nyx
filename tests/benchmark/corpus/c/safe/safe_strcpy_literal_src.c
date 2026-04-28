/* Distilled from postgres `pg_prewarm/autoprewarm.c` and `pgrowlocks.c` —
 * the canonical "set struct field to a fixed string" pattern.  The
 * pattern rule `c.memory.strcpy` flags the call syntactically; the source
 * is a string literal whose length is bounded at compile time, so the
 * call is not exploitable for buffer overflow.  Layer D suppression
 * recognises both forms (plain literal and ternary of two literals,
 * mirroring postgres' `formatting.c::DCH_AM` shape). */
#include <string.h>

struct BackgroundWorker {
    char bgw_library_name[96];
    char bgw_function_name[96];
    char bgw_name[96];
};

void register_bgw(void) {
    struct BackgroundWorker worker;
    strcpy(worker.bgw_library_name, "pg_prewarm");
    strcpy(worker.bgw_function_name, "autoprewarm_main");
    strcpy(worker.bgw_name, "autoprewarm leader");
}

#define A_M_STR "a.m."
#define P_M_STR "p.m."

void format_meridian(char *s, int hour) {
    /* Postgres `formatting.c::DCH_a_m` ternary-of-literals shape. */
    strcpy(s, (hour >= 12) ? P_M_STR : A_M_STR);
}

void append_marker(char *dst) {
    /* `strcat` mirror — bounded source. */
    strcat(dst, " (done)");
}
