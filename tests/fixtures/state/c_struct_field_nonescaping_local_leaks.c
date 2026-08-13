/* Struct-field acquire ownership: container escape analysis (C).
 *
 * The field-LHS ownership-transfer suppression
 * (`acquire_into_field_transfers_ownership`) is LIFTED for a provably
 * NON-ESCAPING local value struct — `struct Ctx c; c.buf = malloc();`
 * where `c` dies at function exit and is never freed is a real leak
 * (the false negative session-0049's blanket suppression missed).  It
 * STAYS suppressed when the container ESCAPES: a parameter pointer
 * (arrow), address-taken, passed to a call, returned, or a field read
 * out.
 *
 * Engine: src/state/transfer.rs::nonescaping_local_field_containers
 * (state pass) + twin in src/cfg_analysis::resources.rs.  Resolves the
 * deferred deep fix from C/C++ bughunt session-0049.
 */
#include <stdlib.h>

struct Ctx {
    char *buf;
    int len;
};

extern void init(struct Ctx *);

/* RECALL: `c` is a non-escaping stack value struct whose field allocation
 * is never freed — a real leak on `c.buf`. */
void build_dead(int n) {
    struct Ctx c;
    c.buf = malloc(n);
    c.len = n;
}

/* PRECISION: parameter pointer (arrow `p->buf`) — owned by the caller's
 * *p, released elsewhere.  Must stay suppressed. */
void fill_param(struct Ctx *p, int n) {
    p->buf = malloc(n);
    p->len = n;
}

/* PRECISION: local struct whose address is taken and passed to init(&e) —
 * the container escapes, so ownership may transfer.  Suppressed. */
void escapes_addr(int n) {
    struct Ctx e;
    e.buf = malloc(n);
    e.len = n;
    init(&e);
}

/* PRECISION: local struct whose field IS freed in-body — not a leak.
 * `free(g.buf)` surfaces bare `g`, treated conservatively as an escape,
 * and the release independently clears the handle.  Suppressed. */
void freed_local(int n) {
    struct Ctx g;
    g.buf = malloc(n);
    free(g.buf);
}
