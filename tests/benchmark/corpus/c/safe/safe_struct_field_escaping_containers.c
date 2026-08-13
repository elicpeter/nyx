/*
 * c-safe-realrepo-026 — container escape analysis precision guard.
 *
 * The struct-field-acquire ownership-transfer suppression is LIFTED only
 * for a provably NON-escaping local value struct (session-0049 deferred
 * deep fix).  When the container ESCAPES the function it stays suppressed:
 *   - a parameter pointer (arrow) is owned by the caller,
 *   - a local whose address is taken (`&c` passed to a call) may have
 *     ownership transferred by the callee,
 *   - a local returned to the caller is caller-owned.
 * None of these may fire state-resource-leak / cfg-resource-leak.
 *
 * Engine: src/state/transfer.rs::nonescaping_local_field_containers
 * (state pass) + twin src/cfg_analysis::resources.rs.  Distilled from
 * redis/hiredis net.c (c->connect_timeout, param arrow) shapes.
 */
#include <stdlib.h>

struct box {
    char *buf;
    int size;
};

extern void box_register(struct box *);

/* Parameter pointer (arrow): `b->buf` owned by the caller's *b. */
void fill_param(struct box *b, int n) {
    b->buf = malloc(n);
    b->size = n;
}

/* Local struct whose address is taken and handed to a registrar — the
 * callee may take ownership, so the field acquire must stay suppressed. */
void register_local(int n) {
    struct box b;
    b.buf = malloc(n);
    b.size = n;
    box_register(&b);
}

/* Local value struct returned BY VALUE — the buffer travels to the caller
 * with the returned struct, so the field acquire is caller-owned. */
struct box make_box(int n) {
    struct box b;
    b.buf = malloc(n);
    b.size = n;
    return b;
}
