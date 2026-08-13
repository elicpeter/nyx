/* Struct-field acquire ownership transfer (C).
 *
 * A resource acquire (malloc/calloc) assigned DIRECTLY into a struct-field
 * LHS (`b->buf = malloc(...)`) transfers ownership to the containing struct,
 * whose lifetime the local body cannot observe.  It must NOT fire
 * `state-resource-leak`.  A genuinely orphaned plain-local malloc in the same
 * file still leaks (recall guard).
 *
 * Engine: src/state/transfer.rs::apply_call SAFE-FOR-FIELD-LHS gate
 * (acquire_into_field_transfers_ownership).  Distilled from redis/hiredis
 * net.c (c->connect_timeout) + lua strbuf.c (s->buf).
 */
#include <stdlib.h>

struct box {
    char *buf;
    int size;
};

/* Param receiver: `b->buf` owned by the caller's *b — no leak. */
int fill(struct box *b, int n) {
    b->buf = malloc(n);
    if (b->buf == NULL)
        return -1;
    b->size = n;
    return 0;
}

/* Constructor: `s->buf` owned by *s; *s is returned to the caller — no leak. */
struct box *box_new(int n) {
    struct box *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->buf = malloc(n);
    s->size = n;
    return s;
}

/* Field store (no leak) alongside a genuinely orphaned local (recall). */
void mixed(struct box *b, int n) {
    b->buf = malloc(n);       /* owned by *b — not a leak */
    char *orphan = malloc(n); /* never freed, never returned — real leak */
    orphan[0] = 'x';
}
