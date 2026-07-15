/*
 * c-safe-realrepo-025 — distilled from redis/deps/hiredis/net.c::
 * redisContextUpdateConnectTimeout and redis/deps/lua/src/strbuf.c::
 * strbuf_init.  Pattern: an acquire call (malloc / calloc) is assigned
 * DIRECTLY into a struct-field / object-member LHS
 * (`c->connect_timeout = malloc(...)`, `s->buf = malloc(...)`), where the
 * receiver struct is a parameter.  The containing struct owns the field's
 * lifetime — the storage is released by the paired free_*() method
 * (redisFree / strbuf_free) or in the caller, never in this body.  Tracking
 * the field as a function-local resource is a guaranteed leak FP at exit.
 *
 * Engine fix (depth: structural — apply_call field-LHS gate):
 *   src/state/transfer.rs::apply_call SAFE-FOR-FIELD-LHS gate
 *   (`acquire_into_field_transfers_ownership`) skips the acquire when the
 *   destination `defines` is a member-access LHS (`.` / `->`) for C/C++ (and
 *   `.` for Go), with a twin gate in src/cfg_analysis/resources.rs so
 *   clearing the state-resource-leak does not unmask cfg-resource-leak.
 *   Sibling of the apply_assignment field-LHS gate (RHS-is-a-var downstream
 *   store, c-safe-realrepo-019).  Closes the dominant `state-resource-leak`
 *   FP cluster on redis/git/curl/openssl/postgres (~165 findings across
 *   redis + git alone).
 */

#include <stdlib.h>
#include <string.h>

struct timeval_t {
    long tv_sec;
    long tv_usec;
};

struct redis_ctx {
    struct timeval_t *connect_timeout;
    struct timeval_t *command_timeout;
    char *saddr;
};

/* Param-receiver: ownership transfers to the caller's *c struct, which is
 * freed by redisFree().  `c->connect_timeout = malloc(...)` must not fire
 * `state-resource-leak`. */
int redis_ctx_update_connect_timeout(struct redis_ctx *c,
                                     const struct timeval_t *timeout) {
    if (c->connect_timeout == NULL) {
        c->connect_timeout = malloc(sizeof(*c->connect_timeout));
        if (c->connect_timeout == NULL)
            return -1;
    }
    memcpy(c->connect_timeout, timeout, sizeof(*c->connect_timeout));
    return 0;
}

struct strbuf {
    char *buf;
    int size;
    int length;
};

/* Param-receiver constructor (real redis strbuf_init signature): s->buf is
 * owned by *s, released by strbuf_free(). */
void strbuf_init(struct strbuf *s, int size) {
    s->buf = malloc(size);      /* owned by *s, not by strbuf_init */
    s->size = size;
    s->length = 0;
}
