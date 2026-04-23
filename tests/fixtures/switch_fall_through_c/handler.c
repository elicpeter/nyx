#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Phase 12.6 fixture: a C switch with explicit fall-through across cases.
 *
 * C's switch semantics allow fall-through from one case body to the next
 * when `break` is omitted. The SSA lowering must preserve this as a
 * cascade of `Branch` headers (not a single `Terminator::Switch`) since
 * Switch targets are mutually exclusive by contract. Case bodies 1 and 2
 * both execute when `mode == 1`; this test exercises that cascade
 * semantics still flow the tainted command through to `system()` on both
 * paths.
 */

void run_mode(int mode) {
    char *user = getenv("USER_CMD");
    char buf[256];

    switch (mode) {
    case 1:
        /* Fall-through to case 2: both bodies execute when mode == 1. */
        snprintf(buf, sizeof(buf), "echo start && %s", user);
    case 2:
        /* Tainted `user` reaches system() here whether we entered via
           case 1 (fall-through) or directly via mode == 2. */
        system(user);
        break;
    case 3:
        /* No break: fall-through to default. */
        printf("case 3\n");
    default:
        /* Also reachable from case 3 fall-through. */
        system(user);
        break;
    }
}

int main(int argc, char **argv) {
    int mode = argc > 1 ? atoi(argv[1]) : 0;
    run_mode(mode);
    return 0;
}
