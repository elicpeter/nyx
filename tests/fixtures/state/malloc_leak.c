#include <stdlib.h>

/* malloc without free — resource leak.
   Tests the memory resource pair (malloc → free).
   Expected: state-resource-leak. */
void malloc_leak(void) {
    void *p = malloc(100);
    *(char *)p = 'x';
}
