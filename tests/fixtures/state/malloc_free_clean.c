#include <stdlib.h>

/* malloc followed by free — clean.
   Tests the memory resource pair.
   Expected: NO state- findings. */
void malloc_free_clean(void) {
    void *p = malloc(100);
    *(char *)p = 'x';
    free(p);
}
