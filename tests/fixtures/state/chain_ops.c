#include <stdio.h>

/* Multiple resource operations in sequence: open → read → write → close.
   Tests that repeated uses do not corrupt lifecycle state.
   Expected: NO state- findings. */
void chain_ops(void) {
    FILE *f = fopen("data.txt", "r");
    char buf[256];
    fread(buf, 1, sizeof(buf), f);
    fwrite(buf, 1, sizeof(buf), f);
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
}
