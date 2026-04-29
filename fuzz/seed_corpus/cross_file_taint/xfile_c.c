#include <stdio.h>
int main(void) {
    char *x = nyx_taint_source();
    nyx_dangerous_sink(x);
    char *y = nyx_sanitize(nyx_taint_source());
    nyx_dangerous_sink(y);
    return 0;
}
