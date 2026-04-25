#include <stdio.h>

FILE *open_either(const char *a, const char *b, int flag) {
    FILE *f;
    if (flag) {
        f = fopen(a, "r");
        return f;
    }
    f = fopen(b, "r");
    return f;
}
