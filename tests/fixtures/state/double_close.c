#include <stdio.h>

void double_close_bug() {
    FILE *f = fopen("data.txt", "r");
    fclose(f);
    fclose(f);  // BUG: double close
}
