#include <stdlib.h>
#include <stdio.h>

int main() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    system(buf);
    return 0;
}
