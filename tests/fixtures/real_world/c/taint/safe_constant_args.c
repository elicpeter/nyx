#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[256];
    sprintf(buf, "Hello, %s!", "world");
    strcpy(buf, "constant value");
    strcat(buf, " appended");
    printf("%s\n", buf);
    return 0;
}
