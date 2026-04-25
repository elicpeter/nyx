#include <stdio.h>
#include <string.h>

int main(void) {
    const char *greeting = "Hello";
    const char *name = "Alice";
    char buf[256];
    sprintf(buf, "%s, %s!", greeting, name);
    strcpy(buf, "reset value");
    strcat(buf, " done");
    printf("%s\n", buf);
    return 0;
}
