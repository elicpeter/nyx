#include <stdio.h>

void read_input() {
    char name[32];
    scanf("%s", name);
    printf("Hello, %s\n", name);
}

void read_safe() {
    char name[32];
    scanf("%31s", name);
    printf("Hello, %s\n", name);
}
