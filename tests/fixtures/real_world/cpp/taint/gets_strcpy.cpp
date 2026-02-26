#include <cstdio>
#include <cstring>

void copy_unsafe(const char *input) {
    char buf[64];
    strcpy(buf, input);
}

void gets_input() {
    char buf[128];
    gets(buf);
}
