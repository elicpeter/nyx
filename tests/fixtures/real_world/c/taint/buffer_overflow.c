#include <stdio.h>
#include <string.h>

void copy_unsafe(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void copy_safe(char *input) {
    char buf[64];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("%s\n", buf);
}

void gets_vuln() {
    char buf[128];
    gets(buf);
    printf("%s\n", buf);
}

void concat_vuln(char *src1, char *src2) {
    char buf[64];
    strcpy(buf, src1);
    strcat(buf, src2);
    printf("%s\n", buf);
}
