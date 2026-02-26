#include <stdio.h>
#include <stdlib.h>

void print_user_input(char *input) {
    printf(input);
}

void print_safe(char *input) {
    printf("%s", input);
}

void sprintf_vuln(char *buf, char *user_input) {
    sprintf(buf, user_input);
}
