#include <stdlib.h>
#include <stdio.h>

char *sanitize_input(char *s);

int main() {
    char *input = getenv("USER_INPUT");
    char *clean = sanitize_input(input);
    printf("%s\n", clean);
    return 0;
}
