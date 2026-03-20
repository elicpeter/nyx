#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void sanitize_input(const char *input, char *output, size_t len) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < len - 1; i++) {
        if (isalnum((unsigned char)input[i])) {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

int main(void) {
    const char *user = getenv("USERNAME");
    if (user) {
        char safe[128];
        sanitize_input(user, safe, sizeof(safe));
        char msg[256];
        sprintf(msg, "Hello, %s!", safe);
        printf("%s\n", msg);
    }
    return 0;
}
