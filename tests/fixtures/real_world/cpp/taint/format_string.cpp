#include <cstdio>
#include <cstdlib>

void print_unsafe(const char *user_input) {
    printf(user_input);
}

void print_safe(const char *user_input) {
    printf("%s", user_input);
}
