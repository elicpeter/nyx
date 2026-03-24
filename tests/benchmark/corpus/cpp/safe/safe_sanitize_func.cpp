#include <cstdlib>
#include <cstdio>
#include <string>

std::string sanitize_input(const char *s);

int main() {
    char *input = getenv("USER_INPUT");
    std::string clean = sanitize_input(input);
    printf("%s\n", clean.c_str());
    return 0;
}
