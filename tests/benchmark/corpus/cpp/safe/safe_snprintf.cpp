#include <cstdlib>
#include <cstdio>

int main() {
    char *input = getenv("USER_INPUT");
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", input);
    return 0;
}
