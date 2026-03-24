#include <cstdlib>
#include <cstring>

int main() {
    char *input = getenv("USER_INPUT");
    char buf[64];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[63] = '\0';
    return 0;
}
