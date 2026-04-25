#include <cstdlib>
#include <cstring>

int main() {
    char *input = getenv("USER_INPUT");
    char buf[64];
    strcpy(buf, input);
    return 0;
}
