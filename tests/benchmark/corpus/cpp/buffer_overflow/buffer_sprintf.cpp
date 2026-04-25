#include <cstdlib>
#include <cstdio>
#include <cstring>

int main() {
    char *input = getenv("USER_INPUT");
    char buf[64];
    sprintf(buf, "%s", input);
    return 0;
}
