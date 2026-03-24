#include <stdlib.h>
#include <string.h>

int main() {
    char *input = getenv("USER_INPUT");
    char buf[64] = "prefix: ";
    strcat(buf, input);
    return 0;
}
