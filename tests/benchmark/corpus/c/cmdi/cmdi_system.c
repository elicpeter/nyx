#include <stdlib.h>
#include <stdio.h>

int main() {
    char *cmd = getenv("USER_CMD");
    system(cmd);
    return 0;
}
