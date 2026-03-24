#include <stdlib.h>
#include <stdio.h>

int main() {
    char *msg = getenv("USER_MSG");
    printf(msg);
    return 0;
}
