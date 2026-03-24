#include <stdlib.h>
#include <stdio.h>

int main() {
    char *msg = getenv("USER_MSG");
    fprintf(stderr, msg);
    return 0;
}
