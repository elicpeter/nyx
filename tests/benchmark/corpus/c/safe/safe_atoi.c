#include <stdlib.h>
#include <stdio.h>

int main() {
    char *input = getenv("PORT_NUM");
    int port = atoi(input);
    printf("Port: %d\n", port);
    return 0;
}
