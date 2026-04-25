#include <stdlib.h>
#include <unistd.h>

int main() {
    char *path = getenv("PROG_PATH");
    execvp(path, NULL);
    return 0;
}
