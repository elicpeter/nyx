#include <cstdlib>
#include <cstdio>

int main() {
    char *msg = getenv("USER_MSG");
    fprintf(stderr, msg);
    return 0;
}
