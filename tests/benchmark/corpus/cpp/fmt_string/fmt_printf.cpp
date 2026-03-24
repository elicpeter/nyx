#include <cstdlib>
#include <cstdio>

int main() {
    char *msg = getenv("USER_MSG");
    printf(msg);
    return 0;
}
