#include <cstdlib>
#include <string>

int main() {
    char *cmd = getenv("USER_CMD");
    system(cmd);
    return 0;
}
