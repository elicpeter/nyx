#include <cstdlib>

int main() {
    char *cmd = getenv("USER_CMD");
    cmd = "echo hello";
    system(cmd);
    return 0;
}
