#include <cstdlib>
#include <cstdio>

int main() {
    char *cmd = getenv("USER_CMD");
    FILE *fp = popen(cmd, "r");
    pclose(fp);
    return 0;
}
