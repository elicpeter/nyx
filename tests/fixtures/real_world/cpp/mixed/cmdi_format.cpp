#include <cstdio>
#include <cstdlib>
#include <string>

void dangerous(const char *user_input) {
    char cmd[256];
    sprintf(cmd, "cat %s", user_input);
    system(cmd);
    printf(user_input);  // also format string vuln
}
