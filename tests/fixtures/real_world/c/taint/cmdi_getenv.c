#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_from_env() {
    char *cmd = getenv("USER_CMD");
    system(cmd);
}

void run_safe() {
    char *cmd = getenv("USER_CMD");
    if (cmd == NULL) return;
    if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "date") == 0) {
        system(cmd);
    }
}
