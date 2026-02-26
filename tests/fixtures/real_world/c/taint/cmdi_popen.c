#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void execute_cmd(char *user_input) {
    char cmd[256];
    sprintf(cmd, "grep -r '%s' /var/log/", user_input);
    FILE *fp = popen(cmd, "r");
    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        printf("%s", buf);
    }
    pclose(fp);
}
