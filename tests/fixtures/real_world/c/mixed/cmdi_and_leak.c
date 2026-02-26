#include <stdio.h>
#include <stdlib.h>

void dangerous_pipe(char *user_input) {
    char cmd[256];
    sprintf(cmd, "cat %s", user_input);
    FILE *fp = popen(cmd, "r");
    char buf[1024];
    fgets(buf, sizeof(buf), fp);
    printf("%s", buf);
    // pclose missing + command injection
}
