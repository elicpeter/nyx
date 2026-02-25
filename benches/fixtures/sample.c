#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* get_env_value(void) {
    return getenv("SECRET");
}

void execute_command(const char* cmd) {
    system(cmd);
}

void safe_flow(void) {
    char* val = get_env_value();
    if (val != NULL) {
        printf("Value: %s\n", val);
    }
}

void unsafe_flow(void) {
    char* val = get_env_value();
    if (val != NULL) {
        execute_command(val);
    }
}

int main(void) {
    safe_flow();
    unsafe_flow();
    return 0;
}
