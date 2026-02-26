/* Positive fixture: each snippet should trigger the named pattern. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* c.memory.gets */
void trigger_gets() {
    char buf[64];
    gets(buf);
}

/* c.memory.strcpy */
void trigger_strcpy(char *src) {
    char dst[32];
    strcpy(dst, src);
}

/* c.memory.strcat */
void trigger_strcat(char *extra) {
    char buf[64] = "prefix";
    strcat(buf, extra);
}

/* c.memory.sprintf */
void trigger_sprintf(const char *name) {
    char buf[128];
    sprintf(buf, "Hello %s", name);
}

/* c.memory.scanf_percent_s */
void trigger_scanf() {
    char name[32];
    scanf("%s", name);
}

/* c.cmdi.system */
void trigger_system(const char *cmd) {
    system(cmd);
}

/* c.cmdi.popen */
void trigger_popen(const char *cmd) {
    FILE *f = popen(cmd, "r");
    pclose(f);
}

/* c.memory.printf_no_fmt */
void trigger_printf_no_fmt(char *user_data) {
    printf(user_data);
}
