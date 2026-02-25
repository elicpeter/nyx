// Positive fixture: each snippet should trigger the named pattern.
#include <cstdlib>
#include <cstring>
#include <cstdio>

// cpp.memory.gets
void trigger_gets() {
    char buf[64];
    gets(buf);
}

// cpp.memory.strcpy
void trigger_strcpy(const char *src) {
    char dst[32];
    strcpy(dst, src);
}

// cpp.memory.strcat
void trigger_strcat(const char *extra) {
    char buf[64] = "prefix";
    strcat(buf, extra);
}

// cpp.memory.sprintf
void trigger_sprintf(const char *name) {
    char buf[128];
    sprintf(buf, "Hello %s", name);
}

// cpp.cmdi.system
void trigger_system(const char *cmd) {
    system(cmd);
}

// cpp.memory.reinterpret_cast
void trigger_reinterpret_cast() {
    int x = 42;
    float *fp = reinterpret_cast<float*>(&x);
}

// cpp.memory.const_cast
void trigger_const_cast(const int *p) {
    int *q = const_cast<int*>(p);
}

// cpp.memory.printf_no_fmt
void trigger_printf_no_fmt(char *user_data) {
    printf(user_data);
}
