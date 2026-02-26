// Negative fixture: none of these should trigger security patterns.
#include <cstdio>
#include <cstring>
#include <string>

void safe_string_ops() {
    std::string s = "hello";
    std::string copy = s;
    auto len = s.length();
}

void safe_cast() {
    double d = 3.14;
    int i = static_cast<int>(d);
}

void safe_snprintf(const char *name) {
    char buf[128];
    snprintf(buf, sizeof(buf), "Hello %s", name);
}

void safe_printf_literal() {
    printf("Hello %s\n", "world");
}
