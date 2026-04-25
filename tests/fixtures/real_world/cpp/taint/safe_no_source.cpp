#include <cstdio>
#include <cstring>

int main() {
    const char *label = "status";
    const char *value = "ok";
    char buf[256];
    std::sprintf(buf, "%s: %s", label, value);
    std::printf("%s\n", buf);
    return 0;
}
