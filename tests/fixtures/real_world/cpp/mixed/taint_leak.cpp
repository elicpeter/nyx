#include <cstdlib>
#include <cstdio>

void env_leak() {
    const char *path = std::getenv("USER_PATH");
    FILE *f = fopen(path, "r");
    char buf[1024];
    fgets(buf, sizeof(buf), f);
    // taint (getenv -> fopen) + resource leak
}
