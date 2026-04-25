#include <cstdio>
#include <cstring>

int main() {
    char buf[256];
    std::strcpy(buf, "constant value");
    std::strcat(buf, " appended");
    std::sprintf(buf, "Hello, %s!", "world");
    std::printf("%s\n", buf);
    return 0;
}
