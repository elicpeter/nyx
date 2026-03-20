#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

std::string sanitize_data(const char *input) {
    std::string result;
    for (const char *p = input; *p; ++p) {
        if (std::isalnum(static_cast<unsigned char>(*p)) || *p == '_') {
            result += *p;
        }
    }
    return result;
}

int main() {
    const char *val = std::getenv("APP_NAME");
    if (val) {
        std::string safe = sanitize_data(val);
        char buf[256];
        std::strcpy(buf, safe.c_str());
        std::printf("App: %s\n", buf);
    }
    return 0;
}
