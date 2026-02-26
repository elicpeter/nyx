#include <cstdio>
#include <stdexcept>

void process_file(const char *path) {
    FILE *f = fopen(path, "r");
    try {
        char buf[256];
        if (fgets(buf, sizeof(buf), f) == NULL) {
            throw std::runtime_error("read failed");
        }
        fclose(f);
    } catch (...) {
        // f leaked in catch
        throw;
    }
}

void process_safe(const char *path) {
    FILE *f = fopen(path, "r");
    try {
        char buf[256];
        if (fgets(buf, sizeof(buf), f) == NULL) {
            fclose(f);
            throw std::runtime_error("read failed");
        }
        fclose(f);
    } catch (...) {
        throw;
    }
}
