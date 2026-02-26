#include <fstream>
#include <cstdio>
#include <string>

std::string read_raii(const char *path) {
    std::ifstream file(path);
    std::string content;
    std::getline(file, content);
    return content;
    // RAII: ifstream destructor closes
}

std::string read_manual(const char *path) {
    FILE *f = fopen(path, "r");
    char buf[256];
    fgets(buf, sizeof(buf), f);
    // f not closed -- manual leak
    return std::string(buf);
}
