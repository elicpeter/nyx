#include <cstdlib>
#include <string>

int main() {
    char *home = std::getenv("HOME");
    std::string cmd = "ls " + std::string(home);
    system(cmd.c_str());
    return 0;
}
