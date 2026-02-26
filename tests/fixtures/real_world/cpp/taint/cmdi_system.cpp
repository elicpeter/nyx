#include <cstdlib>
#include <string>

void execute_user_cmd() {
    const char *cmd = std::getenv("USER_CMD");
    system(cmd);
}

void execute_safe() {
    const char *cmd = std::getenv("USER_CMD");
    if (cmd == nullptr) return;
    std::string s(cmd);
    if (s == "ls" || s == "date") {
        system(cmd);
    }
}
