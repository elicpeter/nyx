// cpp-safe-016: cross-function bool-returning validator with rejection.
#include <fstream>
#include <string>

bool validate_no_dotdot(const std::string &s) {
    return s.find("..") == std::string::npos
        && (s.empty() || (s[0] != '/' && s[0] != '\\'));
}

void handle(const std::string &user_path) {
    if (!validate_no_dotdot(user_path)) return;
    std::ifstream f(user_path);
}
