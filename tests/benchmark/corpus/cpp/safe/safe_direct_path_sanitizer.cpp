// cpp-safe-014: direct-return path sanitiser.
#include <fstream>
#include <string>

std::string sanitize_path(const std::string &s) {
    if (s.find("..") != std::string::npos
        || (!s.empty() && (s[0] == '/' || s[0] == '\\'))) {
        return "";
    }
    return s;
}

void handle(const std::string &user_path) {
    std::string safe = sanitize_path(user_path);
    std::ifstream f(safe);
}
