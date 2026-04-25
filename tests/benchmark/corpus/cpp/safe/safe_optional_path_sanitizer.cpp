// cpp-safe-015: std::optional<std::string>-returning sanitiser.
#include <fstream>
#include <optional>
#include <string>

std::optional<std::string> sanitize_path(const std::string &s) {
    if (s.find("..") != std::string::npos
        || (!s.empty() && (s[0] == '/' || s[0] == '\\'))) {
        return std::nullopt;
    }
    return s;
}

void handle(const std::string &user_path) {
    auto safe = sanitize_path(user_path);
    if (!safe.has_value()) return;
    std::ifstream f(*safe);
}
