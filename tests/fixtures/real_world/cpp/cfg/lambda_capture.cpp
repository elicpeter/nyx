#include <cstdlib>
#include <functional>
#include <string>

std::function<void()> create_dangerous_lambda(const char *user_input) {
    std::string cmd = std::string("echo ") + user_input;
    return [cmd]() {
        system(cmd.c_str());
    };
}
