#include <cstdlib>
#include <iostream>
#include <string>

std::string get_env_value() {
    const char* val = std::getenv("APP_SECRET");
    return val ? std::string(val) : "";
}

void execute_command(const std::string& cmd) {
    std::system(cmd.c_str());
}

void safe_flow() {
    std::string val = get_env_value();
    std::cout << "Value: " << val << std::endl;
}

void unsafe_flow() {
    std::string val = get_env_value();
    execute_command(val);
}

int main() {
    safe_flow();
    unsafe_flow();
    return 0;
}
