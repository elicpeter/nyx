#include <cstdlib>
#include <iostream>
#include <string>

int main() {
    std::string cmd;
    std::getline(std::cin, cmd);
    system(cmd.c_str());
    return 0;
}
