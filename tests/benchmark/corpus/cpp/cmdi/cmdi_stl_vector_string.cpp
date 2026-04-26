// Phase 2 (cpp-precision): tainted user input is stored in a
// std::vector<std::string>, then read back via `front()` and converted
// to a `char*` via `c_str()`.  The c_str() conversion must propagate
// taint from the receiver to the result so that the downstream
// `system()` shell sink fires.

#include <cstdlib>
#include <string>
#include <vector>

int main() {
    char *input = std::getenv("USER_CMD");
    std::vector<std::string> commands;
    commands.push_back(input);            // store tainted string

    std::string cmd = commands.front();   // load tainted string
    std::system(cmd.c_str());             // SHELL_ESCAPE sink
    return 0;
}
