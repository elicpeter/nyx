// Phase 3 (cpp-precision): tainted user input flows through a C++ lambda
// that returns its argument unchanged. The default Call-arg propagation
// in the SSA taint engine carries the argument's taint into the result,
// so the downstream system() shell sink fires.
//
// This fixture pins the "lambda as identity-passthrough" behaviour;
// captures and lambda-body sanitisation through summaries are separate
// Phase 7 / summary work and are deliberately not exercised here.

#include <cstdlib>
#include <string>

int main() {
    char *input = std::getenv("USER_CMD");
    auto echo = [](const char* s) { return s; };
    std::system(echo(input));         // SHELL_ESCAPE sink — must fire
    return 0;
}
