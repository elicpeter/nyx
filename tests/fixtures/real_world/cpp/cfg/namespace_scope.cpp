#include <cstdlib>
#include <cstdio>

namespace security {
    void validate(const char *input) {
        if (input == nullptr) return;
    }
}

namespace execution {
    void run(const char *cmd) {
        system(cmd);
    }
}

void handler() {
    const char *user_input = std::getenv("USER_INPUT");
    security::validate(user_input);
    execution::run(user_input);
}
