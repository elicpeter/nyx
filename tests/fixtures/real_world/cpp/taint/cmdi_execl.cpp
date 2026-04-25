#include <cstdlib>
#include <unistd.h>

void run_user_program() {
    const char *prog = std::getenv("USER_PROGRAM");
    execl(prog, prog, nullptr);
}
