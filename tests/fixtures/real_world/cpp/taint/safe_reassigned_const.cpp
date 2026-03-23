#include <cstdlib>

void run() {
    char* cmd = std::getenv("CMD");
    cmd = "safe";
    system(cmd);
}
