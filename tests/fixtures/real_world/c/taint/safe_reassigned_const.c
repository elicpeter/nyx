#include <stdlib.h>

void run() {
    char* cmd = getenv("CMD");
    cmd = "safe";
    system(cmd);
}
