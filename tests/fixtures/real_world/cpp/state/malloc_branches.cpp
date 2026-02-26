#include <cstdlib>
#include <cstring>

void branch_leak(int flag) {
    char *buf = (char*)malloc(256);
    if (flag) {
        strcpy(buf, "hello");
        free(buf);
    }
    // buf leaked if !flag
}
