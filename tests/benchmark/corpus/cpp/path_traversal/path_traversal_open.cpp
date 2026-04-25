#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

int main() {
    char *path = getenv("FILE_PATH");
    int fd = open(path, O_RDONLY);
    close(fd);
    return 0;
}
