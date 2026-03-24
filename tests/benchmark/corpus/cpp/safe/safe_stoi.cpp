#include <cstdlib>
#include <cstdio>
#include <string>

int main() {
    char *input = getenv("PORT_NUM");
    int port = std::stoi(input);
    printf("Port: %d\n", port);
    return 0;
}
