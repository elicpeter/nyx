// Phase 1 (cpp-precision): a tainted env var is sanitised through
// `std::stoi` *before* being stored in a `std::vector<int>`. The vector
// itself is treated by the engine as a Store/Load container, but every
// value flowing through it is a sanitised integer, so neither the
// sprintf nor the `system()` sink should fire.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

int main() {
    char *input = std::getenv("PORT_NUM");
    int port = std::stoi(input);          // sanitiser: clears Cap::all()

    std::vector<int> ports;
    ports.push_back(port);                // store sanitised int

    int p = ports.front();                // load sanitised int

    char buf[256];
    std::snprintf(buf, sizeof(buf), "ping -c 1 -p %d localhost", p);
    std::system(buf);                     // shell sink with no tainted data
    return 0;
}
