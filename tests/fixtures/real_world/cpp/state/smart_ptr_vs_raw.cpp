#include <memory>
#include <cstdlib>

void smart_clean() {
    auto ptr = std::make_unique<int>(42);
    // automatically cleaned up
}

void raw_leak() {
    int *ptr = new int(42);
    // never deleted
}
