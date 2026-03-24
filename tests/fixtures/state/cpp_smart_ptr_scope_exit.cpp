#include <memory>

int use_ptr() {
    auto ptr = std::make_unique<int>(42);
    return *ptr;
    // unique_ptr destroyed at scope exit
}
