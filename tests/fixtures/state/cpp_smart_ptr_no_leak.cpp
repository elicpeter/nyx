#include <memory>

void smart() {
    auto ptr = std::make_unique<int>(42);
    // automatically cleaned up by unique_ptr destructor
}
