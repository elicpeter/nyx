#include <memory>

void wrap_raw() {
    std::unique_ptr<int> ptr(new int(42));
    // unique_ptr manages the raw pointer — no leak
}
