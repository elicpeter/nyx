// Phase 4 (cpp-precision): a tainted env var flows through an
// inline-defined class member function into `std::system()`.
//
// Pre-Phase-4, the C++ KINDS map left `class_specifier` unmapped,
// which made the CFG walker treat the entire class declaration as a
// single leaf `Seq` node — inline member-function bodies were never
// extracted as separate functions and intra-file calls like
// `inner.run(input)` could not resolve to the body summary.
//
// With `class_specifier` (and `struct_specifier`/`union_specifier`/
// `enum_specifier`/`template_declaration`/`linkage_specification`)
// mapped to `Kind::Block`, the walker descends into the body and
// inline methods participate in summary resolution.

#include <cstdlib>

class Inner {
public:
    void run(const char* arg) {
        std::system(arg);              // SHELL_ESCAPE sink
    }
};

int main() {
    char *input = std::getenv("USER_CMD");
    Inner inner;
    inner.run(input);                  // resolves to Inner::run
    return 0;
}
