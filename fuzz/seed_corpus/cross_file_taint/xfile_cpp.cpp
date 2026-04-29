	#include <string>
int main() {
    std::string x = nyx_taint_source();
    nyx_dangerous_sink(x);
    std::string y = nyx_sanitize(nyx_taint_source());
    nyx_dangerous_sink(y);
    return 0;
}
