#include <cstdlib>

[[authenticated]]
void handle_request(const char* req) {
    std::system("service restart");
}
