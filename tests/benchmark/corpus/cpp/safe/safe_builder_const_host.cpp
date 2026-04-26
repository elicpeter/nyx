// Phase 5 (cpp-precision): a fluent builder chain whose host is a
// hardcoded literal. Even though `.connect()` is an SSRF sink, the
// host carries no taint, so the engine must not fire on this chain.
// Counterpart to `ssrf_builder_user_host.cpp`.

#include <cstdlib>
#include <string>

class Socket {
public:
    static Socket builder() { return Socket(); }
    Socket& host(const std::string& h) { host_ = h; return *this; }
    Socket& port(int p) { port_ = p; return *this; }
    void connect() {}
private:
    std::string host_;
    int port_ = 0;
};

int main() {
    Socket::builder().host("api.example.com").port(8080).connect();
    return 0;
}
