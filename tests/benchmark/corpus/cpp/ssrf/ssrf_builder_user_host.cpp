// Phase 5 (cpp-precision): a tainted env var flows through a fluent
// builder chain (`Socket::builder().host(h).port(p).connect()`). The
// terminal `.connect()` is the SSRF sink; the chained `.host(...)` /
// `.port(...)` calls return the receiver and carry argument taint
// onto the chain via the engine's default Call-arg propagation, so
// the tainted host reaches the connect sink.

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
    char *user_host = std::getenv("REMOTE_HOST");
    Socket::builder().host(user_host).port(8080).connect();   // SSRF sink
    return 0;
}
