#include <cstdlib>
#include <string>
#include <algorithm>
#include <vector>

void handle(const char* user_input) {
    std::string cmd(user_input);
    std::vector<int> v = {1, 2, 3};
    std::for_each(v.begin(), v.end(), [](int x) {
        if (x == 0) return; // lambda-local return
    });
    // This sink should still be reachable
    system(cmd.c_str());
}
