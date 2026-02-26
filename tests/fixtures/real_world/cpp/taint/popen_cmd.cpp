#include <cstdio>
#include <cstdlib>
#include <string>

void run_command(const std::string &user_input) {
    std::string cmd = "grep " + user_input + " /var/log/syslog";
    FILE *fp = popen(cmd.c_str(), "r");
    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        printf("%s", buf);
    }
    pclose(fp);
}
