#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ───── Configuration loader ─────
 * Reads config from environment and files, uses values in system calls.
 */

#define MAX_PATH 4096
#define MAX_CMD  2048
#define MAX_BUF  256

/* VULN: getenv → system (command injection via environment) */
void run_maintenance_task(void) {
    char *cmd = getenv("MAINTENANCE_CMD");
    if (cmd != NULL) {
        system(cmd);
    }
}

/* VULN: getenv → popen (command injection via environment) */
FILE *check_service_status(void) {
    char *service = getenv("SERVICE_NAME");
    char cmd[MAX_CMD];
    sprintf(cmd, "systemctl status %s", service);
    return popen(cmd, "r");
}

/* VULN: getenv flows into sprintf, then system (multi-hop taint) */
void deploy_package(void) {
    char *repo_url = getenv("PACKAGE_REPO");
    char *pkg_name = getenv("PACKAGE_NAME");
    char cmd[MAX_CMD];
    sprintf(cmd, "curl -sL %s/%s.tar.gz | tar xz -C /opt", repo_url, pkg_name);
    system(cmd);
}

/* ───── Network input handling ─────
 * Simulates reading from a socket and processing the data.
 */

/* VULN: fgets (stdin/file source) → strcpy (buffer overflow) */
void handle_client_request(FILE *client_stream) {
    char input[MAX_BUF];
    char request_path[64];
    char query_string[64];

    fgets(input, sizeof(input), client_stream);

    /* Parse the request line — vulnerable string operations */
    strcpy(request_path, input);        /* VULN: strcpy no bounds check */
    strcat(request_path, "/index.html");/* VULN: strcat can overflow */

    /* Build a log message */
    char log_msg[128];
    sprintf(log_msg, "Request: %s from client", request_path); /* VULN: sprintf overflow */
    printf("%s\n", log_msg);
}

/* VULN: scanf with %s has no width limit (buffer overflow) */
void read_username(void) {
    char username[32];
    printf("Username: ");
    scanf("%s", username);

    char greeting[64];
    sprintf(greeting, "Hello, %s! Welcome back.", username);
    printf("%s\n", greeting);
}

/* VULN: gets is always unsafe (removed in C11 but still in legacy code) */
void read_legacy_input(void) {
    char buffer[128];
    printf("Enter command: ");
    gets(buffer);
    system(buffer);
}

/* ───── File processing ─────
 * Reads configuration files and processes their contents.
 */

/* VULN: fgets → sprintf chain (taint from file through format string) */
void process_config_file(const char *config_path) {
    FILE *f = fopen(config_path, "r");
    if (!f) return;

    char line[256];
    char processed[512];

    while (fgets(line, sizeof(line), f) != NULL) {
        /* Strip newline */
        line[strcspn(line, "\n")] = 0;

        /* Build a command from config line — taint propagates */
        sprintf(processed, "configure --set %s", line);

        /* Execute the constructed command */
        system(processed);
    }
    fclose(f);
}

/* VULN: getenv → execvp (command injection) */
void run_custom_shell(void) {
    char *shell = getenv("CUSTOM_SHELL");
    char *args[] = { shell, "-c", "echo started", NULL };
    execvp(shell, args);
}
