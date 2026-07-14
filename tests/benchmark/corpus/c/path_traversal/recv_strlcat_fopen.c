// Synthetic regression fixture for C string-builder taint passthrough.
//
// Mirrors the uftpd CVE-2020-5221 flow shape: a network read fills a buffer,
// strlcat() assembles it into a filesystem path, and fopen() opens the path.
// Pins that taint propagates through the strlcat *destination* out-param
// (labels/c.rs ARG_PROPAGATIONS) — without it the assembled path reads clean.
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

void handle(int sd) {
    char msg[256];
    char path[512] = "/srv/ftp/";
    recv(sd, msg, sizeof msg - 1, 0);
    strlcat(path, msg, sizeof path);
    FILE *fp = fopen(path, "rb");
    if (fp)
        fclose(fp);
}
