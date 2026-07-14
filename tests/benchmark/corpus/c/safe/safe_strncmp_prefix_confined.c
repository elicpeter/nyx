// Synthetic precision fixture for intra-function C path-prefix confinement.
//
// A strncmp() prefix check on the tainted path before fopen() confines it to a
// fixed directory prefix (uftpd CVE-2020-5221 fix idiom).  Pins that
// PredicateKind::PathPrefixConfined clears Cap::FILE_IO on the confined
// (starts-with) branch, so no path-traversal finding fires here.
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

void handle(int sd) {
    char path[256];
    recv(sd, path, sizeof path - 1, 0);
    if (strncmp(path, "/srv/ftp", strlen("/srv/ftp")))
        return;
    FILE *fp = fopen(path, "rb");
    if (fp)
        fclose(fp);
}
