// Synthetic recall guard for the PathPrefixConfined precision fix.
//
// A strncmp() prefix check confines only its subject.  Here the check is on an
// unrelated copy (`other`), while the tainted `path` flows to fopen() with no
// confinement — the finding must still fire.  Guards against the confinement
// clearing FILE_IO on the wrong variable (the value-scoping that distinguishes
// the uftpd bug `strncmp(dir, …)` from the fix `strncmp(rpath, …)`).
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

void handle(int sd) {
    char other[256];
    char path[256];
    recv(sd, path, sizeof path - 1, 0);
    strncpy(other, path, sizeof other);
    if (strncmp(other, "/srv/ftp", strlen("/srv/ftp")))
        return;
    FILE *fp = fopen(path, "rb");
    if (fp)
        fclose(fp);
}
