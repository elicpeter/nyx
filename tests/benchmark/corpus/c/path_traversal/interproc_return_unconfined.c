// Synthetic recall guard for INTERPROCEDURAL C path-return confinement.
//
// The uftpd CVE-2020-5221 BUG shape: the helper confines the *unresolved* `dir`
// (`strncmp(dir, ...)`) — a different var than the returned `rpath` — so the
// returned path is NOT confined and the cross-function fopen() must still fire.
// Guards `confines_path_return` against firing when the confinement subject
// does not match the returned value's name (the bug/fix discriminator).
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static char *home = "/srv/ftp";

char *compose_path(char *cwd, char *path)
{
	static char rpath[4096];
	char dir[4096] = { 0 };
	strlcpy(dir, cwd, sizeof(dir));
	strlcat(dir, path, sizeof(dir));
	if (!realpath(dir, rpath))
		return NULL;
	if (strncmp(dir, home, strlen(home)))
		return NULL;
	return rpath;
}

void handle_RETR(char *cwd, char *file)
{
	int authed = check_auth(cwd);
	if (!authed)
		return;
	char *path = compose_path(cwd, file);
	if (!path)
		return;
	FILE *fp = fopen(path, "rb");
	if (fp)
		fclose(fp);
}

int main(int argc, char **argv)
{
	char msg[512];
	recv(0, msg, sizeof msg - 1, 0);
	handle_RETR(argv[1], msg);
	return 0;
}
