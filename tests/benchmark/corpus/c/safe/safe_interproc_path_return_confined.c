// Synthetic precision fixture for INTERPROCEDURAL C path-return confinement.
//
// The uftpd CVE-2020-5221 fix shape: a helper confines its returned path with
// strncmp(rpath, prefix, strlen(prefix)) before `return rpath`, and a separate
// handler opens the returned path.  Pins that the summary-level
// `confines_path_return` post-condition carries the intra-function
// PathPrefixConfined narrowing across the return, so the cross-function
// fopen() stays silent.  The confinement lives in compose_path(); the sink is
// in handle_RETR() — the interproc hop the intra-function narrowing missed.
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
	if (strncmp(rpath, home, strlen(home)))
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
