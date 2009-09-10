#include "myproxy_common.h"

#define MAXARGS 20

pid_t
myproxy_popen(int fds[3], const char *path, ...)
{
    pid_t childpid;
    int p0[2], p1[2], p2[2];
    
    assert(path);

    if (access(path, X_OK) < 0) {
	verror_put_string("%s not executable", path);
	verror_put_errno(errno);
	return -1;
    }

    if (pipe(p0) < 0 || pipe(p1) < 0 || pipe(p2) < 0) {
	verror_put_string("pipe() failed");
	verror_put_errno(errno);
	return -1;
    }

    if ((childpid = fork()) < 0) {
	verror_put_string("fork() failed");
	verror_put_errno(errno);
	return -1;
    }
    
    if (childpid == 0) {	/* child */
	va_list ap;
	const char *argv[MAXARGS];
	int i=0;

	close(p0[1]); close(p1[0]); close(p2[0]);
	if (dup2(p0[0], 0) < 0 ||
	    dup2(p1[1], 1) < 0 ||
	    dup2(p2[1], 2) < 0)	{
	    perror("dup2");
	    exit(1);
	}
	argv[i++] = path;
	va_start(ap, path);
	while ((argv[i++] = va_arg(ap, const char *)) != NULL) {
	    assert(i < MAXARGS);
	}
	va_end(ap);
	execv(path, (char *const *)argv);
	fprintf(stderr, "failed to run %s: %s\n", path, strerror(errno));
	exit(1);
    }
    close(p0[0]); close(p1[1]); close(p2[1]);

    fds[0] = p0[1];
    fds[1] = p1[0];
    fds[2] = p2[0];

    return childpid;
}
