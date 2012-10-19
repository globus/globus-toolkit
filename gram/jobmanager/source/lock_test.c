#include "globus_common.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    int                                 fd;
    int                                 rc;
    struct flock                        fl;
    pid_t                               pid;
    int                                 child_status;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s lock-file-path\n", argv[0]);
        rc = EXIT_FAILURE;
        goto arg_failed;
    }

    fd = open(argv[1], O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

    if (fd < 0)
    {
        perror("open");
        rc = EXIT_FAILURE;
        goto open_failed;
    }
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    rc = fcntl(fd, F_SETLKW, &fl);
    if (rc < 0)
    {
        perror("fcntl");
        rc = EXIT_FAILURE;
        goto fcntl_failed;
    }

    pid = fork();

    if (pid < 0)
    {
        perror("fork");
        rc = EXIT_FAILURE;
        goto fork_failed;
    }
    else if (pid == 0)
    {
        errno=0;
        fl.l_start = 0;
        fl.l_len = 0;
        fl.l_pid = 0;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;

        rc = fcntl(fd,F_SETLK, &fl);
        if (rc == 0 || (errno != EACCES && errno != EAGAIN))
        {
            perror("fcntl");
            rc = EXIT_FAILURE;
            goto child_lock_failed;
        }
        else
        {
            rc = 0;
            rc = EXIT_SUCCESS;
        }
    }
    else
    {
        pid = wait(&child_status);
        if (pid < 0)
        {
            perror("wait");
            rc = EXIT_FAILURE;

            goto wait_failed;
        }
        else
        {
            rc = EXIT_SUCCESS;
        }
    }
wait_failed:
child_lock_failed:
fork_failed:
fcntl_failed:
    close(fd);
    remove(argv[1]);
open_failed:
arg_failed:
    exit(rc);
}
