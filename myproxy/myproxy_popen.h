/*
 * myproxy_popen.h
 *
 * Provide a safe popen substitute.
 *
 */

#ifndef __MYPROXY_POPEN_H
#define __MYPROXY_POPEN_H

/*
 * myproxy_popen()
 *
 * Run the program at the specified path with the specified arguments
 * (3rd argument is argv[1], 4th argument is argv[2]).
 * The final argument must be NULL.
 * Returns pid of the child process on success.
 * Returns -1 on failure and sets verror.
 * On success, fds[0] is a pipe connected to the child's stdin for writing
 *             fds[1] is a pipe connected to the child's stdout for reading
 *             fds[2] is a pipe connected to the child's stderr for reading
 * The caller should reap the child via waitpid() and close the three pipes.
 */
pid_t myproxy_popen(int fds[3], const char *path, ...);

#endif /* __MYPROXY_POPEN_H */
