#include "syshdrs.h"

int
GetSocketBufSize(int sockfd, size_t *const rsize, size_t *const ssize)
{
#ifdef SO_RCVBUF
	int rc = -1;
	int opt;
	int optsize;

	if (ssize != NULL) {
		opt = 0;
		optsize = sizeof(opt);
		rc = getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &opt, &optsize);
		if (rc == 0)
			*ssize = (size_t) opt;
		else
			*ssize = 0;
	}
	if (rsize != NULL) {
		opt = 0;
		optsize = sizeof(opt);
		rc = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &opt, &optsize);
		if (rc == 0)
			*rsize = (size_t) opt;
		else
			*rsize = 0;
	}
	return (rc);
#else
	if (ssize != NULL)
		*ssize = 0;
	if (rsize != NULL)
		*rsize = 0;
	return (-1);
#endif
}	/* GetSocketBufSize */




int
SetSocketBufSize(int sockfd, size_t rsize, size_t ssize)
{
#ifdef SO_RCVBUF
	int rc = -1;
	int opt;
	int optsize;

	if (ssize > 0) {
		opt = (int) ssize;
		optsize = sizeof(opt);
		rc = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &opt, optsize);
		if (rc < 0)
			return (rc);
	}
	if (rsize > 0) {
		opt = (int) rsize;
		optsize = sizeof(opt);
		rc = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &opt, optsize);
		if (rc < 0)
			return (rc);
	}
	return (0);
#else
	return (-1);
#endif
}	/* SetSocketBufSize */




int
GetSocketNagleAlgorithm(const int fd)
{
#ifndef TCP_NODELAY
	return (-1);
#else
	int optsize;
	int opt;

	opt = -2;
	optsize = (int) sizeof(opt);
	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &opt, &optsize) < 0)
		return (-1);
	return (opt);
#endif	/* TCP_NODELAY */
}	/* GetSocketNagleAlgorithm */





int
SetSocketNagleAlgorithm(const int fd, const int onoff)
{
#ifndef TCP_NODELAY
	return (-1);
#else
	int optsize;
	int opt;

	opt = onoff;
	optsize = (int) sizeof(opt);
	return (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &opt, optsize));
#endif	/* TCP_NODELAY */
}	/* SetSocketNagleAlgorithm */



int
GetSocketLinger(const int fd, int *const lingertime)
{
#ifndef SO_LINGER
	return (-1);
#else
	int optsize;
	struct linger opt;

	optsize = (int) sizeof(opt);
	opt.l_onoff = 0;
	opt.l_linger = 0;
	if (getsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &opt, &optsize) < 0)
		return (-1);
	if (lingertime != NULL)
		*lingertime = opt.l_linger;
	return (opt.l_onoff);
#endif	/* SO_LINGER */
}	/* GetSocketLinger */



int
SetSocketLinger(const int fd, const int l_onoff, const int l_linger)
{
#ifndef SO_LINGER
	return (-1);
#else
	struct linger opt;
	int optsize;
/*
 * From hpux:
 *
 * Structure used for manipulating linger option.
 *
 * if l_onoff == 0:
 *    close(2) returns immediately; any buffered data is sent later
 *    (default)
 * 
 * if l_onoff != 0:
 *    if l_linger == 0, close(2) returns after discarding any unsent data
 *    if l_linger != 0, close(2) does not return until buffered data is sent
 */
#if 0
struct	linger {
	int	l_onoff;		/* 0 = do not wait to send data */
					/* non-0 = see l_linger         */
	int	l_linger;		/* 0 = discard unsent data      */
					/* non-0 = wait to send data    */
};
#endif
	opt.l_onoff = l_onoff;
	opt.l_linger = l_linger;
	optsize = (int) sizeof(opt);
	return (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &opt, optsize));
#endif	/* SO_LINGER */
}	/* SetSocketLinger */
