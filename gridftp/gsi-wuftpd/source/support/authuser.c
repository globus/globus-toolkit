/****************************************************************************  
 
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
  
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994
    The Regents of the University of California.
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.
  Portions Copyright (c) 1998 Sendmail, Inc.
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.
  Portions Copyright (c) 1997 by Stan Barber.
  Portions Copyright (c) 1997 by Kent Landfield.
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997
    Free Software Foundation, Inc.  
 
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.org/license.html.
 
  $Id$
 
****************************************************************************/
#include "../src/config.h"

#ifdef USE_RFC931

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef AIX
#include <netinet/if_ether.h>
#include <net/if_dl.h>
#endif
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>

extern unsigned int timeout_rfc931;

extern int errno;

#include "authuser.h"

unsigned short auth_tcpport = 113;

#define SIZ 500			/* various buffers */

static int usercmp(register char *u, register char *v)
{
    /* is it correct to consider Foo and fOo the same user? yes */
    /* but the function of this routine may change later */
    while (*u && *v)
	if (tolower(*u) != tolower(*v))
	    return tolower(*u) - tolower(*v);
	else
	    ++u, ++v;
    return *u || *v;
}

static char authline[SIZ];

char *auth_xline(register char *user, register int fd, register long unsigned int *in)
{
    unsigned short local;
    unsigned short remote;
    register char *ruser;

    if (auth_fd(fd, in, &local, &remote) == -1)
	return 0;
    ruser = auth_tcpuser(*in, local, remote);
    if (!ruser)
	return 0;
    if (!user)
	user = ruser;		/* forces X-Auth-User */
    (void) sprintf(authline,
	    (usercmp(ruser, user) ? "X-Forgery-By: %s" : "X-Auth-User: %s"),
		   ruser);
    return authline;
}

int auth_fd(register int fd, register long unsigned int *in, register short unsigned int *local, register short unsigned int *remote)
{
    struct sockaddr_in sa;
#if defined(UNIXWARE) || defined(AIX)
    size_t dummy;
#else
    int dummy;
#endif

    dummy = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *) &sa, &dummy) == -1)
	return -1;
    if (sa.sin_family != AF_INET) {
	errno = EAFNOSUPPORT;
	return -1;
    }
    *local = ntohs(sa.sin_port);
    dummy = sizeof(sa);
    if (getpeername(fd, (struct sockaddr *) &sa, &dummy) == -1)
	return -1;
    *remote = ntohs(sa.sin_port);
    *in = sa.sin_addr.s_addr;
    return 0;
}

static char ruser[SIZ];
static char realbuf[SIZ];
static char *buf;

static int fdAuth = -1;

static void timout(int sig)
{
    if (fdAuth != -1) {
	close(fdAuth);
	fdAuth = -1;
    }
}

char *auth_tcpuser(register long unsigned int in, register short unsigned int local, register short unsigned int remote)
{
    struct sockaddr_in sa;
    register int buflen;
    register int w;
    register int saveerrno;
    char ch;
    unsigned short rlocal;
    unsigned short rremote;
    extern struct sockaddr_in ctrl_addr;
    int on = 1;

    buf = realbuf;
    (void) sprintf(buf, "%u , %u\r\n", (unsigned int) remote, (unsigned int) local);
    /* note the reversed order---the example in the RFC is misleading */
    buflen = strlen(buf);

    if ((fdAuth = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	return 0;

    setsockopt(fdAuth, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));	/*Try */

    sa = ctrl_addr;
    sa.sin_port = htons(0);
    bind(fdAuth, (struct sockaddr *) &sa, sizeof(sa));	/* may as well try ... */

    sa.sin_family = AF_INET;
    sa.sin_port = htons(auth_tcpport);
    sa.sin_addr.s_addr = in;

    signal(SIGALRM, timout);

#if defined(LINUX)
    /*
     * The default behaviour of signal() under modern glibc implementations is
     * to have SA_RESTART on by default.  This prevents the alarm() call from
     * interrupting the connect() call, which then, in the case of a firewall,
     * causes the connect() to take minutes to time out, in turn leading to
     * frustrated inbound clients.
     */
    {
	struct sigaction old, new;
	sigaction(SIGALRM, NULL, &old);
	new = old;
	new.sa_flags &= ~SA_RESTART;
	sigaction(SIGALRM, &new, &old);
    }
#endif
    alarm(timeout_rfc931);
    if (connect(fdAuth, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
	saveerrno = errno;
	alarm(0);
	if (fdAuth != -1) {
	    close(fdAuth);
	    fdAuth = -1;
	}
	errno = saveerrno;
	return 0;
    }

    while ((w = write(fdAuth, buf, buflen)) < buflen)
	if (w == -1) {		/* should we worry about 0 as well? */
	    saveerrno = errno;
	    alarm(0);
	    if (fdAuth != -1) {
		close(fdAuth);
		fdAuth = -1;
	    }
	    errno = saveerrno;
	    return 0;
	}
	else {
	    buf += w;
	    buflen -= w;
	}

    buf = realbuf;
    while ((w = read(fdAuth, &ch, 1)) == 1) {
	*buf = ch;
	if ((ch != ' ') && (ch != '\t') && (ch != '\r'))
	    ++buf;
	if ((buf - realbuf == sizeof(realbuf) - 1) || (ch == '\n'))
	    break;
    }

    saveerrno = errno;
    alarm(0);
    if (fdAuth != -1) {
	close(fdAuth);
	fdAuth = -1;
    }
    errno = saveerrno;

    if (w == -1)
	return 0;

    *buf = '\0';

/* H* fix: limit scanf of returned identd string. */
    if (sscanf(realbuf, "%hd,%hd: USERID :%*[^:]:%400s",
	       &rremote, &rlocal, ruser) < 3) {
	errno = EIO;
	/* makes sense, right? well, not when USERID failed to match
	   ERROR but there's no good error to return in that case */
	return 0;
    }
    if ((remote != rremote) || (local != rlocal)) {
	errno = EIO;
	return 0;
    }
    /* XXX: we're not going to do any backslash processing */
    return ruser;
}

#else /* USE_RFC931 */

int auth_dummy_variable = 0;	/* To keep compilers quiet */

#endif /* USE_RFC931 */
