
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
#ifdef DEC
#include <stdlib.h>
#endif
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#ifdef DEC
#include <sys/syslog_pri.h>
#else
#include <syslog.h>
#endif
#include <varargs.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

extern int sys_nerr;
extern char *sys_errlist[];
extern int errno;

static int logfd = -1;
static char *logident = NULL;
static int logopt = 0, logfac = 0;

static int openlogfd()
{
    int err;
    struct sockaddr_un ad;
    if (logfd >= 0)
	return 0;
    if ((logfd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0)
	return logfd;
    if (err = fcntl(logfd, F_SETFD, 1))
	return close(logfd), logfd = -1, err;
    ad.sun_family = AF_UNIX;
    strcpy(ad.sun_path, "/dev/log");
    if (err = connect(logfd, (struct sockaddr *) &ad, sizeof ad))
	return close(logfd), logfd = -1, err;
    return 0;
}

int openlog(ident, opt, facility)
#ifdef DEC
     const char *ident;
#else
     char *ident;
#endif
     int opt, facility;
{
    int err;
    char *p;
    if (opt & ~(LOG_PID | LOG_ODELAY | LOG_NDELAY | LOG_NOWAIT))
	return errno = EINVAL, -1;
    if (facility & ~LOG_FACMASK)
	return errno = EINVAL, -1;
    logopt = opt;
    logfac = facility;
    if ((p = malloc(strlen(ident) + 1)) == NULL)
	return -1;
    strcpy(p, ident);
    if (logident != NULL)
	free(logident);
    logident = p;
    if (logopt & LOG_NDELAY && (err = openlogfd()))
	return err;
    return 0;
}

int vsyslog(priority, message, ap)
     int priority;
#ifdef DEC
     const char *message;
#else
     char *message;
#endif
     va_list ap;
{
    int err;
    char *p, *q, s[4096], format[512];
    time_t tm;
    if ((priority & LOG_FACMASK) == 0)
	if (logfac)
	    priority |= logfac;
	else
	    priority |= LOG_USER;
    sprintf(s, "<%u>", priority & (LOG_FACMASK | LOG_PRIMASK));
    time(&tm);
    strftime(s + strlen(s), 17, "%b %e %T ", localtime(&tm));
    if (logident != NULL)
	strcat(s, logident);
    else
	strcat(s, "syslog");
    if (logopt & LOG_PID)
	sprintf(s + strlen(s), "[%u]", getpid());
    strcat(s, ": ");
    for (p = message, q = format; *p;)
	if (*p == '%')
	    if (p[1] == 'm') {
		strcpy(q, errno >= 0 && errno < sys_nerr ?
		       sys_errlist[errno] : "Unknown error");
		q = format + strlen(format);
		p += 2;
	    }
	    else {
		*q++ = *p++;
		while (strchr("$-+ #*0123456789.l", *p) != NULL)
		    *q++ = *p++;
		if (*p)
		    *q++ = *p++;
	    }
	else
	    *q++ = *p++;
    *q = 0;
    vsprintf(s + strlen(s), format, ap);
    strcat(s, "\n");
    if (err = openlogfd())
	return err;
    if ((err = send(logfd, s, strlen(s), 0)) < 0)
	return err;
    return 0;
}

int syslog(priority, message, va_alist)
     int priority;
     char *message;
     va_dcl
{
    int err;
    va_list ap;
    va_start(ap);
    err = vsyslog(priority, message, ap);
    va_end(ap);
    return err;
}

#ifdef DEC
void closelog()
{
    if (logfd > -1) {
	if (close(logfd) == 0)
	    logfd = -1;
    }
    return;
}
#else
int closelog()
{
    int err;
    if (logfd < 0)
	return 0;
    if ((err = close(logfd)) == 0)
	logfd = -1;
    return err;
}
#endif
