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
#ifndef _SCO_DS			/* none of this is required on SCO OpenServer 5 */

/* Written in 1992, 1993 by Eduard Vopicka, Prague University of Economics */

#include "../src/config.h"

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/immu.h>
#include <sys/dir.h>		/* required by <sys/user.h> */
#include <sys/user.h>
#include <sys/signal.h>
#include <sys/fs/s5param.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <varargs.h>

static int KmemFd = -1;

kmem_open()
{
    if (KmemFd < 0 && (KmemFd = open("/dev/kmem", O_RDWR, 0)) < 0) {
	syslog(LOG_EMERG, "kmem open failed: %m");
	exit(1);
    }
}

int wrub(addr, off, len)
     char *addr;
     off_t off;
     int len;
{
    off_t seek_off = UVUBLK + off;
    kmem_open();		/* make sure it is open */
    if (lseek(KmemFd, (char *) seek_off, SEEK_SET) != seek_off) {
	syslog(LOG_EMERG, "lseek failed on /dev/kmem: %m");
	exit(1);
    }
    if (write(KmemFd, addr, len) != len) {
	syslog(LOG_EMERG, "write failed on /dev/kmem: %m");
	exit(1);
    }
    return (0);
}

/* UHUHUH, this crazy code is still required for 3.2v4.2 */

uid_t
seteuid(id)
     uid_t id;
{
    struct user u;
    return (wrub(&id, (off_t) & u.u_uid - (off_t) & u, sizeof(id)));
}

uid_t
setruid(id)
     uid_t id;
{
    struct user u;
    return (wrub(&id, (off_t) & u.u_ruid - (off_t) & u, sizeof(id)));
}


uid_t
setegid(id)
     uid_t id;
{
    struct user u;
    return (wrub(&id, (off_t) & u.u_gid - (off_t) & u, sizeof(id)));
}

uid_t
setrgid(id)
     uid_t id;
{
    struct user u;
    return (wrub(&id, (off_t) & u.u_rgid - (off_t) & u, sizeof(id)));
}

uid_t
setuid(id)
     uid_t id;
{
    (void) seteuid(id);
    (void) setruid(id);
    return (0);
}

uid_t
setgid(id)
     uid_t id;
{
    (void) setegid(id);
    (void) setrgid(id);
    return (0);
}

uid_t
setreuid(ruid, euid)
     uid_t ruid, euid;
{
    if (ruid != 0xffff)
	(void) setruid(ruid);
    if (euid != 0xffff)
	(void) seteuid(euid);
    return (0);
}

/*
 * Copyright (c) 1989, 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(SYSLOGFILE)

#include <sys/types.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <sys/syslog.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <varargs.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#ifndef CONSOLE
#define CONSOLE "/dev/console"
#endif

static int LogFile = -1;	/* fd for log */
static int LogStat = 0;		/* status bits, set by openlog() */
static char *LogTag = "syslog";	/* string to tag the entry with */
static int LogFacility = LOG_USER;	/* default facility code */
static int LogMask = 0xff;	/* mask of priorities to be logged */

syslog(va_alist)
     va_dcl
{
    va_list args;
    int pri;
    char *fmt;

    va_start(args);

    pri = va_arg(args, int);
    fmt = va_arg(args, char *);

    vsyslog(pri, fmt, args);

    va_end(args);
}

vsyslog(pri, fmt, ap)
     int pri;
     register char *fmt;
     va_list ap;
{
    extern int errno;
    register int cnt;
    register char *p;
    time_t now, time();
    int pid, saved_errno;
    char tbuf[2048], fmt_cpy[1024], *stdp, *ctime();

    sigset_t newmask, oldmask;

    saved_errno = errno;

#ifndef LOG_FAC
#define LOG_FAC(pri)    (((pri) & LOG_FACMASK) >> 3)
#endif
#ifndef LOG_PRI
#define LOG_PRI(pri)    ((pri) & LOG_PRIMASK)
#endif

    /* see if we should just throw out this message */
    if ((u_int) LOG_FAC(pri) >= (1 << LOG_NFACILITIES) ||
	(!(LOG_MASK(LOG_PRI(pri)) & LogMask)) ||
	(pri & ~(LOG_PRIMASK | LOG_FACMASK)))
	return;
    if (LogFile < 0)
	openlog(LogTag, LogStat | LOG_NDELAY, 0);

    /* set default facility if none specified */
    if ((pri & LOG_FACMASK) == 0)
	pri |= LogFacility;

    /* build the message */
    (void) time(&now);
    (void) sprintf(tbuf, "<%d>%.15s ", pri, ctime(&now) + 4);/**/
/*  (void)sprintf(tbuf, "%3o %.15s ", pri, ctime(&now) + 4); /**/
    for (p = tbuf; *p; ++p);
#ifndef LOG_PERROR
#define LOG_PERROR 0x20
#endif
    if (LogStat & LOG_PERROR)
	stdp = p;
    if (LogTag) {
	(void) strcpy(p, LogTag);
	for (; *p; ++p);
    }
    if (LogStat & LOG_PID) {
	(void) sprintf(p, "[%d]", getpid());
	for (; *p; ++p);
    }
    if (LogTag) {
	*p++ = ':';
	*p++ = ' ';
    }

    /* substitute error message for %m */
    {
	register char ch, *t1, *t2;
/*      char *strerror(); /* */

	for (t1 = fmt_cpy; ch = *fmt; ++fmt)
	    if (ch == '%' && fmt[1] == 'm') {
		++fmt;
		for (t2 = strerror(saved_errno);
		     *t1 = *t2++; ++t1);
	    }
	    else
		*t1++ = ch;
	*t1 = '\0';
    }

    (void) vsprintf(p, fmt_cpy, ap);

    cnt = strlen(tbuf);
    tbuf[cnt++] = '\n';

    /* output to stderr if requested */
    if (LogStat & LOG_PERROR)
	write(2, stdp, cnt - (stdp - tbuf));

    /* output the message to the local logger */
    if (write(LogFile, tbuf, cnt) == cnt)
	return;

    /* output the message to the console */
    pid = vfork();
    if (pid == -1)
	return;
    if (pid == 0) {
	int fd;
	int saveerrno;

	sigfillset(&newmask);
	sigdelset(&newmask, SIGALRM);
	(void) sigprocmask(SIG_SETMASK, &newmask, &oldmask);
	(void) signal(SIGALRM, SIG_DFL);
	(void) alarm((u_int) 5);
	fd = open(CONSOLE, O_WRONLY, 0);
	saveerrno = errno;
	(void) alarm((u_int) 0);
	errno = saveerrno;
	if (fd < 0)
	    return;
	(void) strcat(tbuf, "\r");
	p = index(tbuf, '>') + 1;
	(void) write(fd, p, cnt + 1 - (p - tbuf));
	(void) close(fd);
	_exit(0);
    }
    if (!(LogStat & LOG_NOWAIT))
	while ((cnt = wait((int *) 0)) > 0 && cnt != pid);
}

/*
 * OPENLOG -- open system log
 */
openlog(ident, logstat, logfac)
     char *ident;
     int logstat, logfac;
{
    if (ident != NULL)
	LogTag = ident;
    LogStat = logstat;
    if (logfac != 0 && (logfac & ~LOG_FACMASK) == 0)
	LogFacility = logfac;
    if (LogFile == -1) {
	LogFile = open(SYSLOGFILE, O_WRONLY | O_APPEND | O_SYNC);
								/**/
/*      LogFile = open(SYSLOGFILE, O_WRONLY|O_APPEND);      /**/
    }
}

/*
 * CLOSELOG -- close the system log
 */
closelog()
{
    (void) close(LogFile);
    LogFile = -1;
}

/*
 * SETLOGMASK -- set the log mask level
 */
setlogmask(pmask)
     int pmask;
{
    int omask;

    omask = LogMask;
    if (pmask != 0)
	LogMask = pmask;
    return (omask);
}

#endif /* defined(SYSLOGFILE) */

/* Need own getcwd() because of the way getcwd is implemented in SCO UNIX */

/*
 * Copyright (c) 1989, 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)getcwd.c    5.11 (Berkeley) 2/24/91";
#endif /* LIBC_SCCS and not lint */

#include <sys/param.h>

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_D_NAMLEN
#define DNAMLEN(dp) (dp->d_namlen)
#else
#define DNAMLEN(dp) (strlen(dp->d_name))
#endif

#define ISDOT(dp) \
    (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
        dp->d_name[1] == '.' && dp->d_name[2] == '\0'))

char *
     getcwd(pt, size)
     char *pt;
     int size;
{
    register struct dirent *dp;
    register DIR *dir;
    register dev_t dev;
    register ino_t ino;
    register int first;
    register char *bpt, *bup;
    struct stat s;
    dev_t root_dev;
    ino_t root_ino;
    size_t ptsize, upsize;
    int save_errno;
    char *ept, *eup, *up, *ptr;

    /*
     * If no buffer specified by the user, allocate one as necessary.
     * If a buffer is specified, the size has to be non-zero.  The path
     * is built from the end of the buffer backwards.
     */
    if (pt) {
	ptsize = 0;
	if (!size) {
	    errno = EINVAL;
	    return ((char *) NULL);
	}
	ept = pt + size;
    }
    else {
	if (!(pt = (char *) malloc(ptsize = 1024 - 4)))
	    return ((char *) NULL);
	ept = pt + ptsize;
    }
    bpt = ept - 1;
    *bpt = '\0';

    /*
     * Allocate bytes (1024 - malloc space) for the string of "../"'s.
     * Should always be enough (it's 340 levels).  If it's not, allocate
     * as necessary.  Special * case the first stat, it's ".", not "..".
     */
    if (!(up = (char *) malloc(upsize = 1024 - 4)))
	goto err;
    eup = up + MAXPATHLEN;
    bup = up;
    up[0] = '.';
    up[1] = '\0';

    /* Save root values, so know when to stop. */
    if (stat("/", &s))
	goto err;
    root_dev = s.st_dev;
    root_ino = s.st_ino;

    errno = 0;			/* XXX readdir has no error return. */

    for (first = 1;; first = 0) {
	/* Stat the current level. */
	if (lstat(up, &s))
	    goto err;

	/* Save current node values. */
	ino = s.st_ino;
	dev = s.st_dev;

	/* Check for reaching root. */
	if (root_dev == dev && root_ino == ino) {
	    *--bpt = '/';
	    /*
	     * It's unclear that it's a requirement to copy the
	     * path to the beginning of the buffer, but it's always
	     * been that way and stuff would probably break.
	     */
	    (void) bcopy(bpt, pt, ept - bpt);
	    free(up);
	    return (pt);
	}

	/*
	 * Build pointer to the parent directory, allocating memory
	 * as necessary.  Max length is 3 for "../", the largest
	 * possible component name, plus a trailing NULL.
	 */
	if (bup + 3 + MAXNAMLEN + 1 >= eup) {
	    off_t len = bup - up;
	    if (!(ptr = (char *) realloc(up, upsize *= 2)))
		goto err;
	    up = ptr;
	    bup = up + len;
	    eup = up + upsize;
	}
	*bup++ = '.';
	*bup++ = '.';
	*bup = '\0';

	/* Open and stat parent directory. */
	if (!(dir = opendir(up)) || fstat(dir->dd_fd, &s))
	    goto err;

	/* Add trailing slash for next directory. */
	*bup++ = '/';

	/*
	 * If it's a mount point, have to stat each element because
	 * the inode number in the directory is for the entry in the
	 * parent directory, not the inode number of the mounted file.
	 */
	save_errno = 0;
	if (s.st_dev == dev) {
	    for (;;) {
		if (!(dp = readdir(dir)))
		    goto notfound;
		if (dp->d_fileno == ino)
		    break;
	    }
	}
	else
	    for (;;) {
		if (!(dp = readdir(dir)))
		    goto notfound;
		if (ISDOT(dp))
		    continue;
		bcopy(dp->d_name, bup, DNAMLEN(dp) + 1);

		/* Save the first error for later. */
		if (lstat(up, &s)) {
		    if (!save_errno)
			save_errno = errno;
		    errno = 0;
		    continue;
		}
		if (s.st_dev == dev && s.st_ino == ino)
		    break;
	    }

	/*
	 * Check for length of the current name, preceding slash,
	 * leading slash.
	 */
	if (bpt - pt <= DNAMLEN(dp) + (first ? 1 : 2)) {
	    size_t len, off;

	    if (!ptsize) {
		errno = ERANGE;
		goto err;
	    }
	    off = bpt - pt;
	    len = ept - bpt;
	    if (!(ptr = (char *) realloc(pt, ptsize *= 2)))
		goto err;
	    pt = ptr;
	    bpt = pt + off;
	    ept = pt + ptsize;
	    (void) bcopy(bpt, ept - len, len);
	    bpt = ept - len;
	}
	if (!first)
	    *--bpt = '/';
	bpt -= DNAMLEN(dp);
	bcopy(dp->d_name, bpt, DNAMLEN(dp));
	(void) closedir(dir);

	/* Truncate any file name. */
	*bup = '\0';
    }

  notfound:
    /*
     * If readdir set errno, use it, not any saved error; otherwise,
     * didn't find the current directory in its parent directory, set
     * errno to ENOENT.
     */
    if (!errno)
	errno = save_errno ? save_errno : ENOENT;
    /* FALLTHROUGH */
  err:
    if (ptsize && !pt)
	free(pt);
    if (!up)
	free(up);
    return ((char *) NULL);
}

char *
     getwd(b)
     char *b;
{
    char *p;
    uid_t euid = geteuid();
    seteuid(0);
    getcwd(b, MAXPATHLEN);
    p = getcwd(b, MAXPATHLEN);
    seteuid(euid);
    return (p);
}

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if !defined(lint)
static char sccsid[] = "@(#)initgroups.c    5.6 (Berkeley) 6/1/90";
static char rcsid[] = "@(#)$Id$";
#endif /* !lint */

#include <stdio.h>

#include <grp.h>
#ifndef NGROUPS
#ifdef NGROUPS_MAX
#define NGROUPS  NGROUPS_MAX
#else /* !NGROUPS_MAX */
#define NGROUPS  8
#endif /* NGROUPS_MAX */
#endif /* !NGROUPS */

struct group *getgrent();

initgroups(uname, agroup)
     char *uname;
     int agroup;
{
    int groups[NGROUPS], ngroups = 0;
    register struct group *grp;
    register int i;

    /*
     * If installing primary group, duplicate it;
     * the first element of groups is the effective gid
     * and will be overwritten when a setgid file is executed.
     */
    if (agroup >= 0) {
	groups[ngroups++] = agroup;
	groups[ngroups++] = agroup;
    }
    setgrent();
    while (grp = getgrent()) {
	if (grp->gr_gid == agroup)
	    continue;
	for (i = 0; grp->gr_mem[i]; i++)
	    if (!strcmp(grp->gr_mem[i], uname)) {
		if (ngroups == NGROUPS) {
		    fprintf(stderr, "initgroups: %s is in too many groups\n", uname);
		    goto toomany;
		}
		groups[ngroups++] = grp->gr_gid;
	    }
    }
  toomany:
    endgrent();
    if (setgroups(ngroups, groups) < 0) {
	perror("setgroups");
	return (-1);
    }
    return (0);
}
#else
/* this will keep the preprocessor quiet */
int SCOdummy()
{
    return (0);
}
#endif /* _SCO_DS */
