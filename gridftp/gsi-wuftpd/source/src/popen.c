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
#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#ifdef HAVE_GETRLIMIT
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#include <sys/time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <sys/resource.h>
#endif
#include "pathnames.h"
#include "proto.h"

/* 
 * Special version of popen which avoids call to shell.  This insures noone
 * may create a pipe to a hidden program as a side effect of a list or dir
 * command. 
 */
static int *pids;
static int fds;
#define MAX_ARGV 100
#define MAX_GARGV 1000

FILE *ftpd_popen(char *program, char *type, int closestderr)
{
    register char *cp;
    FILE *iop;
    int argc, gargc, pdes[2], pid, i, devnullfd;
    char **pop, *argv[MAX_ARGV], *gargv[MAX_GARGV], *vv[2];

    extern char **ftpglob(register char *v);
    extern char **copyblk(register char **v);
    extern char *strspl(register char *cp, register char *dp);
    extern char *globerr;

#ifdef HAVE_GETRLIMIT
    struct rlimit rlp;

    rlp.rlim_cur = rlp.rlim_max = RLIM_INFINITY;
    if (getrlimit(RLIMIT_NOFILE, &rlp))
	return (NULL);
    fds = rlp.rlim_cur;
#else
#ifdef HAVE_GETDTABLESIZE
    if ((fds = getdtablesize()) <= 0)
	return (NULL);
#else
#ifdef HAVE_SYSCONF
    fds = sysconf(_SC_OPEN_MAX);
#else
#ifdef OPEN_MAX
    fds = OPEN_MAX;		/* need to include limits.h somehow */
#else
    fds = 31;			/* XXX -- magic cookie */
#endif
#endif
#endif
#endif
    if ((*type != 'r' && *type != 'w') || type[1])
	return (NULL);

    if (!pids) {
	pids = (int *) calloc(fds, sizeof(int));
	if (pids == NULL)
	    return (NULL);
    }
    if (pipe(pdes) < 0)
	return (NULL);
    (void) memset((void *) argv, 0, sizeof(argv));

    /* empty the array */
    memset((char *) argv, '\0', sizeof(argv));
    /* break up string into pieces */
    for (argc = 0, cp = program; argc < MAX_ARGV - 1; cp = NULL)
	if (!(argv[argc++] = strtok(cp, " \t\n")))
	    break;

    /* glob each piece */
    gargv[0] = argv[0];
    for (gargc = argc = 1; argc < MAX_ARGV && argv[argc]; argc++) {
	if (!(pop = ftpglob(argv[argc])) || globerr != NULL) {	/* globbing failed */
	    vv[0] = strspl(argv[argc], "");
	    vv[1] = NULL;
	    pop = copyblk(vv);
	}
	argv[argc] = (char *) pop;	/* save to free later */
	while (*pop && gargc < (MAX_GARGV - 1))
	    gargv[gargc++] = *pop++;
    }
    gargv[gargc] = NULL;

#ifdef SIGCHLD
    (void) signal(SIGCHLD, SIG_DFL);
#endif
    iop = NULL;
    switch (pid = vfork()) {
    case -1:			/* error */
	(void) close(pdes[0]);
	(void) close(pdes[1]);
	goto pfree;
	/* NOTREACHED */
    case 0:			/* child */
	if (*type == 'r') {
	    if (pdes[1] != 1) {
		dup2(pdes[1], 1);
		if (closestderr) {
		    (void) close(2);
		    /* stderr output is written to fd 2, so make sure it isn't
		     * available to be assigned to another file */
		    if ((devnullfd = open(_PATH_DEVNULL, O_RDWR)) != -1) {
			if (devnullfd != 2) {
			    dup2(devnullfd, 2);
			    (void) close(devnullfd);
			}
		    }
		}
		else
		    dup2(pdes[1], 2);	/* stderr, too! */
		(void) close(pdes[1]);
	    }
	    (void) close(pdes[0]);
	}
	else {
	    if (pdes[0] != 0) {
		dup2(pdes[0], 0);
		(void) close(pdes[0]);
	    }
	    (void) close(pdes[1]);
	}
	for (i = 3; i < fds; i++)
	    close(i);
	/* begin CERT suggested fixes */
	close(0);
	i = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
	setgid(getegid());
	setuid(i);
	enable_signaling();	/* we can allow signals once again: kinch */
	/* end CERT suggested fixes */
	execvp(gargv[0], gargv);
	_exit(1);
    }
    /* parent; assume fdopen can't fail...  */
    if (*type == 'r') {
	iop = fdopen(pdes[0], type);
	(void) close(pdes[1]);
    }
    else {
	iop = fdopen(pdes[1], type);
	(void) close(pdes[0]);
    }
    pids[fileno(iop)] = pid;

  pfree:for (argc = 1; argc < MAX_ARGV && argv[argc]; argc++) {
	blkfree((char **) argv[argc]);
	free((char *) argv[argc]);
    }
    return (iop);
}

int ftpd_pclose(FILE *iop)
{
    register int fdes;
    int pid;
#if defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))
    sigset_t sig, omask;
    int stat_loc;
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGQUIT);
    sigaddset(&sig, SIGHUP);
#elif defined (_OSF_SOURCE)
    int omask;
    int status;
#else
    int omask;
    union wait stat_loc;
#endif


    /* pclose returns -1 if stream is not associated with a `popened'
     * command, or, if already `pclosed'. */
    if (pids == 0 || pids[fdes = fileno(iop)] == 0)
	return (-1);
    (void) fclose(iop);
#if defined(HAVE_SIGPROCMASK) || (!defined(AUTOCONF) && defined(SVR4))
    sigprocmask(SIG_BLOCK, &sig, &omask);
#else
    omask = sigblock(sigmask(SIGINT) | sigmask(SIGQUIT) | sigmask(SIGHUP));
#endif

#if (!defined(HAVE_SIGPROCMASK) || (!defined(SVR4) && !defined(AUTOCONF))) && defined (_OSF_SOURCE)
    while ((pid = wait(&status)) != pids[fdes] && pid != -1);
#elif ! defined(NeXT)
    while ((pid = wait((int *) &stat_loc)) != pids[fdes] && pid != -1);
#else
    while ((pid = wait(&stat_loc)) != pids[fdes] && pid != -1);
#endif
    pids[fdes] = 0;
#ifdef SIGCHLD
    (void) signal(SIGCHLD, SIG_IGN);
#endif
#if defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))
    sigprocmask(SIG_SETMASK, &omask, (sigset_t *) NULL);
    return (pid == -1 ? -1 : WEXITSTATUS(stat_loc));
#else
    (void) sigsetmask(omask);
#ifdef _OSF_SOURCE
    return (pid == -1 ? -1 : status);
#elif defined(LINUX)
    return (pid == -1 ? -1 : WEXITSTATUS(stat_loc));
#else
    return (pid == -1 ? -1 : stat_loc.w_status);
#endif
#endif
}
