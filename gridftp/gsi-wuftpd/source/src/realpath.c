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
/* Originally taken from FreeBSD 3.0's libc; adapted to handle chroot
 * directories in BeroFTPD by Bernhard Rosenkraenzer
 * <bero@beroftpd.unix.eu.org>
 *
 * Added super-user permissions so we can determine the real pathname even
 * if the user cannot access the file. <lundberg+wuftpd@vr.net>
 */
#include "config.h"

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proto.h"

#ifndef MAXSYMLINKS		/* Workaround for Linux libc 4.x/5.x */
#define MAXSYMLINKS 5
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#endif

char *wu_realpath(const char *path, char resolved_path[MAXPATHLEN], char *chroot_path)
{
    char *ptr;
    char q[MAXPATHLEN];

    fb_realpath(path, q);

    if (chroot_path == NULL)
	strcpy(resolved_path, q);
    else {
	strcpy(resolved_path, chroot_path);
	if (q[0] != '/') {
	    if (strlen(resolved_path) + strlen(q) < MAXPATHLEN)
		strcat(resolved_path, q);
	    else		/* Avoid buffer overruns... */
		return NULL;
	}
	else if (q[1] != '\0') {
	    for (ptr = q; *ptr != '\0'; ptr++);
	    if (ptr == resolved_path || *--ptr != '/') {
		if (strlen(resolved_path) + strlen(q) < MAXPATHLEN)
		    strcat(resolved_path, q);
		else		/* Avoid buffer overruns... */
		    return NULL;
	    }
	    else {
		if (strlen(resolved_path) + strlen(q) - 1 < MAXPATHLEN)
		    strcat(resolved_path, &q[1]);
		else		/* Avoid buffer overruns... */
		    return NULL;
	    }
	}
    }
    return resolved_path;
}

/*
 * char *fb_realpath(const char *path, char resolved_path[MAXPATHLEN]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
char *fb_realpath(const char *path, char *resolved)
{
    struct stat sb;
    int fd, n, rootd, serrno;
    char *p, *q, wbuf[MAXPATHLEN];
    int symlinks = 0;
    int resultcode;
#ifdef HAS_NO_FCHDIR
/* AIX Has no fchdir() so we hope the getcwd() call doesn't overrun the buffer! */
    char cwd[MAXPATHLEN + 1];
    char *pcwd;
#endif

    /* Save the starting point. */
    errno = 0;
#ifdef HAS_NO_FCHDIR
#ifdef HAVE_GETCWD
    pcwd = getcwd(cwd, sizeof(cwd));
#else
    pcwd = getwd(cwd);
#endif
#else
    fd = open(".", O_RDONLY);
#endif
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
#ifdef HAS_NO_FCHDIR
#ifdef HAVE_GETCWD
	pcwd = getcwd(cwd, sizeof(cwd));
#else
	pcwd = getwd(cwd);
#endif
#else
	fd = open(".", O_RDONLY);
#endif
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
#ifdef HAS_NO_FCHDIR
    if (pcwd == NULL)
#else
    if (fd < 0)
#endif
    {
	(void) strcpy(resolved, ".");
	return (NULL);
    }

    /*
     * Find the dirname and basename from the path to be resolved.
     * Change directory to the dirname component.
     * lstat the basename part.
     *     if it is a symlink, read in the value and loop.
     *     if it is a directory, then change to that directory.
     * get the current directory name and append the basename.
     */
    (void) strncpy(resolved, path, MAXPATHLEN - 1);
    resolved[MAXPATHLEN - 1] = '\0';
  loop:
    q = strrchr(resolved, '/');
    if (q != NULL) {
	p = q + 1;
	if (q == resolved)
	    q = "/";
	else {
	    do {
		--q;
	    } while (q > resolved && *q == '/');
	    q[1] = '\0';
	    q = resolved;
	}
	errno = 0;
	resultcode = chdir(q);
	if (EACCES == errno) {
	    uid_t userid = geteuid();
	    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	    seteuid(0);
	    errno = 0;
	    resultcode = chdir(q);
	    seteuid(userid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	}
	if (resultcode < 0)
	    goto err1;
    }
    else
	p = resolved;

    /* Deal with the last component. */
    if (*p != '\0') {
	errno = 0;
	resultcode = lstat(p, &sb);
	if (EACCES == errno) {
	    uid_t userid = geteuid();
	    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	    seteuid(0);
	    errno = 0;
	    resultcode = lstat(p, &sb);
	    seteuid(userid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	}
	if (resultcode == 0) {
#ifdef HAVE_LSTAT
	    if (S_ISLNK(sb.st_mode)) {
		if (++symlinks > MAXSYMLINKS) {
		    errno = ELOOP;
		    goto err1;
		}
		errno = 0;
		{
		    size_t len = strlen(p);
		    char *tmp = calloc(len + 1, sizeof(char));
		    if (tmp == 0) {
			serrno = errno;
			goto err1;
		    }
		    strcpy(tmp, p);
		    p = tmp;
		}
		n = readlink(p, resolved, MAXPATHLEN);
		if (EACCES == errno) {
		    uid_t userid = geteuid();
		    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
		    seteuid(0);
		    errno = 0;
		    n = readlink(p, resolved, MAXPATHLEN);
		    seteuid(userid);
		    enable_signaling();		/* we can allow signals once again: kinch */
		}
		if (n < 0) {
		    free(p);
		    goto err1;
		}
		free(p);
		resolved[n] = '\0';
		goto loop;
	    }
#endif /* HAVE_LSTAT */
	    if (S_ISDIR(sb.st_mode)) {
		errno = 0;
		resultcode = chdir(p);
		if (EACCES == errno) {
		    uid_t userid = geteuid();
		    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
		    seteuid(0);
		    errno = 0;
		    resultcode = chdir(p);
		    seteuid(userid);
		    enable_signaling();		/* we can allow signals once again: kinch */
		}
		if (resultcode < 0)
		    goto err1;
		p = "";
	    }
	}
    }

    /*
     * Save the last component name and get the full pathname of
     * the current directory.
     */
    (void) strcpy(wbuf, p);
    errno = 0;
#ifdef HAVE_GETCWD
    resultcode = getcwd(resolved, MAXPATHLEN) == NULL ? 0 : 1;
#else
    resultcode = getwd(resolved) == NULL ? 0 : 1;
    if (resolved[MAXPATHLEN - 1] != '\0') {
	resultcode = 0;
	errno = ERANGE;
    }
#endif
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
	errno = 0;
#ifdef HAVE_GETCWD
	resultcode = getcwd(resolved, MAXPATHLEN) == NULL ? 0 : 1;
#else
	resultcode = getwd(resolved) == NULL ? 0 : 1;
	if (resolved[MAXPATHLEN - 1] != '\0') {
	    resultcode = 0;
	    errno = ERANGE;
	}
#endif
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
    if (resultcode == 0)
	goto err1;

    /*
     * Join the two strings together, ensuring that the right thing
     * happens if the last component is empty, or the dirname is root.
     */
    if (resolved[0] == '/' && resolved[1] == '\0')
	rootd = 1;
    else
	rootd = 0;

    if (*wbuf) {

        /* switched "rootd + 1" to " + 2" just to be on the safe side */
        /* technically "!rootd + 1" should also work */
        /* see http://isec.pl/vulnerabilities/isec-0011-wu-ftpd.txt */
        
	if (strlen(resolved) + strlen(wbuf) + 2 > MAXPATHLEN) {
	    errno = ENAMETOOLONG;
	    goto err1;
	}
	if (rootd == 0)
	    (void) strcat(resolved, "/");
	(void) strcat(resolved, wbuf);
    }

    /* Go back to where we came from. */
    errno = 0;
#ifdef HAS_NO_FCHDIR
    resultcode = chdir(cwd);
#else
    resultcode = fchdir(fd);
#endif
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
	errno = 0;
#ifdef HAS_NO_FCHDIR
	resultcode = chdir(cwd);
#else
	resultcode = fchdir(fd);
#endif
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
    if (resultcode < 0) {
	serrno = errno;
	goto err2;
    }

#ifndef HAS_NO_FCHDIR
    /* It's okay if the close fails, what's an fd more or less? */
    (void) close(fd);
#endif
    return (resolved);

  err1:serrno = errno;
#ifdef HAS_NO_FCHDIR
    (void) chdir(cwd);
#else
    (void) fchdir(fd);
#endif
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
#ifdef HAS_NO_FCHDIR
	(void) chdir(cwd);
#else
	(void) fchdir(fd);
#endif
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
#ifdef HAS_NO_FCHDIR
  err2:errno = serrno;
#else
  err2:(void) close(fd);
    errno = serrno;
#endif
    return (NULL);
}
