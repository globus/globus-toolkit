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
/*
 * portable version of getcwd()
 */
#include "../src/config.h"
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#else
#include <sys/dir.h>
#define dirent direct
#endif /* DIRENT */
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>

extern int errno;
extern int snprintf();
static char *strnrcpy();

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#define CGETS(b, c, d)        d
/* return true if dp is of the form "../xxx" or "/../xxx" */
#define TRM(a) ((a) & TRIM)
#define NTRM(a) (a)
#define ISDOT(c) (NTRM((c)[0]) == '.' && ((NTRM((c)[1]) == '\0') || \
                  (NTRM((c)[1]) == '/')))
#define ISDOTDOT(c) (NTRM((c)[0]) == '.' && ISDOT(&((c)[1])))
#ifndef DEV_DEV_COMPARE
#define DEV_DEV_COMPARE(x,y)   ((x) == (y))
#endif /* DEV_DEV_COMPARE */

/* getcwd():
 *    Return the pathname of the current directory, or return
 *      an error message in pathname.
 */

#if (SYSVREL != 0 && !defined(d_fileno)) || defined(_VMS_POSIX) || \
		(defined(AIX) && !defined(d_fileno)) || \
		defined(WINNT)
#define d_fileno d_ino
#endif

char *
     getcwd(pathname, pathlen)
     char *pathname;
     size_t pathlen;
{
    DIR *dp;
    struct dirent *d;

    struct stat st_root, st_cur, st_next, st_dotdot;
    char pathbuf[MAXPATHLEN], nextpathbuf[MAXPATHLEN * 2];
    char *pathptr, *nextpathptr, *cur_name_add;
    int save_errno = 0;

    /* find the inode of root */
    if (stat("/", &st_root) == -1) {
	(void) snprintf(pathname, pathlen, CGETS(23, 23,
					  "getcwd: Cannot stat \"/\" (%s)"),
			strerror(errno));
	return NULL;
    }
    pathbuf[MAXPATHLEN - 1] = '\0';
    pathptr = &pathbuf[MAXPATHLEN - 1];
    nextpathbuf[MAXPATHLEN - 1] = '\0';
    cur_name_add = nextpathptr = &nextpathbuf[MAXPATHLEN - 1];

    /* find the inode of the current directory */
    if (lstat(".", &st_cur) == -1) {
	(void) snprintf(pathname, pathlen, CGETS(23, 24,
					  "getcwd: Cannot stat \".\" (%s)"),
			strerror(errno));
	return NULL;
    }
    nextpathptr = strnrcpy(nextpathptr, "../", nextpathptr - nextpathbuf);

    /* Descend to root */
    for (;;) {

	/* look if we found root yet */
	if (st_cur.st_ino == st_root.st_ino &&
	    DEV_DEV_COMPARE(st_cur.st_dev, st_root.st_dev)) {
	    (void) strncpy(pathname, *pathptr != '/' ? "/" : pathptr, pathlen);
	    pathname[pathlen - 1] = '\0';
	    return pathname;
	}

	/* open the parent directory */
	if (stat(nextpathptr, &st_dotdot) == -1) {
	    (void) snprintf(pathname, pathlen, CGETS(23, 25,
			       "getcwd: Cannot stat directory \"%s\" (%s)"),
			    nextpathptr, strerror(errno));
	    return NULL;
	}
	if ((dp = opendir(nextpathptr)) == NULL) {
	    (void) snprintf(pathname, pathlen, CGETS(23, 26,
			       "getcwd: Cannot open directory \"%s\" (%s)"),
			    nextpathptr, strerror(errno));
	    return NULL;
	}

	/* look in the parent for the entry with the same inode */
	if (DEV_DEV_COMPARE(st_dotdot.st_dev, st_cur.st_dev)) {
	    /* Parent has same device. No need to stat every member */
	    for (d = readdir(dp); d != NULL; d = readdir(dp)) {
#ifdef __clipper__
		if (((unsigned long) d->d_fileno & 0xffff) == st_cur.st_ino)
		    break;
#else
		if (d->d_fileno == st_cur.st_ino)
		    break;
#endif
	    }
	}
	else {
	    /*
	     * Parent has a different device. This is a mount point so we
	     * need to stat every member
	     */
	    for (d = readdir(dp); d != NULL; d = readdir(dp)) {
		if (ISDOT(d->d_name) || ISDOTDOT(d->d_name))
		    continue;
		(void) strncpy(cur_name_add, d->d_name,
		      &nextpathbuf[sizeof(nextpathbuf) - 1] - cur_name_add);
		if (lstat(nextpathptr, &st_next) == -1) {
		    /*
		     * We might not be able to stat() some path components
		     * if we are using afs, but this is not an error as
		     * long as we find the one we need; we also save the
		     * first error to report it if we don't finally succeed.
		     */
		    if (save_errno == 0)
			save_errno = errno;
		    continue;
		}
		/* check if we found it yet */
		if (st_next.st_ino == st_cur.st_ino &&
		    DEV_DEV_COMPARE(st_next.st_dev, st_cur.st_dev))
		    break;
	    }
	}
	if (d == NULL) {
	    (void) snprintf(pathname, pathlen, CGETS(23, 27,
				"getcwd: Cannot find \".\" in \"..\" (%s)"),
			    strerror(save_errno ? save_errno : ENOENT));
	    (void) closedir(dp);
	    return NULL;
	}
	else
	    save_errno = 0;
	st_cur = st_dotdot;
	pathptr = strnrcpy(pathptr, d->d_name, pathptr - pathbuf);
	pathptr = strnrcpy(pathptr, "/", pathptr - pathbuf);
	nextpathptr = strnrcpy(nextpathptr, "../", nextpathptr - nextpathbuf);
	*cur_name_add = '\0';
	(void) closedir(dp);
    }
}				/* end getcwd */

/* strnrcpy():
 *    Like strncpy, going backwards and returning the new pointer
 */
static char *
     strnrcpy(ptr, str, siz)
     register char *ptr, *str;
     size_t siz;
{
    register int len = strlen(str);
    if (siz == 0)
	return ptr;

    while (len && siz--)
	*--ptr = str[--len];

    return (ptr);
}				/* end strnrcpy */
