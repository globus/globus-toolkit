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

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#else
#include <sys/dir.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stat.h>

#include "ftw.h"

#define	NODESC	-1

#ifdef HAVE_LSTAT
#define	ISLINK(sb)	((sb.st_mode&S_IFMT) == S_IFLNK)
#else
#define lstat stat
#endif

#define	ISDIR(sb)	((sb.st_mode&S_IFMT) == S_IFDIR)
#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (!dp->d_name[1] || \
	    (dp->d_name[1] == '.' && !dp->d_name[2])))

extern int errno;
static int g_fds, (*g_fn) (), g_opts;
static char *bp;

int treewalk(char *path, int (*fn) ( /* ??? */ ), int maxfds, int opts);

/*
 * cycle through the directories at the top of the tree, otherwise, once
 * you run out of descriptors you have to keep reusing the same one and
 * it gets *real* slow.
 */
typedef struct d_fd {
    struct d_fd *next;
    DIR *dirp;
    off_t off;
} FD;

static FD *freep, *node;

static int walk(register char *name)
{
#ifdef HAVE_DIRENT_H
    register struct dirent *dp;
#else
    register struct direct *dp;
#endif
    register int rval;
    struct stat sb;
    FD cur;
    char *save;

    if (!freep)
	freep = &cur;
    else
	node->next = &cur;
    node = &cur;
    cur.off = 0;

  getfd:if (!g_fds) {
	freep->off = telldir(freep->dirp);
	closedir(freep->dirp);
	freep = freep->next;
	++g_fds;
    }
    if (!(cur.dirp = opendir(bp))) {
	if (errno == EMFILE) {
	    g_fds = 0;
	    goto getfd;
	}
	return (errno == EACCES ? (*g_fn) (bp, &sb, FTW_DNR) : -1);
    }
    else
	--g_fds;

    for (; *name; ++name);
    *name++ = '/';
    for (rval = 0, dp = readdir(cur.dirp); dp; dp = readdir(cur.dirp)) {
	if (ISDOT(dp))
	    continue;
	(void) strcpy(name, dp->d_name);
	if (lstat(bp, &sb)) {
	    rval = errno == EACCES ?
		(*g_fn) (bp, &sb, FTW_NS) : -1;
	    if (rval)
		break;
	}
#ifdef HAVE_LSTAT
	if (ISLINK(sb) && g_opts & FTW_SYMLINK)
	    if (stat(bp, &sb))
		continue;
#endif
	if (!ISDIR(sb)) {
	    rval = (*g_fn) (bp, &sb, FTW_F);
	    if (rval)
		break;
	    continue;
	}
	if (g_opts & FTW_DIRLAST)
#ifdef HAVE_D_NAMLEN
	    save = name + dp->d_namlen;
#else
	    save = name + strlen(dp->d_name);
#endif
	rval = (*g_fn) (bp, &sb, FTW_D);
	if ((rval && rval != NODESC) || (rval = walk(name)))
	    break;
	if (g_opts & FTW_DIRLAST) {
	    *save = '\0';
	    rval = (*g_fn) (dp->d_name, &sb, FTW_D2);
	    if (rval)
		if (rval == NODESC)
		    rval = 0;
		else
		    break;
	}
	if (cur.off) {
	    *name = '\0';
	    if ((cur.dirp = opendir(bp))) {
		seekdir(cur.dirp, cur.off);
		/* tricky; if we have to reset the directory pointer we know
		 * it's the next one to reuse */
		freep = &cur;
		--g_fds;
	    }
	    /* directory moved from under us!!! */
	    else {
		rval = -1;
		break;
	    }
	}
    }
    closedir(cur.dirp);
    ++g_fds;
    return (rval);
}

static int chwalk(register char *name)
{
#ifdef HAVE_DIRENT_H
    register struct dirent *dp;
#else
    register struct direct *dp;
#endif

    register int rval;
    struct stat sb;
    FD cur;
    char *pwd, *getwd(char *);

    if (!freep)
	freep = &cur;
    else
	node->next = &cur;
    node = &cur;
    cur.off = 0;

    if (chdir(name))
	return (errno == EACCES ? (*g_fn) (name, &sb, FTW_DNR) : -1);

  getfd:if (!g_fds) {
	freep->off = telldir(freep->dirp);
	closedir(freep->dirp);
	freep = freep->next;
	++g_fds;
    }
    if (!(cur.dirp = opendir("."))) {
	if (errno == EMFILE) {
	    g_fds = 0;
	    goto getfd;
	}
	return (errno == EACCES ? (*g_fn) (".", &sb, FTW_DNR) : -1);
    }
    else
	--g_fds;

    for (rval = 0, dp = readdir(cur.dirp); dp; dp = readdir(cur.dirp)) {
	if (ISDOT(dp))
	    continue;
	if (lstat(dp->d_name, &sb)) {
	    rval = errno == EACCES ?
		(*g_fn) (dp->d_name, &sb, FTW_NS) : -1;
	    if (rval)
		break;
	}
	pwd = NULL;
#ifdef HAVE_LSTAT
	if (ISLINK(sb) && g_opts & FTW_SYMLINK) {
	    if (stat(dp->d_name, &sb))
		continue;
	    if (ISDIR(sb)) {
		/* NOSTRICT */
		if (!(pwd = malloc((u_int) MAXPATHLEN))) {
		    rval = -1;
		    break;
		}
		if (!getwd(pwd)) {
		    rval = -1;
		    break;
		}
	    }
	}
#endif
	if (!ISDIR(sb)) {
	    rval = (*g_fn) (dp->d_name, &sb, FTW_F);
	    if (rval)
		break;
	    continue;
	}
	rval = (*g_fn) (dp->d_name, &sb, FTW_D);
	if ((rval && rval != NODESC) || (rval = chwalk(dp->d_name)))
	    break;
	if (g_opts & FTW_DIRLAST) {
	    rval = (*g_fn) (dp->d_name, &sb, FTW_D2);
	    if (rval)
		if (rval == NODESC)
		    rval = 0;
		else
		    break;
	}
	if (pwd && chdir(pwd)) {
	    rval = -1;
	    break;
	}
	if (cur.off) {
	    if ((cur.dirp = opendir("."))) {
		seekdir(cur.dirp, cur.off);
		/* tricky; if we have to reset the directory pointer we know
		 * it's the next one to reuse */
		freep = &cur;
		--g_fds;
	    }
	    /* directory moved from under us!!! */
	    else {
		rval = -1;
		break;
	    }
	}
    }
    closedir(cur.dirp);
    ++g_fds;
    if (chdir(".."))
	return (-1);
    return (rval);
}

#ifndef HAVE_FTW
/* S5 compatible ftw(BA_LIB) */
int ftw(char *path, int (*fn) ( /* ??? */ ), int maxfds)
{
    return (treewalk(path, fn, maxfds, 0));
}
#endif

int treewalk(char *path, int (*fn) ( /* ??? */ ), int maxfds, int opts)
{
    struct stat sb;
    int rval;
    char *pwd, *getwd(char *);

    if (lstat(path, &sb))
	return (errno == EACCES ? (*fn) (path, &sb, FTW_NS) : -1);

    pwd = NULL;
#ifdef HAVE_LSTAT
    if (ISLINK(sb) && opts & FTW_SYMLINK) {
	if (stat(path, &sb))
	    return (0);
	if (ISDIR(sb)) {
	    /* NOSTRICT */
	    if (!(pwd = malloc((u_int) MAXPATHLEN)))
		return (-1);
	    if (!getwd(pwd))
		return (-1);
	}
    }
#endif
    if (!ISDIR(sb))
	return ((*fn) (path, &sb, FTW_F));

    if (!maxfds)
	return (-1);
    g_fds = maxfds == -1 ? getdtablesize() : maxfds;
    g_fn = fn;
    g_opts = opts;

    if (!(opts & FTW_CHDIR) && !(bp = malloc((u_int) MAXPATHLEN))) {
	errno = ENOMEM;
	return (-1);
    }
    rval = (*fn) (path, &sb, FTW_D);
    if (rval == NODESC)
	rval = 0;
    else if (!rval) {
	if (opts & FTW_CHDIR)
	    rval = chwalk(path);
	else
	    rval = walk(strcpy(bp, path));
	if (!rval && opts & FTW_DIRLAST) {
	    rval = (*fn) (path, &sb, FTW_D2);
	    if (rval == NODESC)
		rval = 0;
	}
    }
    if (pwd && chdir(pwd))
	return (-1);
    return (rval);
}
