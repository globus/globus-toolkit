/* Pretty generic file recompressor - it only insists on the decompressor
 * accepting the "-c" flag to decompress to stdout, which works for
 * gunzip, uncompress, bunzip2, tunzip, and more.
 * Intended as a future replacement for gzip2cmp.c
 */
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
#include <stdio.h>

/* Some odd systems like SunOS don't have basename :/ */
#define lbasename(x) (strrchr(x,'/')?1+strrchr(x,'/'):x)

main(ac, av)
     int ac;
     char **av;
{
    char *zipfile;
    int fd[2];

    switch (ac) {

    case 4:
	zipfile = av[3];
	break;

    case 3:
	zipfile = NULL;
	break;

    default:
	fputs("usage: recompress decompressor compressor [file]", stderr);
	fputs("       Example: recompress /bin/uncompress /bin/gzip [file]", stderr);
	exit(1);
    }

    if (pipe(fd) < 0) {
	perror("pipe");
	exit(1);
    }

    switch (fork()) {

    default:			/* the father */
	if (dup2(fd[0], 0) < 0) {
	    perror("parent: dup2");
	    exit(1);
	}
	close(fd[1]);
	execlp(av[2], lbasename(av[2]), NULL);
	perror("execlp: compressor");
	exit(1);

    case 0:			/* the son */
	if (dup2(fd[1], 1) < 0) {
	    perror("child: dup2");
	    exit(1);
	}
	close(fd[0]);
	execlp(av[1], lbasename(av[1]), "-c", zipfile, NULL);
	perror("execlp: uncompressor");
	exit(1);

    case -1:			/* Murphy's ghost */
	perror("fork");
	exit(1);
    }
}
