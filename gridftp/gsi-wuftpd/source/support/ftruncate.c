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
 * Using chsize on systems that support it (XENIX and SVR4)
 * SPECIAL NOTE: On Xenix and SVR4, using this call in the BSD library
 * will REQUIRE the use of -lx for the extended library since chsize()
 * is not in the standard C library.
 */

#include <fcntl.h>		/* not always required */

ftruncate(fd, length)
     int fd;			/* File descriptor for file that to change */
     off_t length;		/* New size for this file */
{
    int status;			/* Status returned from chsize() proc */

    status = chsize(fd, length);
    return (status);
}
