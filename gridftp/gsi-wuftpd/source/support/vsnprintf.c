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
 * vsnprintf hack 
 * better than raw vsprintf, but only just barely....
 */
#include <stdio.h>
#include <varargs.h>

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    char *str;
    int status;
    if (bufsize < 1)
	return (EOF);
    /* we need to verify that the actual length of the buf is greater than
       or equal to the bufsize argument */
    if ((str = (char *) calloc(bufsize + 1)) != NULL) {
	strncpy(str, buf, bufsize);
	status = vsprintf(str, fmt, ap);
	strcpy(buf, str);
	free(str);
    }
    else
	status = vsprintf(buf, fmt, ap);
    return status;
}
