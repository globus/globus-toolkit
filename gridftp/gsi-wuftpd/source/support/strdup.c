
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
#if defined(_AIX4)
/* we don't need this for AIX4 */
void ftp_strdup_dummy()
{
}

#else
#include <stddef.h>
#include <stdlib.h>
#ifdef BSD
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/types.h>

char *strdup(char *str)
{
    int len;
    char *copy;

    len = strlen(str) + 1;
    if (!(copy = malloc((u_int) len)))
	return ((char *) NULL);
#ifdef BSD
    bcopy(str, copy, len);
#else
    memcpy(copy, str, len);
#endif
    return (copy);
}
#endif
