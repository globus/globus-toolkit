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
   ** SCO configuration file
 */

#ifdef _SCO_DS			/* SCO OpenServer 5 */
#define HAVE_LSTAT
#undef  F_SETOWN
#define HAVE_REGEX_H
#define HAVE_DIRENT_H
#undef  HAVE_FLOCK
#define HAVE_FTW
#define HAVE_GETCWD
#define HAVE_GETRLIMIT
#define HAVE_GLOB_H
#undef  HAVE_PSTAT
#define HAVE_STATVFS
#define HAVE_ST_BLKSIZE
#undef  HAVE_UT_UT_HOST
#define HAVE_SYSCONF
#define HAVE_VPRINTF
#define HAVE_SNPRINTF
#define HAVE_REGEXEC
#define SPT_TYPE SPT_SCO
#undef  SHADOW_PASSWORD
#define SVR4
#define HAVE_FCNTL_H
#define USG
#define _SVID3
#define USE_VAR
#if !defined(USE_ETC_FTPD) && !defined(USE_LOCAL_ETC) && !defined(USE_OPT_FTPD)
#define USE_ETC
#endif
#define VIRTUAL

#include <limits.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <paths.h>
#include <sys/time.h>

#define SecureWare

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
#ifndef MAXPATHLEN
#ifdef PATH_MAX
#define MAXPATHLEN PATH_MAX
#else
#define MAXPATHLEN 1024
#endif
#endif

#ifndef FACILITY
#define FACILITY LOG_DAEMON
#endif

typedef void SIGNAL_TYPE;
#else
/* this is the older configuration information which is has not been */
/* verified by Stan Barber */

#define FACILITY LOG_LOCAL7

/* End of configurable parameters for SCO. Leave the below as it is. */

#undef  BSD
#define HAVE_DIRENT_H
#undef  HAVE_FLOCK
#undef  HAVE_FTW
#define HAVE_GETCWD
#define HAVE_GETDTABLESIZE
#undef  HAVE_PSTAT
#undef  HAVE_ST_BLKSIZE
#undef  HAVE_SYSINFO
#undef  HAVE_UT_UT_HOST
#define HAVE_VPRINTF
#define HAVE_REGEX
#define SPT_TYPE SPT_SCO
#undef  SHADOW_PASSWORD
#define USG
#define VIRTUAL

#ifdef _M_UNIX
#define HAVE_LSTAT
#else
#undef  HAVE_LSTAT
#endif

#undef  HAVE_D_NAMLEN




#ifdef _M_UNIX
#define _KR			/* need #define NULL 0 */
#undef __STDC__			/* ugly, but does work :-) */
#else
#define SYSLOGFILE "/usr/adm/ftpd"
#define NULL 0
#endif

#define crypt(k,s) bigcrypt(k,s)
#define d_fileno d_ino
#define ftruncate(fd,size) chsize(fd,size)	/* needs -lx */
#define getpagesize() (4096)
#define vfork fork
#define fchown chown

#define _PATH_WTMP "/etc/wtmp"
#define _PATH_UTMP "/etc/utmp"

#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/socket.h>		/* eliminate redefinition of _IO
				   in audit.h under 3.2v2.0 */

#define SecureWare
#include <sys/security.h>
#include <sys/audit.h>
#include <prot.h>

#include <sys/fcntl.h>

#ifndef MAXPATHLEN
#ifdef PATH_MAX
#define MAXPATHLEN PATH_MAX
#else
#define MAXPATHLEN 1024
#endif
#endif

typedef void SIGNAL_TYPE;

#endif
#include "../config.h"
