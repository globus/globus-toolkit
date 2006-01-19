/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*

includes.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Thu Mar 23 16:29:37 1995 ylo

This file includes most of the needed system headers.

*/

/*
 * $Id$
 * $Log$
 * Revision 1.3  2006/01/19 15:44:48  bester
 * Exciting new license!
 *
 * Revision 1.2  2005/04/18 21:33:07  smartin
 * added license statements before the 4.0.0 release
 *
 * Revision 1.1  1998/12/07 17:05:51  bester
 * added Cray MLS security code from NERSC
 *
 * Revision 1.1  1998/12/07 17:03:35  bester
 * added unicos MLS security code from NERSC
 *
 * Revision 1.10  1998/01/02 06:18:20  kivinen
 * 	Added sys/resource.h include. Added _S_IFLNK and S_ISLNK
 * 	defines if not defined by system.
 *
 * Revision 1.9  1997/03/19 18:02:19  kivinen
 * 	Added SECURE_RPC, SECURE_NFS and NIS_PLUS support from Andy
 * 	Polyakov <appro@fy.chalmers.se>.
 *
 * Revision 1.8  1996/10/14 16:16:19  ttsalo
 *       Support for OpenBSD (from Thorsten Lockert <tholo@SigmaSoft.COM>
 *
 * Revision 1.7  1996/10/14 02:37:12  ylo
 * 	Removed spaces from error tokens so that compiler reports the
 * 	error in the right place.
 *
 * Revision 1.6  1996/10/07 11:40:20  ttsalo
 * 	Configuring for hurd and a small fix to do_popen()
 * 	from "Charles M. Hannum" <mycroft@gnu.ai.mit.edu> added.
 *
 * Revision 1.5  1996/08/11 22:30:59  ylo
 * 	Changed the way machine/endian.h include is tested (no longer
 * 	lists specific systems).
 * 	Added optional defines of _S_IFMT and _S_IFDIR.
 *
 * Revision 1.4  1996/07/12 07:19:23  ttsalo
 * 	SCO v5 support
 *
 * Revision 1.3  1996/04/26 00:33:48  ylo
 * 	Added support for HPUX 7.x.
 *
 * Revision 1.2  1996/04/22 23:40:42  huima
 * Added #define SUPPORT_OLD_CHANNELS.
 *
 * Revision 1.1.1.1  1996/02/18  21:38:10  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.12  1995/10/02  01:22:37  ylo
 * 	Added machine/endian.h on Paragon.
 *
 * Revision 1.11  1995/09/27  02:14:08  ylo
 * 	Added support for SCO unix.
 *
 * Revision 1.10  1995/09/21  17:11:28  ylo
 * 	Added Paragon support.
 * 	Added definition of AF_UNIX_SIZE.
 *
 * Revision 1.9  1995/09/13  11:57:21  ylo
 * 	Changed the code so that "short" gets used as word32 on Cray.
 * 	Some of the code depends on that.  (BTW, "short" has really
 * 	weird semantics on Cray...)
 *
 * Revision 1.8  1995/09/11  17:35:27  ylo
 * 	Define word32 properly if any int type is 32 bits.
 *
 * Revision 1.7  1995/08/18  22:54:59  ylo
 * 	Added using netinet/in_system.h if netinet/in_systm.h does not
 * 	exist (some old linux versions, at least).
 *
 * 	Added support for NextStep.
 *
 * Revision 1.6  1995/07/27  03:27:46  ylo
 * 	Moved sparc HAVE_SYS_IOCTL_H stuff to the proper place.
 *
 * Revision 1.5  1995/07/26  23:35:32  ylo
 * 	Undef HAVE_VHANGUP on Sony News.
 *
 * Revision 1.4  1995/07/26  23:15:05  ylo
 * 	Include version.h.
 * 	Fixed SIZEOF_LONG test.
 * 	Added ultrix specific porting stuff.
 * 	Added sparc/sunos specific porting stuff.
 *
 * Revision 1.3  1995/07/13  01:46:00  ylo
 * 	Added snabb's patches for IRIX 4.
 *
 * Revision 1.2  1995/07/13  01:25:11  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#ifndef INCLUDES_H
#define INCLUDES_H

#define HAVE_TERMIOS_H

#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>

#include <sys/ioctl.h>

#include <termios.h>

#if 1
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#else /* STDC_HEADERS */
/* stdarg.h is present almost everywhere, and comes with gcc; I am too lazy
   to make things work with both it and varargs. */
#include <stdarg.h>
#ifndef HAVE_STRCHR
#define strchr index
#define strrchr rindex
#endif
char *strchr(), *strrchr();
#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy((s), (d), (n))
#define memmove(d, s, n) bcopy((s), (d), (n))
#define memset(d, ch, n) bzero((d), (n)) /* We only memset to 0. */
#define memcmp(a, b, n) bcmp((a), (b), (n))
#endif
#endif /* STDC_HEADERS */

#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else /* Some old linux systems at least have in_system.h instead. */
#ifdef HAVE_NETINET_IN_SYSTEM_H
#include <netinet/in_system.h>
#endif /* HAVE_NETINET_IN_SYSTEM_H */
#endif /* HAVE_NETINET_IN_SYSTM_H */
#ifdef __OpenBSD__
#include <netgroup.h>
#include <util.h>
#endif
#ifdef SCO
/* SCO does not have a un.h and there is no appropriate substitute. */
/* Latest news: it doesn't have AF_UNIX at all, but this allows
   it to compile, and outgoing forwarded connections appear to work. */
struct	sockaddr_un {
	short	sun_family;		/* AF_UNIX */
	char	sun_path[108];		/* path name (gag) */
};
/* SCO needs sys/stream.h and sys/ptem.h */
#include <sys/stream.h>
#include <sys/ptem.h>
#else /* SCO */
#include <sys/un.h>
#endif /* SCO */
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif /* HAVE_NETINET_IP_H */
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif /* HAVE_NETINET_TCP_H */
#if defined(HPSUX7_KLUDGES)
struct linger {
        int             l_onoff;/* option on/off */
        int             l_linger;       /* linger time */
};
#else /* normal system */
#include <arpa/inet.h>
#endif
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */

#include <pwd.h>
#include <grp.h>
#ifdef HAVE_GETSPNAM
#include <shadow.h>
#endif /* HAVE_GETSPNAM */

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#else /* HAVE_SYS_WAIT_H */
#if !defined(WNOHANG) /* && (defined(bsd43) || defined(vax)) */
#define WNOHANG 1
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(X) ((unsigned)(X) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(X) (((X) & 255) == 0)
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(X) ((((X) & 255) != 0x255 && ((X) & 255) != 0))
#endif
#ifndef WTERMSIG
#define WTERMSIG(X) ((X) & 255)
#endif
#endif /* HAVE_SYS_WAIT_H */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef TIME_WITH_SYS_TIME
#ifndef SCO
/* I excluded <sys/time.h> to avoid redefinition of timeval 
   which SCO puts in both <sys/select.h> and <sys/time.h> */
#include <sys/time.h>
#endif /* SCO */
#include <time.h>
#else /* TIME_WITH_SYS_TIME */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else /* HAVE_SYS_TIME_H */
#include <time.h>
#endif /* HAVE_SYS_TIME_H */
#endif /* TIME_WITH_SYS_TIME */

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#if HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)
#else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#if HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#if HAVE_NDIR_H
#include <ndir.h>
#endif
#endif

/* These POSIX macros are not defined in every system. */

#ifndef S_IRWXU
#define S_IRWXU 00700		/* read, write, execute: owner */
#define S_IRUSR 00400		/* read permission: owner */
#define S_IWUSR 00200		/* write permission: owner */
#define S_IXUSR 00100		/* execute permission: owner */
#define S_IRWXG 00070		/* read, write, execute: group */
#define S_IRGRP 00040		/* read permission: group */
#define S_IWGRP 00020		/* write permission: group */
#define S_IXGRP 00010		/* execute permission: group */
#define S_IRWXO 00007		/* read, write, execute: other */
#define S_IROTH 00004		/* read permission: other */
#define S_IWOTH 00002		/* write permission: other */
#define S_IXOTH 00001		/* execute permission: other */
#endif /* S_IRWXU */

#ifndef S_ISUID
#define S_ISUID 0x800
#endif /* S_ISUID */
#ifndef S_ISGID
#define S_ISGID 0x400
#endif /* S_ISGID */

#ifndef S_ISDIR
/* NextStep apparently fails to define this. */
#define S_ISDIR(mode)   (((mode)&(_S_IFMT))==(_S_IFDIR))
#endif
#ifndef _S_IFMT
#define _S_IFMT 0170000
#endif
#ifndef _S_IFDIR
#define _S_IFDIR 0040000
#endif
#ifndef _S_IFLNK
#define _S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) (((mode)&(_S_IFMT))==(_S_IFLNK))
#endif

#if USE_STRLEN_FOR_AF_UNIX
#define AF_UNIX_SIZE(unaddr) \
  (sizeof((unaddr).sun_family) + strlen((unaddr).sun_path) + 1)
#else
#define AF_UNIX_SIZE(unaddr) sizeof(unaddr)
#endif

#define SUPPORT_OLD_CHANNELS

#ifdef _HPUX_SOURCE
#define seteuid(uid) setresuid(-1,(uid),-1)
#endif

#endif /* INCLUDES_H */
