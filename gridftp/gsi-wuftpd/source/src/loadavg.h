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
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <string.h>
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
#include <errno.h>
#include <sysexits.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __QNX__
/* in QNX this grabs bogus LOCK_* manifests */
#include <sys/file.h>
#endif
#include <sys/wait.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <pwd.h>

/**********************************************************************
**  Operating system configuration.
**
**      Unless you are porting to a new OS, you shouldn't have to
**      change these.
**********************************************************************/

/*
   **  HP-UX -- tested for 8.07, 9.00, and 9.01.
   **
   **      If V4FS is defined, compile for HP-UX 10.0.
   **      11.x support from Richard Allen <ra@hp.is>.
 */

#ifdef __hpux
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_HPUX
#ifdef V4FS
		/* HP-UX 10.x */
#define _PATH_UNIX            "/stand/vmunix"
#else
		/* HP-UX 9.x */
#define _PATH_UNIX            "/hp-ux"
#endif
#endif

/*
   **  IBM AIX 4.x
 */

#ifdef _AIX4
#define _AIX3          1	/* pull in AIX3 stuff */
#endif

/*
   **  IBM AIX 3.x -- actually tested for 3.2.3
 */

#ifdef _AIX3
#include <paths.h>
#include <sys/machine.h>	/* to get byte order */
#include <sys/select.h>
#define LA_TYPE        LA_INT
#define FSHIFT         16
#define LA_AVENRUN     "avenrun"
#endif

/*
   **  IBM AIX 2.2.1 -- actually tested for osupdate level 2706+1773
   **
   **      From Mark Whetzel <markw@wg.waii.com>.
 */

#ifdef AIX
#include <paths.h>
#define LA_TYPE        LA_SUBR	/* use our ported loadavgd daemon */
#endif

/*
   **  Silicon Graphics IRIX
   **
   **      Compiles on 4.0.1.
   **
   **      Use IRIX64 instead of IRIX for 64-bit IRIX (6.0).
   **      Use IRIX5 instead of IRIX for IRIX 5.x.
   **
   **      This version tries to be adaptive using _MIPS_SIM:
   **              _MIPS_SIM == _ABIO32 (= 1)    Abi: -32  on IRIX 6.2
   **              _MIPS_SIM == _ABIN32 (= 2)    Abi: -n32 on IRIX 6.2
   **              _MIPS_SIM == _ABI64  (= 3)    Abi: -64 on IRIX 6.2
   **
   **              _MIPS_SIM is 1 also on IRIX 5.3
   **
   **      IRIX64 changes from Mark R. Levinson <ml@cvdev.rochester.edu>.
   **      IRIX5 changes from Kari E. Hurtta <Kari.Hurtta@fmi.fi>.
   **      Adaptive changes from Kari E. Hurtta <Kari.Hurtta@fmi.fi>.
 */

#if defined(__sgi)
#ifndef IRIX
#define IRIX
#endif
#if _MIPS_SIM > 0 && !defined(IRIX5)
#define IRIX5			/* IRIX5 or IRIX6 */
#endif
#if _MIPS_SIM > 1 && !defined(IRIX6) && !defined(IRIX64)
#define IRIX6			/* IRIX6 */
#endif
#endif

#ifdef IRIX
#define SYSTEM5        1	/* this is a System-V derived system */
#ifdef IRIX6
#define LA_TYPE       LA_IRIX6	/* figure out at run time */
#else
#define LA_TYPE       LA_INT
#endif
#if defined(IRIX64) || defined(IRIX5) || defined(IRIX6)
#include <sys/cdefs.h>
#include <paths.h>
#endif
#endif

/*
   **  SunOS and Solaris
   **
   **      Tested on SunOS 4.1.x (a.k.a. Solaris 1.1.x) and
   **      Solaris 2.4 (a.k.a. SunOS 5.4).
 */

#if defined(sun) && !defined(BSD)

#ifdef SOLARIS_2_3
#define SOLARIS       20300	/* for back compat only -- use -DSOLARIS=20300 */
#endif
#if !defined(SOLARIS) && defined(sun) && (defined(__svr4__) || defined(__SVR4))
#define SOLARIS       1		/* unknown Solaris version */
#endif
#ifdef SOLARIS
			/* Solaris 2.x (a.k.a. SunOS 5.x) */
#ifndef __svr4__
#define __svr4__		/* use all System V Releae 4 defines below */
#endif
#ifndef _PATH_UNIX
#define _PATH_UNIX           "/dev/ksyms"
#endif
#if SOLARIS >= 20500 || (SOLARIS < 10000 && SOLARIS >= 205)
#if SOLARIS < 207 || (SOLARIS > 10000 && SOLARIS < 20700)
#ifndef LA_TYPE
#define LA_TYPE    LA_KSTAT	/* use kstat(3k) -- may work in < 2.5 */
#endif
#endif
#endif
#if SOLARIS >= 20700 || (SOLARIS < 10000 && SOLARIS >= 207)
#ifndef LA_TYPE
#define LA_TYPE     LA_SUBR	/* getloadavg(3c) appears in 2.7 */
#endif
#endif
#else
			/* SunOS 4.0.3 or 4.1.x */
#include <memory.h>
#include <vfork.h>
#ifdef SUNOS403
			/* special tweaking for SunOS 4.0.3 */
#include <malloc.h>
#define BSD4_3       1		/* 4.3 BSD-based */
#endif
#endif
#ifndef LA_TYPE
#define LA_TYPE       LA_INT
#endif
#endif /* sun && !BSD */

/*
   **  DG/UX
   **
   **      Tested on 5.4.2 and 5.4.3.  Use DGUX_5_4_2 to get the
   **      older support.
   **      5.4.3 changes from Mark T. Robinson <mtr@ornl.gov>.
 */

#ifdef DGUX_5_4_2
#define DGUX           1
#endif

#ifdef  DGUX
#define SYSTEM5        1
#define LA_TYPE        LA_DGUX

/* these include files must be included early on DG/UX */
#include <netinet/in.h>
#include <arpa/inet.h>

/* compiler doesn't understand const? */
#define const

#endif

/*
   **  Digital Ultrix 4.2A or 4.3
   **
   **      Apparently, fcntl locking is broken on 4.2A, in that locks are
   **      not dropped when the process exits.  This causes major problems,
   **      so flock is the only alternative.
 */

#ifdef ultrix
#ifdef vax
#define LA_TYPE       LA_FLOAT
#else
#define LA_TYPE       LA_INT
#define LA_AVENRUN    "avenrun"
#endif
#endif

/*
   **  OSF/1 for KSR.
   **
   **      Contributed by Todd C. Miller <Todd.Miller@cs.colorado.edu>
 */

#ifdef __ksr__
#define __osf__        1	/* get OSF/1 defines below */
#endif

/*
   **  OSF/1 for Intel Paragon.
   **
   **      Contributed by Jeff A. Earickson <jeff@ssd.intel.com>
   **      of Intel Scalable Systems Divison.
 */

#ifdef __PARAGON__
#define __osf__        1	/* get OSF/1 defines below */
#endif

/*
   **  OSF/1 (tested on Alpha) -- now known as Digital UNIX.
   **
   **      Tested for 3.2 and 4.0.
 */

#ifdef __osf__
#define LA_TYPE        LA_ALPHAOSF
#endif

/*
   **  NeXTstep
 */

#ifdef NeXT
#ifndef LA_TYPE
#define LA_TYPE       LA_MACH
#endif
#endif

/*
   **  4.4 BSD
   **
   **      See also BSD defines.
 */

#if defined(BSD4_4) && !defined(__bsdi__) && !defined(__GNU__)
#include <paths.h>
#include <sys/cdefs.h>
#ifndef LA_TYPE
#define LA_TYPE       LA_SUBR
#endif
#endif

/*
   **  BSD/OS (was BSD/386) (all versions)
   **      From Tony Sanders, BSDI
 */

#ifdef __bsdi__
#include <paths.h>
#include <sys/cdefs.h>
#ifndef LA_TYPE
#define LA_TYPE       LA_SUBR
#endif
#endif

/*
   **  QNX 4.2x
   **      Contributed by Glen McCready <glen@qnx.com>.
   **
   **      Should work with all versions of QNX.
 */

#if defined(__QNX__)
#include <unix.h>
#include <sys/select.h>
#define LA_TYPE        LA_ZERO
#endif

/*
   **  FreeBSD / NetBSD / OpenBSD (all architectures, all versions)
   **
   **  4.3BSD clone, closer to 4.4BSD      for FreeBSD 1.x and NetBSD 0.9x
   **  4.4BSD-Lite based                   for FreeBSD 2.x and NetBSD 1.x
   **
   **      See also BSD defines.
 */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <paths.h>
#include <sys/cdefs.h>
#ifndef LA_TYPE
#define LA_TYPE       LA_SUBR
#endif
#if defined(__FreeBSD__)
#if __FreeBSD__ == 2
#include <osreldate.h>		/* and this works */
#if __FreeBSD_version >= 199512	/* 2.2-current right now */
#include <libutil.h>
#endif
#endif
#endif
#endif

/*
   **  Mach386
   **
   **      For mt Xinu's Mach386 system.
 */

#if defined(MACH) && defined(i386) && !defined(__GNU__)
#define MACH386        1
#ifndef LA_TYPE
#define LA_TYPE       LA_FLOAT
#endif
#endif

/*
   **  GNU OS (hurd)
   **      Largely BSD & posix compatible.
   **      Port contributed by Miles Bader <miles@gnu.ai.mit.edu>.
 */

#ifdef __GNU_HURD__
#define LA_TYPE        LA_MACH
#endif /* GNU */

/*
   **  4.3 BSD -- this is for very old systems
   **
   **      Should work for mt Xinu MORE/BSD and Mips UMIPS-BSD 2.1.
   **
   **      You'll also have to install a new resolver library.
   **      I don't guarantee that support for this environment is complete.
 */

#if defined(oldBSD43) || defined(MORE_BSD) || defined(umipsbsd)
#ifndef LA_TYPE
#define LA_TYPE       LA_FLOAT
#endif
#endif

/*
   **  SCO Unix
   **
   **      This includes three parts:
   **
   **      The first is for SCO OpenServer 5.
   **      (Contributed by Keith Reynolds <keithr@sco.COM>).
   **
   **              SCO OpenServer 5 has a compiler version number macro,
   **              which we can use to figure out what version we're on.
   **              This may have to change in future releases.
   **
   **      The second is for SCO UNIX 3.2v4.2/Open Desktop 3.0.
   **      (Contributed by Philippe Brand <phb@colombo.telesys-innov.fr>).
   **
   **      The third is for SCO UNIX 3.2v4.0/Open Desktop 2.0 and earlier.
 */

/* SCO OpenServer 5 */
#if _SCO_DS >= 1
#include <paths.h>
#ifndef LA_TYPE
#define LA_TYPE       LA_DEVSHORT
#endif
#define _PATH_AVENRUN  "/dev/table/avenrun"
#ifndef _SCO_unix_4_2
#define _SCO_unix_4_2
#endif
#endif

/* SCO UNIX 3.2v4.2/Open Desktop 3.0 */
#ifdef _SCO_unix_4_2
#define _SCO_unix_
#endif

/* SCO UNIX 3.2v4.0 Open Desktop 2.0 and earlier */
#ifdef _SCO_unix_
#include <sys/stream.h>		/* needed for IP_SRCROUTE */
#define SYSTEM5        1	/* include all the System V defines */
#define _PATH_UNIX             "/unix"
#ifndef _SCO_DS
#define LA_TYPE       LA_SHORT
#endif
#endif

/*
   **  ISC (SunSoft) Unix.
   **
   **      Contributed by J.J. Bailey <jjb@jagware.bcc.com>
 */

#ifdef ISC_UNIX
#include <net/errno.h>
#include <sys/stream.h>		/* needed for IP_SRCROUTE */
#include <sys/bsdtypes.h>
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_SHORT
#define _PATH_UNIX             "/unix"
#endif

/*
   **  Altos System V (5.3.1)
   **      Contributed by Tim Rice <tim@trr.metro.net>.
 */

#ifdef ALTOS_SYSTEM_V
#include <sys/stream.h>
#include <limits.h>
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_SHORT
#endif

/*
   **  ConvexOS 11.0 and later
   **
   **      "Todd C. Miller" <millert@mroe.cs.colorado.edu> claims this
   **      works on 9.1 as well.
   **
   **  ConvexOS 11.5 and later, should work on 11.0 as defined.
   **  For pre-ConvexOOS 11.0, define NEEDGETOPT, undef IDENTPROTO
   **
   **      Eric Schnoebelen (eric@cirr.com) For CONVEX Computer Corp.
   **              (now the CONVEX Technologies Center of Hewlett Packard)
 */

#ifdef _CONVEX_SOURCE
#define LA_TYPE        LA_FLOAT
#endif

/*
   **  RISC/os 4.52
   **
   **      Gives a ton of warning messages, but otherwise compiles.
 */

#ifdef RISCOS
#define LA_TYPE        LA_INT
#define LA_AVENRUN     "avenrun"
#define _PATH_UNIX     "/unix"
#endif

/*
   **  Linux 0.99pl10 and above...
   **
   **  Thanks to, in reverse order of contact:
   **
   **      John Kennedy <warlock@csuchico.edu>
   **      Andrew Pam <avatar@aus.xanadu.com>
   **      Florian La Roche <rzsfl@rz.uni-sb.de>
   **      Karl London <karl@borg.demon.co.uk>
   **
   **  Last compiled against:      [06/10/96 @ 09:21:40 PM (Monday)]
   **      sendmail 8.8-a4         named bind-4.9.4-T4B    db-1.85
   **      gcc 2.7.2               libc-5.3.12             linux 2.0.0
   **
   **  NOTE: Override HASFLOCK as you will but, as of 1.99.6, mixed-style
   **      file locking is no longer allowed.  In particular, make sure
   **      your DBM library and sendmail are both using either flock(2)
   **      *or* fcntl(2) file locking, but not both.
 */

#ifdef __linux__
#define BSD            1	/* include BSD defines */
#ifndef LA_TYPE
#define LA_TYPE       LA_PROCSTR
#endif
#include <sys/sysmacros.h>
#endif

/*
   **  DELL SVR4 Issue 2.2, and others
   **      From Kimmo Suominen <kim@grendel.lut.fi>
   **
   **      It's on #ifdef DELL_SVR4 because Solaris also gets __svr4__
   **      defined, and the definitions conflict.
   **
   **      Peter Wemm <peter@perth.DIALix.oz.au> claims that the setreuid
   **      trick works on DELL 2.2 (SVR4.0/386 version 4.0) and ESIX 4.0.3A
   **      (SVR4.0/386 version 3.0).
 */

#ifdef DELL_SVR4
				/* no changes necessary */
				/* see general __svr4__ defines below */
#endif

/*
   **  Apple A/UX 3.0
 */

#ifdef _AUX_SOURCE
#include <sys/sysmacros.h>
#define BSD			/* has BSD routines */
#ifndef LA_TYPE
#define LA_TYPE       LA_INT
#define FSHIFT        16
#endif
#define LA_AVENRUN     "avenrun"
#ifndef _PATH_UNIX
#define _PATH_UNIX            "/unix"	/* should be in <paths.h> */
#endif
#endif

/*
   **  Encore UMAX V
   **
   **      Not extensively tested.
 */

#ifdef UMAXV
#endif

/*
   **  Stardent Titan 3000 running TitanOS 4.2.
   **
   **      Must be compiled in "cc -43" mode.
   **
   **      From Kate Hedstrom <kate@ahab.rutgers.edu>.
   **
   **      Note the tweaking below after the BSD defines are set.
 */

#ifdef titan
#endif

/*
   **  Sequent DYNIX 3.2.0
   **
   **      From Jim Davis <jdavis@cs.arizona.edu>.
 */

#ifdef sequent
#define BSD            1
#define LA_TYPE        LA_FLOAT
#ifndef _PATH_UNIX
#define _PATH_UNIX            "/dynix"
#endif
#endif

/*
   **  Sequent DYNIX/ptx v2.0 (and higher)
   **
   **      For DYNIX/ptx v1.x, undefine HASSETREUID.
   **
   **      From Tim Wright <timw@sequent.com>.
   **      Update from Jack Woolley <jwoolley@sctcorp.com>, 26 Dec 1995,
   **              for DYNIX/ptx 4.0.2.
 */

#ifdef _SEQUENT_
#include <sys/stream.h>
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_INT
#endif

/*
   **  Cray Unicos
   **
   **      Ported by David L. Kensiski, Sterling Sofware <kensiski@nas.nasa.gov>
 */

#ifdef UNICOS
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_ZERO
#endif

/*
   **  Apollo DomainOS
   **
   **  From Todd Martin <tmartint@tus.ssi1.com> & Don Lewis <gdonl@gv.ssi1.com>
   **
   **  15 Jan 1994; updated 2 Aug 1995
   **
 */

#ifdef apollo
#define LA_TYPE        LA_SUBR	/* use getloadavg.c */
#endif

/*
   **  UnixWare 2.x
 */

#ifdef UNIXWARE2
#define UNIXWARE       1
#endif

/*
   **  UnixWare 1.1.2.
   **
   **      Updated by Petr Lampa <lampa@fee.vutbr.cz>.
   **      From Evan Champion <evanc@spatial.synapse.org>.
 */

#ifdef UNIXWARE
#include <sys/mkdev.h>
#define SYSTEM5                1
#define LA_TYPE                LA_ZERO
#define _PATH_UNIX             "/unix"
#endif

/*
   **  Intergraph CLIX 3.1
   **
   **      From Paul Southworth <pauls@locust.cic.net>
 */

#ifdef CLIX
#define SYSTEM5        1	/* looks like System V */
#endif

/*
   **  NCR MP-RAS 2.x (SysVr4) with Wollongong TCP/IP
   **
   **      From Kevin Darcy <kevin@tech.mis.cfc.com>.
 */

#ifdef NCR_MP_RAS2
#include <sys/sockio.h>
#define __svr4__
#endif

/*
   **  NCR MP-RAS 3.x (SysVr4) with STREAMware TCP/IP
   **
   **      From Tom Moore <Tom.Moore@DaytonOH.NCR.COM>
 */

#ifdef NCR_MP_RAS3
#define __svr4__
#endif

/*
   **  Tandem NonStop-UX SVR4
   **
   **      From Rick McCarty <mccarty@mpd.tandem.com>.
 */

#ifdef NonStop_UX_BXX
#define __svr4__
#endif

/*
   **  Hitachi 3050R & 3050RX Workstations running HI-UX/WE2.
   **
   **      Tested for 1.04 and 1.03
   **      From Akihiro Hashimoto ("Hash") <hash@dominic.ipc.chiba-u.ac.jp>.
 */

#ifdef __H3050R
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_FLOAT
#ifndef _PATH_UNIX
#define _PATH_UNIX            "/HI-UX"
#endif
#endif

/*
   **  Amdahl UTS System V 2.1.5 (SVr3-based)
   **
   **    From: Janet Jackson <janet@dialix.oz.au>.
 */

#ifdef _UTS
#include <sys/sysmacros.h>
#define LA_TYPE        LA_ZERO	/* doesn't have load average */
#define _PATH_UNIX             "/unix"
#endif

/*
   **  Cray Computer Corporation's CSOS
   **
   **      From Scott Bolte <scott@craycos.com>.
 */

#ifdef _CRAYCOM
#define SYSTEM5        1	/* include all the System V defines */
#define LA_TYPE        LA_ZERO
#endif

/*
   **  Sony NEWS-OS 4.2.1R and 6.0.3
   **
   **      From Motonori NAKAMURA <motonori@cs.ritsumei.ac.jp>.
 */

#ifdef sony_news
#ifndef __svr4
#ifndef BSD
#define BSD			/* has BSD routines */
#endif
#define LA_TYPE       LA_INT
#else
#ifndef __svr4__
#define __svr4__		/* use all System V Releae 4 defines below */
#endif
#define LA_TYPE       LA_READKSYM	/* use MIOC_READKSYM ioctl */
#define _PATH_UNIX            "/stand/unix"
#endif
#endif

/*
   **  Omron LUNA/UNIOS-B 3.0, LUNA2/Mach and LUNA88K Mach
   **
   **      From Motonori NAKAMURA <motonori@cs.ritsumei.ac.jp>.
 */

#ifdef luna
#ifdef uniosb
#define LA_TYPE       LA_INT
#endif
#ifdef luna2
#define LA_TYPE       LA_SUBR
#endif
#ifdef luna88k
#define LA_TYPE       LA_INT
#endif
#endif

/*
   **  NEC EWS-UX/V 4.2 (with /usr/ucb/cc)
   **
   **      From Motonori NAKAMURA <motonori@cs.ritsumei.ac.jp>.
 */

#if defined(nec_ews_svr4) || defined(_nec_ews_svr4)
#ifndef __svr4__
#define __svr4__		/* use all System V Releae 4 defines below */
#endif
#define LA_TYPE        LA_READKSYM	/* use MIOC_READSYM ioctl */
#endif

/*
   **  Fujitsu/ICL UXP/DS (For the DS/90 Series)
   **
   **      From Diego R. Lopez <drlopez@cica.es>.
   **      Additional changes from Fumio Moriya and Toshiaki Nomura of the
   **              Fujitsu Fresoftware gruop <dsfrsoft@oai6.yk.fujitsu.co.jp>.
 */

#ifdef __uxp__
#include <arpa/nameser.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#define __svr4__
#define _PATH_UNIX             "/stand/unix"
#endif

/*
   **  Pyramid DC/OSx
   **
   **      From Earle Ake <akee@wpdiss1.wpafb.af.mil>.
 */

#ifdef DCOSx
#endif

/*
   **  Concurrent Computer Corporation Maxion
   **
   **      From Donald R. Laster Jr. <laster@access.digex.net>.
 */

#ifdef __MAXION__
#include <sys/stream.h>
#define __svr4__               1	/* SVR4.2MP */
#endif

/*
   **  Harris Nighthawk PowerUX (nh6000 box)
   **
   **  Contributed by Bob Miorelli, Pratt & Whitney <miorelli@pweh.com>
 */

#ifdef _PowerUX
#ifndef __svr4__
#define __svr4__
#endif
#define LA_TYPE                LA_ZERO
#endif

/*
   **  Siemens Nixdorf Informationssysteme AG SINIX
   **
   **      Contributed by Gerald Rinske <Gerald.Rinske@mch.sni.de>
   **      of Siemens Business Services VAS.
 */

#ifdef sinix
#endif

/*
   **  CRAY T3E
   **
   **      Contributed by Manu Mahonen <mailadm@csc.fi>
   **      of Center for Scientific Computing.
 */
#ifdef _CRAY
#endif

/**********************************************************************
**  End of Per-Operating System defines
**********************************************************************/

/**********************************************************************
**  More general defines
**********************************************************************/

#ifdef BSD
#endif

#ifdef __svr4__
#define SYSTEM5        1
#ifndef _PATH_UNIX
#define _PATH_UNIX            "/unix"
#endif
#endif

#ifdef SYSTEM5
#include <sys/sysmacros.h>
#ifndef LA_TYPE
#ifdef MIOC_READKSYM
#define LA_TYPE      LA_READKSYM	/* use MIOC_READKSYM ioctl */
#else
#define LA_TYPE      LA_INT	/* assume integer load average */
#endif
#endif
#endif


/* general POSIX defines */
#ifdef _POSIX_VERSION
#endif

/*
   **  Tweaking for systems that (for example) claim to be BSD or POSIX
   **  but don't have all the standard BSD or POSIX routines (boo hiss).
 */
