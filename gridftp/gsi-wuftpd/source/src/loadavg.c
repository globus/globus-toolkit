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
#include "loadavg.h"

/*
   **  GETLA -- get the current load average
   **
   **      This code stolen from la.c.
   **
   **      Parameters:
   **              none.
   **
   **      Returns:
   **              The current load average as an integer.
   **
   **      Side Effects:
   **              none.
 */

/* try to guess what style of load average we have */
#define LA_ZERO         1	/* always return load average as zero */
#define LA_INT          2	/* read kmem for avenrun; interpret as long */
#define LA_FLOAT        3	/* read kmem for avenrun; interpret as float */
#define LA_SUBR         4	/* call getloadavg */
#define LA_MACH         5	/* MACH load averages (as on NeXT boxes) */
#define LA_SHORT        6	/* read kmem for avenrun; interpret as short */
#define LA_PROCSTR      7	/* read string ("1.17") from /proc/loadavg */
#define LA_READKSYM     8	/* SVR4: use MIOC_READKSYM ioctl call */
#define LA_DGUX         9	/* special DGUX implementation */
#define LA_HPUX         10	/* special HPUX implementation */
#define LA_IRIX6        11	/* special IRIX 6.2 implementation */
#define LA_KSTAT        12	/* special Solaris kstat(3k) implementation */
#define LA_DEVSHORT     13	/* read short from a device */
#define LA_ALPHAOSF     14	/* Digital UNIX (OSF/1 on Alpha) table() call */

/* do guesses based on general OS type */
#ifndef LA_TYPE
#define LA_TYPE        LA_ZERO
#endif

#ifndef FSHIFT
#if defined(unixpc)
#define FSHIFT        5
#endif

#if defined(__alpha) || defined(IRIX)
#define FSHIFT        10
#endif

#endif

#ifndef FSHIFT
#define FSHIFT         8
#endif

#ifndef FSCALE
#define FSCALE         (1 << FSHIFT)
#endif

#ifndef LA_AVENRUN
#ifdef SYSTEM5
#define LA_AVENRUN    "avenrun"
#else
#define LA_AVENRUN    "_avenrun"
#endif
#endif

/* _PATH_KMEM should be defined in <paths.h> */
#ifndef _PATH_KMEM
#define _PATH_KMEM     "/dev/kmem"
#endif

#if (LA_TYPE == LA_INT) || (LA_TYPE == LA_FLOAT) || (LA_TYPE == LA_SHORT)

#include <nlist.h>

/* _PATH_UNIX should be defined in <paths.h> */
#ifndef _PATH_UNIX
#if defined(SYSTEM5)
#define _PATH_UNIX    "/unix"
#else
#define _PATH_UNIX    "/vmunix"
#endif
#endif

#ifdef _AUX_SOURCE
struct nlist Nl[2];
#else
struct nlist Nl[] =
{
    {LA_AVENRUN},
    {0},
};
#endif
#define X_AVENRUN       0

int getla()
{
    static int kmem = -1;
#if LA_TYPE == LA_INT
    long avenrun[3];
#else
#if LA_TYPE == LA_SHORT
    short avenrun[3];
#else
    double avenrun[3];
#endif
#endif
    extern int errno;
    extern off_t lseek();

    if (kmem < 0) {
#ifdef _AUX_SOURCE
	strcpy(Nl[X_AVENRUN].n_name, LA_AVENRUN);
	Nl[1].n_name[0] = '\0';
#endif

#if defined(_AIX3) || defined(_AIX4)
	if (knlist(Nl, 1, sizeof Nl[0]) < 0)
#else
	if (nlist(_PATH_UNIX, Nl) < 0)
#endif
	    return (-1);
	if (Nl[X_AVENRUN].n_value == 0)
	    return (-1);
#ifdef NAMELISTMASK
	Nl[X_AVENRUN].n_value &= NAMELISTMASK;
#endif

	kmem = open(_PATH_KMEM, 0, 0);
	if (kmem < 0)
	    return (-1);
	(void) fcntl(kmem, F_SETFD, 1);
    }
    if (lseek(kmem, (off_t) Nl[X_AVENRUN].n_value, SEEK_SET) == -1 ||
	read(kmem, (char *) avenrun, sizeof(avenrun)) < sizeof(avenrun))
	/* thank you Ian */
	return (-1);
#if (LA_TYPE == LA_INT) || (LA_TYPE == LA_SHORT)
    return ((int) (avenrun[0] + FSCALE / 2) >> FSHIFT);
#else /* LA_TYPE == LA_FLOAT */
    return ((int) (avenrun[0] + 0.5));
#endif
}

#endif /* LA_TYPE == LA_INT or LA_SHORT or LA_FLOAT */

#if LA_TYPE == LA_READKSYM

#include <sys/ksym.h>

getla()
{
    static int kmem = -1;
    long avenrun[3];
    extern int errno;
    struct mioc_rksym mirk;

    if (kmem < 0) {
	kmem = open("/dev/kmem", 0, 0);
	if (kmem < 0)
	    return (-1);
	(void) fcntl(kmem, F_SETFD, 1);
    }
    mirk.mirk_symname = LA_AVENRUN;
    mirk.mirk_buf = avenrun;
    mirk.mirk_buflen = sizeof(avenrun);
    if (ioctl(kmem, MIOC_READKSYM, &mirk) < 0)
	return -1;
    return ((int) (avenrun[0] + FSCALE / 2) >> FSHIFT);
}

#endif /* LA_TYPE == LA_READKSYM */

#if LA_TYPE == LA_DGUX

#include <sys/dg_sys_info.h>

int getla()
{
    struct dg_sys_info_load_info load_info;

    dg_sys_info((long *) &load_info,
		DG_SYS_INFO_LOAD_INFO_TYPE, DG_SYS_INFO_LOAD_VERSION_0);

    return ((int) (load_info.one_minute + 0.5));
}

#endif /* LA_TYPE == LA_DGUX */

#if LA_TYPE == LA_HPUX

/* forward declarations to keep gcc from complaining */
struct pst_dynamic;
struct pst_status;
struct pst_static;
struct pst_vminfo;
struct pst_diskinfo;
struct pst_processor;
struct pst_lv;
struct pst_swapinfo;

#include <sys/param.h>
#include <sys/pstat.h>

int getla()
{
    struct pst_dynamic pstd;

    if (pstat_getdynamic(&pstd, sizeof(struct pst_dynamic),
			             (size_t) 1, 0) == -1)
	            return 0;

    return (int) (pstd.psd_avg_1_min + 0.5);
}

#endif /* LA_TYPE == LA_HPUX */

#if LA_TYPE == LA_SUBR

int getla()
{
    double avenrun[3];

    if (getloadavg(avenrun, sizeof(avenrun) / sizeof(avenrun[0])) < 0)
	return (-1);
    return ((int) (avenrun[0] + 0.5));
}

#endif /* LA_TYPE == LA_SUBR */

#if LA_TYPE == LA_MACH

/*
   **  This has been tested on NEXTSTEP release 2.1/3.X.
 */

#if defined(NX_CURRENT_COMPILER_RELEASE) && NX_CURRENT_COMPILER_RELEASE > NX_COMPILER_RELEASE_3_0
#include <mach/mach.h>
#else
#include <mach.h>
#endif

int getla()
{
    processor_set_t default_set;
    kern_return_t error;
    unsigned int info_count;
    struct processor_set_basic_info info;
    host_t host;

    error = processor_set_default(host_self(), &default_set);
    if (error != KERN_SUCCESS)
	return -1;
    info_count = PROCESSOR_SET_BASIC_INFO_COUNT;
    if (processor_set_info(default_set, PROCESSOR_SET_BASIC_INFO,
			   &host, (processor_set_info_t) & info,
			   &info_count) != KERN_SUCCESS)
	return -1;
    return (int) (info.load_average + (LOAD_SCALE / 2)) / LOAD_SCALE;
}

#endif /* LA_TYPE == LA_MACH */

#if LA_TYPE == LA_PROCSTR

/*
   **  Read /proc/loadavg for the load average.  This is assumed to be
   **  in a format like "0.15 0.12 0.06".
   **
   **      Initially intended for Linux.  This has been in the kernel
   **      since at least 0.99.15.
 */

#include <stdio.h>

#ifndef _PATH_LOADAVG
#define _PATH_LOADAVG "/proc/loadavg"
#endif

int getla()
{
    double avenrun;
    register int result;
    FILE *fp;

    fp = fopen(_PATH_LOADAVG, "r");
    if (fp == NULL)
	return -1;
    result = fscanf(fp, "%lf", &avenrun);
    fclose(fp);
    if (result != 1)
	return -1;

    return ((int) (avenrun + 0.5));
}

#endif /* LA_TYPE == LA_PROCSTR */

#if LA_TYPE == LA_IRIX6
#include <sys/sysmp.h>

int getla(void)
{
    static int kmem = -1;
    int avenrun[3];

    if (kmem < 0) {
	kmem = open(_PATH_KMEM, 0, 0);
	if (kmem < 0)
	    return -1;
	(void) fcntl(kmem, F_SETFD, 1);
    }

    if (lseek(kmem, (sysmp(MP_KERNADDR, MPKA_AVENRUN) & 0x7fffffff), SEEK_SET) == -1 ||
	read(kmem, (char *) avenrun, sizeof(avenrun)) < sizeof(avenrun))
	return -1;

    return ((int) (avenrun[0] + FSCALE / 2) >> FSHIFT);

}

#endif

#if LA_TYPE == LA_KSTAT

#include <kstat.h>

int getla()
{
    static kstat_ctl_t *kc = NULL;
    static kstat_t *ksp = NULL;
    kstat_named_t *ksn;
    int la;

    if (kc == NULL)		/* if not initialized before */
	kc = kstat_open();
    if (kc == NULL)
	return -1;
    if (ksp == NULL)
	ksp = kstat_lookup(kc, "unix", 0, "system_misc");
    if (ksp == NULL)
	return -1;
    if (kstat_read(kc, ksp, NULL) < 0)
	return -1;
    ksn = (kstat_named_t *) kstat_data_lookup(ksp, "avenrun_1min");
    la = ((double) ksn->value.ul + FSCALE / 2) / FSCALE;
    /* kstat_close(kc); /o do not close for fast access */
    return la;
}

#endif /* LA_TYPE == LA_KSTAT */

#if LA_TYPE == LA_DEVSHORT

/*
   **  Read /dev/table/avenrun for the load average.  This should contain
   **  three shorts for the 1, 5, and 15 minute loads.  We only read the
   **  first, since that's all we care about.
   **
   **      Intended for SCO OpenServer 5.
 */

#ifndef _PATH_AVENRUN
#define _PATH_AVENRUN "/dev/table/avenrun"
#endif

int getla()
{
    static int afd = -1;
    short avenrun;
    int loadav;
    int r;

    errno = EBADF;

    if (afd == -1 || lseek(afd, 0L, SEEK_SET) == -1) {
	if (errno != EBADF)
	    return -1;
	afd = open(_PATH_AVENRUN, O_RDONLY | O_SYNC);
	if (afd < 0) {
	    sm_syslog(LOG_ERR, NOQID,
		      "can't open %s: %m",
		      _PATH_AVENRUN);
	    return -1;
	}
    }

    r = read(afd, &avenrun, sizeof avenrun);

    loadav = (int) (avenrun + FSCALE / 2) >> FSHIFT;
    return loadav;
}

#endif /* LA_TYPE == LA_DEVSHORT */

#if LA_TYPE == LA_ALPHAOSF
struct rtentry;
struct mbuf;
#include <sys/table.h>

int getla()
{
    int ave = 0;
    struct tbl_loadavg tab;

    if (table (TBL_LOADAVG, 0, &tab, 1, sizeof(tab)) == -1)
	return (-1);

    if (tab.tl_lscale)
	ave = (tab.tl_avenrun.l[0] + (tab.tl_lscale / 2)) / tab.tl_lscale;
    else
	ave = (int) (tab.tl_avenrun.d[0] + 0.5);

    return ave;
}

#endif

#if LA_TYPE == LA_ZERO

int getla()
{
    return (0);
}

#endif /* LA_TYPE == LA_ZERO */

/*
 * Copyright 1989 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * M.I.T. DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL M.I.T.
 * BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Authors:  Many and varied...
 */

/* Non Apollo stuff removed by Don Lewis 11/15/93 */

#ifdef apollo
#undef volatile
#include <apollo/base.h>

/* ARGSUSED */
int getloadavg(call_data)
     caddr_t call_data;		/* pointer to (double) return value */
{
    double *avenrun = (double *) call_data;
    int i;
    status_$t st;
    long loadav[3];
    proc1_$get_loadav(loadav, &st);
    *avenrun = loadav[0] / (double) (1 << 16);
    return (0);
}
#endif /* apollo */
