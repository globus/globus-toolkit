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
#include "config.h"
#include "proto.h"

 /*
  * delay_signaling(), enable_signaling - delay signal delivery for a while
  * 
  * Original Author: Wietse Venema with small changes by Dave Kinchlea and 
  * Stan Barber
  */

/* 
 * Some folks (notably those who do Linux hacking) say this fix is needed.
 * Others (notably the FreeBSD and BSDI folks) say if isn't.
 * I am making it possible to include or exclude it.
 * Just define NEED_SIGFIX and you get it.
 */
#ifdef NEED_SIGFIX
#include <sys/types.h>
#include <sys/signal.h>
#include <syslog.h>

static sigset_t saved_sigmask;
sigset_t block_sigmask;		/* used in ftpd.c */
static int delaying;
static int init_done;
#endif
/* enable_signaling - deliver delayed signals and disable signal delay */

int enable_signaling(void)
{
#ifdef NEED_SIGFIX
    if (delaying != 0) {
	delaying = 0;
	if (sigprocmask(SIG_SETMASK, &saved_sigmask, (sigset_t *) 0) < 0) {
	    syslog(LOG_ERR, "sigprocmask: %m");
	    return (-1);
	}
    }
#endif
    return (0);
}

/* delay_signaling - save signal mask and block all signals */
int delay_signaling(void)
{
#ifdef NEED_SIGFIX
    if (delaying == 0) {
	delaying = 1;
	if (sigprocmask(SIG_BLOCK, &block_sigmask, &saved_sigmask) < 0) {
	    syslog(LOG_ERR, "sigprocmask: %m");
	    return (-1);
	}
    }
#endif
    return (0);
}
