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
#ifndef NO_PRIVATE

#include "config.h"

#include <stdio.h>
#include <errno.h>

extern char *strsep(char **, const char *);

#include <string.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include "pathnames.h"
#include "extensions.h"
#include "proto.h"

#ifdef SECUREOSF
#define SecureWare		/* Does this mean it works for all SecureWare? */
#endif

#ifdef HPUX_10_TRUSTED
#include <hpsecurity.h>
#endif

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
#include <prot.h>
#endif

#ifndef NO_CRYPT_PROTO
extern char *crypt(const char *, const char *);
#endif

#define MAXGROUPLEN 100
char *passbuf = NULL;
char groupname[MAXGROUPLEN];
int group_given = 0;

struct acgrp {
    char gname[MAXGROUPLEN];	/* access group name */
    char gpass[MAXGROUPLEN];	/* access group password */
    char gr_name[MAXGROUPLEN];	/* group to setgid() to */
    gid_t gr_gid;
    struct acgrp *next;
};

struct acgrp *privptr;

extern int lgi_failure_threshold, autospout_free;
extern char remotehost[], remoteaddr[], remoteident[], *autospout;
int group_attempts;

void parsepriv(void)
{
    char *ptr;
    char *acptr = passbuf, *line;
    char *argv[3], *p, *val;
    struct acgrp *aptr, *privtail = (struct acgrp *) NULL;
    struct group *gr;
    int n;

    if (!passbuf || !(*passbuf))
	return;

    /* read through passbuf, stripping comments. */
    while (*acptr != '\0') {
	line = acptr;
	while (*acptr && *acptr != '\n')
	    acptr++;
	*acptr++ = '\0';

	/* deal with comments */
	if ((ptr = strchr(line, '#')) != NULL)
	    *ptr = '\0';

	if (*line == '\0')
	    continue;

	/* parse the lines... */
	for (n = 0, p = line; n < 3 && p != NULL; n++) {
	    val = (char *) strsep(&p, ":\n");
	    argv[n] = val;
	    if ((argv[n][0] == ' ') || (argv[n][0] == '\0'))
		argv[n] = NULL;
	}
	/* check their were 3 fields, if not skip the line... */
	if (n != 3 || p != NULL)
	    continue;

	if (argv[0] && argv[2]) {
	    if (argv[2][0] == '%') {
		gid_t gid = atoi(argv[2] + 1);
		if ((gr = getgrgid(gid)) != NULL) {
		    aptr = (struct acgrp *) calloc(1, sizeof(struct acgrp));
		    if (aptr == NULL) {
			syslog(LOG_ERR, "calloc error in parsepriv");
			exit(0);
		    }

		    /* add element to end of list */
		    if (privtail)
			privtail->next = aptr;
		    privtail = aptr;
		    if (!privptr)
			privptr = aptr;

		    strcpy(aptr->gname, (char *) argv[0]);
		    if (argv[1] == NULL)
			aptr->gpass[0] = '\0';
		    else
			strcpy(aptr->gpass, (char *) argv[1]);
		    strcpy(aptr->gr_name, gr->gr_name);
		    aptr->gr_gid = gid;
		}
	    }
	    else {
		if ((gr = getgrnam((char *) argv[2])) != NULL) {
		    aptr = (struct acgrp *) calloc(1, sizeof(struct acgrp));
		    if (aptr == NULL) {
			syslog(LOG_ERR, "calloc error in parsepriv");
			exit(0);
		    }

		    /* add element to end of list */
		    if (privtail)
			privtail->next = aptr;
		    privtail = aptr;
		    if (!privptr)
			privptr = aptr;

		    strcpy(aptr->gname, (char *) argv[0]);
		    if (argv[1] == NULL)
			aptr->gpass[0] = '\0';
		    else
			strcpy(aptr->gpass, (char *) argv[1]);
		    strcpy(aptr->gr_name, (char *) argv[2]);
		    aptr->gr_gid = gr->gr_gid;
		}
	    }
	    endgrent();
	}
    }
}

/*************************************************************************/
/* FUNCTION  : priv_setup                                                */
/* PURPOSE   : Set things up to use the private access password file.    */
/* ARGUMENTS : path, the path to the private access password file        */
/*************************************************************************/

void priv_setup(char *path)
{
    FILE *prvfile;
    struct stat finfo;

    passbuf = (char *) NULL;

    if ((prvfile = fopen(path, "r")) == NULL) {
	if (errno != ENOENT)
	    syslog(LOG_ERR, "cannot open private access file %s: %s",
		   path, strerror(errno));
	return;
    }
    if (fstat(fileno(prvfile), &finfo) != 0) {
	syslog(LOG_ERR, "cannot fstat private access file %s: %s", path,
	       strerror(errno));
	(void) fclose(prvfile);
	return;
    }
    if (finfo.st_size == 0) {
	passbuf = (char *) calloc(1, 1);
    }
    else {
	if (!(passbuf = (char *) malloc((unsigned) finfo.st_size + 1))) {
	    (void) syslog(LOG_ERR, "could not malloc passbuf (%d bytes)",
			  finfo.st_size + 1);
	    (void) fclose(prvfile);
	    return;
	}
	if (!fread(passbuf, (size_t) finfo.st_size, 1, prvfile)) {
	    (void) syslog(LOG_ERR, "error reading private access file %s: %s",
			  path, strerror(errno));
	    (void) fclose(prvfile);
	    return;
	}
	*(passbuf + finfo.st_size) = '\0';
    }
    (void) fclose(prvfile);
    (void) parsepriv();
}

/*************************************************************************/
/* FUNCTION  : priv_getent                                               */
/* PURPOSE   : Retrieve an entry from the in-memory copy of the group    */
/* access file.                                              */
/* ARGUMENTS : pointer to group name                                     */
/*************************************************************************/

static struct acgrp *priv_getent(char *group)
{
    struct acgrp *ptr;

    for (ptr = privptr; ptr; ptr = ptr->next)
	if (!strcasecmp(group, ptr->gname))
	    return (ptr);

    return (NULL);
}

/*************************************************************************/
/* FUNCTION  : priv_group                                                */
/* PURPOSE   :                                                           */
/* ARGUMENTS :                                                           */
/*************************************************************************/

void priv_group(char *group)
{
    if ((int) strlen(group) < MAXGROUPLEN) {
	strncpy(groupname, group, MAXGROUPLEN);
	group_given = 1;
	reply(200, "Request for access to group %s accepted.", group);
    }
    else {
	group_given = 0;
	reply(500, "Illegal group name");
    }

}

/*************************************************************************/
/* FUNCTION  : priv_gpass                                                */
/* PURPOSE   : validate the group access request, and if OK place user   */
/* in the proper group.                                      */
/* ARGUMENTS : group access password                                     */
/*************************************************************************/

void priv_gpass(char *gpass)
{
    char *xgpass = NULL;
    struct acgrp *grp;
    uid_t uid;
    gid_t gid;

    if (group_given == 0) {
	reply(503, "Give group name with SITE GROUP first.");
	return;
    }
    /* OK, now they're getting a chance to specify a password.  Make them
     * give the group name again if they fail... */
    group_given = 0;

    grp = priv_getent(groupname);
    if (passbuf && gpass && *gpass != '\0' && grp && *grp->gpass != '\0')
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
	xgpass = bigcrypt(gpass, grp->gpass);
#else
	xgpass = crypt(gpass, grp->gpass);
#endif

    if (!(((gpass != NULL)
	   && (*gpass != '\0')
	   && (grp != NULL)
	   && (*grp->gpass != '\0')
	   && (strcmp(xgpass, grp->gpass) == 0))
	  || (((gpass == NULL)
	       || (*gpass == '\0'))
	      && (grp != NULL)
	      && (*grp->gpass == '\0'))
	)) {
	reply(530, "Group access request incorrect.");
	grp = NULL;
	if (++group_attempts >= lgi_failure_threshold) {
	    syslog(LOG_NOTICE,
		   "repeated group access failures from %s, group %s",
		   remoteident, groupname);
	    exit(0);
	}
	sleep(group_attempts);	/* slow down password crackers */
	return;
    }

    uid = geteuid();
    gid = grp->gr_gid;

    delay_signaling();		/* we can't allow any signals while euid==0: kinch */
    seteuid(0);
    setegid(gid);
    seteuid(uid);
    enable_signaling();		/* we can allow signals once again: kinch */

    reply(200, "Group access enabled.");
    group_attempts = 0;
}
#endif /* !NO_PRIVATE */
