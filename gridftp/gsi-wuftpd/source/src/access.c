
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#elif defined(HAVE_SYSLOG_H) || !defined(AUTOCONF)
#include <syslog.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#include <sys/time.h>
#elif defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <time.h>
#endif

#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include "pathnames.h"
#include "extensions.h"
#include "proto.h"

#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif

#ifdef OTHER_PASSWD
#include "getpwnam.h"
extern char _path_passwd[];
#ifdef SHADOW_PASSWORD
extern char _path_shadow[];
#endif
#endif

#if defined(USE_PAM) && defined(OTHER_PASSWD)
extern int use_pam;
#endif

extern char remotehost[], remoteaddr[], *remoteident, *aclbuf;
extern int nameserved, anonymous, guest, TCPwindowsize, use_accessfile;
extern mode_t defumask;
char Shutdown[MAXPATHLEN];
int keepalive = 0;
#define MAXLINE	80
static char incline[MAXLINE];
int pidfd = -1;
extern int Bypass_PID_Files;

#ifndef HELP_CRACKERS
extern char DelayedMessageFile[];
#endif

#include "wu_fnmatch.h"

extern void load_timeouts(void);

/*************************************************************************/
/* FUNCTION  : parse_time                                                */
/* PURPOSE   : Check a single valid-time-string against the current time */
/*             and return whether or not a match occurs.                 */
/* ARGUMENTS : a pointer to the time-string                              */
/*************************************************************************/

int parsetime(char *whattime)
{
    static char *days[] =
    {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa", "Wk"};
    time_t clock;
    struct tm *curtime;
    int wday, start, stop, ltime, validday, loop, match;

    (void) time(&clock);
    curtime = localtime(&clock);
    wday = curtime->tm_wday;
    validday = 0;
    match = 1;

    while (match && isalpha(*whattime) && isupper(*whattime)) {
	match = 0;
	for (loop = 0; loop < 8; loop++) {
	    if (strncmp(days[loop], whattime, 2) == 0) {
		whattime += 2;
		match = 1;
		if ((wday == loop) || ((loop == 7) && wday && (wday < 6))) {
		    validday = 1;
		}
	    }
	}
    }

    if (!validday) {
	if (strncmp(whattime, "Any", 3) == 0) {
	    validday = 1;
	    whattime += 3;
	}
	else
	    return (0);
    }

    if (sscanf(whattime, "%d-%d", &start, &stop) == 2) {
	ltime = curtime->tm_min + 100 * curtime->tm_hour;
	if ((start < stop) && ((ltime >= start) && ltime < stop))
	    return (1);
	if ((start > stop) && ((ltime >= start) || ltime < stop))
	    return (1);
    }
    else
	return (1);

    return (0);
}

/*************************************************************************/
/* FUNCTION  : validtime                                                 */
/* PURPOSE   : Break apart a set of valid time-strings and pass them to  */
/*             parse_time, returning whether or not ANY matches occurred */
/* ARGUMENTS : a pointer to the time-string                              */
/*************************************************************************/

int validtime(char *ptr)
{
    char *nextptr;
    int good;

    while (1) {
	nextptr = strchr(ptr, '|');
	if (strchr(ptr, '|') == NULL)
	    return (parsetime(ptr));
	*nextptr = '\0';
	good = parsetime(ptr);
	/* gotta restore the | or things get skipped! */
	*nextptr++ = '|';
	if (good)
	    return (1);
	ptr = nextptr;
    }
}

/*************************************************************************/
/* FUNCTION  : hostmatch                                                 */
/* PURPOSE   : Match remote hostname or address against a glob string    */
/* ARGUMENTS : The string to match                                       */
/* RETURNS   : 0 if no match, 1 if a match occurs                        */
/*************************************************************************/

int hostmatch(char *addr, char *remoteaddr, char *remotehost)
{
    FILE *incfile;
    char *ptr;
    int found = 1;
    int not_found = 0;
    int match = 0;
    int i, a[4], m[4], r[4], cidr;

    if (addr == NULL)
	return (0);

    if (*addr == '!') {
	found = 0;
	not_found = 1;
	addr++;
    }

    if (sscanf(addr, "%d.%d.%d.%d/%d", a, a + 1, a + 2, a + 3, &cidr) == 5) {
	m[0] = 0;
	m[1] = 0;
	m[2] = 0;
	m[3] = 0;
	if (cidr < 0)
	    cidr = 0;
	else if (cidr > 32)
	    cidr = 32;
	for (i = 0; cidr > 8; i++) {
	    m[i] = 255;
	    cidr -= 8;
	}
	switch (cidr) {
	case 8:
	    m[i] += 1;
	case 7:
	    m[i] += 2;
	case 6:
	    m[i] += 4;
	case 5:
	    m[i] += 8;
	case 4:
	    m[i] += 16;
	case 3:
	    m[i] += 32;
	case 2:
	    m[i] += 64;
	case 1:
	    m[i] += 128;
	}
	sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3);
	for (i = 0; i < 4; i++)
	    if ((a[i] & m[i]) != (r[i] & m[i]))
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%d.%d.%d.%d:%d.%d.%d.%d", a, a + 1, a + 2, a + 3, m, m + 1, m + 2, m + 3) == 8) {
	sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3);
	for (i = 0; i < 4; i++)
	    if ((a[i] & m[i]) != (r[i] & m[i]))
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%d.%d.%d.%d", a, a + 1, a + 2, a + 3) == 4) {
	sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3);
	for (i = 0; i < 4; i++)
	    if (a[i] != r[i])
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%d.%d.%d.*", a, a + 1, a + 2) == 3) {
	sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3);
	for (i = 0; i < 3; i++)
	    if (a[i] != r[i])
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%d.%d.*.*", a, a + 1) == 2) {
	sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3);
	for (i = 0; i < 2; i++)
	    if (a[i] != r[i])
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%d.*.*.*", a) == 1) {
	sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3);
	for (i = 0; i < 1; i++)
	    if (a[i] != r[i])
		return not_found;
	return found;
    }
    else if (*addr == '/') {
	/*
	 * read addrglobs from named path using similar format as addrglobs
	 * in access file
	 */
	if ((incfile = fopen(addr, "r")) == NULL) {
	    if (errno != ENOENT)
		syslog(LOG_ERR,
		       "cannot open addrglob file %s: %m", addr);
	    return (0);
	}

	while (!match && (fgets(incline, MAXLINE, incfile) != NULL)) {
	    ptr = strtok(incline, " \t\n");
	    if (ptr && hostmatch(ptr, remoteaddr, remotehost))
		match = 1;
	    while (!match && ((ptr = strtok(NULL, " \t\n")) != NULL)) {
		if (ptr && hostmatch(ptr, remoteaddr, remotehost))
		    match = 1;
	    }
	}
	fclose(incfile);
	return (match ? found : not_found);
    }
    else {			/* match a hostname or hostname glob */
	match = !wu_fnmatch(addr, remotehost, FNM_CASEFOLD);
	return (match ? found : not_found);
    }
}

/*************************************************************************/
/* FUNCTION  : acl_guestgroup                                            */
/* PURPOSE   : If the real user is a member of any of the listed groups, */
/*             return 1.  Otherwise return 0.                            */
/* ARGUMENTS : pw, a pointer to the passwd struct for the user           */
/*************************************************************************/

int acl_guestgroup(struct passwd *pw)
{
    struct aclmember *entry = NULL;
    struct group *grp;
    int which;
    char **member;

    /*
     * guestuser <name> [<name> ...]
     *
     * If name begins with '%' treat as numeric.
     * Numeric names may be ranges.
     *   %<uid>       A single numeric UID
     *   %<uid>+      All UIDs greater or equal to UID
     *   %<uid>-      All UIDs greater or equal to UID
     *   %-<uid>      All UIDs less or equal to UID
     *   %<uid>-<uid> All UIDs between the two (inclusive)
     *   *            All UIDs
     */
    while (getaclentry("guestuser", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		char *ptr = strchr(ARG[which] + 1, '-');
		if (!ptr) {
		    ptr = strchr(ARG[which] + 1, '+');
		    if (!ptr) {
			if (pw->pw_uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (pw->pw_uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		struct passwd *g_pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		struct passwd *g_pw = getpwnam(ARG[which]);
#endif
		if (g_pw && (g_pw->pw_uid == pw->pw_uid))
		    return (1);
	    }
	}
    }

    /*
     * guestgroup <group> [<group> ...]
     *
     * If group begins with '%' treat as numeric.
     * Numeric groups may be ranges.
     *   %<gid>       A single GID
     *   %<gid>+      All GIDs greater or equal to GID
     *   %<gid>-      All GIDs greater or equal to GID
     *   %-<gid>      All GIDs less or equal to GID
     *   %<gid>-<gid> All GIDs between the two (inclusive)
     *   *            All GIDs
     */
    while (getaclentry("guestgroup", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		char *ptr = strchr(ARG[which] + 1, '-');
		if (!ptr) {
		    ptr = strchr(ARG[which] + 1, '+');
		    if (!ptr) {
			if (pw->pw_gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (pw->pw_gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (pw->pw_gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (pw->pw_gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		if ((grp = getgrnam(ARG[which]))) {
		    if (grp->gr_gid == pw->pw_gid)
			return (1);
		    for (member = grp->gr_mem; *member; member++)
			if (!strcasecmp(*member, pw->pw_name))
			    return (1);
		}
	    }
	}
    }

    return (0);
}

int acl_realgroup(struct passwd *pw)
{
    struct aclmember *entry = NULL;
    struct group *grp;
    int which;
    char **member;

    /*
     * realuser <name> [<name> ...]
     *
     * If name begins with '%' treat as numeric.
     * Numeric names may be ranges.
     *   %<uid>       A single numeric UID
     *   %<uid>+      All UIDs greater or equal to UID
     *   %<uid>-      All UIDs greater or equal to UID
     *   %-<uid>      All UIDs less or equal to UID
     *   %<uid>-<uid> All UIDs between the two (inclusive)
     *   *            All UIDs
     */
    while (getaclentry("realuser", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		char *ptr = strchr(ARG[which] + 1, '-');
		if (!ptr) {
		    ptr = strchr(ARG[which] + 1, '+');
		    if (!ptr) {
			if (pw->pw_uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (pw->pw_uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		struct passwd *g_pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		struct passwd *g_pw = getpwnam(ARG[which]);
#endif
		if (g_pw && (g_pw->pw_uid == pw->pw_uid))
		    return (1);
	    }
	}
    }

    /*
     * realgroup <group> [<group> ...]
     *
     * If group begins with '%' treat as numeric.
     * Numeric groups may be ranges.
     *   %<gid>       A single GID
     *   %<gid>+      All GIDs greater or equal to GID
     *   %<gid>-      All GIDs greater or equal to GID
     *   %-<gid>      All GIDs less or equal to GID
     *   %<gid>-<gid> All GIDs between the two (inclusive)
     *   *            All GIDs
     */
    while (getaclentry("realgroup", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		char *ptr = strchr(ARG[which] + 1, '-');
		if (!ptr) {
		    ptr = strchr(ARG[which] + 1, '+');
		    if (!ptr) {
			if (pw->pw_gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (pw->pw_gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (pw->pw_gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (pw->pw_gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		if ((grp = getgrnam(ARG[which]))) {
		    if (grp->gr_gid == pw->pw_gid)
			return (1);
		    for (member = grp->gr_mem; *member; member++)
			if (!strcasecmp(*member, pw->pw_name))
			    return (1);
		}
	    }
	}
    }

    return (0);
}

/*************************************************************************/
/* FUNCTION  : acl_autogroup                                             */
/* PURPOSE   : If the guest user is a member of any of the classes in    */
/*             the autogroup comment, cause a setegid() to the specified */
/*             group.                                                    */
/* ARGUMENTS : pw, a pointer to the passwd struct for the user           */
/*************************************************************************/

void acl_autogroup(struct passwd *pw)
{
    char class[1024];

    struct aclmember *entry = NULL;
    struct group *grp;
    int which;

    (void) acl_getclass(class);

    /* autogroup <group> <class> [<class> ...] */
    while (getaclentry("autogroup", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcasecmp(ARG[which], class)) {
		if (ARG0[0] == '%')
		    pw->pw_gid = atoi(ARG0 + 1);
		else {
		    if ((grp = getgrnam(ARG0)))
			pw->pw_gid = grp->gr_gid;
		    else
			syslog(LOG_ERR, "autogroup: set group %s not found", ARG0);
		    endgrent();
		}
		return;
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : acl_setfunctions                                          */
/* PURPOSE   : Scan the ACL buffer and determine what logging to perform */
/*             for this user, and whether or not user is allowed to use  */
/*             the automatic TAR and COMPRESS functions.  Also, set the  */
/*             current process priority of this copy of the ftpd server  */
/*             to a `nice' value value if this user is a member of a     */
/*             group which the ftpaccess file says should be nice'd.     */
/* ARGUMENTS : pointer to buffer to class name, pointer to ACL buffer    */
/*************************************************************************/

void acl_setfunctions(void)
{
    char class[1024];

    extern int log_incoming_xfers, log_outbound_xfers, mangleopts, log_commands,
        log_security, syslogmsg, lgi_failure_threshold;

    struct aclmember *entry = NULL;

    int l_compress, l_tar, inbound = 0, outbound = 0, which, set;

    log_incoming_xfers = 0;
    log_outbound_xfers = 0;
    log_commands = 0;
    log_security = 0;

    memset((void *) &class[0], 0, sizeof(class));

    (void) acl_getclass(class);

    entry = (struct aclmember *) NULL;
    if (getaclentry("loginfails", &entry) && ARG0 != NULL) {
	lgi_failure_threshold = atoi(ARG0);
    }
#ifndef NO_PRIVATE
    entry = (struct aclmember *) NULL;
    if (getaclentry("private", &entry) && !strcasecmp(ARG0, "yes"))
	priv_setup(_path_private);
#endif /* !NO_PRIVATE */

    entry = (struct aclmember *) NULL;
    set = 0;
    while (!set && getaclentry("compress", &entry)) {
	l_compress = 0;
	if (!strcasecmp(ARG0, "yes"))
	    l_compress = 1;
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    if (!wu_fnmatch(ARG[which], class, FNM_CASEFOLD)) {
		mangleopts |= l_compress * (O_COMPRESS | O_UNCOMPRESS);
		set = 1;
	    }
	}
    }

    entry = (struct aclmember *) NULL;
    set = 0;
    while (!set && getaclentry("tar", &entry)) {
	l_tar = 0;
	if (!strcasecmp(ARG0, "yes"))
	    l_tar = 1;
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    if (!wu_fnmatch(ARG[which], class, FNM_CASEFOLD)) {
		mangleopts |= l_tar * O_TAR;
		set = 1;
	    }
	}
    }

    /* plan on expanding command syntax to include classes for each of these */

    entry = (struct aclmember *) NULL;
    while (getaclentry("log", &entry)) {
	if (!strcasecmp(ARG0, "commands")) {
	    if (anonymous && strcasestr(ARG1, "anonymous"))
		log_commands = 1;
	    if (guest && strcasestr(ARG1, "guest"))
		log_commands = 1;
	    if (!guest && !anonymous && strcasestr(ARG1, "real"))
		log_commands = 1;
	}
	if (!strcasecmp(ARG0, "transfers")) {
	    set = 0;
	    if (strcasestr(ARG1, "anonymous") && anonymous)
		set = 1;
	    if (strcasestr(ARG1, "guest") && guest)
		set = 1;
	    if (strcasestr(ARG1, "real") && !guest && !anonymous)
		set = 1;
	    if (strcasestr(ARG2, "inbound"))
		inbound = 1;
	    if (strcasestr(ARG2, "outbound"))
		outbound = 1;
	    if (set)
		log_incoming_xfers = inbound;
	    if (set)
		log_outbound_xfers = outbound;
	}
	if (!strcasecmp(ARG0, "security")) {
	    if (strcasestr(ARG1, "anonymous") && anonymous)
		log_security = 1;
	    if (strcasestr(ARG1, "guest") && guest)
		log_security = 1;
	    if (strcasestr(ARG1, "real") && !guest && !anonymous)
		log_security = 1;
	}
	if (!strcasecmp(ARG0, "syslog"))
	    syslogmsg = 1;
	if (!strcasecmp(ARG0, "xferlog"))
	    syslogmsg = 0;
	if (!strcasecmp(ARG0, "syslog+xferlog")
	    || !strcasecmp(ARG0, "xferlog+syslog"))
	    syslogmsg = 2;
    }
}

/*************************************************************************/
/* FUNCTION  : acl_getclass                                              */
/* PURPOSE   : Scan the ACL buffer and determine what class user is in   */
/* ARGUMENTS : pointer to buffer to class name, pointer to ACL buffer    */
/*************************************************************************/

int acl_getclass(char *classbuf)
{
    int which;
    struct aclmember *entry = NULL;

    while (getaclentry("class", &entry)) {
	if (ARG0)
	    strcpy(classbuf, ARG0);

	for (which = 2; (which < MAXARGS) && ARG[which]; which++) {
	    if (anonymous && strcasestr(ARG1, "anonymous") &&
		hostmatch(ARG[which], remoteaddr, remotehost))
		return (1);

	    if (guest && strcasestr(ARG1, "guest") && hostmatch(ARG[which], remoteaddr, remotehost))
		return (1);

	    if (!guest && !anonymous && strcasestr(ARG1, "real") &&
		hostmatch(ARG[which], remoteaddr, remotehost))
		return (1);
	}
    }

    *classbuf = (char) NULL;
    return (0);

}

/*************************************************************************/
/* FUNCTION  : acl_getlimit                                              */
/* PURPOSE   : Scan the ACL buffer and determine what limit applies to   */
/*             the user                                                  */
/* ARGUMENTS : pointer class name, pointer to ACL buffer                 */
/*************************************************************************/

int acl_getlimit(char *class, char *msgpathbuf)
{
    int limit;
    struct aclmember *entry = NULL;

    if (msgpathbuf)
	*msgpathbuf = '\0';

    /* limit <class> <n> <times> [<message_file>] */
    while (getaclentry("limit", &entry)) {
	if (!ARG0 || !ARG1 || !ARG2)
	    continue;
	if (!strcasecmp(class, ARG0)) {
	    limit = atoi(ARG1);
	    if (validtime(ARG2)) {
		if (ARG3 && msgpathbuf)
		    strcpy(msgpathbuf, ARG3);
		return (limit);
	    }
	}
    }
    return (-1);
}

/*************************************************************************/
/* FUNCTION  : acl_getnice                                               */
/* PURPOSE   : Scan the ACL buffer and determine what nice value applies */
/*             to the user                                               */
/* ARGUMENTS : pointer class name                                        */
/*************************************************************************/

int acl_getnice(char *class)
{
    int nice_delta_for_class_found = 0;
    int nice_delta = 0;
    int default_nice_delta = 0;

    struct aclmember *entry = NULL;

    /* nice <nice_delta> [<class>] */
    while (getaclentry("nice", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    default_nice_delta = atoi(ARG0);
	else if (!strcasecmp(class, ARG1)) {
	    nice_delta_for_class_found = 1;
	    nice_delta = atoi(ARG0);
	}
    }
    if (!nice_delta_for_class_found)
	nice_delta = default_nice_delta;
    return nice_delta;
}


/*************************************************************************/
/* FUNCTION  : acl_getdefumask                                           */
/* PURPOSE   : Scan the ACL buffer to determine what umask value applies */
/*             to the user                                               */
/* ARGUMENTS : pointer to class name                                     */
/*************************************************************************/

void acl_getdefumask(char *class)
{
    struct aclmember *entry = NULL;

    /* defumask <umask> [<class>] */
    while (getaclentry("defumask", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    defumask = strtoul(ARG0, NULL, 0);
	else if (!strcasecmp(class, ARG1)) {
	    defumask = strtoul(ARG0, NULL, 0);
	    break;
	}
    }
    umask(defumask);
}

/*************************************************************************/
/* FUNCTION  : acl_tcpwindow                                             */
/* PURPOSE   : Scan the ACL buffer and determine what TCP window size to */
/*             use based upon the class                                  */
/* ARGUMENTS : pointer to class name                                     */
/*************************************************************************/

void acl_tcpwindow(char *class)
{
    struct aclmember *entry = NULL;

    /* tcpwindow <size> [<class>] */
    while (getaclentry("tcpwindow", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    TCPwindowsize = strtoul(ARG0, NULL, 0);
	else if (!strcasecmp(class, ARG1)) {
	    TCPwindowsize = strtoul(ARG0, NULL, 0);
	    break;
	}
    }
}

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT

/*************************************************************************/
/* FUNCTION  : acl_filelimit                                             */
/* PURPOSE   : Scan the ACL buffer and determine what file limit to use  */
/*             based upon the class                                      */
/* ARGUMENTS : pointer to class name                                     */
/*************************************************************************/

void acl_filelimit(char *class)
{
    struct aclmember *entry = NULL;
    int raw_in = 0;
    int raw_out = 0;
    int raw_total = 0;
    int data_in = 0;
    int data_out = 0;
    int data_total = 0;
    extern int file_limit_raw_in;
    extern int file_limit_raw_out;
    extern int file_limit_raw_total;
    extern int file_limit_data_in;
    extern int file_limit_data_out;
    extern int file_limit_data_total;

    /* file-limit [<raw>] <in|out|total> <count> [<class>] */
    while (getaclentry("file-limit", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	if (!strcasecmp(ARG0, "raw")) {
	    if (!ARG2)
		continue;
	    if (!strcasecmp(ARG1, "in")) {
		if (!ARG3) {
		    if (!raw_in)
			file_limit_raw_in = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_in = 1;
		    file_limit_raw_in = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "out")) {
		if (!ARG3) {
		    if (!raw_out)
			file_limit_raw_out = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_out = 1;
		    file_limit_raw_out = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "total")) {
		if (!ARG3) {
		    if (!raw_total)
			file_limit_raw_total = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_total = 1;
		    file_limit_raw_total = atoi(ARG2);
		}
	    }
	}
	else if (!strcasecmp(ARG0, "in")) {
	    if (!ARG2) {
		if (!data_in)
		    file_limit_data_in = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_in = 1;
		file_limit_data_in = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "out")) {
	    if (!ARG2) {
		if (!data_out)
		    file_limit_data_out = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_out = 1;
		file_limit_data_out = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "total")) {
	    if (!ARG2) {
		if (!data_total)
		    file_limit_data_total = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_total = 1;
		file_limit_data_total = atoi(ARG1);
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : acl_datalimit                                             */
/* PURPOSE   : Scan the ACL buffer and determine what data limit to use  */
/*             based upon the class                                      */
/* ARGUMENTS : pointer to class name                                     */
/*************************************************************************/

void acl_datalimit(char *class)
{
    struct aclmember *entry = NULL;
    int raw_in = 0;
    int raw_out = 0;
    int raw_total = 0;
    int data_in = 0;
    int data_out = 0;
    int data_total = 0;
    extern int data_limit_raw_in;
    extern int data_limit_raw_out;
    extern int data_limit_raw_total;
    extern int data_limit_data_in;
    extern int data_limit_data_out;
    extern int data_limit_data_total;

    /* data-limit [<raw>] <in|out|total> <count> [<class>] */
    while (getaclentry("data-limit", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	if (!strcasecmp(ARG0, "raw")) {
	    if (!ARG2)
		continue;
	    if (!strcasecmp(ARG1, "in")) {
		if (!ARG3) {
		    if (!raw_in)
			data_limit_raw_in = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_in = 1;
		    data_limit_raw_in = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "out")) {
		if (!ARG3) {
		    if (!raw_out)
			data_limit_raw_out = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_out = 1;
		    data_limit_raw_out = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "total")) {
		if (!ARG3) {
		    if (!raw_total)
			data_limit_raw_total = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_total = 1;
		    data_limit_raw_total = atoi(ARG2);
		}
	    }
	}
	else if (!strcasecmp(ARG0, "in")) {
	    if (!ARG2) {
		if (!data_in)
		    data_limit_data_in = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_in = 1;
		data_limit_data_in = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "out")) {
	    if (!ARG2) {
		if (!data_out)
		    data_limit_data_out = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_out = 1;
		data_limit_data_out = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "total")) {
	    if (!ARG2) {
		if (!data_total)
		    data_limit_data_total = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_total = 1;
		data_limit_data_total = atoi(ARG1);
	    }
	}
    }
}


#ifdef RATIO

/*************************************************************************/
/* FUNCTION  : acl_downloadrate                                          */
/* PURPOSE   : Scan the ACL buffer and determine what data limit to use  */
/*             based upon the class                                      */
/* ARGUMENTS : pointer to class name                                     */
/*************************************************************************/

void acl_downloadrate(char *class)
{
    struct aclmember *entry = NULL;
    extern int upload_download_rate;
    int which;

    /* ul-dl-rate <rate> [<class> ...] */
    while (getaclentry("ul-dl-rate", &entry)) {
	if (!ARG0 )
	    continue;

	if (!ARG1) {
	    upload_download_rate = atol(ARG0);
	}
	else {
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if (!strcasecmp(ARG[which], class))
		    upload_download_rate = atol(ARG0);
	    }
	}

    }
}
#endif /* RATIO */

#endif
#endif

/*************************************************************************/
/* FUNCTION  : acl_deny                                                  */
/* PURPOSE   : Scan the ACL buffer and determine a deny command applies  */
/* ARGUMENTS : pointer class name, pointer to ACL buffer                 */
/*************************************************************************/

int acl_deny(char *msgpathbuf)
{
    struct aclmember *entry = NULL;

    if (msgpathbuf)
	*msgpathbuf = (char) NULL;

    /* deny <addrglob> [<message_file>] */
    while (getaclentry("deny", &entry)) {
	if (!ARG0)
	    continue;
	if (strcasecmp(ARG0, "!nameserved") == 0) {
	    if (!nameserved) {
		if (ARG1)
		    strcpy(msgpathbuf, entry->arg[1]);
		return (1);
	    }
	}
	else if (hostmatch(ARG0, remoteaddr, remotehost)) {
	    if (ARG1)
		strcpy(msgpathbuf, entry->arg[1]);
	    return (1);
	}
    }
    return (0);
}

/*************************************************************************/
/* FUNCTION  : acl_countusers                                            */
/* PURPOSE   : Check the anonymous FTP access lists to see if this       */
/*             access is permitted.                                      */
/* ARGUMENTS : none                                                      */
/*************************************************************************/

int acl_countusers(char *class)
{
    int count, which;
    char pidfile[MAXPATHLEN];
    pid_t buf[MAXUSERS];
#ifndef HAVE_FLOCK
    struct flock arg;
#endif

    if (Bypass_PID_Files)
	return (0);
    /* 
     * if pidfd was not opened previously... 
     * pidfd must stay open after the chroot(~ftp)  
     */

    sprintf(pidfile, _PATH_PIDNAMES, class);

    if (pidfd < 0) {
	mode_t oldmask;
	oldmask = umask(0);
	pidfd = open(pidfile, O_RDWR | O_CREAT, 0644);
	(void) umask(oldmask);
    }

    if (pidfd < 0) {
	syslog(LOG_ERR, "cannot open pid file %s: %m", pidfile);
	return -1;
    }

#ifdef HAVE_FLOCK
    while (flock(pidfd, LOCK_EX)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: flock of pid file failed: %m");
#endif
#else
    arg.l_type = F_WRLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    while (-1 == fcntl(pidfd, F_SETLK, &arg)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: fcntl lock of pid file failed: %m");
#endif
#endif
	sleep(1);
    }
    lseek(pidfd, (off_t) 0, SEEK_SET);

    count = 0;

    if (read(pidfd, (void *) buf, sizeof(buf)) == sizeof(buf)) {
	for (which = 0; which < MAXUSERS; which++)
	    if (buf[which] && !kill(buf[which], 0))
		count++;
    }
#ifdef HAVE_FLOCK
    flock(pidfd, LOCK_UN);
#else
    arg.l_type = F_UNLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    fcntl(pidfd, F_SETLK, &arg);
#endif
    return (count);
}

/*************************************************************************/
/* FUNCTION  : acl_join                                                  */
/* PURPOSE   : Add the current process to the list of processes in the   */
/*             specified class.                                          */
/* ARGUMENTS : The name of the class to join                             */
/*************************************************************************/

void acl_join(char *class)
{
    int which, avail;
    pid_t buf[MAXUSERS];
    char pidfile[MAXPATHLEN];
    pid_t procid;
#ifndef HAVE_FLOCK
    struct flock arg;
#endif

    if (Bypass_PID_Files)
	return;

    /* 
     * if pidfd was not opened previously... 
     * pidfd must stay open after the chroot(~ftp)  
     */

    sprintf(pidfile, _PATH_PIDNAMES, class);

    if (pidfd < 0) {
	mode_t oldmask;
	oldmask = umask(0);
	pidfd = open(pidfile, O_RDWR | O_CREAT, 0644);
	(void) umask(oldmask);
    }

    if (pidfd < 0) {
	syslog(LOG_ERR, "cannot open pid file %s: %m", pidfile);
	return;
    }

#ifdef HAVE_FLOCK
    while (flock(pidfd, LOCK_EX)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: flock of pid file failed: %m");
#endif
#else
    arg.l_type = F_WRLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    while (-1 == fcntl(pidfd, F_SETLK, &arg)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: fcntl lock of pid file failed: %m");
#endif
#endif
	sleep(1);
    }

    procid = getpid();

    lseek(pidfd, (off_t) 0, SEEK_SET);
    if (read(pidfd, (void *) buf, sizeof(buf)) < sizeof(buf))
	for (which = 0; which < MAXUSERS; buf[which++] = 0)
	    continue;

    avail = 0;
    for (which = 0; which < MAXUSERS; which++) {
	if ((buf[which] == 0) || (kill(buf[which], 0) == -1)) {
	    avail = which;
	    buf[which] = 0;
	}
	else if (buf[which] == procid) {
	    /* already exists in pid file... */
#ifdef HAVE_FLOCK
	    flock(pidfd, LOCK_UN);
#else
	    arg.l_type = F_UNLCK;
	    arg.l_whence = arg.l_start = arg.l_len = 0;
	    fcntl(pidfd, F_SETLK, &arg);
#endif
	    return;
	}
    }

    buf[avail] = procid;

    lseek(pidfd, (off_t) 0, SEEK_SET);
    write(pidfd, (void *) buf, sizeof(buf));
#ifdef HAVE_FLOCK
    flock(pidfd, LOCK_UN);
#else
    arg.l_type = F_UNLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    fcntl(pidfd, F_SETLK, &arg);
#endif

}

/*************************************************************************/
/* FUNCTION  : acl_remove                                                */
/* PURPOSE   : remove the current process to the list of processes in    */
/*             the specified class.                                      */
/* ARGUMENTS : The name of the class to remove                           */
/*************************************************************************/

void acl_remove(void)
{
    char class[1024];
    int which, avail;
    pid_t buf[MAXUSERS];
    char pidfile[MAXPATHLEN];
    pid_t procid;
#ifndef HAVE_FLOCK
    struct flock arg;
#endif

    if (Bypass_PID_Files)
	return;

    if (!acl_getclass(class)) {
	return;
    }

    /* 
     * if pidfd was not opened previously... 
     * pidfd must stay open after the chroot(~ftp)  
     */

    sprintf(pidfile, _PATH_PIDNAMES, class);

    if (pidfd < 0) {
	mode_t oldmask;
	oldmask = umask(0);
	pidfd = open(pidfile, O_RDWR | O_CREAT, 0644);
	(void) umask(oldmask);
    }

    if (pidfd < 0) {
	syslog(LOG_ERR, "cannot open pid file %s: %m", pidfile);
	return;
    }

#ifdef HAVE_FLOCK
    while (flock(pidfd, LOCK_EX)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: flock of pid file failed: %m");
#endif
#else
    arg.l_type = F_WRLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    while (-1 == fcntl(pidfd, F_SETLK, &arg)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: fcntl lock of pid file failed: %m");
#endif
#endif
	sleep(1);
    }

    procid = getpid();

    lseek(pidfd, (off_t) 0, SEEK_SET);
    if (read(pidfd, (void *) buf, sizeof(buf)) < sizeof(buf))
	for (which = 0; which < MAXUSERS; buf[which++] = 0)
	    continue;

    avail = 0;
    for (which = 0; which < MAXUSERS; which++) {
	if ((buf[which] == 0) || (kill(buf[which], 0) == -1)) {
	    avail = which;
	    buf[which] = 0;
	}
	else if (buf[which] == procid) {
	    buf[which] = 0;
	}
    }

    lseek(pidfd, (off_t) 0, SEEK_SET);
    write(pidfd, (void *) buf, sizeof(buf));
#ifdef HAVE_FLOCK
    flock(pidfd, LOCK_UN);
#else
    arg.l_type = F_UNLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    fcntl(pidfd, F_SETLK, &arg);
#endif

    close(pidfd);
    pidfd = -1;
}

/*************************************************************************/
/* FUNCTION  : pr_mesg                                                   */
/* PURPOSE   : Display a message to the user                             */
/* ARGUMENTS : message code, name of file to display                     */
/*************************************************************************/

void pr_mesg(int msgcode, char *msgfile)
{
    FILE *infile;
    char inbuf[1024], outbuf[1024], *cr;

    if (msgfile && (int) strlen(msgfile) > 0) {
	infile = fopen(msgfile, "r");
	if (infile) {
	    while (fgets(inbuf, sizeof(inbuf), infile) != NULL) {
		if ((cr = strchr(inbuf, '\n')) != NULL)
		    *cr = '\0';
		msg_massage(inbuf, outbuf, sizeof(outbuf));
		lreply(msgcode, "%s", outbuf);
	    }
	    fclose(infile);
	}
    }
}

/*************************************************************************/
/* FUNCTION  : access_init                                               */
/* PURPOSE   : Read and parse the access lists to set things up          */
/* ARGUMENTS : none                                                      */
/*************************************************************************/

void access_init(void)
{
    struct aclmember *entry;

    if (!readacl(_path_ftpaccess))
	return;
    (void) parseacl();

    Shutdown[0] = '\0';
    entry = (struct aclmember *) NULL;
    if (getaclentry("shutdown", &entry) && ARG0 != NULL)
	(void) strncpy(Shutdown, ARG0, sizeof(Shutdown));
#ifdef OTHER_PASSWD
    entry = (struct aclmember *) NULL;
    while (getaclentry("passwd", &entry) && ARG0 != NULL) {
	    strcpy(_path_passwd, ARG0);
#ifdef USE_PAM
	    use_pam = 0;
#endif
    }
#ifdef SHADOW_PASSWORD
    entry = (struct aclmember *) NULL;
    while (getaclentry("shadow", &entry) && ARG0 != NULL) {
	    strcpy(_path_shadow, ARG0);
#ifdef USE_PAM
	    use_pam = 0;
#endif
    }
#endif
#endif
    entry = (struct aclmember *) NULL;
    if (getaclentry("keepalive", &entry) && ARG0 != NULL)
	if (!strcasecmp(ARG0, "yes"))
	    keepalive = 1;
    load_timeouts();
}

/*************************************************************************/
/* FUNCTION  : access_ok                                                 */
/* PURPOSE   : Check the anonymous FTP access lists to see if this       */
/*             access is permitted.                                      */
/* ARGUMENTS : none                                                      */
/*************************************************************************/

int access_ok(int msgcode)
{
    char class[1024], msgfile[MAXPATHLEN];
    int limit;
    int nice_delta;

    if (!use_accessfile)
	return (1);

    if (aclbuf == NULL) {
	syslog(LOG_NOTICE,
	       "ACCESS DENIED (error reading access file) TO %s",
	       remoteident);
	return (0);
    }
    if (acl_deny(msgfile)) {
#ifndef HELP_CRACKERS
	memcpy(DelayedMessageFile, msgfile, sizeof(msgfile));
#else
	pr_mesg(msgcode, msgfile);
#endif
	syslog(LOG_NOTICE, "ACCESS DENIED (deny command) TO %s",
	       remoteident);
	return (0);
    }
    /* if user is not in any class, deny access */
    if (!acl_getclass(class)) {
	syslog(LOG_NOTICE, "ACCESS DENIED (not in any class) TO %s",
	       remoteident);
	return (0);
    }
    if ((nice_delta = acl_getnice(class))) {
	if (nice_delta < 0)
	    syslog(LOG_NOTICE, "Process nice value adjusted by %d", nice_delta);
	nice(nice_delta);
    }
    acl_getdefumask(class);
    acl_tcpwindow(class);
#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    acl_filelimit(class);
    acl_datalimit(class);
#ifdef RATIO
    acl_downloadrate(class);
#endif
#endif
#endif
    /* if no limits defined, no limits apply -- access OK */
    limit = acl_getlimit(class, msgfile);

    if ((limit == -1) || (acl_countusers(class) < limit)) {
	acl_join(class);
	return (1);
    }
    else {
#ifdef LOG_TOOMANY
	syslog(LOG_NOTICE, "ACCESS DENIED (user limit %d; class %s) TO %s",
	       limit, class, remoteident);
#endif
#ifndef HELP_CRACKERS
	memcpy(DelayedMessageFile, msgfile, sizeof(msgfile));
#else
	pr_mesg(msgcode, msgfile);
#endif
	return (-1);
    }

    /* NOTREACHED */
}
