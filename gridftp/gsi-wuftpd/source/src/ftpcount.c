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

#ifdef TSOL
#include <tsol/priv.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <signal.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include "pathnames.h"
#include "extensions.h"

#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif

struct c_list {
    char *class;
    struct c_list *next;
};

void print_copyright(void);

char *progname;

/*************************************************************************/
/* FUNCTION  : parse_time                                                */
/* PURPOSE   : Check a single valid-time-string against the current time */
/*             and return whether or not a match occurs.                 */
/* ARGUMENTS : a pointer to the time-string                              */
/*************************************************************************/

static int parsetime(char *whattime)
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
		if ((wday == loop) || ((loop == 7) && wday && (wday < 6)))
		    validday = 1;
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

static int validtime(char *ptr)
{
    char *nextptr;
    int good;

    while (1) {
	nextptr = strchr(ptr, '|');
	if (strchr(ptr, '|') == NULL)
	    return (parsetime(ptr));
	*nextptr = '\0';
	good = parsetime(ptr);
	*nextptr++ = '|';	/* gotta restore the | or things get skipped! */
	if (good)
	    return (1);
	ptr = nextptr;
    }
}

static int acl_getlimit(char *aclbuf, char *class)
{
    char *crptr, *ptr, linebuf[1024];
    int limit;

    while (*aclbuf != '\0') {
	if (strncasecmp(aclbuf, "limit", 5) == 0) {
	    for (crptr = aclbuf; *crptr++ != '\n';);
	    *--crptr = '\0';
	    strcpy(linebuf, aclbuf);
	    *crptr = '\n';
	    (void) strtok(linebuf, " \t");	/* returns "limit" */
	    if ((ptr = strtok(NULL, " \t")) && (strcmp(class, ptr) == 0)) {
		if ((ptr = strtok(NULL, " \t"))) {
		    limit = atoi(ptr);	/* returns limit <n> */
		    if ((ptr = strtok(NULL, " \t")) && validtime(ptr))
			return (limit);
		}
	    }
	}
	while (*aclbuf && *aclbuf++ != '\n');
    }

    return (-1);
}

static int acl_countusers(char *class)
{
    int pidfd, count, stat, which;
    char pidfile[1024];
    char line[1024];
    pid_t buf[MAXUSERS];
    FILE *ZeFile;
#ifndef HAVE_FLOCK
    struct flock arg;
#endif

#ifdef TSOL
    int retval;
#endif

    sprintf(pidfile, _PATH_PIDNAMES, class);
    pidfd = open(pidfile, O_RDONLY);
    if (pidfd == -1) {
	return (0);
    }

#ifdef HAVE_FLOCK
    while (flock(pidfd, LOCK_EX)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: flock of pid file failed: %m");
#endif
#else
    arg.l_type = F_RDLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
#ifdef TSOL
    if ((retval = set_effective_priv(PRIV_ON, 1, PRIV_FILE_LOCK)) != 0) {
	syslog(LOG_ERR, "Cannot add PRIV_FILE_LOCK to eff. priv. set");
    }
#endif
    while (-1 == fcntl(pidfd, F_SETLK, &arg)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: fcntl lock of pid file failed: %m");
#endif
#endif /* HAVE_FLOCK */
	sleep(1);
    }
#ifndef HAVE_FLOCK
#ifdef TSOL
    if ((retval = set_effective_priv(PRIV_OFF, 1, PRIV_FILE_LOCK)) != 0) {
	syslog(LOG_ERR, "Cannot remove PRIV_FILE_LOCK from eff. priv. set");
    }
#endif
#endif /* HAVE_FLOCK */

    count = 0;

    if (read(pidfd, (void *) buf, sizeof(buf)) == sizeof(buf)) {
	for (which = 0; which < MAXUSERS; which++)
	    if (buf[which]) {
		stat = kill(buf[which], SIGCONT);
		if (((stat == -1) && (errno == EPERM)) || !stat) {
		    if (strcmp(progname, "ftpcount")) {
#if defined(SVR4)
#ifdef AIX
			sprintf(line, "/bin/ps %d", buf[which]);
#elif defined(sun)
			sprintf(line, "/usr/ucb/ps auxww %ld", buf[which]);
#else
#if defined (LINUX_BUT_NOT_REDHAT_6_0)
			sprintf(line, "/bin/ps axwww %d", buf[which]);
#else
			sprintf(line, "/bin/ps -f -p %d", buf[which]);
#endif
#endif
#elif defined(M_UNIX)
			sprintf(line, "/bin/ps -f -p %d", buf[which]);
#else
			sprintf(line, "/bin/ps %d", buf[which]);
#endif
			ZeFile = popen(line, "r");
			fgets(line, 1024, ZeFile);
			fgets(line, 1024, ZeFile);
			{
			    size_t i;
			    for (i = strlen(line); (i > 0) && ((line[i - 1] == ' ') || (line[i - 1] == '\n')); --i)
				line[i - 1] = '\0';
			}
			printf("%s\n", line);
			pclose(ZeFile);
		    }
		    count++;
		}
	    }
    }
#ifdef HAVE_FLOCK
    flock(pidfd, LOCK_UN);
#else
    arg.l_type = F_UNLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
#ifdef TSOL
    if ((retval = set_effective_priv(PRIV_ON, 1, PRIV_FILE_LOCK)) != 0) {
	syslog(LOG_ERR, "Cannot add PRIV_FILE_LOCK to eff. priv. set");
    }
#endif
    fcntl(pidfd, F_SETLK, &arg);
#ifdef TSOL
    if ((retval = set_effective_priv(PRIV_OFF, 1, PRIV_FILE_LOCK)) != 0) {
	syslog(LOG_ERR, "Cannot remove PRIV_FILE_LOCK from eff. priv. set");
    }
#endif
#endif /* HAVE_FLOCK */
    close(pidfd);

    return (count);
}

static void new_list(struct c_list **list)
{
    (*list) = (struct c_list *) malloc(sizeof(struct c_list));
    if ((*list) == NULL) {
	perror("malloc error in new_list");
	exit(0);
    }

    (*list)->next = NULL;
}

static int add_list(char *class, struct c_list **list)
{
    struct c_list *cp;

    for (cp = (*list)->next; cp; cp = cp->next) {
	if (!strcmp(cp->class, class))
	    return (-1);
    }

    cp = (struct c_list *) malloc(sizeof(struct c_list));
    if (cp == NULL) {
	perror("malloc error in add_list");
	exit(0);
    }

    cp->class = (char *) malloc(strlen(class) + 1);
    if (cp->class == NULL) {
	perror("malloc error in add_list");
	exit(0);
    }
    strcpy(cp->class, class);
    cp->next = (*list)->next;
    (*list)->next = cp;
    return (1);
}

int main(int argc, char **argv)
{
    FILE *accessfile;
    char class[80], linebuf[1024], *aclbuf, *myaclbuf, *crptr;
    int limit, c;
    struct stat finfo;
    struct c_list *list;

#ifdef TSOL
/* Before anything, clear the effective privilege set */
    int retval;

    if ((retval = set_effective_priv(PRIV_SET, 0)) != 0) {
	syslog(LOG_ERR, "ftp[count|who] cannot clear effective privileges!");
	exit(1);
    }
#endif

    if ((progname = strrchr(argv[0], '/')))
	++progname;
    else
	progname = argv[0];

    gsi_wuftp_get_version();

    if (argc > 1) {
	while ((c = getopt(argc, argv, "V")) != EOF) {
	    switch (c) {
	    case 'V':
		print_copyright();
		exit(0);
	    default:
		fprintf(stderr, "usage: %s [-V]\n", progname);
		exit(1);
	    }
	}
    }

    if ((accessfile = fopen(_PATH_FTPACCESS, "r")) == NULL) {
	if (errno != ENOENT)
	    perror("ftpcount: could not open() access file");
	exit(1);
    }
    if (stat(_PATH_FTPACCESS, &finfo)) {
	perror("ftpcount: could not stat() access file");
	exit(1);
    }
    if (finfo.st_size == 0) {
	printf("%s: no service classes defined, no usage count kept\n", progname);
	exit(0);
    }
    else {
	if (!(aclbuf = (char *) malloc((size_t) finfo.st_size + 1))) {
	    perror("ftpcount: could not malloc aclbuf");
	    exit(1);
	}
	fread(aclbuf, (size_t) finfo.st_size, 1, accessfile);
	*(aclbuf + (size_t) finfo.st_size) = '\0';
    }

    (void) new_list(&list);
    myaclbuf = aclbuf;
    while (*myaclbuf != '\0') {
	if (strncasecmp(myaclbuf, "class", 5) == 0) {
	    for (crptr = myaclbuf; *crptr++ != '\n';);
	    *--crptr = '\0';
	    strcpy(linebuf, myaclbuf);
	    *crptr = '\n';
	    (void) strtok(linebuf, " \t");	/* returns "class" */
	    strcpy(class, strtok(NULL, " \t"));		/* returns class name */
	    if ((add_list(class, &list)) < 0) {
		/* we have a class with multiple "class..." lines so, only
		 * display one count... */
		;
	    }
	    else {
		limit = acl_getlimit(myaclbuf, class);
		if (strcmp(progname, "ftpcount")) {
		    printf("Service class %s: \n", class);
		    printf("   - %3d users ", acl_countusers(class));
		}
		else {
		    printf("Service class %-20.20s - %3d users ",
			   class, acl_countusers(class));
		}
		if (limit == -1)
		    printf("(no maximum)\n");
		else
		    printf("(%3d maximum)\n", limit);
	    }
	}
	while (*myaclbuf && *myaclbuf++ != '\n');
    }
    return (0);
}
