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
/* ftpshut 
 * ======= 
 * creates the ftpd shutdown file.
 */

#include "config.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#include "pathnames.h"

#define  WIDTH  70

int verbose = 0;
int denyoffset = 10;		/* default deny time   */
int discoffset = 5;		/* default disc time   */
char *message = "System shutdown at %s";	/* default message     */

struct tm *tp;

#define MAXVIRTUALS 512

char *msgfiles[MAXVIRTUALS];
int numfiles = 0;

#ifdef VIRTUAL
extern int read_servers_line(FILE *, char *, char *);
#endif
void print_copyright(void);

static int newfile(char *fpath)
{
    int i;
    int fnd;

    /*  
       ** Check to see if the message file path has already been
       ** seen. If so then there is no need to create it again.
     */

    fnd = 0;
    for (i = 0; i < numfiles; i++) {
	if (strcmp(msgfiles[i], fpath) == 0) {
	    fnd = 1;
	    break;
	}
    }
    if (!fnd) {
	msgfiles[numfiles++] = strdup(fpath);
	return (1);
    }
    return (0);
}

static int shutdown_msgfile(char *filename, char *buffer)
{
    FILE *fp;

    if ((fp = fopen(filename, "w")) == NULL) {
	perror("Couldn't open shutdown file");
	return (1);
    }

    fprintf(fp, "%.4d %.2d %.2d %.2d %.2d %.4d %.4d\n",
	    (tp->tm_year) + 1900,
	    tp->tm_mon,
	    tp->tm_mday,
	    tp->tm_hour,
	    tp->tm_min,
	    denyoffset,
	    discoffset);
    fprintf(fp, "%s\n", buffer);
    fclose(fp);
    if (verbose)
	printf("%s created\n", filename);
    return (0);
}

static void massage(char *buf)
{
    char *sp = NULL;
    char *ptr;
    int i = 0;
    int j = 0;

    ptr = buf;

    while (*ptr++ != '\0') {
	++i;

	/* if we have a space, keep track of where and at what "count" */

	if (*ptr == ' ') {
	    sp = ptr;
	    j = i;
	}
	/* magic cookies... */

	if (*ptr == '%') {
	    ++ptr;
	    switch (*ptr) {
	    case 'r':
	    case 's':
	    case 'd':
	    case 'T':
		i = i + 24;
		break;
	    case '\n':
		i = 0;
		break;
	    case 'C':
	    case 'R':
	    case 'L':
	    case 'U':
		i = i + 10;
		break;
	    case 'M':
	    case 'N':
		i = i + 3;
		break;
	    case '\0':
		return;
		/* break; */
	    default:
		i = i + 1;
		break;
	    }
	}
	/* break up the long lines... */

	if ((i >= WIDTH) && (sp != NULL)) {
	    *sp = '\n';
	    sp = NULL;
	    i = i - j;
	}
    }
}

int main(int argc, char **argv)
{
    time_t c_time = 0;

    char buf[BUFSIZ];

    int c;
    extern int optind;
    extern char *optarg;

    FILE *accessfile;
    char *aclbuf, *myaclbuf, *crptr;
    char *sp = NULL;
    char linebuf[1024];
    char shutmsg[BUFSIZ];
    char anonpath[BUFSIZ];
    struct stat finfo;
    struct passwd *pwent;

#ifdef VIRTUAL
    char *cp = NULL;
    FILE *svrfp;
    char hostaddress[32];
    char root[MAXPATHLEN];
    char accesspath[MAXPATHLEN];
    char configdir[MAXPATHLEN];
    char altmsgpath[MAXPATHLEN];
#endif

    gsi_wuftp_get_version();

    while ((c = getopt(argc, argv, "vVl:d:")) != EOF) {
	switch (c) {
	case 'v':
	    verbose++;
	    break;
	case 'l':
	    denyoffset = atoi(optarg);
	    break;
	case 'd':
	    discoffset = atoi(optarg);
	    break;
	case 'V':
	    print_copyright();
	    exit(0);
	default:
	    fprintf(stderr,
		"Usage: %s [-d min] [-l min] now [\"message\"]\n", argv[0]);
	    fprintf(stderr,
		"       %s [-d min] [-l min] +dd [\"message\"]\n", argv[0]);
	    fprintf(stderr,
	       "       %s [-d min] [-l min] HHMM [\"message\"]\n", argv[0]);
	    exit(-1);
	}
    }

    if ((accessfile = fopen(_PATH_FTPACCESS, "r")) == NULL) {
	if (errno != ENOENT)
	    perror("ftpshut: could not open() access file");
	exit(1);
    }
    if (stat(_PATH_FTPACCESS, &finfo)) {
	perror("ftpshut: could not stat() access file");
	exit(1);
    }
    if (finfo.st_size == 0) {
	printf("ftpshut: no service shutdown path defined\n");
	exit(0);
    }
    else {
	if (!(aclbuf = (char *) malloc(finfo.st_size + 1))) {
	    perror("ftpshut: could not malloc aclbuf");
	    exit(1);
	}
	fread(aclbuf, finfo.st_size, 1, accessfile);
	*(aclbuf + finfo.st_size) = '\0';
    }

    myaclbuf = aclbuf;
    while (*myaclbuf != '\0') {
	if (strncasecmp(myaclbuf, "shutdown", 8) == 0) {
	    for (crptr = myaclbuf; *crptr++ != '\n';);
	    *--crptr = '\0';
	    strcpy(linebuf, myaclbuf);
	    *crptr = '\n';
	    (void) strtok(linebuf, " \t");	/* returns "shutdown" */
	    sp = strtok(NULL, " \t");	/* returns shutdown path */
	    strcpy(shutmsg, sp);	/* save for future use */
	}
	while (*myaclbuf && *myaclbuf++ != '\n');
    }

    /* three cases 
     * -- now 
     * -- +ddd 
     * -- HHMM 
     */

    c = -1;

    if (optind < argc) {
	if (!strcasecmp(argv[optind], "now")) {
	    c_time = time(0);
	    tp = localtime(&c_time);
	}
	else if ((*(argv[optind])) == '+') {
	    c_time = time(0);
	    c_time += 60 * atoi(++(argv[optind]));
	    tp = localtime(&c_time);
	}
	else if ((c = atoi(argv[optind])) >= 0) {
	    c_time = time(0);
	    tp = localtime(&c_time);
	    tp->tm_hour = c / 100;
	    tp->tm_min = c % 100;

	    if ((tp->tm_hour > 23) || (tp->tm_min > 59)) {
		fprintf(stderr, "Illegal time format.\n");
		return (1);
	    }
	}
    }
    if (c_time <= 0) {
	fprintf(stderr, "Usage: %s [-d min] [-l min] now [\"message\"]\n",
		argv[0]);
	fprintf(stderr, "       %s [-d min] [-l min] +dd [\"message\"]\n",
		argv[0]);
	fprintf(stderr, "       %s [-d min] [-l min] HHMM [\"message\"]\n",
		argv[0]);
	exit(1);
    }

    if (sp == NULL) {
	fprintf(stderr, "No shutdown file defined in ftpaccess file.\n");
	exit(1);
    }

    /* do we have a shutdown message? */
    if (++optind < argc) {
	strncpy(buf, argv[optind++], sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
    }
    else
	strcpy(buf, message);

    massage(buf);

    /* 
       ** Create the system shutdown message file at the location
       ** specified in the ftpaccess 'shutdown' directive.  This
       ** is for support of real system users.
     */
    c = shutdown_msgfile(shutmsg, buf);
    msgfiles[numfiles++] = shutmsg;

    /* 
       ** Determine if the site supports anonymous ftp and if so, create
       ** the shutdown message file in the anonymous ftp area as well
       ** so that shutdown works appropriately for both real and guest 
       ** accounts. Save in msgfiles array for later comparison.
     */

    if ((pwent = getpwnam("ftp")) != NULL) {
	sprintf(anonpath, "%s%s", pwent->pw_dir, shutmsg);
	if (newfile(anonpath))
	    c += shutdown_msgfile(anonpath, buf);
    }

#ifdef VIRTUAL
    /*
       ** Search the Master access file for virtual ftp servers.
       ** If found, construct a path to the shutdown message file
       ** under the virtual server's root.  Don't duplicate what
       ** is specified in the "ftp" account directory information.
     */

    rewind(accessfile);

    while (fgets(linebuf, sizeof(linebuf) - 1, accessfile) != NULL) {
	if (strncasecmp(linebuf, "virtual", 7) == 0) {

	    if ((sp = strstr(linebuf, "root")) != NULL) {
		if ((cp = strchr(sp, '\n')) != NULL)
		    *cp = '\0';	/* strip newline */

		sp += 4;	/* skip past "root" keyword */

		while (*sp && isspace(*sp))	/* skip whitespace to root path */
		    sp++;
		cp = sp;
		while (*sp && !isspace(*sp))
		    sp++;
		*sp = '\0';	/* truncate blanks, comments etc. */

		sprintf(altmsgpath, "%s%s", cp, shutmsg);

		if (newfile(altmsgpath))
		    c += shutdown_msgfile(altmsgpath, buf);
	    }
	}
    }

    /*
       ** Need to deal with the access files at the virtual domain directory
       ** locations specified in the ftpservers file. 
     */

    if ((svrfp = fopen(_PATH_FTPSERVERS, "r")) != NULL) {
	while (read_servers_line(svrfp, hostaddress, configdir) == 1) {
	    /* get rid of any trailing slash */
	    sp = configdir + (strlen(configdir) - 1);
	    if (*sp == '/')
		*sp = '\0';

	    /* 
	       ** check to see that a valid directory value was
	       ** supplied and not something such as "INTERNAL"
	       **
	       ** It is valid to have a string such as "INTERNAL" in the
	       ** ftpservers entry. This is not an error. Silently ignore it.
	     */

	    if ((stat(configdir, &finfo) == 0) &&
		((finfo.st_mode & S_IFMT) == S_IFDIR))
		sprintf(accesspath, "%s/ftpaccess", configdir);
	    else
		continue;

	    (void) fclose(accessfile);

	    if ((accessfile = fopen(accesspath, "r")) == NULL) {
		if (errno != ENOENT) {
		    fprintf(stderr, "%s: could not open %s accessfile\n",
			    argv[0], accesspath);
		    continue;
		}
	    }

	    /* need to find the root path */

	    while (fgets(linebuf, sizeof(linebuf) - 1, accessfile) != NULL) {
		if ((sp = strstr(linebuf, "root")) != NULL) {
		    if ((cp = strchr(sp, '\n')) != NULL)
			*cp = '\0';	/* strip newline */
		    sp += 4;	/* skip past "root" keyword */

		    while (*sp && isspace(*sp))		/* skip whitespace to path */
			sp++;
		    cp = sp;
		    while (*sp && !isspace(*sp))
			sp++;
		    *sp = '\0';	/* truncate blanks, comments etc. */
		    strcpy(root, cp);
		    break;
		}
	    }
	    /* need to find the shutdown message file path */

	    rewind(accessfile);

	    while (fgets(linebuf, sizeof(linebuf) - 1, accessfile) != NULL) {
		if ((sp = strstr(linebuf, "shutdown")) != NULL) {
		    if ((cp = strchr(sp, '\n')) != NULL)
			*cp = '\0';	/* strip newline */
		    sp += 8;	/* skip past "root" keyword */

		    while (*sp && isspace(*sp))		/* skip whitespace to path */
			sp++;
		    cp = sp;
		    while (*sp && !isspace(*sp))
			sp++;
		    *sp = '\0';	/* truncate blanks, comments etc. */
		    break;
		}
	    }

	    /*
	       ** check to make sure the admin hasn't specified 
	       ** a complete path in the 'shutdown' directive.
	     */
	    if ((sp = strstr(cp, root)) == NULL)
		sprintf(altmsgpath, "%s%s", root, cp);

	    /*
	       ** Check to see if the message file has been created elsewhere.
	     */
	    if (newfile(altmsgpath))
		c += shutdown_msgfile(altmsgpath, buf);
	}
	fclose(svrfp);
    }

#endif
    fclose(accessfile);
    free(aclbuf);
    return (c > 0 ? 1 : 0);
}
