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
#ifndef HOST_ACCESS
#define  HOST_ACCESS  1
#endif
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "pathnames.h"

/* Prototypes */
#ifdef VIRTUAL
extern int read_servers_line(FILE *, char *, char *);
#endif
void print_copyright(void);

int main(int argc, char **argv)
{
    struct stat sbuf;
    char *sp;
    char buf[1024];
    int c;

#ifdef VIRTUAL
    FILE *svrfp;
    char accesspath[1024];
    char hostaddress[32];
#endif

    gsi_wuftp_get_version();

    if (argc > 1) {
	while ((c = getopt(argc, argv, "V")) != EOF) {
	    switch (c) {
	    case 'V':
		print_copyright();
		exit(0);
	    default:
		fprintf(stderr, "usage: %s [-V]\n", argv[0]);
		exit(1);
	    }
	}
    }

    /* _PATH_FTPUSERS   */
    fprintf(stdout, "Checking _PATH_FTPUSERS :: %s\n", _PATH_FTPUSERS);
    if ((stat(_PATH_FTPUSERS, &sbuf)) < 0)
	printf("I can't find it... look in doc/examples for an example.\n");
    else
	printf("ok.\n");

#ifdef VIRTUAL

    /* _PATH_FTPSERVERS  */
    fprintf(stdout, "\nChecking _PATH_FTPSERVERS :: %s\n", _PATH_FTPSERVERS);
    if ((stat(_PATH_FTPSERVERS, &sbuf)) < 0)
	printf("I can't find it... look in doc/examples for an example.\n");
    else {
	printf("ok.\n");
	/* Need to check the access files specified in the ftpservers file. */
	if ((svrfp = fopen(_PATH_FTPSERVERS, "r")) == NULL)
	    printf("I can't open it! check permissions and run ckconfig again.\n");
	else {
	    while (read_servers_line(svrfp, hostaddress, accesspath) == 1) {
		fprintf(stderr, "\nChecking accessfile for %s :: %s\n", hostaddress, accesspath);
		/*
		   ** check to see that a valid directory value was
		   ** supplied and not something such as "INTERNAL"
		   **
		   ** It is valid to have a string such as "INTERNAL" in the
		   ** ftpservers entry. This is not an error. Silently ignore it.
		 */
		if (stat(accesspath, &sbuf) == 0) {
		    if ((sbuf.st_mode & S_IFMT) == S_IFDIR)
			printf("ok.\n");
		    else {
			printf("Check servers file and make sure only directories are listed...\n");
			printf("look in doc/examples for an example.\n");
		    }
		}
		else
		    printf("Internal ftpaccess usage specified... ok.\n");
	    }
	    fclose(svrfp);
	}
    }
#endif

    /* _PATH_FTPACCESS  */
    fprintf(stdout, "\nChecking _PATH_FTPACCESS :: %s\n", _PATH_FTPACCESS);
    if ((stat(_PATH_FTPACCESS, &sbuf)) < 0)
	printf("I can't find it... look in doc/examples for an example.\n");
    else
	printf("ok.\n");

    /* _PATH_PIDNAMES   */
    fprintf(stdout, "\nChecking _PATH_PIDNAMES :: %s\n", _PATH_PIDNAMES);
    strcpy(buf, _PATH_PIDNAMES);
    sp = (char *) strrchr(buf, '/');
    *sp = '\0';
    if ((stat(buf, &sbuf)) < 0) {
	printf("I can't find it...\n");
	printf("You need to make this directory [%s] in order for\n", buf);
	printf("the limit and user count functions to work.\n");
    }
    else
	printf("ok.\n");

    /* _PATH_CVT        */
    fprintf(stdout, "\nChecking _PATH_CVT :: %s\n", _PATH_CVT);
    if ((stat(_PATH_CVT, &sbuf)) < 0)
	printf("I can't find it... look in doc/examples for an example.\n");
    else
	printf("ok.\n");

    /* _PATH_XFERLOG    */
    fprintf(stdout, "\nChecking _PATH_XFERLOG :: %s\n", _PATH_XFERLOG);
    if ((stat(_PATH_XFERLOG, &sbuf)) < 0) {
	printf("I can't find it... \n");
	printf("Don't worry, it will be created automatically by the\n");
	printf("server if you do transfer logging.\n");
    }
    else
	printf("ok.\n");

    /* _PATH_PRIVATE    */
    fprintf(stdout, "\nChecking _PATH_PRIVATE :: %s\n", _PATH_PRIVATE);
    if ((stat(_PATH_PRIVATE, &sbuf)) < 0) {
	printf("I can't find it... look in doc/examples for an example.\n");
	printf("You only need this if you want SITE GROUP and SITE GPASS\n");
	printf("functionality. If you do, you will need to edit the example.\n");
    }
    else
	printf("ok.\n");

    /* _PATH_FTPHOSTS   */
    fprintf(stdout, "\nChecking _PATH_FTPHOSTS :: %s\n", _PATH_FTPHOSTS);
    if ((stat(_PATH_FTPHOSTS, &sbuf)) < 0) {
	printf("I can't find it... look in doc/examples for an example.\n");
	printf("You only need this if you are using the HOST ACCESS features\n");
	printf("of the server.\n");
    }
    else
	printf("ok.\n");
    return (0);
}
