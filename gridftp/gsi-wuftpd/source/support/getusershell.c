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
#ifndef _AIX

#include "../src/config.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>


#define SHELLS "/etc/shells"

/*
 * Do not add local shells here.  They should be added in /etc/shells
 */
static char *okshells[] =
{"/bin/sh", "/bin/csh", 0};

static char **shells, *strings;
static char **curshell = NULL;
static char **initshells();

/*
 * Get a list of shells from SHELLS, if it exists.
 */
char *getusershell(void)
{
    char *ret;

    if (curshell == NULL)
	curshell = initshells();
    ret = *curshell;
    if (ret != NULL)
	curshell++;
    return (ret);
}

void endusershell(void)
{
    if (shells != NULL)
	free((char *) shells);
    shells = NULL;
    if (strings != NULL)
	free(strings);
    strings = NULL;
    curshell = NULL;
}

void setusershell(void)
{
    curshell = initshells();
}

static char **initshells(void)
{
    register char **sp, *cp;
    register FILE *fp;
    struct stat statb;

    if (shells != NULL)
	free((char *) shells);
    shells = NULL;
    if (strings != NULL)
	free(strings);
    strings = NULL;
    if ((fp = fopen(SHELLS, "r")) == (FILE *) 0)
	return (okshells);
    if (fstat(fileno(fp), &statb) == -1) {
	(void) fclose(fp);
	return (okshells);
    }
    if ((strings = (char *) malloc((unsigned) statb.st_size + 1)) == NULL) {
	(void) fclose(fp);
	return (okshells);
    }
    shells = (char **) calloc((unsigned) statb.st_size / 3, sizeof(char *));

    if (shells == NULL) {
	(void) fclose(fp);
	free(strings);
	strings = NULL;
	return (okshells);
    }
    sp = shells;
    cp = strings;
    while (fgets(cp, MAXPATHLEN + 1, fp) != NULL) {
	while (*cp != '#' && *cp != '/' && *cp != '\0')
	    cp++;
	if (*cp == '#' || *cp == '\0')
	    continue;
	*sp++ = cp;
	while (!isspace(*cp) && *cp != '#' && *cp != '\0')
	    cp++;
	*cp++ = '\0';
    }
    *sp = (char *) 0;
    (void) fclose(fp);
    return (shells);
}

#else /* it is AIX */


/* emulate getusershell for AIX */

#include <userconf.h>
#include <userpw.h>
#include <sys/audit.h>
#include <usersec.h>

static int GETUSERSHELL_opened = 0;
static char **GETUSERSHELL_shells;
static int GETUSERSHELL_current;


char *getusershell()
{
    static char *val;
    static char *list;
    static char *retVal;
    int n;

    if (!GETUSERSHELL_opened) {
	if (getconfattr(SC_SYS_LOGIN, SC_SHELLS, (void *) &val, SEC_LIST)) {
	    return (NULL);
	}
	GETUSERSHELL_opened = 1;
	GETUSERSHELL_current = 0;
	list = val;
    }

    if ((list != NULL) && (*list != NULL)) {
	while (list && *list)
	    list++;

	*list = '\0';

	retVal = val;
	list++;
	val = list;
    }
    else
	retVal = NULL;

    return (retVal);

}

void setusershell()
{
    GETUSERSHELL_opened = 0;
}

void endusershell()
{
    GETUSERSHELL_opened = 0;
}







#endif
