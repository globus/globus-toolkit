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
/*
 * rdservers - read ftpservers file 
 *
 * INITIAL AUTHOR - Kent Landfield  <kent@landfield.com>
 */

#include "config.h"

#ifdef  VIRTUAL

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Prototype */
int read_servers_line(FILE *, char *, char *);

int read_servers_line(FILE *svrfp, char *hostaddress, char *accesspath)
{
    static char buffer[BUFSIZ];

    struct hostent *hp;
    char *hcp, *acp;
    char *bcp, *ecp;

    while (fgets(buffer, BUFSIZ, svrfp) != NULL) {

	/* Find first non-whitespace character */
	for (bcp = buffer; ((*bcp == '\t') || (*bcp == ' ')); bcp++);

	/* Get rid of comments */
	if ((ecp = strchr(buffer, '#')) != NULL)
	    *ecp = '\0';

	/* Skip empty lines */
	if ((bcp == ecp) || (*bcp == '\n'))
	    continue;

	/* separate parts */

	hcp = bcp;
	for (acp = hcp;
	     (*acp && !isspace(*acp)); acp++);

	/* better have something in access path or skip the line */
	if (!*acp)
	    continue;

	*acp++ = '\0';

	while (*acp && isspace(*acp))
	    acp++;

	/* again better have something in access path or skip the line */
	if (!*acp)
	    continue;

	ecp = acp;

	while (*ecp && (!isspace(*ecp)) && *ecp != '\n')
	    ++ecp;

	*ecp = '\0';

	if ((hp = gethostbyname(hcp)) != NULL) {
	    struct in_addr in;
	    memmove(&in, hp->h_addr, sizeof(in));
	    strcpy(hostaddress, inet_ntoa(in));
	}
	else
	    strcpy(hostaddress, hcp);

	strcpy(accesspath, acp);

	return (1);
    }
    return (0);
}
#endif
