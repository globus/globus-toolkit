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
/* GREGORY's comments
 * Use 194.80.17.14 for when the control connection is on any other address
 * passive address 194.80.17.14 0.0.0.0/0
 *
 * My idea for 'passive address' is that the entire ftpaccess be parsed and a
 * table build from them.  The table is sorted (insertion sort is probably
 * good enough) from largest to smallest CIDR mask (/8 then /0).  The first
 * match when top-down searching for the control connection's address is the
 * most-specific and is taken.  If no matches occur at all, use the default
 * address determined from the interface, just as the daemon always has in
 * the past.
 *
 * That's where CIDR comes in.  A /0 means 'match everything'.  If it's
 * there, it'll give the IP address to use everywhere there isn't a more
 * specific remapping given.  If it's not there, we still need something, so
 * we returnthe default from the interface.  In your case, just 0/0 and
 * nobody'll ever see the internal IP numbers.
 */
#include "config.h"
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../support/ftp.h"
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <setjmp.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
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
#include <string.h>
#include <limits.h>
#include "extensions.h"
#include "pathnames.h"
#include "proto.h"

extern struct sockaddr_in ctrl_addr;
extern struct sockaddr_in his_addr;	/* added.  _H */
extern struct sockaddr_in vect_addr;	/* added.  _H */
static struct sockaddr_in *vector_ptr = (struct sockaddr_in *) NULL;
extern int logging;
extern int log_commands;
extern int debug;
extern char hostname[], remotehost[];
extern int usedefault;
extern int transflag;
extern int data;
extern int errno;
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/*  The following code is used to create and maintain the 
 *  Address lists using the S_addr struct ( from in.h )
 * struct in_addr { 
 *      union { 
 *              struct { u_char s_b1, s_b2, s_b3, s_b4; } S_un_b; 
 *              struct { u_short s_w1, s_w2; } S_un_w; 
 *              u_long S_addr; 
 *      } S_un; 
 * define s_addr  S_un.S_addr              should be used for all code 
 */
struct v_addr {
    u_long s_external_identity;
    u_long s_vector;
    unsigned short s_sig;
};
typedef struct v_addr v_addr;
struct v_index {
    v_addr *memory;
    v_addr **index;
    unsigned short count;
    unsigned short slots;
};
typedef struct v_index v_index;
struct v_paddr {
    u_long s_address;
    int minport;
    int maxport;
    unsigned short s_sig;
};
typedef struct v_paddr v_paddr;
struct v_ports {
    v_paddr *memory;
    v_paddr **index;
    unsigned short count;
    unsigned short slots;
};
typedef struct v_ports v_ports;

static struct v_index *VECTORS = NULL;
static struct v_ports *PORTS = NULL;

extern int passive_port_max;
extern int passive_port_min;

extern void perror_reply(int, char *);
int routevector(void);
void checkports(void);
static struct v_index *initvectstruct(int num);
static struct v_ports *initportstruct(int num);
static void makeportentry(v_paddr * p, u_long entry, u_short s_sig, char *minport_in, char *maxport_in);
static void makevectentry(v_addr * p, u_long external_identity, u_long vector, u_short s_sig);
static void addportentry(char *address, char *minport, char *maxport);
static void addvectentry(char *external_identity, char *vector);
static void initportvectors(void);
static int addr_cmp(u_long s1, u_short s1_sig, u_long s2, u_short s2_sig);
static int addr_smatch(u_long s1, u_long s2, u_short shift_in);
static v_paddr *find_passive_port_entry(u_long port);
static v_addr *find_passive_vect_entry(u_long e);

int routevector(void)
{
    int vect_addr_set;
    u_long entry;
    v_addr *vaddr;
    extern struct sockaddr_in vect_addr;
    vect_addr_set = 0;

    initportvectors();
    if (VECTORS != NULL) {
	entry = ntohl((his_addr.sin_addr.s_addr));
	if ((int) entry != -1) {
	    vaddr = find_passive_vect_entry(entry);
	    if (vaddr != NULL) {
		vect_addr.sin_addr.s_addr = htonl(vaddr->s_external_identity);
		vect_addr.sin_family = AF_INET;
		vect_addr_set = 1;
		vector_ptr = &vect_addr;

	    }
	}
    }
#if 0
    {
	extern void debug_listing();
	debug_listing();
    }
#endif
    return (vect_addr_set);
}



void checkports(void)
{
    u_long entry;
    v_paddr *addr;

    passive_port_min = -1;
    passive_port_max = -1;
    if (PORTS != NULL) {
	entry = his_addr.sin_addr.s_addr;
	if ((int) entry != -1) {
	    addr = find_passive_port_entry(entry);
	    if (addr != NULL) {
		passive_port_min = addr->minport;
		passive_port_max = addr->maxport;
	    }
	}

    }

}



static struct v_index *initvectstruct(int num)
{
    int i;
    v_addr *ptr, **index;
    v_index *v;

    if ((v = (v_index *) malloc(sizeof(v_index))) == (v_index *) NULL) {
	syslog(LOG_INFO, "ERROR allocating memory for index record");
	perror_reply(421, "Local resource failure: malloc");
	dologout(1);
    }
    else {
	v->count = 0;
	v->slots = 0;
	v->index = NULL;
	if ((v->memory = (v_addr *) malloc(sizeof(v_addr) * num)) == (v_addr *) NULL) {
	    syslog(LOG_INFO, "ERROR allocating memory for port addresses");
	    perror_reply(421, "Local resource failure: malloc");
	    dologout(1);
	}
	else {
	    if ((v->index = (v_addr **) malloc(sizeof(v_addr *) * num)) == (v_addr **) NULL) {
		syslog(LOG_INFO, "ERROR allocating memory for vector index");
		perror_reply(421, "Local resource failure: malloc");
		dologout(1);
	    }
	    else {
		v->slots = num;
		for (i = 0, ptr = v->memory, index = v->index; i < num; i++) {
		    ptr->s_external_identity = ntohl(inet_addr("0.0.0.0"));
		    ptr->s_vector = ntohl(inet_addr("0.0.0.0"));
		    ptr->s_sig = (u_short) 0;
		    *index++ = ptr++;
		}
	    }
	}
    }
    return (v);
}



static struct v_ports *initportstruct(int num)
{
    int i;
    v_paddr *ptr;
    v_ports *v;

    if ((v = (v_ports *) malloc(sizeof(v_ports))) == (v_ports *) NULL) {
	syslog(LOG_INFO, "ERROR allocating memory for index record");
	perror_reply(421, "Local resource failure: malloc");
	dologout(1);
    }
    else {
	v->slots = 0;
	v->count = 0;
	v->index = NULL;
	if ((v->memory = (v_paddr *) malloc(sizeof(v_paddr) * (num + 1))) == (v_paddr *) NULL) {
	    syslog(LOG_INFO, "ERROR allocating memory for port addresses");
	    perror_reply(421, "Local resource failure: malloc");
	    dologout(1);
	}
	else {
	    if ((v->index = (v_paddr **) malloc(sizeof(v_paddr *) * num)) == (v_paddr **) NULL) {
		syslog(LOG_INFO, "ERROR allocating memory for port index");
		perror_reply(421, "Local resource failure: malloc");
		dologout(1);
	    }
	    else {
		v->slots = (u_short) num;
		for (i = 0, ptr = v->memory; i < num; i++, ptr++) {
		    *(v->index + i) = ptr;
		    ptr->s_address = ntohl(inet_addr("0.0.0.0"));
		    ptr->minport = -1;
		    ptr->maxport = -1;
		    ptr->s_sig = (u_short) 0;
		}
	    }
	}
    }
    return (v);
}



static void makeportentry(v_paddr * p, u_long entry, u_short s_sig, char *minport_in, char *maxport_in)
{
    p->s_address = entry;
    p->s_sig = s_sig;
    p->minport = atoi(minport_in);
    p->maxport = atoi(maxport_in);

    if (p->maxport < p->minport) {
	p->minport = -1;
	p->maxport = -1;
    }
}


static void makevectentry(v_addr * p, u_long external_identity, u_long vector, u_short s_sig)
{
    p->s_external_identity = external_identity;
    p->s_vector = vector;
    p->s_sig = s_sig;
}



static void addportentry(char *address_in, char *minport_in, char *maxport_in)
{
    u_long entry;
    int cmp;
    u_short s_sig;
    char *s1, *s2;
    char addrstr[MAXHOSTNAMELEN + 1];
    register unsigned short i, fnd;
    s_sig = (u_short) 0;

    if (PORTS == NULL) {
	syslog(LOG_INFO, "ERROR port index addition, invalid ptr");
	perror_reply(421, "Local resource failure: malloc");
	dologout(1);
    }
    else {
	if (strlen(address_in) > MAXHOSTNAMELEN)
	    syslog(LOG_INFO, "ERROR ftpaccess port entry<%s> too large", address_in);
	else {
	    /* Find the significance of the entry ( if it exists )
	       *  eg XXX.XXX.XXX.XXX/sig
	     */
	    for (i = 0; i < MAXHOSTNAMELEN; i++)
		addrstr[i] = '\0';
	    for (s1 = address_in, s2 = &(addrstr[0]); *s1 && *s1 != '/'; s1++, s2++)
		*s2 = *s1;
	    *s2 = '\0';
	    if (*s1 == '/') {
		s1++;
		if (*s1)
		    s_sig = (u_short) atoi(s1);
	    }
	    if ((int) (entry = ntohl(inet_addr(addrstr))) == -1)
		syslog(LOG_INFO, "ERROR ftpaccess port entry<%s> invalid", address_in);
	    else {
		for (i = 0, fnd = 0; i < PORTS->count && fnd == 0 && entry != (u_long) 0; i++) {
		    v_paddr *vp = *(PORTS->index + i);
		    cmp = addr_cmp(vp->s_address, vp->s_sig, entry, s_sig);
		    if (cmp == 0) {
			fnd = 1;
			makeportentry(vp, entry, s_sig, minport_in, maxport_in);
		    }
		    else if (cmp > 0) {
			v_paddr *p1;
			for (p1 = *(PORTS->index + PORTS->count); p1 >= vp; p1--)
			    *p1 = *(p1 - 1);
			fnd = 2;
			makeportentry(vp, entry, s_sig, minport_in, maxport_in);
			PORTS->count += 1;
		    }
		}
		if (fnd == 0) {
		    makeportentry(*(PORTS->index + PORTS->count), entry, s_sig, minport_in, maxport_in);
		    PORTS->count += 1;
		}
		if (i == PORTS->slots) {
		    syslog(LOG_INFO, "ERROR bad slot count  for port index record");
		    perror_reply(421, "Local resource failure: malloc");
		    dologout(1);
		}
	    }
	}
    }
}



static void addvectentry(char *external_identity_in, char *vector_in)
{
    u_long external_identity, vector;
    int cmp;
    u_short s_sig;
    char *s1, *s2;
    char addrstr[MAXHOSTNAMELEN + 1];
    register unsigned short i, fnd;
    s_sig = (u_short) 0;

    if (VECTORS == NULL) {
	syslog(LOG_INFO, "ERROR vector index addition, invalid ptr");
	perror_reply(421, "Local resource failure: malloc");
	dologout(1);
    }
    else {
	if (strlen(external_identity_in) > MAXHOSTNAMELEN)
	    syslog(LOG_INFO, "ERROR ftpaccess passive entry <%s> to large", external_identity_in);
	else {
	    if (strlen(vector_in) > MAXHOSTNAMELEN)
		syslog(LOG_INFO, "ERROR ftpaccess vector entry<%s> to large", vector_in);
	    else {
		/* Find the significance of the entry ( if it exists )
		   *  eg XXX.XXX.XXX.XXX/sig
		 */
		for (i = 0; i < MAXHOSTNAMELEN; i++)
		    addrstr[i] = '\0';
		for (s1 = vector_in, s2 = &(addrstr[0]); *s1 && (*s1 != '/'); s1++, s2++)
		    *s2 = *s1;
		*s2 = '\0';
		if (*s1 == '/') {
		    s1++;
		    if (*s1)
			s_sig = (u_short) atoi(s1);
		}
		if ((int) (vector = ntohl(inet_addr(addrstr))) == -1)
		    syslog(LOG_INFO, "ERROR ftpaccess vector entry<%s> invalid", vector_in);
		else {
		    if ((int) (external_identity = ntohl(inet_addr(external_identity_in))) == -1)
			syslog(LOG_INFO, "ERROR ftpaccess vector entry<%s> invalid", external_identity_in);
		    else {
			for (i = 0, fnd = 0; i < VECTORS->count && fnd == 0 && vector != (u_long) 0; i++) {
			    v_addr *vp = *(VECTORS->index + i);
			    cmp = addr_cmp(vp->s_vector, vp->s_sig, vector, s_sig);
			    if (cmp == 0) {
				fnd = 1;
				makevectentry(vp, external_identity, vector, s_sig);
			    }
			    else if (cmp > 0) {
				v_addr *p1;
				for (p1 = *(VECTORS->index + VECTORS->count); p1 >= vp; p1--)
				    *p1 = *(p1 - 1);
				fnd = 2;
				makevectentry(vp, external_identity, vector, s_sig);
				VECTORS->count += 1;
			    }
			}
			if (fnd == 0) {
			    makevectentry(*(VECTORS->index + VECTORS->count), external_identity, vector, s_sig);
			    VECTORS->count += 1;
			}
			if (i >= VECTORS->slots) {
			    syslog(LOG_INFO, "ERROR bad slot count  for passive vectors index record");
			    perror_reply(421, "Local resource failure: malloc");
			    dologout(1);
			}
		    }
		}
	    }
	}
    }
}



static void initportvectors(void)
{
    struct aclmember *entry = NULL;
    int pcnt;
    int acnt;

    pcnt = 0;
    acnt = 0;

    entry = (struct aclmember *) NULL;

    while (getaclentry("passive", &entry)) {
	if (!strcasecmp(ARG0, "ports")) {
	    if (!ARG0 || !ARG1 || !ARG2)
		continue;
	    pcnt++;
	}
	if (!strcasecmp(ARG0, "address")) {
	    if (!ARG0 || !ARG1 || !ARG2)
		continue;
	    acnt++;
	}
    }
    PORTS = (pcnt > 0) ? initportstruct(pcnt) : NULL;
    VECTORS = (acnt > 0) ? initvectstruct(acnt) : NULL;
    while (getaclentry("passive", &entry)) {
	if (!strcasecmp(ARG0, "ports"))
	    addportentry(ARG1, ARG2, ARG3);
	else if (!strcasecmp(ARG0, "address"))
	    addvectentry(ARG1, ARG2);
    }
}



/* compare two internet masks so that the significance order
 * is from the widest mask down (wide masks match before narrow ones)
 */
static int addr_cmp(u_long s1, u_short s1_sig, u_long s2, u_short s2_sig)
{
    if (s1_sig > s2_sig)
	return (-1);
    if (s1_sig < s2_sig)
	return (1);
    if (s1 < s2)
	return (-1);
    if (s1 > s2)
	return (1);
    return (0);
}



/* Compare the first x bits of two internet addresses 
 * 32  means match all ( return is zero on exact match only )
 * 24  means match on first 3 bytes 
 * 16  means match on first 2 bytes 
 *  8  means match on first 1 bytes 
 *  0  means assume match ( match 0 bytes )
 */

#define BITS_PER_BYTE 8

static int addr_smatch(u_long s1, u_long s2, u_short shift_in)
{
    u_long sh1, sh2;
    int shift;

    if (shift_in > 0) {
	shift = sizeof(u_long) * BITS_PER_BYTE;
	if (shift >= (int) shift_in)
	    shift -= (int) shift_in;
	if (shift > 0) {
	    sh2 = (s2 >> shift) << shift;
	    sh1 = (s1 >> shift) << shift;
	}
	else {
	    sh2 = s2;
	    sh1 = s1;
	}
	if (sh1 < sh2)
	    return (-1);
	if (sh1 > sh2)
	    return (1);
    }
    return (0);
}



static v_paddr *find_passive_port_entry(u_long addr)
{
    register int i;
    v_paddr *p;

    if (PORTS != NULL)
	for (i = 0; i < PORTS->count; i++) {
	    p = *(PORTS->index + i);
	    if (addr_smatch(addr, p->s_address, p->s_sig) == 0)
		return (p);
	}
    return (NULL);
}



static v_addr *find_passive_vect_entry(u_long addr)
{
    register int i;
    v_addr *p;

    if (VECTORS != NULL)
	for (i = 0; i < VECTORS->count; i++) {
	    p = *(VECTORS->index + i);
	    if (addr_smatch(addr, p->s_vector, p->s_sig) == 0)
		return (p);
	}
    return (NULL);
}
