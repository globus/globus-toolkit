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
 * domain.c  - DNS functions for WU-FTPD using res_*
 *
 * INITIAL AUTHOR - *      Nikos Mouat    <nikm@cyberflunk.com>
 */

#include "config.h"
#include <stdlib.h>
#include "proto.h"

#ifdef HAVE_LIBRESOLV

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef NO_DNS
#include <arpa/nameser.h>
#include <resolv.h>

#ifndef INT16SZ
#define INT16SZ sizeof(u_short)
#endif /* !INT16SZ */

#ifndef INT32SZ
#define INT32SZ sizeof(u_long)
#endif /* !INT32SZ */

#ifndef INADDRSZ
#define INADDRSZ sizeof(struct in_addr)
#endif /* !INADDRSZ */

#ifndef HFIXEDSZ
#define HFIXEDSZ sizeof(HEADER)
#endif /* !HFIXEDSZ */

#endif /* !NO_DNS */
#include "extensions.h"

/* these should go in a new ftpd.h perhaps? config.h doesn't seem appropriate */
/* and there does not appear to be a global include file                      */
#ifndef TRUE
#define  TRUE   1
#endif

#ifndef FALSE
#define  FALSE  !TRUE
#endif

struct t_resolver_options {
    char *token;
    int value;
} resolver_options[] = {

#ifdef RES_DEBUG
    {
	"debug", RES_DEBUG
    },
#endif
#ifdef RES_AAONLY
    {
	"aaonly", RES_AAONLY
    },
#endif
#ifdef RES_USEVC
    {
	"usevc", RES_USEVC
    },
#endif
#ifdef RES_STAYOPEN
    {
	"stayopen", RES_STAYOPEN
    },
#endif
#ifdef RES_PRIMARY
    {
	"primary", RES_PRIMARY
    },
#endif
#ifdef RES_IGNTC
    {
	"igntc", RES_IGNTC
    },
#endif
#ifdef RES_RECURSE
    {
	"recurse", RES_RECURSE
    },
#endif
#ifdef RES_DEFNAMES
    {
	"defnames", RES_DEFNAMES
    },
#endif
#ifdef RES_DNSRCH
    {
	"dnsrch", RES_DNSRCH
    },
#endif
#ifdef RES_INSECURE1
    {
	"insecure1", RES_INSECURE1
    },
#endif
#ifdef RES_INSECURE2
    {
	"insecure2", RES_INSECURE2
    },
#endif
#ifdef RES_NOALIASES
    {
	"noaliases", RES_NOALIASES
    },
#endif
#ifdef RES_USE_INET6
    {
	"use_inet6", RES_USE_INET6
    },
#endif
#ifdef RES_ROTATE
    {
	"rotate", RES_ROTATE
    },
#endif
#ifdef RES_NOCHECKNAME
    {
	"nocheckname", RES_NOCHECKNAME
    },
#endif
#ifdef RES_KEEPSIG
    {
	"keepsig", RES_KEEPSIG
    },
#endif
#ifdef RES_DEFAULT
    {
	"default", RES_DEFAULT
    },
#endif
    {
	NULL, 0
    }
};

/* globals */
int resolver_initialized = FALSE;
char *remote_hostname = NULL;
char *remote_address = NULL;
int has_reverse_dns = FALSE;
int has_matching_dns = FALSE;

/* Prototypes */
int check_matching_dns(void);
int lookup_ip(char *ip, char **fqdn);
int check_name_for_ip(char *name, char *ip);
int initialize_dns(struct sockaddr_in *remote_socket);
int check_reverse_dns(void);

/* types for res_* answers */
#ifndef NO_DNS
typedef union {
    HEADER qb1;
    u_char qb2[PACKETSZ];
} querybuf;

#endif

/****************************************************************************
 * lookup_name()
 *   This routine takes a FQDN and tries to find a valid IP address.
 *   If a CNAME is returned, it looks further on in the reply for an
 *   A record. It will return as soon as it finds an A record, so hosts
 *   with multiple A records will have the first A record returned.
 ***************************************************************************/
int lookup_name(char *name, char **ip)
{
#ifndef NO_DNS
    u_char *msg_end, *msg_ptr;
#ifdef USE_RES_SEND
    querybuf question, answer;
#else
    querybuf answer;
#endif
    int rc, num_answers, num_query, q_type, q_class, q_ttl, q_len;
    char query_name[MAXDNAME + 1];
    struct in_addr inaddr;
    char *result;

    /* res_mkquery+res_send seem to function identically to res_query, so I'm */
    /* using res_query. If there's some advantage to using res_mkquery that I */
    /* don't know about (which wouldn't surprise me :) then you can just      */
    /* define USE_RES_SEND and it will use that method                        */

#ifdef USE_RES_SEND
    rc = res_mkquery(QUERY, name, C_IN, T_A, NULL, 0, NULL, question.qb2, sizeof(querybuf));

    if (rc < 0) {
	return FALSE;
    }

    rc = res_send(question.qb2, rc, answer.qb2, sizeof(querybuf));
#else
    rc = res_query(name, C_IN, T_A, answer.qb2, sizeof(querybuf));
#endif

    if (rc < 0) {
	return FALSE;
    }

    msg_end = (u_char *) & answer + rc;

    num_answers = ntohs(answer.qb1.ancount);
    num_query = ntohs(answer.qb1.qdcount);

    if (num_answers < 1) {
	/* No answers mean that this hostname doesn't exist..                 */
	return FALSE;
    }

    msg_ptr = answer.qb2 + HFIXEDSZ;

    /* skip over the query */
    for (; (num_query > 0) && (msg_ptr < msg_end); num_query--) {
	msg_ptr += dn_skipname(msg_ptr, msg_end) + QFIXEDSZ;
    }

    for (; (num_answers > 0) && (msg_ptr < msg_end); num_answers--) {

	rc = dn_expand(answer.qb2, msg_end, msg_ptr, (void *) query_name, MAXDNAME);

	msg_ptr += rc;

	q_type = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	q_class = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	q_ttl = _getlong(msg_ptr);
	msg_ptr += INT32SZ;

	q_len = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	/* look at the type of response that we recieved. If it's a CNAME then */
	/* we need to find out what the CNAME's IP is.                         */
	switch (q_type) {
	case T_CNAME:
	    /* Got a CNAME - hope that there are other answers with the A */
	    msg_ptr += q_len;
	    break;
	case T_A:
	    bcopy(msg_ptr, (char *) &inaddr, INADDRSZ);
	    msg_ptr += q_len;
	    result = inet_ntoa(inaddr);

	    *ip = (char *) malloc(strlen(result) + 1);
	    if (*ip == NULL)
		return FALSE;
	    strcpy(*ip, result);
	    return TRUE;
	default:
	    /* what the ?? - we don't expect this response type */
	    return FALSE;
	}
    }

    /* oh dear, there was no A's in the response */
#endif /* !NO_DNS */
    return FALSE;
}
/****************************************************************************
 * lookup_ip()
 *   This routine takes an IP address in the format a.b.c.d and returns the
 *   hostname.
 ***************************************************************************/
int lookup_ip(char *ip, char **fqdn)
{
#ifndef NO_DNS
    u_char *msg_end, *msg_ptr;
#ifdef USE_RES_SEND
    querybuf question, answer;
#else
    querybuf answer;
#endif
    int rc, num_answers, num_query, q_type, q_class, q_ttl, q_len;
    char query_name[MAXDNAME + 1];
    char in_addr[MAXDNAME + 1];
    unsigned int a, b, c, d;

    a = b = c = d = 0;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    sprintf(in_addr, "%u.%u.%u.%u.in-addr.arpa", d, c, b, a);

#ifdef USE_RES_SEND
    rc = res_mkquery(QUERY, in_addr, C_IN, T_PTR, NULL, 0, NULL, question.qb2, sizeof(querybuf));

    if (rc < 0) {
	return FALSE;
    }

    rc = res_send(question.qb2, rc, answer.qb2, sizeof(querybuf));
#else
    rc = res_query(in_addr, C_IN, T_PTR, answer.qb2, sizeof(querybuf));
#endif

    if (rc < 0) {
	return FALSE;
    }

    msg_end = (u_char *) & answer + rc;

    num_answers = ntohs(answer.qb1.ancount);
    num_query = ntohs(answer.qb1.qdcount);

    if (num_answers < 1) {
	/* No answers mean that this hostname doesn't exist..                 */
	return FALSE;
    }

    msg_ptr = answer.qb2 + HFIXEDSZ;

    /* skip over the query */
    for (; (num_query > 0) && (msg_ptr < msg_end); num_query--) {
	msg_ptr += dn_skipname(msg_ptr, msg_end) + QFIXEDSZ;
    }

    for (; num_answers > 0 && (msg_ptr < msg_end); num_answers--) {

	rc = dn_expand(answer.qb2, msg_end, msg_ptr, (void *) query_name, MAXDNAME);

	/* increment our pointer */
	msg_ptr += rc;

	/* read off the various answer information */
	q_type = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	q_class = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	q_ttl = _getlong(msg_ptr);
	msg_ptr += INT32SZ;

	q_len = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	switch (q_type) {
	case T_PTR:
	    /* this is our answer, expand the name, allocate space for it and */
	    /* set the return information                                     */
	    rc = dn_expand(answer.qb2, msg_end, msg_ptr, (void *) query_name, MAXDNAME);

	    if (rc >= 0) {
		*fqdn = (char *) malloc(strlen(query_name) + 1);
		if (*fqdn == NULL)
		    return FALSE;

		strcpy(*fqdn, query_name);
		return TRUE;
	    }
	    break;
	default:
	    /* unknown response type.. keep looking */
	    msg_ptr += q_len;
	}
    }

#endif /* !NO_DNS */

    return FALSE;
}
/****************************************************************************
 * check_name_for_ip()
 *   This routine checks to see if a given IP address is a valid IP for a
 *   given name. We need this because lookup_name() only returns the first
 *   IP address in the response, and if a user is coming from a different
 *   IP address for the same machine, we want to make sure that we match
 *   them.
 ***************************************************************************/
int check_name_for_ip(char *name, char *ip)
{
#ifndef NO_DNS
#ifdef USE_RES_SEND
    querybuf question, answer;
#else
    querybuf answer;
#endif
    u_char *msg_end, *msg_ptr;
    char query_name[MAXDNAME + 1];
    int rc, num_answers, num_query, q_type, q_class, q_ttl, q_len;
    struct in_addr inaddr, qaddr;

    /* convert the passed IP address into an in_addr (for comparison later) */
    /* not all systems have inet_aton(), so use inet_addr() */
    if ((qaddr.s_addr = inet_addr(ip)) == (u_long) - 1) {
	return FALSE;
    }

#ifdef USE_RES_SEND
    rc = res_mkquery(QUERY, name, C_IN, T_A, NULL, 0, NULL, question.qb2, sizeof(querybuf));

    if (rc < 0) {
	return FALSE;
    }

    rc = res_send(question.qb2, rc, answer.qb2, sizeof(querybuf));
#else
    rc = res_query(name, C_IN, T_A, answer.qb2, sizeof(querybuf));
#endif

    if (rc < 0) {
	return FALSE;
    }

    msg_end = (u_char *) & answer + rc;

    num_answers = ntohs(answer.qb1.ancount);
    num_query = ntohs(answer.qb1.qdcount);

    if (num_answers < 1) {
	/* No answers mean that this hostname doesn't exist..                 */
	return FALSE;
    }

    msg_ptr = answer.qb2 + HFIXEDSZ;

    /* skip over the query */
    for (; (num_query > 0) && (msg_ptr < msg_end); num_query--) {
	msg_ptr += dn_skipname(msg_ptr, msg_end) + QFIXEDSZ;
    }

    for (; (num_answers > 0) && (msg_ptr < msg_end); num_answers--) {
	rc = dn_expand(answer.qb2, msg_end, msg_ptr, (void *) query_name, MAXDNAME);

	msg_ptr += rc;

	q_type = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	q_class = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	q_ttl = _getlong(msg_ptr);
	msg_ptr += INT32SZ;

	q_len = _getshort(msg_ptr);
	msg_ptr += INT16SZ;

	/* look at the type of response that we recieved. If it's a CNAME then */
	/* we need to find out what the CNAME's IP is.                         */
	switch (q_type) {
	case T_CNAME:
	    /* Got a CNAME - hope that there are other answers with the A */
	    msg_ptr += q_len;
	    break;
	case T_A:
	    bcopy(msg_ptr, (char *) &inaddr, INADDRSZ);
	    msg_ptr += q_len;
	    if (memcmp(&inaddr, &qaddr, sizeof(struct in_addr)) == 0) {
		return TRUE;
	    }
	    break;
	default:
	    /* what the ?? - we don't expect this response type */
	    return FALSE;
	}
    }

#endif /* !NO_DNS */

    /* no matching IP's */
    return FALSE;
}

/****************************************************************************
 * initialize_dns()
 *    initialize the DNS subsystem, set resolver options and collect global
 *    variables. The remote socket is passed to this routine so that it
 *    can set DNS variables related to the remote site. 
 ***************************************************************************/
int initialize_dns(struct sockaddr_in *remote_socket)
{
#ifndef NO_DNS

    struct aclmember *entry = NULL;
    char *temp_pointer;

    if (resolver_initialized)
	return TRUE;

    /* check to see if the resolver has been initialized already */
    if ((_res.options & RES_INIT) == 0) {
	if ((res_init()) == -1) {
	    /* failed to initialize the resolver */
	    return FALSE;
	}
    }

    /* load the 'dns resolveroptions X' entries from the config. This will */
    /* change when we have the new config file parsing methods             */
    while (getaclentry("dns", &entry) && ARG0 && ARG1 != NULL) {
	/* there are other DNS options, we only care about 'resolveroptions' */
	if (!strcasecmp(ARG0, "resolveroptions")) {
	    int arg_count;

	    /* read in the options, and set _res.options appropriately        */
	    for (arg_count = 1; ARG[arg_count] != NULL; arg_count++) {
		int operation = 0;
		char *option;
		int table_index;
		int option_bitvalue;

		if (ARG[arg_count][0] == '-') {
		    operation = -1;	/* want to UNSET option */
		    option = &ARG[arg_count][1];
		}
		else if (ARG[arg_count][0] == '+') {
		    operation = 1;	/* want to SET option */
		    option = &ARG[arg_count][1];
		}

		if (operation == 0) {
		    /* no operation specified, assume they meant + so do a SET */
		    operation = 1;
		    option = &ARG[arg_count][0];
		}

		option_bitvalue = 0;

		/* now lookup option bit value in the resolver_options table */
		for (table_index = 0; resolver_options[table_index].token != NULL;
		     table_index++) {
		    if (!strcasecmp(option, resolver_options[table_index].token)) {
			option_bitvalue = resolver_options[table_index].value;
		    }
		}

		/* make sure that we have a valid operation to perform */
		if (option_bitvalue == 0) {
		    /* nope. keep looking at other args. */
		    continue;
		}


		/* okay, let's do this operation then */
		if (operation < 0) {
		    /* turn *off* option */
		    _res.options &= ~option_bitvalue;
		}
		else {
		    _res.options |= option_bitvalue;
		}
	    }
	}
    }

    /* save the remote address */
    temp_pointer = inet_ntoa(remote_socket->sin_addr);
    remote_address = (char *) malloc(strlen(temp_pointer) + 1);
    if (remote_address == NULL) {
	/* memory error */
	return FALSE;
    }
    /* size should be identical */
    strcpy(remote_address, temp_pointer);

    /* the old code checks remote_address for 0.0.0.0 and if there's a   */
    /* match, sets the hostname to 'localhost' - so let's do that for    */
    /* compatibility and perhaps unknown resolvers which behave this way */
    if (!strcmp(remote_address, "0.0.0.0")) {
	remote_hostname = "localhost";
    }
    else if (lookup_ip(remote_address, &temp_pointer)) {
	has_reverse_dns = TRUE;

	/* save the remote hostname (returned from lookup_ip()) */
	remote_hostname = (char *) malloc(strlen(temp_pointer) + 1);
	if (remote_hostname == NULL) {
	    /* memory error */
	    return FALSE;
	}
	/* size should be identical */
	strcpy(remote_hostname, temp_pointer);

	/* ok, we should now have hostname and address based on the real */
	/* IP address. Let's check the forward DNS of remote_hostname    */
	/* and see if we get the same address..                          */
	has_matching_dns = check_name_for_ip(remote_hostname, inet_ntoa(remote_socket->sin_addr));
    }
    else {
	has_reverse_dns = FALSE;
	has_matching_dns = TRUE;	/* no reverse, nothing to match */
    }

    resolver_initialized = TRUE;

#endif /* !NO_DNS */

    return TRUE;
}
/****************************************************************************
 * check_reverse_dns()
 ***************************************************************************/
int check_reverse_dns(void)
{
#ifndef NO_DNS

    struct aclmember *entry = NULL;
    int rc = TRUE;

    /* check the config to see if we care */
    while (getaclentry("dns", &entry) && ARG0 && ARG1 != NULL) {

	if (!strcasecmp(ARG0, "refuse_no_reverse")) {
	    FILE *msg_file;
	    char linebuf[MAXPATHLEN];
	    char outbuf[MAXPATHLEN];
	    int code = 530;
	    char *crptr;

	    /* ok, so configuration is telling us to not allow connections */
	    /* that don't have any reverse DNS                             */
	    if (!has_reverse_dns) {
		/* ok, so we need to kick out this user */

		/* check to see if admin wants to override */
		if (ARG2 && (!strcasecmp(ARG2, "override"))) {
		    /* Administrative override - but display the warning anyway */
		    code = 220;
		}

		msg_file = fopen(ARG1, "r");
		if (msg_file != NULL) {
		    while (fgets(linebuf, sizeof(linebuf), msg_file)) {
			if ((crptr = strchr(linebuf, '\n')) != NULL)
			    *crptr = '\0';
			msg_massage(linebuf, outbuf, sizeof(outbuf));
			lreply(code, "%s", outbuf);
		    }
		    fclose(msg_file);
#ifndef NO_SUCKING_NEWLINES
		    lreply(code, "");
#endif
		    if (code == 530) {
			reply(code, "");
			rc = FALSE;
		    }
		    else {
			lreply(code, "Administrative Override. Permission granted.");
			lreply(code, "");
		    }
		}
	    }
	}
    }

    return rc;
#else /* NO_DNS */
    return TRUE;
#endif
}
/****************************************************************************
 * check_matching_dns()
 ***************************************************************************/
int check_matching_dns(void)
{
#ifndef NO_DNS
    struct aclmember *entry = NULL;
    int rc = TRUE;

    /* check the config to see if we care */
    while (getaclentry("dns", &entry) && ARG0 && ARG1 != NULL) {
	if (!strcasecmp(ARG0, "refuse_mismatch")) {
	    FILE *msg_file;
	    char linebuf[MAXPATHLEN];
	    char outbuf[MAXPATHLEN];
	    int code = 530;
	    char *crptr;

	    /* ok, so configuration is telling us to not allow connections */
	    /* that don't have any reverse DNS                             */
	    if (!has_matching_dns) {
		/* ok, so we need to kick out this user */

		/* check to see if admin wants to override */
		if (ARG2 && (!strcasecmp(ARG2, "override"))) {
		    /* Administrative override - but display the warning anyway */
		    code = 220;
		}

		msg_file = fopen(ARG1, "r");
		if (msg_file != NULL) {
		    while (fgets(linebuf, sizeof(linebuf), msg_file)) {
			if ((crptr = strchr(linebuf, '\n')) != NULL)
			    *crptr = '\0';
			msg_massage(linebuf, outbuf, sizeof(outbuf));
			lreply(code, "%s", outbuf);
		    }
		    fclose(msg_file);
#ifndef NO_SUCKING_NEWLINES
		    lreply(code, "");
#endif
		    if (code == 530) {
			reply(code, "");
			rc = FALSE;
		    }
		    else {
			lreply(code, "Administrative Override. Permission granted.");
			lreply(code, "");
		    }
		}
	    }
	}
    }
    return rc;
#else /* NO_DNS */
    return TRUE;
#endif
}

#endif /* HAVE_LIBRESOLV */
