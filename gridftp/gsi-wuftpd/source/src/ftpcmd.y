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
 * Grammar for FTP commands.
 * See RFC 959.
 */

%{

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
#include "mlsx.h"
#include "cksmcmd.h"

#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "extensions.h"
#include "pathnames.h"
#include "proto.h"

#ifdef FTP_SECURITY_EXTENSIONS

#include "secure_ext.h"
 
#else /* !FTP_SECURITY_EXTENSIONS */

#define LARGE_BUFSIZE		BUFSIZ

#endif /* !FTP_SECURITY_EXTENSIONS */

/*
 *  globus code added by JB
 */
#ifdef USE_GLOBUS_DATA_CODE
extern globus_ftp_control_handle_t              g_data_handle;
globus_list_t *					host_port_list = NULL;
globus_ftp_control_layout_t			g_layout;
globus_size_t                                   g_striped_file_size;
globus_ftp_control_parallelism_t		g_parallelism;
globus_ftp_control_delay_passive_t              g_delayed_passive;
globus_ftp_control_dcau_t			g_dcau;
globus_bool_t					g_send_restart_info = GLOBUS_FALSE;
globus_fifo_t					g_restarts;
extern gss_cred_id_t                            g_deleg_cred;
#endif

extern int dolreplies;
#ifndef INTERNAL_LS
extern char ls_long[50];
extern char ls_short[50];
#endif
extern struct sockaddr_in data_dest;
extern struct sockaddr_in his_addr;	/* added.  _H */
extern int logged_in;
extern struct passwd *pw;
extern int anonymous;
extern int logging;
extern int log_commands;
extern int log_security;
extern int type;
extern int mode;
extern int form;
extern int debug;
extern unsigned int timeout_idle;
extern unsigned int timeout_maxidle;
extern int pdata;
extern char hostname[], remotehost[], *remoteident;
extern char remoteaddr[];
extern char chroot_path[];
extern char guestpw[], authuser[];	/* added.  _H */
extern char proctitle[];
extern char *globerr;
extern int usedefault;
extern int transflag;
extern char tmpline[];
extern int data;
extern int errno;
extern char *home;
int exit_at=0;

off_t restart_point;
int yyerrorcalled;

extern char *strunames[];
extern char *typenames[];
extern char *modenames[];
extern char *formnames[];
extern int restricted_user;	/* global flag indicating if user is restricted to home directory */

/* TCP window size to use for data transferrs */
extern int TCPwindowsize;
 
#ifdef TRANSFER_COUNT
extern int data_count_total;
extern int data_count_in;
extern int data_count_out;
extern int byte_count_total;
extern int byte_count_in;
extern int byte_count_out;
extern int file_count_total;
extern int file_count_in;
extern int file_count_out;
extern int xfer_count_total;
extern int xfer_count_in;
extern int xfer_count_out;
#endif

extern int retrieve_is_data;

#ifdef VIRTUAL
extern int virtual_mode;
extern int virtual_ftpaccess;
extern char virtual_email[];
#endif

#ifdef IGNORE_NOOP
static int alarm_running = 0;
#endif

static unsigned short cliport = 0;
static struct in_addr cliaddr;
static int cmd_type;
static int cmd_form;
static int cmd_bytesz;
#ifndef FTP_BUFSIZE
#define FTP_BUFSIZE	512
#endif /* FTP_BUFSIZE */

#ifdef FTP_SECURITY_EXTENSIONS
char cbuf[LARGE_BUFSIZE];	/* Needed for ADAT commands */
#else /* !FTP_SECURITY_EXTENSIONS */
char cbuf[FTP_BUFSIZE];
#endif /* !FTP_SECURITY_EXTENSIONS */
char *fromname;

/* Debian linux bison fix: moved this up, added forward decls */

struct tab {
    char *name;
    short token;
    short state;
    short implemented;		/* 1 if command is implemented */
    char *help;
};

extern struct tab cmdtab[];
extern struct tab sitetab[];
extern char * feattab[];
static void toolong(int);
void help(struct tab *ctab, char *s);
void feat(char *tab[]);
struct tab *lookup(register struct tab *p, char *cmd);
int yylex(void);

static char *nullstr = "(null)";
#define CHECKNULL(p) ((p) ? (p) : nullstr)

extern int pasv_allowed(const char *remoteaddr);
extern int port_allowed(const char *remoteaddr);
%}

%token
    A   B   C   E   F   I
    L   N   P   R   S   T

    SP  CRLF    COMMA  SEMICOLON EQUALS HYPHEN
    
    STRING  NUMBER   BIGNUM

    USER    PASS    ACCT    REIN    QUIT    PORT
    PASV    TYPE    STRU    MODE    RETR    STOR
    APPE    MLFL    MAIL    MSND    MSOM    MSAM
    MRSQ    MRCP    ALLO    REST    RNFR    RNTO
    ABOR    DELE    CWD     LIST    NLST    SITE
    STAT_CMD    HELP    NOOP    MKD     RMD     PWD
    CDUP    STOU    SMNT    SYST    SIZE    MDTM
    FAULT   MLST    MLSD

    AUTH    ADAT    PROT    PBSZ    CCC     DCAU

    ESTO    ERET    SPAS    SPOR    FEAT    OPTS

    UMASK   IDLE    CHMOD   GROUP   GPASS   NEWER
    MINFO   INDEX   EXEC    ALIAS   CDPATH  GROUPS
    CHECKMETHOD     CHECKSUM        BUFSIZE PSIZE

    STRIPELAYOUT    PARTITIONED BLOCKED BLOCKSIZE
    PARALLELISM     DELAYED_PASV USE_DATA_MODE

    LEXERR	CKSM

%union {
    char *String;
    int Number;
    struct {
	char mode;
	off_t offset;
	off_t length;
    } estor_eret;
    struct {
	struct in_addr addr;
	unsigned short port;
    } address;
    off_t Bignum;
}

%type <String>  STRING password pathname pathstring username method
%type <Number>  NUMBER byte_size check_login form_code
%type <Number>  struct_code mode_code octal_number
%type <Number>  prot_code bufsize
%type <estor_eret> esto_mode eret_mode
%type <Bignum>	BIGNUM OFFSET LENGTH
%type <address> host_port
%type <Number>  byte_range byte_range_list
%start  cmd_list

%%

cmd_list:	/* empty */
    | cmd_list cmd
	{
	    fromname = (char *) NULL;
	    restart_point = 0;
	}
    | cmd_list rcmd
    ;

cmd: USER SP username CRLF
	{
	    if(exit_at == USER)
	    {
		dologout(0);
	    }
	    user($3);
	    if (log_commands)
		syslog(LOG_INFO, "USER %s", $3);
	    free($3);
	}
    | PASS SP password CRLF
	{
	    if(exit_at == PASS)
	    {
		dologout(0);
	    }
	    if (log_commands)
		if (anonymous)
		    syslog(LOG_INFO, "PASS %s", $3);
		else
		    syslog(LOG_INFO, "PASS password");

	    pass($3);
	    free($3);
	}
    | PORT check_login SP host_port CRLF
	{
	    if(exit_at == PORT)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "PORT");
/* H* port fix, part B: admonish the twit.
   Also require login before PORT works */
	    if ($2) 
            {
#ifndef DISABLE_PORT
		if (((cliaddr.s_addr == his_addr.sin_addr.s_addr)
		     || (port_allowed(inet_ntoa(cliaddr))))
		    && (ntohs(cliport) > 1023)) 
                {
                    /*
                     *  globus hack added by JB
                     */
#                   if defined(USE_GLOBUS_DATA_CODE)
                    {
                        globus_result_t                   res = GLOBUS_SUCCESS;
                        globus_ftp_control_host_port_t    host_port;
                        unsigned char *                   a;

                        a = (unsigned char *)&cliaddr;
                        host_port.host[0] = (int)a[0];
                        host_port.host[1] = (int)a[1];
                        host_port.host[2] = (int)a[2];
                        host_port.host[3] = (int)a[3];
                        host_port.port = ntohs(cliport);

                        res = globus_ftp_control_local_port(
                                  &g_data_handle,
                                  &host_port);
                        if(res != GLOBUS_SUCCESS)
                        {
                    	    memset(&data_dest, 0, sizeof(data_dest));
		            syslog(LOG_WARNING, "refused PORT %s,%d from %s",
			    inet_ntoa(cliaddr), ntohs(cliport), remoteident);
		            reply(500, "Illegal PORT Command");
     
                            goto globus_port_err;
                        }
                    }
#                   endif
		    usedefault = 0;
		    if (pdata >= 0) 
                    {
			(void) close(pdata);
			pdata = -1;
		    }
		    data_dest.sin_family = AF_INET;
		    data_dest.sin_addr = cliaddr;
		    data_dest.sin_port = cliport;
		    reply(200, "PORT command successful.");
		}
		else 
                {
#endif
 globus_port_err:
		    memset(&data_dest, 0, sizeof(data_dest));
		    syslog(LOG_WARNING, "refused PORT %s,%d from %s",
			   inet_ntoa(cliaddr), ntohs(cliport), remoteident);
		    reply(500, "Illegal PORT Command");
#ifndef DISABLE_PORT
		}
#endif
	    }
	}
    | SPOR check_login host_port_list CRLF
	{
	    if(exit_at == SPOR)
	    {
		dologout(0);
	    }
#if defined(USE_GLOBUS_DATA_CODE)
	    if (log_commands)
		syslog(LOG_INFO, "SPOR");
	    if ($2) 
            {
#ifndef DISABLE_PORT
		globus_list_t * tmp;
		globus_ftp_control_host_port_t * hp;
		int i,size;
		globus_result_t                   res = GLOBUS_SUCCESS;

		tmp = host_port_list;
		size = globus_list_size(tmp);

		hp = globus_libc_malloc(size * 
					sizeof(globus_ftp_control_host_port_t));
		for(i = 0; i < size; i++)
		{
		    memcpy(&hp[i], globus_list_first(tmp), 
			   sizeof(globus_ftp_control_host_port_t));
		    globus_libc_free(globus_list_first(tmp));
		    tmp = globus_list_rest(tmp);
		}
		globus_list_free(host_port_list);
		host_port_list = GLOBUS_NULL;
		

		res = globus_ftp_control_local_spor( &g_data_handle,
						     hp,
						     size);
		globus_libc_free(hp);
		if(res != GLOBUS_SUCCESS)
		{
		    memset(&data_dest, 0, sizeof(data_dest));
		    syslog(LOG_WARNING, "refused SPOR %s,%d from %s",
			   inet_ntoa(cliaddr), ntohs(cliport), remoteident);
		    reply(500, "Illegal SPOR Command");
		}
#endif
	    }
	    usedefault = 0;
	    if (pdata >= 0) 
	    {
		(void) close(pdata);
		pdata = -1;
	    }
	    data_dest.sin_family = AF_INET;
	    data_dest.sin_addr = cliaddr;
	    data_dest.sin_port = cliport;
	    reply(200, "SPOR command successful.");
#endif
	}

    | PASV check_login CRLF
	{
	    if(exit_at == PASV)
	    {
            dologout(0);
	    }
/* Require login for PASV, too.  This actually fixes a bug -- telnet to an
   unfixed wu-ftpd and type PASV first off, and it crashes! */
	    if (log_commands)
		syslog(LOG_INFO, "PASV");
	    if ($2)
#if (defined (DISABLE_PORT) || !defined (DISABLE_PASV))

#               if defined(USE_GLOBUS_DATA_CODE)
                {
                    if(g_delayed_passive)
                    {
                        g_delayed_passive = GLOBUS_FTP_CONTROL_DELAYED_SINGLE_PASSIVE;
                    }
                    
                    g_passive(GLOBUS_FALSE);
                }
#               else
                {
                    passive();
                }
#               endif

#else
		reply(425, "Cannot open passive connection");
#endif
	}
    | SPAS check_login CRLF
	{
	    if(exit_at == SPAS)
	    {
		dologout(0);
	    }
#if defined(USE_GLOBUS_DATA_CODE)
	    if (log_commands)
		syslog(LOG_INFO, "SPAS");
	    if ($2)
#if (defined (DISABLE_PORT) || !defined (DISABLE_PASV))

                {
                    if(g_delayed_passive)
                    {
                        g_delayed_passive = GLOBUS_FTP_CONTROL_DELAYED_STRIPED_PASSIVE;
                    }
                    g_passive(GLOBUS_TRUE);
                }
#else
		reply(425, "Cannot open passive connection");
#endif
#endif
	}
    | PROT SP prot_code CRLF
        {
	    if(exit_at == PROT)
	    {
		dologout(0);
	    }
#ifdef FTP_SECURITY_EXTENSIONS
	    set_prot_level($3);
#endif /* FTP_SECURITY_EXTENSIONS */
#           if USE_GLOBUS_DATA_CODE
	    {
		switch($3)
		{
		  case PROT_C:
		    globus_ftp_control_local_prot(&g_data_handle,
		         GLOBUS_FTP_CONTROL_PROTECTION_CLEAR);
		    break;
		  case PROT_P:
		    globus_ftp_control_local_prot(&g_data_handle,
		         GLOBUS_FTP_CONTROL_PROTECTION_PRIVATE);
                    break;
		  case PROT_S:
		    globus_ftp_control_local_prot(&g_data_handle,
		         GLOBUS_FTP_CONTROL_PROTECTION_SAFE);
		}
	    }
#           endif
	}
	|	CCC CRLF
	{
	    if(exit_at == CCC)
	    {
		dologout(0);
	    }
#ifdef FTP_SECURITY_EXTENSIONS
	    clear_cmd_channel();
#endif /* FTP_SECURITY_EXTENSIONS */
	}
	|	PBSZ SP STRING CRLF
	{
	    if(exit_at == PBSZ)
	    {
		dologout(0);
	    }
#ifdef FTP_SECURITY_EXTENSIONS
	    (void) pbsz($3);
#endif /* FTP_SECURITY_EXTENSIONS */
	}
    | TYPE check_login SP type_code CRLF
	{
	    if(exit_at == TYPE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "TYPE %s", typenames[cmd_type]);
	    if ($2)
		switch (cmd_type) 
                {

		case TYPE_A:
		    if (cmd_form == FORM_N) 
                    {
			reply(200, "Type set to A.");
			type = cmd_type;
			form = cmd_form;
#                       if defined(USE_GLOBUS_DATA_CODE)
                        {
                            globus_ftp_control_local_type(
                                &g_data_handle,
                                GLOBUS_FTP_CONTROL_TYPE_ASCII,
                                0);
                        }
#                       endif
		    }
		    else
                    {
			reply(504, "Form must be N.");
		    }
		    break;

		case TYPE_E:
		    reply(504, "Type E not implemented.");
		    break;

		case TYPE_I:
		    reply(200, "Type set to I.");
		    type = cmd_type;
#                   if defined(USE_GLOBUS_DATA_CODE)
                    {
                        globus_ftp_control_local_type(
                            &g_data_handle,
                            GLOBUS_FTP_CONTROL_TYPE_IMAGE,
                            0);
                    }
#                   endif

		    break;

		case TYPE_L:
#if NBBY == 8
		    if (cmd_bytesz == 8) 
                    {
			reply(200,
			      "Type set to L (byte size 8).");
			type = cmd_type;
		    }
		    else
                    {
			reply(504, "Byte size must be 8.");
		    }
#else /* NBBY == 8 */
#error UNIMPLEMENTED for NBBY != 8
#endif /* NBBY == 8 */
		}
	}
    | STRU check_login SP struct_code CRLF
	{
	    if(exit_at == STRU)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "STRU %s", strunames[$4]);
	    if ($2)
		switch ($4) 
                {

		case STRU_F:
		    reply(200, "STRU F ok.");
		    break;

		default:
		    reply(504, "Unimplemented STRU type.");
		}
	}
    | MODE check_login SP mode_code CRLF
	{
#           if defined(USE_GLOBUS_DATA_CODE)
            globus_result_t                            res;
	    g_send_restart_info = GLOBUS_FALSE;
#           endif
	    
	    if(exit_at == MODE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "MODE %s", modenames[$4]);
	    if ($2)
		switch ($4) {

		case MODE_S:
#                   if defined(USE_GLOBUS_DATA_CODE)
			res = globus_ftp_control_local_mode(
				  &g_data_handle,
				  GLOBUS_FTP_CONTROL_MODE_STREAM);
			if(res == GLOBUS_SUCCESS)
			{
			    g_send_restart_info = GLOBUS_FALSE;
			    mode = $4;
			    reply(200, "MODE S ok.");
			    
			}
			else
			{
			    reply(502, "Failure setting MODE S.");
			}
#		    else
			reply(200, "MODE S ok.");
			mode = $4;
#                   endif
		    break;

#               if defined(USE_GLOBUS_DATA_CODE)

                case MODE_E:
                    res = globus_ftp_control_local_mode(
                              &g_data_handle,
                              GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
                    if(res == GLOBUS_SUCCESS)
                    {
			g_send_restart_info = GLOBUS_TRUE;
			mode = $4;
		        reply(200, "MODE E ok.");
			
                    }
                    else
                    {
		        reply(502, "Failure setting MODE E.");
                    }

                    break;

#               endif

		default:
		    reply(502, "Unimplemented MODE type.");
		}
	}
    | ALLO check_login SP NUMBER CRLF
	{
	    if(exit_at == ALLO)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "ALLO %d", $4);
	    if ($2)
		reply(202, "ALLO command ignored.");
	}
    | ALLO check_login SP NUMBER SP R SP NUMBER CRLF
	{
	    if(exit_at == ALLO)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "ALLO %d R %d", $4, $8);
	    if ($2)
		reply(202, "ALLO command ignored.");
	}
    | RETR check_login SP pathname CRLF
	{
	    if(exit_at == RETR)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "RETR %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4)) {
		retrieve_is_data = 1;

		if(g_delayed_passive == GLOBUS_FTP_CONTROL_DELAYED_SINGLE_PASSIVE)
		{
            g_passive(GLOBUS_FALSE);
        }
        else if( g_delayed_passive == GLOBUS_FTP_CONTROL_DELAYED_STRIPED_PASSIVE)
        {
            g_passive(GLOBUS_TRUE);
        }
                
		retrieve((char *) NULL, $4, -1, -1);
	    }
	    if ($4 != NULL)
		free($4);
	}
    | STOR check_login SP pathname CRLF
	{
	    if(exit_at == STOR)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "STOR %s", CHECKNULL($4));
#ifdef USE_GLOBUS_DATA_CODE
	    if ($2 && $4 != NULL && !restrict_check($4))
	    {
	        if(! globus_fifo_empty(&g_restarts))
		{
		    store($4, "r+", 0, 0);
		}
		else
		{
		    store($4, "w", 0, -1);
		}
	    }
#else
	    if ($2 && $4 != NULL && !restrict_check($4))
		store($4, "w", 0, -1);
#endif
	    if ($4 != NULL)
		free($4);
	}
    | ERET check_login SP eret_mode SP pathname CRLF
	{
	    if(exit_at == ERET)
	    {
		dologout(0);
	    }
#ifdef USE_GLOBUS_DATA_CODE
	    if (log_commands)
	        syslog(
		    LOG_INFO,
		    "ERET %c %" GLOBUS_OFF_T_FORMAT " %" GLOBUS_OFF_T_FORMAT " %s",
		    $4.mode,
		    $4.offset,
		    $4.length,
		    CHECKNULL($6));
#endif
	    if ($2 && $6 != NULL && !restrict_check($6)) {
		retrieve_is_data = 1;
		retrieve((char *) NULL, $6, $4.offset, $4.length);
	    }
	    if ($6 != NULL)
		free($6);
	}
    | ESTO check_login SP esto_mode SP pathname CRLF
        {
	    if(exit_at == ESTO)
	    {
		dologout(0);
	    }
#ifdef USE_GLOBUS_DATA_CODE
	    if (log_commands)
		syslog(
		    LOG_INFO,
		    "ESTO %c %" GLOBUS_OFF_T_FORMAT " %s",
		    $4.mode,
		    $4.offset,
		    CHECKNULL($6));
#endif
	    if ($2 && $6 != NULL && !restrict_check($6))
		store($6, "r+", 0, $4.offset);
	    if ($6 != NULL)
		free($6);
	}
    | APPE check_login SP pathname CRLF
	{
	    if(exit_at == APPE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "APPE %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		store($4, "a", 0, -1);
	    if ($4 != NULL)
		free($4);
	}
    | NLST check_login CRLF
	{
	    if(exit_at == NLST)
	    {
		dologout(0);
	    }
#if USE_GLOBUS_DATA_CODE
	    if (log_commands)
		syslog(LOG_INFO, "NLST");
	    if ($2 && !restrict_check(".")) 
            {
		retrieve_is_data = 0;
#ifndef INTERNAL_LS
                retrieve("/bin/ls -c1", "", -1, -1);
#else
		ls(NULL, 0);
#endif
            }
#else
	    if (log_commands)
		syslog(LOG_INFO, "NLST");
	    if ($2 && !restrict_check("."))
		send_file_list("");
#endif
	}
    | NLST check_login SP STRING CRLF
	{

	    if(exit_at == NLST)
	    {
		dologout(0);
	    }
#if USE_GLOBUS_DATA_CODE
	    if (log_commands)
		syslog(LOG_INFO, "NLST %s", $4);
	    if ($2 && $4 && !restrict_check($4))
            {
		retrieve_is_data = 0;
#ifndef INTERNAL_LS
                retrieve("/bin/ls -c1 %s", $4, -1, -1);
#else
		ls($4, 0);
#endif
            }
#else /* USE_GLOBUS_DATA_CODE */
        if (log_commands)
        syslog(LOG_INFO, "NLST %s", $4);
	    if ($2 && $4 && !restrict_check($4))
		send_file_list($4);
	    if ($4 != NULL)
		free($4);
#endif
	}
    | MLST check_login CRLF
            {
            if(exit_at == MLST)
            {
                dologout(0);
            }
            if(log_commands)
                syslog(LOG_INFO, "MLST");
            if($2 && !restrict_check("."))
            {
                mlst(NULL);
            }
        }
        
    | MLST check_login SP pathname CRLF
            {
            if(exit_at == MLST)
            {
                dologout(0);
            }
            if (log_commands)
                syslog(LOG_INFO, "MLST %s", CHECKNULL($4));
            if($2 && $4 && !restrict_check($4))
            {
                mlst($4);
            }
            if($4 != NULL)
                free($4);
        }
        
    | MLSD check_login CRLF
            {
            if(exit_at == MLSD)
            {
                dologout(0);
            }
            if(log_commands)
                syslog(LOG_INFO, "MLSD");
            if($2 && !restrict_check("."))
            {
                retrieve_is_data = 0;
                mlsd(NULL);
            }
        }
        
    | MLSD check_login SP pathname CRLF
          {
        if(exit_at == MLSD)
            {
                dologout(0);
            }
            if (log_commands)
                syslog(LOG_INFO, "MLSD %s", CHECKNULL($4));
            if($2 && $4 && !restrict_list_check($4))
            {
                retrieve_is_data = 0;
                mlsd($4);
            }
            if($4 != NULL)
                free($4);
        }

    | LIST check_login CRLF
	{
	    if(exit_at == LIST)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "LIST");
	    if ($2 && !restrict_check(".")) {
		retrieve_is_data = 0;
#ifndef INTERNAL_LS
		if (anonymous && dolreplies)
		    retrieve(ls_long, "", -1, -1);
		else
		    retrieve(ls_short, "", -1, -1);
#else
		ls(NULL, 0);
#endif
	    }
	}

    | LIST check_login SP pathname CRLF
	{
	    if(exit_at == LIST)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "LIST %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_list_check($4)) {
		retrieve_is_data = 0;
#ifndef INTERNAL_LS
		if (anonymous && dolreplies)
		    retrieve(ls_long, $4, -1, -1);
		else
		    retrieve(ls_short, $4, -1, -1);
#else
		ls($4, 0);
#endif
	    }
	    if ($4 != NULL)
		free($4);
	}
    | STAT_CMD check_login SP pathname CRLF
	{
	    if(exit_at == STAT_CMD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "STAT %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		statfilecmd($4);
	    if ($4 != NULL)
		free($4);
	}
    | STAT_CMD check_login CRLF
	{
	    if(exit_at == STAT_CMD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "STAT");
	    if ($2)
		statcmd();
	}
    | DELE check_login SP pathname CRLF
	{
	    if(exit_at == DELE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "DELE %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		delete($4);
	    if ($4 != NULL)
		free($4);
	}
    | RNTO check_login SP pathname CRLF
	{
	    if(exit_at == RNTO)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "RNTO %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4)) {
		if (fromname) {
		    renamecmd(fromname, $4);
		    free(fromname);
		    fromname = (char *) NULL;
		}
		else {
		    reply(503, "Bad sequence of commands.");
		}
	    }
	    if ($4)
		free($4);
	}
    | ABOR check_login CRLF
	{
	    if(exit_at == ABOR)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "ABOR");
	    if ($2)
		reply(225, "ABOR command successful.");
	}
    | CWD check_login CRLF
	{
	    if(exit_at == CWD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "CWD");
	    if ($2 && !restrict_check(home))
		cwd(home);
	}
    | CWD check_login SP pathname CRLF
	{
	    if(exit_at == CWD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "CWD %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		cwd($4);
	    if ($4 != NULL)
		free($4);
	}
    | HELP check_login CRLF
	{
	    if(exit_at == HELP)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "HELP");
	    if ($2)
		help(cmdtab, (char *) NULL);
	}
    | HELP check_login SP STRING CRLF
	{
	    register char *cp = (char *) $4;

	    if(exit_at == HELP)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "HELP %s", $4);
	    if ($2)
		if (strncasecmp(cp, "SITE", 4) == 0) {
		    cp = (char *) $4 + 4;
		    if (*cp == ' ')
			cp++;
		    if (*cp)
			help(sitetab, cp);
		    else
			help(sitetab, (char *) NULL);
		}
		else
		    help(cmdtab, $4);
	    if ($4 != NULL)
		free($4);
	}
    | FEAT check_login CRLF
	{
	    if(exit_at == FEAT)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "FEAT");
	    if ($2)
		feat(feattab);
	}
    | DCAU check_login SP STRING CRLF
        {
	    if(exit_at == DCAU)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "DCAU");
	    if($2)
	    {
#               if defined(USE_GLOBUS_DATA_CODE)
                {
		    globus_result_t                            res;
		    globus_bool_t             bad_arg = GLOBUS_FALSE;
		    if(g_dcau.mode == GLOBUS_FTP_CONTROL_DCAU_SUBJECT)
		    {
			globus_libc_free(g_dcau.subject.subject);
		    }
		    if($4[0] == 'N')
		    {
			g_dcau.mode = GLOBUS_FTP_CONTROL_DCAU_NONE;
		    }
		    else if($4[0] == 'A')
		    {
			g_dcau.mode = GLOBUS_FTP_CONTROL_DCAU_SELF;
		    }
		    else if($4[0] == 'S')
		    {
			g_dcau.mode = GLOBUS_FTP_CONTROL_DCAU_SUBJECT;
			g_dcau.subject.subject = globus_libc_strdup($4+2);
		    }
		    else
		    {
		        bad_arg = GLOBUS_TRUE;
		        reply(504, "Bad DCAU mode");
		    }
		    
		    if(!bad_arg)
		    {
        		res = globus_ftp_control_local_dcau(&g_data_handle,
        		                                    &g_dcau,
                                                            g_deleg_cred);
        		if(res != GLOBUS_SUCCESS)
        		{
        		    reply(432, "Data channel authentication failed");
        		}
        		else
        		{
        		    reply(200, "DCAU %c", $4[0]);
        		}
        	    }
        		    
                }
#               endif
	    }
	}
    | NOOP check_login CRLF
	{
	    if(exit_at == NOOP)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "NOOP");
	    if ($2)
		reply(200, "NOOP command successful.");
	}
    | MKD check_login SP pathname CRLF
	{
	    if(exit_at == MKD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "MKD %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		makedir($4);
	    if ($4 != NULL)
		free($4);
	}
    | RMD check_login SP pathname CRLF
	{
	    if(exit_at == RMD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "RMD %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		removedir($4);
	    if ($4 != NULL)
		free($4);
	}
    | PWD check_login CRLF
	{
	    if(exit_at == PWD)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "PWD");
	    if ($2)
		pwd();
	}
    | CDUP check_login CRLF
	{
	    if(exit_at == CDUP)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "CDUP");
	    if ($2)
		if (!test_restriction(".."))
		    cwd("..");
		else
		    ack("CWD");
	}
    | SITE check_login SP PSIZE SP bufsize CRLF
	{
#if defined(STRIPED_SERVER_BACKEND)
            g_striped_file_size = $6;
            reply(200, "PSIZE command received.");
#else
            reply(200, "PSIZE command not understood.");
#endif
	}
    | SITE check_login SP HELP CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE HELP");
	    if ($2)
		help(sitetab, (char *) NULL);
	}
    | SITE check_login SP HELP SP STRING CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE HELP %s", $6);
	    if ($2)
		help(sitetab, $6);
	    if ($6 != NULL)
		free($6);
	}
    | SITE check_login SP UMASK CRLF
	{
	    mode_t oldmask;

	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE UMASK");
	    if ($2) {
		oldmask = umask(0);
		(void) umask(oldmask);
		reply(200, "Current UMASK is %03o", oldmask);
	    }
	}
    | SITE check_login SP UMASK SP octal_number CRLF
	{
	    mode_t oldmask;
	    struct aclmember *entry = NULL;
	    int ok = 1;

	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE UMASK %03o", $6);
	    if ($2) {
		/* check for umask permission */
		while (getaclentry("umask", &entry) && ARG0 && ARG1 != NULL) {
		    if (type_match(ARG1))
			if (*ARG0 == 'n')
			    ok = 0;
		}
		if (ok && !restricted_user) {
		    if (($6 < 0) || ($6 > 0777)) {
			reply(501, "Bad UMASK value");
		    }
		    else {
			oldmask = umask((mode_t) $6);
			reply(200, "UMASK set to %03o (was %03o)", $6, oldmask);
		    }
		}
		else
		    reply(553, "Permission denied on server. (umask)");
	    }
	}
    | SITE check_login SP CHMOD SP octal_number SP pathname CRLF
	{
	    struct aclmember *entry = NULL;
	    int ok = (anonymous ? 0 : 1);

	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHMOD %03o %s", $6, CHECKNULL($8));
	    if ($2 && $8) {
		/* check for chmod permission */
		while (getaclentry("chmod", &entry) && ARG0 && ARG1 != NULL) {
		    if (type_match(ARG1))
			if (anonymous) {
			    if (*ARG0 == 'y')
				ok = 1;
			}
			else if (*ARG0 == 'n')
			    ok = 0;
		}
		if (ok) {
#ifdef UNRESTRICTED_CHMOD
		    if (chmod($8, (mode_t) $6) < 0)
#else
		    if (($6 < 0) || ($6 > 0777))
			reply(501,
			    "CHMOD: Mode value must be between 0 and 0777");
		    else if (chmod($8, (mode_t) $6) < 0)
#endif
			perror_reply(550, $8);
		    else {
			char path[MAXPATHLEN];

			wu_realpath($8, path, chroot_path);

			if (log_security)
			    if (anonymous) {
				syslog(LOG_NOTICE, "%s of %s changed permissions for %s", guestpw, remoteident, path);
			    }
			    else {
				syslog(LOG_NOTICE, "%s of %s changed permissions for %s", pw->pw_name,
				       remoteident, path);
			    }
			reply(200, "CHMOD command successful.");
		    }
		}
		else
		    reply(553, "Permission denied on server. (chmod)");
	    }
	    if ($8 != NULL)
		free($8);
	}
    | SITE check_login SP IDLE CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE IDLE");
	    if ($2)
		reply(200,
		      "Current IDLE time limit is %d seconds; max %d",
		      timeout_idle, timeout_maxidle);
	}
    | SITE check_login SP IDLE SP NUMBER CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE IDLE %d", $6);
	    if ($2)
		if ($6 < 30 || $6 > timeout_maxidle) {
		    reply(501,
		      "Maximum IDLE time must be between 30 and %d seconds",
			  timeout_maxidle);
		}
		else {
		    timeout_idle = $6;
		    reply(200, "Maximum IDLE time set to %d seconds", timeout_idle);
		}
	}
    | SITE check_login SP GROUP SP username CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
#ifndef NO_PRIVATE
	    if (log_commands)
		syslog(LOG_INFO, "SITE GROUP %s", $6);
	    if (!restricted_user && $2 && $6)
		priv_group($6);
	    free($6);
#endif /* !NO_PRIVATE */
	}
    | SITE check_login SP GPASS SP password CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
#ifndef NO_PRIVATE
	    if (log_commands)
		syslog(LOG_INFO, "SITE GPASS password");
	    if (!restricted_user && $2 && $6)
		priv_gpass($6);
	    free($6);
#endif /* !NO_PRIVATE */
	}
    | SITE check_login SP GPASS CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
#ifndef NO_PRIVATE
	    if (log_commands)
		syslog(LOG_INFO, "SITE GPASS");
	    if (!restricted_user && $2)
		priv_gpass(NULL);
#endif /* !NO_PRIVATE */
	}
    | SITE check_login SP NEWER SP STRING CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE NEWER %s", $6);
#ifdef SITE_NEWER
	    if ($2 && $6 && !restrict_check("."))
		newer($6, ".", 0);
#else
	    reply(500, "Command no longer honored by this server");
#endif
	    free($6);
	}
    | SITE check_login SP NEWER SP STRING SP pathname CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE NEWER %s %s", $6,
		       CHECKNULL($8));
#ifdef SITE_NEWER
	    if ($2 && $6 && $8 && !restrict_check($8))
		newer($6, $8, 0);
#else
	    reply(500, "Command no longer honored by this server");
#endif
	    free($6);
	    if ($8)
		free($8);
	}
    | SITE check_login SP MINFO SP STRING CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE MINFO %s", $6);
#ifdef SITE_NEWER
	    if ($2 && $6 && !restrict_check("."))
		newer($6, ".", 1);
#else
	    reply(500, "Command no longer honored by this server");
#endif
	    free($6);
	}
    | SITE check_login SP MINFO SP STRING SP pathname CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE MINFO %s %s", $6,
		       CHECKNULL($8));
#ifdef SITE_NEWER
	    if ($2 && $6 && $8 && !restrict_check($8))
		newer($6, $8, 1);
#else
	    reply(500, "Command no longer honored by this server");
#endif
	    free($6);
	    if ($8)
		free($8);
	}
    | SITE check_login SP INDEX SP STRING CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    /* this is just for backward compatibility since we
	     * thought of INDEX before we thought of EXEC
	     */
	    if (!restricted_user && $2 != 0 && $6 != NULL) {
		char buf[MAXPATHLEN];
		if (strlen($6) + 7 <= sizeof(buf)) {
		    sprintf(buf, "index %s", (char *) $6);
		    (void) site_exec(buf);
		}
	    }
	    if ($6 != NULL)
		free($6);
	}
    | SITE check_login SP EXEC SP STRING CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (!restricted_user && $2 != 0 && $6 != NULL) {
		(void) site_exec((char *) $6);
	    }
	    if ($6 != NULL)
		free($6);
	}

    | STOU check_login SP pathname CRLF
	{
	    if(exit_at == STOU)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "STOU %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4))
		store($4, "w", 1, -1);
	    if ($4 != NULL)
		free($4);
	}
    | SYST check_login CRLF
	{
	    if(exit_at == SYST)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SYST");
	    if ($2)
#ifdef BSD
		reply(215, "UNIX Type: L%d Version: BSD-%d",
		      NBBY, BSD);
#else /* BSD */
#if defined (unix) || defined (__unix__)
		reply(215, "UNIX Type: L%d", NBBY);
#else /* unix */
		reply(215, "UNKNOWN Type: L%d", NBBY);
#endif /* unix */
#endif /* BSD */
	}

	/*
	 * SIZE is not in RFC959, but Postel has blessed it and
	 * it will be in the updated RFC.
	 *
	 * Return size of file in a format suitable for
	 * using with RESTART (we just count bytes).
	 */
    | SIZE check_login SP pathname CRLF
	{
	    if(exit_at == SIZE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SIZE %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4)) 
            {
#               if defined(STRIPED_SERVER_BACKEND)
                {
                    stripd_server_size($4);
                }
#               else
                {
		    sizecmd($4);
                }
#               endif
	    }
	    if ($4 != NULL)
		free($4);
	}


        /*
         * CKSM*
         */
    | CKSM check_login SP STRING SP OFFSET SP LENGTH SP pathname CRLF
        {
            if(exit_at == CKSM)
            {   
                dologout(0);
            }
            if (log_commands)
                syslog(LOG_INFO, "CKSM %s", CHECKNULL($10)); 
            if (!restrict_check($10))
            {
                cksmcmd($10,$4,$6,$8);
            }
            else
            {
                reply(550, "Cannot access %s", $10);
            }
            if ($10 != NULL)
                free($10);
        }
	/*
	 * MDTM is not in RFC959, but Postel has blessed it and
	 * it will be in the updated RFC.
	 *
	 * Return modification time of file as an ISO 3307
	 * style time. E.g. YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx
	 * where xxx is the fractional second (of any precision,
	 * not necessarily 3 digits)
	 */
    | MDTM check_login SP pathname CRLF
	{
	    if(exit_at == MDTM)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "MDTM %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4)) {
		struct stat stbuf;

		if (stat($4, &stbuf) < 0)
		    perror_reply(550, $4);
		else if ((stbuf.st_mode & S_IFMT) != S_IFREG) {
		    reply(550, "%s: not a plain file.",
			  $4);
		}
		else {
		    register struct tm *t;
		    t = gmtime(&stbuf.st_mtime);
		    reply(213,
			  "%04d%02d%02d%02d%02d%02d",
			  t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
			  t->tm_hour, t->tm_min, t->tm_sec);
		}
	    }
	    if ($4 != NULL)
		free($4);
	}
    |	AUTH SP STRING CRLF
    {
	    if(exit_at == AUTH)
	    {
		dologout(0);
	    }
#ifdef FTP_SECURITY_EXTENSIONS
	auth((char *) $3);
#endif /* FTP_SECURITY_EXTENSIONS */
    }
    |	ADAT SP STRING CRLF
    {
	    if(exit_at == ADAT)
	    {
		dologout(0);
	    }
#ifdef FTP_SECURITY_EXTENSIONS 
	auth_data((char *) $3);
#endif /* FTP_SECURITY_EXTENSIONS */
	free((char *) $3);
    }
    | OPTS check_login opts CRLF
    {
	reply(200, "Opts successful.");
    }
    | QUIT CRLF
	{
	    if(exit_at == QUIT)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "QUIT");
#ifdef TRANSFER_COUNT
	    if (logged_in) {
		lreply(221, "You have transferred %d bytes in %d files.", data_count_total, file_count_total);
		lreply(221, "Total traffic for this session was %d bytes in %d transfers.", byte_count_total, xfer_count_total);
		lreply(221, "Thank you for using the FTP service on %s.", hostname);
	    }
#endif /* TRANSFER_COUNT */
	    reply(221, "Goodbye.");
	    dologout(0);
	}
    | error CRLF
	{
	    yyerrok;
	}
    ;

rcmd: RNFR check_login SP pathname CRLF
	{

	    if(exit_at == RNFR)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "RNFR %s", CHECKNULL($4));
	    if ($2) {
		restart_point = (off_t) 0;
#               if USE_GLOBUS_DATA_CODE
		globus_i_wu_free_ranges(&g_restarts);
#               endif
	    }
	    if ($2 && $4 && !restrict_check($4)) {
		fromname = renamefrom($4);
	    }
	    if (fromname == 0 && $4)
		free($4);
	}
    | REST check_login SP byte_size CRLF
	{
	    if(exit_at == REST)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "REST %d", (int) $4);
	    if ($2)
	    {
#           if USE_GLOBUS_DATA_CODE
		if(mode == MODE_E)
		{
		    fromname = 0;
		    restart_point = $4;
		    globus_i_wu_free_ranges(&g_restarts);
		    reply(550, "Invalid MODE E restart Marker");
		}
	    else
#           endif
		{
		    fromname = 0;
		    restart_point = $4;
		    reply(350, "Restarting at %ld. %s", (long) restart_point,
			  "Send STORE or RETRIEVE to initiate transfer.");
		}
	    }
	}
    | REST check_login SP byte_range_list CRLF
	{
#       if USE_GLOBUS_DATA_CODE
	    if(exit_at == REST)
	    {
		dologout(0);
	    }
	    if(log_commands)
	        syslog(LOG_INFO, "REST [byte ranges]");
	    if ($2) {
		fromname = 0;
		restart_point = 0;

		if(mode == MODE_S)
		{
		    reply(550, "Invalid MODE S restart Marker");
		    globus_i_wu_free_ranges(&g_restarts);
		}
		else
		{
		    reply(350, 
			  "Restart Marker OK. "
			  "Send STORE or RETRIEVE to initiate transfer.");
		}
	    }
#       else
	    if(log_commands)
	        syslog(LOG_INFO, "REST [byte ranges] (invalid)");
	    reply(500, "'REST': invalid restart offset.");

#	endif
	}
    | SITE check_login SP ALIAS CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE ALIAS");
	    if ($2)
		alias((char *) NULL);
	}
    | SITE check_login SP ALIAS SP STRING CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE ALIAS %s", $6);
	    if ($2)
		alias($6);
	    if ($6 != NULL)
		free($6);
	}
    | SITE check_login SP GROUPS CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE GROUPS");
	    if ($2)
		print_groups();
	}
    | SITE check_login SP CDPATH CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE CDPATH");
	    if ($2)
		cdpath();
	}
    | SITE check_login SP CHECKMETHOD SP method CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKMETHOD %s", CHECKNULL($6));
	    if (($2) && ($6 != NULL))
		SetCheckMethod($6);
	    if ($6 != NULL)
		free($6);
	}
    | SITE check_login SP CHECKMETHOD CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKMETHOD");
	    if ($2)
		ShowCheckMethod();
	}
    | SITE check_login SP CHECKSUM SP pathname CRLF
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKSUM %s", CHECKNULL($6));
	    if (($2) && ($6 != NULL) && (!restrict_check($6)))
		CheckSum($6);
	    if ($6 != NULL)
		free($6);
	}
    | SITE check_login SP CHECKSUM CRLF
	   {
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKSUM");
	    if ($2)
		CheckSumLastFile();
	}
    | SITE check_login SP BUFSIZE CRLF   
	{
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
	    if (log_commands) syslog(LOG_INFO, "SITE BUFSIZE");
	    print_bufsize ();
 	}
    | SITE check_login SP BUFSIZE SP bufsize CRLF
	{	
	    int size = $6;
	    if(exit_at == SITE)
	    {
		dologout(0);
	    }
 
	    if (log_commands) syslog(LOG_INFO, "SITE BUFSIZE %d", size);
	    set_bufsize (size);
	}
    | SITE check_login SP FAULT SP STRING CRLF
        {
	    struct tab * cmd;

	    if (log_commands)
		syslog(LOG_INFO, "SITE FAULT %s", $6);
	    if ($2)
	    {
	        cmd = lookup(cmdtab, $6);
		if(cmd)
		{
		    exit_at = cmd->token;
	  	    reply(200, "FAULT %s command accepted.", $6);
	        }
		else
		{
		    reply(500, "Invalid SITE FAULT command.");
		}
	    }
	    if ($6 != NULL)
		free($6);
	}
    ;
        
username: STRING
    ;

password: /* empty */
	{
	    $$ = (char *) malloc(1);
	    $$[0] = '\0';
	}
    | STRING
    ;

byte_size: NUMBER
    ;

opts: 
    SP MLST SP STRING
    {
        mlsx_options($4);
    }
    |
    SP MLST
    {
        mlsx_options(NULL);
    }
    |
    SP RETR SP retr_option_list 
    ;

byte_range_list:
    byte_range COMMA byte_range_list
    | byte_range 
    ;
byte_range:
    NUMBER HYPHEN NUMBER
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    globus_i_wu_insert_range(&g_restarts,
				     (globus_size_t) $1,
				     (globus_size_t) ($3-$1));
	}
#       endif
    }
    ;

retr_option_list: 
    retr_option retr_option_list
    | retr_option
    ;

retr_option:
    STRIPELAYOUT EQUALS PARTITIONED SEMICOLON
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    g_layout.mode = GLOBUS_FTP_CONTROL_STRIPING_PARTITIONED;
	}
#       endif
    }
    | STRIPELAYOUT EQUALS BLOCKED SEMICOLON
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    g_layout.mode = GLOBUS_FTP_CONTROL_STRIPING_BLOCKED_ROUND_ROBIN;
	}
#       endif
    }
    | BLOCKSIZE EQUALS NUMBER SEMICOLON
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    g_layout.round_robin.block_size = $3;
	}
#       endif
    }
    | DELAYED_PASV EQUALS NUMBER SEMICOLON
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    g_delayed_passive = $3;
	}
#       endif
    }
    | PARALLELISM EQUALS NUMBER COMMA NUMBER COMMA NUMBER SEMICOLON
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    g_parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
	    g_parallelism.fixed.size = $3;
	}
#       endif
    }
    ;
host_port_list:
    SP host_port host_port_list
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    globus_ftp_control_host_port_t * host_port;
	    unsigned char * a;
	    
	    host_port = globus_libc_malloc(sizeof(globus_ftp_control_host_port_t));
	    a = (unsigned char*) &$2.addr;
	    
	    host_port->host[0] = (int)a[0];
	    host_port->host[1] = (int)a[1];
	    host_port->host[2] = (int)a[2];
	    host_port->host[3] = (int)a[3];
	    host_port->port = ntohs($2.port);
	    
	    globus_list_insert(&host_port_list, host_port);
	}
#       endif
    }
    | SP host_port
    {
#       if USE_GLOBUS_DATA_CODE
	{
	    globus_ftp_control_host_port_t * host_port;
	    unsigned char * a;
	    
	    host_port_list = NULL;
	    
	    host_port = globus_libc_malloc(sizeof(globus_ftp_control_host_port_t));
	    a = (unsigned char *) &$2.addr;
	    
	    host_port->host[0] = (int)a[0];
	    host_port->host[1] = (int)a[1];
	    host_port->host[2] = (int)a[2];
	    host_port->host[3] = (int)a[3];
	    host_port->port = ntohs($2.port);
	    
	    globus_list_insert(&host_port_list, host_port);
	}
#       endif
    }
    ;

host_port: NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER
	{
	    register char *a, *p;
		   
	    a = (char *) &cliaddr;
	    a[0] = $1;
	    a[1] = $3;
	    a[2] = $5;
	    a[3] = $7;
	    p = (char *) &cliport;
	    p[0] = $9;
	    p[1] = $11;

	    $$.addr = cliaddr;
	    $$.port = cliport;
	}
    ;

form_code: N
	{
	    $$ = FORM_N;
	}
    | T
	{
	    $$ = FORM_T;
	}
    | C
	{
	    $$ = FORM_C;
	}
    ;

prot_code:	C
	{
#ifdef FTP_SECURITY_EXTENSIONS
		$$ = PROT_C;
#endif /* FTP_SECURITY_EXTENSIONS */
	}
	|	S
	{
#ifdef FTP_SECURITY_EXTENSIONS
		$$ = PROT_S;
#endif /* FTP_SECURITY_EXTENSIONS */
	}
	|	P
	{
#ifdef FTP_SECURITY_EXTENSIONS
		$$ = PROT_P;
#endif /* FTP_SECURITY_EXTENSIONS */
	}
	|	E
	{
#ifdef FTP_SECURITY_EXTENSIONS
		$$ = PROT_E;
#endif /* FTP_SECURITY_EXTENSIONS */
	}
	;

type_code: A
	{
	    cmd_type = TYPE_A;
	    cmd_form = FORM_N;
	}
    | A SP form_code
	{
	    cmd_type = TYPE_A;
	    cmd_form = $3;
	}
    | E
	{
	    cmd_type = TYPE_E;
	    cmd_form = FORM_N;
	}
    | E SP form_code
	{
	    cmd_type = TYPE_E;
	    cmd_form = $3;
	}
    | I
	{
	    cmd_type = TYPE_I;
	}
    | L
	{
	    cmd_type = TYPE_L;
	    cmd_bytesz = NBBY;
	}
    | L SP byte_size
	{
	    cmd_type = TYPE_L;
	    cmd_bytesz = $3;
	}
    /* this is for a bug in the BBN ftp */
    | L byte_size
	{
	    cmd_type = TYPE_L;
	    cmd_bytesz = $2;
	}
    ;

struct_code: F
	{
	    $$ = STRU_F;
	}
    | R
	{
	    $$ = STRU_R;
	}
    | P
	{
	    $$ = STRU_P;
	}
    ;

mode_code:  S
	{
	    $$ = MODE_S;
	}
    | E
	{
	    $$ = MODE_E;
	}
    | B
	{
	    $$ = MODE_B;
	}
    | C
	{
	    $$ = MODE_C;
	}
    ;

pathname: pathstring
	{
	    /*
	     * Problem: this production is used for all pathname
	     * processing, but only gives a 550 error reply.
	     * This is a valid reply in some cases but not in others.
	     */
	    if (restricted_user && logged_in && $1 && strncmp($1, "/", 1) == 0) {
		/*
		 * This remaps the root so it is appearently at the user's home
		 * rather than the real root/chroot.
		 */
		char **globlist;
		char *t = calloc(1 + strlen($1) + 1, sizeof(char));
		if (t == NULL) {
		    errno = EAGAIN;
		    perror_reply(550, $1);
		    $$ = NULL;
		}
		else {
		    t[0] = '~';
		    t[1] = '\0';
		    if (strncmp($1, "/../", 4) == 0)
			strcpy(t + 1, $1 + 3);
		    else if (strcmp($1, "/..") != 0)
			strcpy(t + 1, $1);
		    globlist = ftpglob(t);
		    if (globerr) {
			reply(550, "%s", globerr);
			$$ = NULL;
			if (globlist) {
			    blkfree(globlist);
			    free((char *) globlist);
			}
		    }
		    else if (globlist && *globlist) {
			$$ = *globlist;
			blkfree(&globlist[1]);
			free((char *) globlist);
		    }
		    else {
			if (globlist) {
			    blkfree(globlist);
			    free((char *) globlist);
			}
			errno = ENOENT;
			perror_reply(550, $1);
			$$ = NULL;
		    }
		    free(t);
		}
		free($1);
	    }
	    else if (logged_in && $1 && strncmp($1, "~", 1) == 0) {
		char **globlist;

		globlist = ftpglob($1);
		if (globerr) {
		    reply(550, "%s", globerr);
		    $$ = NULL;
		    if (globlist) {
			blkfree(globlist);
			free((char *) globlist);
		    }
		}
		else if (globlist && *globlist) {
		    $$ = *globlist;
		    blkfree(&globlist[1]);
		    free((char *) globlist);
		}
		else {
		    if (globlist) {
			blkfree(globlist);
			free((char *) globlist);
		    }
		    errno = ENOENT;
		    perror_reply(550, $1);
		    $$ = NULL;
		}
		free($1);
	    }
	    else
		$$ = $1;
	}
    ;

pathstring: STRING
    ;

method: STRING
    ;

octal_number: NUMBER
	{
	    register int ret, dec, multby, digit;

	    /*
	     * Convert a number that was read as decimal number
	     * to what it would be if it had been read as octal.
	     */
	    dec = $1;
	    multby = 1;
	    ret = 0;
	    while (dec) {
		digit = dec % 10;
		if (digit > 7) {
		    ret = -1;
		    break;
		}
		ret += digit * multby;
		multby *= 8;
		dec /= 10;
	    }
	    $$ = ret;
	}
    ;

check_login: /* empty */
	{
	    if (logged_in)
		$$ = 1;
	    else {
		if (log_commands)
		    syslog(LOG_INFO, "cmd failure - not logged in");
		reply(530, "Please login with USER and PASS.");
		$$ = 0;
		yyerrorcalled = 1;
	    }
	}
    ;

bufsize: NUMBER
    ;

esto_mode: A SP OFFSET
    {
	$$.mode = 'A';
	$$.offset = $3;
    }
    ;

eret_mode: P SP OFFSET SP LENGTH
    {
	$$.mode = 'P';
	$$.offset = $3;
	$$.length = $5;
    }
    ;

OFFSET: BIGNUM
    ;
LENGTH: BIGNUM
    ;
%%

extern jmp_buf errcatch;

#define CMD 0			/* beginning of command */
#define ARGS    1		/* expect miscellaneous arguments */
#define STR1    2		/* expect SP followed by STRING */
#define STR2    3		/* expect STRING */
#define OSTR    4		/* optional SP then STRING */
#define ZSTR1   5		/* SP then optional STRING */
#define ZSTR2   6		/* optional STRING after SP */
#define SITECMD 7		/* SITE command */
#define NSTR    8		/* Number followed by a string */
#define STR3    9		/* expect STRING followed by optional SP then STRING */

#define ESTOARGS 10		/* SP CHAR SP NUMBER SP STRING */
#define EARGS1 11		/* CHAR SP NUMBER SP STRING */
#define ERETARGS 12		/* SP CHAR SP NUMBER SP NUMBER SP STRING */
#define EARGS2 13		/* CHAR SP NUMBER SP NUMBER SP STRING */
#define EARGS3 14		/* SP NUMBER SP NUMBER SP STRING */
#define EARGS4 15		/* NUMBER SP NUMBER SP STRING */
#define EARGS5 17		/* SP NUMBER SP STRING */
#define EARGS6 18		/* NUMBER SP STRING */
#define NEWARGS 19		/* miscellaneous word/number
				 * arguments, with punctuation */
#define OPTSARGS 20             /* a command token, followed by newargs */
#define CKSMARGS 21		/* SP STRING SP optional OFFSET SP 
				   optional LENGTH SP STRING */
#define CARGS1 22
#define CARGS2 23
#define CARGS3 24
#define CARGS4 25
#define CARGS5 26
#define CARGS6 27

struct tab cmdtab[] =
{				/* In order defined in RFC 765 */
    {"USER", USER, STR1, 1, "<sp> username"},
    {"PASS", PASS, ZSTR1, 1, "<sp> password"},
    {"ACCT", ACCT, STR1, 0, "(specify account)"},
    {"SMNT", SMNT, ARGS, 0, "(structure mount)"},
    {"REIN", REIN, ARGS, 0, "(reinitialize server state)"},
    {"QUIT", QUIT, ARGS, 1, "(terminate service)",},
    {"PORT", PORT, ARGS, 1, "<sp> b0, b1, b2, b3, b4, b5"},
    {"PASV", PASV, ARGS, 1, "(set server in passive mode)"},
    {"TYPE", TYPE, ARGS, 1, "<sp> [ A | E | I | L ]"},
    {"STRU", STRU, ARGS, 1, "(specify file structure)"},
    {"MODE", MODE, ARGS, 1, "(specify transfer mode)"},
    {"RETR", RETR, STR1, 1, "<sp> file-name"},
    {"STOR", STOR, STR1, 1, "<sp> file-name"},
    {"APPE", APPE, STR1, 1, "<sp> file-name"},
    {"MLFL", MLFL, OSTR, 0, "(mail file)"},
    {"MAIL", MAIL, OSTR, 0, "(mail to user)"},
    {"MSND", MSND, OSTR, 0, "(mail send to terminal)"},
    {"MSOM", MSOM, OSTR, 0, "(mail send to terminal or mailbox)"},
    {"MSAM", MSAM, OSTR, 0, "(mail send to terminal and mailbox)"},
    {"MRSQ", MRSQ, OSTR, 0, "(mail recipient scheme question)"},
    {"MRCP", MRCP, STR1, 0, "(mail recipient)"},
    {"ALLO", ALLO, ARGS, 1, "allocate storage (vacuously)"},
    {"REST", REST, NEWARGS, 1, "(restart command)"},
    {"RNFR", RNFR, STR1, 1, "<sp> file-name"},
    {"RNTO", RNTO, STR1, 1, "<sp> file-name"},
    {"ABOR", ABOR, ARGS, 1, "(abort operation)"},
    {"DELE", DELE, STR1, 1, "<sp> file-name"},
    {"CWD", CWD, OSTR, 1, "[ <sp> directory-name ]"},
    {"XCWD", CWD, OSTR, 1, "[ <sp> directory-name ]"},
    {"LIST", LIST, OSTR, 1, "[ <sp> path-name ]"},
    {"MLSD", MLSD, OSTR, 1, "[ <sp> path-name ]"},
    {"MLST", MLST, OSTR, 1, "[ <sp> path-name ]"},
    {"NLST", NLST, OSTR, 1, "[ <sp> path-name ]"},
    {"SITE", SITE, SITECMD, 1, "site-cmd [ <sp> arguments ]"},
    {"SYST", SYST, ARGS, 1, "(get type of operating system)"},
    {"STAT", STAT_CMD, OSTR, 1, "[ <sp> path-name ]"},
    {"HELP", HELP, OSTR, 1, "[ <sp> <string> ]"},
    {"NOOP", NOOP, ARGS, 1, ""},
    {"MKD", MKD, STR1, 1, "<sp> path-name"},
    {"XMKD", MKD, STR1, 1, "<sp> path-name"},
    {"RMD", RMD, STR1, 1, "<sp> path-name"},
    {"XRMD", RMD, STR1, 1, "<sp> path-name"},
    {"PWD", PWD, ARGS, 1, "(return current directory)"},
    {"XPWD", PWD, ARGS, 1, "(return current directory)"},
    {"CDUP", CDUP, ARGS, 1, "(change to parent directory)"},
    {"XCUP", CDUP, ARGS, 1, "(change to parent directory)"},
    {"STOU", STOU, STR1, 1, "<sp> file-name"},
    {"SIZE", SIZE, OSTR, 1, "<sp> path-name"},
    {"CKSM", CKSM, CKSMARGS, 1, "<sp> cksm-alg <sp> offset <sp> length <sp> path-name"},
#ifdef FTP_SECURITY_EXTENSIONS
    { "AUTH", AUTH, STR1, 1,	"<sp> auth-type" },
    { "ADAT", ADAT, STR1, 1,	"<sp> auth-data" },
    { "PROT", PROT, ARGS, 1,	"<sp> protection-level" },
    { "PBSZ", PBSZ, STR1, 1,	"<sp> buffer-size" },
    { "CCC",  CCC,  ARGS, 1,	"(clear command channel)" },
#endif /* FTP_SECURITY_EXTENSIONS */
    {"MDTM", MDTM, OSTR, 1, "<sp> path-name"},
    { "ESTO", ESTO, ESTOARGS, 1, "<sp> A <sp> <offset> <sp> <filename>" },
    { "ERET", ERET, ERETARGS, 1, "<sp> P <sp> <offset> <sp> size <sp> <filename>" },
#ifdef USE_GLOBUS_DATA_CODE
    { "SPAS", SPAS, ARGS, 1, "(set server in striped passive mode"},
    { "SPOR", SPOR, ARGS, 1, "<sp> h1,h2,h2,h3,p1,p2..."},
    { "DCAU", DCAU, STR1, 1, "<sp> N|A|S <subject>"},
#endif
    { "FEAT", FEAT, ARGS, 1, "(return list of FTP extensions supported)"},
    { "OPTS", OPTS, OPTSARGS, 1, "(set operation-specific options)"},
    {NULL, 0, 0, 0, 0}
};

struct tab sitetab[] =
{
    {"UMASK", UMASK, ARGS, 1, "[ <sp> umask ]"},
    {"IDLE", IDLE, ARGS, 1, "[ <sp> maximum-idle-time ]"},
    {"CHMOD", CHMOD, NSTR, 1, "<sp> mode <sp> file-name"},
    {"HELP", HELP, OSTR, 1, "[ <sp> <string> ]"},
    {"GROUP", GROUP, STR1, 1, "<sp> access-group"},
    {"GPASS", GPASS, OSTR, 1, "<sp> access-password"},
    {"NEWER", NEWER, STR3, 1, "<sp> YYYYMMDDHHMMSS [ <sp> path-name ]"},
    {"MINFO", MINFO, STR3, 1, "<sp> YYYYMMDDHHMMSS [ <sp> path-name ]"},
    {"INDEX", INDEX, STR1, 1, "<sp> pattern"},
    {"EXEC", EXEC, STR1, 1, "<sp> command [ <sp> arguments ]"},
    {"ALIAS", ALIAS, OSTR, 1, "[ <sp> alias ] "},
    {"CDPATH", CDPATH, OSTR, 1, "[ <sp> ] "},
    {"GROUPS", GROUPS, OSTR, 1, "[ <sp> ] "},
    {"CHECKMETHOD", CHECKMETHOD, OSTR, 1, "[ <sp> method ]"},
    {"CHECKSUM", CHECKSUM, OSTR, 1, "[ <sp> file-name ]"},
    {"BUFSIZE", BUFSIZE, ARGS, 1, "[ <sp> <socket buffer size in bytes> ]"},
    {"PSIZE", PSIZE, ARGS, 1, "[ <sp> <set file size for partitioned file> ]"},
    {"FAULT", FAULT, STR1, 1, "<sp> command" },
    {NULL, 0, 0, 0, 0}
};

struct tab optstab[] =
{
    {"RETR", RETR, NEWARGS, 1, "<sp> <retr_opts>"},
    {"MLST", MLST, OSTR, 1, "[ <sp> <fact list> ]"},
    {"LIST", LIST, NEWARGS, 1, "[ <sp> <list_opts> ]"},
    {NULL, 0, 0, 0, 0}
};

char * feattab[] =
{
    "REST STREAM",
    "ESTO",
    "ERET",
    "MDTM",
    "MLST Type*;Size*;Modify*;Perm*;Charset*;UNIX.mode*;UNIX.slink*;Unique*;", 
    "SIZE",
    "CKSM",
#ifdef USE_GLOBUS_DATA_CODE
    "PARALLEL",
    "DCAU",
#endif
    NULL
};
struct tab *lookup(register struct tab *p, char *cmd)
{
    for (; p->name != NULL; p++)
	if (strcmp(cmd, p->name) == 0)
	    return (p);
    return (0);
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
char *wu_getline(char *s, int n, register FILE *iop)
{
    register int c;
    register char *cs;
    char *passtxt = "PASS password\r\n";
#ifdef FTP_SECURITY_EXTENSIONS
    int buffer_len = n;
#endif /* FTP_SECURITY_EXTENSIONS */    

    cs = s;
/* tmpline may contain saved command from urgent mode interruption */
    for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
	*cs++ = tmpline[c];
	if (tmpline[c] == '\n') {
	    *cs++ = '\0';
	    if (debug) {
		if (strncasecmp(passtxt, s, 5) == 0)
		    syslog(LOG_DEBUG, "command: %s", passtxt);
		else
		    syslog(LOG_DEBUG, "command: %s", s);
	    }
	    tmpline[0] = '\0';
	    return (s);
	}
	if (c == 0)
	    tmpline[0] = '\0';
    }
  retry:
    while ((c = getc(iop)) != EOF) {
#ifdef TRANSFER_COUNT
	byte_count_total++;
	byte_count_in++;
#endif
	c &= 0377;
	if (c == IAC) {
	    if ((c = getc(iop)) != EOF) {
#ifdef TRANSFER_COUNT
		byte_count_total++;
		byte_count_in++;
#endif
		c &= 0377;
		switch (c) {
		case WILL:
		case WONT:
		    c = getc(iop);
#ifdef TRANSFER_COUNT
		    byte_count_total++;
		    byte_count_in++;
#endif
		    printf("%c%c%c", IAC, DONT, 0377 & c);
		    (void) fflush(stdout);
		    continue;
		case DO:
		case DONT:
		    c = getc(iop);
#ifdef TRANSFER_COUNT
		    byte_count_total++;
		    byte_count_in++;
#endif
		    printf("%c%c%c", IAC, WONT, 0377 & c);
		    (void) fflush(stdout);
		    continue;
		case IAC:
		    break;
		default:
		    continue;	/* ignore command */
		}
	    }
	}
	*cs++ = c;
	if (--n <= 0 || c == '\n')
	    break;
    }

    if (c == EOF && cs == s) {
	if (ferror(iop) && (errno == EINTR))
	    goto retry;
	return (NULL);
    }

    *cs++ = '\0';

    if (debug) {
	if (strncasecmp(passtxt, s, 5) == 0)
	    syslog(LOG_DEBUG, "command: %s", passtxt);
#ifdef FTP_SECURITY_EXTENSIONS
	/* Don't dump ADAT buffers as they can overflow syslogd */
	else if (strncmp(s, "ADAT", 4) == 0)
	    syslog(LOG_DEBUG, "command: ADAT (%d bytes)", strlen(s));

	/* Also don't dump MIC, ENC or COMP buffers as they are encoded */
	else if (strncmp(s, "MIC", 3) == 0)
	    syslog(LOG_DEBUG, "command: MIC (%d bytes)", strlen(s));
	else if (strncmp(s, "ENC", 3) == 0)
	    syslog(LOG_DEBUG, "command: ENC (%d bytes)", strlen(s));
	else if (strncmp(s, "COMP", 3) == 0)
	    syslog(LOG_DEBUG, "command: COMP (%d bytes)", strlen(s));
#endif /* FTP_SECURITY_EXTENSIONS */
	else
	    syslog(LOG_DEBUG, "command: %s", s);
    }

#ifdef FTP_SECURITY_EXTENSIONS
    if (decode_secure_message(s, s, buffer_len) < 0)
	return NULL;
    
#endif /* FTP_SECURITY_EXTENSIONS */

    return (s);
}

static void toolong(int a) /* signal that caused this function to be called */
{
    time_t now;

    reply(421,
	  "Timeout (%d seconds): closing control connection.", timeout_idle);
    (void) time(&now);
    if (logging) {
	syslog(LOG_INFO,
	       "User %s timed out after %d seconds at %.24s",
	       (pw ? pw->pw_name : "unknown"), timeout_idle, ctime(&now));
    }
    dologout(1);
}

int yylex(void)
{
    static int cpos, state, start_cpos;
    register char *cp, *cp2;
    register struct tab *p;
    int n;
    time_t now;
    char c = '\0';
    extern time_t limit_time;
    extern time_t login_time;

    for (;;) {
	switch (state) {

	case CMD:
	    yyerrorcalled = 0;

	    setproctitle("%s: IDLE", proctitle);

	    if (is_shutdown(!logged_in, 0) != 0) {
		reply(221, "Server shutting down.  Goodbye.");
		dologout(0);
	    }

	    time(&now);
	    if ((limit_time > 0) && (((now - login_time) / 60) > limit_time)) {
		reply(221, "Time limit reached.  Goodbye.");
		dologout(0);
	    }

#ifdef IGNORE_NOOP
	    if (!alarm_running) {
		(void) signal(SIGALRM, toolong);
		(void) alarm((unsigned) timeout_idle);
		alarm_running = 1;
	    }
#else
	    (void) signal(SIGALRM, toolong);
	    (void) alarm((unsigned) timeout_idle);
#endif
	    if (wu_getline(cbuf, sizeof(cbuf) - 1, stdin) == NULL) {
		(void) alarm(0);
		reply(221, "You could at least say goodbye.");
		dologout(0);
	    }
#ifndef IGNORE_NOOP
	    (void) alarm(0);
#endif
	    if ((cp = strchr(cbuf, '\r'))) {
		*cp++ = '\n';
		*cp = '\0';
	    }
	    if ((cp = strpbrk(cbuf, " \n")))
		cpos = cp - cbuf;
	    if (cpos == 0)
		cpos = 4;
	    c = cbuf[cpos];
	    cbuf[cpos] = '\0';
	    upper(cbuf);
#ifdef IGNORE_NOOP
	    if (strncasecmp(cbuf, "NOOP", 4) != 0) {
		(void) alarm(0);
		alarm_running = 0;
	    }
#endif
	    p = lookup(cmdtab, cbuf);
	    cbuf[cpos] = c;
	    if (strncasecmp(cbuf, "PASS", 4) != 0 &&
		strncasecmp(cbuf, "SITE GPASS", 10) != 0) {
		if ((cp = strchr(cbuf, '\n')))
		    *cp = '\0';
		setproctitle("%s: %s", proctitle, cbuf);
		if (cp)
		    *cp = '\n';
	    }
	    if (p != 0) {
		if (p->implemented == 0) {
		    nack(p->name);
		    longjmp(errcatch, 0);
		    /* NOTREACHED */
		}
		state = p->state;
		yylval.String = p->name;
		return (p->token);
	    }
	    break;

	case SITECMD:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }
	    cp = &cbuf[cpos];
	    if ((cp2 = strpbrk(cp, " \n")))
		cpos = cp2 - cbuf;
	    c = cbuf[cpos];
	    cbuf[cpos] = '\0';
	    upper(cp);
	    p = lookup(sitetab, cp);
	    cbuf[cpos] = c;
	    if (p != 0) {
#ifndef PARANOID		/* what GOOD is SITE *, anyways?!  _H */
		if (p->implemented == 0) {
#else
		if (1) {
		    syslog(LOG_WARNING, "refused SITE %s %s from %s of %s",
			   p->name, &cbuf[cpos],
			   anonymous ? guestpw : authuser, remoteident);
#endif /* PARANOID */
		    state = CMD;
		    nack(p->name);
		    longjmp(errcatch, 0);
		    /* NOTREACHED */
		}
		state = p->state;
		yylval.String = p->name;
		return (p->token);
		}
	    state = CMD;
	    break;

	case OSTR:
	    if (cbuf[cpos] == '\n') {
		state = CMD;
		return (CRLF);
	    }
	    /* FALLTHROUGH */

	case STR1:
	case ZSTR1:
	  dostr1:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		if (state == OSTR)
		    state = STR2;
		else
		    ++state;
		return (SP);
	    }
	    break;

	case ZSTR2:
	    if (cbuf[cpos] == '\n') {
		state = CMD;
		return (CRLF);
	    }
	    /* FALLTHROUGH */

	case STR2:
	  dostr2:
	    cp = &cbuf[cpos];
	    n = strlen(cp);
	    cpos += n - 1;
	    /*
	     * Make sure the string is nonempty and \n terminated.
	     */
	    if (n > 1 && cbuf[cpos] == '\n') {
		cbuf[cpos] = '\0';
		yylval.String = copy(cp);
		cbuf[cpos] = '\n';
		state = ARGS;
		return (STRING);
	    }
	    break;

	case NSTR:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }
	    if (isdigit(cbuf[cpos])) {
		cp = &cbuf[cpos];
		while (isdigit(cbuf[++cpos]));
		c = cbuf[cpos];
		cbuf[cpos] = '\0';
		yylval.Number = atoi(cp);
		cbuf[cpos] = c;
		state = STR1;
		return (NUMBER);
	    }
	    state = STR1;
	    goto dostr1;

	case STR3:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }

	    cp = &cbuf[cpos];
	    cp2 = strpbrk(cp, " \n");
	    if (cp2 != NULL) {
		c = *cp2;
		*cp2 = '\0';
	    }
	    n = strlen(cp);
	    cpos += n;
	    /*
	     * Make sure the string is nonempty and SP terminated.
	     */
	    if ((cp2 - cp) > 1) {
		yylval.String = copy(cp);
		cbuf[cpos] = c;
		state = OSTR;
		return (STRING);
	    }
	    break;

	case ARGS:
	    if (isdigit(cbuf[cpos])) {
		cp = &cbuf[cpos];
		while (isdigit(cbuf[++cpos]));
		c = cbuf[cpos];
		cbuf[cpos] = '\0';
		yylval.Number = atoi(cp);
		cbuf[cpos] = c;
		return (NUMBER);
	    }

	    switch (cbuf[cpos++]) {

	    case '\n':
		state = CMD;
		return (CRLF);

	    case ' ':
		return (SP);

	    case ',':
		return (COMMA);

	    case 'A':
	    case 'a':
		return (A);

	    case 'B':
	    case 'b':
		return (B);

	    case 'C':
	    case 'c':
		return (C);

	    case 'E':
	    case 'e':
		return (E);

	    case 'F':
	    case 'f':
		return (F);

	    case 'I':
	    case 'i':
		return (I);

	    case 'L':
	    case 'l':
		return (L);

	    case 'N':
	    case 'n':
		return (N);

	    case 'P':
	    case 'p':
		return (P);

	    case 'R':
	    case 'r':
		return (R);

	    case 'S':
	    case 's':
		return (S);

	    case 'T':
	    case 't':
		return (T);

	    }
	    break;

	    case ESTOARGS:
	    case ERETARGS:
	    case EARGS3:
	    case EARGS5:
		if (cbuf[cpos] == ' ') {
		    cpos++;
		    state++;
		    return (SP);
		}
		break;
	    case EARGS1:
		/* Pull off a char, go to EARGS5 */
		if(cbuf[cpos] == 'A' || cbuf[cpos] == 'a')
		{
		    cpos++;
		    state = EARGS5;
		    return (A);
		}
		break;
	    case EARGS2:
		/* Pull off a char, go to EARGS3 */
		if(cbuf[cpos] == 'P' || cbuf[cpos] == 'p')
		{
		    cpos++;
		    state = EARGS3;
		    return P;
		}
		break;
	    case EARGS4:
		/* Pull off a number, go to EARGS5 */
		if (isdigit(cbuf[cpos])) {
		    cp = &cbuf[cpos];
		    while (isdigit(cbuf[++cpos]));
		    c = cbuf[cpos];
		    cbuf[cpos] = '\0';
#ifdef USE_GLOBUS_DATA_CODE
		    sscanf(cp,"%"GLOBUS_OFF_T_FORMAT, &yylval.Bignum);
#else
                    yylval.Number = atoi(cp);
#endif
		    cbuf[cpos] = c;

		    state = EARGS5;
#ifdef USE_GLOBUS_DATA_CODE
		    return (BIGNUM);
#else
                    return(NUMBER);
#endif                    
		}
		break;

	    case EARGS6:
		/* pull of a number, go to STR1 */
		if (isdigit(cbuf[cpos])) {
		    cp = &cbuf[cpos];
		    while (isdigit(cbuf[++cpos]));
		    c = cbuf[cpos];
		    cbuf[cpos] = '\0';
#ifdef USE_GLOBUS_DATA_CODE
		    sscanf(cp,"%"GLOBUS_OFF_T_FORMAT, &yylval.Bignum);
#else
                    yylval.Number = atoi(cp);
#endif
		    cbuf[cpos] = c;

		    state = STR1;

#ifdef USE_GLOBUS_DATA_CODE
		    return (BIGNUM);
#else
                    return(NUMBER);
#endif                    
		}
		break;

	    case CKSMARGS:
	    case CARGS2:
	    case CARGS4:
	    case CARGS6:
		 if (cbuf[cpos] == ' ') {
                    cpos++;
                    if(state == CARGS6)
                    {
                        state = STR2;
                    }
                    else
                    {
                        state++;
                    }
                    return (SP);
                }
                break;

	    case CARGS1:
	     /* must be a word of some sort */
            	cp = &cbuf[cpos];
            	
            	while(isalnum(cbuf[++cpos]));

            	c = cbuf[cpos];
            	cbuf[cpos] = '\0';
     		yylval.String = copy(cp);
                cbuf[cpos] = c;
                state++;
                return STRING;
              break;

	    case CARGS3:
	    case CARGS5:
	 	/* pull of a number,  */
                if (isdigit(cbuf[cpos])) {
                    start_cpos = cpos;
                    cp = &cbuf[cpos];
                    while (isdigit(cbuf[++cpos]));
                    c = cbuf[cpos];
                    if(c != ' ')
                    {
                        cpos = start_cpos;
                        state = STR2;
                        goto dostr2;
                    }
                    cbuf[cpos] = '\0';
#ifdef USE_GLOBUS_DATA_CODE
                    sscanf(cp,"%"GLOBUS_OFF_T_FORMAT, &yylval.Bignum);
#else
                    yylval.Number = atoi(cp);
#endif
                    cbuf[cpos] = c; 

                    state++;
    
#ifdef USE_GLOBUS_DATA_CODE 
                    return (BIGNUM);
#else               
                    return(NUMBER);
#endif                    
                }
                else if(cbuf[cpos] == '-' &&
                        cbuf[cpos + 1] == '1' &&
                        cbuf[cpos + 2] == ' ')
                {
#ifdef USE_GLOBUS_DATA_CODE
                    yylval.Bignum = -1;
#else
                    yylval.Number = -1;
#endif
                    state++;
                    cpos += 2;
    
#ifdef USE_GLOBUS_DATA_CODE 
                    return (BIGNUM);
#else               
                    return(NUMBER);
#endif                                        
                }
                else
                {
                    state = STR2;
                    goto dostr2;
                }
                break;	
                             

	    case OPTSARGS:
		if (cbuf[cpos] == ' ') {
		    cpos++;
		    return (SP);
		}
		cp = &cbuf[cpos];
		if ((cp2 = strpbrk(cp, " \n")))
		    cpos = cp2 - cbuf;
		c = cbuf[cpos];
		cbuf[cpos] = '\0';
		upper(cp);
		p = lookup(optstab, cp);
		cbuf[cpos] = c;
	        if (p != 0) {
                    if (p->implemented == 0) {
                        state = CMD;
                        nack(p->name);
                        longjmp(errcatch, 0);
                        /* NOTREACHED */
                    }
                    state = p->state;
                    yylval.String = p->name;
                    return (p->token);
		}
	        state = CMD;
	        break;
	        
	    case NEWARGS:
	    if (isdigit(cbuf[cpos])) {
		cp = &cbuf[cpos];
		while (isdigit(cbuf[++cpos]));
		c = cbuf[cpos];
		cbuf[cpos] = '\0';
		yylval.Number = atoi(cp);
		cbuf[cpos] = c;
		return (NUMBER);
	    }

	    switch (cbuf[cpos]) {

	    case '\n':
		state = CMD;
		cpos++;
		return (CRLF);

	    case ' ':
		cpos++;
		return (SP);

	    case ',':
		cpos++;
		return (COMMA);
	    case ';':
		cpos++;
		return (SEMICOLON);
	    case '-':
		cpos++;
		return (HYPHEN);
	    case '=':
		cpos++;
		return EQUALS;
	    }
	    /* must be a word of some sort */
	    cp = &cbuf[cpos];
	    while(isalnum(cbuf[++cpos]));

	    c = cbuf[cpos];
	    cbuf[cpos] = '\0';

	    if(strcasecmp(cp, "usedatamode") == 0)
	    {
		cbuf[cpos] = c;
		return USE_DATA_MODE;
	    }
	    else if(strcasecmp(cp, "stripelayout") == 0)
	    {
		cbuf[cpos] = c;
		return STRIPELAYOUT;
	    }
	    else if(strcasecmp(cp, "partitioned") == 0)
	    {
		cbuf[cpos] = c;
		return PARTITIONED;
	    }
	    else if(strcasecmp(cp, "blocked") == 0)
	    {
		cbuf[cpos] = c;
		return BLOCKED;
	    }
	    else if(strcasecmp(cp, "blocksize") == 0)
	    {
		cbuf[cpos] = c;
		return BLOCKSIZE;
	    }
	    else if(strcasecmp(cp, "parallelism") == 0)
	    {
		cbuf[cpos] = c;
		return PARALLELISM;
	    }
	    else if(strcasecmp(cp, "delayedpasv") == 0)
	    {
		cbuf[cpos] = c;
		return DELAYED_PASV;
	    }
	    else
	    {
		yylval.String = copy(cp);
		cbuf[cpos] = c;
		return STRING;
	    }

	default:
	    fatal("Unknown state in scanner.");
	}
	if (yyerrorcalled == 0) {
	    if ((cp = strchr(cbuf, '\n')) != NULL)
		*cp = '\0';
	    if (logged_in)
		reply(500, "'%s': command not understood.", cbuf);
	    else
		reply(530, "Please login with USER and PASS.");
	}
	state = CMD;
	longjmp(errcatch, 0);
    }
}

void upper(char *s)
{
    while (*s != '\0') {
	if (islower(*s))
	    *s = toupper(*s);
	s++;
    }
}

char *copy(char *s)
{
    char *p;

    p = (char *) malloc((unsigned) strlen(s) + 1);
    if (p == NULL)
	fatal("Ran out of memory.");
    (void) strcpy(p, s);
    return (p);
}

void help(struct tab *ctab, char *s)
{
    struct aclmember *entry = NULL;
    struct tab *c;
    size_t width, NCMDS;
    char *type;

    if (ctab == sitetab)
	type = "SITE ";
    else
	type = "";
    width = 0, NCMDS = 0;
    for (c = ctab; c->name != NULL; c++) {
	size_t len = strlen(c->name);

	if (len > width)
	    width = len;
	NCMDS++;
    }
    width = (width + 8) & ~7;
    if (s == 0) {
	register size_t i, j, w;
	size_t columns, lines;

	lreply(214, "The following %scommands are recognized %s.",
	       type, "(* =>'s unimplemented)");
	columns = 76 / width;
	if (columns == 0)
	    columns = 1;
	lines = (NCMDS + columns - 1) / columns;
	for (i = 0; i < lines; i++) {
	    char line[LARGE_BUFSIZE];
	    char *ptr = line;
	    strcpy(ptr, "   ");
	    ptr += 3;
	    for (j = 0; j < columns; j++) {
		c = ctab + j * lines + i;
		(void) sprintf(ptr, "%s%c", c->name,
			       c->implemented ? ' ' : '*');
		w = strlen(c->name) + 1;
		ptr += w;
		if (c + lines >= &ctab[NCMDS])
		    break;
		while (w < width) {
		    *(ptr++) = ' ';
		    w++;
		}
	    }
	    *ptr = '\0';
	    lreply(0, "%s", line);
	}
	(void) fflush(stdout);
#ifdef VIRTUAL
	if (virtual_mode && !virtual_ftpaccess && virtual_email[0] != '\0')
	    reply(214, "Direct comments to %s.", virtual_email);
	else
#endif
	if ((getaclentry("email", &entry)) && ARG0)
	    reply(214, "Direct comments to %s.", ARG0);
	else
	    reply(214, "Direct comments to ftp-bugs@%s.", hostname);
	return;
    }
    upper(s);
    c = lookup(ctab, s);
    if (c == (struct tab *) NULL) {
	reply(502, "Unknown command %s.", s);
	return;
    }
    if (c->implemented)
	reply(214, "Syntax: %s%s %s", type, c->name, c->help);
    else
	reply(214, "%s%-*s\t%s; unimplemented.", type, width,
	      c->name, c->help);
}

void feat(char *tab[])
{
    int i;

    if(tab[0] == NULL)
    {
	reply(211, "No features supported");
	return;
    }
    lreply(211, "Extensions supported:");
    for(i = 0; tab[i] != NULL; i++)
    {
	lreply(0, " %s", feattab[i]);
    }
    reply(211, "END");
}

void sizecmd(char *filename)
{
    switch (type) {
    case TYPE_L:
    case TYPE_I:{
	    struct stat stbuf;
	    if (stat(filename, &stbuf) < 0 ||
		(stbuf.st_mode & S_IFMT) != S_IFREG)
#               if defined(HAVE_BROKEN_STAT)
                {
		    int fd;
		    off_t size;
		    fd = open(filename, O_RDONLY);
		    if(fd >= 0)
		    {
			size = lseek(fd, 0, SEEK_END);
			close(fd);
		    }
		    if(fd < 0 || size < 0)
			reply(550, "%s: not a plain file.", filename);
		    else
			reply(213, "%" GLOBUS_OFF_T_FORMAT, size);
		}
#               else
		    reply(550, "%s: not a plain file.", filename);
#               endif
	    else
		reply(213, "%" GLOBUS_OFF_T_FORMAT, stbuf.st_size);
	    break;
	}
    case TYPE_A:{
	    FILE *fin;
	    register int c;
	    register off_t count;
	    struct stat stbuf;
	    fin = fopen(filename, "r");
	    if (fin == NULL) {
		perror_reply(550, filename);
		return;
	    }

            /* with a broken stat, we can still detect non-plain files--
	     * we just can't trust that stat returning -1 is a bad file.
	     */
#           if defined(HAVE_BROKEN_STAT)
		if ((fstat(fileno(fin), &stbuf) == 0) &&
		    (stbuf.st_mode & S_IFMT) != S_IFREG) {
#           else
		if ((fstat(fileno(fin), &stbuf) < 0) ||
		    (stbuf.st_mode & S_IFMT) != S_IFREG) {
#           endif
		reply(550, "%s: not a plain file.", filename);
		(void) fclose(fin);
		return;
	    }

	    count = 0;
	    while ((c = getc(fin)) != EOF) {
		if (c == '\n')	/* will get expanded to \r\n */
		    count++;
		count++;
	    }
	    (void) fclose(fin);

	    reply(213, "%" GLOBUS_OFF_T_FORMAT, count);
	    break;
	}
    default:
	reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
    }
}



void site_exec(char *cmd)
{
#ifdef PARANOID
    syslog(LOG_CRIT, "REFUSED SITE_EXEC (slipped through!!): %s", cmd);
#else
    char buf[MAXPATHLEN];
    char *sp = (char *) strchr(cmd, ' '), *slash, *t;
    FILE *cmdf;


    /* sanitize the command-string */

    if (sp == 0) {
	while ((slash = strchr(cmd, '/')) != 0)
	    cmd = slash + 1;
    }
    else {
	while (sp && (slash = (char *) strchr(cmd, '/'))
	       && (slash < sp))
	    cmd = slash + 1;
    }

    for (t = cmd; *t && !isspace(*t); t++) {
	if (isupper(*t)) {
	    *t = tolower(*t);
	}
    }

    /* build the command */
    if (strlen(_PATH_EXECPATH) + strlen(cmd) + 2 > sizeof(buf))
	return;
    sprintf(buf, "%s/%s", _PATH_EXECPATH, cmd);

    cmdf = ftpd_popen(buf, "r", 0);
    if (!cmdf) {
	perror_reply(550, cmd);
	if (log_commands)
	    syslog(LOG_INFO, "SITE EXEC (FAIL: %m): %s", cmd);
    }
    else {
	int lines = 0;
	int maxlines = 0;
	struct aclmember *entry = NULL;
	char class[1024];
	int maxfound = 0;
	int defmaxlines = 20;
	int which;

	(void) acl_getclass(class);
	while ((getaclentry("site-exec-max-lines", &entry)) && ARG0) {
	    if (ARG1)
		for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		    if (!strcasecmp(ARG[which], class)) {
			maxlines = atoi(ARG0);
			maxfound = 1;
		    }
		    if (!strcmp(ARG[which], "*"))
			defmaxlines = atoi(ARG0);
		}
	    else
		defmaxlines = atoi(ARG0);
	}
	if (!maxfound)
	    maxlines = defmaxlines;
	lreply(200, "%s", cmd);
	while (fgets(buf, sizeof buf, cmdf)) {
	    size_t len = strlen(buf);

	    if (len > 0 && buf[len - 1] == '\n')
		buf[--len] = '\0';
	    lreply(200, "%s", buf);
	    if (maxlines <= 0)
		++lines;
	    else if (++lines >= maxlines) {
		lreply(200, "*** Truncated ***");
		break;
	    }
	}
	reply(200, " (end of '%s')", cmd);
	if (log_commands)
	    syslog(LOG_INFO, "SITE EXEC (lines: %d): %s", lines, cmd);
	ftpd_pclose(cmdf);
    }
#endif /* PARANOID */
}

void alias(char *s)
{
    struct aclmember *entry = NULL;

    if (s != (char *) NULL) {
	while (getaclentry("alias", &entry) && ARG0 && ARG1 != NULL)
	    if (!strcmp(ARG0, s)) {
		reply(214, "%s is an alias for %s.", ARG0, ARG1);
		return;
	    }
	reply(502, "Unknown alias %s.", s);
	return;
    }

    lreply(214, "The following aliases are available.");

    while (getaclentry("alias", &entry) && ARG0 && ARG1 != NULL)
	lreply(0, "   %-8s %s", ARG0, ARG1);
    (void) fflush(stdout);

    reply(214, "");
}

void cdpath(void)
{
    struct aclmember *entry = NULL;

    lreply(214, "The cdpath is:");
    while (getaclentry("cdpath", &entry) && ARG0 != NULL)
	lreply(0, "  %s", ARG0);
    (void) fflush(stdout);
    reply(214, "");
}

void print_groups(void)
{
    gid_t groups[NGROUPS_MAX];
    int ngroups = 0;

    if ((ngroups = getgroups(NGROUPS_MAX, groups)) < 0) {
	return;
    }

    lreply(214, "Group membership is:");
    ngroups--;

    for (; ngroups >= 0; ngroups--)
	lreply(214, "  %d", groups[ngroups]);

    (void) fflush(stdout);
    reply(214, "");
}

/*
 * Functions to display and manipulate the TCP window size
 */
set_bufsize(int size)
{
    TCPwindowsize = size;
#ifdef USE_GLOBUS_DATA_CODE
    g_set_tcp_buffer(size);
#endif
    
    reply(214, "TCP window size set to %d bytes.",
	 TCPwindowsize);
}
 
print_bufsize()
{
    if (TCPwindowsize > 0)
	reply(214, "TCP window size is %d bytes.",
	      TCPwindowsize);
    else
	reply(214, "TCP window size is the system default.");
}
