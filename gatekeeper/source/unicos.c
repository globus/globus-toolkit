/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  This is a modified (mostly condensed) version of the UNICOS
 *  extensions to SSH -- see original comments below for details
 *  on this source.
 *
 *  Mod Author: Brent Milne (BMilne@lbl.gov)
 *              September 1998
 */ 


/*
 *  $Source$
 *  $Revision$
 *  $Date$
 *
 *  Purpose:
 *	Define variables and functions needed for UNICOS and multi-level
 *	security (MLS) operations.  Essentially, isolate the major 
 *	functions needed specifically for Cray UNICOS in order to 
 *	make maintenance easier and to keep the "#ifdef CRAY" in 
 *	other ssh routines to a minimum.
 *
 *	Routines defined that may be referenced externally:
 *
 *	    cray_setup
 *	    get_udbent
 *	    get_unicos_connect_info
 *	    mls_validate
 *	    set_seclabel
 *	    set_unicos_sockopts
 *	    showusrv
 *	    showprivs
 *	    unicos_access_denied
 *	    unicos_init
 *	    update_udb
 *
 *  Preconditions:
 *	Generally, unicos_init must be called before any other routine
 *	in this module.  Exceptions:  showusrv and showprivs.
 *
 *  Notes:
 *	Many of these routines initialize within-module global variables,
 *	called module-globals (MG), used by other routines.  A tale of 
 *	intrigue is thusly woven.  To keep the intrigue manageable, routines 
 *	that initialize global variables should appear before routines that 
 *	use them.  To help understand, here is some terminology and a brief 
 *	description of the calling sequence.
 *
 *	sshd operates as follows:
 *	     ssh forks after invocation to detach from the terminal.  The
 *		original program exits and the child lives on to become 
 *		the main (M) daemon.
 *
 *	     The main daemon forks a copy for each connection.  I term
 *		this copy a connection (C) daemon.  The connection
 *		daemon handles authentication and TMPDIR cleanup.
 *
 *	    After authentication, the connection daemon forks a 
 *		session (S) daemon which performs final setup, 
 *		then execs the specified user shell or command.
 *
 *	    Thus, there is the (M)ain ssh daemon, the (C)onnection ssh,
 *		and the (S)ession ssh.
 *
 *	   ssh
 *	  Daemon  Called Routine		
 *	  ------  --------------
 *	    M	    unicos_init
 *			Called shortly after ssh startup to determine 
 *			whether MLS and MAC are active.  This information
 *			is stored in module-global (MG) variables.  If
 *			MLS is active, get the current security validation
 *			information (MG usrv) and modify the programs 
 *			security validation to work with all valid labels.
 *		
 *	    M	    set_unicos_sockopts
 *			Modify the socket to allow connections at multiple
 *			security labels.  Uses MG usrv.
 *	
 *	    C	    get_unicos_connect_info
 *			Determine the security label of the connected socket
 *			and set the label of the program to that label.
 *			Uses MG usrv and establishes MG ptylabel.
 *	
 *	    C	    get_udbent
 *			After the user name is known, read the udb and copy
 *			this information into a MG structure, udbent, which
 *			is used by many of the routines in this module.  This
 *			prevents having to make multiple references to the udb
 *			during processing.  The lookup operation occurs while 
 *			the program still has sufficient privilege to obtain 
 *			all udb fields, particularly the security information
 *			fields.
 *			
 *	    C	    unicos_access_denied
 *			Determines whether the user is allowed to login.
 *			Checks for system restriction, user disabled, or 
 *			user denied interactive access.  
 *
 *	    S	    mls_validate
 *			If MLS is active, obtains security label information
 *			from stdout, then calls ia_mlsuser to ensure that
 *			the user is allowed to connect at the requested
 *			security label.
 *	
 *	    S	    update_udb
 *			Called after the user has been authenticated and 
 *			is allowed to log in to record a successful login in
 *			the udb.
 *	
 *	    S	    cray_setup
 *			Perform final unicos-specific setup operations for the 
 *			user.  This includes establishing a new job, setting 
 *			session (job) limits, creating the job temporary 
 *			directory (TMPDIR), and establishing the acid (account 
 *			id) for the login.
 *			
 *	    S	    set_seclabel
 *			Set the security label and other security validation
 *			information for the user, then remove all privilege
 *			that the ssh session daemon still possesses.  Security
 *			validation information includes the valid compartments,
 *			valid levels, active and valid security categories, 
 *			class, and permits.
 *	
 *
 *	TMPDIR handling.
 *	    TMPDIR code has been removed (milne).
 *	    TMPDIR, is somewhat awkward to handle properly so that the
 *	    directory is cleaned up after the session ends.  TMPDIR is
 *	    handled as follows:
 *
 *	    1)	The connection daemon requests to catch WJSIGNAL.  It is
 *		responsible for cleaning up the temporary directory.
 *
 *	    2)	When setjob is called in the session ssh, it is told that 
 *		WJSIGNAL should be sent to the parent when the last child 
 *		in the job dies.  The connection daemon will catch the
 *		signal and clean-up the temporary directory.
 *
 *
 *  Author(s):	Randy Bremmer, March 1998, Los Alamos National Laboratory
 *		Wayne Schroeder, SDSC (routine cray_setup and acidburn).
 *		Dan Reynolds, University of Texas at Austin.  (update_udb).
 *
 *  Modification $Author$
 *
 *  Maintenance and modification 
 *
 *	Revision 1.13  1998-07-14 11:12:30-06  rrb
 *	Add a call to setshares to establish the resource group of the session.
 *	The resource group is used by the fair share (or other) scheduler.
 *
 *	Revision 1.12  1998-06-18 15:46:59-06  rrb
 *	Change mls_validate to include an argument specifying whether
 *	the connection is on a pty or not.  Different methods of
 *	determining the security attributes of the connection are
 *	needed depending on whether a pty is involved or not.
 *	This fixes a problem where interactive connections worked,
 *	but non-interactive, such as scp, failed.
 *
 *	Revision 1.11  1998-05-28 12:19:36-06  rrb
 *	Make the account/project prompts a bit more friendly.
 *
 *	Revision 1.10  1998-05-28 11:45:06-06  rrb
 *	Add routine converted_to_int.
 *	Use converted_to_int in place of atoi in routine acidburn so that
 *	    semi-numeric account names will work properly.
 *	Fix logic problems in acidburn which prevented proper recognition of
 *	    account names and numeric menu selections.
 *	Correct the range and default values printed on the account name prompt.
 *
 *	Revision 1.9  1998-05-28 09:46:04-06  rrb
 *	Place conditional around ssent.mask as the mask field is not defined
 *	in UNICOS 8.0.
 *	Update update_udb author information.
 *
 *	Revision 1.8  1998-05-27 15:23:03-06  rrb
 *
 *	Revision 1.7  1998-05-27 09:43:05-06  rrb
 *	Change to uid 0 in unicos_init.
 *
 *	Revision 1.6  1998-05-26 15:19:51-06  rrb
 *	Add routine pty_labeled.
 *	Initialize the security label information needed by pty_labeled.
 *	Change mls_validate so that it uses secstat on the tty device rather
 *	than fsecstat against the stdout file descriptor in order to obtain the
 *	correct security label information.
 *
 *	Revision 1.5  1998-05-20 16:33:15-06  rrb
 *	Modify showusrv routine so that it will call getusrv if a the passed
 *	in pointer is NULL.
 *
 *	Revision 1.4  1998-05-20 16:21:01-06  rrb
 *	Add new elements from sdsc/ut cray_setup.
 *	Make sysv a module-global (static) variable.
 *
 *	Revision 1.3  1998-05-18 15:26:53-06  rrb
 *	Divide crayuser_disallowed into routines mls_validate and
 *	unicos_access_denied.
 *	Changes required to compile correctly.
 *	Add "const" declarations where appropriate and adjust some calls
 *	Add IA_LOGFAILS to udb_update ssent.mask entry.
 *
 *	Revision 1.2  1998-05-14 09:11:08-06  rrb
 *	Intermediate check-in.
 *	Fix problems found by the compiler.
 *	Expand documentation.
 *
 *	Revision 1.1  1998-05-13 14:49:49-06  rrb
 *
 *
 *-------------------------*/

#include "globus_config.h"
#ifdef	TARGET_ARCH_CRAYT3E		/* the whole module is conditional */

#define DEBUG

#include "unicos.h"


#include "unicos_includes.h"
#include <sys/sysv.h>
#include <sys/tfm.h>
#include <sys/mac.h>
#include <sys/secparm.h>
#include <sys/stat.h>
#include <sys/secstat.h>
#include <sys/priv.h>
#include <sys/aoutdata.h>
#include <sys/sema.h>
#include <sys/cred.h>
#include <sys/category.h>
#include <sys/secdev.h>
#include <signal.h>
#include <udb.h>
#include <sys/jtab.h>
#include <ia.h>
#include <string.h>
#include <tmpdir.h>
#include <sysexits.h>
#include <syslog.h>


/*--------------------   Global declarations ------------------------*/

char*	TmpDir = NULL;		/* job temporary directory */

char connection_hostname[256] = "Unknown";


/*---------------- Within-module Global declarations ----------------*/

typedef	struct	jtab	JTAB;
typedef	priv_proc_t	PRIVS;
typedef	struct	secdev	SECDEV;
typedef	struct	secstat	SECSTAT;
typedef	struct	socksec	SOCKSEC;
typedef struct	stat	STAT;
typedef struct	sysv	SYSV;
typedef	struct	udb	UDB_t;
typedef struct	usrv	USRV;


static	PRIVS*	priv;			/* privilege list */
static	SECDEV	ptylabel;		/* security label for pty device */
static	logical	SecureSys = FALSE;	/* FLAG: secure UNICOS system */
static	logical	SecureMAC = FALSE;	/* FLAG: secure UNICOS MLS sys w/ SYSHIGH 
					   and SYSLOW */
static	SYSV	sysv;			/* system security validation structure */

static	UDB_t*	udbent = NULL;		/* udb entry for logging-in user */
static	logical	use_priv = FALSE;	/* FLAG: use least-privilege mechanism for 
					   UNICOS >= 8.0 */
static	USRV	usrv;			/* user validation structure. */

typedef struct	authfail {
    char*	user;		/* pointer to user id */
    int		reason_code;	/* failure code */
} AUTHFAIL;

static	AUTHFAIL failinfo = { NULL, EX_DATAERR };


#define PW_WARNING_PERIOD       3600*24*7*2

#ifdef	IA_CALLER1
#define IA_SSH	IA_CALLER1
#else
#define IA_SSH	IA_CALLER
#endif

/*
 *	ADD_PRIV and SET_PRIV macros are disabled for now
 *	until someone comes along who is willing to modify
 *	ssh routines to conform to "least-privilege" practices.
 */
#define ADD_PRIV(SAVE, SET) { \
/* \
    if (use_priv) { \
	if ((SAVE = (priv_proc_t *)priv_get_proc()) != (priv_proc_t *)0) { \
		priv_value_t value = SET; \
		priv_proc_t temp_priv = *SAVE; \
		priv_set_proc_flag(&temp_priv, PRIV_EFFECTIVE, 1, \
				   &value, PRIV_SET); \
		priv_set_proc(&temp_priv); \
	} \
    } \
 */ \
}

#define SET_PRIV(PRIV) { \
/* \
    if (use_priv) { \
	priv_set_proc(PRIV); \
	priv_free_proc(PRIV); \
    } \
 */ \
}

/*--------------------- External declarations -----------------------*/

extern	void	child_set_env		P_(( char ***envp, unsigned int *envsizep, \
					     const char *name, const char *value ));
extern	char*	setlimits		/* undocumented system routine */
					P_(( const char *username, \
					     const int limit_type, \
			            	     pid_t pid, const int update ));
extern	int	setshares();		/* undocumented system routine */

/*--------------------- Function declarations -----------------------*/

static	void	acidburn		P_(( const UDB_t* up ));
static	void	cleanjtmp		P_(( const char* user, const char* jtmpdir ));
static	logical	converted_to_int	P_(( const char* string, int* value ));
static	void	job_termination_handler	P_(( int signum ));
static	char*	jtmp_dir 		P_(( const char* path, logical create, \
					     int* level, long* compart ));
static	int	mkjobdir		P_(( const char* jobdir, int mode, \
					     uid_t owner, gid_t group, \
					     int level, long compart ));
static	
const	char*	makejtmp		P_(( int jid ));

static	void    record_login_failure	P_(( const char* user, int reason_code )); 
static	void	remove_jtmpdir		P_(( int jid ));
static	void	unicos_auth_failed	P_(( void* context ));

/*------------------ Globus stubs for debug(), fatal() --------------*/

extern void gatekeeper_notice(int, char*);
extern void gatekeeper_failure(short, char*);


/* Debugging messages that should not be logged during normal operation. */

void debug(const char *fmt, ...)
{
  char buf[1024];
  va_list args;

#ifdef DEBUG
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  gatekeeper_notice(LOG_DEBUG, buf);
#endif 
}


/* Error messages that should be logged. */

void error(const char *fmt, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  gatekeeper_notice(LOG_ERR, buf);
}


/* Fatal messages.  This function never returns. */

void fatal(const char *fmt, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);

  gatekeeper_failure(0,buf); /* Does not return. */

  exit(1); /* Not reached. */
}


/*  This function never returns. */

void packet_disconnect(char *msg)
{
  gatekeeper_failure(0,msg); /* Does not return. */

  exit(1); /* Not reached. */
}




/*-----------------------------*/

static logical
converted_to_int ( string, value )

    const char*	string;		/* string to be converted */
    int*	value;		/* returned integer value */
{
/*  Purpose:
 *	Convert the character string to an integer value with error 
 *	checking.
 *
 *  Preconditions: 	None
 *  Postconditions:
 *	If string == NULL, value == NULL, or string can not be converted, 
 *	value is indeterminate, and this function returns FALSE.
 *
 *	If string is successfully converted, return TRUE, and value
 *	will contain the converted integer value.
 *
 *  Invariants:
 *  1)	String must not have any leading or trailing white space or
 *	the conversion will fail.
 *
 *  2)	The whole string must be consumed during the conversion or the
 *	conversion is deemed to have failed.  For example, the
 *	string "8h07" will fail, whereas atoi("8h07") will return 8.
 *
 *  3)	Decimal ([+-]*[0-9]+), octal (0[0-7]*), 
 *	and hexidecimal (0x[0-9a-fA-F]) formats are accepted.
 */
    int i;
    int n;
    int cnt = 0;	/* # of chars converted */

    if ((string == NULL) || (value == NULL)) return FALSE;
    cnt = 0;
    n = sscanf (string, "%i%n", value, &cnt);
#if RELEASE_LEVEL >= 9000
/*
 *	9.0 unicos introduced a change which causes a single "0" string
 *	to fail conversion because sscanf thinks it has converted
 *	2 chars instead of 1.  So if cnt >= strlen(string), we'll call
 *	that good enough.  This is fixed in UNICOS 9.0.2.8, and some
 *	variant of UNICOS 10; unfortunately RELEASE_LEVEL does not 
 *	reflect such fine granularity.  In UNICOS 9.0.2.8, RELEASE_LEVEL 
 *	is still 9000.  Sigh.
 */
    return ((cnt >= strlen(string)) && (n == 1));
#else
    return ((cnt == strlen(string)) && (n == 1));
#endif
}

int
unicos_init() 
/* Modified (milne) to return 0 if running priveleged, -1 otherwise.
   Fatal errors are ignored in non-priveleged mode.
*/
/*
 *  Purpose:
 *	Perform initialization needed on a secure UNICOS system so that
 *	the sshd can handle connections at varying security labels.
 *
 *  Preconditions:	none.
 *  Postconditions:
 *	If there are no fatal errors, set module-global variables:
 *	  1)	SecureSys
 *	  2)	SecureMAC
 *	  3)	Read system security validation information info sysv.
 *	  4)	Read current user security validation information
 *		into usrv.
 *	  5)	Modify usrv and apply (using setusrv) security ranges 
 *		appropriate to this machine so that connections
 *		at various labels can be handled.
 *	  6)	Establish a routine to catch signal WJSIGNAL.  The
 *		specified routine will clean-up the job temporary
 *		directory when a child session terminates.
 *	  7)	Remove environment variable TMPDIR.  See notes below.
 *	  8)	If SecureSys, attempt to change the uid to 0 (root).
 *
 *	If one of the system calls fails, an error message will be
 *	issued using routine "fatal", which does does not return.
 *
 *  Invariants:
 *  	This routine does not alter the value of SecureMAC unless
 *	MLS is active.
 *
 *  Notes:
 *   1)	The TMPDIR environment variable is defined for each session
 *	at login.  It describes a unique directory, also created at
 *	login, for the session.  The TMPDIR directory and all contents
 *	is destroyed when a session ends.  Kerberos library routines
 *	will attempt to use TMPDIR if it is defined.  Problem:
 *	when the administrator who starts sshd logs out, the TMPDIR
 *	is deleted, but kerberos routines still expect to create
 *	and read files there.  This can result in failing to forward
 *	k5 TGT's, and denying password logins to those who do not already
 *	have k5 credentials.  ssh will log the following symptoms when
 *	the TMPDIR directory is gone:
 *
 *		Password authentication of user {moniker} using Kerberos 
 *		failed: Generic unknown RC/IO error
 *
 *		Kerberos V5 tgt rejected for user {moniker} : Message replay 
 *		detection requires rcache parameter
 *
 *	Either TMPDIR must be redefined, or removed.  When removed, kerberos
 *	will use OS-specific default parameters.  On UNICOS, the default
 *	is /usr/tmp.
 *
 *   2)	On a UNICOS system with secure MAC, be careful not to start 
 *	sshd with the priv_root flag enabled.  The priv_root has some
 *	undocumented side-effects on the setuid(2) system call - it
 *	prevents you from changing your uid to something other than uid 0.
 *	I know of no way for the program to detect the state of the priv_root
 *	flag, nor a way to disable it. 
 *
 *   3)	Switch to uid 0 (root).  On a MLS system, an administrator
 *	with a proper active category could have started sshd. This
 *	is ok, except that sshd will later check to see the uid and
 *	if not 0, will only allow someone with the same uid to log in.
 *	Probably not desireable.
 */
{
    int setusrv_failed=0, priveleged;
    char setusrv_err_msg[1024];

    memset (&usrv, 0, sizeof(USRV));
    memset (&sysv, 0, sizeof(SYSV));

/*
 * Don't set SecureSys.  sysconf() implies that MLS is enabled, but
 * on golden.sdsc.edu it effectively isn't (meaning that we can safely
 * ignore it).  This avoids a bug in the fsecstat() system call.
 * SDSC Remedy ticket [0021093]
 * SGI/Cray Ticket 157765, RTA 2675
 * Globus Req #2366
 */

#if 0
    SecureSys = sysconf(_SC_CRAY_SECURE_SYS);
#endif

    if (SecureSys) {
	use_priv = (sysconf(_SC_CRAY_RELEASE) >= 8000);
	SecureMAC = sysconf(_SC_CRAY_SECURE_MAC);
	debug ("MLS enabled, MAC is %s", SecureMAC ? "on" : "off");

        if (getusrv(&usrv) < 0 ) {
	    fatal ("%s(%d): getusrv(): %s\n",
			__FILE__, __LINE__, strerror(errno)); 
	}

        if (getsysv(&sysv, sizeof(struct sysv)) < 0) {
	    fatal ("%s(%d): getsysv(): %s\n",
			__FILE__, __LINE__, strerror(errno)); 
	}

	ADD_PRIV(priv, PRIV_MAC_RELABEL_SUBJECT);

	if (SecureMAC) {
	    usrv.sv_minlvl = SYSLOW;
	    usrv.sv_actlvl = SYSHIGH;
	    usrv.sv_maxlvl = SYSHIGH;
	} else {
	    usrv.sv_minlvl = sysv.sy_minlvl;
	    usrv.sv_actlvl = sysv.sy_maxlvl;
	    usrv.sv_maxlvl = sysv.sy_maxlvl;
	}
	usrv.sv_actcmp = 0;
	usrv.sv_valcmp = sysv.sy_valcmp;

	usrv.sv_intcat = TFM_SYSTEM;
	usrv.sv_valcat |= (TFM_SYSTEM | TFM_SYSFILE);

	if (setusrv(&usrv) < 0) {
            setusrv_failed = 1;
	    sprintf (setusrv_err_msg, "%s(%d): setusrv(): %s\n",
			__FILE__, __LINE__, strerror(errno)); 
	}
	SET_PRIV(priv);

    }
/*
 *	    Switch to uid 0 (root).
 *		If this fails, then the program does not have sufficient 
 *		privilege, which is probably intentional so ignore 
 *		any errors. 
 */
        if (setuid(0) == 0)
          priveleged = 1;
        else
          priveleged = 0;

    if (priveleged && setusrv_failed)
    {
       fatal (setusrv_err_msg);
    }

    unsetenv ("TMPDIR");
    debug ("unicos_init complete.");

    return (priveleged) ? 0 : -1;
}

void
set_unicos_sockopts ( sfd )

    int	sfd;	/* socket file descriptor */
/*
 *  Purpose:
 *	Set socket option(s) on the provided socket to allow connections
 *	at multiple security labels.
 *
 *  Preconditions:
 *	Module-global variable "SecureSys" must specify the MLS state.
 *
 *  Postconditions:
 *	If MLS is enabled, the socket will be modified appropriately
 *	so that connections will be accepted from different
 *	security labels; otherwise no socket options are set.
 *
 *  Invariants:
 *	If there is system call error, report using the "fatal" 
 *	routine, which issues an error message and does not return.
 */
{
    int on = 1;
	
    ADD_PRIV(priv, PRIV_SOCKET | PRIV_MAC_UPGRADE |
             PRIV_MAC_DOWNGRADE | PRIV_MAC_READ | PRIV_MAC_WRITE);


    if (SecureSys) {
        debug ("Setting secure socket options.");
        if ( setsockopt(sfd, SOL_SOCKET, SO_SEC_MULTI, 
                        (char *)&on, sizeof (on)) < 0 ) 
            fatal ("%s(%d): setsockopt(): %s\n",
                    __FILE__, __LINE__, strerror(errno)); 
    }

    SET_PRIV(priv);
    debug ("Unicos socket options set.");
    return;
}

void
get_unicos_connect_info ( sfd )

    int	sfd;			/* connected socket */
/*
 *  Purpose:
 *	Determine the security label of the specified connection and
 *	change the security level of the running program to the label
 *	of the connection.
 *
 *  Preconditions:
 *  1)	Module-global SecureSys must reflect the MLS state of the system.
 *  2)	Module-global usrv must contain current security validation information.
 *
 *  Postconditions:
 *	Return after placing security label information about the
 *	connection on socket sfd into module-global usrv and setting the 
 *	current label to match the connection.  Permbits and integrity 
 *	class(s) are also cleared.
 *
 *  Invariants:
 *   o	If there is an error in a system call, function "fatal" will
 *	issue an error message and will not return.
 *
 *  Notes:
 *	This routine is usually called by a forked-child of the main
 *	server daemon.
 */
{
    logical	multilev_sock;		/* FLAG: multilevel socket */
    SOCKSEC	sockv;			/* socket security info struct */
    int		sockv_size = sizeof(SOCKSEC);
    int		sol = sizeof(logical);

    debug ("entering get_unicos_connect_info.");

    if (SecureSys) {	/* get the socket label */

	memset (&sockv, 0, sizeof(SOCKSEC));
        ADD_PRIV(priv, PRIV_MAC_READ);

        if ( getsockopt(sfd, SOL_SOCKET, SO_SECURITY, (char *)&sockv, &sockv_size) 
	     < 0) fatal ("%s(%d): getsockopt(SO_SECURITY): %s\n",
				__FILE__, __LINE__, strerror(errno)); 
        if ( getsockopt(sfd, SOL_SOCKET, SO_SEC_MULTI, (char *)&multilev_sock, &sol) 
	     < 0) fatal ("%s(%d): getsockopt(SO_SEC_MULTI): %s\n",
				__FILE__, __LINE__, strerror(errno)); 
        SET_PRIV(priv);
	debug("Connection at level %d, compartment %#o",
		sockv.ss_actlabel.lt_level, sockv.ss_actlabel.lt_compart);
        usrv.sv_minlvl = sockv.ss_minlabel.lt_level;
        usrv.sv_actlvl = sockv.ss_actlabel.lt_level;
        usrv.sv_actcmp = sockv.ss_actlabel.lt_compart;
        usrv.sv_maxlvl = sockv.ss_maxlabel.lt_level;
        usrv.sv_valcmp = sockv.ss_maxlabel.lt_compart;
/*
 *		Shed trusted process information to ensure that
 *		forked and exec'd processes can not inherit such privilege.
 */
        usrv.sv_permit = 0;
        usrv.sv_intcls = 0;
        usrv.sv_maxcls = 0;

        ADD_PRIV(priv, PRIV_MAC_RELABEL_SUBJECT);

        if (setusrv(&usrv) < 0) {
            fatal ("%s(%d): setusrv(): %s\n",
			__FILE__, __LINE__, strerror(errno)); 
        }
        SET_PRIV(priv);
#ifdef DEBUG
	showusrv(&usrv);
#endif
/*
 *	    Setup a device label that may be used for the pseudo tty 
 *	    device.
 */
        ptylabel.dv_actlvl = sockv.ss_actlabel.lt_level;
        ptylabel.dv_actcmp = sockv.ss_actlabel.lt_compart;

        if (multilev_sock) {

            ptylabel.dv_minlvl = sockv.ss_minlabel.lt_level;
            ptylabel.dv_maxlvl = sockv.ss_maxlabel.lt_level;
            ptylabel.dv_valcmp = sockv.ss_maxlabel.lt_compart;

        } else {

            ptylabel.dv_minlvl = ptylabel.dv_maxlvl = ptylabel.dv_actlvl;
            ptylabel.dv_valcmp = ptylabel.dv_actcmp;
        }
        ptylabel.dv_devflg = 0;	/* I don't know what this does, but all the
				   examples I've seen set it to zero. */
    }
    debug ("get_unicos_connect_info done.");
}

void
get_udbent ( user )

    const char*	user;	/* user to lookup in the udb */
/*
 *  Purpose:
 *	Lookup user in the udb and set module-global udbent to point to
 *	a copy of the udb entry.
 *
 *  Preconditions:
 *	This program must have sufficient privilege to read the system
 *	copy of the udb.
 *
 *  Postconditions:
 *	Return if the user is found in the udb.  Module-global
 *	udbent will contain the information from the udb.
 *
 *  Invariants:
 *	If there is a udb lookup error, this routine calls function
 *	fatal to report the error; fatal does not return.
 */
{
    FLAGREG	ok;
    int		result;
    SECSTAT	secstat;
    UDB_t*	ue;

    debug("Find user [%s] in the udb.", user);

    getsysudb();
    ue = getudbnam ((char*)user);
    if ( ue == UDB_NULL ) {
#if RELEASE_LEVEL >= 9000
	fatal("%s(line %d) getudbnam(%s) failed: %s\n", 
		__FILE__, __LINE__, user, udb_strerror(udb_errno));
#else
	fatal("%s(line %d) getudbnam(%s) failed: udb errno %d\n", 
		__FILE__, __LINE__, user, udb_errno);
#endif
    }
/*
 *	Copy the udb entry point to by getudbnam for future use
 *	by other routines in this module.  If this is not
 *	done, other calls to getudb* functions, or getpw* calls
 *	(which turn around and use getpw*) will overwrite the 
 *	information.  This can be critical later when privilege is
 *	dropped and the udb security information is no longer available.
 */
    udbent = (UDB_t*) malloc (sizeof(UDB_t));
    memcpy (udbent, ue, sizeof(UDB_t));
    endudb();
}

logical
unicos_access_denied ()
{
/* Purpose:
 *	Determine if the user's access is blocked due to system login 
 *	restriction, account disabled, or the user is not allowed 
 *	interactive access.
 *
 *  Preconditions:
 *   o	Module-global udbent points to a udb entry describing the user.
 *
 *  Postconditions:
 *	Return true if the user is allowed to login, false otherwise.  
 *
 *  Invariants:
 *	If the user is system restricted, not allowed interactive access,
 *	or disabled, a login failure is not recorded in the UDB.
 */
    int		result;
    SECSTAT	secstat;
    time_t	system_time;

    debug("Determine if user [%s] is allowed access.", udbent->ue_name);

    if ( udbent->ue_permbits & PERMBITS_RESTRICTED ) {
        debug("User %s is system_restricted.", udbent->ue_name);
	packet_disconnect ("Login failed");

    } else if ( udbent->ue_permbits & PERMBITS_NOIACTIVE ) {
        debug("User %s is not allowed interactive jobs.", udbent->ue_name);
	packet_disconnect ("Login failed");

    } else if ( udbent->ue_disabled ) {
        debug("User %s is disabled.", udbent->ue_name);
	packet_disconnect ("Login failed");
    }
    debug ("User %s is allowed UNICOS access", udbent->ue_name);
    return (FALSE);
}

void
mls_validate ( havepty )

    logical havepty;	
{
/* Purpose:
 *	When MLS is active, ensure that the user is allowed to connect
 *	at the requested label.
 *
 *  Preconditions:
 *   o	SecureSys must reflect the current state of MLS on this system.
 *   o	stdout is connected and available, and properly labeled with the 
 *	security label of the connection.
 *   o	Module-global udbent points to a udb entry describing the user.
 *
 *  Postconditions:
 *	If SecureSys, then
 *	    Determine if the user is allowed to connect at the current
 *	    security label.  
 *	    If yes, then 
 *		this routine returns to the caller after
 *		updating fields in module-global usrv with security 
 *		validation information for the user on this connection 
 *		which can later be used to establish the security 
 *		the security validation information for this session.
 *	    If no, then 
 *		issue error messages, record a failed login attempt, 
 *		and terminate the program using packet_disconnect.
 *
 *	If !SecureSys, return without doing anything.
 *	
 *  Invariants:
 *   o	If havepty is TRUE, the security attributes of the connection
 *	are obtained from the tty device associated with stdout; otherwise,
 *	the attributes of stdout are used directly.  The later is
 *	straignt forward and is the prefered method for all cases, except 
 *	that pty's and controlling terminals and MLS make a convoluted 
 *	situation.  Thus the logical operation is 
 *	secstat (ttyname(stdout), ...) for pty's and fsecstat (stdout, ...)
 *	for non-pty connections.
 *
 *   o	If there is an error obtaining security information for the 
 *	stdout, this routine will report the error using routine
 *	fatal, which does not return.
 */
    int		result;
    SECSTAT	secinfo;
    char*	ttydevname;		/* tty device */

    debug("Determine if user [%s] is allowed access.", udbent->ue_name);

    if ( SecureSys ) {
	debug ("Get security attributes of stdout.");
	memset (&secinfo, 0, sizeof(SECSTAT));
	if ( havepty ) {
	    ttydevname = ttyname(fileno(stdout));
	    result = secstat (ttydevname, &secinfo);
	} else {		/* no pty, use fsecstat */
	    result = fsecstat (fileno(stdout), &secinfo);
	}
	if ( result == 0 ) {
	    debug ("[f]secstat successful, calling ia_mlsuser...");
	    debug ("stdout label is level %d, compart %#o\n",
		    secinfo.st_slevel, secinfo.st_compart);
	    result = ia_mlsuser (udbent, &secinfo, &usrv, /*rlabptr*/ (USRV*) NULL, 0);
	    if ( result == IA_NORMAL )	debug ("ia_mlsuser successful.");
	    else {
		debug ("ia_mlsuser failed.");
		record_login_failure( udbent->ue_name, result );
		packet_disconnect ("Login incorrect");
	    }

	} else fatal ("%s(%d) %csecstat(stdout) failed: %s.",
			__FILE__, __LINE__, 
			havepty ? ' ' : 'f', 
			strerror(errno));

#ifdef DEBUG
	    debug ("Connection label is valid");
	    showusrv (&usrv);
#endif
    }
}

static void
record_login_failure (user, reason)

    const char*	user;		/* the login name (moniker) */
    int		reason;		/* some sort of status code indicating the
				   reason for the failure, 0 == no reason
				   specified */
{
/*  Purpose:
 *	Record login failure in the udb.
 *
 *  Preconditions:
 *   o	Module-global udbent points to a udb entry describing the user.
 *
 *  Postconditions:
 *	Failure information is recorded in the user's UDB entry.
 */
    ia_failure_ret_t    fret;           /* Params returned from ia_failure   */
    ia_failure_t        fsent;          /* Parameters sent to ia_failure.    */
    JTAB		jobtable;
    char*		ttyp;

    memset (&fsent, 0, sizeof(ia_failure_t));
    getjtab (&jobtable);
    ttyp = ttyname(0);

    fsent.revision = 0;
    fsent.uname = (char*) user;
    fsent.host = connection_hostname;
    fsent.ttyn = ttyp;
    fsent.caller = IA_SSH;
    fsent.flags = IA_IDENTIFICATION;
    fsent.ueptr = udbent;
    fsent.jid = jobtable.j_jid;
    fsent.errcode = reason;
    fsent.pwdp = NULL;
    fsent.exitcode = 0;		/* 0 -> return to caller (don't exit) */

    fret.revision = 0;
    fret.normal = 0;

    ia_failure(&fsent, &fret);
}

static void 
unicos_auth_failed ( context )

	void*	context;
{
/*  Purpose:
 *	Cleanup routine which records login failure in a user's udb entry.  
 *	Usually called from do_fatal_cleanups after the authentication
 *	operation fails.
 *
 *  Preconditions:
 *	Context must point to a AUTHFAIL structure, properly initialized
 *	with the user and failure reason code.
 *
 *  Postconditions:
 *	Failure information is recorded in the user's UDB entry.
 *
 *  Invariants:
 *	This routine will only perform once.  All subsequent calls
 *	will produce no action.
 */
    static	int		already_called = 0;
		AUTHFAIL*	fi;

    if ( already_called++ ) debug ("Extra call No. %d to unicos_auth_failed",
				    already_called);
    else {
	fi = (AUTHFAIL*) context;
	record_login_failure ( fi->user, fi->reason_code );
    }
}

void
register_udb_authfail ( user ) 

	const char*  user;
{
}

void
cancel_udb_authfail()
{
}

static void 
job_termination_handler (int signum)
{
}

void
catch_jobsignal ()
{
}

void
ignore_jobsignal ()
{
}



void
set_connection_hostname (const char *hostname)
{
    strncpy (connection_hostname,hostname,sizeof(connection_hostname));
}

/** update_udb - update user database entry.
 *
 *  Author unknown.
 */
void
update_udb (uid_t uid, const char *user, const char *ttyname)
{

    int err;			/* return code */
    ia_success_ret_t sret;	/* parameters returned from ia_success */
    ia_success_t ssent;		/* Parameters sent to ia_success */

    /* Format parameters for ia_success() */
    ssent.revision = 1;			/* Select revision 1 update mode. */
    ssent.uname = strdup(user);
    ssent.host = strdup(connection_hostname);	/* Set remote hostname. */
    ssent.ttyn = strdup(ttyname);	/* Record tty name. */
    ssent.caller = IA_LOGIN;
    ssent.flags = IA_INTERACTIVE;
    ssent.ueptr = udbent;
    ssent.jid = 0;
    ssent.errcode = IA_NORMAL;
    ssent.us = &usrv;			/* Only used when MLS is enabled. */
    ssent.time = 1;			/* Request ue_logtime update. */
#if (RELEASE_LEVEL >= 9000) || (RELEASE_LEVEL == 2030)
    ssent.mask = IA_LOGHOST | IA_LOGLINE | IA_LOGTIME | IA_LOGFAILS;
#endif

    /* Format return block */
    sret.revision = 1;
    sret.normal = 0;

    /* Update UDB entry */
    if ((err = ia_success(&ssent,&sret)) != IA_NORMAL) {
	if (SecureSys != 0) {
	    debug ("Security auditing failed.");
	} else {
	    debug ("ia_success() failed, return code %d.", err);
	} /* if */
    } /* if */
    free (ssent.uname);
    free (ssent.host);
    free (ssent.ttyn);
    return;

} /* update_udb */
  
/** cray_setup - set up session/job on Crays.

 On a Cray, set the account number for the current process to the user's 
 default account. If the user has multiple account IDs, allow him/her to
 choose one.

 This routine also calls setjob to set up a Cray Job (also known 
 as a Session).  This is needed for CRI's Cray System Accounting 
 and SDSC's Resource Management accounting/management system.

 It also calls setlimit, to set up limits and permissions.
 
 Wayne Schroeder
 San Diego Supercomputer Center
 schroeder@sdsc.edu
 
*/
int
cray_setup (uid_t uid, const char *username)
{
  int err;			/* error return */
  int jid;			/* job ID */
  pid_t pid;			/* process ID */
  struct secstat sb;		/* file security parameters */
  char *sr;			/* status return from setlimits() */

  /* Set account ID */
  acidburn (udbent);


  /* Now call setjob to create a new job(/session).  This assigns a new Session
     ID and session table entry to the calling process.  This process will be
     the first process in the job/session.

     Setting the second argument to 0 means that no signal will be
     generated when the job terminates.  Previously the second argument
     was sent to WJSIGNAL (SIGCRAY13), but since there was no call to
     waitjob() this wasn't useful.  (It could be used to clean up
     a temporary directory.)  See Globus Req #3010.
             -- Keith Thompson, kst@sdsc.edu
     */
  if ((jid = setjob (uid, 0)) < 0) {
      debug("System call setjob failure: %s", strerror(errno));
      packet_disconnect("System call setjob failure.");
  }

#ifdef CREATE_TMPDIR
  /* Create user's temporary directory. */
  TmpDir = (char*) makejtmp (jid);
  if ( TmpDir == NULL ) {
    debug ("could not create temporary directory for %s", udbent->ue_name);
  } else debug ("Tmp dir is %s\n", TmpDir);
#endif 

  /* Now set limits, including CPU time for the (interactive) job and process,
     and set up permissions (for chown etc), etc.  This is via an internal CRI
     routine, setlimits, used by CRI's login. */
  pid = getpid();
  if ((sr = setlimits(username, C_PROC, pid, UDBRC_INTER)) != NULL) {
      debug("setlimits(C_PROC) failure: %s", sr);
      packet_disconnect("setlimits(C_PROC) failure.");
  } /* if */
  if ((sr = setlimits(username, C_JOB, jid, UDBRC_INTER)) != NULL) {
      debug("setlimits(C_JOB) failure: %s", sr);
      packet_disconnect("setlimits(C_JOB) failure.");
  } /* if */

  return(0);
}

/** acidburn - set account ID.
 *
 *  If the user is permitted to choose
 *  an account ID, too bad... set
 *  the acid from the first account ID found in the UDB entry.
 */
static void
acidburn (const UDB_t* ue)
{
    int		acid;		/* account ID */

    /* Set account ID */

    acid = ue->ue_acids[0];

    if (acctid(0, acid) < 0) {
	fprintf (stderr, "Invalid account ID: %d\n", acid);
	exit(1);
    }
    
   /*	Establish the resource group for fair share (or other) 
    	resource scheduler.  */
    
    if ( setshares (ue->ue_uid, acid, error, 0, 0)) {
	fatal ("Unable to give %d shares to <%s>(%d/%d)\n",
		ue->ue_shares, ue->ue_name, ue->ue_uid, acid);
    }

    return;
}

static const char*
makejtmp(jid)

    register	int	jid;
{
    return(NULL);
}

static int
mkjobdir ( jobdir, mode, owner, group, level, compart )

    const char*	jobdir;		/* name (path) of the directory */
    int		mode;		/* directory permission mode */
    uid_t	owner;		/* owner of the directory */
    gid_t	group;		/* group of the directory */
    int		level;		/* security level */
    long	compart;	/* compartment */
{
    return (0);
}

static char*
jtmp_dir ( path, create, level, compart )

    long*	compart;
    logical	create;
    int*	level;
    const char*	path;
{
    return (NULL);
}

void
set_seclabel ()
/*
 *  Purpose:
 *	Change security attributes for the user and clear all privilege
 *	prior to starting the user process.
 *
 *  Preconditions:
 *	Module-global usrv must specify the user's security attributes.
 *
 *  Postconditions:
 *	Return iff the call to setusrv is successful, otherwise 
 *	report a fatal error through function fatal (which does not
 *	return).
 *
 *  Invariants:
 *	If MLS is not active, this routine returns without doing anything.
 *
 *-------------------------*/
{
    PRIVS*	privstate;
    int		result;

    extern	int	priv_set_proc();
    extern	PRIVS*	priv_init_proc();

    if (SecureSys) {
	debug ("Set user's security label.");
#ifdef DEBUG
	    showusrv (&usrv);
	    showprivs ();
#endif
#if 1
	if (setusrv(&usrv) < 0) fatal ("%s(%d): setusrv(): %s\n",
					__FILE__, __LINE__, strerror(errno)); 
#endif
    }
    if ( use_priv && sysconf(_SC_CRAY_POSIX_PRIV) ) {

	debug ("Dropping privileges.");
        if ((privstate = priv_init_proc()) != NULL) {
            result = priv_set_proc(privstate);
	    if ( result != 0 ) fatal ("%s(%d): priv_set_proc(): %s\n",
					__FILE__, __LINE__, strerror(errno)); 
            priv_free_proc(privstate);
        }
#ifdef DEBUG
	    debug ("Privileges should be cleared...");
	    showprivs ();
#endif
    }
}

static void
remove_jtmpdir ( jid )
    int	jid;
{
    return;
}

static void
cleanjtmp(user, tpath)
    const char*	user;
    const char*	tpath;
{
}


/*	MLS Debugging Aids  */

#include <sys/sectab.h>
typedef struct	sectab	SECTAB;

#include <pwd.h>
#include <grp.h>

typedef struct	passwd	PWENT;
typedef struct	group	GRPENT;

static	SECTAB	privtab;
static	int	privtab_read = 0;

static char*
namestring ( char** namelist )
{
/*  Purpose:
 *	Return a pointer to a buffer containing the items in
 *	namelist separated by commas.
 *
 *  Invariants:
 *	You may call this routine up to 4 times and still get a pointer
 *	to a unique string.
 */
static	char	buf[4][1024];
static	char	bn;

    bn = ++bn % 4;
    for ( buf[bn][0] = '\0'; *namelist != NULL; ) {
	strcat (buf[bn], *namelist);
	namelist++;
	if ( *namelist != NULL ) strcat (buf[bn],",");
    }
    return (buf[bn]);
}

static void
PrivNames ( priv_value_t privmask )
{
/*  Purpose:
 *	Print the named equivalent of all bits set if privmask.
 *	The format is a leading tab, followed by up to 72 characters
 *	of privilege names.  Individual privilege names are separated
 *	by a space character.
 *
 *  Invariants:
 *	Function "debug" is used to display the information.  If the
 *	debug flag is not set, nothing will be displayed.
 */
	char	buf[80];
	int	buflen;
	int	i;
	int	len;

    for ( i = 0, buflen = 0; i < MAXNAMES; i++ ) {
	if ( (privtab.tb_num[i] & privmask) == 0 ) continue;
	len = strlen (privtab.tb_name[i]);
	if ((buflen + len + 1) > 72 ) {
	    debug ("\t%s", buf);
	    buflen = 0;
	}
	if (buflen == 0) buf[0] = '\0';
	else strcat (buf, " ");
	strcat (buf, privtab.tb_name[i]);
	buflen += len + 1;
    }
    if (buflen > 0 ) debug ("\t%s", buf);
}

void
showusrv ( usrv )

    const USRV*	usrv;
{
/*  Purpose:
 *	Display usr, group, and the security information in secval.
 *
 *  Invariants:
 *   o	Function "debug" is used to display the information.  If the
 *	debug flag is not set, nothing will be displayed.
 *   o	If secval is NULL, then this routine calls getusrv and displays
 *	the information returned.
 */
    int		euid;		/* effective user id */
    int		egid;		/* effective group id */
    int		gid;		/* group id */
    GRPENT*	grpent;		/* group file entry */
    char*	namelist[MAXNAMES+1];	/* list of pointers to security names */
    char*	namelist2[MAXNAMES+1];	/* list of pointers to security names */
    int		ok = 1;		/* all ok flag */
    priv_proc_t	privbuf;	/* privileges */
    USRV	pusrv;		/* process user validation information */
    USRV*	secval;		/* pointer to usr validation structure */
    PWENT*	pwent;		/* password file entry */
    int		uid;		/* user id */
/*
 *	Begin execution
 */
    uid = getuid();
    gid = getgid();
    euid = geteuid();
    egid = getegid();

    pwent = getpwuid (uid);
    grpent = getgrgid (gid);

    debug ("     uid %d(%s),  gid %d(%s)", 
		 uid, pwent->pw_name, gid, grpent->gr_name);

    pwent = getpwuid (euid);
    grpent = getgrgid (egid);

    debug ("    euid %d(%s), egid %d(%s)", 
		euid, pwent->pw_name, egid, grpent->gr_name);

    if ( SecureSys ) {

	if ( usrv == NULL ) {	/* get process usrv information */
	    if (getusrv(&pusrv) == 0 ) secval = &pusrv;
	    else {
		debug ("%s(%d): getusrv() failed: %s\n",
			    __FILE__, __LINE__, strerror(errno)); 
		return;
	    }
    
	} else secval = (USRV*) usrv;	/* use supplied usrv structure */

	if (! privtab_read) {
	    privtab_read = getsectab(PRVTAB, &privtab) == 0;
	    if (!privtab_read) {
		error ("Unable to get privilege table(getsectab): %s", 
			strerror(errno));
		return;
	    }
	}
	secwords (secval->sv_actlvl, namelist, SECNAMES_ACTLVL);
	debug ("    Security level:  active %d (%s).", 
		secval->sv_actlvl, namelist[0]);

	secwords (secval->sv_minlvl, namelist, SECNAMES_VMINLVL);
	secwords (secval->sv_maxlvl, namelist2, SECNAMES_VMAXLVL);
	debug ("    Valid levels: %d (%s) <-> %d (%s)", 
			secval->sv_minlvl, namelist[0],
			secval->sv_maxlvl, namelist2[0]);

	secnames (secval->sv_actcmp, namelist, SECNAMES_ACTCMP);
	secnames (secval->sv_valcmp, namelist2, SECNAMES_VALCMP);
	debug ("    Compartments:  active 0%o (%s); valid 0%o (%s)", 
			secval->sv_actcmp, namestring(namelist),
			secval->sv_valcmp, namestring(namelist2));

	secnames (secval->sv_intcat, namelist, SECNAMES_VALCAT);
	secnames (secval->sv_valcat, namelist2, SECNAMES_ACTCAT);
	debug ("    Categories:  active (%s), valid (%s)", 
			namestring(namelist),
			namestring(namelist2));

	secwords (secval->sv_intcls, namelist, SECNAMES_ACTCLS);
	secwords (secval->sv_maxcls, namelist2, SECNAMES_VMAXCLS);
	debug ("    Class:  active %d (%s); valid max %d (%s)", 
			secval->sv_intcls, namelist[0],
			secval->sv_maxcls, namelist2[0]);

	secnames (secval->sv_permit, namelist, SECNAMES_PERMIT);
	debug ("    Permissions:  0%o (%s)", secval->sv_permit, 
			namestring(namelist));
    }
    return;
}
void
showprivs ()
{
/*  Purpose:
 *	Display process privilege information for this program.
 *
 *  Invariants:
 *	Function "debug" is used to display the information.  If the
 *	debug flag is not set, nothing will be displayed.
 */
    int		ok = 1;			/* all ok flag */
    char*	namelist[MAXNAMES+1];	/* list of pointers to security names */
    priv_proc_t	privbuf;		/* privileges */
 
    if ( SecureSys ) {

        if (! privtab_read) {
            ok = getsectab(PRVTAB, &privtab) == 0;
            if (!ok) error ("Unable to get privilege table(getsectab): %s",
                     	   strerror(errno));
            else privtab_read = 1;
	}
        if (ok) {
	    ok = getppriv (&privbuf, sizeof(priv_proc_t)) == 0;
	    if (!ok) error ("Unable to get privilege sets (getppriv): %s",
				strerror(errno));
	}
	if (ok) {

	    debug ("    Effective privileges: 0%o", privbuf.pv_priveff);
	    PrivNames ( privbuf.pv_priveff );
	    debug ("    Permitted privileges: 0%o", privbuf.pv_privprm); 
	    PrivNames ( privbuf.pv_privprm );
	}
    }
    return;
}

int unicos_get_gid()
{
    return udbent->ue_gids[0];
}

#endif	/* TARGET_ARCH_CRAYT3E */
