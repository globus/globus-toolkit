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
/* FTP server. */
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/wait.h>

#ifdef AIX
#include <sys/id.h>
#include <sys/priv.h>
#include <netinet/if_ether.h>
#include <net/if_dl.h>
#endif

#ifdef AUX
#include <compat.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#define FTP_NAMES
#include "../support/ftp.h"
#include <arpa/inet.h>
#include <arpa/telnet.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#ifdef INTERNAL_LS
#ifdef HAVE_GLOB_H
#include <glob.h>
#else
#include <wuftpd_glob.h>
#endif
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <sys/stat.h>

#define VA_LOCAL_DECL	va_list ap;
#define VA_START(f)	va_start(ap, f)
#define VA_END		va_end(ap)

#include "globus_common.h"

/**** added by JB **********/
#if defined(THROUGHPUT)
#   define SEND_DATA(__name, __instr, __outstr, __blksize, __logical_offset, __length)    \
        send_data(__name, __instr, __outstr, __blksize, __logical_offset, __length)
#else
#   define SEND_DATA(__name, __instr, __outstr, __blksize, __logical_offset, __length)    \
        send_data(__instr, __outstr, __blksize, __length)
#endif

#include "proto.h"

#ifdef HAVE_UFS_QUOTA_H
#include <ufs/quota.h>
#endif
#ifdef HAVE_SYS_FS_UFS_QUOTA_H
#include <sys/fs/ufs_quota.h>
#endif

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
#include "conversions.h"
#include "extensions.h"

#ifdef SHADOW_PASSWORD
#include <shadow.h>
#endif

#include "pathnames.h"

#ifdef M_UNIX
#include <arpa/nameser.h>
#include <resolv.h>
#endif

#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif

#ifdef HAVE_SYSINFO
#include <sys/systeminfo.h>
#endif

#ifdef KERBEROS
#include <sys/types.h>
#include <auth.h>
#include <krb.h>
#endif

#ifdef ULTRIX_AUTH
#include <auth.h>
#include <sys/svcinfo.h>
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#ifdef AFS_AUTH
#include <afs/stds.h>
#include <afs/kautils.h>
#endif

#ifdef DCE_AUTH
#include <dce/rpc.h>
#include <dce/sec_login.h>
#include <dce/dce_error.h>
#endif


#ifdef HAVE_DIRENT_H
#include <dirent.h>
#else
#include <sys/dir.h>
#endif

#ifdef HAVE_GETRLIMIT
#include <sys/resource.h>
#endif

#if defined(USE_LONGJMP)
#define wu_longjmp(x, y)	longjmp((x), (y))
#define wu_setjmp(x)		setjmp(x)
#ifndef JMP_BUF
#define JMP_BUF			jmp_buf
#endif
#else
#define wu_longjmp(x, y)	siglongjmp((x), (y))
#define wu_setjmp(x)		sigsetjmp((x), 1)
#ifndef JMP_BUF
#define JMP_BUF			sigjmp_buf
#endif
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64	/* may be too big */
#endif

#ifndef TRUE
#define  TRUE   1
#endif

#ifndef FALSE
#define  FALSE  !TRUE
#endif

#ifdef GSSAPI

#include "gssapi-local.h"

/* User has passed all GSSAPI authentication and authorization checks */
int gssapi_user_is_good = 0;

/* User must perform GSSAPI authentication */
int gssapi_authentication_required = 1;

#endif /* GSSAPI */

#ifdef GLOBUS_AUTHORIZATION

/*
 * Code to use in reply messages if permission is denied due to
 * authorization failure.
 */
#define GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE       553

/*
 * Syslog level to use for logging messages due to authorization failure.
 */
#define GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL     LOG_NOTICE

/*
 * Buffer for returning error strings from ftp_authorization routines.
 * The number 256 is arbitraty.
 */
char ftp_authorization_error_buffer[256];

#endif /* GLOBUS_AUTHORIZATION */

#ifdef FTP_SECURITY_EXTENSIONS

#include "secure_ext.h"

#else /* !FTP_SECURITY_EXTENSIONS */

#define LARGE_BUFSIZE		BUFSIZ

#endif /* !FTP_SECURITY_EXTENSIONS */


#ifdef MAIL_ADMIN
#define MAILSERVERS 10
#define INCMAILS 10
int mailservers = 0;
char *mailserver[MAILSERVERS];
int incmails = 0;
char *incmail[INCMAILS];
char *mailfrom;
char *email(char *full_address);
FILE *SockOpen(char *host, int clientPort);
char *SockGets(FILE *sockfp, char *buf, int len);
int SockWrite(char *buf, int size, int nels, FILE *sockfp);
int SockPrintf(FILE *sockfp, char *format,...);
int SockPuts(FILE *sockfp, char *buf);
int Reply(FILE *sockfp);
int Send(FILE *sockfp, char *format,...);
#endif /* MAIL_ADMIN */

#if defined(_SCO_DS) && !defined(SIGURG)
#define SIGURG	SIGUSR1
#endif


/*
 *  globus code added by JB
 */
#ifdef USE_GLOBUS_DATA_CODE
extern globus_ftp_control_handle_t               g_data_handle;
extern char *                                    g_perf_log_file_name;
extern int
gsi_wuftp_get_version(void);
#endif


/* File containing login names NOT to be used on this machine. Commonly used
 * to disallow uucp. */
extern int errno;
extern int pidfd;

extern char *ctime(const time_t *);
#ifndef NO_CRYPT_PROTO
extern char *crypt(const char *, const char *);
#endif

extern char *version;
extern char *home;		/* pointer to home directory for glob */
extern char cbuf[];
extern off_t restart_point;
extern int yyerrorcalled;

struct sockaddr_in ctrl_addr;
struct sockaddr_in data_source;
struct sockaddr_in data_dest;
struct sockaddr_in his_addr;
struct sockaddr_in pasv_addr;
struct sockaddr_in vect_addr;
int route_vectored = 0;
int passive_port_min = -1;
int passive_port_max = -1;
int restricted_user = 0;

#ifdef VIRTUAL
char virtual_root[MAXPATHLEN];
char virtual_banner[MAXPATHLEN];
char virtual_email[MAXPATHLEN];

char virtual_hostname[MAXHOSTNAMELEN];
char virtual_address[MAXHOSTNAMELEN];

char hostaddress[32];

extern int virtual_mode;
extern int virtual_ftpaccess;
#endif

#ifdef QUOTA
extern struct dqblk quota;
#endif

int data;
jmp_buf errcatch;
JMP_BUF urgcatch;
int logged_in = 0;
struct passwd *pw;
char chroot_path[MAXPATHLEN];
int debug = 0;
int disable_rfc931 = 0;
extern unsigned int timeout_idle;
extern unsigned int timeout_maxidle;
extern unsigned int timeout_data;
extern unsigned int timeout_accept;
extern unsigned int timeout_connect;

/* previously defaulted to 1, and -l or -L set them to 1, so that there was
   no way to turn them *off*!  Changed so that the manpage reflects common
   sense.  -L is way noisy; -l we'll change to be "just right".  _H */
int logging = 0;
int log_commands = 0;
int log_security = 0;
int syslogmsg = 0;
static int wtmp_logging = 1;
static int debug_no_fork = 0;

#ifdef SECUREOSF
#define SecureWare		/* Does this mean it works for all SecureWare? */
#endif

#ifdef HPUX_10_TRUSTED
#include <hpsecurity.h>
#endif

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
#include <prot.h>
#endif

int anonymous = 1;
int guest;
int type;
int form;
int stru;			/* avoid C keyword */
int mode;
int usedefault = 1;		/* for data transfers */
int pdata = -1;			/* for passive mode */
int transflag;
int ftwflag;
off_t file_size;
off_t byte_count;
int TCPwindowsize = 0;		/* 0 = use system default */

#ifdef TRANSFER_COUNT
int data_count_total = 0;	/* total number of data bytes */
int data_count_in = 0;
int data_count_out = 0;
int byte_count_total = 0;	/* total number of general traffic */
int byte_count_in = 0;
int byte_count_out = 0;
int file_count_total = 0;	/* total number of data files */
int file_count_in = 0;
int file_count_out = 0;
int xfer_count_total = 0;	/* total number of transfers */
int xfer_count_in = 0;
int xfer_count_out = 0;
#ifdef TRANSFER_LIMIT
int file_limit_raw_in = 0;
int file_limit_raw_out = 0;
int file_limit_raw_total = 0;
int file_limit_data_in = 0;
int file_limit_data_out = 0;
int file_limit_data_total = 0;
int data_limit_raw_in = 0;
int data_limit_raw_out = 0;
int data_limit_raw_total = 0;
int data_limit_data_in = 0;
int data_limit_data_out = 0;
int data_limit_data_total = 0;
#ifdef RATIO /* 1998/08/04 K.Wakui */
#define TRUNC_KB(n)   ((n)/1024+(((n)%1024)?1:0))
off_t   total_free_dl = 0;
int     upload_download_rate = 0;
int     freefile;
int     is_downloadfree( char * );
#endif /* RATIO */
#endif
#endif

int retrieve_is_data = 1;	/* !0=data, 0=general traffic -- for 'ls' */
char LastFileTransferred[MAXPATHLEN] = "";

static char *RootDirectory = NULL;

#if !defined(CMASK) || CMASK == 0
#undef CMASK
#define CMASK 022
#endif
mode_t defumask = CMASK;	/* default umask value */
#ifdef ALTERNATE_CD
char defhome[] = "/";
#endif
char tmpline[7];
char hostname[MAXHOSTNAMELEN];
char remotehost[MAXHOSTNAMELEN];
char remoteaddr[MAXHOSTNAMELEN];
char *remoteident = "[nowhere yet]";

/* log failures         27-apr-93 ehk/bm */
#ifdef LOG_FAILED
#define MAXUSERNAMELEN	256
char the_user[MAXUSERNAMELEN];
#endif

/* Access control and logging passwords */
/* OFF by default.  _H */
int use_accessfile = 0;
char guestpw[MAXHOSTNAMELEN];
char privatepw[MAXHOSTNAMELEN];
int nameserved = 0;
extern char authuser[];
extern int authenticated;
extern int keepalive;

/* File transfer logging */
int xferlog = 0;
int log_outbound_xfers = 0;
int log_incoming_xfers = 0;
char logfile[MAXPATHLEN];

/* Allow use of lreply(); this is here since some older FTP clients don't
 * support continuation messages.  In violation of the RFCs... */
int dolreplies = 1;

/* Spontaneous reply text.  To be sent along with next reply to user */
char *autospout = NULL;
int autospout_free = 0;

/* allowed on-the-fly file manipulations (compress, tar) */
int mangleopts = 0;

/* number of login failures before attempts are logged and FTP *EXITS* */
int lgi_failure_threshold = 5;

/* Timeout intervals for retrying connections to hosts that don't accept PORT
 * cmds.  This is a kludge, but given the problems with TCP... */
#define SWAITMAX    90		/* wait at most 90 seconds */
#define SWAITINT    5		/* interval between retries */

int swaitmax = SWAITMAX;
int swaitint = SWAITINT;

SIGNAL_TYPE lostconn(int sig);
SIGNAL_TYPE randomsig(int sig);
SIGNAL_TYPE myoob(int sig);
FILE *getdatasock(char *mode);
FILE *dataconn(char *name, off_t size, char *mode);
void setproctitle(const char *fmt,...);
void initsetproctitle(int, char **, char **);
void reply(int, char *fmt,...);
void lreply(int, char *fmt,...);

#ifndef HAVE_VSNPRINTF
extern int vsnprintf(char *, size_t, const char *, va_list);
#endif

#ifndef HAVE_SNPRINTF
extern int snprintf(char *, size_t, const char *,...);
#endif

#ifdef HAVE_LIBRESOLV
int initialize_dns(struct sockaddr_in *remote_socket);
int check_reverse_dns(void);
int check_matching_dns(void);
#endif

#ifdef NEED_SIGFIX
extern sigset_t block_sigmask;	/* defined in sigfix.c */
#endif

char proctitle[BUFSIZ];		/* initial part of title */

#if defined(SKEY) && defined(OPIE)
#error YOU SHOULD NOT HAVE BOTH SKEY AND OPIE DEFINED!!!!!
#endif

#ifdef SKEY
#include <skey.h>
int pwok = 0;
#endif

#ifdef OPIE
#include <opie.h>
int pwok = 0;
int af_pwok = 0;
struct opie opiestate;
#endif

#ifdef KERBEROS
void init_krb();
void end_krb();
char krb_ticket_name[100];
#endif /* KERBEROS */

#ifdef ULTRIX_AUTH
int ultrix_check_pass(char *passwd, char *xpasswd);
#endif

#ifdef USE_PAM
#if defined(ULTRIX_AUTH) || defined(SECUREOSF) || defined(KERBEROS) || defined(SKEY) || defined (OPIE) || defined (BSD_AUTH)
#error No other auth methods are allowed with PAM.
#endif
static int pam_check_pass(char *user, char *passwd);
#endif

#ifndef INTERNAL_LS
/* ls program commands and options for lreplies on and off */
char ls_long[1024];
char ls_short[1024];
char ls_plain[1024];
#endif

#ifdef DAEMON
int be_daemon = 0;		/* Run standalone? */
int daemon_port = -1;
void do_daemon(int argc, char **argv, char **envp);
#endif
int Bypass_PID_Files = 0;

#ifdef OTHER_PASSWD
#include "getpwnam.h"
char _path_passwd[MAXPATHLEN];
#ifdef SHADOW_PASSWORD
char _path_shadow[MAXPATHLEN];
#endif
#endif
#if defined(USE_PAM) && defined(OTHER_PASSWD)
int use_pam = 1;
#else
int use_pam = 0;
#endif

void end_login(void);
void print_copyright(void);
char *mapping_getcwd(char *path, size_t size);

#ifdef THROUGHPUT
int send_data(char *name, FILE *, FILE *, off_t, int);
#else
int send_data(FILE *, FILE *, off_t, int);
#endif

void dolog(struct sockaddr_in *);
void dologout(int);
void perror_reply(int, char *);
int denieduid(uid_t);
int alloweduid(uid_t);
int deniedgid(gid_t);
int allowedgid(gid_t);
int restricteduid(uid_t);
int unrestricteduid(uid_t);
int restrictedgid(gid_t);
int unrestrictedgid(gid_t);

#ifdef THROUGHPUT
extern void throughput_calc(char *, int *, double *);
extern void throughput_adjust(char *);
#endif

time_t login_time;
time_t limit_time = 0;

int regexmatch(char *name, char *rgexp);

int pasv_allowed(char *remoteaddr);
int port_allowed(char *remoteaddr);

#if sparc && !__svr4__
int fclose(FILE *);
#endif

static SIGNAL_TYPE alarm_signal(int sig)
{
}

static FILE *draconian_FILE = NULL;

static SIGNAL_TYPE draconian_alarm_signal(int sig)
{
    if (draconian_FILE != NULL) {
	fclose(draconian_FILE);
	draconian_FILE = NULL;
    }
}

static void socket_flush_wait(FILE *file)
{
#ifndef SUPPORT_BROKEN_CLIENTS
    char c;
    int fd = fileno(file);
    if (draconian_FILE != NULL)
	shutdown(fd, 1);
    if (draconian_FILE != NULL)
	read(fd, &c, 1);
/*
 * GAL - the read() here should be checked to ensure it returned 0 (indicating
 * EOF) or -1 (an error occurred).  Anything else (real data) is a protocol
 * error.
 */
#endif
}

int main(int argc, char **argv, char **envp)
{
int i = 0;
#if defined(UNIXWARE) || defined(AIX)
    size_t addrlen;
#else
    int addrlen;
#endif
    int on = 1;
#ifdef IPTOS_LOWDELAY
    int tos;
#endif
    int c;
#ifndef INTERNAL_LS
    int which;
#endif
    extern int optopt;
    extern char *optarg;
    struct hostent *shp;
    struct aclmember *entry;
#ifdef VIRTUAL
#if defined(UNIXWARE) || defined(AIX)
    size_t virtual_len;
#else
    int virtual_len;
#endif
    struct sockaddr_in *virtual_ptr;
    struct sockaddr_in virtual_addr;
#endif
#ifndef DAEMON
    struct servent *serv;
#endif
#ifdef GLOBUS_AUTHORIZATION
    char *my_hostname = 0;
    char *authz_cfg_file = 0;
#endif

    extern char **environ;
    
    /* generate version string; populates char * version global*/
    gsi_wuftp_get_version();
    
#ifdef AUX
    setcompat(COMPAT_POSIX | COMPAT_BSDSETUGID);
#endif

    closelog();
#ifdef FACILITY
    openlog("gridftpd", LOG_PID | LOG_NDELAY, FACILITY);
#else
    openlog("gridftpd", LOG_PID);
#endif

#ifdef SecureWare
    setluid(1);			/* make sure there is a valid luid */
    set_auth_parameters(argc, argv);
    setreuid(0, 0);
#endif
#if defined(M_UNIX) && !defined(_M_UNIX)
    res_init();			/* bug in old (1.1.1) resolver     */
    _res.retrans = 20;		/* because of fake syslog in 3.2.2 */
    setlogmask(LOG_UPTO(LOG_INFO));
#endif

#ifndef DAEMON
    addrlen = sizeof(his_addr);
    if (getpeername(0, (struct sockaddr *) &his_addr, &addrlen) < 0) {
	syslog(LOG_ERR, "getpeername (%s): %m", argv[0]);
#ifndef DEBUG
	exit(1);
#endif
    }
    addrlen = sizeof(ctrl_addr);
    if (getsockname(0, (struct sockaddr *) &ctrl_addr, &addrlen) < 0) {
	syslog(LOG_ERR, "getsockname (%s): %m", argv[0]);
#ifndef DEBUG
	exit(1);
#endif
    }
#ifdef IPTOS_LOWDELAY
    tos = IPTOS_LOWDELAY;
    if (setsockopt(0, IPPROTO_IP, IP_TOS, (char *) &tos, sizeof(int)) < 0)
	    syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif

    serv = getservbyname("ftp-data", "tcp");
    if (serv != NULL)
	data_source.sin_port = serv->s_port;
    else
	data_source.sin_port = htons(ntohs(ctrl_addr.sin_port) - 1);
    data_source.sin_port = 0;
#endif /* DAEMON */

#ifndef DAEMON
    while ((c = getopt(argc, argv, ":aAvdlLiIoPZ:qQr:t:T:u:wVWX1G:H:C")) != -1) {
#else /* DAEMON */
    while ((c = getopt(argc, argv, ":aAvdlLiIop:Z:P:qQr:sSt:T:u:VwWX1G:H:C")) != -1) {
#endif /* DAEMON */
	switch (c) {

	case 'a':
	    use_accessfile = 1;
	    break;

	case 'A':
	    use_accessfile = 0;
	    break;

	case 'v':
	    debug = 1;
	    break;

	case 'd':
	    debug = 1;
	    break;

	case 'l':
	    logging = 1;
	    break;

	case 'L':
	    log_commands = 1;
	    break;

	case 'i':
	    log_incoming_xfers = 1;
	    break;

	case 'I':
	    disable_rfc931 = 1;
	    break;

	case 'o':
	    log_outbound_xfers = 1;
	    break;

	case 'q':
	    Bypass_PID_Files = 0;
	    break;

	case 'Q':
	    Bypass_PID_Files = 1;
	    break;

	case 'r':
	    if ((optarg != NULL) && (optarg[0] != '\0')) {
		RootDirectory = malloc(strlen(optarg) + 1);
		if (RootDirectory != NULL)
		    strcpy(RootDirectory, optarg);
	    }
	    break;

	case 'P':
	    data_source.sin_port = htons(atoi(optarg));
	    data_source.sin_port = 0;
	    break;

#if defined(USE_GLOBUS_DATA_CODE)
        case 'Z':
            g_perf_log_file_name = strdup(optarg);
            break;
#endif

#ifdef DAEMON
	case 'p':
	    daemon_port = atoi(optarg);
	    break;

	case 's':
	    be_daemon = 1;
	    break;

	case 'S':
	    be_daemon = 2;
	    break;
#endif /* DAEMON */

	case 't':
	    timeout_idle = atoi(optarg);
	    if (timeout_maxidle < timeout_idle)
		timeout_maxidle = timeout_idle;
	    break;

	case 'T':
	    timeout_maxidle = atoi(optarg);
	    if (timeout_idle > timeout_maxidle)
		timeout_idle = timeout_maxidle;
	    break;

	case 'u':
	    {
		unsigned int val = 0;

		while (*optarg && *optarg >= '0' && *optarg <= '9')
		    val = val * 8 + *optarg++ - '0';
		if (*optarg || val > 0777)
		    syslog(LOG_ERR, "bad value for -u");
		else
		    defumask = val;
		break;
	    }

	case 'V':
	    print_copyright();
	    exit(0);
	    /* NOTREACHED */
	case 'w':
	    wtmp_logging = 1;
	    break;

	case 'W':
	    wtmp_logging = 0;
	    break;

	case 'x':
	    syslogmsg = 2;
	    break;

	case 'X':
	    syslogmsg = 1;
	    break;

	case ':':
	    syslog(LOG_ERR, "option -%c requires an argument", optopt);
	    break;

	case '1':
	    debug_no_fork = 1;
	    break;

    case 'C':
        gssapi_authentication_required = 0;
        break;
        
	case 'G':
	    globus_libc_setenv("GLOBUS_LOCATION", optarg, 1);
	    break;

	case 'H':
#ifdef GLOBUS_AUTHORIZATION
	    my_hostname = strdup(optarg);
#else
	    syslog(LOG_ERR, "Not built with Globus authorization libraries: -%c option ignored", optopt);
#endif
	    break;
	default:
	    syslog(LOG_ERR, "unknown option -%c ignored", optopt);
	    break;
	}
    }
    initsetproctitle(argc, argv, environ);
    (void) freopen(_PATH_DEVNULL, "w", stderr);

    /* Checking for random signals ... */
#ifdef NEED_SIGFIX
    sigemptyset(&block_sigmask);
#endif
#ifndef SIG_DEBUG
#ifdef SIGHUP
    (void) signal(SIGHUP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGHUP);
#endif
#endif
#ifdef SIGINT
    (void) signal(SIGINT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGINT);
#endif
#endif
#ifdef SIGQUIT
    (void) signal(SIGQUIT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGQUIT);
#endif
#endif
#ifdef SIGILL
    (void) signal(SIGILL, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGILL);
#endif
#endif
#ifdef SIGTRAP
    (void) signal(SIGTRAP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTRAP);
#endif
#endif
#ifdef SIGIOT
    (void) signal(SIGIOT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGIOT);
#endif
#endif
#ifdef SIGEMT
    (void) signal(SIGEMT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGEMT);
#endif
#endif
#ifdef SIGFPE
    (void) signal(SIGFPE, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGFPE);
#endif
#endif
#ifdef SIGKILL
    (void) signal(SIGKILL, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGKILL);
#endif
#endif
#ifdef SIGBUS
    (void) signal(SIGBUS, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGBUS);
#endif
#endif
#ifdef SIGSEGV
    (void) signal(SIGSEGV, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGSEGV);
#endif
#endif
#ifdef SIGSYS
    (void) signal(SIGSYS, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGSYS);
#endif
#endif
#ifdef SIGALRM
    (void) signal(SIGALRM, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGALRM);
#endif
#endif
#ifdef SIGSTOP
    (void) signal(SIGSTOP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGSTOP);
#endif
#endif
#ifdef SIGTSTP
    (void) signal(SIGTSTP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTSTP);
#endif
#endif
#ifdef SIGTTIN
    (void) signal(SIGTTIN, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTTIN);
#endif
#endif
#ifdef SIGTTOU
    (void) signal(SIGTTOU, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTTOU);
#endif
#endif
#ifdef SIGIO
    (void) signal(SIGIO, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGIO);
#endif
#endif
#ifdef SIGXCPU
    (void) signal(SIGXCPU, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGXCPU);
#endif
#endif
#ifdef SIGXFSZ
    (void) signal(SIGXFSZ, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGXFSZ);
#endif
#endif
#ifdef SIGWINCH
    (void) signal(SIGWINCH, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGWINCH);
#endif
#endif
#ifdef SIGVTALRM
    (void) signal(SIGVTALRM, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGVTALRM);
#endif
#endif
    if(! debug_no_fork)
    {
#ifdef SIGPROF
    (void) signal(SIGPROF, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGPROF);
#endif
    ;
    }
    
#endif
#ifdef SIGUSR1
    (void) signal(SIGUSR1, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGUSR1);
#endif
#endif
#ifdef SIGUSR2
    (void) signal(SIGUSR2, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGUSR2);
#endif
#endif

#ifdef SIGPIPE
    (void) signal(SIGPIPE, lostconn);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGPIPE);
#endif
#endif
#ifdef SIGCHLD
    (void) signal(SIGCHLD, SIG_IGN);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGCHLD);
#endif
#endif

#ifdef SIGURG
    if (signal(SIGURG, myoob) == SIG_ERR)
	syslog(LOG_ERR, "signal: %m");
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGURG);
#endif
#endif
#endif /* SIG_DEBUG */

#ifdef VIRTUAL
    virtual_root[0] = '\0';
    virtual_banner[0] = '\0';
#endif

#ifdef GSSAPI
    gssapi_setup_environment();
#endif /* GSSAPI */

    setup_paths();

#ifdef OTHER_PASSWD
    strcpy(_path_passwd, "/etc/passwd");
#ifdef SHADOW_PASSWORD
    strcpy(_path_shadow, "/etc/shadow");
#endif
#endif

    access_init();

#ifdef DAEMON
    if (be_daemon != 0)
	do_daemon(argc, argv, environ);
    addrlen = sizeof(his_addr);
    if (getpeername(0, (struct sockaddr *) &his_addr, &addrlen) < 0) {
	syslog(LOG_ERR, "getpeername (%s): %m", argv[0]);
#ifndef DEBUG
	exit(1);
#endif
    }
    addrlen = sizeof(ctrl_addr);
    if (getsockname(0, (struct sockaddr *) &ctrl_addr, &addrlen) < 0) {
	syslog(LOG_ERR, "getsockname (%s): %m", argv[0]);
#ifndef DEBUG
	exit(1);
#endif
    }
#ifdef IPTOS_LOWDELAY
    tos = IPTOS_LOWDELAY;
    if (setsockopt(0, IPPROTO_IP, IP_TOS, (char *) &tos, sizeof(int)) < 0)
	    syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
    if (keepalive)
	if (setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0)
	    syslog(LOG_ERR, "setsockopt SO_KEEPALIVE %m");
    data_source.sin_port = htons(ntohs(ctrl_addr.sin_port) - 1);
    data_source.sin_port = 0;
#endif /* DAEMON */

#ifdef GLOBUS_AUTHORIZATION
    if (!ftp_authorization_initialize(my_hostname,
				      ftp_authorization_error_buffer,
                                      sizeof(ftp_authorization_error_buffer)))
    {
        syslog(LOG_ERR,
               "Could not initialize ftp authorization code: %s",
               ftp_authorization_error_buffer);
        exit(1);
    } 
#endif /* GLOBUS_AUTHORIZATION */

    /* Try to handle urgent data inline */
#ifdef SO_OOBINLINE
    if (setsockopt(0, SOL_SOCKET, SO_OOBINLINE, (char *) &on, sizeof(int)) < 0)
	    syslog(LOG_ERR, "setsockopt (SO_OOBINLINE): %m");
#endif

#ifdef  F_SETOWN
    if (fcntl(fileno(stdin), F_SETOWN, getpid()) == -1)
	syslog(LOG_ERR, "fcntl F_SETOWN: %m");
#elif defined(SIOCSPGRP)
    {
	int pid;
	pid = getpid();
	if (ioctl(fileno(stdin), SIOCSPGRP, &pid) == -1)
	    syslog(LOG_ERR, "ioctl SIOCSPGRP: %m");
    }
#endif

    if (RootDirectory != NULL) {
	if ((chroot(RootDirectory) < 0)
	    || (chdir("/") < 0)) {
	    syslog(LOG_ERR, "Cannot chroot to initial directory, aborting.");
	    exit(1);
	}
    }

#ifdef HAVE_LIBRESOLV
    /* initialize the resolver, and set global DNS variables */
    initialize_dns(&his_addr);
#endif

    dolog(&his_addr);
    /* Set up default state */
    data = -1;
    type = TYPE_A;

    /*
     *  globus hack added by JB
     *  initialize handle and put it into ascii mode
     */
#   if defined(USE_GLOBUS_DATA_CODE)
    {
        g_start(argc, argv);
    }
#   endif

    form = FORM_N;
    stru = STRU_F;
    mode = MODE_S;
    tmpline[0] = '\0';
    yyerrorcalled = 0;

    entry = (struct aclmember *) NULL;
    if ((getaclentry("hostname", &entry)) && ARG0) 
    {
	(void) strncpy(hostname, ARG0, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
    }
    else 
    {
#ifdef HAVE_SYSINFO
	sysinfo(SI_HOSTNAME, hostname, sizeof(hostname));
#else
	(void) gethostname(hostname, sizeof(hostname));
#endif
/* set the FQDN here */
	shp = gethostbyname(hostname);
	if (shp != NULL) 
        {
	    (void) strncpy(hostname, shp->h_name, sizeof(hostname));
	    hostname[sizeof(hostname) - 1] = '\0';
	}
    }
    route_vectored = routevector();
    conv_init();

#ifdef MAIL_ADMIN
    incmails = 0;
    mailfrom = NULL;
#endif /* MAIL_ADMIN */
#ifdef VIRTUAL
    /*
       ** If virtual_mode is set at this point then an alternate ftpaccess
       ** is in use.  Otherwise we need to check the Master ftpaccess file
       ** to see if the site is only using the "virtual" directives to
       ** specify virtual site directives.
       **
       ** In this manner an admin can put a virtual site in the ftpservers
       ** file if they need expanded configuration support or can use the
       ** minimal root/banner/logfile if they do not need any more than that.
     */

    if (virtual_mode) {
	/* Get the root of the virtual server directory */
	entry = (struct aclmember *) NULL;
	if (getaclentry("root", &entry)) {
	    if (ARG0)
		strcpy(virtual_root, ARG0);
	}

	/* Get the logfile to use */
	entry = (struct aclmember *) NULL;
	if (getaclentry("logfile", &entry)) {
	    if (ARG0)
		strcpy(logfile, ARG0);
	}
    }
    else {
	virtual_hostname[0] = '\0';
	virtual_address[0] = '\0';
	virtual_len = sizeof(virtual_addr);
	if (getsockname(0, (struct sockaddr *) &virtual_addr, &virtual_len) == 0) {
	    virtual_ptr = (struct sockaddr_in *) &virtual_addr;
	    strcpy(virtual_address, inet_ntoa(virtual_ptr->sin_addr));
	    shp = gethostbyaddr((char *) &virtual_ptr->sin_addr, sizeof(struct in_addr), AF_INET);
	    if (shp != NULL) {
		(void) strncpy(virtual_hostname, shp->h_name, sizeof(virtual_hostname));
		virtual_hostname[sizeof(virtual_hostname) - 1] = '\0';
	    }
	    entry = (struct aclmember *) NULL;
	    while (getaclentry("virtual", &entry)) {
		if (!ARG0 || !ARG1 || !ARG2)
		    continue;
		if (hostmatch(ARG0, virtual_address, virtual_hostname)) {
		    if (!strcasecmp(ARG1, "root")) {
			syslog(LOG_NOTICE, "VirtualFTP Connect to: %s [%s]",
			       virtual_hostname, virtual_address);
			virtual_mode = 1;
			strncpy(virtual_root, ARG2, sizeof(virtual_root));
			virtual_root[sizeof(virtual_root) - 1] = '\0';
			/* reset hostname to this virtual name */
			(void) strcpy(hostname, virtual_hostname);
			virtual_email[0] = '\0';
		    }
		    if (!strcasecmp(ARG1, "banner")) {
			strncpy(virtual_banner, ARG2, sizeof(virtual_banner));
			virtual_banner[sizeof(virtual_banner) - 1] = '\0';
		    }
		    if (!strcasecmp(ARG1, "logfile")) {
			strncpy(logfile, ARG2, sizeof(logfile));
			logfile[sizeof(logfile) - 1] = '\0';
		    }
		    if (!strcasecmp(ARG1, "hostname")) {
			strncpy(hostname, ARG2, sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
		    }
		    if (!strcasecmp(ARG1, "email")) {
			strncpy(virtual_email, ARG2, sizeof(virtual_email));
			virtual_email[sizeof(virtual_email) - 1] = '\0';
		    }
#ifdef OTHER_PASSWD
		    if (!strcasecmp(ARG1, "passwd")) {
			strncpy(_path_passwd, ARG2, sizeof(_path_passwd));
			_path_passwd[sizeof(_path_passwd) - 1] = '\0';
#ifdef USE_PAM
			use_pam = 0;
#endif
		    }
#ifdef SHADOW_PASSWORD
		    if (!strcasecmp(ARG1, "shadow")) {
			strncpy(_path_shadow, ARG2, sizeof(_path_shadow));
			_path_shadow[sizeof(_path_shadow) - 1] = '\0';
#ifdef USE_PAM
			use_pam = 0;
#endif
		    }
#endif
#endif
#ifdef MAIL_ADMIN
		    if (mailfrom == NULL)
			if (!strcasecmp(ARG1, "mailfrom")) {
			    mailfrom = strdup(ARG2);
			}
		    if (!strcasecmp(ARG1, "incmail")) {
			if (incmails < INCMAILS)
			    incmail[incmails++] = strdup(ARG2);
		    }
#endif
		}
	    }
	    if (!virtual_mode) {
		entry = (struct aclmember *) NULL;
		while (getaclentry("defaultserver", &entry)) {
		    if (!ARG0 || !ARG1)
			continue;
#ifdef MAIL_ADMIN
		    if (mailfrom == NULL)
			if (!strcasecmp(ARG0, "mailfrom")) {
			    mailfrom = strdup(ARG1);
			}
		    if (!strcasecmp(ARG0, "incmail")) {
			if (incmails < INCMAILS)
			    incmail[incmails++] = strdup(ARG1);
		    }
#endif
		}
	    }
	}
    }

#ifdef VIRTUAL_DEBUG
    lreply(220, "_path_ftpaccess == %s", _path_ftpaccess);
    lreply(220, "_path_ftpusers == %s", _path_ftpusers);
    lreply(220, "_path_ftphosts == %s", _path_ftphosts);
    lreply(220, "_path_private == %s", _path_private);
    lreply(220, "_path_cvt == %s", _path_cvt);
    if (virtual_mode) {
	if (virtual_ftpaccess)
	    lreply(220, "VIRTUAL Mode: Using %s specific %s access file",
		   hostname, _path_ftpaccess);
	else
	    lreply(220, "VIRTUAL Mode: Using Master access file %s",
		   _path_ftpaccess);

	lreply(220, "virtual_root == %s", virtual_root);
	if (!virtual_ftpaccess)
	    lreply(220, "virtual_banner == %s", virtual_banner);
    }
    lreply(220, "logfile == %s", logfile);
#endif
#endif

    if (is_shutdown(1, 1) != 0) {
	syslog(LOG_INFO, "connection refused (server shut down) from %s",
	       remoteident);
	reply(500, "%s FTP server shut down -- please try again later.",
	      hostname);
	exit(0);
    }

#ifdef OPIE
    af_pwok = opieaccessfile(remotehost);
#endif

#ifdef HAVE_LIBRESOLV
    /* check permitted access based on remote host DNS information */
    if (!check_reverse_dns()) {
	exit(0);
    }
    if (!check_matching_dns()) {
	exit(0);
    }
#endif /* HAVE_LIBRESOLV */

    show_banner(220);

#ifndef INTERNAL_LS
    entry = (struct aclmember *) NULL;
    if (getaclentry("lslong", &entry) && ARG0 && (int) strlen(ARG0) > 0) {
	strcpy(ls_long, ARG0);
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    strcat(ls_long, " ");
	    strcat(ls_long, ARG[which]);
	}
    }
    else {
#if defined(SVR4) || defined(ISC)
#if defined(AIX) || defined(SOLARIS2)
	strcpy(ls_long, "/bin/ls -lA");
#else
	strcpy(ls_long, "/bin/ls -la");
#endif
#else
	strcpy(ls_long, "/bin/ls -lgA");
#endif
    }
    strcat(ls_long, " %s");

    entry = (struct aclmember *) NULL;
    if (getaclentry("lsshort", &entry) && ARG0 && (int) strlen(ARG0) > 0) {
	strcpy(ls_short, ARG0);
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    strcat(ls_short, " ");
	    strcat(ls_short, ARG[which]);
	}
    }
    else {
#if defined(SVR4) || defined(ISC)
#if defined(AIX) || defined(SOLARIS2)
	strcpy(ls_short, "/bin/ls -lA");
#else
	strcpy(ls_short, "/bin/ls -la");

#endif
#else
	strcpy(ls_short, "/bin/ls -lgA");
#endif
    }
    strcat(ls_short, " %s");

    entry = (struct aclmember *) NULL;
    if (getaclentry("lsplain", &entry) && ARG0 && (int) strlen(ARG0) > 0) {
	strcpy(ls_plain, ARG0);
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    strcat(ls_plain, " ");
	    strcat(ls_plain, ARG[which]);
	}
    }
    else
	strcpy(ls_plain, "/bin/ls");
    strcat(ls_plain, " %s");
#endif /* ! INTERNAL_LS */
#ifdef MAIL_ADMIN
    mailservers = 0;
    entry = (struct aclmember *) NULL;
    while (getaclentry("mailserver", &entry) && ARG0 && mailservers < MAILSERVERS)
	mailserver[mailservers++] = strdup(ARG0);
    if (mailservers == 0)
	mailserver[mailservers++] = strdup("localhost");
    if (incmails == 0) {
	entry = (struct aclmember *) NULL;
	while (getaclentry("incmail", &entry) && ARG0 && incmails < INCMAILS)
	    incmail[incmails++] = strdup(ARG0);
    }
    if (mailfrom == NULL) {
	entry = (struct aclmember *) NULL;
	if (getaclentry("mailfrom", &entry) && ARG0)
	    mailfrom = strdup(ARG0);
	else
	    mailfrom = strdup("wu-ftpd");
    }
#endif /* MAIL_ADMIN */
    {
#define OUTPUT_LEN 1024
	int version_option = 0;
	char output_text[OUTPUT_LEN + 1];
	int arg_count, output_len;

	entry = NULL;
	if (getaclentry("greeting", &entry) && ARG0) {
	    if (!strcasecmp(ARG0, "full"))
		version_option = 0;
	    else if (!strcasecmp(ARG0, "text") && ARG1)
		version_option = 3;
	    else if (!strcasecmp(ARG0, "terse"))
		version_option = 2;
	    else if (!strcasecmp(ARG0, "brief"))
		version_option = 1;
	}
	version_option = 0;
	switch (version_option) {
	default:
	    reply(220, "%s %s ready.", hostname, version);
	    break;
	case 1:
	    reply(220, "%s FTP server ready.", hostname);
	    break;
	case 2:
	    reply(220, "FTP server ready.");
	    break;
	case 3:
	    output_text[0] = '\0';
	    output_len = 0;
	    for (arg_count = 1; ARG[arg_count] != NULL; arg_count++) {
		int arg_len;

		arg_len = strlen(ARG[arg_count]);

		if ((output_len + arg_len) > OUTPUT_LEN) {
		    /* avoid possible buffer overflow */
		    break;
		}

		/* append the text to the greeting */
		strcat(output_text, ARG[arg_count]);
		output_len += arg_len;

		if (ARG[arg_count + 1] != NULL) {
		    if ((output_len + 2) > OUTPUT_LEN) {
			/* avoid possible buffer overflow and adding a trailing space */
			break;
		    }
		    /* if the next entry exists, add a white space */
		    strcat(output_text, " ");
		    output_len += 1;
		}
	    }
	    reply(220, "%s", output_text);
	    break;
	}
    }
    (void) setjmp(errcatch);

    for (;;)
    {
#       if defined(USE_GLOBUS_DATA_CODE)
        {
            globus_poll();
        }
#       endif

	(void) yyparse();
    }
    /* NOTREACHED */
}


SIGNAL_TYPE randomsig(int sig)
{
#ifdef HAVE_SIGLIST
    syslog(LOG_ERR, "exiting on signal %d: %s", sig, sys_siglist[sig]);
#else
    syslog(LOG_ERR, "exiting on signal %d", sig);
#endif
    chdir("/");
    signal(SIGIOT, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    exit(1);
    /* dologout(-1); *//* NOTREACHED */
}

SIGNAL_TYPE lostconn(int sig)
{
#ifdef VERBOSE_ERROR_LOGING
    syslog(LOG_INFO, "lost connection to %s", remoteident);
#else
    if (debug)
	syslog(LOG_DEBUG, "lost connection to %s", remoteident);
#endif
    dologout(-1);
}

static char ttyline[20];

#ifdef MAPPING_CHDIR
/* Keep track of the path the user has chdir'd into and respond with
 * that to pwd commands.  This is to avoid having the absolue disk
 * path returned, which I want to avoid.
 */
char mapped_path[MAXPATHLEN] = "/";

char *mapping_getwd(char *path)
{
    strcpy(path, mapped_path);
    return path;
}

char *mapping_getcwd(char *path, size_t size)
{
    strncpy(path, mapped_path, size);
    path[size - 1] = '\0';
    return path;
}

/* Make these globals rather than local to mapping_chdir to avoid stack overflow */
char pathspace[MAXPATHLEN];
char old_mapped_path[MAXPATHLEN];

void do_elem(char *dir)
{
    /* . */
    if (dir[0] == '.' && dir[1] == '\0') {
	/* ignore it */
	return;
    }

    /* .. */
    if (dir[0] == '.' && dir[1] == '.' && dir[2] == '\0') {
	char *last;
	/* lop the last directory off the path */
	if ((last = strrchr(mapped_path, '/'))) {
	    /* If start of pathname leave the / */
	    if (last == mapped_path)
		last++;
	    *last = '\0';
	}
	return;
    }

    /* append the dir part with a leading / unless at root */
    if (!(mapped_path[0] == '/' && mapped_path[1] == '\0'))
	if (strlen(mapped_path) < sizeof(mapped_path) - 1)
	    strcat(mapped_path, "/");
    if (sizeof(mapped_path) - strlen(mapped_path) > 1)
	strncat(mapped_path, dir, sizeof(mapped_path) - strlen(mapped_path) - 1);
}

int mapping_chdir(char *orig_path)
{
    int ret;
    char *sl, *path;

    strcpy(old_mapped_path, mapped_path);
    path = &pathspace[0];
    strcpy(path, orig_path);

    /* / at start of path, set the start of the mapped_path to / */
    if (path[0] == '/') {
	mapped_path[0] = '/';
	mapped_path[1] = '\0';
	path++;
    }

    while ((sl = strchr(path, '/'))) {
	char *dir;
	dir = path;
	*sl = '\0';
	path = sl + 1;
	if (*dir)
	    do_elem(dir);
	if (*path == '\0')
	    break;
    }
    if (*path)
	do_elem(path);

    if ((ret = chdir(mapped_path)) < 0) {
	strcpy(mapped_path, old_mapped_path);
    }

    return ret;
}
/* From now on use the mapping version */

#define chdir(d) mapping_chdir(d)
#define getwd(d) mapping_getwd(d)
#define getcwd(d,u) mapping_getcwd((d),(u))

#endif /* MAPPING_CHDIR */

/* Helper function for sgetpwnam(). */
char *sgetsave(char *s)
{
    char *new;

    new = (char *) malloc(strlen(s) + 1);

    if (new == NULL) {
	perror_reply(421, "Local resource failure: malloc");
	dologout(1);
	/* NOTREACHED */
    }
    (void) strcpy(new, s);
    return (new);
}

/* Save the result of a getpwnam.  Used for USER command, since the data
 * returned must not be clobbered by any other command (e.g., globbing). */
struct passwd *sgetpwnam(char *name)
{
    static struct passwd save;
    register struct passwd *p;
#ifdef M_UNIX
    struct passwd *ret = (struct passwd *) NULL;
#endif
    char *sgetsave(char *s);
#ifdef KERBEROS
    register struct authorization *q;
#endif /* KERBEROS */

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    struct pr_passwd *pr;
#endif

#ifdef KERBEROS
    init_krb();
    q = getauthuid(p->pw_uid);
    end_krb();
#endif /* KERBEROS */

#ifdef M_UNIX
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    if ((pr = getprpwnam(name)) == NULL)
	goto DONE;
#endif /* SecureWare || HPUX_10_TRUSTED */
#ifdef OTHER_PASSWD
    if ((p = bero_getpwnam(name, _path_passwd)) == NULL)
#else
    if ((p = getpwnam(name)) == NULL)
#endif
	goto DONE;
#else /* M_UNIX */
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    if ((pr = getprpwnam(name)) == NULL)
	return ((struct passwd *) pr);
#endif /* SecureWare || HPUX_10_TRUSTED */
#ifdef OTHER_PASSWD
    if ((p = bero_getpwnam(name, _path_passwd)) == NULL)
#else
    if ((p = getpwnam(name)) == NULL)
#endif
	return (p);
#endif /* M_UNIX */

    if (save.pw_name)
	free(save.pw_name);
    if (save.pw_gecos)
	free(save.pw_gecos);
    if (save.pw_dir)
	free(save.pw_dir);
    if (save.pw_shell)
	free(save.pw_shell);
    if (save.pw_passwd)
	free(save.pw_passwd);

    save = *p;

    save.pw_name = sgetsave(p->pw_name);

#ifdef KERBEROS
    save.pw_passwd = sgetsave(q->a_password);
#elif defined(SecureWare) || defined(HPUX_10_TRUSTED)
    if (pr->uflg.fg_encrypt && pr->ufld.fd_encrypt && *pr->ufld.fd_encrypt)
	save.pw_passwd = sgetsave(pr->ufld.fd_encrypt);
    else
	save.pw_passwd = sgetsave("");
#else
    save.pw_passwd = sgetsave(p->pw_passwd);
#endif
#ifdef SHADOW_PASSWORD
    if (p && (p->pw_passwd==NULL || strlen(p->pw_passwd)<8)) {
	struct spwd *spw;
#ifdef OTHER_PASSWD
	if ((spw = bero_getspnam(p->pw_name, _path_shadow)) != NULL) {
#else
	setspent();
	if ((spw = getspnam(p->pw_name)) != NULL) {
#endif
	    int expired = 0;
	    /*XXX Does this work on all Shadow Password Implementations? */
	    /* it is supposed to work on Solaris 2.x */
	    time_t now;
	    long today;

	    now = time((time_t *) 0);
	    today = now / (60 * 60 * 24);

	    if ((spw->sp_expire > 0) && (spw->sp_expire < today))
		expired++;
	    if ((spw->sp_max > 0) && (spw->sp_lstchg > 0) &&
		(spw->sp_lstchg + spw->sp_max < today))
		expired++;
	    free(save.pw_passwd);
	    save.pw_passwd = sgetsave(expired ? "" : spw->sp_pwdp);
	}
/* Don't overwrite the password if the shadow read fails, getpwnam() is NIS
   aware but getspnam() is not. */
/* Shadow passwords are optional on Linux.  --marekm */
#if !defined(LINUX) && !defined(UNIXWARE)
	else {
	    free(save.pw_passwd);
	    save.pw_passwd = sgetsave("");
	}
#endif
/* marekm's fix for linux proc file system shadow passwd exposure problem */
#ifndef OTHER_PASSWD
	endspent();
#endif
    }
#endif
    save.pw_gecos = sgetsave(p->pw_gecos);
    save.pw_dir = sgetsave(p->pw_dir);
    save.pw_shell = sgetsave(p->pw_shell);
#ifdef M_UNIX
    ret = &save;
  DONE:
    endpwent();
#endif
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    endprpwent();
#endif
#ifdef M_UNIX
    return (ret);
#else
    return (&save);
#endif
}
#if defined(SKEY) && !defined(__NetBSD__)
/*
 * From Wietse Venema, Eindhoven University of Technology. 
 */
/* skey_challenge - additional password prompt stuff */

char *skey_challenge(char *name, struct passwd *pwd, int pwok)
{
    static char buf[128];
    char sbuf[40];
    struct skey skey;

    /* Display s/key challenge where appropriate. */

    if (pwd == NULL || skeychallenge(&skey, pwd->pw_name, sbuf))
	sprintf(buf, "Password required for %s.", name);
    else
	sprintf(buf, "%s %s for %s.", sbuf,
		pwok ? "allowed" : "required", name);
    return (buf);
}
#endif

int login_attempts;		/* number of failed login attempts */
int askpasswd;			/* had user command, ask for passwd */
#ifndef HELP_CRACKERS
int DenyLoginAfterPassword;
char DelayedMessageFile[MAXPATHLEN];
extern void pr_mesg(int msgcode, char *msgfile);
#endif

#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
static int defaultserver_allow(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("defaultserver", &entry))
	if (ARG0 && !strcasecmp(ARG0, "allow"))
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int defaultserver_deny(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("defaultserver", &entry))
	if (ARG0 && !strcasecmp(ARG0, "deny"))
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int defaultserver_private(void)
{
    struct aclmember *entry = NULL;

    while (getaclentry("defaultserver", &entry))
	if (ARG0 && !strcasecmp(ARG0, "private"))
	    return (1);
    return (0);
}
#endif

/* USER command. Sets global passwd pointer pw if named account exists and is
 * acceptable; sets askpasswd if a PASS command is expected.  If logged in
 * previously, need to reset state.  If name is "ftp" or "anonymous", the
 * name is not in _PATH_FTPUSERS, and ftp account exists, set anonymous and
 * pw, then just return.  If account doesn't exist, ask for passwd anyway.
 * Otherwise, check user requesting login privileges.  Disallow anyone who
 * does not have a standard shell as returned by getusershell().  Disallow
 * anyone mentioned in the file _PATH_FTPUSERS to allow people such as root
 * and uucp to be avoided. */

/*
   char *getusershell();
 */
void user(char *name)
{
    char *cp;
    char *shell;
#ifdef	BSD_AUTH
    char *auth;
#endif

/* H* fix: if we're logged in at all, we can't log in again. */
    if (logged_in) {
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (already logged in as %s) FROM %s, %s",
	       pw->pw_name, remoteident, name);
#endif
	reply(530, "Already logged in.");
	return;
    }
#ifndef HELP_CRACKERS
    askpasswd = 1;
    DenyLoginAfterPassword = 0;
    DelayedMessageFile[0] = '\0';
#endif

#if (defined(GSSAPI) && defined(GLOBUS_AUTHORIZATION))
    if (!ftp_authorization_initialize_sc(gssapi_get_gss_ctx_id_t(),
                                         ftp_authorization_error_buffer,
                                         sizeof(ftp_authorization_error_buffer)))
    {
        syslog(LOG_NOTICE,
               "Error initializing gss security context for authorization: %s",
               ftp_authorization_error_buffer);

        /*
         * Could probably reply with something better here, but what
         * escapes me at the moment.
         */
        reply(530,
              "Error initializing gss security context for authorization: %s",
              ftp_authorization_error_buffer);
        return;
    }
    syslog(LOG_INFO, "authenticated identity is %s, authz identity is %s",
	   gssapi_audit_identity(), gssapi_identity());
#endif /*(defined(GSSAPI) && defined(GLOBUS_AUTHORIZATION)) */

#ifdef GSSAPI
    if (gssapi_authentication_required)
    {
	/*
	 * Disallow login unless gssapi authentication has been done.
	 */
	if (gssapi_identity() == NULL)
	{
	    reply(530, "Must perform GSSAPI authentication");
	    return;
	}
    }
#endif /* GSSAPI */

#ifdef GSSAPI_GLOBUS
    /*
     * Use mapping file to determine local user name?
     */
    if (strcmp(name, ":globus-mapping:") == 0) {
	char *identity;
	
	identity = gssapi_identity();
	
	if (identity == NULL) {
	    reply(530, "Must authenticate first");
	    return;
	}
	name = globus_local_name(identity);
	if (name == NULL) {
	    reply(530, "No local mapping for Globus ID");
	    return;
	}
	if (debug)
	    syslog(LOG_INFO, "Globus user %s maps to local user %s",
		   identity, name);
    }	

#endif /* GSSAPI_GLOBUS */

#ifdef	BSD_AUTH
    if ((auth = strchr(name, ':')))
	*auth++ = 0;
#endif

#ifdef HOST_ACCESS		/* 19-Mar-93    BM              */
    if (!rhost_ok(name, remotehost, remoteaddr)) {
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (name in %s) FROM %s, %s",
	       _PATH_FTPHOSTS, remoteident, name);
#else
	reply(530, "User %s access denied.", name);
	syslog(LOG_NOTICE,
	       "FTP LOGIN REFUSED (name in %s) FROM %s, %s",
	       _PATH_FTPHOSTS, remoteident, name);
	return;
#endif
    }
#endif

#ifdef LOG_FAILED		/* 06-Nov-92    EHK             */
    strncpy(the_user, name, MAXUSERNAMELEN - 1);
#endif

    anonymous = 0;
    acl_remove();

    if (!strcasecmp(name, "ftp") || !strcasecmp(name, "anonymous")) 
    {
	struct aclmember *entry = NULL;
	int machineok = 1;
	char guestservername[MAXHOSTNAMELEN];
	guestservername[0] = '\0';

#       ifdef NO_ANONYMOUS_ACCESS
        {
	    reply(530, "Anonymous FTP access denied.");
	    syslog(
                LOG_NOTICE, 
                "FTP LOGIN REFUSED (anonymous ftp not supported) FROM %s, %s",
	        remoteident, name);
	    return;
        }
#       else
        {
#           if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
	        if (!virtual_mode && defaultserver_private()) 
                {
#                   ifndef HELP_CRACKERS
                    {
	                DenyLoginAfterPassword = 1;
	                syslog(
                          LOG_NOTICE, 
 "FTP LOGIN REFUSED (anonymous ftp denied on default server) FROM %s, %s",
               		   remoteident, name);
                   }
#                  else
                   {
                       reply(530, "User %s access denied.", name);
	               syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (anonymous ftp denied on default server) FROM %s, %s",
		       remoteident, name);
	               return;
                   }
#                  endif
	}
     }
#    endif
	if (checkuser("ftp") || checkuser("anonymous")) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (ftp in %s) FROM %s, %s",
		   _PATH_FTPUSERS, remoteident, name);
#else
	    reply(530, "User %s access denied.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (ftp in %s) FROM %s, %s",
		   _PATH_FTPUSERS, remoteident, name);
	    return;
#endif

	    /*
	       ** Algorithm used:
	       ** - if no "guestserver" directive is present,
	       **     anonymous access is allowed, for backward compatibility.
	       ** - if a "guestserver" directive is present,
	       **     anonymous access is restricted to the machines listed,
	       **     usually the machine whose CNAME on the current domain
	       **     is "ftp"...
	       **
	       ** the format of the "guestserver" line is
	       ** guestserver [<machine1> [<machineN>]]
	       ** that is, "guestserver" will forbid anonymous access on all machines
	       ** while "guestserver ftp inf" will allow anonymous access on
	       ** the two machines whose CNAMES are "ftp.enst.fr" and "inf.enst.fr".
	       **
	       ** if anonymous access is denied on the current machine,
	       ** the user will be asked to use the first machine listed (if any)
	       ** on the "guestserver" line instead:
	       ** 530- Guest login not allowed on this machine,
	       **      connect to ftp.enst.fr instead.
	       **
	       ** -- <Nicolas.Pioch@enst.fr>
	     */
	}
	else if (getaclentry("guestserver", &entry)
		 && ARG0 && (int) strlen(ARG0) > 0) {
	    struct hostent *tmphostent;

	    /*
	       ** if a "guestserver" line is present,
	       ** default is not to allow guest logins
	     */
	    machineok = 0;

	    if (hostname[0]
		&& ((tmphostent = gethostbyname(hostname)))) {

		/*
		   ** hostname is the only first part of the FQDN
		   ** this may or may not correspond to the h_name value
		   ** (machines with more than one IP#, CNAMEs...)
		   ** -> need to fix that, calling gethostbyname on hostname
		   **
		   ** WARNING!
		   ** for SunOS 4.x, you need to have a working resolver in the libc
		   ** for CNAMES to work properly.
		   ** If you don't, add "-lresolv" to the libraries before compiling!
		 */
		char dns_localhost[MAXHOSTNAMELEN];
		int machinecount;

		strncpy(dns_localhost,
			tmphostent->h_name,
			sizeof(dns_localhost));
		dns_localhost[sizeof(dns_localhost) - 1] = '\0';

		for (machinecount = 0;
		  entry->arg[machinecount] && (entry->arg[machinecount])[0];
		     machinecount++) {

		    if ((tmphostent = gethostbyname(entry->arg[machinecount]))) {
			/*
			   ** remember the name of the first machine for redirection
			 */

			if ((!machinecount) && tmphostent->h_name) {
			    strncpy(guestservername, entry->arg[machinecount],
				    sizeof(guestservername));
			    guestservername[sizeof(guestservername) - 1] = '\0';
			}

			if (!strcasecmp(tmphostent->h_name, dns_localhost)) {
			    machineok++;
			    break;
			}
		    }
		}
	    }
	}
	if (!machineok) {
	    if (guestservername[0])
		reply(530,
		      "Guest login not allowed on this machine, connect to %s instead.",
		      guestservername);
	    else
		reply(530,
		      "Guest login not allowed on this machine.");
	    syslog(LOG_NOTICE,
	    "FTP LOGIN REFUSED (localhost not in guestservers) FROM %s, %s",
		   remoteident, name);
	    /* End of the big patch -- Nap */

	}
	else if ((pw = sgetpwnam("ftp")) != NULL) {
	    anonymous = 1;	/* for the access_ok call */
	    if (access_ok(530) < 1) {
#ifndef HELP_CRACKERS
		DenyLoginAfterPassword = 1;
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (access denied) FROM %s, %s",
		       remoteident, name);
		reply(331, "Guest login ok, send your complete e-mail address as password.");
#else
		reply(530, "User %s access denied.", name);
		syslog(LOG_NOTICE,
		       "FTP LOGIN REFUSED (access denied) FROM %s, %s",
		       remoteident, name);
		dologout(0);
#endif
	    }
	    else {
		askpasswd = 1;
/* H* fix: obey use_accessfile a little better.  This way, things set on the
   command line [like xferlog stuff] don't get stupidly overridden.
   XXX: all these checks maybe should be in acl.c and access.c */
		if (use_accessfile)
		    acl_setfunctions();
		reply(331, "Guest login ok, send your complete e-mail address as password.");
	    }
	}
	else {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    reply(331, "Guest login ok, send your complete e-mail address as password.");
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (ftp not in /etc/passwd) FROM %s, %s",
		   remoteident, name);
#else
	    reply(530, "User %s unknown.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (ftp not in /etc/passwd) FROM %s, %s",
		   remoteident, name);
#endif
	}
	return;
#endif
    }
#ifdef ANON_ONLY
/* H* fix: define the above to completely DISABLE logins by real users,
   despite ftpusers, shells, or any of that rot.  You can always hang your
   "real" server off some other port, and access-control it. */

    else {			/* "ftp" or "anon" -- MARK your conditionals, okay?! */
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (not anonymous) FROM %s, %s",
	       remoteident, name);
	reply(331, "Password required for %s.", name);
#else
	reply(530, "User %s unknown.", name);
	syslog(LOG_NOTICE,
	       "FTP LOGIN REFUSED (not anonymous) FROM %s, %s",
	       remoteident, name);
#endif
	return;
    }
/* fall here if username okay in any case */
#endif /* ANON_ONLY */

#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
    if (!virtual_mode && defaultserver_deny(name) && !defaultserver_allow(name)) {
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (ftp denied on default server) FROM %s, %s",
	       remoteident, name);
#else
	reply(530, "User %s access denied.", name);
	syslog(LOG_NOTICE,
	     "FTP LOGIN REFUSED (ftp denied on default server) FROM %s, %s",
	       remoteident, name);
	return;
#endif
    }
#endif

    if ((pw = sgetpwnam(name)) != NULL) {

	if ((denieduid(pw->pw_uid) && !alloweduid(pw->pw_uid))
	    || (deniedgid(pw->pw_gid) && !allowedgid(pw->pw_gid))) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (username in denied-uid) FROM %s, %s",
		   remoteident, name);
	    reply(331, "Password required for %s.", name);
#else
	    reply(530, "User %s access denied.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (username in denied-uid) FROM %s, %s",
		   remoteident, name);
#endif
	    return;
	}

#if !defined(USE_PAM) || (defined(USE_PAM) && defined(OTHER_PASSWD))	/* PAM should be doing these checks, not ftpd */
#ifdef USE_PAM
	if(!use_pam) {
#endif
	if ((shell = pw->pw_shell) == NULL || *shell == 0)
	    shell = _PATH_BSHELL;
	while ((cp = getusershell()) != NULL)
	    if (strcmp(cp, shell) == 0)
		break;
	endusershell();
	if (cp == NULL || checkuser(name)) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    if (cp == NULL)
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (shell not in /etc/shells) FROM %s, %s", remoteident, name);
	    else
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (username in %s) FROM %s, %s", _PATH_FTPUSERS, remoteident, name);
	    reply(331, "Password required for %s.", name);
#else
	    reply(530, "User %s access denied.", name);
	    if (cp == NULL)
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (shell not in /etc/shells) FROM %s, %s", remoteident, name);
	    else
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (username in %s) FROM %s, %s", _PATH_FTPUSERS, remoteident, name);
#endif /* HELP_CRACKERS */
	    pw = (struct passwd *) NULL;
	    return;
	}
#ifdef USE_PAM
	} /* if(!use_pam) */
#endif
#endif /* !USE_PAM || (USE_PAM && OTHER_PASSWD) */
	/* if user is a member of any of the guestgroups, cause a chroot() */
	/* after they log in successfully                                  */
	if (use_accessfile) {	/* see above.  _H */
	    guest = acl_guestgroup(pw);
	    if (guest && acl_realgroup(pw))
		guest = 0;
	}
#ifdef FTP_SECURITY_EXTENSIONS
	if (auth_type) {
#ifdef GSSAPI	
	    if (strcmp(auth_type, "GSSAPI") == 0) {
		char *gssapi_name = gssapi_identity();
	    
		/* Check authorization of already authenticated user */
		gssapi_user_is_good = (gssapi_check_authorization(gssapi_name,
								  name) == 0);
	
		syslog((gssapi_user_is_good ? LOG_INFO : LOG_ERR),
		       "GSSAPI user %s is%s authorized as %s",
		       gssapi_name,
		       (gssapi_user_is_good ? "" : " not"),
		       name);

		/*
		 * We always needs the PASS command for our state machine
		 * so we always send back 331, even though we may just
		 * need a dummy password.
		 */
        reply(331, 
			  "GSSAPI user %s is%s authorized as %s%s",
		      gssapi_name,
		      (gssapi_user_is_good ? "" : " not"),
		      name,
		      (gssapi_user_is_good ? "" : "; Password required."));

		if (!gssapi_user_is_good)
		    pw = (struct passwd *) NULL;
	    
		return;
	    }	    
#endif /* GSSAPI */
	}
#endif /* FTP_SECURITY_EXTENSIONS */
    }

    if (access_ok(530) < 1) {
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (access denied) FROM %s, %s",
	       remoteident, name);
	reply(331, "Password required for %s.", name);
#else
	reply(530, "User %s access denied.", name);
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (access denied) FROM %s, %s",
	       remoteident, name);
#endif
	return;
    }
    else if (use_accessfile)	/* see above.  _H */
	acl_setfunctions();

#ifdef	BSD_AUTH
    if ((cp = start_auth(auth, name, pw)) != NULL) {
	char *s;

	for (;;) {
	    s = strsep(&cp, "\n");
	    if (cp == NULL || *cp == '\0')
		break;
	    lreply(331, "%s", s);
	}
	reply(331, "%s", s);
    }
    else {
#endif
#ifdef SKEY
#ifndef __NetBSD__
#ifdef SKEY_NAME
	/* this is the old way, but freebsd uses it */
	pwok = skeyaccess(name, NULL, remotehost, remoteaddr);
#else
	/* this is the new way */
	pwok = skeyaccess(pw, NULL, remotehost, remoteaddr);
#endif
	reply(331, "%s", skey_challenge(name, pw, pwok));
#else
	if (skey_haskey(name) == 0) {
	    char *myskey;

	    myskey = skey_keyinfo(name);
	    reply(331, "Password [%s] required for %s.",
		  myskey ? myskey : "error getting challenge", name);
	}
	else
	    reply(331, "Password required for %s.", name);
#endif
#else
#ifdef OPIE
	{
	    char prompt[OPIE_CHALLENGE_MAX + 1];
	    opiechallenge(&opiestate, name, prompt);

	    if (askpasswd == -1) {
		syslog(LOG_WARNING, "Invalid FTP user name %s attempted from %s", name, remotehost);
		pwok = 0;
	    }
	    else
		pwok = af_pwok && opiealways(pw->pw_dir);
	    reply(331, "Response to %s %s for %s.",
		  prompt, pwok ? "requested" : "required", name);
	}
#else
	reply(331, "Password required for %s.", name);
#endif
#endif
#ifdef	BSD_AUTH
    }
#endif
    askpasswd = 1;
    /* Delay before reading passwd after first failed attempt to slow down
     * passwd-guessing programs. */
    if (login_attempts) {
	enable_signaling();	/* we can allow signals once again: kinch */
	sleep((unsigned) login_attempts);
    }
    return;
}

/* Check if a user is in the file _PATH_FTPUSERS */

int checkuser(char *name)
{
    register FILE *fd;
    register char *p;
    char line[BUFSIZ];

    if ((fd = fopen(_PATH_FTPUSERS, "r")) != NULL) {
	while (fgets(line, sizeof(line), fd) != NULL)
	    if ((p = strchr(line, '\n')) != NULL) {
		*p = '\0';
		if (line[0] == '#')
		    continue;
		if (strcasecmp(line, name) == 0) {
		    (void) fclose(fd);
		    return (1);
		}
	    }
	(void) fclose(fd);
    }
    return (0);
}

int denieduid(uid_t uid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct passwd *pw;

    while (getaclentry("deny-uid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		pw = getpwnam(ARG[which]);
#endif
		if (pw && (uid == pw->pw_uid))
		    return (1);
	    }
	}
    }
    return (0);
}

int alloweduid(uid_t uid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct passwd *pw;

    while (getaclentry("allow-uid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		pw = getpwnam(ARG[which]);
#endif
		if (pw && (uid == pw->pw_uid))
		    return (1);
	    }
	}
    }
    return (0);
}

int deniedgid(gid_t gid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct group *grp;

    while (getaclentry("deny-gid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		grp = getgrnam(ARG[which]);
		if (grp && (gid == grp->gr_gid))
		    return (1);
	    }
	}
    }
    return (0);
}

int allowedgid(gid_t gid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct group *grp;

    while (getaclentry("allow-gid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		grp = getgrnam(ARG[which]);
		if (grp && (gid == grp->gr_gid))
		    return (1);
	    }
	}
    }
    return (0);
}

/* Terminate login as previous user, if any, resetting state; used when USER
 * command is given or login fails. */

void end_login(void)
{
#ifdef GSSAPI
	gssapi_remove_delegation();
#endif /* GSSAPI */

    delay_signaling();		/* we can't allow any signals while euid==0: kinch */
    (void) seteuid((uid_t) 0);
    if (logged_in)
	if (wtmp_logging)
	    wu_logwtmp(ttyline, pw->pw_name, remotehost, 0);
    pw = NULL;
#if defined(AFS)
    afs_logout();
#endif
    logged_in = 0;
    anonymous = 0;
    guest = 0;
}

int validate_eaddr(char *eaddr)
{
    int i, host, state;

    for (i = host = state = 0; eaddr[i] != '\0'; i++) {
	switch (eaddr[i]) {
	case '.':
	    if (!host)
		return 0;
	    if (state == 2)
		state = 3;
	    host = 0;
	    break;
	case '@':
	    if (!host || state > 1 || !strncasecmp("ftp", eaddr + i - host, host))
		return 0;
	    state = 2;
	    host = 0;
	    break;
	case '!':
	case '%':
	    if (!host || state > 1)
		return 0;
	    state = 1;
	    host = 0;
	    break;
	case '-':
	    break;
	default:
	    host++;
	}
    }
    if (((state == 3) && host > 1) || ((state == 2) && !host) ||
	((state == 1) && host > 1))
	return 1;
    else
	return 0;
}


#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
static int AllowVirtualUser(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("virtual", &entry))
	if (ARG0 && hostmatch(ARG0, virtual_address, virtual_hostname)
	    && ARG1 && !strcasecmp(ARG1, "allow"))
	    for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int DenyVirtualUser(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("virtual", &entry))
	if (ARG0 && hostmatch(ARG0, virtual_address, virtual_hostname)
	    && ARG1 && !strcasecmp(ARG1, "deny"))
	    for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int DenyVirtualAnonymous(void)
{
    struct aclmember *entry = NULL;

    while (getaclentry("virtual", &entry))
	if (ARG0 && hostmatch(ARG0, virtual_address, virtual_hostname)
	    && ARG1 && !strcasecmp(ARG1, "private"))
	    return (1);
    return (0);
}
#endif

void pass(char *passwd)
{

#if !defined(USE_PAM) || (defined(USE_PAM) && defined(OTHER_PASSWD))
    char *xpasswd, *salt;
#endif

    int passwarn = 0;
    int rval = 1;

#ifdef SECUREOSF
    struct pr_passwd *pr;
    int crypt_alg = 0;
#endif

#ifdef BSD_AUTH
    extern int ext_auth;
    extern char *check_auth();
#endif

#ifdef ULTRIX_AUTH
    int numfails;
#endif /* ULTRIX_AUTH */

#ifdef HAS_PW_EXPIRE
    int set_expired = FALSE;
#endif 

#ifdef AFS_AUTH
    char *reason;
#endif /* AFS_AUTH */

#ifdef DCE_AUTH
    sec_passwd_rec_t pwr;
    sec_login_handle_t lhdl;
    boolean32 rstpwd;
    sec_login_auth_src_t asrc;
    error_status_t status;
#endif /* DCE_AUTH */

    if (logged_in || askpasswd == 0) {
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (PASS before USER) FROM %s",
	       remoteident);
#endif
	reply(503, "Login with USER first.");
	return;
    }
    askpasswd = 0;
    
#ifdef GSSAPI
    if (gssapi_authentication_required)
    {
	/*
	 * Disallow login unless gssapi authentication has been done.
	 */
	if (gssapi_identity() == NULL)
	{
	    reply(530, "Must perform GSSAPI authentication");
	    return;
	}
    }
#endif /* GSSAPI */

    /* Disable lreply() if the first character of the password is '-' since
     * some hosts don't understand continuation messages and hang... */

    if (*passwd == '-')
	dolreplies = 0;
    else
	dolreplies = 1;
/* ******** REGULAR/GUEST USER PASSWORD PROCESSING ********** */
    if (!anonymous) {		/* "ftp" is only account allowed no password */
#ifndef HELP_CRACKERS
	if (DenyLoginAfterPassword) {
	    pr_mesg(530, DelayedMessageFile);
	    reply(530, "Login incorrect.");
	    acl_remove();
	    pw = NULL;
	    if (++login_attempts >= lgi_failure_threshold) {
		syslog(LOG_NOTICE, "repeated login failures from %s",
		       remoteident);
		exit(0);
	    }
	    return;
	}
#endif
	if (*passwd == '-')
	    passwd++;
#ifdef USE_PAM
#ifdef OTHER_PASSWD
	if (use_pam) {
#endif
	/* PAM authentication
	 * If PAM authenticates a user we know nothing about on the local
	 * system, use the generic guest account credentials. We should make
	 * this somehow a configurable item somewhere; later more on that.
	 *
	 * For now assume the guest (not anonymous) identity, so the site
	 * admins can still differentiate between the truw anonymous user and
	 * a little bit more special ones. Otherwise he wouldn't go the extra
	 * mile to have a different user database, right?
	 *              --gaftonc */
	if (pam_check_pass(the_user, passwd)) {
	    rval = 0;
	    if (pw == NULL) {
		/* assume guest account identity */
		pw = sgetpwnam("ftp");
		anonymous = 0;
		guest = 1;
		/* even go as far as... */
		if (pw != NULL && pw->pw_name != NULL) {
		    free(pw->pw_name);
		    pw->pw_name = sgetsave(the_user);
		}
	    }
	}
#ifdef OTHER_PASSWD
	} else {
#endif
#endif /* USE_PAM */
#if !defined(USE_PAM) || (defined(USE_PAM) && defined(OTHER_PASSWD))
#ifdef BSD_AUTH
	if (ext_auth) {
	    if ((salt = check_auth(the_user, passwd))) {
		reply(530, salt);
#ifdef LOG_FAILED		/* 27-Apr-93      EHK/BM          */
		syslog(LOG_INFO, "failed login from %s",
		       remoteident);
#endif /* LOG_FAILED */
		acl_remove();
		pw = NULL;
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s",
			   remoteident);
		    exit(0);
		}
		return;
	    }
	}
	else {
#endif /* BSD_AUTH */
	    *guestpw = '\0';
	    if (pw == NULL || strlen(pw->pw_passwd) == 0)
		salt = "xx";
	    else
                salt = pw->pw_passwd;
#ifndef OPIE
#ifdef SECUREOSF
	    if ((pr = getprpwnam(pw->pw_name)) != NULL) {
		if (pr->uflg.fg_newcrypt)
		    crypt_alg = pr->ufld.fd_newcrypt;
		else if (pr->sflg.fg_newcrypt)
		    crypt_alg = pr->sfld.fd_newcrypt;
		else
		    crypt_alg = 0;
	    }
	    else
		crypt_alg = 0;

	    xpasswd = dispcrypt(passwd, salt, crypt_alg);
#elif defined(SecureWare) || defined(HPUX_10_TRUSTED)
	    xpasswd = bigcrypt(passwd, salt);
#elif defined(KERBEROS)
	    xpasswd = crypt16(passwd, salt);
#elif defined(SKEY)
#ifndef __NetBSD__
	    xpasswd = skey_crypt(passwd, salt, pw, pwok);
	    pwok = 0;
#else
	    if ((pw != NULL) && (pw->pw_name != NULL) && skey_haskey(pw->pw_name) == 0 &&
		skey_passcheck(pw->pw_name, passwd) != -1)
		xpasswd = pw->pw_passwd;
	    else
		xpasswd = crypt(passwd, salt);
#endif
#else /* !SKEY */
	    xpasswd = crypt(passwd, salt);
#endif /* SKEY */
#else /* OPIE */
	    if (!opieverify(&opiestate, passwd))
		rval = 0;
	    xpasswd = crypt(passwd, salt);
#endif /* OPIE */
#ifdef GSSAPI
	    if (gssapi_user_is_good) {
		/*
		 * User has alreay been authenticated (in auth_data()) and
		 * authorized (in user())
		 */
		rval = 0;
	    }
	    else
#endif /* GSSAPI */
#ifdef ULTRIX_AUTH
	    if ((numfails = ultrix_check_pass(passwd, xpasswd)) >= 0) {
#else
	    if (pw != NULL) {
#ifdef AFS_AUTH
		if (strcmp(pw->pw_passwd, "X") == 0)
		    if (ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION | KA_USERAUTH_DOSETPAG, pw->pw_name, "", 0, passwd, 0, 0, 0, &reason) == 0)
			rval = 0;
		    else
			printf("230-AFS: %s", reason);
		else
#endif /* AFS_AUTH */
		    /* The strcmp does not catch null passwords! */
#ifdef HAS_PW_EXPIRE
		    if(pw->pw_expire != NULL) {
			if(pw->pw_expire && time(NULL) >= pw->pw_expire) {
			    set_expired = TRUE;
			} 
		    }
#endif
			    
		    if (*pw->pw_passwd != '\0' &&
#ifdef HAS_PW_EXPIRE
			!set_expired &&
#endif
			strcmp(xpasswd, pw->pw_passwd) == 0) {
#endif
		    rval = 0;
		}
#ifdef DCE_AUTH
#ifndef ALWAYS_TRY_DCE
		else
#endif /* ALWAYS_TRY_DCE */
		{
		    sec_login_setup_identity((unsigned_char_p_t) pw->pw_name, sec_login_no_flags, &lhdl, &status);
		    if (status == error_status_ok) {
			printf("230-sec_login_setup_identity OK\n");
			pwr.key.tagged_union.plain = (idl_char *) passwd;
			pwr.key.key_type = sec_passwd_plain;
			pwr.pepper = 0;
			pwr.version_number = sec_passwd_c_version_none;
			/* validate password with login context */
			sec_login_valid_and_cert_ident(lhdl, &pwr, &rstpwd, &asrc, &status);
			if (!rstpwd && (asrc == sec_login_auth_src_network) && (status == error_status_ok)) {
			    printf("230-sec_login_valid_and_cert_ident OK\n");
			    sec_login_set_context(lhdl, &status);
			    printf("230-sec_login_set_context finished\n");
			    if (status != error_status_ok) {
				int pstatus;
				dce_error_string_t s;
				printf("230-Error status: %d:\n", status);
				dce_error_inq_text(status, s, &pstatus);
				printf("230-%s\n", s);
				fflush(stderr);
				sec_login_purge_context(lhdl, &status);
			    }
			    else {
				/*sec_login_get_pwent(lhdl, &pw, &status); */
				rval = 0;
			    }
			}
		    }
		}
#endif /* DCE_AUTH */
	    }
#ifdef USE_PAM
	    }
#endif
#endif /* !USE_PAM  || (USE_PAM && OTHER_PASSWD) */
	    if (rval) {
		reply(530, "Login incorrect.");

#ifdef LOG_FAILED		/* 27-Apr-93    EHK/BM             */
/* H* add-on: yell about attempts to use the trojan.  This may alarm you
   if you're "stringsing" the binary and you see "NULL" pop out in just
   about the same place as it would have in 2.2c! */
		if (!strcasecmp(passwd, "NULL"))
		    syslog(LOG_NOTICE, "REFUSED \"NULL\" from %s, %s",
			   remoteident, the_user);
		else
		    syslog(LOG_INFO, "failed login from %s",
			   remoteident);
#endif
		acl_remove();

		pw = NULL;
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s",
			   remoteident);
		    exit(0);
		}
		return;
	    }
#ifdef	BSD_AUTH
	}
#endif
/* ANONYMOUS USER PROCESSING STARTS HERE */
    }
    else {
	char *pwin, *pwout = guestpw;
	struct aclmember *entry = NULL;
	int valid;
	int enforce = 0;

	if (getaclentry("passwd-check", &entry) &&
	    ARG0 && strcasecmp(ARG0, "none")) {

	    if (!strcasecmp(ARG0, "rfc822"))
		valid = validate_eaddr(passwd);
	    else if (!strcasecmp(ARG0, "trivial"))
		valid = (strchr(passwd, '@') == NULL) ? 0 : 1;
	    else
		valid = 1;
	    if (ARG1 && !strcasecmp(ARG1, "enforce"))
		enforce = 1;
	    /* Block off "default" responses like mozilla@ and IE30User@
	     * (at the administrator's discretion).  --AC
	     */
	    entry = NULL;
	    while (getaclentry("deny-email", &entry)) {
		if (ARG0
		    && ((strcasecmp(passwd, ARG0) == 0)
			|| regexmatch(passwd, ARG0)
			|| ((*passwd == '-')
			    && ((strcasecmp(passwd + 1, ARG0) == 0)
				|| regexmatch(passwd + 1, ARG0))))) {
		    valid = 0;
		    break;
		}
	    }
	    if (!valid && enforce) {
		lreply(530, "The response '%s' is not valid", passwd);
		lreply(530, "Please use your e-mail address as your password");
		lreply(530, "   for example: %s@%s or %s@",
		       authenticated ? authuser : "joe", remotehost,
		       authenticated ? authuser : "joe");
		lreply(530, "[%s will be added if password ends with @]",
		       remotehost);
		reply(530, "Login incorrect.");
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP ACCESS REFUSED (anonymous password not rfc822) from %s",
		       remoteident);
#endif
		acl_remove();
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s",
			   remoteident);
		    exit(0);
		}
		return;
	    }
	    else if (!valid)
		passwarn = 1;
	}
	if (!*passwd) {
	    strcpy(guestpw, "[none_given]");
	}
	else {
	    int cnt = sizeof(guestpw) - 2;

	    for (pwin = passwd; *pwin && cnt--; pwin++)
		if (!isgraph(*pwin))
		    *pwout++ = '_';
		else
		    *pwout++ = *pwin;
	}
#ifndef HELP_CRACKERS
	if (DenyLoginAfterPassword) {
	    pr_mesg(530, DelayedMessageFile);
	    reply(530, "Login incorrect.");
	    acl_remove();
	    pw = NULL;
	    if (++login_attempts >= lgi_failure_threshold) {
		syslog(LOG_NOTICE, "repeated login failures from %s",
		       remoteident);
		exit(0);
	    }
	    return;
	}
#endif
    }

    /* if logging is enabled, open logfile before chroot or set group ID */
    if ((log_outbound_xfers || log_incoming_xfers) && (syslogmsg != 1)) {
	mode_t oldmask;
	oldmask = umask(0);
	xferlog = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0640);
	(void) umask(oldmask);
	if (xferlog < 0) {
	    syslog(LOG_ERR, "cannot open logfile %s: %s", logfile,
		   strerror(errno));
	    xferlog = 0;
	}
    }

#ifdef DEBUG
/* I had a lot of trouble getting xferlog working, because of two factors:
   acl_setfunctions making stupid assumptions, and sprintf LOSING.  _H */
/* 
 * Actually, sprintf was not losing, but the rules changed... next release
 * this will be fixed the correct way, but right now, it works well enough
 * -- sob 
 */
    syslog(LOG_INFO, "-i %d,-o %d,xferlog %s: %d",
	   log_incoming_xfers, log_outbound_xfers, logfile, xferlog);
#endif
    enable_signaling();		/* we can allow signals once again: kinch */
    /* if autogroup command applies to user's class change pw->pw_gid */
    if (anonymous && use_accessfile) {	/* see above.  _H */
	(void) acl_autogroup(pw);
	guest = acl_guestgroup(pw);	/* the new group may be a guest */
	if (guest && acl_realgroup(pw))
	    guest = 0;
	anonymous = !guest;
    }
/* END AUTHENTICATION */
    login_attempts = 0;		/* this time successful */
/* SET GROUP ID STARTS HERE */
#ifndef AIX
    (void) setegid((gid_t) pw->pw_gid);
#else
    (void) setgid((gid_t) pw->pw_gid);
#endif
    (void) initgroups(pw->pw_name, pw->pw_gid);
#ifdef DEBUG
    syslog(LOG_DEBUG, "initgroups has been called");
#endif
/* WTMP PROCESSING STARTS HERE */
    if (wtmp_logging) {
	/* open wtmp before chroot */
#if ((defined(BSD) && (BSD >= 199103)) || defined(sun))
	(void) sprintf(ttyline, "ftp%ld", (long) getpid());
#else
	(void) sprintf(ttyline, "ftpd%d", getpid());
#endif
#ifdef DEBUG
	syslog(LOG_DEBUG, "about to call wtmp");
#endif
	wu_logwtmp(ttyline, pw->pw_name, remotehost, 1);
    }
    logged_in = 1;

#ifdef GSSAPI
    /* Fix our GSSAPI environment and credentials */
    gssapi_fix_env();
    gssapi_chown_delegation(pw->pw_uid, pw->pw_gid);
#endif /* GSSAPI */

#ifdef AFS
	/* Create pagesh for AFS */
	afs_pagsh();
#endif /* AFS */
	
    expand_id();

#ifdef QUOTA
    memset(&quota, 0, sizeof(quota));
    get_quota(pw->pw_dir, pw->pw_uid);
#endif

    restricted_user = 0;
    if (!anonymous)
	if ((restricteduid(pw->pw_uid) && !unrestricteduid(pw->pw_uid))
	    || (restrictedgid(pw->pw_gid) && !unrestrictedgid(pw->pw_gid)))
	    restricted_user = 1;
    if (anonymous || guest) {
	char *sp;
	/* We MUST do a chdir() after the chroot. Otherwise the old current
	 * directory will be accessible as "." outside the new root! */
#ifdef ALTERNATE_CD
	home = defhome;
#endif
#ifdef VIRTUAL
	if (virtual_mode && !guest) {
#ifdef CLOSED_VIRTUAL_SERVER
	    if (DenyVirtualAnonymous()) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host anonymous access denied) for %s",
		       remoteident);
#endif
		reply(530, "Login incorrect.");
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
		    exit(0);
		}
		goto bad;
	    }
#endif
	    /* Anonymous user in virtual_mode */
	    if (pw->pw_dir)
		free(pw->pw_dir);
	    pw->pw_dir = sgetsave(virtual_root);
	}
	else
#endif

	    /*
	       *  New chroot logic.
	       *
	       *  If VIRTUAL is supported, the chroot for anonymous users on the
	       *  virtual host has already been determined.  Otherwise the logic
	       *  below applies:
	       *
	       *  If this is an anonymous user, the chroot directory is determined
	       *  by the "anonymous-root" clause and the home directory is taken
	       *  from the etc/passwd file found after chroot'ing.
	       *
	       *  If this a guest user, the chroot directory is determined by the
	       *  "guest-root" clause and the home directory is taken from the
	       *  etc/passwd file found after chroot'ing.
	       *
	       *  The effect of this logic is that the entire chroot environment
	       *  is under the control of the ftpaccess file and the supporting
	       *  files in the ftp environment.  The system-wide passwd file is
	       *  used only to authenticate the user.
	     */

	{
	    struct aclmember *entry = NULL;
	    char *root_path = NULL;

	    if (anonymous) {
		char class[1024];

		(void) acl_getclass(class);
		while (getaclentry("anonymous-root", &entry) && ARG0) {
		    if (!ARG1) {
			if (!root_path)
			    root_path = ARG0;
		    }
		    else {
			int which;

			for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
			    if (!strcmp(ARG[which], "*")) {
				if (!root_path)
				    root_path = ARG0;
			    }
			    else {
				if (!strcasecmp(ARG[which], class))
				    root_path = ARG0;
			    }
			}
		    }
		}
	    }
	    else {		/* (guest) */
		while (getaclentry("guest-root", &entry) && ARG0) {
		    if (!ARG1) {
			if (!root_path)
			    root_path = ARG0;
		    }
		    else {
			int which;
			char *ptr;

			for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
			    if (!strcmp(ARG[which], "*")) {
				if (!root_path)
				    root_path = ARG0;
			    }
			    else {
				if (ARG[which][0] == '%') {
				    if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
					if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
					    if (pw->pw_uid == strtoul(ARG[which] + 1, NULL, 0))
						root_path = ARG0;
					}
					else {
					    *ptr++ = '\0';
					    if ((ARG[which][1] == '\0')
						|| (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0)))
						root_path = ARG0;
					    *--ptr = '+';
					}
				    }
				    else {
					*ptr++ = '\0';
					if (((ARG[which][1] == '\0')
					     || (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0)))
					    && ((*ptr == '\0')
						|| (pw->pw_uid <= strtoul(ptr, NULL, 0))))
					    root_path = ARG0;
					*--ptr = '-';
				    }
				}
				else {
#ifdef OTHER_PASSWD
				    struct passwd *guest_pw = bero_getpwnam(ARG[which], _path_passwd);
#else
				    struct passwd *guest_pw = getpwnam(ARG[which]);
#endif
				    if (guest_pw && (pw->pw_uid == guest_pw->pw_uid))
					root_path = ARG0;
				}
			    }
			}
		    }
		}
	    }

	    if (root_path) {
		struct passwd *chroot_pw = NULL;

#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
		if (virtual_mode && strcmp(root_path, virtual_root) && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
		    syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
			   remoteident, pw->pw_name);
#endif
		    reply(530, "Login incorrect.");
		    if (++login_attempts >= lgi_failure_threshold) {
			syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
			exit(0);
		    }
		    goto bad;
		}
#endif
		(void) strncpy(chroot_path, root_path, sizeof(chroot_path));
		chroot_path[sizeof(chroot_path) - 1] = '\0';
		pw->pw_dir = sgetsave(chroot_path);
		if (chroot(root_path) < 0 || chdir("/") < 0) {
#ifdef VERBOSE_ERROR_LOGING
		    syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set guest privileges) for %s, %s",
			   remoteident, pw->pw_name);
#endif
		    reply(530, "Can't set guest privileges.");
		    goto bad;
		}
#ifdef OTHER_PASSWD
		if ((chroot_pw = bero_getpwuid(pw->pw_uid, _path_passwd)) != NULL)
#else
		if ((chroot_pw = getpwuid(pw->pw_uid)) != NULL)
#endif
		    if (chdir(chroot_pw->pw_dir) >= 0)
			home = sgetsave(chroot_pw->pw_dir);
		goto slimy_hack;	/* onea these days I'll make this structured code, honest ... */
	    }
	}

	/* determine root and home directory */

	if ((sp = strstr(pw->pw_dir, "/./")) == NULL) {
	    (void) strncpy(chroot_path, pw->pw_dir, sizeof(chroot_path));
	    chroot_path[sizeof(chroot_path) - 1] = '\0';
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
	    if (virtual_mode && strcmp(chroot_path, virtual_root) && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "Login incorrect.");
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
		    exit(0);
		}
		goto bad;
	    }
#endif
	    if (chroot(pw->pw_dir) < 0 || chdir("/") < 0) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set guest privileges) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "Can't set guest privileges.");
		goto bad;
	    }
	}
	else {
	    *sp++ = '\0';
	    (void) strncpy(chroot_path, pw->pw_dir, sizeof(chroot_path));
	    chroot_path[sizeof(chroot_path) - 1] = '\0';
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
	    if (virtual_mode && strcmp(chroot_path, virtual_root) && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "Login incorrect.");
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
		    exit(0);
		}
		goto bad;
	    }
#endif
	    if (chroot(pw->pw_dir) < 0 || chdir(++sp) < 0) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set guest privileges) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(550, "Can't set guest privileges.");
		goto bad;
	    }
#ifdef ALTERNATE_CD
	    home = sp;
#endif
	}
      slimy_hack:
	/* shut up you stupid compiler! */  {
	    int i = 0;
	    i++;
	}
    }
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
    else if (virtual_mode && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
	       remoteident, pw->pw_name);
#endif
	reply(530, "Login incorrect.");
	if (++login_attempts >= lgi_failure_threshold) {
	    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
	    exit(0);
	}
	goto bad;
    }
#endif
#ifdef AIX
    {
	/* AIX 3 lossage.  Don't ask.  It's undocumented.  */
	priv_t priv;

	priv.pv_priv[0] = 0;
	priv.pv_priv[1] = 0;
/*       setgroups(NULL, NULL); */
	if (setpriv(PRIV_SET | PRIV_INHERITED | PRIV_EFFECTIVE | PRIV_BEQUEATH,
		    &priv, sizeof(priv_t)) < 0 ||
	    setuidx(ID_REAL | ID_EFFECTIVE, (uid_t) pw->pw_uid) < 0 ||
	    seteuid((uid_t) pw->pw_uid) < 0) {
#ifdef VERBOSE_ERROR_LOGING
	    syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set uid) for %s, %s",
		   remoteident, pw->pw_name);
#endif
	    reply(530, "Can't set uid (AIX3).");
	    goto bad;
	}
    }
#ifdef UID_DEBUG
    lreply(230, "ruid=%d, euid=%d, suid=%d, luid=%d", getuidx(ID_REAL),
	   getuidx(ID_EFFECTIVE), getuidx(ID_SAVED), getuidx(ID_LOGIN));
    lreply(230, "rgid=%d, egid=%d, sgid=%d, lgid=%d", getgidx(ID_REAL),
	   getgidx(ID_EFFECTIVE), getgidx(ID_SAVED), getgidx(ID_LOGIN));
#endif
#else
#ifdef HAVE_SETREUID
    if (setreuid(-1, (uid_t) pw->pw_uid) < 0) {
#else
    if (seteuid((uid_t) pw->pw_uid) < 0) {
#endif
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set uid) for %s, %s",
	       remoteident, pw->pw_name);
#endif
	reply(530, "Can't set uid.");
	goto bad;
    }
#endif
    if (!anonymous && !guest) {
#ifdef POST_AUTH_PROCESS
	run_post_auth_process(pw);
#endif /* POST_AUTH_PROCESS */	
	if ((!debug_no_fork) && chdir(pw->pw_dir) < 0) {
#ifdef PARANOID
#ifdef VERBOSE_ERROR_LOGING
	    syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot chdir) for %s, %s",
		   remoteident, pw->pw_name);
#endif
	    reply(530, "User %s: can't change directory to %s.",
		  pw->pw_name, pw->pw_dir);
	    goto bad;
#else
	    if (chdir("/") < 0) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot chdir) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "User %s: can't change directory to %s.",
		      pw->pw_name, pw->pw_dir);
		goto bad;
	    }
	    else {
		lreply(230, "No directory! Logging in with home=/");
#ifdef ALTERNATE_CD
		home = defhome;
#endif
	    }
#endif
	}
    }

    if (passwarn) {
	lreply(230, "The response '%s' is not valid", passwd);
	lreply(230,
	       "Next time please use your e-mail address as your password");
	lreply(230, "        for example: %s@%s",
	       authenticated ? authuser : "joe", remotehost);
    }

    /* following two lines were inside the next scope... */

    show_message(230, LOG_IN);
    show_message(230, C_WD);
    show_readme(230, LOG_IN);
    show_readme(230, C_WD);

#ifdef ULTRIX_AUTH
    if (!anonymous && numfails > 0) {
	lreply(230,
	   "There have been %d unsuccessful login attempts on your account",
	       numfails);
    }
#endif /* ULTRIX_AUTH */

    (void) is_shutdown(0, 0);	/* display any shutdown messages now */

    if (anonymous) {

	reply(230, "Guest login ok, access restrictions apply.");
	sprintf(proctitle, "%s: anonymous/%.*s", remotehost,
		(int) (sizeof(proctitle) - sizeof(remotehost) -
		       sizeof(": anonymous/")), passwd);
	setproctitle("%s", proctitle);
	if (logging)
	    syslog(LOG_INFO, "ANONYMOUS FTP LOGIN FROM %s, %s",
		   remoteident, passwd);
    }
    else {
	reply(230, "User %s logged in.%s", pw->pw_name, guest ?
	      "  Access restrictions apply." : "");
	sprintf(proctitle, "%s: %s", remotehost, pw->pw_name);
	setproctitle("%s", proctitle);
	if (logging)
	    syslog(LOG_INFO, "FTP LOGIN FROM %s, %s", remoteident, pw->pw_name);
/* H* mod: if non-anonymous user, copy it to "authuser" so everyone can
   see it, since whoever he was @foreign-host is now largely irrelevant.
   NMM mod: no, it isn't!  Think about accounting for the transfers from or
   to a shared account. */
	/* strcpy (authuser, pw->pw_name); */
    }				/* anonymous */
#ifdef ALTERNATE_CD
    if (!home)
#endif
	home = pw->pw_dir;	/* home dir for globbing */
    (void) umask(defumask);
    time(&login_time);
    {
	struct aclmember *entry;
	entry = NULL;
	while (getaclentry("limit-time", &entry) && ARG0 && ARG1)
	    if ((anonymous && strcasecmp(ARG0, "anonymous") == 0)
		|| (guest && strcasecmp(ARG0, "guest") == 0)
		|| ((guest | anonymous) && strcmp(ARG0, "*") == 0))
		limit_time = strtoul(ARG1, NULL, 0);
    }
    return;
  bad:
    /* Forget all about it... */
    if (xferlog)
	close(xferlog);
    xferlog = 0;
    end_login();
    return;
}

int restricteduid(uid_t uid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct passwd *pw;

    while (getaclentry("restricted-uid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		pw = getpwnam(ARG[which]);
#endif
		if (pw && (uid == pw->pw_uid))
		    return (1);
	    }
	}
    }
    return (0);
}

int unrestricteduid(uid_t uid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct passwd *pw;

    while (getaclentry("unrestricted-uid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		pw = getpwnam(ARG[which]);
#endif
		if (pw && (uid == pw->pw_uid))
		    return (1);
	    }
	}
    }
    return (0);
}

int restrictedgid(gid_t gid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct group *grp;

    while (getaclentry("restricted-gid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		grp = getgrnam(ARG[which]);
		if (grp && (gid == grp->gr_gid))
		    return (1);
	    }
	}
    }
    return (0);
}

int unrestrictedgid(gid_t gid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct group *grp;

    while (getaclentry("unrestricted-gid", &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		grp = getgrnam(ARG[which]);
		if (grp && (gid == grp->gr_gid))
		    return (1);
	    }
	}
    }
    return (0);
}

char *opt_string(int options)
{
    static char buf[100];
    char *ptr = buf;

    if ((options & O_COMPRESS) != 0)	/* debian fixes: NULL -> 0 */
	*ptr++ = 'C';
    if ((options & O_TAR) != 0)
	*ptr++ = 'T';
    if ((options & O_UNCOMPRESS) != 0)
	*ptr++ = 'U';
    if (options == 0)
	*ptr++ = '_';
    *ptr++ = '\0';
    return (buf);
}

#ifdef INTERNAL_LS
char *rpad(char *s, unsigned int len)
{
    char *a;
    a = (char *) malloc(len + 1);
    memset(a, ' ', len-1);
    a[len] = 0;
    if (strlen(s) <= len)
	memcpy(a, s, strlen(s));
    else
	strncpy(a, s, len);
    return a;
}

char *ls_file(const char *file, int nameonly, char remove_path, char classify)
{
    static const char month[12][4] =
    {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    char *permissions;
    struct stat s;
    struct tm *t;
    char *ls_entry;
    char *owner, *ownerg;
    char *rpowner, *rpownerg;
    char *link;
#ifndef LS_NUMERIC_UIDS
    struct passwd *pw;
    struct group *gr;
#endif
    link = NULL;
    owner = NULL;
    ownerg = NULL;
    if (lstat(file, &s) != 0)	/* File doesn't exist, or is not readable by user */
	return NULL;
    ls_entry = (char *) malloc(312);
    memset(ls_entry, 0, 312);
    permissions = strdup("----------");
    if (S_ISLNK(s.st_mode)) {
	permissions[0] = 'l';
	if (classify)
	    classify = '@';
    }
    else if (S_ISDIR(s.st_mode)) {
	permissions[0] = 'd';
	if (classify)
	    classify = '/';
    }
    else if (S_ISBLK(s.st_mode))
	permissions[0] = 'b';
    else if (S_ISCHR(s.st_mode))
	permissions[0] = 'c';
    else if (S_ISFIFO(s.st_mode)) {
	permissions[0] = 'p';
	if (classify == 1)
	    classify = '=';
    }
#ifdef S_ISSOCK
    else if (S_ISSOCK(s.st_mode))
	permissions[0] = 's';
#endif
    if ((s.st_mode & S_IRUSR) == S_IRUSR)
	permissions[1] = 'r';
    if ((s.st_mode & S_IWUSR) == S_IWUSR)
	permissions[2] = 'w';
    if ((s.st_mode & S_IXUSR) == S_IXUSR) {
	permissions[3] = 'x';
	if (classify == 1)
	    classify = '*';
#ifndef HIDE_SETUID
	if ((s.st_mode & S_ISUID) == S_ISUID)
	    permissions[3] = 's';
#endif
    }
#ifndef HIDE_SETUID
    else if ((s.st_mode & S_ISUID) == S_ISUID)
	permissions[3] = 'S';
#endif
    if ((s.st_mode & S_IRGRP) == S_IRGRP)
	permissions[4] = 'r';
    if ((s.st_mode & S_IWGRP) == S_IWGRP)
	permissions[5] = 'w';
    if ((s.st_mode & S_IXGRP) == S_IXGRP) {
	permissions[6] = 'x';
	if (classify == 1)
	    classify = '*';
#ifndef HIDE_SETUID
	if ((s.st_mode & S_ISGID) == S_ISGID)
	    permissions[6] = 's';
#endif
    }
#ifndef HIDE_SETUID
    else if ((s.st_mode & S_ISGID) == S_ISGID)
	permissions[6] = 'S';
#endif
    if ((s.st_mode & S_IROTH) == S_IROTH)
	permissions[7] = 'r';
    if ((s.st_mode & S_IWOTH) == S_IWOTH)
	permissions[8] = 'w';
    if ((s.st_mode & S_IXOTH) == S_IXOTH) {
	permissions[9] = 'x';
	if (classify == 1)
	    classify = '*';
#ifndef HIDE_SETUID
	if ((s.st_mode & S_ISVTX) == S_ISVTX)
	    permissions[9] = 't';
#endif
    }
#ifndef HIDE_SETUID
    else if ((s.st_mode & S_ISVTX) == S_ISVTX)
	permissions[9] = 'T';
#endif
    t = localtime(&s.st_mtime);
#ifndef LS_NUMERIC_UIDS
#ifdef OTHER_PASSWD
    pw = bero_getpwuid(s.st_uid, _path_passwd);
#else
    pw = getpwuid(s.st_uid);
#endif
    if (pw != NULL)
	owner = strdup(pw->pw_name);
    gr = getgrgid(s.st_gid);
    if (gr != NULL)
	ownerg = strdup(gr->gr_name);
#endif
    if (owner == NULL) {	/* Can't figure out username (or don't want to) */
	if (s.st_uid == 0)
	    owner = strdup("root");
	else {
	    owner = (char *) malloc(9);
	    memset(owner, 0, 9);
#ifdef SOLARIS_2
	    snprintf(owner, 8, "%lu", s.st_uid);
#else
	    snprintf(owner, 8, "%u", s.st_uid);
#endif
	}
    }
    if (ownerg == NULL) {	/* Can't figure out groupname (or don't want to) */
	if (s.st_gid == 0)
	    ownerg = strdup("root");
	else {
	    ownerg = (char *) malloc(9);
	    memset(ownerg, 0, 9);
#ifdef SOLARIS_2
	    snprintf(ownerg, 8, "%lu", s.st_gid);
#else
	    snprintf(ownerg, 8, "%u", s.st_gid);
#endif
	}
    }

#ifdef HAVE_LSTAT
    if ((s.st_mode & S_IFLNK) == S_IFLNK) {
	link = (char *) malloc(MAXPATHLEN);
	memset(link, 0, MAXPATHLEN);
	if (readlink(file, link, MAXPATHLEN) == -1) {
	    free(link);
	    link = NULL;
	}
    }
#endif

    if (remove_path != 0 && strchr(file, '/'))
	file = strrchr(file, '/') + 1;

    rpowner = rpad(owner, 8);
    rpownerg = rpad(ownerg, 8);

#ifdef SOLARIS_2
#define N_FORMAT "lu"
#define S_FORMAT "lu"
#else
#if defined(__FreeBSD__) || defined(__bsdi__)
#define N_FORMAT "u"
#define S_FORMAT "ld"
#else
#define N_FORMAT "u"
#define S_FORMAT "u"
#endif
#endif

    if (nameonly) {
	sprintf(ls_entry, "%s", file);
	if (link != NULL)
	    free(link);
    }
    else {
	if ((time(NULL) - s.st_mtime) > 6307200) {	/* File is older than 6 months */
	    if (link == NULL)
		snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" S_FORMAT " %s %2u %5u %s", permissions, s.st_nlink, rpowner, rpownerg, (long) s.st_size, month[t->tm_mon], t->tm_mday, 1900 + t->tm_year, file);
	    else {
		snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" S_FORMAT " %s %2u %5u %s -> %s", permissions, s.st_nlink, rpowner, rpownerg, (long) s.st_size, month[t->tm_mon], t->tm_mday, 1900 + t->tm_year, file, link);
		free(link);
	    }
	}
	else if (link == NULL)
	    snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" S_FORMAT " %s %2u %02u:%02u %s", permissions, s.st_nlink, rpowner, rpownerg, (long) s.st_size, month[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, file);
	else {
	    snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" S_FORMAT " %s %2u %02u:%02u %s -> %s", permissions, s.st_nlink, rpowner, rpownerg, (long) s.st_size, month[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, file, link);
	    free(link);
	}
    }
    free(rpowner);
    free(rpownerg);
    free(owner);
    free(ownerg);
    if (classify > 1)
	sprintf(ls_entry + strlen(ls_entry), "%c", classify);
    strcat(ls_entry, "\r\n");
    free(permissions);
    return ls_entry;
}

void 
ls_dir(
    char *d, 
    char ls_a, 
    char ls_F, 
    char ls_l, 
    char ls_R, 
    char omit_total, 
    FILE *out)
{
    int total;
    char *realdir;		/* fixed up value to pass to glob() */
    char **subdirs;		/* Subdirs to be scanned for ls -R  */
    int numSubdirs = 0;
    glob_t g;
    char isDir;			/* 0: d is a file; 1: d is some files; 2: d is dir */
    struct stat s;
    char *dirlist;
    unsigned long dl_size, dl_used;
    char *c;
    char *lsentry;
    int i;
#ifndef GLOB_PERIOD
    char *dperiod;
#endif

    isDir = 0;
    realdir = (char *) malloc(strlen(d) + 3);
    memset(realdir, 0, strlen(d) + 3);
    strcpy(realdir, d);
    if (strcmp(realdir, ".") == 0)
	realdir[0] = '*';
    if (strcmp(realdir + strlen(realdir) - 2, "/.") == 0)
	realdir[strlen(realdir) - 1] = '*';
    if (realdir[strlen(realdir) - 1] == '/')
	strcat(realdir, "*");
    if (strchr(realdir, '*') || strchr(realdir, '?'))
	isDir = 1;
    if (strcmp(realdir, "*") == 0 || 
        strcmp(realdir + strlen(realdir) - 2, "/*") == 0)
    {
	isDir = 2;
    }
    else 
    {
	if (lstat(realdir, &s) == 0) {
	    if (S_ISDIR(s.st_mode)) {
		strcat(realdir, "/*");
		isDir = 2;
	    }
	}
    }

    if (isDir == 0) 
    {
	if (ls_l) 
        {
	    lsentry = ls_file(realdir, 0, 0, ls_F);
	    if (lsentry != NULL) 
            {
		if (draconian_FILE != NULL) 
                {
		    (void) signal(SIGALRM, draconian_alarm_signal);
		    alarm(timeout_data);
		    fputs(lsentry, out);
		    (void) signal(SIGALRM, SIG_DFL);
		}
		free(lsentry);
	    }
	}
	else 
        {
	    if (draconian_FILE != NULL) 
            {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
		fputs(realdir, out);
		(void) signal(SIGALRM, SIG_DFL);
	    }
	}
	free(realdir);
    }
    else 
    {
	if (ls_R) 
        {
	    numSubdirs = 0;
	    subdirs = (char **) malloc(200 * sizeof(char *));
	    memset(subdirs, 0, 200 * sizeof(char *));
	}

	dl_size = 65536;
	dirlist = (char *) malloc(65536);
	memset(dirlist, 0, 65536);
	dl_used = 0;

	total = 0;
	memset(&g, 0, sizeof(g));
	if (ls_a) {
#ifdef GLOB_PERIOD
	    if (glob(realdir, GLOB_ERR | GLOB_PERIOD, NULL, &g) != 0)
		g.gl_pathc = 0;
#else
	    dperiod = (char *) malloc(strlen(realdir) + 2);
	    memset(dperiod, 0, strlen(realdir) + 2);
	    strcpy(dperiod, ".");
	    strcat(dperiod, realdir);
	    if (glob(dperiod, GLOB_ERR, NULL, &g) != 0)
		g.gl_pathc = 0;
	    glob(realdir, GLOB_ERR | GLOB_APPEND, NULL, &g);
	    free(dperiod);
#endif
	}
	else if (glob(realdir, GLOB_ERR, NULL, &g) != 0)
        {
	    g.gl_pathc = 0;
        }

	free(realdir);
	for (i = 0; i < g.gl_pathc; i++) {
	    c = g.gl_pathv[i];
	    if (lstat(c, &s) != -1) {
		if (ls_l) {
		    total += s.st_blocks;
		    lsentry = ls_file(c, 0, 1, ls_F);
		    if (lsentry != NULL) {
			/* This can actually happen even though the lstat() worked - 
			   if someone deletes the file between the lstat() and ls_file()
			   calls. Unlikely, but better safe than sorry... */
			int flag = snprintf(dirlist + dl_used, dl_size - dl_used, "%s", lsentry);
			dl_used += (flag == -1 ? dl_size - dl_used : flag);
			free(lsentry);
		    }
		}
		else {
		    int flag;
		    lsentry = ls_file(c, 1, 1, ls_F);
		    if (lsentry != NULL) {
		        flag = snprintf(dirlist + dl_used, dl_size - dl_used, "%s", lsentry);
		        dl_used += (flag == -1 ? dl_size - dl_used : flag);
			free(lsentry);
		    }
		}
		if ((ls_R != 0) && (S_ISDIR(s.st_mode))
		    && (strcmp(c, "..") != 0) && (strcmp(c, ".") != 0)
		&& !(strlen(c) > 3 && strcmp(c + strlen(c) - 3, "/..") == 0)
		    && !(strlen(c) > 2 && strcmp(c + strlen(c) - 2, "/.") == 0)) {
		    subdirs[numSubdirs++] = strdup(c);
		    if ((numSubdirs % 200) == 0)
			subdirs = (char **) realloc(subdirs, (numSubdirs + 200) * sizeof(char *));
		}
	    }
	    if (dl_used + 512 >= dl_size) {
		dl_size += 65536;
		dirlist = (char *) realloc(dirlist, dl_size);
	    }
	}
	globfree(&g);
	if (ls_l && isDir == 2 && omit_total == 0) {
	    if (draconian_FILE != NULL) {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
		fprintf(out, "total %u\r\n", total);
	    }
	}
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    fputs(dirlist, out);
	}
	free(dirlist);
	if (ls_R) {
	    for (i = 0; i < numSubdirs; i++) {
		if (draconian_FILE != NULL) {
		    (void) signal(SIGALRM, draconian_alarm_signal);
		    alarm(timeout_data);
		    fprintf(out, "\r\n%s:\r\n", subdirs[i]);
		    ls_dir(subdirs[i], ls_a, ls_F, ls_l, ls_R, 0, out);
		}
		free(subdirs[i]);
	    }
	    free(subdirs);
	}
    }
}

void 
ls(
    char *                                  file, 
    char                                    nlst)
{
    FILE *                                  out;
    char                                    free_file = 0;
    char ls_l = 0, ls_a = 0, ls_R = 0, ls_F = 0;

    if (nlst == 0)
    {
	ls_l = 1;		/* LIST defaults to ls -l */
    }
    if (file == NULL) 
    {
	file = strdup(".");
	free_file = 1;
    }
    if (strcmp(file, "*") == 0)
    {
	file[0] = '.';
    }

    if (file[0] == '-') 
    {	/* options... */
	if (strchr(file, ' ') == 0) 
        {
	    if (strchr(file, 'l'))
            {
		ls_l = 1;
            }
	    if (strchr(file, 'a'))
            {
		ls_a = 1;
            }
	    if (strchr(file, 'R'))
            {
		ls_R = 1;
            }
	    if (strchr(file, 'F'))
            {
		ls_F = 1;
            }
	    file = strdup(".");
	    free_file = 1;
	}
	else 
        {
	    if (strchr(file, 'l') != NULL && strchr(file, 'l') < strchr(file, ' '))
		ls_l = 1;
	    if (strchr(file, 'a') != NULL && strchr(file, 'a') < strchr(file, ' '))
		ls_a = 1;
	    if (strchr(file, 'R') != NULL && strchr(file, 'R') < strchr(file, ' '))
		ls_R = 1;
	    if (strchr(file, 'F') != NULL && strchr(file, 'F') < strchr(file, ' '))
		ls_F = 1;
	    file = strchr(file, ' ');
	}
    }
    /* ignore additional whitespaces between parameters */
    while (file[0] == ' ')	
    {
	file++;
    }

    if (strlen(file) == 0)  
    {
	file = strdup(".");
	free_file = 1;
    }

    out = dataconn("directory listing", -1, "w");

    draconian_FILE = out;

    transflag++;

    fixpath(file);
    if (file[0] == '\0') 
    {
	if (free_file != 0)
        {
	    free(file);
        }
	file = strdup(".");
	free_file = 1;
    }

    ls_dir(file, ls_a, ls_F, ls_l, ls_R, 0, out);
    data = -1;
    pdata = -1;
    if (draconian_FILE != NULL) 
    {
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	fflush(out);
    }
    if (draconian_FILE != NULL) 
    {
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	socket_flush_wait(out);
    }
    if (draconian_FILE != NULL) 
    {
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	fclose(out);
	draconian_FILE = NULL;
    }
    alarm(0);
    transflag = 0;
    reply(226, "Transfer complete.");
    if (free_file != 0)
    {
	free(file);
    }
}
#endif /* INTERNAL_LS */

void 
retrieve(
    char *                                           cmd, 
    char *                                           name, 
    off_t                                            offset, 
    off_t                                            length)
{
    FILE *fin = NULL, *dout;
    struct stat st, junk;
    int (*closefunc) () = NULL;
    int options = 0;
    int ThisRetrieveIsData = retrieve_is_data;
    time_t start_time = time(NULL);
    char *logname;
    char namebuf[MAXPATHLEN];
    char fnbuf[MAXPATHLEN];
    int TransferComplete = 0;
    struct convert *cptr;
    char realname[MAXPATHLEN];
    int stat_ret = -1;

    off_t                            tmp_restart = 0; /* added by JB */

    extern int checknoretrieve(char *);

    wu_realpath(name, realname, chroot_path);

#   if HAVE_BROKEN_STAT
    if(cmd == NULL && (stat_ret = open(name, O_RDONLY)) >= 0)
    {
	st.st_size = lseek(stat_ret, 0, SEEK_END);
	st.st_blksize = BUFSIZ;
	close(stat_ret);
	stat_ret = 0;
    }
    if(cmd == NULL && stat_ret == 0)
#   else
    if (cmd == NULL && (stat_ret = stat(name, &st)) == 0)
#   endif
	/* there isn't a command and the file exists */
	if (use_accessfile && checknoretrieve(name)) {	/* see above.  _H */
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to download %s (noretrieve)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to download %s (noretrieve)",
			   pw->pw_name, remoteident, realname);
	    return;
	}

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    if (retrieve_is_data)
    {
	if (((file_limit_data_out > 0) && 
             (file_count_out >= file_limit_data_out))
	    || ((file_limit_data_total > 0) && 
               (file_count_total >= file_limit_data_total))
	    || ((data_limit_data_out > 0) 
               && ( (data_count_out + st.st_size) >= data_limit_data_out))
	    || ((data_limit_data_total > 0) && 
               ( (data_count_total + st.st_size) >= data_limit_data_total))) 
        {
	    if (log_security)
            {
		if (anonymous)
		    syslog(LOG_NOTICE, 
          "anonymous(%s) of %s tried to retrieve %s (Transfer limits exceeded)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to retrieve %s (Transfer limits exceeded)",
			   pw->pw_name, remoteident, realname);
            }
	    reply(553, "Permission denied on server. (Transfer limits exceeded)");
	    return;
	}
    }

    if (((file_limit_raw_out > 0) && (xfer_count_out >= file_limit_raw_out))
	|| ((file_limit_raw_total > 0) && (xfer_count_total >= file_limit_raw_total))
	|| ((data_limit_raw_out > 0) && (byte_count_out >= data_limit_raw_out))
	|| ((data_limit_raw_total > 0) && (byte_count_total >= data_limit_raw_total))) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to retrieve %s (Transfer limits exceeded)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to retrieve %s (Transfer limits exceeded)",
		       pw->pw_name, remoteident, realname);
	reply(553, "Permission denied on server. (Transfer limits exceeded)");
	return;
    }
#ifdef RATIO
    if (retrieve_is_data && (upload_download_rate > 0) )
	if( freefile = is_downloadfree(name) ) {
	    syslog(LOG_INFO, "%s is download free.", name );
	}
	else {
	    if( cmd == NULL ) {
		off_t credit = ( data_count_in * upload_download_rate ) - (data_count_out - total_free_dl);
		if( st.st_size > credit  ) {
		    reply( 550, "%s: file size %d exceed credit %d.",
			name, st.st_size, credit );
		    goto done;
		}
	    }
	}
#endif /* RATIO */
#endif
#endif


    logname = (char *) NULL;
    /* file does not exist */
    if (cmd == NULL && stat_ret != 0) 
    {
	char *ptr;

	for (cptr = cvtptr; cptr != NULL; cptr = cptr->next) 
        {
	    if (!(mangleopts & O_COMPRESS) && (cptr->options & O_COMPRESS))
            {
		continue;
            }
	    if (!(mangleopts & O_UNCOMPRESS) && (cptr->options & O_UNCOMPRESS))
            {
		continue;
            }
	    if (!(mangleopts & O_TAR) && (cptr->options & O_TAR))
            {
		continue;
            }

	    if ((cptr->stripfix) && (cptr->postfix)) 
            {
		int pfxlen = strlen(cptr->postfix);
		int sfxlen = strlen(cptr->stripfix);
		int namelen = strlen(name);
		(void) strcpy(fnbuf, name);

		if (namelen <= pfxlen)
		    continue;
		if ((namelen - pfxlen + sfxlen) >= sizeof(fnbuf))
		    continue;

		if (strcmp(fnbuf + namelen - pfxlen, cptr->postfix))
		    continue;
		*(fnbuf + namelen - pfxlen) = '\0';
		(void) strcat(fnbuf, cptr->stripfix);
		if (stat(fnbuf, &st) != 0)
		    continue;
	    }
	    else if (cptr->postfix) 
            {
		int pfxlen = strlen(cptr->postfix);
		int namelen = strlen(name);

		if (namelen <= pfxlen)
		    continue;
		(void) strcpy(fnbuf, name);
		if (strcmp(fnbuf + namelen - pfxlen, cptr->postfix))
		    continue;
		*(fnbuf + namelen - pfxlen) = (char) NULL;
		if (stat(fnbuf, &st) != 0)
		    continue;
	    }
	    else if (cptr->stripfix) 
            {
		(void) strcpy(fnbuf, name);
		(void) strcat(fnbuf, cptr->stripfix);
		if (stat(fnbuf, &st) != 0)
		    continue;
	    }
	    else 
            {
		continue;
	    }

	    if (S_ISDIR(st.st_mode)) 
            {
		if (!cptr->types || !(cptr->types & T_DIR)) {
		    reply(550, "Cannot %s directories.", cptr->name);
		    return;
		}
		if ((cptr->options & O_TAR)) 
                {
		    strcpy(namebuf, fnbuf);
		    strcat(namebuf, "/.notar");
		    if (stat(namebuf, &junk) == 0) {
			if (log_security)
			    if (anonymous)
				syslog(LOG_NOTICE, "anonymous(%s) of %s tried to tar %s (.notar)",
				       guestpw, remoteident, realname);
			    else
				syslog(LOG_NOTICE, "%s of %s tried to tar %s (.notar)",
				       pw->pw_name, remoteident, realname);
			reply(550, "Sorry, you may not TAR that directory.");
			return;
		    }
		}
	    }
/* XXX: checknoretrieve() test is weak in that if I can't get /etc/passwd
   but I can tar /etc or /, I still win.  Be careful out there... _H*
   but you could put .notar in / and /etc and stop that ! */
	    if (use_accessfile && checknoretrieve(fnbuf)) {
		if (log_security)
		    if (anonymous)
			syslog(LOG_NOTICE, "anonymous(%s) of %s tried to download %s (noretrieve)",
			       guestpw, remoteident, realname);
		    else
			syslog(LOG_NOTICE, "%s of %s tried to download %s (noretrieve)",
			       pw->pw_name, remoteident, realname);
		return;
	    }

	    if (S_ISREG(st.st_mode) && (!cptr->types || (cptr->types & T_REG) == 0)) {
		reply(550, "Cannot %s plain files.", cptr->name);
		return;
	    }
	    if (S_ISREG(st.st_mode) != 0 && S_ISDIR(st.st_mode) != 0) {
		reply(550, "Cannot %s special files.", cptr->name);
		return;
	    }
	    if ((!cptr->types || !(cptr->types & T_ASCII)) && deny_badasciixfer(550, ""))
		return;

	    logname = &fnbuf[0];
	    options |= cptr->options;

	    strcpy(namebuf, cptr->external_cmd);
	    if ((ptr = strchr(namebuf, ' ')) != NULL)
		*ptr = '\0';
	    if (stat(namebuf, &st) != 0) {
		syslog(LOG_ERR, "external command %s not found",
		       namebuf);
		reply(550,
		"Local error: conversion program not found. Cannot %s file.",
		      cptr->name);
		return;
	    }
	    (void) retrieve(cptr->external_cmd, logname, offset, length);

	    goto logresults;	/* transfer of converted file completed */
	}
    }

    /* no command */
    if (cmd == NULL) 
    {
	fin = fopen(name, "r"), closefunc = fclose;
	st.st_size = 0;
    }
    else 
    {			/* run command */
	static char line[BUFSIZ];

	(void) snprintf(line, sizeof line, cmd, name), name = line;
	fin = ftpd_popen(line, "r", 1), closefunc = ftpd_pclose;
	st.st_size = -1;
#ifdef HAVE_ST_BLKSIZE
	st.st_blksize = BUFSIZ;
#endif
    }

    if (fin == NULL) 
    {
	if (errno != 0)
	    perror_reply(550, name);
	if ((errno == EACCES) || (errno == EPERM))
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to download %s (file permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to download %s (file permissions)",
			   pw->pw_name, remoteident, realname);
	return;
    }
    if (cmd == NULL &&
	(fstat(fileno(fin), &st) < 0 || (st.st_mode & S_IFMT) != S_IFREG)) 
    {
#       if HAVE_BROKEN_STAT
        /* Is this safe to do on a FILE *'s fd? */
        st.st_size = lseek(fileno(fin), 0, SEEK_END);
	lseek(fileno(fin), 0, SEEK_SET);
	if(st.st_size < 0)
	{
	    reply(550, "%s: not a plain file.", name);
	    goto done;
	}
#       else
	reply(550, "%s: not a plain file.", name);
	goto done;
#       endif
    }


    /* added by JB */
    if(restart_point)
    {
        tmp_restart = restart_point;
        if(offset != -1) tmp_restart += offset;
    }
    else if(offset != -1)
    {
        tmp_restart += offset;
    }
    else
    {
        tmp_restart = 0;
    }

#ifdef GSSAPI_GLOBUS 
#ifdef GLOBUS_AUTHORIZATION
     
    if (retrieve_is_data)
    {
        /* An actual get of a file (e.g. a "get") */
        if (!ftp_check_authorization(realname, "read"))
        {
            reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                  "%s: Permission denied by proxy credential ('read')",
                  name);   
            syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                   "%s of %s tried to download %s (noretrieve)",
                   pw->pw_name, remoteident, realname); 
            return;
        }
    }
    else
    {
        /* Just getting information about a file (e.g. an "ls") */
        if (!ftp_check_authorization(realname, "lookup"))
        {
            reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                  "%s: Permission denied by proxy credential ('lookup')",
                  name);   
            syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                   "%s of %s tried to lookup %s (noretrieve)",
                   pw->pw_name, remoteident, realname); 
            return;
        }
    }
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */

#   if defined(USE_GLOBUS_DATA_CODE)
    {
            TransferComplete = g_send_data(
                                   name, 
                                   fin, 
                                   &g_data_handle, 
                                   tmp_restart,
                                   offset==-1?0:offset, 
                                   length, 
                                   st.st_size);
    }
#   else
    {
        if (tmp_restart) 
        {
            if (type == TYPE_A) 
            {
                register int i, n, c;

	        n = tmp_restart;
                i = 0;
	        while (i++ < n) {
	    	    if ((c = getc(fin)) == EOF) {
		        perror_reply(550, name);
		        goto done;
		    }
		    if (c == '\n')
		        i++;
	        }
	    }
	    else if (lseek(fileno(fin), tmp_restart, SEEK_SET) < 0) {
	        perror_reply(550, name);
	        goto done;
	    }
        }

        dout = dataconn(name, st.st_size, "w");
        if (dout == NULL)
        {
	    goto done;
        }
#       ifdef BUFFER_SIZE
            TransferComplete = SEND_DATA(name, fin, dout, BUFFER_SIZE, length);
#       else
#           ifdef HAVE_ST_BLKSIZE
                TransferComplete = SEND_DATA(name, fin, dout, 
                                       st.st_blksize * 2, length);
#           else
                TransferComplete = SEND_DATA(name, fin, dout, BUFSIZ);
#           endif
#       endif
       (void) fclose(dout);
    }
#   endif


  logresults:
    if (ThisRetrieveIsData)
	fb_realpath((logname != NULL) ? logname : name, LastFileTransferred);

    if (log_outbound_xfers && (xferlog || syslogmsg) && (cmd == 0)) {
	char msg[MAXPATHLEN + 2 * MAXHOSTNAMELEN + 100 + 128];	/* AUTHNAMESIZE is 100 */
	size_t msglen;		/* for stupid_sprintf */
	int xfertime = time(NULL) - start_time;
	time_t curtime = time(NULL);
	int loop;

	if (!xfertime)
	    xfertime++;
#ifdef XFERLOG_REALPATH
	wu_realpath((logname != NULL) ? logname : name, &namebuf[0], chroot_path);
#else
	fb_realpath((logname != NULL) ? logname : name, &namebuf[0]);
#endif
	for (loop = 0; namebuf[loop]; loop++)
	    if (isspace(namebuf[loop]) || iscntrl(namebuf[loop]))
		namebuf[loop] = '_';

/* Some systems use one format, some another.  This takes care of the garbage */
#ifndef L_FORMAT		/* Autoconf detects this... */
#if (defined(BSD) && (BSD >= 199103)) && !defined(LONGOFF_T)
#define L_FORMAT "qd"
#else
#ifdef _AIX42
#define L_FORMAT "lld"
#else
#ifdef SOLARIS_2
#define L_FORMAT "ld"
#else
#define L_FORMAT "d"
#endif
#endif
#endif
#endif

/* Some sprintfs can't deal with a lot of arguments, so we split this */
/* Note it also needs fixing for C9X, so we ALWAYS split it. */
	sprintf(msg, "%.24s %d %s %" L_FORMAT " ",
		ctime(&curtime),
		xfertime,
		remotehost,
		byte_count
	    );
	msglen = strlen(msg);	/* sigh */
	snprintf(msg + msglen, sizeof(msg) - msglen, "%s %c %s %c %c %s ftp %d %s %c\n",
		 namebuf,
		 (type == TYPE_A) ? 'a' : 'b',
		 opt_string(options),
		 'o',
		 anonymous ? 'a' : (guest ? 'g' : 'r'),
		 anonymous ? guestpw : pw->pw_name,
		 authenticated,
		 authenticated ? authuser : "*",
		 TransferComplete ? 'c' : 'i'
	    );
	/* Ensure msg always ends with '\n' */
	if (strlen(msg) == sizeof(msg) - 1)
	    msg[sizeof(msg) - 2] = '\n';
	if (syslogmsg != 1)
	    write(xferlog, msg, strlen(msg));
	if (syslogmsg != 0)
	    syslog(LOG_INFO, "xferlog (send): %s", msg + 25);
    }
    data = -1;
    pdata = -1;
  done:
    if (closefunc)
	(*closefunc) (fin);
}

/*
 *  modified by JB for globus data code
 */
void 
store(
    char *                                    name, 
    char *                                    mode, 
    int                                       unique, 
    off_t                                     offset)
{
    FILE *                                    fout; 
    FILE *                                    din;
    struct stat                               st;
    int                                       TransferIncomplete = 1;
    char *                                    gunique(char *local);
    time_t                                    start_time = time(NULL);
    off_t                                       tmp_restart; /* added by JB */

    struct aclmember *                        entry = NULL;

    int                                       fdout;
    char                                      realname[MAXPATHLEN];

#ifdef OVERWRITE
    int                                       overwrite = 1;
    int                                       exists = 0;
#endif /* OVERWRITE */

    int                                       open_flags = 0;

#ifdef UPLOAD
    mode_t                                    oldmask;
    uid_t                                     uid;
    gid_t                                     gid;
    uid_t                                     oldid;
    int                                       f_mode = -1;
    int                                       match_value = -1;
    int                                       valid = 0;

    open_flags = (O_RDWR | O_CREAT |
		  ((mode != NULL && *mode == 'a') 
                    ? O_APPEND : (offset==-1) ? O_TRUNC : 0));
#endif /* UPLOAD */

    wu_realpath(name, realname, chroot_path);

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    {
        if (((file_limit_data_in > 0) && (file_count_in >= file_limit_data_in))
	     || ((file_limit_data_total > 0) && 
                 (file_count_total >= file_limit_data_total))
             || ((data_limit_data_in > 0) && 
                 (data_count_in >= data_limit_data_in))
             || ((data_limit_data_total > 0) && 
                 (data_count_total >= data_limit_data_total))) 
        {
            if (log_security)
            {
	        if (anonymous)
                {
                    syslog(LOG_NOTICE, 
         "anonymous(%s) of %s tried to upload %s (Transfer limits exceeded)",
		       guestpw, remoteident, realname);
                }
	        else
                {
		    syslog(LOG_NOTICE, 
                      "%s of %s tried to upload %s (Transfer limits exceeded)",
		       pw->pw_name, remoteident, realname);
                }
            }
            reply(553, 
              "Permission denied on server. (Transfer limits exceeded)");
            return;
        }
        if (((file_limit_raw_in > 0) && (xfer_count_in >= file_limit_raw_in))
             || ((file_limit_raw_total > 0) && 
                 (xfer_count_total >= file_limit_raw_total))
	     || ((data_limit_raw_in > 0) && 
                 (byte_count_in >= data_limit_raw_in))
	     || ((data_limit_raw_total > 0) && 
                 (byte_count_total >= data_limit_raw_total))) 
        {
            if (log_security)
            {
                if (anonymous)
                {
                    syslog(LOG_NOTICE, 
       "anonymous(%s) of %s tried to upload %s (Transfer limits exceeded)",
		       guestpw, remoteident, realname);
                }
                else
                {
		    syslog(LOG_NOTICE, 
                      "%s of %s tried to upload %s (Transfer limits exceeded)",
		       pw->pw_name, remoteident, realname);
                }
            }
            reply(553, 
             "Permission denied on server. (Transfer limits exceeded)");
            return;
        }
    }
#   endif /* TRANSFER_COUNT */
#   endif /* TRANSFER_LIMIT */

    if (unique && stat(name, &st) == 0 &&
	(name = gunique(name)) == NULL)
    {
	return;
    }
    /*
     * check the filename, is it legal?
     */
    if ((fn_check(name)) <= 0) 
    {
	if (log_security)
        {
	    if (anonymous)
            {
		syslog(LOG_NOTICE, 
                   "anonymous(%s) of %s tried to upload \"%s\" (path-filter)",
		       guestpw, remoteident, realname);
            }
	    else
            {
		syslog(LOG_NOTICE, 
                       "%s of %s tried to upload \"%s\" (path-filter)",
		       pw->pw_name, remoteident, realname);
             }
        }
	return;
    }

#   ifdef OVERWRITE
    {
        /* 
         * if overwrite permission denied and file exists... then deny the user
         * permission to write the file. 
         */
        while (getaclentry("overwrite", &entry) && ARG0 && ARG1 != NULL) 
        {
            if (type_match(ARG1))
            {
     	        if (strcasecmp(ARG0, "yes") != 0) 
                {
  		    overwrite = 0;
             	    open_flags |= O_EXCL;
	        }
            }
        }

#       ifdef PARANOID
        {
            overwrite = 0;
        }
#       endif
        if (!stat(name, &st))
        {
	    exists = 1;
        }

#ifdef GSSAPI_GLOBUS 
#ifdef GLOBUS_AUTHORIZATION
        if (exists)
        {
            /* put overwritting a current file */
            if (!ftp_check_authorization(realname, "write"))
            {
                reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                     "%s: Permission denied by proxy credential. ('write')",
                     name);
                syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                       "%s of %s tried to upload %s",
                      pw->pw_name, remoteident, realname);
                return;
            }      
        }
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */

        if (!overwrite && exists) 
        {
  	    if (log_security)
            {
	        if (anonymous)
                {
		    syslog(LOG_NOTICE, 
                       "anonymous(%s) of %s tried to overwrite %s",
		       guestpw, remoteident, realname);
                }
	        else
                {
              	    syslog(LOG_NOTICE, "%s of %s tried to overwrite %s",
		       pw->pw_name, remoteident, realname);
                }
            }
 	    reply(553, "%s: Permission denied on server. (Overwrite)", name);
	    return;
        }
    }
#   endif /* OVERWRITE */

#   ifdef UPLOAD
    {
        if ((match_value = upl_check(name, &uid, &gid, &f_mode, &valid)) < 0) 
        {
	    if (log_security)
            {
	        if (anonymous)
                {
		    syslog(LOG_NOTICE, 
                      "anonymous(%s) of %s tried to upload %s (upload denied)",
		       guestpw, remoteident, realname);
                }
	        else
                {
		    syslog(LOG_NOTICE, 
                      "%s of %s tried to upload %s (upload denied)",
		       pw->pw_name, remoteident, realname);
                }
            }
	    return;
        }

#ifdef GSSAPI_GLOBUS 
#ifdef GLOBUS_AUTHORIZATION
        if (!exists)
        {
            /* put uploading new file */
            if (!ftp_check_authorization(realname, "create"))
            {
             reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                   "%s: Permission denied by proxy credential. ('create')",
                   name); 
             syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL, 
                    "%s of %s tried to upload %s (upload denied)",
                    pw->pw_name, remoteident, realname);
              
             return;
            }
        }
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */
  
    /* do not truncate the file if we are restarting */
        if (restart_point)
        {
    	    open_flags &= ~O_TRUNC;
        }
        /* 
         * if the user has an explicit new file mode, than open the file using
         * that mode.  We must take care to not let the umask affect the file
         * mode.
         * 
         * else open the file and let the default umask determine the file 
         * mode. 
         */
        if (f_mode >= 0) 
        {
	    oldmask = umask(0000);
            fdout = open(name, open_flags, f_mode);
	    umask(oldmask);
        }
        else
        { 
	    fdout = open(name, open_flags, 0666);
        }

        if (fdout < 0) 
        {
	    if (log_security)
            {
	        if (anonymous)
                {
		    syslog(LOG_NOTICE, 
                    "anonymous(%s) of %s tried to upload %s (permissions)",
		       guestpw, remoteident, realname);
                }
   	        else
                {
		    syslog(LOG_NOTICE, 
                       "%s of %s tried to upload %s (permissions)",
		       pw->pw_name, remoteident, realname);
                }
            }
  	    perror_reply(553, name);
	    return;
        }
        /* if we have a uid and gid, then use them. */

#ifdef OVERWRITE
        if (!exists)
#endif
        {   
  	    if (valid > 0) 
            {
	        oldid = geteuid();
	        if (uid != 0)
                {
		    (void) seteuid((uid_t) uid);
                }
	        if ((uid == 0) || ((fchown(fdout, uid, gid)) < 0)) 
                {
                    /* we can't allow any signals while euid==0: kinch */
		    delay_signaling();	
		    (void) seteuid((uid_t) 0);
		    if ((fchown(fdout, uid, gid)) < 0) 
                    {
		        (void) seteuid(oldid);
                        /* we can allow signals once again: kinch */
		        enable_signaling();		
		        perror_reply(550, "fchown");
		        return;
		    }
		    (void) seteuid(oldid);
                    /* we can allow signals once again: kinch */
		    enable_signaling();	
	        }
   	        else
                {
		    (void) seteuid(oldid);
	        }
	    }
        }
    }
#   endif /* UPLOAD */

    if (restart_point && (open_flags & O_APPEND) == 0 || offset != -1)
    {
	mode = "r+";
    }

#   ifdef UPLOAD
    {
        fout = fdopen(fdout, mode);
    }
#   else
    {
        fout = fopen(name, mode);
    }
#   endif /* UPLOAD */

    if (fout == NULL) 
    {
	if (log_security)
        {
	    if (anonymous)
            {
		syslog(LOG_NOTICE, 
                   "anonymous(%s) of %s tried to upload %s (permissions)",
		       guestpw, remoteident, realname);
            }
	    else
            {
		syslog(LOG_NOTICE, "%s of %s tried to upload %s (permissions)",
		       pw->pw_name, remoteident, realname);
            }
        }
	perror_reply(553, name);
	return;
    }

    /* added offset JB */
    if(restart_point)
    {
        tmp_restart = restart_point;
        if(offset != -1) tmp_restart += offset;
    }
    else if(offset != -1)
    {
        tmp_restart = offset;
    }
    else
    {
        tmp_restart = 0;
    }

    if (tmp_restart)
    {
	if (type == TYPE_A) 
        {
	    register int i, n, c;

            n = tmp_restart;
	    i = 0;
	    while (i++ < n) 
            {
		if ((c = getc(fout)) == EOF) 
                {
		    perror_reply(550, name);
		    goto done;
		}
		if (c == '\n')
                {
		    i++;
                }
	    }
	    /* We must do this seek to "current" position because we are
	     * changing from reading to writing. */
	    if (fseek(fout, 0L, SEEK_CUR) < 0) 
            {
		perror_reply(550, name);
		goto done;
	    }
	}
	else if (lseek(fileno(fout), tmp_restart, SEEK_SET) < 0) 
        {
	    perror_reply(550, name);
	    goto done;
	}
    }

/*
 * use standard data code or globus data code
 */
#   if defined(USE_GLOBUS_DATA_CODE)
    {
        TransferIncomplete = g_receive_data(
                                 &g_data_handle, fout, 
                                 tmp_restart, name);
    }
#   else
    {
        din = dataconn(name, (off_t) - 1, "r");
        if (din == NULL)
        {
   	    goto done;
        }
        TransferIncomplete = receive_data(din, fout);
        (void) fclose(din);
    }
#   endif

    if (TransferIncomplete == 0) 
    {
	if (unique)
        {
	    reply(226, "Transfer complete (unique file name:%s).", name);
        }
	else
        {
	    reply(226, "Transfer complete.");
        }
    }
    fb_realpath(name, LastFileTransferred);

#   ifdef MAIL_ADMIN
    {
        if (anonymous && incmails > 0) 
        {
  	    FILE *sck = NULL;

	    unsigned char temp = 0, temp2 = 0;
	    char pathname[MAXPATHLEN];
	    while ((temp < mailservers) && (sck == NULL))
	        sck = SockOpen(mailserver[temp++], 25);
	    if (sck == NULL) {
	        syslog(LOG_ERR, "Can't connect to a mailserver.");
	        goto mailfail;
	    }
	    if (Reply(sck) != 220) {
	        syslog(LOG_ERR, "Mailserver failed to initiate contact.");
	        goto mailfail;
	    }
	    if (Send(sck, "HELO localhost\r\n") != 250) {
	        syslog(LOG_ERR, "Mailserver doesn't understand HELO.");
	        goto mailfail;
	    }
	    if (Send(sck, "MAIL FROM: <%s>\r\n", email(mailfrom)) != 250) {
	        syslog(LOG_ERR, "Mailserver didn't accept MAIL FROM.");
	        goto mailfail;
	    }
	    for (temp = 0; temp < incmails; temp++) {
	        if (Send(sck, "RCPT TO: <%s>\r\n", email(incmail[temp])) == 250)
		    temp2++;
	    }
	    if (temp2 == 0) {
	        syslog(LOG_ERR, "Mailserver didn't accept any RCPT TO.");
	        goto mailfail;
	    }
	    if (Send(sck, "DATA\r\n") != 354) {
	        syslog(LOG_ERR, "Mailserver didn't accept DATA.");
	        goto mailfail;
	    }
  	    SockPrintf(sck, "From: wu-ftpd <%s>\r\n", mailfrom);
	    SockPrintf(sck, "Subject: New file uploaded: %s\r\n\r\n", name);
	    fb_realpath(name, pathname);
	    SockPrintf(sck, "%s uploaded %s from %s.\r\nFile size is %d.\r\nPlease move the file where it belongs.\r\n", guestpw, pathname, remotehost, byte_count);
	    if (Send(sck, ".\r\n") != 250)
	        syslog(LOG_ERR, "Message rejected by mailserver.");
	    if (Send(sck, "QUIT\r\n") != 221)
	        syslog(LOG_ERR, "Mailserver didn't accept QUIT.");
	    goto mailok;
          mailfail:
	    if (sck != NULL)
	        fclose(sck);
          mailok:
	    sck = NULL;		/* We don't need this, but some (stupid) compilers need an
				   instruction after a label. This one can't hurt. */
        }
    }
#   endif /* MAIL_ADMIN */

    if (log_incoming_xfers && (xferlog || syslogmsg)) 
    {
        /* AUTHNAMESIZE is 100 */
	char namebuf[MAXPATHLEN]; 
        char msg[MAXPATHLEN + 2 * MAXHOSTNAMELEN + 100 + 128];	
	size_t msglen;		/* for stupid_sprintf */
	int xfertime = time(NULL) - start_time;
	time_t curtime = time(NULL);
	int loop;

	if (!xfertime)
	    xfertime++;
#       ifdef XFERLOG_REALPATH
        {
	    wu_realpath(name, namebuf, chroot_path);
        }
#       else
        {
	    fb_realpath(name, namebuf);
        }
#       endif
	for (loop = 0; namebuf[loop]; loop++)
        {
	    if (isspace(namebuf[loop]) || iscntrl(namebuf[loop]))
            {
		namebuf[loop] = '_';
            }
        }
/* see above */
	sprintf(msg, "%.24s %d %s %" L_FORMAT " ",
		ctime(&curtime),
		xfertime,
		remotehost,
		byte_count
	    );
	msglen = strlen(msg);	/* sigh */
	snprintf(msg + msglen, sizeof(msg) - msglen, "%s %c %s %c %c %s ftp %d %s %c\n",
		 namebuf,
		 (type == TYPE_A) ? 'a' : 'b',
		 opt_string(0),
		 'i',
		 anonymous ? 'a' : (guest ? 'g' : 'r'),
		 anonymous ? guestpw : pw->pw_name,
		 authenticated,
		 authenticated ? authuser : "*",
		 TransferIncomplete ? 'i' : 'c'
	    );
	/* Ensure msg always ends with '\n' */
	if (strlen(msg) == sizeof(msg) - 1)
        {
	    msg[sizeof(msg) - 2] = '\n';
        }
	if (syslogmsg != 1)
        {
	    write(xferlog, msg, strlen(msg));
        }
	if (syslogmsg != 0)
        {
	    syslog(LOG_INFO, "xferlog (recv): %s", msg + 25);
        }
    }
    data = -1;
    pdata = -1;
  done:
    (void) fclose(fout);
}

FILE *getdatasock(char *mode)
{
    int s, on = 1, tries;

    if (data >= 0)
	return (fdopen(data, mode));
    delay_signaling();		/* we can't allow any signals while euid==0: kinch */
    (void) seteuid((uid_t) 0);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
	goto bad;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		   (char *) &on, sizeof(on)) < 0)
	goto bad;
    if (keepalive)
	(void) setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
    if (TCPwindowsize)
	(void) setsockopt(s, SOL_SOCKET, (*mode == 'w' ? SO_SNDBUF : SO_RCVBUF),
			  (char *) &TCPwindowsize, sizeof(TCPwindowsize));
    /* anchor socket to avoid multi-homing problems */
    data_source.sin_family = AF_INET;
    data_source.sin_addr = ctrl_addr.sin_addr;

#if defined(VIRTUAL) && defined(CANT_BIND)	/* can't bind to virtual address */
    data_source.sin_addr.s_addr = htonl(INADDR_ANY);
#endif
    for (tries = 1;; tries++) {
	if (bind(s, (struct sockaddr *) &data_source,
		 sizeof(data_source)) >= 0)
	    break;
	if (errno != EADDRINUSE || tries > 10)
	    goto bad;
	sleep(tries);
    }
#if defined(M_UNIX) && !defined(_M_UNIX)	/* bug in old TCP/IP release */
    {
	struct linger li;
	li.l_onoff = 1;
	li.l_linger = 900;
	if (setsockopt(s, SOL_SOCKET, SO_LINGER,
		       (char *) &li, sizeof(struct linger)) < 0) {
	    syslog(LOG_WARNING, "setsockopt (SO_LINGER): %m");
	    goto bad;
	}
    }
#endif
    (void) seteuid((uid_t) pw->pw_uid);
    enable_signaling();		/* we can allow signals once again: kinch */

#ifdef IPTOS_THROUGHPUT
    on = IPTOS_THROUGHPUT;
    if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *) &on, sizeof(int)) < 0)
	    syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
#ifdef TCP_NOPUSH
    /*
     * Turn off push flag to keep sender TCP from sending short packets
     * at the boundaries of each write().  Should probably do a SO_SNDBUF
     * to set the send buffer size as well, but that may not be desirable
     * in heavy-load situations.
     */
    on = 1;
    if (setsockopt(s, IPPROTO_TCP, TCP_NOPUSH, (char *) &on, sizeof on) < 0)
	syslog(LOG_WARNING, "setsockopt (TCP_NOPUSH): %m");
#endif

    return (fdopen(s, mode));
  bad:
    on = errno;			/* hold errno for return */
    (void) seteuid((uid_t) pw->pw_uid);
    enable_signaling();		/* we can allow signals once again: kinch */
    if (s != -1)
	(void) close(s);
    errno = on;
    return (NULL);
}

FILE *dataconn(char *name, off_t size, char *mode)
{
    char sizebuf[32];
    FILE *file;
    int retry = 0;
    int on = 1;
#ifdef IPTOS_LOWDELAY
    int tos;
#endif
#ifdef THROUGHPUT
    int bps;
    double bpsmult;
#endif

    file_size = size;
    byte_count = 0;
    if (size != (off_t) - 1)
	(void) sprintf(sizebuf, " (%" L_FORMAT " bytes)", size);
    else
	(void) strcpy(sizebuf, "");
    if (pdata >= 0) {
	struct sockaddr_in from;
	char dataaddr[MAXHOSTNAMELEN];
#if defined(UNIXWARE) || defined(AIX)
	size_t fromlen = sizeof(from);
#else
	int fromlen = sizeof(from);
#endif
	int s;
#ifdef FD_ZERO
	int rv;
#endif

	if (keepalive)
	    (void) setsockopt(pdata, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
	if (TCPwindowsize)
	    (void) setsockopt(pdata, SOL_SOCKET, (*mode == 'w' ? SO_SNDBUF : SO_RCVBUF),
			    (char *) &TCPwindowsize, sizeof(TCPwindowsize));
#ifdef FD_ZERO
	do {
	    struct timeval timeout;
	    fd_set set;

	    FD_ZERO(&set);
	    FD_SET(pdata, &set);

	    timeout.tv_usec = 0;
	    timeout.tv_sec = timeout_accept;
#ifdef HPUX_SELECT
	    rv = select(pdata + 1, (int *) &set, NULL, NULL, &timeout);
#else
	    rv = select(pdata + 1, &set, (fd_set *) 0, (fd_set *) 0,
			(struct timeval *) &timeout);
#endif
	} while ((rv == -1) && (errno == EINTR));
	if ((rv != -1) && (rv != 0))
	    s = accept(pdata, (struct sockaddr *) &from, &fromlen);
	else
	    s = -1;
#else /* FD_ZERO */
	(void) signal(SIGALRM, alarm_signal);
	alarm(timeout_accept);
	s = accept(pdata, (struct sockaddr *) &from, &fromlen);
	alarm(0);
#endif
	if (s == -1) {
	    reply(425, "Can't open data connection.");
	    (void) close(pdata);
	    pdata = -1;
	    return (NULL);
	}
	(void) close(pdata);
	pdata = s;
#ifdef IPTOS_LOWDELAY
	tos = IPTOS_LOWDELAY;
	(void) setsockopt(s, IPPROTO_IP, IP_TOS, (char *) &tos,
			  sizeof(int));

#endif
	(void) strncpy(dataaddr, inet_ntoa(from.sin_addr), sizeof(dataaddr));
	if (!pasv_allowed(dataaddr))
	    if (strcasecmp(dataaddr, remoteaddr) != 0) {
		/* 
		 * This will log when data connection comes from an address different
		 * than the control connection.
		 */
#ifdef FIGHT_PASV_PORT_RACE
		syslog(LOG_ERR, "%s of %s: data connect from %s for %s%s",
		       anonymous ? guestpw : pw->pw_name, remoteident,
		       dataaddr, name, sizebuf);
		reply(425, "Possible PASV port theft, cannot open data connection.");
		(void) close(pdata);
		pdata = -1;
		return (NULL);
#else
		syslog(LOG_NOTICE, "%s of %s: data connect from %s for %s%s",
		       anonymous ? guestpw : pw->pw_name, remoteident,
		       dataaddr, name, sizebuf);
#endif
	    }
#ifdef THROUGHPUT
	throughput_calc(name, &bps, &bpsmult);
	if (bps != -1) {
	    lreply(150, "Opening %s mode data connection for %s%s.",
		   type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	    reply(150, "Restricting network throughput to %d bytes/s.", bps);
	}
	else
#endif
	    reply(150, "Opening %s mode data connection for %s%s.",
		  type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	return (fdopen(pdata, mode));
    }
    if (data >= 0) {
	reply(125, "Using existing data connection for %s%s.",
	      name, sizebuf);
	usedefault = 1;
	return (fdopen(data, mode));
    }
    if (usedefault)
	data_dest = his_addr;
    if (data_dest.sin_port == 0) {
	reply(500, "Can't build data connection: no PORT specified");
	return (NULL);
    }
    usedefault = 1;
    file = getdatasock(mode);
    if (file == NULL) {
	reply(425, "Can't create data socket (%s,%d): %s.",
	      inet_ntoa(data_source.sin_addr),
	      ntohs(data_source.sin_port), strerror(errno));
	return (NULL);
    }
    data = fileno(file);
    (void) signal(SIGALRM, alarm_signal);
    alarm(timeout_connect);
    while (connect(data, (struct sockaddr *) &data_dest,
		   sizeof(data_dest)) < 0) {
	alarm(0);
	if ((errno == EADDRINUSE || errno == EINTR) && retry < swaitmax) {
	    sleep((unsigned) swaitint);
	    retry += swaitint;
	    (void) signal(SIGALRM, alarm_signal);
	    alarm(timeout_connect);
	    continue;
	}
	perror_reply(425, "Can't build data connection");
	(void) fclose(file);
	data = -1;
	return (NULL);
    }
    alarm(0);
    if (keepalive)
	(void) setsockopt(pdata, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
    if (TCPwindowsize)
	(void) setsockopt(data, SOL_SOCKET, (*mode == 'w' ? SO_SNDBUF : SO_RCVBUF),
			  (char *) &TCPwindowsize, sizeof(TCPwindowsize));
#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
    if (bps != -1) {
	lreply(150, "Opening %s mode data connection for %s%s.",
	       type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	reply(150, "Restricting network throughput to %d bytes/s.", bps);
    }
    else
#endif
	reply(150, "Opening %s mode data connection for %s%s.",
	      type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
    return (file);
}

/* Tranfer the contents of "instr" to "outstr" peer using the appropriate
 * encapsulation of the data subject to Mode, Structure, and Type.
 *
 * NB: Form isn't handled. */

int
#ifdef THROUGHPUT
    send_data(char *name, FILE *instr, FILE *outstr, off_t blksize, int length)
#else
     send_data(FILE *instr, FILE *outstr, off_t blksize, int length)
#endif
{
    int                             jb_count;
    int                             jb_i;
    register int c, cnt = 0;
    static char *buf;
    int netfd, filefd;
#ifdef THROUGHPUT
    int bps;
    double bpsmult;
    time_t t1, t2;
#endif

#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
#endif

    buf = NULL;
    if (wu_setjmp(urgcatch)) {
	draconian_FILE = NULL;
	alarm(0);
	transflag = 0;
	if (buf)
	    (void) free(buf);
	retrieve_is_data = 1;
	return (0);
    }
    transflag++;
    switch (type) {

    case TYPE_A:
	draconian_FILE = outstr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	
	jb_count = 0;
	while ((draconian_FILE != NULL) && 
               (jb_count < length || length == -1) &&
               ((c = getc(instr)) != EOF)) 
        {
	    if (++byte_count % 4096 == 0) 
            {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
	    }
	    if (c == '\n') 
            {
		if (ferror(outstr))
		    goto data_err;
		(void) putc('\r', outstr);
		jb_count++;
#ifdef TRANSFER_COUNT
		if (retrieve_is_data) 
                {
		    data_count_total++;
		    data_count_out++;
		}
		byte_count_total++;
		byte_count_out++;
#endif
	    }
	    if(jb_count++ == length)
	    {
		break;
	    }
	    (void) putc(c, outstr);
#ifdef TRANSFER_COUNT
	    if (retrieve_is_data) 
            {
		data_count_total++;
		data_count_out++;
	    }
	    byte_count_total++;
	    byte_count_out++;
#endif
	}
	if (draconian_FILE != NULL) 
        {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    fflush(outstr);
	}
	if (draconian_FILE != NULL) 
        {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    socket_flush_wait(outstr);
	}
	transflag = 0;
	if (ferror(instr))
	    goto file_err;
	if ((draconian_FILE == NULL) || ferror(outstr))
	    goto data_err;
	draconian_FILE = NULL;
	alarm(0);
	reply(226, "Transfer complete.");
#ifdef TRANSFER_COUNT
	if (retrieve_is_data) {
	    file_count_total++;
	    file_count_out++;
	}
	xfer_count_total++;
	xfer_count_out++;
#endif
	retrieve_is_data = 1;
	return (1);

    case TYPE_I:
    case TYPE_L:
#ifdef THROUGHPUT
	if (bps != -1)
	    blksize = bps;
#endif
	if ((buf = (char *) malloc(blksize)) == NULL) {
	    transflag = 0;
	    perror_reply(451, "Local resource failure: malloc");
	    retrieve_is_data = 1;
	    return (0);
	}
	netfd = fileno(outstr);
	filefd = fileno(instr);
	draconian_FILE = outstr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
#ifdef THROUGHPUT
	if (bps != -1)
	    t1 = time(NULL);
#endif

        jb_count = 0;
	while ((draconian_FILE != NULL) && 
                (jb_count < length || length == -1))
        {
            if(length == -1 || length - jb_count >= blksize)
            {
                jb_i = blksize;
            }
            else
            {
                jb_i = length - jb_count;
            }

            /* modified by JB */
            if((cnt = read(filefd, buf, jb_i)) <= 0 ||
	       write(netfd, buf, cnt) != cnt)
            {
                break;
            }
            jb_count += cnt;

	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    byte_count += cnt;
#ifdef TRANSFER_COUNT
	    if (retrieve_is_data) {
#ifdef RATIO
		if( freefile ) {
		    total_free_dl += cnt;
		}
#endif /* RATIO */
		data_count_total += cnt;
		data_count_out += cnt;
	    }
	    byte_count_total += cnt;
	    byte_count_out += cnt;

#endif
#ifdef THROUGHPUT
	    if (bps != -1) {
		t2 = time(NULL);
		if (t2 == t1)
		    sleep(1);
		t1 = time(NULL);
	    }
#endif
	}
	if(jb_count == length && length != -1)
	{
	    cnt = 0;
	}
#ifdef THROUGHPUT
	if (bps != -1)
	    throughput_adjust(name);
#endif
	transflag = 0;
	(void) free(buf);
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    socket_flush_wait(outstr);
	}
	if (cnt != 0) {
	    if (cnt < 0)
		goto file_err;
	    goto data_err;
	}
	if (draconian_FILE == NULL)
	    goto data_err;
	draconian_FILE = NULL;
	alarm(0);
	reply(226, "Transfer complete.");
#ifdef TRANSFER_COUNT
	if (retrieve_is_data) {
	    file_count_total++;
	    file_count_out++;
	}
	xfer_count_total++;
	xfer_count_out++;
#endif
	retrieve_is_data = 1;
	return (1);
    default:
	transflag = 0;
	reply(550, "Unimplemented TYPE %d in send_data", type);
	retrieve_is_data = 1;
	return (0);
    }

  data_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
    perror_reply(426, "Data connection");
    retrieve_is_data = 1;
    return (0);

  file_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
    perror_reply(551, "Error on input file");
    retrieve_is_data = 1;
    return (0);
}

/* Transfer data from peer to "outstr" using the appropriate encapulation of
 * the data subject to Mode, Structure, and Type.
 *
 * N.B.: Form isn't handled. */

int receive_data(FILE *instr, FILE *outstr)
{
    register int c;
    int cnt = 0, bare_lfs = 0;
    static char *buf;
    int netfd, filefd;
#ifdef BUFFER_SIZE
    size_t buffer_size = BUFFER_SIZE;
#else
    size_t buffer_size = BUFSIZ;
#endif

    buf = NULL;
    if (wu_setjmp(urgcatch)) {
	alarm(0);
	transflag = 0;
	if (buf)
	    (void) free(buf);
	return (-1);
    }
    transflag++;
    switch (type) {

    case TYPE_I:
    case TYPE_L:
	if ((buf = (char *) malloc(buffer_size)) == NULL) {
	    transflag = 0;
	    perror_reply(451, "Local resource failure: malloc");
	    return (-1);
	}
	netfd = fileno(instr);
	filefd = fileno(outstr);
	draconian_FILE = instr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	while ((draconian_FILE != NULL) && ((cnt = read(netfd, buf, buffer_size)) > 0 && write(filefd, buf, cnt) == cnt)) {
	    byte_count += cnt;
#ifdef TRANSFER_COUNT
	    data_count_total += cnt;
	    data_count_in += cnt;
	    byte_count_total += cnt;
	    byte_count_in += cnt;
#endif
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	}
	transflag = 0;
	(void) free(buf);
	if (cnt != 0) {
	    if (cnt < 0)
		goto data_err;
	    goto file_err;
	}
	if (draconian_FILE == NULL)
	    goto data_err;
	draconian_FILE = NULL;
	alarm(0);
#ifdef TRANSFER_COUNT
	file_count_total++;
	file_count_in++;
	xfer_count_total++;
	xfer_count_in++;
#endif
	return (0);

    case TYPE_E:
	reply(553, "TYPE E not implemented.");
	transflag = 0;
	return (-1);

    case TYPE_A:
	draconian_FILE = instr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	while ((draconian_FILE != NULL) && ((c = getc(instr)) != EOF)) {
	    if (++byte_count % 4096 == 0) {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
	    }
	    if (c == '\n')
		bare_lfs++;
	    while (c == '\r') {
		if (ferror(outstr))
		    goto file_err;
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
		if ((draconian_FILE != NULL) && ((c = getc(instr)) != '\n')) {
		    (void) putc('\r', outstr);
#ifdef TRANSFER_COUNT
		    data_count_total++;
		    data_count_in++;
		    byte_count_total++;
		    byte_count_in++;
#endif
		    if (c == EOF)	/* null byte fix, noid@cyborg.larc.nasa.gov */
			goto contin2;
		    if (++byte_count % 4096 == 0) {
			(void) signal(SIGALRM, draconian_alarm_signal);
			alarm(timeout_data);
		    }
		}
	    }
	    (void) putc(c, outstr);
#ifdef TRANSFER_COUNT
	    data_count_total++;
	    data_count_in++;
	    byte_count_total++;
	    byte_count_in++;
#endif
	  contin2:;
	}
	fflush(outstr);
	if ((draconian_FILE == NULL) || ferror(instr))
	    goto data_err;
	if (ferror(outstr))
	    goto file_err;
	transflag = 0;
	draconian_FILE = NULL;
	alarm(0);
	if (bare_lfs) {
	    lreply(226, "WARNING! %d bare linefeeds received in ASCII mode", bare_lfs);
	    lreply(0, "   File may not have transferred correctly.");
	}
#ifdef TRANSFER_COUNT
	file_count_total++;
	file_count_in++;
	xfer_count_total++;
	xfer_count_in++;
#endif
	return (0);
    default:
	reply(550, "Unimplemented TYPE %d in receive_data", type);
	transflag = 0;
	return (-1);
    }

  data_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
    perror_reply(426, "Data Connection");
    return (-1);

  file_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
    perror_reply(452, "Error writing file");
    return (-1);
}

void statfilecmd(char *filename)
{
#ifndef INTERNAL_LS
    char line[BUFSIZ], *ptr;
    FILE *fin;
    int c;
#endif /* ! INTERNAL_LS */

    fixpath(filename);
    if (filename[0] == '\0')
	filename = ".";
#ifndef INTERNAL_LS
    if (anonymous && dolreplies)
	(void) snprintf(line, sizeof(line), ls_long, filename);
    else
	(void) snprintf(line, sizeof(line), ls_short, filename);
    fin = ftpd_popen(line, "r", 0);
#endif /* ! INTERNAL_LS */
    lreply(213, "status of %s:", filename);
#ifndef INTERNAL_LS
    /*
       while ((c = getc(fin)) != EOF) {
       if (c == '\n') {
       if (ferror(stdout)) {
       perror_reply(421, "control connection");
       (void) ftpd_pclose(fin);
       dologout(1);
       / * NOTREACHED * /
       }
       if (ferror(fin)) {
       perror_reply(551, filename);
       (void) ftpd_pclose(fin);
       return;
       }
       (void) putc('\r', stdout);
       }
       (void) putc(c, stdout);
       }
     */
    while (fgets(line, sizeof(line), fin) != NULL) {
	if ((ptr = strchr(line, '\n')))		/* clip out unnecessary newline */
	    *ptr = '\0';
	lreply(0, "%s", line);
    }
    (void) ftpd_pclose(fin);
#else /* INTERNAL_LS */
    ls_dir(filename, 1, 0, 1, 0, 1, stdout);
#endif /* INTERNAL_LS */
    reply(213, "End of Status");
}

void statcmd(void)
{
    struct sockaddr_in *sin;
    u_char *a, *p;

    lreply(211, "%s FTP server status:", hostname);
    lreply(0, "     %s", version);
    if (!isdigit(remotehost[0]))
	lreply(0, "     Connected to %s (%s)", remotehost,
	       inet_ntoa(his_addr.sin_addr));
    else
	lreply(0, "     Connected to %s", remotehost);

    if (logged_in) {
	if (anonymous)
	    lreply(0, "     Logged in anonymously");
	else
	    lreply(0, "     Logged in as %s", pw->pw_name);
    }
    else if (askpasswd)
	lreply(0, "     Waiting for password");
#ifdef FTP_SECURITY_EXTENSIONS
    else if ( attempting_auth_type ) {
	lreply(0, "     Waiting for authentication data");
    }
#endif /* FTP_SECURITY_EXTENSIONS */
    else
	lreply(0, "     Waiting for user name");

#ifdef FTP_SECURITY_EXTENSIONS
    reply(0, "     PROTection level: %s",
	  protection_levelnames[protection_level]);
#endif /* FTP_SECURITY_EXTENSIONS */

    if (type == TYPE_L)
#ifdef NBBY
	lreply(0, "     TYPE: %s %d; STRUcture: %s; transfer MODE: %s",
	       typenames[type], NBBY, strunames[stru], modenames[mode]);
#else
	lreply(0, "     TYPE: %s %d; STRUcture: %s; transfer MODE: %s",
	       typenames[type], bytesize, strunames[stru], modenames[mode]);
#endif /* NBBY */
    else
	lreply(0, "     TYPE: %s%s%s; STRUcture: %s; transfer MODE: %s",
	       typenames[type], (type == TYPE_A || type == TYPE_E) ?
	       ", FORM: " : "", (type == TYPE_A || type == TYPE_E) ?
	       formnames[form] : "", strunames[stru], modenames[mode]);
    if (data != -1)
	lreply(0, "     Data connection open");
    else if (pdata != -1 || usedefault == 0) {
	if (usedefault == 0)
	    sin = &data_dest;
	else if (route_vectored)
	    sin = &vect_addr;
	else
	    sin = &pasv_addr;
	a = (u_char *) & sin->sin_addr;
	p = (u_char *) & sin->sin_port;
#define UC(b) (((int) b) & 0xff)
	lreply(0, "     %s (%d,%d,%d,%d,%d,%d)",
	       usedefault == 0 ? "PORT" : "in Passive mode",
	       UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
#undef UC
    }
    else
	lreply(0, "     No data connection");
#ifdef TRANSFER_COUNT
    lreply(0, "     %d data bytes received in %d files", data_count_in, file_count_in);
    lreply(0, "     %d data bytes transmitted in %d files", data_count_out, file_count_out);
    lreply(0, "     %d data bytes total in %d files", data_count_total, file_count_total);
    lreply(0, "     %d traffic bytes received in %d transfers", byte_count_in, xfer_count_in);
    lreply(0, "     %d traffic bytes transmitted in %d transfers", byte_count_out, xfer_count_out);
    lreply(0, "     %d traffic bytes total in %d transfers", byte_count_total, xfer_count_total);
#endif
    reply(211, "End of status");
}

void fatal(char *s)
{
    reply(451, "Error in server: %s\n", s);
    reply(221, "Closing connection due to server error.");
    dologout(0);
    /* NOTREACHED */
}

#define USE_REPLY_NOTFMT	(1<<1)	/* fmt is not a printf fmt (KLUDGE) */
#define USE_REPLY_LONG		(1<<2)	/* this is a long reply; use a - */

void vreply(long flags, int n, char *fmt, va_list ap)
{
    char buf[LARGE_BUFSIZE];

    flags &= USE_REPLY_NOTFMT | USE_REPLY_LONG;

    if (n)			/* if numeric is 0, don't output one; use n==0 in place of printf's */
	sprintf(buf, "%03d%c", n, flags & USE_REPLY_LONG ? '-' : ' ');

    /* This is somewhat of a kludge for autospout.  I personally think that
     * autospout should be done differently, but that's not my department. -Kev
     */
    if (flags & USE_REPLY_NOTFMT)
	snprintf(buf + (n ? 4 : 0), n ? sizeof(buf) - 4 : sizeof(buf), "%s", fmt);
    else
	vsnprintf(buf + (n ? 4 : 0), n ? sizeof(buf) - 4 : sizeof(buf), fmt, ap);

    if (debug) {		/* debugging output :) */
#ifdef FTP_SECURITY_EXTENSIONS
	/* Don't print whole ADAT buffers as they are huge */
	if (strncmp(&buf[4], "ADAT", 4) == 0) {
	    syslog(LOG_DEBUG, "<--- ADAT (%d bytes)", strlen(buf));
	} else
#endif /* FTP_SECURITY_EXTENSIONS */
	syslog(LOG_DEBUG, "<--- %s", buf);
    }
    
    /* Yes, you want the debugging output before the client output; wrapping
     * stuff goes here, you see, and you want to log the cleartext and send
     * the wrapped text to the client.
     */

#ifdef FTP_SECURITY_EXTENSIONS
    encode_secure_message(buf, buf, sizeof(buf));
#endif /* FTP_SECURITY_EXTENSIONS */

    printf("%s\r\n", buf);	/* and send it to the client */
#ifdef TRANSFER_COUNT
    byte_count_total += strlen(buf);
    byte_count_out += strlen(buf);
#endif
    fflush(stdout);
}

void reply(int n, char *fmt,...)
{
    VA_LOCAL_DECL

	if (autospout != NULL) {	/* deal with the autospout stuff... */
	char *p, *ptr = autospout;

	while (*ptr) {
	    if ((p = strchr(ptr, '\n')) != NULL)	/* step through line by line */
		*p = '\0';

	    /* send a line...(note that this overrides dolreplies!) */
	    vreply(USE_REPLY_LONG | USE_REPLY_NOTFMT, n, ptr, ap);

	    if (p)
		ptr = p + 1;	/* set to the next line... (\0 is handled in the while) */
	    else
		break;		/* oh, we're done; drop out of the loop */
	}

	if (autospout_free) {	/* free autospout if necessary */
	    (void) free(autospout);
	    autospout_free = 0;
	}
	autospout = 0;		/* clear the autospout */
    }

    VA_START(fmt);

    /* send the reply */
    vreply(0L, n, fmt, ap);

    VA_END;
}

void lreply(int n, char *fmt,...)
{
    VA_LOCAL_DECL

	if (!dolreplies)	/* prohibited from doing long replies? */
	return;

    VA_START(fmt);

    /* send the reply */
    vreply(USE_REPLY_LONG, n, fmt, ap);

    VA_END;
}

void ack(char *s)
{
    reply(250, "%s command successful.", s);
}

void nack(char *s)
{
    reply(502, "%s command not implemented.", s);
}

void yyerror(char *s)
{
    char *cp;
    if (s == NULL || yyerrorcalled != 0)
	return;
    if ((cp = strchr(cbuf, '\n')) != NULL)
	*cp = '\0';
    reply(500, "'%s': command not understood.", cbuf);
    yyerrorcalled = 1;
    return;
}

void delete(char *name)
{
    struct stat st;
    char realname[MAXPATHLEN];

    /*
     * delete permission?
     */

    wu_realpath(name, realname, chroot_path);

    if ((del_check(name)) == 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to delete %s",
		       pw->pw_name, remoteident, realname);
	return;
    }

#ifdef GSSAPI_GLOBUS
#ifdef GLOBUS_AUTHORIZATION
        if (!ftp_check_authorization(name, "delete"))  /* DELE */
        {
            reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                  "%s: Permission denied by proxy credential ('delete')",
                  name);       
            syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                   "%s of %s tried to delete %s",
                   pw->pw_name, remoteident, realname);        
            return;
        } 
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */

    if (lstat(name, &st) < 0) {
	perror_reply(550, name);
	return;
    }
    if ((st.st_mode & S_IFMT) == S_IFDIR) {
	uid_t uid;
	gid_t gid;
	int d_mode;
	int valid;

	/*
	 * check the directory, can we rmdir here?
	 */
	if ((dir_check(name, &uid, &gid, &d_mode, &valid)) <= 0) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete directory %s",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to delete directory %s",
			   pw->pw_name, remoteident, realname);
	    return;
	}


	if (rmdir(name) < 0) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete directory %s (permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to delete directory %s (permissions)",
			   pw->pw_name, remoteident, realname);
	    perror_reply(550, name);
	    return;
	}
	goto done;
    }
    if (unlink(name) < 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete %s (permissions)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to delete %s (permissions)",
		       pw->pw_name, remoteident, realname);
	perror_reply(550, name);
	return;
    }
  done:
    {
	char path[MAXPATHLEN];

	wu_realpath(name, path, chroot_path);

	if (log_security)
	    if ((st.st_mode & S_IFMT) == S_IFDIR)
		if (anonymous) {
		    syslog(LOG_NOTICE, "%s of %s deleted directory %s", guestpw, remoteident, path);
		}
		else {
		    syslog(LOG_NOTICE, "%s of %s deleted directory %s", pw->pw_name,
			   remoteident, path);
		}
	    else if (anonymous) {
		syslog(LOG_NOTICE, "%s of %s deleted %s", guestpw,
		       remoteident, path);
	    }
	    else {
		syslog(LOG_NOTICE, "%s of %s deleted %s", pw->pw_name,
		       remoteident, path);
	    }
    }

    ack("DELE");
}

void cwd(char *path)
{
    struct aclmember *entry = NULL;
    char cdpath[MAXPATHLEN + 1];
#ifdef GLOBUS_AUTHORIZATION
    char **actions;
    int ok = 0;
    char realname[MAXPATHLEN];
#endif /* GLOBUS_AUTHORIZATION */

#ifdef GLOBUS_AUTHORIZATION
    wu_realpath(path, realname, chroot_path);

    for (actions = ftp_i_list_possible_actions(); *actions && ! ok; actions++)
    {
       if (ftp_check_authorization(realname, *actions))
	   ok = 1;
    }

    if (! ok)
    {
	reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
	      "\"%s\": Permission denied by proxy credential (no permission on directory)",
	      realname);
	syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
	       "%s of %s tried to cd to directory %s",
	       pw->pw_name, remoteident, realname);
	return;
    }
#endif /* GLOBUS_AUTHORIZATION */
    
    if (chdir(path) < 0) {
	/* alias checking */
	while (getaclentry("alias", &entry) && ARG0 && ARG1 != NULL) {
	    if (!strcasecmp(ARG0, path)) {
		if (chdir(ARG1) < 0)
		    perror_reply(550, path);
		else {
		    show_message(250, C_WD);
		    show_readme(250, C_WD);
		    ack("CWD");
		}
		return;
	    }
	}
	/* check for "cdpath" directories. */
	entry = (struct aclmember *) NULL;
	while (getaclentry("cdpath", &entry) && ARG0 != NULL) {
	    snprintf(cdpath, sizeof cdpath, "%s/%s", ARG0, path);
	    if (chdir(cdpath) >= 0) {
		show_message(250, C_WD);
		show_readme(250, C_WD);
		ack("CWD");
		return;
	    }
	}
	perror_reply(550, path);
    }
    else {
	show_message(250, C_WD);
	show_readme(250, C_WD);
	ack("CWD");
    }
}

void makedir(char *name)
{
    uid_t uid;
    gid_t gid;
    int d_mode;
    mode_t oldumask;
    int valid;
    uid_t oldid;
    char path[MAXPATHLEN + 1];	/* for realpath() later  - cky */
    char realname[MAXPATHLEN];

    wu_realpath(name, realname, chroot_path);
    /*
     * check the directory, can we mkdir here?
     */
    if ((dir_check(name, &uid, &gid, &d_mode, &valid)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to create directory %s",
		       pw->pw_name, remoteident, realname);
	return;
    }

    /*
     * check the filename, is it legal?
     */
    if ((fn_check(name)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s (path-filter)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to create directory %s (path-filter)",
		       pw->pw_name, remoteident, realname);
	return;
    }

    oldumask = umask(0000);
    if (valid <= 0) {
	d_mode = 0777;
	umask(oldumask);
    }

#ifdef GSSAPI_GLOBUS
#ifdef GLOBUS_AUTHORIZATION
       if (!ftp_check_authorization(name, "create"))  /* MKD */
       {
             reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                   "\"%s\": Permission denied by proxy credential ('create')",
                   path);
             syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                    "%s of %s tried to create directory %s",
                    pw->pw_name, remoteident, realname);
             return;
       }
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */ 

    if (mkdir(name, d_mode) < 0) {
	if (errno == EEXIST) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s (exists)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to create directory %s (exists)",
			   pw->pw_name, remoteident, realname);
	    fb_realpath(name, path);
	    reply(521, "\"%s\" directory exists", path);
	}
	else {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s (permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to create directory %s (permissions)",
			   pw->pw_name, remoteident, realname);
	    perror_reply(550, name);
	}
	umask(oldumask);
	return;
    }
    umask(oldumask);
    if (valid > 0) {
	oldid = geteuid();
	if (uid != 0)
	    (void) seteuid((uid_t) uid);
	if ((uid == 0) || ((chown(name, uid, gid)) < 0)) {
	    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	    (void) seteuid((uid_t) 0);
	    if ((chown(name, uid, gid)) < 0) {
		(void) seteuid(oldid);
		enable_signaling();	/* we can allow signals once again: kinch */
		perror_reply(550, "chown");
		return;
	    }
	    (void) seteuid(oldid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	}
	else
	    (void) seteuid(oldid);
    }
    wu_realpath(name, path, chroot_path);
    if (log_security)
	if (anonymous) {
	    syslog(LOG_NOTICE, "%s of %s created directory %s", guestpw, remoteident, path);
	}
	else {
	    syslog(LOG_NOTICE, "%s of %s created directory %s", pw->pw_name,
		   remoteident, path);
	}
    fb_realpath(name, path);
    /* According to RFC 959:
     *   The 257 reply to the MKD command must always contain the
     *   absolute pathname of the created directory.
     * This is implemented here using similar code to the PWD command.
     * XXX - still need to do `quote-doubling'.
     */
    reply(257, "\"%s\" new directory created.", path);
}

void removedir(char *name)
{
    uid_t uid;
    gid_t gid;
    int d_mode;
    int valid;
    char realname[MAXPATHLEN];

    wu_realpath(name, realname, chroot_path);

    /*
     * delete permission?
     */

    if ((del_check(name)) == 0)
	return;
    /*
     * check the directory, can we rmdir here?
     */
    if ((dir_check(name, &uid, &gid, &d_mode, &valid)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to remove directory %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to remove directory %s",
		       pw->pw_name, remoteident, realname);
	return;
    }

#ifdef GSSAPI_GLOBUS
#ifdef GLOBUS_AUTHORIZATION
     
    if (!ftp_check_authorization(name, "delete"))  /* rmdir */
    {
        reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
              "%s: Permission denied by proxy credential ('delete')",name);
        syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
               "%s of %s tried to delete directory %s",
               pw->pw_name, remoteident, realname);
        return;
    }
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */

    if (rmdir(name) < 0) {
	if (errno == EBUSY)
	    perror_reply(450, name);
	else {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to remove directory %s (permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to remove directory %s (permissions)",
			   pw->pw_name, remoteident, realname);
	    perror_reply(550, name);
	}
    }
    else {
	char path[MAXPATHLEN];

	wu_realpath(name, path, chroot_path);

	if (log_security)
	    if (anonymous) {
		syslog(LOG_NOTICE, "%s of %s deleted directory %s", guestpw, remoteident, path);
	    }
	    else {
		syslog(LOG_NOTICE, "%s of %s deleted directory %s", pw->pw_name,
		       remoteident, path);
	    }
	ack("RMD");
    }
}

void pwd(void)
{
    char path[MAXPATHLEN + 1];
    char rhome[MAXPATHLEN + 1];
    char *rpath = path;		/* Path to return to client */
    int pathlen;
#ifndef MAPPING_CHDIR
#ifdef HAVE_GETCWD
    extern char *getcwd();
#else
    extern char *getwd(char *);
#endif
#endif /* MAPPING_CHDIR */

#ifdef HAVE_GETCWD
    if (getcwd(path, MAXPATHLEN) == (char *) NULL)
#else
    if (getwd(path) == (char *) NULL)
#endif
/* Dink!  If you couldn't get the path and the buffer is now likely to
   be undefined, why are you trying to PRINT it?!  _H*
   reply(550, "%s.", path); */
    {
	fb_realpath(".", path);	/* realpath_on_steroids can deal */
    }
    /* relative to home directory if restricted_user */
    if (restricted_user) {
	fb_realpath(home, rhome);
	pathlen = strlen(rhome);
	if (pathlen && rhome[pathlen - 1] == '/')
	    pathlen--;
	rpath = rpath + pathlen;
	if (!*rpath)
	    strcpy(rpath, "/");
    }
    reply(257, "\"%s\" is current directory.", rpath);
}

char *renamefrom(char *name)
{
    struct stat st;

    if (lstat(name, &st) < 0) {
	perror_reply(550, name);
	return ((char *) 0);
    }
    reply(350, "File exists, ready for destination name");
    return (name);
}

void renamecmd(char *from, char *to)
{
    int allowed = (anonymous ? 0 : 1);
    char realfrom[MAXPATHLEN];
    char realto[MAXPATHLEN];
    struct aclmember *entry = NULL;
#ifdef GSSAPI_GLOBUS
#ifdef GLOBUS_AUTHORIZATION
     int exists = 0;
     struct stat chk;
#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */
 
#ifdef PARANOID
    struct stat st;
#endif
    wu_realpath(from, realfrom, chroot_path);
    wu_realpath(to, realto, chroot_path);
    /*
     * check the filename, is it legal?
     */
    if ((fn_check(to)) == 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to \"%s\" (path-filter)",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to \"%s\" (path-filter)",
		       pw->pw_name, remoteident, realfrom, realto);
	return;
    }

    /* 
     * if rename permission denied and file exists... then deny the user
     * permission to rename the file. 
     */
    while (getaclentry("rename", &entry) && ARG0 && ARG1 != NULL) {
	if (type_match(ARG1))
	    if (anonymous) {
		if (*ARG0 == 'y')
		    allowed = 1;
	    }
	    else if (*ARG0 == 'n')
		allowed = 0;
    }
    if (!allowed) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to %s",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to %s",
		       pw->pw_name, remoteident, realfrom, realto);
	reply(553, "%s: Permission denied on server. (rename)", from);
	return;
    }

#ifdef PARANOID
/* Almost forgot about this.  Don't allow renaming TO existing files --
   otherwise someone can rename "trivial" to "warez", and "warez" is gone!
   XXX: This part really should do the same "overwrite" check as store(). */
    if (!stat(to, &st)) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to %s",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to %s",
		       pw->pw_name, remoteident, realfrom, realto);
	reply(550, "%s: Permission denied on server. (rename)", to);
	return;
    }
#endif
#ifdef GSSAPI_GLOBUS
#ifdef GLOBUS_AUTHORIZATION
    /*
     * Check permissions for file we are renaming to.
     */
    exists = stat(to, &chk);

    if (exists)
    {
        /* Creating new file */
        if (!ftp_check_authorization(to, "create"))
        {
            reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                  "Permission denied by proxy credential: \"%s\"  rename denied ('create')",
                  to);
            syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                   "%s of %s tried to rename %s to %s",
                   pw->pw_name, remoteident, realfrom, realto);
            return;
        }
    }
    else
    {
        /* Overwriting existing file */
        if  (!ftp_check_authorization(to, "write"))
        {
            reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
                  "Permission denied by proxy credential: \"%s\"  rename denied ('write')",
                  to);
            syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
                   "%s of %s tried to rename %s to %s",
                   pw->pw_name, remoteident, realfrom, realto);
            return;
        }
    }
    
    /*
     * Check permissions for file we are renaming from.
     * Need both read and delete permissions.
     */
    if  (!ftp_check_authorization(from, "read") || !ftp_check_authorization(from, "delete"))
    if  (!ftp_check_authorization(from, "read"))
    {
        reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
              "Permission denied by proxy credential: \"%s\"  rename denied ('read')",
              from);
        syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
               "%s of %s tried to rename %s to %s",
               pw->pw_name, remoteident, realfrom, realto);
        return;
    }

    if  (!ftp_check_authorization(from, "delete"))
    {
        reply(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_REPLY_CODE,
              "Permission denied by proxy credential: \"%s\"  rename denied ('delete')",
              from);
        syslog(GLOBUS_AUTHORIZATION_PERMISSION_DENIED_SYSLOG_LEVEL,
               "%s of %s tried to rename %s to %s",
               pw->pw_name, remoteident, realfrom, realto);
        return;
    }

#endif /* GLOBUS_AUTHORIZATION */
#endif /* GSSAPI_GLOBUS */ 

    if (rename(from, to) < 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to %s",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to %s",
		       pw->pw_name, remoteident, realfrom, realto);
	perror_reply(550, "rename");
    }
    else {
	char frompath[MAXPATHLEN];
	char topath[MAXPATHLEN];

	wu_realpath(from, frompath, chroot_path);
	wu_realpath(to, topath, chroot_path);

	if (log_security)
	    if (anonymous) {
		syslog(LOG_NOTICE, "%s of %s renamed %s to %s", guestpw, remoteident, frompath, topath);
	    }
	    else {
		syslog(LOG_NOTICE, "%s of %s renamed %s to %s", pw->pw_name,
		       remoteident, frompath, topath);
	    }
	ack("RNTO");
    }
}

void dolog(struct sockaddr_in *sin)
{
#ifndef NO_DNS
    struct hostent *hp;
    char *blah;

#ifdef	DNS_TRYAGAIN
    int num_dns_tries = 0;
    /*
     * 27-Apr-93    EHK/BM
     * far away connections might take some time to get their IP address
     * resolved. That's why we try again -- maybe our DNS cache has the
     * PTR-RR now. This code is sloppy. Far better is to check what the
     * resolver returned so that in case of error, there's no need to
     * try again.
     */
  dns_again:
    hp = gethostbyaddr((char *) &sin->sin_addr,
		       sizeof(struct in_addr), AF_INET);

    if (!hp && ++num_dns_tries <= 1) {
	sleep(3);
	goto dns_again;		/* try DNS lookup once more     */
    }
#else
    hp = gethostbyaddr((char *) &sin->sin_addr, sizeof(struct in_addr), AF_INET);
#endif

    blah = inet_ntoa(sin->sin_addr);

    (void) strncpy(remoteaddr, blah, sizeof(remoteaddr));

    if (!strcasecmp(remoteaddr, "0.0.0.0")) {
	nameserved = 1;
	strncpy(remotehost, "localhost", sizeof(remotehost));
    }
    else {
	if (hp) {
	    nameserved = 1;
	    (void) strncpy(remotehost, hp->h_name, sizeof(remotehost));
	}
	else {
	    nameserved = 0;
	    (void) strncpy(remotehost, remoteaddr, sizeof(remotehost));
	}
    }
#else
    char *blah;

    blah = inet_ntoa(sin->sin_addr);
    (void) strncpy(remoteaddr, blah, sizeof(remoteaddr));
    nameserved = 0;
    (void) strncpy(remotehost, remoteaddr, sizeof(remotehost));
#endif

    remotehost[sizeof(remotehost) - 1] = '\0';
    sprintf(proctitle, "%s: connected", remotehost);
    setproctitle("%s", proctitle);

    wu_authenticate();
/* Create a composite source identification string, to improve the logging
 * when RFC 931 is being used. */
    {
	int n = 20 + strlen(remotehost) + strlen(remoteaddr) +
	(authenticated ? strlen(authuser + 5) : 0);
	if ((remoteident = malloc(n)) == NULL) {
	    syslog(LOG_ERR, "malloc: %m");
#ifndef DEBUG
	    exit(1);
#endif
	}
	else if (authenticated)
	    sprintf(remoteident, "%s @ %s [%s]",
		    authuser, remotehost, remoteaddr);
	else
	    sprintf(remoteident, "%s [%s]", remotehost, remoteaddr);
    }
#ifdef DAEMON
    if (be_daemon && logging)
	syslog(LOG_INFO, "connection from %s", remoteident);
#else
#if 0				/* this is redundant unless the caller doesn't do *anything*, and
				   tcpd will pick it up and deal with it better anyways. _H */
    if (logging)
	syslog(LOG_INFO, "connection from %s", remoteident);
#endif
#endif
}

/* Record logout in wtmp file and exit with supplied status. */

void dologout(int status)
{
    /*
     * Prevent reception of SIGURG from resulting in a resumption
     * back to the main program loop.
     */
    transflag = 0;

    /*
     * Cancel any pending alarm request, reception of SIGALRM would cause
     * dologout() to be called again from the SIGALRM handler toolong().
     */
    (void) alarm(0);

    if (logged_in) {
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	(void) seteuid((uid_t) 0);
	if (wtmp_logging)
	    wu_logwtmp(ttyline, pw->pw_name, remotehost, 0);
    }
    if (logging)
	syslog(LOG_INFO, "FTP session closed");
    if (xferlog)
	close(xferlog);
    acl_remove();
    if(data >= 0)
	close(data);		/* H* fix: clean up a little better */
    if(pdata >= 0)
	close(pdata);
#ifdef AFS
    afs_logout();
#endif
#ifdef GSSAPI
	gssapi_remove_delegation();
#endif /* GSSAPI */
    /* beware of flushing buffers after a SIGPIPE */

#ifdef USE_GLOBUS_DATA_CODE
    g_end();
#endif

    if(status >= 0)
    {
        exit(status);
    }
    else
    {
	_exit(status);
    }
}

SIGNAL_TYPE myoob(int sig)
{
    char *cp;

    /* only process if transfer occurring */
    if (!transflag) {
#ifdef SIGURG
	(void) signal(SIGURG, myoob);
#endif
	return;
    }
    cp = tmpline;
    if (wu_getline(cp, sizeof(tmpline) - 1, stdin) == NULL) {
	reply(221, "You could at least say goodbye.");
	dologout(0);
    }
    upper(cp);
    if (strcasecmp(cp, "ABOR\r\n") == 0) 
    {
	tmpline[0] = '\0';
	reply(426, "Transfer aborted. Data connection closed.");
	reply(226, "Abort successful");
#ifdef SIGURG
	(void) signal(SIGURG, myoob);
#endif
	if (ftwflag > 0) {
	    ftwflag++;
	    return;
	}
#       if  defined(USE_GLOBUS_DATA_CODE)
        {
            g_abort();
            return;
        }
#       else
        { 
	    wu_longjmp(urgcatch, 1);
        }
#       endif
    }
    if (strcasecmp(cp, "STAT\r\n") == 0) {
	tmpline[0] = '\0';
	if (file_size != (off_t) - 1)
	    reply(213, "Status: %" L_FORMAT " of %" L_FORMAT " bytes transferred",
		  byte_count, file_size);
	else
	    reply(213, "Status: %" L_FORMAT " bytes transferred", byte_count);
    }
#ifdef SIGURG
    (void) signal(SIGURG, myoob);
#endif
}

/* Note: a response of 425 is not mentioned as a possible response to the
 * PASV command in RFC959. However, it has been blessed as a legitimate
 * response by Jon Postel in a telephone conversation with Rick Adams on 25
 * Jan 89. */

void passive(void)
{
#if defined(UNIXWARE) || defined(AIX)
    size_t len;
#else
    int len;
#endif
    int bind_error;
    int on = 1;
    register char *p, *a;

    /* 
     * H* fix: if we already *have* a passive socket, close it first.  Prevents
     *         a whole variety of entertaining clogging attacks. 
     */
    if (pdata > 0) 
    {
	close(pdata);
	pdata = -1;
    }
    if (!logged_in) 
    {
	reply(530, "Login with USER first.");
	return;
    }
    pdata = socket(AF_INET, SOCK_STREAM, 0);
    if (pdata < 0) 
    {
	perror_reply(425, "Can't open passive connection");
	return;
    }
    if (keepalive)
    {
	(void) setsockopt(pdata, SOL_SOCKET, SO_KEEPALIVE, 
                   (char *) &on, sizeof(on));
    }
    if (TCPwindowsize) 
    {
	(void) setsockopt(pdata, SOL_SOCKET, SO_SNDBUF, 
                   (char *) &TCPwindowsize, sizeof(TCPwindowsize));
	(void) setsockopt(pdata, SOL_SOCKET, SO_RCVBUF, 
                   (char *) &TCPwindowsize, sizeof(TCPwindowsize));
    }
    pasv_addr = ctrl_addr;
    pasv_addr.sin_port = 0;
    delay_signaling();		/* we can't allow any signals while euid==0: kinch */
    (void) seteuid((uid_t) 0);	/* XXX: not needed if > 1024 */

    checkports();

    if (passive_port_min == -1) 
    {
	passive_port_max = 65534;
	passive_port_min = 1024;
    }

    {
	int *port_array;
	int *pasv_port_array;
	int i;
	int j;
	int k;

	if (passive_port_max < passive_port_min) 
        {
	    (void) seteuid((uid_t) pw->pw_uid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	    goto pasv_error;
	}

	i = passive_port_max - passive_port_min + 1;

	port_array = calloc(i, sizeof(int));
	if (port_array == NULL) 
        {
	    (void) seteuid((uid_t) pw->pw_uid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	    goto pasv_error;
	}

	pasv_port_array = calloc(i, sizeof(int));
	if (pasv_port_array == NULL) 
        {
	    free(port_array);
	    (void) seteuid((uid_t) pw->pw_uid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	    goto pasv_error;
	}

	do 
        {
	    --i;
	    port_array[i] = passive_port_min + i;
	} while (i > 0);

	srand(time(NULL));

/*
   i = passive_port_max - passive_port_min + 1;
   do {
   --i;
   j = (int) (((1.0 + i) * rand()) / (RAND_MAX + 1.0));
   pasv_port_array [i] = port_array [j];
   while (++j <= i)
   port_array [j-1] = port_array [j];
   } while (i > 0);
 */

	bind_error = -1;
	errno = EADDRINUSE;
	for (i = 3; (bind_error < 0) && (errno == EADDRINUSE) && (i > 0); i--) 
        {
	    for (j = passive_port_max - passive_port_min + 1; 
                 (bind_error < 0) && (errno == EADDRINUSE) && (j > 0); 
                 j--) 
            {
		if (i == 3) 
                {
		    k = (int) ((1.0 * j * rand()) / (RAND_MAX + 1.0));
		    pasv_port_array[j - 1] = port_array[k];
		    while (++k < j)
                    {
			port_array[k - 1] = port_array[k];
                    }
		}
		pasv_addr.sin_port = htons(pasv_port_array[j - 1]);
		bind_error = bind(pdata, (struct sockaddr *) 
                                    &pasv_addr, sizeof(pasv_addr));
	    }
	}

	free(pasv_port_array);
	free(port_array);

	if (bind_error < 0) 
        {
	    (void) seteuid((uid_t) pw->pw_uid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	    goto pasv_error;
	}
    }

    (void) seteuid((uid_t) pw->pw_uid);
    enable_signaling();		/* we can allow signals once again: kinch */
    len = sizeof(pasv_addr);
    
    if (getsockname(pdata, (struct sockaddr *) &pasv_addr, &len) < 0)
    {
	goto pasv_error;
    }
    if (listen(pdata, 1) < 0)
    {
	goto pasv_error;
    }

    usedefault = 1;
    if (route_vectored)
    {
	a = (char *) &vect_addr.sin_addr;
    }
    else
    {
	a = (char *) &pasv_addr.sin_addr;
    }
    p = (char *) &pasv_addr.sin_port;

#define UC(b) (((int) b) & 0xff)

    if (debug) 
    {
	char *s = calloc(128 + strlen(remoteident), sizeof(char));
	if (s) 
        {
	    int i = ntohs(pasv_addr.sin_port);
	    sprintf(s, "PASV port %i assigned to %s", i, remoteident);
	    syslog(LOG_DEBUG, s);
	    free(s);
	}
    }
    reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", UC(a[0]),
	  UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
    return;

  pasv_error:
    (void) close(pdata);
    pdata = -1;
    if (debug) 
    {
	char *s = calloc(128 + strlen(remoteident), sizeof(char));
	if (s) 
        {
	    sprintf(s, "PASV port assignment assigned for %s", remoteident);
	    syslog(LOG_DEBUG, s);
	    free(s);
	}
    }
    perror_reply(425, "Can't open passive connection");
    return;
}

/*
 * Generate unique name for file with basename "local". The file named
 * "local" is already known to exist. Generates failure reply on error. 
 */
char *gunique(char *local)
{
    static char new[MAXPATHLEN];
    struct stat st;
    char *cp = strrchr(local, '/');
    int count = 0;

    if (cp)
	*cp = '\0';
    if (stat(cp ? local : ".", &st) < 0) {
	perror_reply(553, cp ? local : ".");
	return ((char *) 0);
    }
    if (cp)
	*cp = '/';
    (void) strncpy(new, local, (sizeof new) - 3);
    new[sizeof(new) - 3] = '\0';
    cp = new + strlen(new);
    *cp++ = '.';
    for (count = 1; count < 100; count++) {
	if (count == 10) {
	    cp -= 2;
	    *cp++ = '.';
	}
	(void) sprintf(cp, "%d", count);
	if (stat(new, &st) < 0)
	    return (new);
    }
    reply(452, "Unique file name cannot be created.");
    return ((char *) 0);
}

/* Format and send reply containing system error number. */

void perror_reply(int code, char *string)
{
    /*
     * If restricted user and string starts with home dir path, strip it off
     * and return only the relative path.
     */
    if (restricted_user && (home != NULL) && (home[0] != '\0')) {
	size_t len = strlen (home);
	if (strncmp (home, string, len) == 0) {
	    if (string[len - 1] == '/')
		string += len - 1;
	    else if (string[len] == '/')
		string += len;
	    else if (string[len] == '\0')
		string = "/";
	}
    }
    reply(code, "%s: %s.", string, strerror(errno));
}

static char *onefile[] =
{"", 0};

extern char **ftpglob(register char *v);
extern char *globerr;

void 
send_file_list(
    char *                                       whichfiles)
{
    /* static so not clobbered by longjmp(), volatile would also work */
    static FILE *dout;
    static DIR *dirp;
    static char **sdirlist;
    static char *wildcard = NULL;

    struct stat st;

    register char **dirlist, *dirname;
    int simple = 0;
    int statret;
    /* This is ANSI/ISO C .. strpbrk should be in <string.h> which we've 
       ** already included so we don't need the following line.  'sides, it 
       ** breaks the GNU EGCS C compiler
       ** extern char *strpbrk(const char *, const char *);
     */

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    if (((file_limit_raw_out > 0) && (xfer_count_out >= file_limit_raw_out))
	|| ((file_limit_raw_total > 0) && (xfer_count_total >= file_limit_raw_total))
     || ((data_limit_raw_out > 0) && (byte_count_out >= data_limit_raw_out))
	|| ((data_limit_raw_total > 0) && (byte_count_total >= data_limit_raw_total))) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to list files (Transfer limits exceeded)",
		       guestpw, remoteident);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to list files (Transfer limits exceeded)",
		       pw->pw_name, remoteident);
	reply(553, "Permission denied on server. (Transfer limits exceeded)");
	return;
    }
#endif
#endif

    draconian_FILE = NULL;
    dout = NULL;
    dirp = NULL;
    sdirlist = NULL;
    wildcard = NULL;
    if (strpbrk(whichfiles, "~{[*?") == NULL) 
    {
	if (whichfiles[0] == '\0') 
        {
	    wildcard = strdup("*");
	    if (wildcard == NULL) 
            {
		reply(550, "Memory allocation error");
		goto globfree;
	    }
	    whichfiles = wildcard;
	}
	else 
        {
	    if (statret=stat(whichfiles, &st) < 0)
	       statret=lstat(whichfiles, &st); /* Check if it's a dangling symlink */
	    if (statret >= 0) 
            {
	       if ((st.st_mode & S_IFMT) == S_IFDIR) 
               {
		   wildcard = malloc(strlen(whichfiles) + 3);
		   if (wildcard == NULL) {
		       reply(550, "Memory allocation error");
		       goto globfree;
		   }
		   strcpy(wildcard, whichfiles);
		   strcat(wildcard, "/*");
		   whichfiles = wildcard;
	       }
	    }
	}
    }
    if (strpbrk(whichfiles, "~{[*?") != NULL) 
    {
	globerr = NULL;
	dirlist = ftpglob(whichfiles);
	sdirlist = dirlist;	/* save to free later */
	if (globerr != NULL) 
        {
	    reply(550, globerr);
	    goto globfree;
	}
	else if (dirlist == NULL) {
	    errno = ENOENT;
	    perror_reply(550, whichfiles);
	    goto globfree;
	}
    }
    else {
	onefile[0] = whichfiles;
	dirlist = onefile;
	simple = 1;
    }

    if (wu_setjmp(urgcatch)) {
	transflag = 0;
	if (dout != NULL)
	    (void) fclose(dout);
	if (dirp != NULL)
	    (void) closedir(dirp);
	data = -1;
	pdata = -1;
	goto globfree;
    }

    while ((dirname = *dirlist++) != NULL) 
    {
	statret=stat(dirname, &st);
	if (statret < 0)
	   statret=lstat(dirname, &st); /* Could be a dangling symlink */

	if (statret < 0) 
        {
	    /* If user typed "ls -l", etc, and the client used NLST, do what
	     * the user meant. */
	    if (dirname[0] == '-' && *dirlist == NULL && transflag == 0) {
		retrieve_is_data = 0;
#ifndef INTERNAL_LS
		retrieve(ls_plain, dirname, -1, -1);
#else
		ls(dirname, 1);
#endif
		retrieve_is_data = 1;
		goto globfree;
	    }
	    perror_reply(550, dirname);
	    if (dout != NULL) {
		(void) fclose(dout);
		transflag = 0;
		data = -1;
		pdata = -1;
	    }
	    goto globfree;
	}

	if ((st.st_mode & S_IFMT) != S_IFDIR) 
        {
	    if (dout == NULL) 
            {
		dout = dataconn("file list", (off_t) - 1, "w");
		if (dout == NULL)
		    goto globfree;
		transflag++;
		draconian_FILE = dout;
	    }
	    if (draconian_FILE != NULL) 
            {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
		fprintf(dout, "%s%s\n", dirname,
			type == TYPE_A ? "\r" : "");
	    }
	    byte_count += strlen(dirname) + 1;
#ifdef TRANSFER_COUNT
	    byte_count_total += strlen(dirname) + 1;
	    byte_count_out += strlen(dirname) + 1;
	    if (type == TYPE_A) 
            {
		byte_count_total++;
		byte_count_out++;
	    }
#endif
	}
    }

    if (dout != NULL) {
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    fflush(dout);
	}
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    socket_flush_wait(dout);
	}
    }
    if (dout == NULL)
	reply(550, "No files found.");
    else if ((draconian_FILE == NULL) || ferror(dout) != 0) {
	alarm(0);
	perror_reply(550, "Data connection");
    }
    else {
#ifdef TRANSFER_COUNT
	xfer_count_total++;
	xfer_count_out++;
#endif
	alarm(0);
	reply(226, "Transfer complete.");
    }

    transflag = 0;
    if ((dout != NULL) && (draconian_FILE != NULL))
	(void) fclose(dout);
    data = -1;
    pdata = -1;
  globfree:
    if (wildcard != NULL) {
	free(wildcard);
	wildcard = NULL;
    }
    if (sdirlist) {
	blkfree(sdirlist);
	free((char *) sdirlist);
    }
}

/*
   **  SETPROCTITLE -- set process title for ps
   **
   **   Parameters:
   **           fmt -- a printf style format string.
   **           a, b, c -- possible parameters to fmt.
   **
   **   Returns:
   **           none.
   **
   **   Side Effects:
   **           Clobbers argv of our main procedure so ps(1) will
   **           display the title.
 */

#define SPT_NONE	0	/* don't use it at all */
#define SPT_REUSEARGV	1	/* cover argv with title information */
#define SPT_BUILTIN	2	/* use libc builtin */
#define SPT_PSTAT	3	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_PSSTRINGS	4	/* use PS_STRINGS->... */
#define SPT_SYSMIPS	5	/* use sysmips() supported by NEWS-OS 6 */
#define SPT_SCO		6	/* write kernel u. area */
#define SPT_CHANGEARGV	7	/* write our own strings into argv[] */
#define MAXLINE      2048	/* max line length for setproctitle */
#define SPACELEFT(buf, ptr)  (sizeof buf - ((ptr) - buf))

#ifdef HAVE_PSTAT
#undef	SPT_TYPE
#define	SPT_TYPE	SPT_PSTAT
#endif

#ifndef SPT_TYPE
#define SPT_TYPE	SPT_REUSEARGV
#endif

#if SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN

#if SPT_TYPE == SPT_PSTAT
#include <sys/pstat.h>
#endif
#if SPT_TYPE == SPT_PSSTRINGS
#include <machine/vmparam.h>
#include <sys/exec.h>
#ifndef PS_STRINGS		/* hmmmm....  apparently not available after all */
#undef SPT_TYPE
#define SPT_TYPE	SPT_REUSEARGV
#else
#ifndef NKPDE			/* FreeBSD 2.0 */
#define NKPDE 63
typedef unsigned int *pt_entry_t;
#endif
#endif
#endif

#if SPT_TYPE == SPT_PSSTRINGS || SPT_TYPE == SPT_CHANGEARGV
#define SETPROC_STATIC	static
#else
#define SETPROC_STATIC
#endif

#if SPT_TYPE == SPT_SYSMIPS
#include <sys/sysmips.h>
#include <sys/sysnews.h>
#endif

#if SPT_TYPE == SPT_SCO
#ifdef UNIXWARE
#include <sys/exec.h>
#include <sys/ksym.h>
#include <sys/proc.h>
#include <sys/user.h>
#else /* UNIXWARE */
#include <sys/immu.h>
#include <sys/dir.h>
#include <sys/user.h>
#include <sys/fs/s5param.h>
#endif /* UNIXWARE */
#if PSARGSZ > MAXLINE
#define SPT_BUFSIZE	PSARGSZ
#endif
#ifndef _PATH_KMEM
#define _PATH_KMEM	"/dev/kmem"
#endif /* _PATH_KMEM */
#endif /* SPT_SCO */

#ifndef SPT_PADCHAR
#define SPT_PADCHAR	' '
#endif

#ifndef SPT_BUFSIZE
#define SPT_BUFSIZE	MAXLINE
#endif

#endif /* SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN */

#if SPT_TYPE == SPT_REUSEARGV || SPT_TYPE == SPT_CHANGEARGV
char **Argv = NULL;		/* pointer to argument vector */
#endif

#if SPT_TYPE == SPT_REUSEARGV
char *LastArgv = NULL;		/* end of argv */
#endif

/*
   **  Pointers for setproctitle.
   **   This allows "ps" listings to give more useful information.
 */
void initsetproctitle(argc, argv, envp)
     int argc;
     char **argv;
     char **envp;
{
#if SPT_TYPE == SPT_REUSEARGV
    register int i, envpsize = 0;
    char **newenviron;
    extern char **environ;

    /*
       **  Save start and extent of argv for setproctitle.
     */

    LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
    if (envp != NULL) {
	/*
	   **  Move the environment so setproctitle can use the space at
	   **  the top of memory.
	 */
	for (i = 0; envp[i] != NULL; i++)
	    envpsize += strlen(envp[i]) + 1;
	newenviron = (char **) malloc(sizeof(char *) * (i + 1));
	if (newenviron) {
	    int err = 0;
	    for (i = 0; envp[i] != NULL; i++) {
		if ((newenviron[i] = strdup(envp[i])) == NULL) {
		    err = 1;
		    break;
		}
	    }
	    if (err) {
		for (i = 0; newenviron[i] != NULL; i++)
		    free(newenviron[i]);
		free(newenviron);
		i = 0;
	    }
	    else {
		newenviron[i] = NULL;
		environ = newenviron;
	    }
	}
	else {
	    i = 0;
	}

	/*
	   **  Find the last environment variable within wu-ftpd's
	   **  process memory area.
	 */
	while (i > 0 && (envp[i - 1] < argv[0] ||
		    envp[i - 1] > (argv[argc - 1] + strlen(argv[argc - 1]) +
				   1 + envpsize)))
	    i--;

	if (i > 0)
	    LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    }
#endif /* SPT_TYPE == SPT_REUSEARGV */

#if SPT_TYPE == SPT_REUSEARGV || SPT_TYPE == SPT_CHANGEARGV
    Argv = argv;
#endif
}


#if SPT_TYPE != SPT_BUILTIN

/*VARARGS1 */
void setproctitle(const char *fmt,...)
{
#if SPT_TYPE != SPT_NONE
    register char *p;
    register int i;
    SETPROC_STATIC char buf[SPT_BUFSIZE];
    VA_LOCAL_DECL
#if SPT_TYPE == SPT_PSTAT
	union pstun pst;
#endif
#if SPT_TYPE == SPT_SCO
    static off_t seek_off;
    static int kmemfd = -1;
    static int kmempid = -1;
#ifdef UNIXWARE
    off_t offset;
    void *ptr;
    struct mioc_rksym rks;
#endif /* UNIXWARE */
#endif /* SPT_SCO */

    p = buf;

    /* print ftpd: heading for grep */
    (void) strcpy(p, "ftpd: ");
    p += strlen(p);

    /* print the argument string */
    VA_START(fmt);
    (void) vsnprintf(p, SPACELEFT(buf, p), fmt, ap);
    VA_END;

    i = strlen(buf);

#if SPT_TYPE == SPT_PSTAT
    pst.pst_command = buf;
    pstat(PSTAT_SETCMD, pst, i, 0, 0);
#endif
#if SPT_TYPE == SPT_PSSTRINGS
    PS_STRINGS->ps_nargvstr = 1;
    PS_STRINGS->ps_argvstr = buf;
#endif
#if SPT_TYPE == SPT_SYSMIPS
    sysmips(SONY_SYSNEWS, NEWS_SETPSARGS, buf);
#endif
#if SPT_TYPE == SPT_SCO
    if (kmemfd < 0 || kmempid != getpid()) {
	if (kmemfd >= 0)
	    close(kmemfd);
	if ((kmemfd = open(_PATH_KMEM, O_RDWR, 0)) < 0)
	    return;
	(void) fcntl(kmemfd, F_SETFD, 1);
	kmempid = getpid();
#ifdef UNIXWARE
	seek_off = 0;
	rks.mirk_symname = "upointer";
	rks.mirk_buf = &ptr;
	rks.mirk_buflen = sizeof(ptr);
	if (ioctl(kmemfd, MIOC_READKSYM, &rks) < 0)
	    return;
	offset = (off_t) ptr + (off_t) & ((struct user *) 0)->u_procp;
	if (lseek(kmemfd, offset, SEEK_SET) != offset)
	    return;
	if (read(kmemfd, &ptr, sizeof(ptr)) != sizeof(ptr))
	    return;
	offset = (off_t) ptr + (off_t) & ((struct proc *) 0)->p_execinfo;
	if (lseek(kmemfd, offset, SEEK_SET) != offset)
	    return;
	if (read(kmemfd, &ptr, sizeof(ptr)) != sizeof(ptr))
	    return;
	seek_off = (off_t) ptr + (off_t) ((struct execinfo *) 0)->ei_psargs;
#else /* UNIXWARE */
	seek_off = UVUBLK + (off_t) & ((struct user *) 0)->u_psargs;
#endif /* UNIXWARE */
    }
#ifdef UNIXWARE
    if (seek_off == 0)
	return;
#endif /* UNIXWARE */
    buf[PSARGSZ - 1] = '\0';
    if (lseek(kmemfd, (off_t) seek_off, SEEK_SET) == seek_off)
	(void) write(kmemfd, buf, PSARGSZ);
#endif /* SPT_SCO */
#if SPT_TYPE == SPT_REUSEARGV
    if (i > LastArgv - Argv[0] - 2) {
	i = LastArgv - Argv[0] - 2;
	buf[i] = '\0';
    }
    (void) strcpy(Argv[0], buf);
    p = &Argv[0][i];
    while (p < LastArgv)
	*p++ = SPT_PADCHAR;
    Argv[1] = NULL;
#endif
#if SPT_TYPE == SPT_CHANGEARGV
    Argv[0] = buf;
    Argv[1] = 0;
#endif
#endif /* SPT_TYPE != SPT_NONE */
}

#endif /* SPT_TYPE != SPT_BUILTIN */

#ifdef KERBEROS
/* thanks to gshapiro@wpi.wpi.edu for the following kerberosities */

void init_krb()
{
    char hostname[100];

#ifdef HAVE_SYSINFO
    if (sysinfo(SI_HOSTNAME, hostname, sizeof(hostname)) < 0) {
	perror("sysinfo");
#else
    if (gethostname(hostname, sizeof(hostname)) < 0) {
	perror("gethostname");
#endif
	exit(1);
    }
    if (strchr(hostname, '.'))
	*(strchr(hostname, '.')) = 0;

    sprintf(krb_ticket_name, "/var/dss/kerberos/tkt/tkt.%d", getpid());
    krb_set_tkt_string(krb_ticket_name);

    config_auth();

    if (krb_svc_init("hesiod", hostname, (char *) NULL, 0, (char *) NULL,
		     (char *) NULL) != KSUCCESS) {
	fprintf(stderr, "Couldn't initialize Kerberos\n");
	exit(1);
    }
}

void end_krb()
{
    unlink(krb_ticket_name);
}

#endif /* KERBEROS */

#ifdef ULTRIX_AUTH
static int ultrix_check_pass(char *passwd, char *xpasswd)
{
    struct svcinfo *svp;
    int auth_status;

    if ((svp = getsvc()) == (struct svcinfo *) NULL) {
	syslog(LOG_WARNING, "getsvc() failed in ultrix_check_pass");
	return -1;
    }
    if (pw == (struct passwd *) NULL) {
	return -1;
    }
    if (((svp->svcauth.seclevel == SEC_UPGRADE) &&
	 (!strcmp(pw->pw_passwd, "*")))
	|| (svp->svcauth.seclevel == SEC_ENHANCED)) {
	if ((auth_status = authenticate_user(pw, passwd, "/dev/ttypXX")) >= 0) {
	    /* Indicate successful validation */
	    return auth_status;
	}
	if (auth_status < 0 && errno == EPERM) {
	    /* Log some information about the failed login attempt. */
	    switch (abs(auth_status)) {
	    case A_EBADPASS:
		break;
	    case A_ESOFTEXP:
		syslog(LOG_NOTICE, "password will expire soon for user %s",
		       pw->pw_name);
		break;
	    case A_EHARDEXP:
		syslog(LOG_NOTICE, "password has expired for user %s",
		       pw->pw_name);
		break;
	    case A_ENOLOGIN:
		syslog(LOG_NOTICE, "user %s attempted login to disabled acct",
		       pw->pw_name);
		break;
	    }
	}
    }
    else {
	if ((*pw->pw_passwd != '\0') && (!strcmp(xpasswd, pw->pw_passwd))) {
	    /* passwd in /etc/passwd isn't empty && encrypted passwd matches */
	    return 0;
	}
    }
    return -1;
}
#endif /* ULTRIX_AUTH */

#ifdef USE_PAM
/* This is rather an abuse of PAM, but the FTP protocol doesn't allow much
 * flexibility here.  :-(
 */

#include <security/pam_appl.h>
/* Static variables used to communicate between the conversation function
 * and the server_login function
 */
static char *PAM_password;

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */
static int PAM_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int replies = 0;
    struct pam_response *reply = NULL;

#define COPY_STRING(s) (s) ? strdup(s) : NULL

    reply = malloc(sizeof(struct pam_response) * num_msg);
    if (!reply)
	return PAM_CONV_ERR;

    for (replies = 0; replies < num_msg; replies++) {
	switch (msg[replies]->msg_style) {
	case PAM_PROMPT_ECHO_ON:
	    return PAM_CONV_ERR;
	    break;
	case PAM_PROMPT_ECHO_OFF:
	    reply[replies].resp_retcode = PAM_SUCCESS;
	    reply[replies].resp = COPY_STRING(PAM_password);
	    /* PAM frees resp */
	    break;
	case PAM_TEXT_INFO:
	    /* ignore it... */
	    reply[replies].resp_retcode = PAM_SUCCESS;
	    reply[replies].resp = NULL;
	    break;
	case PAM_ERROR_MSG:
	    /* ignore it... */
	    reply[replies].resp_retcode = PAM_SUCCESS;
	    reply[replies].resp = NULL;
	    break;
	default:
	    /* Must be an error of some sort... */
	    return PAM_CONV_ERR;
	}
    }
    *resp = reply;
    return PAM_SUCCESS;
}
static struct pam_conv PAM_conversation =
{
    &PAM_conv,
    NULL
};

static int pam_check_pass(char *user, char *passwd)
{
    pam_handle_t *pamh;
    int pam_error;

    /* Now use PAM to do authentication.  For now, we won't worry about
     * session logging, only authentication.  Bail out if there are any
     * errors.  Since this is a limited protocol, and an even more limited
     * function within a server speaking this protocol, we can't be as
     * verbose as would otherwise make sense.
     */
#define PAM_BAIL if (pam_error != PAM_SUCCESS) { pam_end(pamh, 0); return 0; }
    PAM_password = passwd;
    pam_error = pam_start("ftp", user, &PAM_conversation, &pamh);
    pam_set_item(pamh, PAM_RHOST, remotehost);
    PAM_BAIL;
    pam_error = pam_authenticate(pamh, 0);
    PAM_BAIL;
    pam_error = pam_acct_mgmt(pamh, 0);
    PAM_BAIL;
#ifdef PAM_ESTABLISH_CRED
    pam_error = pam_setcred(pamh, PAM_ESTABLISH_CRED);
#else
    pam_error = pam_setcred(pamh, PAM_CRED_ESTABLISH);
#endif
    PAM_BAIL;
    pam_end(pamh, PAM_SUCCESS);
    /* If this point is reached, the user has been authenticated. */
    return 1;
}
#endif

#ifdef DAEMON

static unsigned long int acl_DaemonAddress(void)
{
    unsigned long int rv = INADDR_ANY;
    struct aclmember *entry = NULL;

    if (getaclentry("daemonaddress", &entry) && ARG0) {
	rv = inet_addr(ARG0);
	if (rv == -1)
	    rv = INADDR_ANY;
    }
    return rv;
}

/* I am running as a standalone daemon (not under inetd) */
void do_daemon(int argc, char **argv, char **envp)
{
    struct sockaddr_in server;
    struct servent *serv;
    int pgrp;
    int lsock;
    int namelen;
    int one = 1;
    FILE *pidfile;
    int i;
    int port;

    /* Some of this is "borrowed" from inn - lots of it isn't */

    if (be_daemon == 2) {
	/* Fork - so I'm not the owner of the process group any more */
	i = fork();
	if (i < 0) {
	    syslog(LOG_ERR, "cant fork %m");
	    exit(1);
	}
	/* No need for the parent any more */
	if (i > 0)
	    exit(0);

#ifdef NO_SETSID
	pgrp = setpgrp(0, getpid());
#else
	pgrp = setsid();
#endif
	if (pgrp < 0) {
	    syslog(LOG_ERR, "cannot daemonise: %m");
	    exit(1);
	}
    }

    if (!Bypass_PID_Files)
	if ((pidfile = fopen(_PATH_FTPD_PID, "w"))) {
	    fprintf(pidfile, "%ld\n", (long) getpid());
	    fclose(pidfile);
	}
	else {
	    syslog(LOG_ERR, "Cannot write pidfile: %m");
	}

    /* Close off all file descriptors and reopen syslog */
    if (be_daemon == 2) {
	int i, fds;
#ifdef HAVE_GETRLIMIT
	struct rlimit rlp;

	rlp.rlim_cur = rlp.rlim_max = RLIM_INFINITY;
	if (getrlimit(RLIMIT_NOFILE, &rlp))
	    return;
	fds = rlp.rlim_cur;
#else
#ifdef HAVE_GETDTABLESIZE
	if ((fds = getdtablesize()) <= 0)
	    return;
#else
#ifdef OPEN_MAX
	fds = OPEN_MAX;		/* need to include limits.h somehow */
#else
	fds = sizeof(long);	/* XXX -- magic */
#endif
#endif
#endif

	closelog();
	for (i = 0; i <= fds; i++) {
	    close(i);
	}
#ifdef FACILITY
	openlog("gridftpd", LOG_PID | LOG_NDELAY, FACILITY);
#else
	openlog("gridftpd", LOG_PID);
#endif

	/* junk stderr */
	(void) freopen(_PATH_DEVNULL, "w", stderr);
    }

    if (RootDirectory != NULL) {
	if ((chroot(RootDirectory) < 0)
	    || (chdir("/") < 0)) {
	    syslog(LOG_ERR, "Cannot chroot to initial directory, aborting.");
	    exit(1);
	}
	free(RootDirectory);
	RootDirectory = NULL;
    }

    if (!use_accessfile)
	syslog(LOG_WARNING, "FTP server started without ftpaccess file");

    syslog(LOG_INFO, "FTP server (%s) ready.", version);

    /* Create a socket to listen on */
    lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsock < 0) {
	syslog(LOG_ERR, "Cannot create socket to listen on: %m");
	exit(1);
    }
    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) < 0) {
	syslog(LOG_ERR, "Cannot set SO_REUSEADDR option: %m");
	exit(1);
    }
    if (keepalive)
	(void) setsockopt(lsock, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = acl_DaemonAddress();
    if (daemon_port == -1) {
	if (!(serv = getservbyname("ftp", "tcp"))) {
	    syslog(LOG_ERR, "Cannot find service ftp: %m");
	    exit(1);
	}
	server.sin_port = serv->s_port;
    }
    else if(daemon_port >= 0)
    { 
	server.sin_port = htons(daemon_port);
    }
    else
    {
        syslog(LOG_ERR, "Bad port number passed to server");
        exit(1);
    }

    namelen = sizeof(server);
    
    if (bind(lsock, (struct sockaddr *) &server, namelen) < 0) {
	syslog(LOG_ERR, "Cannot bind socket: %m");
	exit(1);
    }
    
    listen(lsock, MAX_BACKLOG);

    if(getsockname(lsock,(struct sockaddr *) &server, &namelen) < 0)
    {
        syslog(LOG_ERR, "Cannot get local address of socket: %m");
	exit(1);
    }
    
    port = ntohs(server.sin_port);

    if(daemon_port == 0)
    {
        fprintf(stdout, "Accepting connections on port %i\n", port);
        fflush(stdout);
    }

    daemon_port = port;
    
    sprintf(proctitle, "accepting connections on port %i", daemon_port);
    setproctitle("%s", proctitle);

    while (1) {
	int pid;
	int msgsock;

	msgsock = accept(lsock, 0, 0);
	if (msgsock < 0) {
	    syslog(LOG_ERR, "Accept failed: %m");
	    sleep(1);
	    continue;
	}
	if (keepalive)
	    (void) setsockopt(msgsock, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

	if (debug_no_fork) {
		pid = 0;
	} else {
		/* Fork off a handler */
		pid = fork();
	}
	if (pid < 0) {
	    syslog(LOG_ERR, "failed to fork: %m");
	    sleep(1);
	    continue;
	}
	if (pid == 0) {
	    /* I am that forked off child */
	    closelog();
	    /* Make sure that stdin/stdout are the new socket */
	    dup2(msgsock, 0);
	    dup2(msgsock, 1);
	    /* Only parent needs lsock */
	    if (lsock != 0 && lsock != 1)
		close(lsock);
#ifdef FACILITY
	    openlog("gridftpd", LOG_PID | LOG_NDELAY, FACILITY);
#else
	    openlog("gridftpd", LOG_PID);
#endif
	    return;
	}

	/* I am the parent */
	close(msgsock);

	/* Quick check to see if any of the forked off children have
	 * terminated. */
	while ((pid = waitpid((pid_t) -1, (int *) 0, WNOHANG)) > 0) {
	    /* A child has finished */
	}
    }
}

#endif /* DAEMON */

#ifdef RATIO
int is_downloadfree(char *fname)
{
    char        rpath[MAXPATHLEN];
    char	class[1024];
    char        *cp;
    int		which;
    struct aclmember *entry = NULL;

    if( wu_realpath(fname,rpath,chroot_path) == NULL )
        return 0;

    (void) acl_getclass(class);

    syslog(LOG_INFO, "class: %s, fname: %s, rpath: %s", class, fname, rpath);

    while( getaclentry("dl-free-dir",&entry) ) {
        if( ARG0 == NULL )
            continue;
        if( strncmp(rpath,ARG0,strlen(ARG0)) == 0 ) {
	    if( ARG1 == NULL )
		return 1;
	    else for(which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if( strcmp(class,ARG[which]) == 0 )
		    return 1;
	    }
        }
    }
    while( getaclentry("dl-free",&entry) ) {
        if( ARG0 == NULL )
            continue;
        if( *(ARG0) != '/' ) {  /* compare basename */
            if( (cp = strrchr(rpath,'/')) == NULL ) {
                cp = rpath;
            }
            else {
                ++cp;
            }
            if( strcmp(cp,ARG0) == 0 ) {
		if( ARG1 == NULL )
		    return 1;
		else for(which = 1; (which < MAXARGS) && ARG[which]; which++) {
		    if( strcmp(class,ARG[which]) == 0 )
		    return 1;
		}
            }
        }
        else {  /* compare real path */
            if( strcmp(rpath,ARG0) == 0 ) {
		if( ARG1 == NULL )
		    return 1;
		else for(which = 1; (which < MAXARGS) && ARG[which] ; which++) {
		    if( strcmp(class,ARG[which]) == 0 )
		    return 1;
		}
            }
        }
    }
    return 0;
}
#endif /* RATIO */

int pasv_allowed(char *remoteaddr)
{
    char class[MAXPATHLEN];
    int which;
    struct aclmember *entry = NULL;
    (void) acl_getclass(class);
    while (getaclentry("port-allow", &entry)) {
	if ((ARG0 != NULL) && (strcasecmp(class, ARG0) == 0))
	    for (which = 1; (which < MAXARGS) && (ARG[which] != NULL); which++) {
		if (hostmatch(ARG[which], remoteaddr, NULL))
		    return 1;
	    }
    }
    return 0;
}

int port_allowed(char *remoteaddr)
{
    char class[MAXPATHLEN];
    int which;
    struct aclmember *entry = NULL;
    (void) acl_getclass(class);
    while (getaclentry("port-allow", &entry)) {
	if ((ARG0 != NULL) && (strcasecmp(class, ARG0) == 0))
	    for (which = 1; (which < MAXARGS) && (ARG[which] != NULL); which++) {
		if (hostmatch(ARG[which], remoteaddr, NULL))
		    return 1;
	    }
    }
    return 0;
}

#ifdef MAIL_ADMIN
char *email(char *full_address)
{
    /* Get the plain address part from an e-mail address
       (i.e. remove realname) */

    char *addr;

    addr = (char *) malloc(strlen(full_address) + 1);
    memset(addr, 0, strlen(full_address) + 1);
    strcpy(addr, full_address);

    /* Realname <user@host> type address */
    if (((char *) strchr(addr, '<')) != NULL) {
	addr = (char *) strchr(addr, '<') + 1;
	addr[strchr(addr, '>') - addr] = '\0';
    }

    /* user@host (Realname) type address */
    if (((char *) strchr(addr, ' ')) != NULL)
	addr[strchr(addr, ' ') - addr] = '\0';

    return addr;
}

FILE *SockOpen(char *host, int clientPort)
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    struct hostent *hp;
    FILE *fp;

    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;

    inaddr = inet_addr(host);
    if (inaddr != (unsigned long) -1)
	memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
    else {
	hp = gethostbyname(host);
	if (hp == NULL)
	    return (FILE *) NULL;
	memcpy(&ad.sin_addr, hp->h_addr, hp->h_length);
    }
    ad.sin_port = htons(clientPort);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
	return (FILE *) NULL;
    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) < 0) {
	close(sock);
	return (FILE *) NULL;
    }
    fp = fdopen(sock, "r+");
    setvbuf(fp, NULL, _IOLBF, 2048);
    return (fp);
}

int SockPrintf(FILE *sockfp, char *format,...)
{
    va_list ap;
    char buf[32768];

    va_start(ap, format);
    vsprintf(buf, format, ap);
    va_end(ap);
    return SockWrite(buf, 1, strlen(buf), sockfp);
}

int SockWrite(char *buf, int size, int len, FILE *sockfp)
{
    return (fwrite(buf, size, len, sockfp));
}

char *SockGets(FILE *sockfp, char *buf, int len)
{
    return (fgets(buf, len, sockfp));
}

int SockPuts(FILE *sockfp, char *buf)
{
    int rc;

    if ((rc = SockWrite(buf, 1, strlen(buf), sockfp)))
	return rc;
    return SockWrite("\r\n", 1, 2, sockfp);
}

int Reply(FILE *sockfp)
{
    char *reply, *rec, *separator;
    int ret = 0;

    reply = (char *) malloc(1024);
    memset(reply, 0, 1024);
    do {
	rec = SockGets(sockfp, reply, 1024);
	if (rec != NULL) {
	    ret = strtol(reply, &separator, 10);
	}
	else
	    ret = 250;
    } while ((rec != NULL) && (separator[0] != ' '));
    return ret;
}

int Send(FILE *sockfp, char *format,...)
{
    va_list ap;
    char buf[32728];

    va_start(ap, format);
    vsprintf(buf, format, ap);
    va_end(ap);
    SockWrite(buf, 1, strlen(buf), sockfp);
    return Reply(sockfp);
}
#endif /* MAIL_ADMIN */


/*
 * fixpath
 *
 * In principal, this is similar to realpath() or the mapping chdir function.
 * It removes unnecessary path components.  We do this to put a stop to
 * attempts to cause a memory starvation DoS.
 *
 */

void fixpath(char *path)
{
    int abs = 0;
    char *in;
    char *out;

    if (*path == '/') {
	abs = 1;
	path++;
    }
    else if (*path == '~') {
	do
	    path++;
	while ((*path != '\0') && (*path != '/'));
	if (*path == '/')
	    path++;
    }
    in = path;
    out = path;
    while (*in != '\0') {
	if (*in == '/')
	    in++;
	else if ((in[0] == '.') && ((in[1] == '/') || (in[1] == '\0'))) {
	    in++;
	    if (*in == '/')
		in++;
	}
	else if ((in[0] == '.') && (in[1] == '.') && ((in[2] == '/') || (in[2] == '\0'))) {
	    if (out == path) {
		if (abs) {
		    in++;
		    in++;
		    if (*in == '/')
			in++;
		}
		else {
		    *out++ = *in++;
		    *out++ = *in++;
		    if (*in == '/')
			*out++ = *in++;
		    path = out;
		}
	    }
	    else {
		out--;
		while ((out != path) && (*--out != '/'));
		in++;
		in++;
		if (*in == '/')
		    in++;
	    }
	}
	else {
	    do
		*out++ = *in++;
	    while ((*in != '\0') && (*in != '/'));
	    if (*in == '/')
		*out++ = *in++;
	}
    }
    *out = '\0';
}


#ifdef POST_AUTH_PROCESS
/*
 * Run the post authentication process on the user's behalf.
 * pw should be the user's passwd information.	
 */
int
run_post_auth_process(struct passwd *pw)
{
    struct stat st;
    char *program = POST_AUTH_PROCESS;


    /* XXX Need to add some sanity checks here on the process */
    if (stat(program, &st) == 0) {
	int pid;
	int testpid;


	if (debug)
	    syslog(LOG_DEBUG,
		   "Running post authentication process \"%s\"",
		   program);

	/*
	 * Run the process under the user's actual ID. This is because many
	 * programs we want to run here (aklog, sslk5) need to be run
	 * under the real ID of the user.
	 */
	pid = fork();

	if (pid == 0) {			/* CHILD */
	    int rc;
	    
	    seteuid(0);
	    setuid(pw->pw_uid);
	    if (pw->pw_dir) {
		/*
		 * Don't use setenv() here as not all systems (e.g. solaris)
		 * have it.
		 */
		char *envstr;
		
		envstr = malloc(strlen(pw->pw_dir) + 6 /* 'HOME=' + NUL */);
		
		if (envstr) {
		    sprintf(envstr, "HOME=%s", pw->pw_dir);
		    putenv(envstr);
		} else {
		    syslog(LOG_ERR, "malloc() failed");
		}
	    }
	    rc = system(program);
	    if (debug)
		syslog(LOG_DEBUG, "PostAuthProcess returned %d", rc);
	    
	    exit(0);
	}

	/* PARENT */
	while ((testpid = wait(NULL)) != pid &&
	       testpid != -1)
	    { /* EMPTY LOOP */ }


    } else {
	syslog(LOG_ERR,
	       "Error accessing post authentication program \"%s\" (errno=%d)",
	       program, errno);
    }
    return(0);
}
#endif /* POST_AUTH_PROCESS */

