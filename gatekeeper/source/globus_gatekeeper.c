/******************************************************************************
gram_gatekeeper.c
 
Description:
    Resource Managemant gatekeeper.
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$

 This source file has been modified by Brent Milne (BMilne@lbl.gov)
 with extensions for UNICOS.
 September 1998
 
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#if defined(_AIX32) && !defined(_ALL_SOURCE)
#define _ALL_SOURCE
#endif
#include "globus_config.h"
#include "globus_i_gram_version.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/param.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <syslog.h>
#include <netdb.h>
#include <netinet/in.h>
#if defined (HAVE_NETINET_TCP_H)
#   include <netinet/tcp.h>
#endif
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/wait.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef GSS_AUTHENTICATION
#include "globus_gss_assist.h"
#include <gssapi.h>
#endif

#if defined(TARGET_ARCH_SOLARIS)
#include <termios.h>
#endif

#if defined(TARGET_ARCH_AIX)
#define netlen_t size_t
#else
#define netlen_t int
#endif

#include <strings.h>

#include <arpa/inet.h> /* for inet_ntoa() */

#ifdef BSD
#include <strings.h>
#endif

#ifdef SYSV
#include <string.h>
#endif

#if defined(TARGET_ARCH_CRAYT3E)
#include "unicos.h"
#endif

#if defined(HAVE_PROJ_H) && defined(TARGET_ARCH_IRIX)
#include <proj.h>
#endif

#if !defined(MAXPATHLEN) 
#   define MAXPATHLEN PATH_MAX
#endif

#include "globus_gatekeeper_utils.h"

/******************************************************************************
                               Type definitions
******************************************************************************/

#define SERVICE_ARGS_MAX 100
/* offsets in the service command line after tokenize */
/* note the one before the path gets overlaid */
#define SERVICE_OPTIONS_INDEX 0
#define SERVICE_USER_INDEX 1
#define SERVICE_PATH_INDEX 2
#define SERVICE_ARG0_INDEX 3
#define SERVICE_ARG1_INDEX 4

#define SERVICE_OPTIONS_MAX 20
/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static void 
doit();
static int 
logging_startup(void);
static int
logging_phase2(void);
static void 
failure(char *s);
static void 
notice(int, char *s);
static int 
net_accept(int socket);
static void 
net_setup_listener(int backlog, int *port, int *socket);
static void 
error_check(int val, char *string);
static char 
*timestamp(void);

static char *
genfilename(char * prefix, char * path, char * sufix);

/*
 * GSSAPI - credential handle for this process
 */

static gss_cred_id_t credential_handle = GSS_C_NO_CREDENTIAL;
static gss_ctx_id_t  context_handle    = GSS_C_NO_CONTEXT;

/******************************************************************************
                       Define module specific variables
******************************************************************************/
#define MAXARGS 256
#define DEFAULT_PORT 754
#define MAX_MESSAGE_LENGTH 100000
#ifndef GRAM_K5_EXE
#	define GRAM_K5_EXE "globus-k5"
#endif
#ifndef GLOBUS_LIBEXECDIR
#  define GLOBUS_LIBEXECDIR "libexec"
#endif
#ifndef GLOBUS_GATEKEEPER_HOME
#	define GLOBUS_GATEKEEPER_HOME "/etc"
#endif
#ifndef LOGFILE
#define LOGFILE ""
#endif

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif

static char     tmpbuf[1024];
#define notice2(i,a,b) {sprintf(tmpbuf, a,b); notice(i,tmpbuf);}
#define notice3(i,a,b,c) {sprintf(tmpbuf, a,b,c); notice(i,tmpbuf);}
#define notice4(i,a,b,c,d) {sprintf(tmpbuf, a,b,c,d); notice(i,tmpbuf);}
#define failure2(a,b) {sprintf(tmpbuf, a,b); failure(tmpbuf);}
#define failure3(a,b,c) {sprintf(tmpbuf, a,b,c); failure(tmpbuf);}
#define failure4(a,b,c,d) {sprintf(tmpbuf, a,b,c,d); failure(tmpbuf);}

#if ! defined(TARGET_ARCH_LINUX) & ! defined(TARGET_ARCH_FREEBSD)
extern char *   sys_errlist[];
#endif

extern int      errno;

static int      connection_fd;

static FILE *   usrlog_fp;
static char *   logfile = LOGFILE;
static char     test_dat_file[1024];
static int      gatekeeper_test;
static int      gatekeeper_uid;
static int      daemon_port;
static int      logging_syslog;
static int      logging_usrlog;
static int      debug;
static int      foreground;
static int      krb5flag;
static int      run_from_inetd;
static char *   gatekeeperhome = NULL;
static char *	job_manager_exe = NULL;
static char *   jm_conf_path = NULL;
static char *   libexecdir = GLOBUS_LIBEXECDIR;
static char *   service_name = NULL;
static char *   grid_services = "grid-services";
static char *   globusmap = "globusmap";
static char *   globuskmap = "globuskmap";
static char *   globuspwd = NULL;
static char *   globuscertdir = "cert";
static char *   globuskeydir = "key";
static char *   globusnologin ="globus-nologin";
static char *   x509_cert_dir = NULL;
static char *   x509_cert_file = NULL;
static char *   x509_user_proxy = NULL;
static char *   x509_user_cert = NULL;
static char *   x509_user_key = NULL;
static int      ok_to_send_errmsg = 0;
static FILE *   fdout;

/******************************************************************************
Function:       get_globusid()
Description:    Get the globusid from gssapi or environment if possible.
Parameters:
Returns:
******************************************************************************/
static char * 
get_globusid()
{
    char *            globusid;
    char *            globusid_tmp;
    gss_name_t        server_name = GSS_C_NO_NAME;
    gss_buffer_desc   server_buffer_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_t      server_buffer = &server_buffer_desc; 
    OM_uint32         major_status = 0;
    OM_uint32         minor_status = 0;
    OM_uint32         minor_status2 = 0;

    if ((major_status = gss_inquire_cred(&minor_status,
                                        credential_handle,
                                        &server_name,
                                        NULL,
                                        NULL,
                                        NULL)) == GSS_S_COMPLETE)
    {
        major_status = gss_export_name(&minor_status,
                                       server_name,
                                       server_buffer);
        gss_release_name(&minor_status2, &server_name);
    }
    /*
     * The gssapi_cleartext does not implement gss_inquire_cred,
     * so fall back to using environment variable.
     */
    if (major_status == GSS_S_COMPLETE) 
    {
        globusid = server_buffer_desc.value;
    }
    else 
    {
        globusid = getenv("GLOBUSID");
        globusid = (globusid ? globusid : "GLOBUSID");
    }
    globusid_tmp = strdup(globusid);

    if (server_buffer_desc.value)
    {
        gss_release_buffer(&minor_status2, server_buffer);
    }
    return globusid_tmp;
}

/******************************************************************************
Function:       reaper()
Description:    Wait for any child processes that have terminated.
Parameters:
Returns:
******************************************************************************/
void 
reaper(int s)
{
    int pid;
#   ifdef HAS_WAIT_UNION_WAIT
      union wait status;
#   else
      int status;
#   endif

#   ifdef HAS_WAIT3
      while ((pid = wait3(&status, WNOHANG, NULL)) > 0) ;
#   else
      while ((pid = waitpid(-1, &status, WNOHANG)) > 0) ;
#   endif
} /* reaper() */


/******************************************************************************
Function:       genfilename()
Description:    generate an absolute file name given a starting prefix,
                a relative or absolute path, and a sufix
                Only use prefix if path is relative.
Parameters:
Returns:		a pointer to a string which could be freeded.
******************************************************************************/

static char *
genfilename(char * prefixp, char * pathp, char * sufixp)
{
    char * newfilename;
    int    prefixl, pathl, sufixl;
    char * prefix,  * path, * sufix;

    prefix = (prefixp) ? prefixp : "";
    path   = (pathp) ? pathp : "";
    sufix  = (sufixp) ? sufixp : "";

    prefixl = strlen(prefix);
    pathl   =  strlen(path);
    sufixl  =  strlen(sufix); 

    newfilename = (char *) calloc(1, (prefixl + pathl + sufixl + 3));
    if (newfilename) 
    {
        if (*path != '/')
        {
            strcat(newfilename, prefix);
            if ((prefixl != 0) && (prefix[prefixl-1] != '/'))
            {
                strcat(newfilename, "/");
            }
        }
        strcat(newfilename, path);
        if ((pathl  != 0) &&
            (sufixl != 0) && 
            (path[pathl-1] != '/') && 
             sufix[0] != '/')
        {
            strcat(newfilename, "/");
        }
        strcat(newfilename, sufix);
    }
    return newfilename;
}

/******************************************************************************
Function:       main()
Description:    
Parameters:
Returns:
******************************************************************************/
int 
main(int xargc,
     char ** xargv)
{
    int argc = xargc;
    char ** argv = xargv;
    int    i;
    int    fd;
    int    pid;
    int    ttyfd;
	int    rc;
    netlen_t   namelen;
    int    listener_fd;
    struct sockaddr_in name;
	struct stat         statbuf;

    /* GSSAPI status vaiables */
    OM_uint32 major_status = 0;
    OM_uint32 minor_status = 0;

#if defined(TARGET_ARCH_CRAYT3E)
    unicos_init();
#endif

	/* 
	 * Don't allow logins of /etc/nologins is defined. 
	 * Silently ignore them, as the sysadmin
	 * must have other problems.
	 */

	if ((rc = stat("/etc/nologin",&statbuf)) == 0 )
	{
		exit (1);
	}

    gatekeeper_uid = getuid();
    if (gatekeeper_uid == 0)
    {
        /*
         * If root, use DEFAULT_PORT
         */
        daemon_port = DEFAULT_PORT;
    }
    else
    {
        /*
         * If not root, let net_setup_listener call provide the port
         * (may be overridden by the "-p" option, see below)
         */
        daemon_port = 0;
    }

    /*
     * Decide if we are being run from inetd.
     * If so, then stdin will be connected to a socket,
     * so getpeername() will succeed.
     */

    namelen = sizeof(name);
    if (getpeername(0, (struct sockaddr *) &name, &namelen) < 0)
    {
        /* set current working directory as default for 
         * gatekeeperhome (-home path) when not run from inetd. 
         * otherwise it is NULL
         */
        {
            char *tmppath = NULL;
            int size = 1;

            while ( (tmppath = getcwd (NULL, size)) == NULL )
            {
                size++;
            }
            gatekeeperhome = tmppath;
        }

        run_from_inetd = 0;
    }
    else
    {
        run_from_inetd = 1;
        gatekeeperhome = GLOBUS_GATEKEEPER_HOME;
        /* 
         * cant have stdout pointing at socket, some of the
         * old-old gssapi code writes to stdout so point at stderr
         */
        close(1);
        (void) open("/dev/null",O_WRONLY);
    }

    *test_dat_file = '\0';
    /*
     * Parse the command line arguments
     */
    /* 
     * But first see if the first parameter is a -c filename
     * which has the real parameter list. This is needed
     * since the parameters are getting long, and inetd/wrapper
     * may have a problem.  Will assume there are at most 52 
     * args, in a buffer of BUFSIZ at the most. 
     */

    /* But before that, check if there is a -test option
     * after the -c file. This will test the gatekeeper
     * -test can also be in the options file 
     * this will run in forground, and not inetd
     */

    if (argc == 4 && !strcmp(argv[3],"-test"))
    {
        gatekeeper_test++;
        argc--;
    }

    if (argc == 3 && !strcmp(argv[1],"-c"))
    {
        char ** newargv;
        char * newbuf; 	
        int newargc = 52;
        int  pfd;
	  
        newargv = (char**) malloc(newargc * sizeof(char *)); /* not freeded */
        newbuf = (char *) malloc(BUFSIZ);  /* dont free */
        newargv[0] = argv[0];
        pfd = open(argv[2],O_RDONLY);
        i = read(pfd, newbuf, BUFSIZ-1);
        if (i < 0) 
            failure("Unable to read extra parameters");
        newbuf[i] = '\0';
        close(pfd);

        newargv[0] = argv[0];
        newargc--;
        globus_gatekeeper_util_tokenize(newbuf, 
							&newargv[1],
							&newargc,
							" \t\n");
        argv = newargv;
        argc = newargc + 1;
    }

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            debug = 1;
            foreground = 1;   /* Run in the forground */
        }
        else if (strcmp(argv[i], "-inetd") == 0)
        {
            run_from_inetd = 1;
            foreground = 0;
        }
        else if ((strcmp(argv[i], "-p") == 0)
                 && (i + 1 < argc))
        {
            daemon_port = atoi(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-l") == 0)
                && (i + 1 < argc))
        {
            logfile =  argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-home") == 0)
                && (i + 1 < argc))
        {
			/* Also know ad the ${deploy_prefix} */
            gatekeeperhome = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-e") == 0)
                && (i + 1 < argc))
        {
            libexecdir = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-grid_services") == 0)
                && (i + 1 < argc))
        {
            grid_services = argv[i+1];
            i++;
        }
		/* The jmconf and -jm are left here during the 
	 	 * cutover to the 1.1 so as to not have to change
		 * the deploy scripts just yet. 
		 */
        else if ((strcmp(argv[i], "-jmconf") == 0)
                 && (i + 1 < argc))
        {
            jm_conf_path =  argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-jm") == 0)
                 && (i + 1 < argc))
        {
            job_manager_exe =  argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-t") == 0)
                 && (i + 1 < argc))
        {
            strncpy(test_dat_file, argv[i+1],sizeof(test_dat_file));
            i++;
        }
        else if (strcmp(argv[i], "-test") == 0)
        {
            gatekeeper_test++;
        }
		
        else if ((strcmp(argv[i], "-globusid") == 0)
                && (i + 1 < argc))
        {
            grami_setenv("GLOBUSID", argv[i+1],1);
            i++;
        }
        else if ((strcmp(argv[i], "-globusmap") == 0)
                 && (i + 1 < argc))
        {
            globusmap = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-globuspwd") == 0)
                 && (i + 1 < argc))
        {
            globuspwd = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-globuskeydir") == 0)
                && (i + 1 < argc))
        {
            globuskeydir = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-globuscertdir") == 0)
                && (i + 1 < argc))
        {
            globuscertdir = argv[i+1];
            i++;
        }
	
        /* set environment variables used by gssapi_ssleay */

        else if ((strcmp(argv[i], "-x509_cert_dir") == 0)
                && (i + 1 < argc))
        {
            x509_cert_dir = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-x509_cert_file") == 0)
                && (i + 1 < argc))
        {
            x509_cert_file = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-x509_user_proxy") == 0)
                && (i + 1 < argc))
        {
            x509_user_proxy = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-x509_user_cert") == 0)
                && (i + 1 < argc))
        {
            x509_user_cert = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-x509_user_key") == 0)
                && (i + 1 < argc))
        {
            x509_user_key = argv[i+1];
            i++;
        }
        
        else if ((strcmp(argv[i], "-globuskmap") == 0)
                && (i + 1 < argc))
        {
            globuskmap = argv[i+1];
            krb5flag = 1;
            i++;
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            krb5flag = 1;
        }
        else if (strcmp(argv[i], "-f") == 0)
        {
            /* make the daemon run in the Foreground */

            foreground = 1;
            run_from_inetd = 0;
        }
        else
        {

            fprintf(stderr, "Unknown argument %s\n", argv[i]);
            fprintf(stderr, "Usage: %s %s %s %s %s %s %s %s %s %s\n ",
                    argv[0], 
                    "{-c parmfile [-test]} | {[-d] [-inetd | -f] [-p port] ",
                    "[-home path] [-l logfile] [-e path] ",
					"[-grid_services file] ",
                    "[-globusid globusid] [-globusmap file] [-globuspwd file]",
                    "[-x509_cert_dir path] [-x509_cert_file file]",
                    "[-x509_user_cert file] [-x509_user_key file]",
                    "[-x509_user_proxy file]",
                    "[-k] [-globuskmap file]",
                    "[-test]"
                   );
            exit(1);
        }
    }

    /*
     * Dont use default env proxy cert for gatekeeper if run as root
     * this might get left over. You can still use -x509_user_proxy
     */

    if (gatekeeper_uid == 0)
    {
    grami_unsetenv("X509_USER_PROXY");
    }

    if (gatekeeper_test)
    {
        fprintf(stderr,"Testing gatekeeper\n");
        if (getuid()) 
        {
            fprintf(stderr,"Local user id (uid)      : %d\n",gatekeeper_uid);
        }
        else
        {
            fprintf(stderr,"Local user id (uid)      : root\n");
        }
        run_from_inetd = 0;
        foreground = 1;
    }

	if (gatekeeperhome)
	{
		grami_setenv("GLOBUS_DEPLOY",gatekeeperhome,1);
	}
    grami_setenv("GLOBUSMAP", genfilename(gatekeeperhome,globusmap,NULL),1);
    if (globuspwd) 
    {
        grami_setenv("GLOBUSPWD", genfilename(gatekeeperhome,globuspwd,NULL),1);
    }

    if (x509_cert_dir)
    {
        grami_setenv("X509_CERT_DIR",
                     genfilename(gatekeeperhome,x509_cert_dir,NULL),
                     1);
    }
    if (x509_cert_file)
    {
        grami_setenv("X509_CERT_FILE",
                     genfilename(gatekeeperhome,x509_cert_file,NULL),
                     1);
    }
    if (x509_user_proxy)
    {
        grami_setenv("X509_USER_PROXY",
                     genfilename(gatekeeperhome,x509_user_proxy,NULL),
                     1);
    }

    if (x509_user_cert)
    {
        grami_setenv("X509_USER_CERT",
                     genfilename(gatekeeperhome,x509_user_cert,NULL),
                     1);
    }
    if (x509_user_key)
    {
        grami_setenv("X509_USER_KEY", 
                     genfilename(gatekeeperhome,x509_user_key,NULL),
                     1);
    }
    if (krb5flag) 
    {
        grami_setenv("GLOBUSKMAP",
                     genfilename(gatekeeperhome,globuskmap,NULL),
                     1);
    }

    if (run_from_inetd)
    {
        (void) close(2);  /* dont want messages. logging will use fd=2 */ 
        (void) open("/dev/null",O_WRONLY);
    }

    if (logging_startup() != 0)
    {
        failure("Logging startup failure");
    }

    notice4(LOG_INFO, "%s pid=%d starting at %s",
        argv[0], getpid(), timestamp());

    /*
     * Setup SIGCHLD signal handler to reap processes that we create
     */
#ifdef HAS_BSD_SIGNAL
    signal(SIGCHLD, reaper);
#else
    {
        struct sigaction act;
        act.sa_handler = reaper;
        sigemptyset(&act.sa_mask);
        sigaddset(&act.sa_mask, SIGCHLD);
        act.sa_flags = 0;
        sigaction(SIGCHLD, &act, NULL);
    }
#endif

    if (run_from_inetd)
    {
        logging_phase2();
        dup2(2,1); /* point stdout at log as well */
        setbuf(stdout,NULL);
    }

#ifdef GSS_AUTHENTICATION
    /* Get the GSS credential for the accepter
     * If not run_from_inetd we can prompt here.
     * If we are running as a deamon, and should not
     * have any prompts
     */
    major_status = globus_gss_assist_acquire_cred(&minor_status,
                                                  GSS_C_ACCEPT,
                                                  &credential_handle);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(stderr,
                              "GSS failed getting server credentials: ",
                              major_status,
                              minor_status,
                              0);

        failure("GSS failed to get server credentials\n");
    }
#endif /* GSS_AUTHENTICATION */

    if (gatekeeper_test) 
    {
        fprintf(stderr,"Gatekeeper subject name  : \"%s\"\n",
        get_globusid());
        fprintf(stderr,"Gatekeeper test complete : Success!\n");
        exit(0);
    }

    if (run_from_inetd)
    {
		(void) setsid();
        doit();
    }
    else
    {

        logging_phase2(); /* now set stderr to logfile after gss prompts */

        net_setup_listener(2, &daemon_port, &listener_fd);

#       if defined(TARGET_ARCH_CRAYT3E)
        {
	    if(gatekeeper_uid == 0)
	    {
		set_unicos_sockopts(listener_fd);
	    }
	}
#       endif

        {
            char hostname[255];
            char *globusid;
            struct hostent *hp;
            char *fqdn;

            gethostname(hostname, sizeof(hostname)-1);

            if ((hp = gethostbyname(hostname)))
            {
                fqdn = (char *) hp->h_name;
            }
            else
            {
                fqdn = (hostname ? hostname : "HOSTNAME");
            }

            globusid = get_globusid();
            printf("GRAM contact: %s:%d:%s\n",
                    fqdn, daemon_port, globusid);
            notice4(LOG_INFO, "GRAM contact: %s:%d:%s\n",
                    fqdn, daemon_port, globusid);
            free(globusid);
        }

        if (!foreground)
        {
            /*
             * Fork off a child, terminate the parent, and detach
             * the child from the tty.
             */
            if (fork())
                exit(0);

            if (!logging_usrlog)
            {
                (void) close(2); /* close stderr as well */
                (void) open ("/dev/null",0);
            }

            (void) close(0);
            (void) close(1);

#           if (defined(SYSV) || \
                defined(__hpux) || \
                defined(CRAY) || \
                defined(TARGET_ARCH_CYGWIN))
	    {
		
    	char fname[256];

		/* mod here (variable "fname") no longer in use. --milne */
		sprintf(fname, "/dev/console"); 
		fd = open (fname, O_RDWR);
		notice2(0, "open dev console fd = %d\n", fd);
		if (fd < 0)
		{
		    sprintf(fname, "/dev/tty");
		    fd = open (fname, O_RDWR);
		}
		notice2(0, "open dev tty fd = %d\n", fd);
		if (fd < 0)
		{
		    sprintf(fname, "/dev/null");
		    fd = open (fname, O_RDWR);
		}
		notice3(0, "open %s fd = %d\n", fname, fd);
		(void) dup2(2, 1); /* point out at stderr or log */

#		if HAVE_SETSID
		(void) setsid();
#		endif
		(void) setpgrp();
	    }
#           else
	    {
		(void) open("/dev/null", O_RDONLY);
		(void) dup2(2, 1); /* point stdout to stderr */
		fd = open("/dev/tty", O_RDWR);
		if (fd >= 0)
		{
		    ioctl(fd, TIOCNOTTY, 0);
		    (void) close(fd);
		}
	    }
#           endif
        }

        /* stderr is either the logfile, the users stderr or the /dev/null */
        /* stdout is either the logfile, the users stdout or the /dev/null */

        while (1)
        {
            connection_fd = net_accept(listener_fd);

            pid = fork();

            if (pid < 0)
            {
                failure2("Fork failed: %s\n", sys_errlist[errno]);
            }

            if (pid == 0)
            {
				(void) setsid();
#               if defined(__hpux) || defined(TARGET_ARCH_SOLARIS)
		{
		    (void) setpgrp();
		}
#               else
		{
		    ttyfd = open("/dev/tty",O_RDWR);
		    if (ttyfd >= 0)
		    {
#                       if !defined(CRAY) && !defined(TARGET_ARCH_CYGWIN)
			{
			    ioctl(ttyfd, TIOCNOTTY, 0);
			}
#                       endif
			close(ttyfd);
		    }
                }
#               endif
		
                fclose(stdin); /* take care of stream buffers too */
                close(0);
                close(listener_fd);

                dup2(connection_fd, 0);
                /* this should work, but not sure !? */
                /* Reports say it is needed on some systems */
                *stdin = *fdopen(0,"r"); /* reopen stdin  we need this since */
                doit();
                exit(0);
            }
            close(connection_fd);
        }
    }
    return 0;
}


/******************************************************************************
Function:       doit()
Description:    Assume stdin is connected to the socket.
                usrlog_fp is set to the logfile.
                Authenticate the client, create the child process, and pass
                the data on to the child process via its stdin. 
Parameters:
Returns:
******************************************************************************/
static void doit()
{
    int                 p1[2];
    int                 pid;
    int                 n;
    int                 i;
    int                 service_uid;
    int                 service_gid;
    int                 close_on_exec_read_fd;
    int                 close_on_exec_write_fd;
    char                buf[1024];
    char *              s;
    char **             args;
    char *              argnp;
    char *              execp;
	char **				argi;
	int					num_service_args = SERVICE_ARGS_MAX;
	char *				service_args[SERVICE_ARGS_MAX];
	int					num_service_options = SERVICE_OPTIONS_MAX;
	char *				service_options[SERVICE_OPTIONS_MAX];
	int					service_option_local_cred = 0;
	int					service_option_stderr_log = 0;
    unsigned char       int_buf[4];
    char                tmp_version[1];
    struct stat         statbuf;
	char *				service_line = NULL;
    char *              service_path;
    char *              gram_k5_path; 
    struct sockaddr_in  peer;
    netlen_t            peerlen;
    char *              peernum;
    char *              x509_delegate;
	size_t				length;

#ifdef GSS_AUTHENTICATION
    /* GSSAPI assist variables */
    OM_uint32           major_status = 0;
    OM_uint32           minor_status = 0;
    int                 token_status = 0;
    OM_uint32           ret_flags = 0;
	gss_buffer_desc 	context_token = GSS_C_EMPTY_BUFFER;
	FILE *				context_tmpfile = NULL;

    /* Authorization variables */
    int                 rc;
    char *              client_name;
    char *              userid;
    struct passwd *     pw;

#endif

	/* Now do stdout, so it points at the socket too */
	/* needed for the grid-services */
			
	fclose(stdout);
	close(1);
	dup2(0,1);
	*stdout = *fdopen(1,"w");
    (void) setbuf(stdout,NULL);

#if defined(TARGET_ARCH_CRAYT3E)
    if(gatekeeper_uid == 0)
    {
	get_unicos_connect_info(0);
    }
#endif

    peerlen = sizeof(peer);
    if (getpeername(0, (struct sockaddr *) &peer, &peerlen) == 0)
    {
        if (peer.sin_family == AF_INET)
            peernum = inet_ntoa(peer.sin_addr);
        else
            peernum = "";
    }

    fdout = fdopen(dup(0),"w"); /* establish an output stream */
    setbuf(fdout,NULL);

    notice3(LOG_INFO, "Got connection %s at %s", peernum, timestamp());

#ifdef TARGET_ARCH_CRAYT3E
         /* Need to lookup hostname -- provide for use in udb updates. */
          {
            struct sockaddr_in from;
            int fromlen;
            struct hostent *hp;
            char hostname[256];

            /* Get IP address of client. */
            fromlen = sizeof(from);
            memset(&from, 0, sizeof(from));
            if (getpeername(connection_fd, (struct sockaddr *)&from,
                            &fromlen) < 0)
            {
              notice2(LOG_ERR,"getpeername failed: %.100s", strerror(errno));
              strcpy(hostname, "UNKNOWN");
            }
            else
            {
              /* Map the IP address to a host name. */
              hp = gethostbyaddr((char *)&from.sin_addr, 
                                 sizeof(struct in_addr), from.sin_family);
              if (hp)
                strncpy(hostname, hp->h_name, sizeof(hostname));
              else
                strncpy(hostname, inet_ntoa(from.sin_addr), sizeof(hostname));
            }

            set_connection_hostname (hostname);
          }
#endif /* TARGET_ARCH_CRAYT3E */

    /* Do gss authentication here */

	/* 
	 * if globus nologin is set, error message and exit
	 */
	
	if (stat(genfilename(gatekeeperhome,"etc",globusnologin),
				&statbuf) == 0)
	{
		failure("Not accepting connections at this time");
	}

	if (stat(genfilename(gatekeeperhome,"var",globusnologin),
				&statbuf) == 0)
	{
		failure("Not accepting connections at this time");
	}

#ifdef GSS_AUTHENTICATION

    /* We will use the assist functions here since we 
     * don't need any special processing
     */
	
	/* 
	 * We will not accept limited proxies for authentication, as
	 * they may have been stolen. This enforces part of the 
	 * Globus security policy.
	 */

#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
	ret_flags = GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
#else
	ret_flags = 0;
#endif

    major_status = globus_gss_assist_accept_sec_context(&minor_status,
                       &context_handle,
                       credential_handle,
                       &client_name,
                       &ret_flags,
                       NULL,            /* don't need user_to_user */
                       &token_status,
                       globus_gss_assist_token_get_fd,
                       (void *)stdin,
                       globus_gss_assist_token_send_fd,
                       (void *)fdout);


    if (major_status != GSS_S_COMPLETE)
    {
        if (logging_usrlog) 
        {
            globus_gss_assist_display_status(usrlog_fp,
                "GSS authentication failure ",
                major_status,
                minor_status,
                token_status);
        }

        failure4("GSS failed Major:%8.8x Minor:%8.8x Token:%8.8x\n",
            major_status,minor_status,token_status);
    }

	/* now OK to send wrapped error message */
    ok_to_send_errmsg = 1;

    /* client_name is the globusID of the client, we need to check 
     * the globusmap file to see which local ID this is and if the
     * the user is authorized.
     */

    notice2(LOG_NOTICE, "Authenticated globus user: %s", client_name);

    /*
     * now do authorization  i.e. globus userid must be in the 
     * in the globusmap file. 
     */

    rc = globus_gss_assist_globusmap(client_name, &userid);

    if (rc != 0)
    {
        failure2("globus_gss_assist_globusmap() failed authorization."
                 " rc = %d", rc);
 
    }
    
#ifdef TARGET_ARCH_CRAYT3E
    if (gatekeeper_uid == 0)
    {
        get_udbent(userid);
	if (unicos_access_denied())
	{
	    failure2("UNICOS denied access to user %s.", userid);
	}
    }
#endif /* TARGET_ARCH_CRAYT3E */


    /* End of authentication */

#else /* GSS_AUTHENTICATION */

    /*
     * if the GSS_AUTHENTICATION is left as an option, then
     * running as root without authentication is considered
     * a failure. It may be set to notice for testing only
     */

    if ((service_uid = getuid()) == 0) 
        failure("ERROR: Root requires authentication");
    else
        notice(LOG_ERR, "WARNING: No authentication done");

#endif /* GSS_AUTHENTICATION */

    /* client will check version # sent here with it's own.  If they match
     * then the client will continue and send the service name
     * for the job manager or other service.
     */

    *tmp_version = GLOBUS_GRAM_PROTOCOL_VERSION;

	
    major_status = globus_gss_assist_wrap_send(&minor_status,
					context_handle,
					tmp_version,
					1,
					&token_status,
        			globus_gss_assist_token_send_fd,
					fdout,
					logging_usrlog?usrlog_fp:NULL);

   	if (major_status != GSS_S_COMPLETE)
   	{
		failure4("Sending Version:GSS failed Major:%8.8x Minor:%8.8x Token:%8.8x\n",
					major_status,minor_status,token_status);
	}
 	
	/* 
	 * Read from the client the service it would like to use
	 * For now this is a null terminated string which has been
	 * wrapped.
	 */

	major_status = globus_gss_assist_get_unwrap(&minor_status,
				 		context_handle,
						&service_name,
						&length,
						&token_status,
						globus_gss_assist_token_get_fd,
						stdin,
						logging_usrlog?usrlog_fp:NULL);

   	if (major_status != GSS_S_COMPLETE)
   	{
		failure4("Reading service GSS failed Major:%8.8x Minor:%8.8x Token:%8.8x\n",
					major_status,minor_status,token_status);
	}
 	
	/*DEE should do sanity check on length, and null term */
	if (length > 256 || service_name[length-1] != '\0')
	{
		failure("Service name malformed");
	}

	notice2(LOG_NOTICE,"Requested service:%s", service_name);

	if ((rc = globus_gatekeeper_util_globusxmap(
	            genfilename(gatekeeperhome,grid_services,NULL), 
				service_name, 
				&service_line)) != 0)
	{
		/*
		 *DEE For an easier transition, if -jmconf -jm are given and 
		 * this is the jobmanager, and the grid_services file was 
		 * not found, simulate the service and the args
		 * This should be removed at some time.
		 */

		if ((rc == -2) && jm_conf_path && job_manager_exe 
					&& !strncmp("jobmanager",service_name,10))
				
		{
			service_line = (char *)malloc(BUFSIZ);
			sprintf(service_line,
			"local_cred,stderr_log - %s jobmanager -conf ${JM_CONF_PATH}",
					job_manager_exe);
			notice(LOG_INFO,
			   "grid_services not found, using default for jobmanager");
		} /* end of the easier transition */
		else
		{
			failure3("Failed to find requested service: %s: %d", 
					service_name, rc);
		}
	}

	/* 
	 * Parse the command line.
	 */ 

	if (globus_gatekeeper_util_tokenize(service_line,
							service_args, 
							&num_service_args,
							" \t\n"))
	{
		notice(LOG_ERR, "ERROR:Tokenize failed for services");
		failure("ERROR: gatekeeper misconfigured");
	}

	if (num_service_args < SERVICE_ARG0_INDEX)
	{
		notice(LOG_ERR, "ERROR:To few service arguments");
		failure("ERROR: gatekeeper misconfigured");
	}


	/*
	 * Either run as the userid from the globus map,
	 *  or from grid_service as a selected user
	 */
	
	if (strcmp(service_args[SERVICE_USER_INDEX],"-"))
	{
		userid = service_args[SERVICE_USER_INDEX];
	}

    notice2(LOG_NOTICE, "Authorized as local user: %s", userid);

    if ((pw = getpwnam(userid)) == NULL)
    {
        failure2("getpwname() failed to find %s",userid);
    }

    service_uid = pw->pw_uid;
#   if defined(TARGET_ARCH_CRAYT3E)
    {
        service_gid = unicos_get_gid();
    }
#   else
    {
        service_gid = pw->pw_gid;
    }
#   endif

    notice2(LOG_NOTICE, "Authorized as local uid: %d", service_uid);
    notice2(LOG_NOTICE, "          and local gid: %d", service_gid);

    /* for gssapi_ssleay if we received delegated proxy certificate
     * they will be in a file in tmp pointed at by the 
     * X509_USER_DELEG_PROXY env variable. 
     * This will be owned by the current uid, we need this owned by
     * the user.
     * for other gss, this is a noop, since X509_USER_DELEG_PROXY 
     * should not be defined.
     */

    {
        char *proxyfile;
        if ((proxyfile = getenv("X509_USER_DELEG_PROXY")) != NULL)
        {
            chown(proxyfile,service_uid,service_gid);
        }
    }

	/* now check for options */
	if (globus_gatekeeper_util_tokenize(
					service_args[SERVICE_OPTIONS_INDEX],
					service_options,
					&num_service_options,
					","))
	{
		notice(LOG_ERR, "ERROR:Tokenize failed for services options");
		failure("ERROR: gatekeeper misconfigured");
	}
	
    for (i = 0; i < num_service_options; i++)
    {
        if (strcmp(service_options[i], "local_cred") == 0)
        {
            service_option_local_cred = 1;
		}
		else if (strcmp(service_options[i], "stderr_log") == 0)
		{
			service_option_stderr_log = 1;
		}
		else if (strcmp(service_options[i], "-") == 0)
		{
		}
		else
		{
			notice2(LOG_ERR, "ERROR:Invalid service option %s",
						service_options[i]);
			failure("ERROR: gatekeeper misconfigured");
		}
	}


	service_path = genfilename(libexecdir,
			service_args[SERVICE_PATH_INDEX],NULL);
	
	/*
	 * Replace the unused arg0 much like wrapper does
	 * generate a arg0 from the path later
	 * arg0 is really only there since inetd.conf has it. 
	 */

	service_args[SERVICE_ARG0_INDEX] = service_path; 

    if (stat(service_path, &statbuf) != 0)
    {
        notice2(LOG_ERR, "ERROR: Cannot stat globus service %s.",
                          service_path);
        failure("ERROR: gatekeeper misconfigured");
    }

    if (!(statbuf.st_mode & 0111))
    {
        notice2(LOG_ERR, "ERROR: Cannot execute globus service %s.",
                          service_path);
        failure("ERROR: gatekeeper misconfigured");
    }

    /*
     * Start building the arg list. If the -k flag is set, we want
     * to exec GRAM_K5_EXE first, passing it the path and
     * args for the service. 
     * If run from inetd, then the executables will be in libexecdir
     * otherwise they are in the current directory. 
     * we need absolute path, since we will do a chdir($HOME)
     */
	

    gram_k5_path = genfilename( gatekeeperhome, libexecdir, GRAM_K5_EXE);

    /* need k5 plus the number of args in the service_args + NULL */
	/* we will overlay the previous service arg to do this. */
	/* this should be the SERVICE_PATH_INDEX */

    args = &service_args[SERVICE_ARG0_INDEX];

    if (krb5flag && service_option_local_cred)
    {
		args--;
#       ifdef TARGET_ARCH_CRAYT3E
		/*DEE Not sure what is not complient, maybe some one could
		 * be more specific about this test
		 */
        {
            if(gatekeeper_uid == 0)
            {
                failure("Gatekeeper Kerberos code is not UNICOS compliant.");
            }
        }
#       endif
		if (stat(gram_k5_path, &statbuf) != 0)
	    	failure2("Cannot stat %s",gram_k5_path);
		if (!(statbuf.st_mode & 0111))
	    	failure2("Cannot execute %s", gram_k5_path);
		*args = gram_k5_path;
    }

    notice2(0, "executing %s", args[0]);

    /*
     * Create two pipes to connect us to the servic:
     *   One is used with close-on-exec to sense child creation
     *		and pass back any error messages from the child
     *		to the parent.
	 *DEE The above is obsolete, as gram_k5 gets execed next. 
     *   One is connected to the child's stdin, for passing a
     *		the message from the partent to the child.
     */

    if (pipe(p1) != 0)
    {
	failure2("Cannot create pipe: %s", sys_errlist[errno]);
    }
    close_on_exec_read_fd = p1[0];
    close_on_exec_write_fd = p1[1];

    if (fcntl(close_on_exec_write_fd, F_SETFD, 1) != 0)
    {
	failure2("fcntl F_SETFD failed: %s", sys_errlist[errno]);
    }

    grami_setenv("GLOBUS_ID",client_name,1);
    grami_setenv("GRID_ID",client_name,1);
	grami_setenv("GRID_AUTH_METHOD","TO_FILLED_IN_LATER",1);

    /*
     * Become the appropriate user
     */
    if (gatekeeper_uid == 0)
    {
	grami_setenv("USER",userid,1);
	grami_setenv("LOGNAME",userid,1);
	grami_setenv("LOGIN",userid,1);
	grami_setenv("HOME",pw->pw_dir,1);
	grami_setenv("SHELL",pw->pw_shell,1);
	/* 
	 * Could set path, and other variables as well 
	 * Unset many of the gssapi set env variables. 
	 * If not present won't hurt to unset. 
	 * Leave the X509_CERT_DIR of trusted certs
	 * for the user to use. 
	 */
	grami_unsetenv("GLOBUSMAP"); /* unset it */
	grami_unsetenv("GLOBUSCERTDIR"); /* unset it */
	grami_unsetenv("GLOBUSKEYDIR"); /* unset it */
	grami_unsetenv("X509_USER_KEY"); /* unset it */
	grami_unsetenv("X509_USER_CERT"); /* unset it */
	grami_unsetenv("X509_USER_PROXY"); /* unset it */
    }

	/* for tranition, if gatekeeper has the path, set it
	 * for the grid_services to use 
	 */
	if (jm_conf_path && !strncmp(service_name,"jobmanager",10))
	{
		grami_setenv("JM_CONF_PATH",jm_conf_path,1);
	} 
    /* 
     * If the gssapi_ssleay did delegation, promote the
     * delegated proxy file to the user proxy file
     */
    if ((x509_delegate = getenv("X509_USER_DELEG_PROXY")))
    {
        grami_setenv("X509_USER_PROXY",strdup(x509_delegate),1);
        grami_unsetenv("X509_USER_DELEG_PROXY");
    }

	/*
	 * finally do environment variable substitution 
	 * on the args
	 */
	
	for (argi = &service_args[SERVICE_ARG1_INDEX]; *argi; argi++)
	{
		if(globus_gatekeeper_util_envsub(argi))
		{
			notice(LOG_ERR,"ERROR: Failed env substitution in services");
			failure("ERROR: gatekeeper misconfigured");
		}
	}
			

    if (gatekeeper_uid == 0)
    {

		/* do all the work to run as user, unless gram_k5 will do it for us */

		if (!(krb5flag && service_option_local_cred))
		{
			char * errmsg = NULL;
			int rc;
			if ((rc = globus_gatekeeper_util_trans_to_user(pw, userid, &errmsg)) != 0)
			{
				failure3("trans_to_user: %d: %s", rc, errmsg);
			}
    	}
	}

	/* 
	 * export the security context which will destroy it. 
	 * This will also destroy the ability to wrap any error
	 * messages, so we do this very late. 
	 * First we get an temp file, open it, and delete it. 
	 */

	context_tmpfile = tmpfile();
	if (context_tmpfile) 
	{
		setbuf(context_tmpfile,NULL);
		fcntl(fileno(context_tmpfile), F_SETFD, 0);
		sprintf(buf, "%d", fileno(context_tmpfile));
		grami_setenv("GRID_SECURITY_CONTEXT_FD", buf, 1);
		notice2(0,"GRID_SECURITY_CONTEXT_FD=%s",buf)
	}
	else
	{
		failure("Unable to create context tmpfile");
	}

	major_status = gss_export_sec_context(&minor_status,
								&context_handle, 
								&context_token);

	if (major_status != GSS_S_COMPLETE) 
	{
        globus_gss_assist_display_status(stderr,
                              "GSS failed exporting context: ",
                              major_status,
                              minor_status,
                              0);
		failure("GSS Failed exporting context");
	}
	
  	int_buf[0] = (unsigned char)(((context_token.length)>>24)&0xff);
    int_buf[1] = (unsigned char)(((context_token.length)>>16)&0xff);
    int_buf[2] = (unsigned char)(((context_token.length)>> 8)&0xff);
    int_buf[3] = (unsigned char)(((context_token.length)    )&0xff);

	if (fwrite(int_buf,4,1,context_tmpfile) != 1)
	{
		failure("Failure writing context length");
	}
	if (fwrite(context_token.value,context_token.length,1,
					context_tmpfile) != 1)
	{
		 failure("Failure writing context token");
	}

	gss_release_buffer(&minor_status,&context_token);

	/* reposition so service can read */

	lseek(fileno(context_tmpfile), 0, SEEK_SET);

	chdir(pw->pw_dir);

    pid = fork();
    if (pid < 0)
    {
		failure2("fork failed: %s", sys_errlist[errno]);
    }

    if (pid == 0)
    {
		close(close_on_exec_read_fd);
	
		/* stderr is still set to logfile, user's stderr or /dev/null */

		/*
	 	 * convert arg[0] to path and simple name for exec
		 */

		execp = args[0];
		argnp = strrchr(args[0], '/'); 
	
		if (argnp)
	    	argnp++;
		else
			argnp = execp;
		args[0] = argnp;
	
		/*
		 * If grid_service wanted stderr pointing at our log 
		 * skip this part
		 * otherwise point it at the socket
		 */

		if (service_option_stderr_log == 0)
		{
			fclose(stderr);
			close(2);
			dup2(0,2);
			*stderr = *fdopen(2,"w");
    		(void) setbuf(stderr,NULL);
		}

		if (execv(execp, args) != 0)
		{
			sprintf(tmpbuf, "Exec failed: %s\n", sys_errlist[errno]);
	    	write(close_on_exec_write_fd, tmpbuf, strlen(tmpbuf));
	    	exit(0);
		}
    }

    close(close_on_exec_write_fd);
    
    /*
     * If the read_fd is closed without any data, then the
     * job manager was executed ok by the child process, due
     * to the close-on-exec flag being set on write_fd.
     *
     * If there is data on read_fd, then it is an error message
     * from the child process.
     */
    if ((n = read(close_on_exec_read_fd, buf, sizeof(buf))) > 0)
    {
	buf[n] = '\0';
	s = index(buf, '\n');
	if (s)
	    *s = 0;
	failure2("child failed: %s", buf);
    }
    if (n < 0)
    {
	failure("child failed: error reading child fd");
    }
    close(close_on_exec_read_fd);

    notice2(0, "Child %d started", pid);

    ok_to_send_errmsg = 0;
} /* doit() */  

/******************************************************************************
Function:    net_accept()
Description: Accept a connection on socket skt and return fd of new connection. 
Parameters:
Returns:
******************************************************************************/
static int 
net_accept(int skt)
{
    netlen_t           fromlen;
    int                skt2;
    int                gotit;
    struct sockaddr_in from;

    fromlen = sizeof(from);
    gotit = 0;
    while (!gotit)
    {
	skt2 = accept(skt, (struct sockaddr *) &from, &fromlen);
	if (skt2 == -1)
	{
	    if (errno == EINTR)
		continue;
	    else
		error_check(skt2, "net_accept accept");
	}
	else
	    gotit = 1;
    }

    return(skt2);
}


/******************************************************************************
Function:       net_setup_listener()
Description:    
Parameters:
Returns:
******************************************************************************/
static void 
net_setup_listener(int backlog,
                   int * port,
                   int * skt)
{
    netlen_t        sinlen;
    struct sockaddr_in sin;

    *skt = socket(AF_INET, SOCK_STREAM, 0);
    error_check(*skt,"net_setup_anon_listener socket");

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(*port);

    sinlen = sizeof(sin);

    error_check(bind(*skt,(struct sockaddr *) &sin,sizeof(sin)),
		   "net_setup_anon_listener bind");


    error_check(listen(*skt, backlog), "net_setup_anon_listener listen");

    getsockname(*skt, (struct sockaddr *) &sin, &sinlen);
    *port = ntohs(sin.sin_port);
}

/******************************************************************************
Function:       logging_startup()
Description:
Parameters:
Returns:
******************************************************************************/
static int
logging_startup(void)
{
    if ((strncmp(logfile, "logoff", 6) == 0) ||
        (strncmp(logfile, "LOGOFF", 6) == 0))
    {
        /* no logging will be done, even syslog */
        fprintf(stderr, "No logging will be done, even syslog.\n");
        logging_syslog = 0;
        logging_usrlog = 0;
    }
    else
    {
        /*
         * By default open syslogfile.
         * All messages will have GRAM gatekeeper and include the PID.
         * The messages will be treated like any other system daemon.
         */
        logging_syslog = 1;
        openlog("GRAM gatekeeper", LOG_PID, LOG_DAEMON);

        if (strlen(logfile) > 0) 
        {
	    char * logfilename;
            /*
             * Open the user specified logfile
             */
			
	    logfilename = genfilename(gatekeeperhome, logfile, NULL);
            if ((usrlog_fp = fopen(logfilename, "a")) == NULL)
            {
                fprintf(stderr, "Cannot open logfile %s: %s\n",
                        logfilename, sys_errlist[errno]);
                syslog(LOG_ERR, "Cannot open logfile %s\n", logfilename);

                return(1);
            }
	    free(logfilename);
            logging_usrlog = 1;
        }
    }
    return(0);
} /* logging_startup() */

/******************************************************************************
Function:       logging_phase2()
Description:
Parameters:
Returns:
******************************************************************************/
static int
logging_phase2(void)
{

    if (logging_usrlog) 
    {
	/*
	 * set stderr to the log file, to catch all fprintf(stderr,...
	 * and catch some from gram_k5, and job_manager
	 * But if testing gatekeeper, write to stderr instead. 
	 */

	if (!gatekeeper_test) {
		(void) fflush(usrlog_fp);
		(void) dup2(fileno(usrlog_fp),2);
		(void) fclose(usrlog_fp);
	}
	usrlog_fp = stderr;

	/*
	 * Set output to non-buffered mode
	 */
	setbuf(stderr, NULL);
    }
    return(0);
} /* logging_phase2() */

/******************************************************************************
Function:       failure()
Description:    
Parameters:
Returns:
******************************************************************************/
static void 
failure(char * s)
{

	OM_uint32 minor_status = 0;
	int		   token_status = 0;

    fprintf(stderr,"Failure: %s\n", s);
    if (logging_syslog)
    {
        syslog(LOG_ERR, "%s\n", s);
    }
    if (logging_usrlog)
    {
        fprintf(usrlog_fp, "Failure: %s\n", s);
    }
    /* 
     * attempt to send back to the gram_client one final 
     * error message before quiting. 
     */
    if (ok_to_send_errmsg)
    {
		/* don't care about errors here */
    	globus_gss_assist_wrap_send(&minor_status,
					context_handle,
					s,
					strlen(s) + 1,
					&token_status,
        			globus_gss_assist_token_send_fd,
					fdout,
					logging_usrlog?usrlog_fp:NULL);
    }
    if (gatekeeper_test)
    {
        fprintf(stderr,"Gatekeeper test complete : Failure!\n");
    }
    exit(1);
} /* failure() */

/******************************************************************************
Function:       notice()
Description:    
Parameters: prty is the syslog priority, but if = 0, then dont syslog. 
Returns:
******************************************************************************/
static void 
notice(int prty, char * s)
{
    if (logging_syslog && prty)
    {
        syslog(prty, s);
    }
    if (logging_usrlog)
    {
        fprintf(usrlog_fp, "Notice: %d: %s\n", prty, s);
    }
} /* notice() */

#if defined(TARGET_ARCH_CRAYT3E)
/* Make callable entries to failure() and notice() */
void gatekeeper_failure(char * s)
{
  failure(s);
}

void gatekeeper_notice(int prty, char * s)
{
  notice(prty, s);
}
#endif


/******************************************************************************
Function:       error_check()
Description:    
Parameters:
Returns:
******************************************************************************/
static void 
error_check(int val,
            char * str)
{
    if (val < 0)
    {
        failure3("error check %s: %s\n", str, sys_errlist[errno]);
/*
	fprintf(usrlog_fp, "%s: %s\n",
		str,
		sys_errlist[errno]);
	exit(1);
*/
    }
} /* error_check() */

/******************************************************************************
Function:       timestamp()
Description:    
Parameters:
Returns:
******************************************************************************/
static char *
timestamp(void)
{
    time_t clock;
    struct tm *tmp;

    time(&clock);
    tmp = localtime(&clock);
    return asctime(tmp);
} /* timestamp() */
