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
#include "globus_gatekeeper_config.h"

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
#include <sys/select.h>
#include <syslog.h>
#include <netdb.h>
#include <netinet/in.h>

#if defined (HAVE_NETINET_TCP_H)
#   include <netinet/tcp.h>
#endif

#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/wait.h>

#ifdef HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "globus_gss_assist.h"
#include "gssapi.h"

#ifndef _HAVE_GSI_EXTENDED_GSSAPI
#include "globus_gss_ext_compat.h"
#endif

#if defined(TARGET_ARCH_SOLARIS)
#include <termios.h>
#endif

#if defined(TARGET_ARCH_AIX)
#define netlen_t size_t
#else
#define netlen_t int
#endif

#include <arpa/inet.h> /* for inet_ntoa() */

#if HAVE_STRINGS_H
#include <strings.h>
#endif

#if HAVE_STRING_H
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

#ifndef HAVE_SETENV
extern int setenv();
#endif

#ifndef HAVE_UNSETENV
extern void unsetenv();
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
static void doit(void);
static int logging_startup(void);
static int logging_phase2(void);
static void failure(short failure_type, char *s);
static void notice(int, char *s);
static int net_accept(int socket);
static void net_setup_listener(int backlog, int *port, int *socket);
static void error_check(int val, char *string);
static char *timestamp(void);
static void null_terminate_string(char ** s, size_t len);

static char * genfilename(char * prefix, char * path, char * sufix);

static int get_content_length(char * http_message, char * http_body);
/*
 * GSSAPI - credential handle for this process
 */
static gss_cred_id_t credential_handle = GSS_C_NO_CREDENTIAL;
static gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
static gss_ctx_id_t  context_handle    = GSS_C_NO_CONTEXT;

/*
 * local definition of restrictions oid
 *
 */

extern
const gss_OID_desc * const gss_restrictions_extension;

/******************************************************************************
                       Define module specific variables
******************************************************************************/
#define MAXARGS 256
#define DEFAULT_PORT 754
#define MAX_MESSAGE_LENGTH 100000
#ifndef GRAM_K5_EXE
#       define GRAM_K5_EXE "globus-k5"
#endif
#ifndef GLOBUS_LIBEXECDIR
#  define GLOBUS_LIBEXECDIR "libexec"
#endif
#ifndef GLOBUS_GATEKEEPER_HOME
#       define GLOBUS_GATEKEEPER_HOME "/etc"
#endif
#ifndef LOGFILE
#define LOGFILE ""
#endif

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif

#define FAILED_AUTHORIZATION        1
#define FAILED_SERVICELOOKUP        2
#define FAILED_SERVER               3
#define FAILED_NOLOGIN              4
#define FAILED_AUTHENTICATION       5
#define FAILED_PING                 6

#undef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))

static char     tmpbuf[1024];
#define notice2(i,a,b) {sprintf(tmpbuf, a,b); notice(i,tmpbuf);}
#define notice3(i,a,b,c) {sprintf(tmpbuf, a,b,c); notice(i,tmpbuf);}
#define notice4(i,a,b,c,d) {sprintf(tmpbuf, a,b,c,d); notice(i,tmpbuf);}
#define notice5(i,a,b,c,d,e) {sprintf(tmpbuf, a,b,c,d,e); notice(i,tmpbuf);}
#define failure2(t,a,b) {sprintf(tmpbuf, a,b); failure(t,tmpbuf);}
#define failure3(t,a,b,c) {sprintf(tmpbuf, a,b,c); failure(t,tmpbuf);}
#define failure4(t,a,b,c,d) {sprintf(tmpbuf, a,b,c,d); failure(t,tmpbuf);}

#define FORK_AND_EXIT	1
#define FORK_AND_WAIT	2
#define DONT_FORK	3
static int	launch_method = FORK_AND_EXIT;

extern int      errno;

static int      connection_fd;
static int      listener_fd = -1;

static FILE *   usrlog_fp;
static char *   logfile = LOGFILE;
static char *   acctfile;
static volatile int	logrotate;
static pid_t    gatekeeper_pid;
static unsigned reqnr;
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
static char *   job_manager_exe = "globus-job-manager";
static char *   jm_conf_path = NULL;
static char *   libexecdir = NULL;
static char *   libexecdirr = GLOBUS_LIBEXECDIR;
static char *   service_name = NULL;
static char *   grid_services = "etc/grid-services";
static char *   gridmap = "etc/gridmap";
static char *   globuskmap = "etc/globuskmap";
static char *   globuspwd = NULL;
static char *   globuscertdir = "cert";
static char *   globuskeydir = "key";
static char *   globusnologin ="globus-nologin";
static char *   x509_cert_dir = NULL;
static char *   x509_cert_file = NULL;
static char *   x509_user_proxy = NULL;
static char *   x509_user_cert = NULL;
static char *   x509_user_key = NULL;
static char *   desired_name_char = NULL;
static int      ok_to_send_errmsg = 0;
static FILE *   fdout;
static int      got_ping_request = 0;

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
        major_status = gss_display_name(&minor_status,
                                        server_name,
                                        server_buffer,
                                        NULL);
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
Function:       terminate()
Description:    Handle a  SIGTERM, and specificly close the listener_fd
                                This should avoid problems when the gatekeeper
                                is shutdown. 
Parameters:
Returns:
******************************************************************************/
void 
terminate(int s)
{
    notice2(LOG_NOTICE,"Gatekeeper received signal:%d",s);
    if (listener_fd > 0)
    {

#if 0
/* may need to add code for unicos MLS to get socket closed */
#     if defined(TARGET_ARCH_CRAYT3E)
        {
            if(gatekeeper_uid == 0)
            {
                close_unicos_socket(listener_fd);
            }
        }
#     endif
#endif

        if (close(listener_fd) == -1)
        {
            notice3(LOG_ERR, "Shutdown of %d: %.100s",
                    listener_fd, strerror(errno));
                                        
        }
        listener_fd = -1;
    }
    failure2(FAILED_SERVER,"Gatekeeper shutdown on signal:%d",s)
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

    if (launch_method == DONT_FORK) return;

#   ifdef HAS_WAIT3
    while ((pid = wait3(&status, WNOHANG, NULL)) > 0) ;
#   else
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) ;
#   endif
} /* reaper() */

/******************************************************************************
Function:       rotatelog()
Description:    Handle a SIGUSR1: set a flag indicating the logfile should be
                                  rotated by the main loop.
Parameters:
Returns:
******************************************************************************/
static void
rotatelog(int s)
{
    logrotate = 1;
}

/******************************************************************************
Function:       new_acct_file()
Description:    Rotate old and open new job accounting file.
Parameters:
Returns:
******************************************************************************/
static void
new_acct_file(void)
{
    static int acct_fd = -1;

    if (acct_fd >= 0)
    {
	if (strcmp(acctfile, logfile) != 0)
	{
	    static int seqnr;
            char *acctpath = genfilename(gatekeeperhome, acctfile, NULL);
	    char *oldpath = malloc(strlen(acctpath) + 64);
	    time_t clock = time((time_t *) 0);
	    struct tm *tmp = localtime(&clock);
	    int ret;

	    sprintf(oldpath, "%s.%04d%02d%02d%02d%02d%02d.%d", acctpath,
		tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
		tmp->tm_hour, tmp->tm_min, tmp->tm_sec, seqnr++);

	    if ((ret = rename(acctpath, oldpath)) != 0)
	    {
		notice4(LOG_ERR, "ERROR: cannot rename %s to %s: %s",
		    acctpath, oldpath, strerror(errno));
	    }
	    else
	    {
		notice2(0, "renamed accounting file %s", oldpath);
	    }

	    free(acctpath);
	    free(oldpath);

	    if (ret) {
		return;
	    }
	}

	close(acct_fd);
	acct_fd = -1;
    }

    if (!acctfile)
    {
	acctfile = logfile;
    }

    if (acctfile && *acctfile)
    {
	const char *acct_fd_var = "GATEKEEPER_ACCT_FD";
	char *acctpath = genfilename(gatekeeperhome, acctfile, NULL);

	acct_fd = open(acctpath, O_WRONLY | O_APPEND | O_CREAT, 0644);

	if (acct_fd < 0)
	{
	    notice3(LOG_ERR, "ERROR: cannot open accounting file '%s': %s",
		acctpath, strerror(errno));

	    unsetenv(acct_fd_var);
	}
	else
	{
	    /*
	     * Now inform JM via environment.
	     */

	    char buf[32];

	    sprintf(buf, "%d", acct_fd);

	    setenv(acct_fd_var, buf, 1);

	    notice4(0, "%s=%s (%s)", acct_fd_var, buf, acctpath);
	}

	free(acctpath);
    }
}

/******************************************************************************
Function:       genfilename()
Description:    generate an absolute file name given a starting prefix,
                a relative or absolute path, and a sufix
                Only use prefix if path is relative.
Parameters:
Returns:                a pointer to a string which could be freeded.
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
    struct sockaddr_in name;
    struct stat         statbuf;

    /* GSSAPI status vaiables */
    OM_uint32 major_status = 0;
    OM_uint32 minor_status = 0;

    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }

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

    gatekeeper_pid = getpid();

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
#if defined(TARGET_ARCH_LINUX) || defined(TARGET_ARCH_SOLARIS)
        /*
         * There is a memory corruption bug in the getcwd in
         * glibc-2.1.1 and earlier
         *
         * Solaris 2.5.1 does not have a correct implementation
         * of getcwd either.
         *
         */
        {
            char tmppath[PATH_MAX];

            if(getwd(tmppath))
            {
                gatekeeperhome = strdup(tmppath);
            }
        }
#else
        {
            char *tmppath = NULL;
            int size = 1;
            while ( (tmppath = getcwd (NULL, size)) == NULL )
            {
                size++;
            }
            gatekeeperhome = tmppath;
        }
#endif
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
     * But first see if the first parameter is a -c or -conf filename
     * which has the real parameter list. This is needed
     * since the parameters are getting long, and inetd/wrapper
     * may have a problem.  Will assume there are at most 52 
     * args, in a buffer of BUFSIZ at the most. 
     */

    /* But before that, check if there is a -test option
     * after the -c or -conf file. This will test the gatekeeper
     * -test can also be in the options file 
     * this will run in forground, and not inetd
     */

    if (argc == 4 && !strcmp(argv[3],"-test"))
    {
        gatekeeper_test++;
        argc--;
    }

    if ( argc == 3 &&
         (!strcmp(argv[1],"-c") ||
          !strcmp(argv[1],"-conf"))
        )
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
            failure(FAILED_SERVER, "Unable to read extra parameters");
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
        if ((strcmp(argv[i], "-d") == 0) ||
            (strcmp(argv[i], "-debug") == 0 ))
        {
            debug = 1;
            foreground = 1;   /* Run in the forground */
        }
        else if (strcmp(argv[i], "-inetd") == 0)
        {
            if(!run_from_inetd)
            {
                if(!gatekeeper_test)
                {
                    fprintf(stderr, "Gatekeeper running as daemon, ignoring -inetd!\n");
                }
            }
            else
            {
                run_from_inetd = 1;
                foreground = 0;
            }
            
        }
        else if (((strcmp(argv[i], "-p") == 0) ||
                  (strcmp(argv[i], "-port") == 0))
                 && (i + 1 < argc))
        {
            daemon_port = atoi(argv[i+1]);
            i++;
        }
        else if (((strcmp(argv[i], "-l") == 0) ||
                  (strcmp(argv[i], "-logfile") == 0))
                 && (i + 1 < argc))
        {
            logfile =  argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-acctfile") == 0)
                 && (i + 1 < argc))
        {
            acctfile = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-home") == 0)
                 && (i + 1 < argc))
        {
            /* Also known as the ${deploy_prefix} */
            gatekeeperhome = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-e") == 0)
                 && (i + 1 < argc))
        {
            libexecdirr = argv[i+1];
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
            setenv("GLOBUSID", argv[i+1],1);
            i++;
        }
        else if ((strcmp(argv[i], "-gridmap") == 0)
                 && (i + 1 < argc))
        {
            gridmap = argv[i+1];
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
        
        else if ((strcmp(argv[i], "-desired_name") == 0)
                 && (i + 1 < argc))
        {
            desired_name_char = argv[i+1];
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
        else if ((strcmp(argv[i], "-f") == 0) ||
                 (strcmp(argv[i], "-foreground") == 0))
        {
            if(!run_from_inetd)
            {
                /* make the daemon run in the Foreground */
                
                foreground = 1;
                run_from_inetd = 0;
            }
        }
	else if ((strcmp(argv[i], "-launch_method") == 0)
		 && (i + 1 < argc))
	{
	    if(!run_from_inetd)
	    {
		fprintf(stderr, "Gatekeeper running as daemon, "
			"ignoring -launch_method!\n");
	    }
	    else if (strcmp(argv[i + 1], "fork_and_exit") == 0)
	    {
		launch_method = FORK_AND_EXIT;
	    }
	    else if (strcmp(argv[i + 1], "fork_and_wait") == 0)
	    {
		launch_method = FORK_AND_WAIT;
	    }
	    else if (strcmp(argv[i + 1], "dont_fork") == 0)
	    {
		launch_method = DONT_FORK;
	    }
	    else
	    {
		fprintf(stderr, "Bad -launch_method argument %s\n",
			argv[i + 1]);
	    }
	    i++;
	}
        else
        {

            fprintf(stderr, "Unknown argument %s\n", argv[i]);
            fprintf(stderr, "Usage: %s %s %s %s %s %s %s %s %s %s\n ",
                    argv[0], 
                    "{-conf parmfile [-test]} | {[-d[ebug] [-inetd | -f] [-p[ort] port] ",
                    "[-home path] [-l[ogfile] logfile] [-acctfile acctfile] [-e path] ",
                    "[-launch_method fork_and_exit|fork_and_wait|dont_fork] "
                    "[-grid_services file] ",
                    "[-globusid globusid] [-gridmap file] [-globuspwd file]",
                    "[-x509_cert_dir path] [-x509_cert_file file]",
                    "[-x509_user_cert file] [-x509_user_key file]",
                    "[-x509_user_proxy file]",
                    "[-k] [-globuskmap file]",
                    "[-test]}"
                );
            exit(1);
        }
    }

    /* 
     * define libexec relative to home
     * if needed
     */

    libexecdir = genfilename(gatekeeperhome, libexecdirr, NULL);

    /*
     * Dont use default env proxy cert for gatekeeper if run as root
     * this might get left over. You can still use -x509_user_proxy
     */

    if (gatekeeper_uid == 0)
    {
        unsetenv("X509_USER_PROXY");
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
        fprintf(stderr,"Home directory           : %s\n", 
                (gatekeeperhome) ? gatekeeperhome : "(not defined)");
        fprintf(stderr,"Libexec directory        : %s\n",
                (libexecdir) ? libexecdir : "(not defined)");

        run_from_inetd = 0;
        foreground = 1;
    }

    if (gatekeeperhome)
    {
        setenv("GLOBUS_LOCATION",gatekeeperhome,1);
    }
        
    setenv("GRIDMAP", genfilename(gatekeeperhome,gridmap,NULL),1);
    if (globuspwd) 
    {
        setenv("GLOBUSPWD", genfilename(gatekeeperhome,globuspwd,NULL),1);
    }

    if (x509_cert_dir)
    {
        setenv("X509_CERT_DIR",
               genfilename(gatekeeperhome,x509_cert_dir,NULL),
               1);
    }
    if (x509_cert_file)
    {
        setenv("X509_CERT_FILE",
               genfilename(gatekeeperhome,x509_cert_file,NULL),
               1);
    }
    if (x509_user_proxy)
    {
        setenv("X509_USER_PROXY",
               genfilename(gatekeeperhome,x509_user_proxy,NULL),
               1);
    }

    if (x509_user_cert)
    {
        setenv("X509_USER_CERT",
               genfilename(gatekeeperhome,x509_user_cert,NULL),
               1);
    }
    if (x509_user_key)
    {
        setenv("X509_USER_KEY", 
               genfilename(gatekeeperhome,x509_user_key,NULL),
               1);
    }
    if (krb5flag) 
    {
        setenv("GLOBUSKMAP",
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
        failure(FAILED_SERVER, "Logging startup failure");
    }

    notice4(LOG_INFO, "%s pid=%d starting at %s",
            argv[0], getpid(), timestamp());

    /*
     * Setup SIGCHLD signal handler to reap processes that we create
     */
    {
        struct sigaction act;
        act.sa_handler = reaper;
        sigemptyset(&act.sa_mask);
        sigaddset(&act.sa_mask, SIGCHLD);
        act.sa_flags = 0;
        sigaction(SIGCHLD, &act, NULL);
        if (!run_from_inetd)
        {
            act.sa_handler = terminate;
            sigemptyset(&act.sa_mask);
            sigaddset(&act.sa_mask, SIGTERM);
            act.sa_flags = 0;
            sigaction(SIGTERM, &act, NULL);
        }
	act.sa_handler = rotatelog;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGUSR1);
	act.sa_flags = 0;
	sigaction(SIGUSR1, &act, NULL);
    }

    if (run_from_inetd)
    {
        logging_phase2();
        dup2(2,1); /* point stdout at log as well */
    }

    /*
     * Always make stdout unbuffered: otherwise the fclose(stdout)
     * in doit() will flush any buffered output again and again!
     */
    setbuf(stdout,NULL);

    /* Get the GSS credential for the accepter
     * If not run_from_inetd we can prompt here.
     * If we are running as a deamon, and should not
     * have any prompts
     */
    major_status = globus_gss_assist_acquire_cred_ext(&minor_status,
                                                      desired_name_char,
                                                      GSS_C_INDEFINITE,
                                                      GSS_C_NO_OID_SET,
                                                      GSS_C_ACCEPT,
                                                      &credential_handle,
                                                      NULL,
                                                      NULL);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(stderr,
                                         "GSS failed getting server credentials: ",
                                         major_status,
                                         minor_status,
                                         0);

        failure(FAILED_SERVER, "GSS failed to get server credentials\n");
    }

    if (gatekeeper_test) 
    {
        fprintf(stderr,"Gatekeeper subject name  : \"%s\"\n",
                get_globusid());
        fprintf(stderr,"Gatekeeper test complete : Success!\n\n");
        fprintf(stderr,"Gatekeeper shutting down!\n");
        exit(0);
    }

    {
        char hostname[255];
        char *globusid;
        struct hostent *hp;
        char *fqdn;
        char * contact_string;
      
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


        if (!run_from_inetd)
        {
            logging_phase2(); /* now set stderr to logfile after gss prompts */

            net_setup_listener(2, &daemon_port, &listener_fd);
          
#         if defined(TARGET_ARCH_CRAYT3E)
            {
                if(gatekeeper_uid == 0)
                {
                    set_unicos_sockopts(listener_fd);
                }
            }
#         endif
        }
      
        /* ajr,vs --changed printf to sprintf, and added setenv
         * This is considered to be a temporary change */
        if ((contact_string = (char *)malloc(strlen(fqdn) 
                                             + strlen(globusid) + 40))) 
        {
        
            sprintf(contact_string, "%s:%d:%s",
                    fqdn, daemon_port, globusid);
            if (!run_from_inetd)
                printf("GRAM contact: %s\n", contact_string);
            setenv("GLOBUS_GATEKEEPER_CONTACT_STRING",
                   contact_string,
                   1);
     
            if (!run_from_inetd && strlen(contact_string)<sizeof(tmpbuf)-15)
                notice2(LOG_INFO, "GRAM contact: %s\n", contact_string);

            free(contact_string);
        }
        free(globusid);
    }

    new_acct_file();

    if (run_from_inetd)
    {
        (void) setsid();
        doit();
    }
    else
    {
        if (!foreground)
        {
            /*
             * Fork off a child, terminate the parent, and detach
             * the child from the tty.
             */
            if (fork())
                exit(0);

	    gatekeeper_pid = getpid();

            if (!logging_usrlog)
            {
                (void) close(2); /* close stderr as well */
		(void) open("/dev/null",O_WRONLY);
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

#               if HAVE_SETSID
                (void) setsid();
#               endif
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
	    reqnr++;

            pid = fork();

            if (pid < 0)
            {
                failure2(FAILED_SERVER, "Fork failed: %s\n", strerror(errno));
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
                listener_fd = -1;

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

    rc = globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        exit(1);
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
    int                                 p1[2];
    int                                 pid = 0;
    int                                 n;
    int                                 i;
    int                                 service_uid;
    int                                 service_gid;
    int                                 close_on_exec_read_fd;
    int                                 close_on_exec_write_fd;
    char                                buf[1024];
    char *                              s;
    char **                             args;
    char *                              argnp;
    char *                              execp;
    char **                             argi;
    int                                 num_service_args = SERVICE_ARGS_MAX;
    char *                              service_args[SERVICE_ARGS_MAX];
    int                                 num_service_options =
        SERVICE_OPTIONS_MAX;
    char *                              service_options[SERVICE_OPTIONS_MAX];
    int                                 service_option_local_cred = 0;
    int                                 service_option_stderr_log = 0;
    int                                 service_option_accept_limited = 0;
    unsigned char                       int_buf[4];
    struct stat                         statbuf;
    char *                              service_line = NULL;
    char *                              service_path;
    char *                              gram_k5_path; 
    struct sockaddr_in                  peer;
    netlen_t                            peerlen;
    char *                              peernum;
    char *                              x509_delegate;
    size_t                              length;
    char *                              http_message;
    size_t                              http_length;
    char *                              http_body;
    FILE *                              http_body_file;
    /* GSSAPI assist variables */
    OM_uint32                           major_status = 0;
    OM_uint32                           minor_status = 0;
    int                                 token_status = 0;
    OM_uint32                           ret_flags = 0;
    gss_buffer_desc                     context_token = GSS_C_EMPTY_BUFFER;
#if 0
    gss_buffer_desc                     option_token = GSS_C_EMPTY_BUFFER;
    gss_OID_set_desc                    extension_oids;
#endif
    FILE *                              context_tmpfile = NULL;

    /* Authorization variables */
    int                                 rc;
    globus_result_t                     result;
    char *                              client_name;
    char                                identity_buffer[256];
    char *                              userid = NULL;
    struct passwd *                     pw;
    char *                              mapping = NULL;


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
        failure(FAILED_NOLOGIN, 
                "Not accepting connections at this time");
    }

    if (stat(genfilename(gatekeeperhome,"var",globusnologin),
             &statbuf) == 0)
    {
        failure(FAILED_NOLOGIN, 
                "Not accepting connections at this time");
    }

    /* We will use the assist functions here since we 
     * don't need any special processing
     */

#if 0
    extension_oids.elements = (gss_OID) gss_restrictions_extension;
    extension_oids.count = 1;
    
    option_token.value = (void *) &extension_oids;

    /* don't use this code until we require CAS for the gatekeeper */
    major_status = gss_set_sec_context_option(
        &minor_status,
        &context_handle,
        (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS,
        &option_token);

    if (major_status != GSS_S_COMPLETE && major_status != GSS_S_EXT_COMPAT)
    {
        if (logging_usrlog) 
        {
            globus_gss_assist_display_status(usrlog_fp,
                                             "GSS authentication failure ",
                                             major_status,
                                             minor_status,
                                             token_status);
        }

        failure4(FAILED_AUTHENTICATION,
                 "GSS failed Major:%8.8x Minor:%8.8x Token:%8.8x\n",
                 major_status,minor_status,token_status);
    }
#endif
    
    /* 
     * We will not accept limited proxies for authentication, as
     * they may have been stolen. This enforces part of the 
     * Globus security policy.
     * This check will be made later, after the service is
     * is determined. This is done to allow limited proxies
     * to be used for some services, like GARA
     */
    
    major_status = globus_gss_assist_accept_sec_context(
        &minor_status,
        &context_handle,
        credential_handle,
        &client_name,
        &ret_flags,
        NULL,            /* don't need user_to_user */
        &token_status,
        &delegated_cred_handle,
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

        failure4(FAILED_AUTHENTICATION,
                 "GSS failed Major:%8.8x Minor:%8.8x Token:%8.8x\n",
                 major_status,minor_status,token_status);
    }
    
    /* now OK to send wrapped error message */
    ok_to_send_errmsg = 1;

    /* client_name is the globusID of the client, we need to check 
     * the gridmap file to see which local ID this is and if the
     * the user is authorized.
     */

    notice2(LOG_NOTICE, "Authenticated globus user: %s", client_name);

    /* End of authentication */

    /* 
     * Read from the client the service it would like to use
     * For now this is a null terminated string which has been
     * wrapped.
     */

    /*
     * read HTTP message, extract service name from the header.
     */
    major_status = globus_gss_assist_get_unwrap(&minor_status,
                                                context_handle,
                                                &http_message,
                                                &http_length,
                                                &token_status,
                                                globus_gss_assist_token_get_fd,
                                                stdin,
                                                logging_usrlog?usrlog_fp:NULL);
    
    if (major_status != GSS_S_COMPLETE)
    {
        failure4(FAILED_SERVICELOOKUP,
                 "Reading incoming message GSS failed Major:%8.8x "
                 "Minor:%8.8x Token:%8.8x\n",
                 major_status,
                 minor_status,
                 token_status);
    }

    if (http_message != NULL) 
    {
        null_terminate_string(&http_message, http_length);
    }

    for (length=0; length<http_length && http_message[length]!='\n'; length++)
        ;

    if ((length==0) || (length>=http_length))
    {
        failure2(FAILED_SERVICELOOKUP,
                 "Incoming message has invalid first-line length %ld\n",
                 (long) length);
    }

    {
        char    save = http_message[length];
        char *  tmpbuf = (char *) malloc(length);
        char *  p;

        http_message[length] = '\0';
        if ((1 != sscanf(http_message, "POST %s", tmpbuf)) ||
            (! (p = strchr(tmpbuf, '/'))))
        {
            failure(FAILED_SERVICELOOKUP, 
                    "Unable to extract service name from incoming message\n");
        }
        http_message[length] = save;

        if (strncmp(tmpbuf,"ping/",5)==0)
            got_ping_request = 1;

        if ((mapping = strchr(tmpbuf, '@')) != NULL)
        {
            *mapping = '\0';
            mapping = strdup(++mapping);
        }

        service_name = strdup(++p);
        free(tmpbuf);
    }

    /*
     * Cook up a unique ID such that we can link the GSI info logged by
     * the Gatekeeper to the batch system info logged by the Job Manager.
     */
    {
	time_t       clock;
	struct tm  * tmp;
	const char * gk_jm_id_var = "GATEKEEPER_JM_ID";
	char         gatekeeper_jm_id[64];

	time(&clock);
	tmp = localtime(&clock);

	sprintf(gatekeeper_jm_id, "%04d-%02d-%02d.%02d:%02d:%02d.%010u.%010u",
	    tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
	    tmp->tm_hour, tmp->tm_min, tmp->tm_sec,
	    gatekeeper_pid & 0xFFFFFFFF, reqnr & 0xFFFFFFFF);

	setenv(gk_jm_id_var, gatekeeper_jm_id, 1);
	setenv("GATEKEEPER_PEER", peernum, 1);

	notice5(0, "%s %s for %s on %s", gk_jm_id_var, gatekeeper_jm_id,
	    client_name, peernum);
    }

    /*
     * now that we know the desired service, do authorization
     * i.e. globus userid must be in the in the gridmap file. 
     */

    result = globus_gss_assist_map_and_authorize(context_handle,
                                                 service_name,
                                                 mapping,
                                                 identity_buffer, 256);

    if (result != GLOBUS_SUCCESS)
    {
        globus_object_t *               error;
        char *                          error_message = NULL;

        error = globus_error_get(result);
        error_message = globus_error_print_friendly(error);
        globus_object_free(error);
        failure2(FAILED_AUTHORIZATION,
                 "globus_gss_assist_gridmap() failed authorization."
                 " %s\n", error_message);
    }
    else if (mapping != NULL)
    {
        strncpy(&identity_buffer[0], mapping, sizeof(identity_buffer));
    }

    userid = identity_buffer;
    
#ifdef TARGET_ARCH_CRAYT3E
    if (gatekeeper_uid == 0)
    {
        get_udbent(userid);
        if (unicos_access_denied())
        {
            failure2(FAILED_AUTHORIZATION,
                     "UNICOS denied access to user %s.", userid);
        }
    }
#endif /* TARGET_ARCH_CRAYT3E */

    /* find body of message and forward it to the service */
    {
        char *  end_of_header = "\015\012\015\012";
        int     content_length;

        http_body = strstr(http_message, end_of_header);
        
        if (!http_body)
        {
            failure(FAILED_SERVER, "Could not find http message body");
        }

        content_length = get_content_length(http_message, http_body);

        http_body += 4;  /* CR LF CR LF */

        if (! got_ping_request)
        {
            http_body_file = tmpfile();
            if (http_body_file)
            {
                size_t body_length;

                setbuf(http_body_file,NULL);
                fcntl(fileno(http_body_file), F_SETFD, 0);
                sprintf(buf, "%d", fileno(http_body_file));
                setenv("GRID_SECURITY_HTTP_BODY_FD", buf, 1);
                notice2(0,"GRID_SECURITY_HTTP_BODY_FD=%s",buf);

                body_length = (size_t)(&http_message[http_length] - http_body);

                do
                {
                    fwrite(http_body,
                           1,
                           body_length,
                           http_body_file);

                    if((content_length > 0) &&
                            ((content_length -= body_length) > 0))
                    {
                        free(http_message);

                        major_status = globus_gss_assist_get_unwrap(
                                &minor_status,
                                context_handle,
                                &http_message,
                                &http_length,
                                &token_status,
                                globus_gss_assist_token_get_fd,
                                stdin,
                                logging_usrlog?usrlog_fp:NULL);
                        if (major_status != GSS_S_COMPLETE)
                        {
                            failure4(FAILED_SERVICELOOKUP,
                                     "Reading incoming message GSS failed "
                                     "Major:%8.8x "
                                     "Minor:%8.8x Token:%8.8x\n",
                                     major_status,
                                     minor_status,
                                     token_status);
                        }
                        null_terminate_string(&http_message, http_length);
                        http_body = http_message;
                        body_length = http_length;
                    }
                }
                while(content_length > 0);

                lseek(fileno(http_body_file), 0, SEEK_SET);
            }    
            else
            {
                failure(FAILED_SERVER, "Unable to create http body tmpfile");
            }
        }
    }
    
    free(http_message);
    length = strlen(service_name);
    
    if (length > 256)
    {
        failure(FAILED_SERVICELOOKUP, "Service name malformed");
    }

    notice3(LOG_NOTICE,
            "Requested service: %s %s",
            service_name,
            (got_ping_request) ? "[PING ONLY]" : "");

    /* Don't allow the client to look for service files outside of the 
     * service directory
     */
    if (strchr(service_name, '/') != NULL)
    {
        failure2(FAILED_SERVICELOOKUP, "Invalid service name %s", service_name);
    }

    if ((rc = globus_gatekeeper_util_globusxmap(
		genfilename(gatekeeperhome,grid_services,service_name), 
		NULL, 
		&service_line)) != 0)
      {
	    failure3(FAILED_SERVICELOOKUP,
		     "Failed to find requested service: %s: %d", 
		     service_name, rc);
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
        failure(FAILED_SERVER, "ERROR: gatekeeper misconfigured");
    }
    
    if (num_service_args < SERVICE_ARG0_INDEX)
    {
        notice(LOG_ERR, "ERROR:To few service arguments");
        failure(FAILED_SERVER, "ERROR: gatekeeper misconfigured");
    }

    /* now check for options */
    if (globus_gatekeeper_util_tokenize(
            service_args[SERVICE_OPTIONS_INDEX],
            service_options,
            &num_service_options,
            ","))
    {
        notice(LOG_ERR, "ERROR:Tokenize failed for services options");
        failure(FAILED_SERVER, "ERROR: gatekeeper misconfigured");
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
        else if (strcmp(service_options[i], "accept_limited") == 0)
        {
            service_option_accept_limited = 1;
        }
        else if (strcmp(service_options[i], "-") == 0)
        {
        }
        else
        {
            notice2(LOG_ERR, "ERROR:Invalid service option %s",
                    service_options[i]);
            failure(FAILED_SERVER, 
                    "ERROR: gatekeeper misconfigured");
        }
    }

    /*
     * most services will not acceot a limited proxy
     * for authentication. We will check now. This
     * only works with the Globus GSSAPI but is a noop
     * for the Kerberos GSSAPI
     */
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
    if ((service_option_accept_limited == 0)
        && (ret_flags & GSS_C_GLOBUS_LIMITED_PROXY_FLAG))
    {
        failure(FAILED_AUTHORIZATION, 
                "Attempt to use limited proxy for service");

    }
#endif


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
        failure2(FAILED_SERVER, "getpwname() failed to find %s",userid);
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

    /*
     * service existed, we were authorized to use it. ping was successful.
     */
    if (got_ping_request)
    {
#if 0
        char *     proxyfile;
        int        fd, i;
        size_t     len, bufsize;

        /*
         * DEE this is no longer needed as the delegated cred is
         * returned, and proxy is still in memory
         * failure will cleanup the delegated cred. 
         */
        if ( ((proxyfile = getenv("X509_USER_DELEG_PROXY")) != NULL)
             && ((fd = open(proxyfile, O_RDWR, 0600) >= 0))  )
        {
            len = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            bufsize = sizeof(tmpbuf);
            for (i=0; i<bufsize; i++)
                tmpbuf[i] = 0;

            for (i=0; i<len; )
                i += write(fd, tmpbuf, MIN(bufsize, len-i));

            close(fd);
            unlink(proxyfile);
        }
#endif
        failure(FAILED_PING, "ping successful");
    }

    if (delegated_cred_handle)
    {
        gss_buffer_desc                 deleg_proxy_filename;
        
        major_status = gss_export_cred(&minor_status,
                                       delegated_cred_handle,
                                       NULL,
                                       1,
                                       &deleg_proxy_filename);

        if (major_status == GSS_S_COMPLETE)
        {
            char *                      cp;

            cp = strchr((char *)deleg_proxy_filename.value, '=');
            *cp = '\0';
            cp++;
            setenv((char *)deleg_proxy_filename.value, cp, 1);
            free(deleg_proxy_filename.value);
        }
        else
        {
            char *                      error_str = NULL;
            globus_object_t *           error_obj;

            error_obj = globus_error_get((globus_result_t) minor_status);
            
            error_str = globus_error_print_friendly(error_obj);
            failure(FAILED_SERVER, error_str);
        }
    }

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
        if ((proxyfile = getenv("X509_USER_PROXY")) != NULL)
        {
            chown(proxyfile,service_uid,service_gid);
        }
    }

    /* For the Kerberos GSSAPI  prior to 1.1 with the mode to 
     * src/lib/gssapi/krb5/accept_sec_context.c 
     * to setenv KRB5CCNAME, the KRB5CCANME will be 
     * owned by root, and we need to change the ownership. 
     */
    {
        char *ccname;
        if ((ccname = getenv("KRB5CCNAME")) != NULL
            && strlen(ccname) > 5 
            && !strncmp(ccname,"FILE:",5))
        {
            chown(ccname+5,service_uid,service_gid);
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
        failure(FAILED_SERVER, "ERROR: gatekeeper misconfigured");
    }

    if (!(statbuf.st_mode & 0111))
    {
        notice2(LOG_ERR, "ERROR: Cannot execute globus service %s.",
                service_path);
        failure(FAILED_SERVER, "ERROR: gatekeeper misconfigured");
    }

    /*
     * Start building the arg list. If the -k flag is set, we want
     * to exec GRAM_K5_EXE first, passing it the path and
     * args for the service. 
     * If run from inetd, then the executables will be in libexecdir
     * otherwise they are in the current directory. 
     * we need absolute path, since we will do a chdir($HOME)
     */
        

    gram_k5_path = genfilename(libexecdir, GRAM_K5_EXE, NULL);

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
                failure(FAILED_SERVER,
                        "Gatekeeper Kerberos code is not UNICOS compliant.");
            }
        }
#       endif
        if (stat(gram_k5_path, &statbuf) != 0)
            failure2(FAILED_SERVER, "Cannot stat %s",gram_k5_path);
        if (!(statbuf.st_mode & 0111))
            failure2(FAILED_SERVER, "Cannot execute %s", gram_k5_path);
        *args = gram_k5_path;
    }

    notice2(0, "executing %s", args[0]);

    /*
     * Create two pipes to connect us to the servic:
     *   One is used with close-on-exec to sense child creation
     *          and pass back any error messages from the child
     *          to the parent.
     *DEE The above is obsolete, as gram_k5 gets execed next. 
     *   One is connected to the child's stdin, for passing a
     *          the message from the partent to the child.
     */

    if (pipe(p1) != 0)
    {
        failure2(FAILED_SERVER, "Cannot create pipe: %s", strerror(errno));
    }
    close_on_exec_read_fd = p1[0];
    close_on_exec_write_fd = p1[1];

    if (fcntl(close_on_exec_write_fd, F_SETFD, 1) != 0 ||
	fcntl(close_on_exec_read_fd, F_SETFD, 1) != 0)
    {
        failure2(FAILED_SERVER, "fcntl F_SETFD failed: %s", strerror(errno));
    }

    setenv("GLOBUS_ID",client_name,1);
    setenv("GRID_ID",client_name,1);
    setenv("GRID_AUTH_METHOD","TO_FILLED_IN_LATER",1);

    /*
     * Become the appropriate user
     */
    if (gatekeeper_uid == 0)
    {
        setenv("USER",userid,1);
        setenv("LOGNAME",userid,1);
        setenv("LOGIN",userid,1);
        setenv("HOME",pw->pw_dir,1);
        setenv("SHELL",pw->pw_shell,1);
        /* 
         * Could set path, and other variables as well 
         * Unset many of the gssapi set env variables. 
         * If not present won't hurt to unset. 
         * Leave the X509_CERT_DIR of trusted certs
         * for the user to use. 
         */
        unsetenv("GRIDMAP"); /* unset it */
        unsetenv("GLOBUSCERTDIR"); /* unset it */
        unsetenv("GLOBUSKEYDIR"); /* unset it */
        unsetenv("X509_USER_KEY"); /* unset it */
        unsetenv("X509_USER_CERT"); /* unset it */

	/* SLANG - can't unset this, otherwise jobmanager won't know where to look. */
	/* unsetenv("X509_USER_PROXY"); */ /* unset it  */
    }

    /* for tranition, if gatekeeper has the path, set it
     * for the grid_services to use 
     */
    if (jm_conf_path && !strncmp(service_name,"jobmanager",10))
    {
        setenv("JM_CONF_PATH",jm_conf_path,1);
    } 
    /* 
     * If the gssapi_ssleay did delegation, promote the
     * delegated proxy file to the user proxy file
     */
    if ((x509_delegate = getenv("X509_USER_DELEG_PROXY")))
    {
        setenv("X509_USER_PROXY",strdup(x509_delegate),1);
        unsetenv("X509_USER_DELEG_PROXY");
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
            failure(FAILED_SERVER, "ERROR: gatekeeper misconfigured");
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
                failure3(FAILED_SERVER, 
                         "trans_to_user: %d: %s", rc, errmsg);
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
        setenv("GRID_SECURITY_CONTEXT_FD", buf, 1);
        notice2(0,"GRID_SECURITY_CONTEXT_FD=%s",buf);
    }
    else
    {
        failure(FAILED_SERVER, "Unable to create context tmpfile");
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
        failure(FAILED_SERVER, "GSS Failed exporting context");
    }
        
    int_buf[0] = (unsigned char)(((context_token.length)>>24)&0xff);
    int_buf[1] = (unsigned char)(((context_token.length)>>16)&0xff);
    int_buf[2] = (unsigned char)(((context_token.length)>> 8)&0xff);
    int_buf[3] = (unsigned char)(((context_token.length)    )&0xff);
    
    if (fwrite(int_buf,4,1,context_tmpfile) != 1)
    {
        failure(FAILED_SERVER, "Failure writing context length");
    }
    if (fwrite(context_token.value,
               context_token.length,
               1,
               context_tmpfile) != 1)
    {
        failure(FAILED_SERVER, "Failure writing context token");
    }

    gss_release_buffer(&minor_status,&context_token);

    /* reposition so service can read */

    lseek(fileno(context_tmpfile), 0, SEEK_SET);

    chdir(pw->pw_dir);

    if ( launch_method != DONT_FORK )
    {
	pid = fork();
	if (pid < 0)
	{
	    failure2(FAILED_SERVER, "fork failed: %s", strerror(errno));
	}
    }

    if (launch_method == DONT_FORK)
    {
	notice2(0, "Starting child %d", pid);
    }

    if (pid == 0 || launch_method == DONT_FORK)
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
            sprintf(tmpbuf, "Exec failed: %s\n", strerror(errno));
            write(close_on_exec_write_fd, tmpbuf, strlen(tmpbuf));
	    if (launch_method != DONT_FORK)
	    {
		exit(0);
	    }
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
        failure2(FAILED_SERVER, "child failed: %s", buf);
    }
    if (n < 0)
    {
        failure(FAILED_SERVER, "child failed: error reading child fd");
    }
    close(close_on_exec_read_fd);

    if (launch_method != DONT_FORK)
    {
	notice2(0, "Child %d started", pid);
    }

    if (launch_method == FORK_AND_WAIT)
    {
	/* wait until child is reaped */
	int dead_pid;
#       ifdef HAS_WAIT_UNION_WAIT
	union wait status;
#       else
	int status;
#       endif

	do
	{
#           ifdef HAS_WAIT3
	    dead_pid = wait3(&status, 0, NULL);
#           else
	    dead_pid = waitpid(-1, &status, 0);
#           endif
	    if (dead_pid < 0 && errno != EINTR)
	    {
		break;
	    }
	} while (dead_pid != pid);
    }

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
	fd_set         fdset;
	struct timeval timeout;
	int            n;

	FD_ZERO(&fdset);
	FD_SET(skt, &fdset);
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;

	n = select(skt + 1, &fdset, (fd_set *) 0, &fdset, &timeout);

	if (n < 0 && errno != EINTR)
	{
	    error_check(n, "net_accept select");
	}
	else if (n > 0)
	{
            long flags;

	    skt2 = accept(skt, (struct sockaddr *) &from, &fromlen);

	    if (skt2 == -1)
	    {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
		{
		    error_check(skt2, "net_accept accept");
		}
	    }
	    else
		gotit = 1;
            flags = fcntl(skt2, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(skt2, F_SETFL, flags);
	}

	if (logrotate)
	{
	    time_t clock = time((time_t *) 0);
	    struct tm *tmp = localtime(&clock);
	    char buf[128];

	    sprintf(buf, "logfile rotating at %04d-%02d-%02d %02d:%02d:%02d",
		tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
		tmp->tm_hour, tmp->tm_min, tmp->tm_sec);

	    notice2(LOG_INFO, "%s", buf);

	    if (logging_usrlog)
	    {
		static int seqnr;
		char *logpath = genfilename(gatekeeperhome, logfile, NULL);
		char *oldpath = malloc(strlen(logpath) + 64);

		sprintf(oldpath, "%s.%04d%02d%02d%02d%02d%02d.%d", logpath,
		    tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
		    tmp->tm_hour, tmp->tm_min, tmp->tm_sec, seqnr++);

		if (rename(logpath, oldpath) != 0)
		{
		    notice4(LOG_ERR, "ERROR: cannot rename %s to %s: %s",
			logpath, oldpath, strerror(errno));
		}
		else if (logging_startup() != 0)
		{
		    failure(FAILED_SERVER, "Logging restart failure");
		}
		else
		{
		    logging_phase2();
		    fclose(stdout);
		    (void) dup2(2, 1); /* point stdout to stderr */
		    *stdout = *fdopen(1, "w");
		    notice2(LOG_INFO, "Continuing from %s", oldpath);
		}

		free(logpath);
		free(oldpath);
	    }

	    new_acct_file();

	    logrotate = 0;
	}
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
	long flags;
    int one=1;

    *skt = socket(AF_INET, SOCK_STREAM, 0);
    error_check(*skt,"net_setup_anon_listener socket");

	flags = fcntl(*skt, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(*skt, F_SETFL, flags);

    error_check(setsockopt(*skt, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)),
                "net_setup_anon_listener setsockopt");

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
	if (!logging_syslog)
	{
	    /*
	     * By default open syslogfile if it is not open already.
	     * All messages will have GRAM gatekeeper and include the PID.
	     * The messages will be treated like any other system daemon.
	     */
	    logging_syslog = 1;
	    openlog("GRAM gatekeeper", LOG_PID, LOG_DAEMON);
	}

        if (strlen(logfile) > 0) 
        {
            char * logfilename;
            /*
             * Open the user specified logfile
             */
                        
	    if (logging_usrlog)
	    {
		/* close previous logfile, if any */

		if (usrlog_fp)
		{
		    fclose(usrlog_fp);
		}

		logging_usrlog = 0;
	    }

            logfilename = genfilename(gatekeeperhome, logfile, NULL);

            if ((usrlog_fp = fopen(logfilename, "a")) == NULL)
            {
                fprintf(stderr, "Cannot open logfile %s: %s\n",
                        logfilename, strerror(errno));
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

	if (!gatekeeper_test && usrlog_fp) {
	    int tmpfd = dup(fileno(usrlog_fp));	/* save copy of logfile fd */

	    fflush(stderr);

	    if (usrlog_fp != stderr)
	    {
		fclose(usrlog_fp);	/* this may still close fd 2! */
	    }

	    fclose(stderr);

	    dup2(tmpfd, 2);		/* reconnect fd 2 to logfile */
	    close(tmpfd);

	    *stderr = *fdopen(2, "w");	/* reinitialize stderr */
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
failure(short failure_type, char * s)
{

    OM_uint32        minor_status = 0;
    int              token_status = 0;

    fprintf(stderr,"Failure: %s\n", s);
    if (logging_syslog)
    {
        syslog(LOG_ERR, "%s\n", s);
    }
    if (logging_usrlog)
    {
        fprintf(usrlog_fp, "TIME: %s PID: %d -- Failure: %s\n", timestamp(), getpid(), s);
    }
    /* 
     * attempt to send back to the gram_client one final 
     * error message before quiting. 
     */
    if (ok_to_send_errmsg)
    {
        char * response;
        
        switch (failure_type)
        {
        case FAILED_AUTHORIZATION: 
            response = ("HTTP/1.1 403 Forbidden\015\012"
                        "Connection: close\015\012"
                        "\015\012");
            break;

        case FAILED_SERVICELOOKUP:
            response = ("HTTP/1.1 404 Not Found\015\012"
                        "Connection: close\015\012"
                        "\015\012");
            break;

        case FAILED_PING:
            response = ("HTTP/1.1 200 OK\015\012"
                        "Content-Type: application/x-globus-gram\015\012"
                        "Content-Length: 0\015\012"
                        "\015\012");
            break;

        case FAILED_SERVER:
        case FAILED_NOLOGIN:
        case FAILED_AUTHENTICATION:
        default: 
            response = ("HTTP/1.1 500 Internal Server Error\015\012"
                        "Connection: close\015\012"
                        "\015\012");
            break;
        }
        
        /* don't care about errors here */
        globus_gss_assist_wrap_send(&minor_status,
                                    context_handle,
                                    response,
                                    strlen(response) + 1,
                                    &token_status,
                                    globus_gss_assist_token_send_fd,
                                    fdout,
                                    logging_usrlog?usrlog_fp:NULL);
    }
    if (gatekeeper_test)
    {
        fprintf(stderr,"Gatekeeper test complete : Failure!\n");
    }

    /* Cleanup any delegated credential */

    if (delegated_cred_handle)
    {
        OM_uint32 minor_status2;
        gss_release_cred(&minor_status2, &delegated_cred_handle);
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
        fprintf(usrlog_fp, "TIME: %s PID: %d -- Notice: %d: %s\n", timestamp(), getpid(), prty, s);
    }
} /* notice() */

#if defined(TARGET_ARCH_CRAYT3E)
/* Make callable entries to failure() and notice() */
void gatekeeper_failure(short failure_type, char * s)
{
    failure(failure_type, s);
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
static
void 
error_check(int val,
            char * str)
{
    if (val < 0)
    {
        failure3(FAILED_SERVER, 
                 "error check %s: %s\n", str, strerror(errno));
/*
  fprintf(usrlog_fp, "%s: %s\n",
  str,
  strerror(errno));
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
static
char *
timestamp(void)
{
    time_t clock;
    struct tm *tmp;

    time(&clock);
    tmp = localtime(&clock);
    return asctime(tmp);
} /* timestamp() */

static
int
get_content_length(char * http_message, char * http_body)
{
    char save = *http_body;
    char * content_header;
    int content_length = -1;
    *http_body = '\0';

    content_header = strstr(http_message, "\012Content-Length:");

    if(content_header != NULL)
    {
        content_header += 16;
        while(*content_header && isspace(*content_header))
        {
            content_header++;
        }
        if(*content_header)
        {
            content_length = atoi(content_header);
        }
    }
    *http_body = save;
    return content_length;
} /* get_content_length() */


static
void
null_terminate_string(char ** s, size_t len)
{

    *s = realloc(*s, len+1);

    if ((*s) == NULL)
    {
        failure(FAILED_SERVER, "Error NULL-terminating string");
    }
    (*s)[len] = 0;
}
