#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_job_manager.c Resource Allocation Job Manager
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_common.h"

#if HAVE_UTIME_H
#   include <utime.h>
#endif

#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <memory.h>
#include <fcntl.h>
#include <stdlib.h>

#include "gssapi.h"
#include "globus_gss_assist.h"

#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_gram_protocol.h"
#include "globus_rsl.h"
#include "globus_gass_file.h"
#include "globus_gass_cache.h"
#include "globus_gass_copy.h"
#include "globus_duct_control.h"
#include "globus_rsl_assist.h"
#include "globus_io.h"

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#define GRAM_JOB_MANAGER_STATUS_FILE_SECONDS 600


/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct globus_l_gram_client_contact_s
{
    char *				contact;
    int					job_state_mask;
    int					failed_count;
}
globus_l_gram_client_contact_t;


typedef struct globus_l_gram_conf_values_s
{
    char *				type;
    char *				condor_arch;
    char *				condor_os;
    char *				rdn;
    char *				host_dn;
    char *				org_dn;
    char *				gate_dn;
    char *				gate_host;
    char *				gate_port;
    char *				gate_subject;
    char *				host_osname;
    char *				host_osversion;
    char *				host_cputype;
    char *				host_manufacturer;
    char *				x509_cert_dir;
    char *				globus_location;
    char *				tcp_port_range;
    char *				scratch_dir_base;
} globus_l_gram_conf_values_t;

typedef struct globus_l_jm_http_query_s
{
    void *				arg;
    globus_gram_protocol_handle_t	handle;
    globus_byte_t *			buf;
    globus_size_t			nbytes;
    int					errorcode;
}
globus_l_jm_http_query_t;

/* Only poll once every GRAM_JOB_MANAGER_POLL_FREQUENCY seconds */
#define GRAM_JOB_MANAGER_POLL_FREQUENCY 10

/* Only do status file cleanup once every
 * GRAM_JOB_MANAGER_STAT_FREQUENCY seconds
 */
#define GRAM_JOB_MANAGER_STAT_FREQUENCY 60

#define GRAM_JOB_MANAGER_TTL_LIMIT  60
#define GRAM_JOB_MANAGER_TTL_UPDATE 30

#define GRAM_JOB_MANAGER_COMMIT_TIMEOUT 60

/******************************************************************************
                          Module specific prototypes
******************************************************************************/

static int
globus_l_gram_jm_read(int fd, globus_byte_t *buffer, size_t length);

static int
globus_l_gram_jm_write(int fd, globus_byte_t *buffer, size_t length);

static int
globus_l_gram_status_file_gen(char * request_string,
                              char * job_status_file_path,
                              char * globus_id,
                              char * job_id,
			      int status);

static char *
globus_l_gram_genfilename(char * prefix,
                          char * path,
                          char * sufix);

static int
globus_l_gram_rsl_env_add(globus_rsl_t * ast_node,
                          char * var,
                          char * value);

static int
globus_l_gram_setup_duct(
    globus_gram_jobmanager_request_t *	request,
    int					count,
    char *				myjob);

static void
globus_l_gram_client_callback(int status, int failure_code);

static
int
globus_l_gram_request_fill(
    globus_rsl_t *			rsl_tree,
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_client_contact_list_free(
    globus_list_t *			contact_list);

static
char *
globus_l_gram_getenv_var(
    char *				env_var_name,
    char *				default_name);

static char *
globus_l_gram_user_proxy_relocate();

static globus_bool_t
globus_l_gram_status_file_cleanup(
    globus_abstime_t *                  time_stop,
    void *				callback_arg);

static int
globus_l_gram_tokenize(char * command,
                       char ** args,
                       int * n);

static void
globus_l_gram_conf_values_init(globus_l_gram_conf_values_t * conf);

void
globus_l_jm_http_query_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					errorcode);

globus_bool_t
globus_l_jm_http_query_handler(
    globus_abstime_t *                  time_stop,
    void *                              callback_arg);

void
globus_l_gram_update_remote_file(
    int                                 local_fd,
    int                                 remote_fd,
    int *                               position);

void
globus_l_gram_set_state_file(
    char *                              uniq_id);

int
globus_l_gram_write_state_file(
    globus_gram_jobmanager_request_t *	request,
    int                                 status,
    int                                 failure_code,
    char *                              job_id,
    char *                              rsl);

globus_bool_t
globus_l_gram_proxy_expiration(
    globus_abstime_t *      		time_stop,
    void *				callback_arg);

globus_bool_t
globus_l_gram_ttl_update(
    globus_abstime_t *      		time_stop,
    void *				callback_arg);

int
globus_l_gram_update_state_file(
    int                                 status,
    int                                 failure_code);

int
globus_l_gram_update_state_file_io();

int
globus_l_gram_read_state_file(
    globus_gram_jobmanager_request_t *  request,
    char **                             rsl);

static
int
globus_l_jobmanager_fault_callback(void *user_arg, int fault_code);

static
int
globus_l_gram_job_manager_eval_one_attribute(
    globus_rsl_t *			rsl_tree,
    char *				attribute,
    globus_symboltable_t *		symbol_table,
    char **				value);

static
int
globus_l_gram_job_manager_create_scratchdir(
    globus_gram_jobmanager_request_t *	request,
    const char *			scratch_dir_base,
    globus_symboltable_t *		symbol_table,
    globus_rsl_t *			rsl_tree);

static
int
globus_l_gram_job_manager_create_remote_io_file(
    globus_gram_jobmanager_request_t *	request,
    char *				remote_io_url,
    char *				cache_tag);

static
globus_rsl_t *
globus_l_gram_job_manager_merge_rsl(
    globus_rsl_t *			base_rsl,
    globus_rsl_t *			override_rsl);

/******************************************************************************
                       Define variables for external use
******************************************************************************/

extern int errno;

/******************************************************************************
                       Define module specific variables
******************************************************************************/
/*
 *                                                reason needed
 *                                                --------------
 */
static char * graml_env_x509_user_proxy = NULL;   /* security */
static char * graml_env_logname = NULL;           /* all */
static char * graml_env_home = NULL;              /* all */


/*
 * other GRAM local variables
 */
static FILE *         graml_log_fp = NULL;
static char *         graml_job_contact = NULL;
static char *         graml_env_globus_id = NULL;
static int            graml_cleanup_print_flag = 1;

static globus_bool_t  graml_jm_cancel = GLOBUS_FALSE;
static globus_bool_t  graml_jm_commit_request = GLOBUS_FALSE;
static globus_bool_t  graml_jm_commit_end = GLOBUS_FALSE;
static globus_bool_t  graml_jm_request_made = GLOBUS_FALSE;
static char *         graml_job_state_file = GLOBUS_NULL;
static char *         graml_job_state_file_dir = GLOBUS_NULL;
static int            graml_commit_time_extend = 0;

globus_list_t *  globus_l_gram_client_contacts = GLOBUS_NULL;

static globus_bool_t         graml_jm_done = GLOBUS_FALSE;
static globus_bool_t         graml_jm_stop = GLOBUS_FALSE;
static globus_bool_t         graml_jm_ttl_expired = GLOBUS_FALSE;
static globus_bool_t         graml_jm_request_failed = GLOBUS_FALSE;
static long                  graml_jm_ttl = 0;
static char *                graml_remote_io_url = GLOBUS_NULL;
static char *                graml_remote_io_url_file = GLOBUS_NULL;

#define GRAM_TIMED_WAIT(wait_time) { \
     globus_abstime_t abs; \
     int save_errno; \
     abs.tv_sec = time(GLOBUS_NULL) + wait_time; \
     abs.tv_nsec = 0; \
     while(!graml_jm_done) \
     { \
         save_errno = globus_cond_timedwait(&request->cond, \
                                            &request->mutex, \
                                            &abs); \
         if(save_errno == ETIMEDOUT) \
         { \
           break; \
         } \
     } \
}

/******************************************************************************
Function:       main()
Description:
Parameters:
Returns:
******************************************************************************/
int main(int argc,
     char **argv)
{
    int                    i;
    int                    tag_index;
    int                    rc;
    int                    length;
    int                    job_state_mask;
    int                    save_logfile_always_flag = 0;
    int                    save_logfile_on_errors_flag = 0;
    int                    krbflag = 0;
    int                    tmp_status;
    int                    publish_jobs_flag = 0;
    char                   *rsl_spec = GLOBUS_NULL; /* Must free! */
    char                   tmp_buffer[256];
    char                   job_status_file_path[512];
    char *                 job_status_dir = GLOBUS_NULL;
    char *                 home_dir = NULL;
    char *                 client_contact_str = GLOBUS_NULL;
    char *                 my_url_base;
    char *                 libexecdir;
    char *                 final_rsl_spec = GLOBUS_NULL;
    unsigned long          my_pid;
    unsigned long          my_time;
    FILE *                 fp;
    struct stat            statbuf;
    globus_byte_t                       buffer[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    globus_byte_t *                     reply = NULL;
    globus_size_t                       replysize;
    globus_byte_t *                     sendbuf;
    globus_size_t                       sendsize;
    globus_rsl_t *                      rsl_tree = NULL;
    globus_gass_cache_entry_t *         cache_entries;
    int                                 cache_size;
    globus_symboltable_t *              symbol_table = NULL;
    globus_gram_jobmanager_request_t *  request;
    globus_l_gram_client_contact_t *    client_contact_node;
    globus_l_gram_conf_values_t         conf;
    globus_result_t                     error;
    globus_callback_handle_t		stat_cleanup_poll_handle;
    globus_callback_handle_t            ttl_update_handle;
    globus_callback_handle_t            proxy_expiration_handle;
    char *                              sleeptime_str;
    long                                sleeptime;
    int	                                debugging_without_client = 0;
    int	                                sent_request_failure = GLOBUS_FALSE;

    /* gssapi */
    OM_uint32			        major_status = 0;
    OM_uint32		                minor_status = 0;
    int					token_status = 0;
    gss_ctx_id_t	                context_handle = GSS_C_NO_CONTEXT;
    size_t				jrbuf_size;
    int					args_fd=0;

    /*
     * Stdin and stdout point at socket to client
     * Make sure no buffering.
     * stderr may also, depending on the option in the grid-services
     */
    setbuf(stdout,NULL);

    /* Initialize modules that I use */
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "common module activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "io activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gram protocol activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_GASS_COPY_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_copy activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_GASS_CACHE_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_cache activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_GASS_FILE_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_file activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_DUCT_CONTROL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "%s activation failed with rc=%d\n",
		GLOBUS_DUCT_CONTROL_MODULE->module_name, rc);
	exit(1);
    }

    globus_nexus_enable_fault_tolerance(
        globus_l_jobmanager_fault_callback,
        GLOBUS_NULL);

    *job_status_file_path = '\0';

    /* if -conf is passed then get the arguments from the file
     * specified
     */
    if (argc > 2 && !strcmp(argv[1],"-conf"))
    {
        char ** newargv;
        char * newbuf;
        int newargc = 52;
        int  pfd;

        newargv = (char**) malloc(newargc * sizeof(char *)); /* not freeded */
        newargv[0] = argv[0];

        /* get file length via fseek & ftell */
        if ((fp = fopen(argv[2], "r")) == NULL)
        {
            fprintf(stderr, "failed to open configuration file\n");
            exit(1);
        }
        fseek(fp, 0, SEEK_END);
        length = ftell(fp);
        if (length <=0)
        {
           fprintf(stderr,"failed to determine length of configuration file\n");
           exit(1);
        }
        fclose(fp);

        pfd = open(argv[2],O_RDONLY);
        newbuf = (char *) malloc(length+1);  /* dont free */
        i = read(pfd, newbuf, length);
        if (i < 0)
        {
            fprintf(stderr, "Unable to read parameters from configuration "
                            "file\n");
            exit(1);
        }
        newbuf[i] = '\0';
        close(pfd);

        newargv[0] = argv[0];
        newargc--;
        globus_l_gram_tokenize(newbuf, &newargv[1], &newargc);

        for (i=3; i<argc; i++)
            newargv[++newargc] = globus_libc_strdup(argv[i]);

        argv = newargv;
        argc = newargc + 1;
    }

    globus_l_gram_conf_values_init(&conf);

    if (globus_jobmanager_request_init(&request) != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
            "ERROR: globus_jobmanager_request_init() failed.\n");
        exit(1);
    }

    globus_mutex_lock(&request->mutex);

    /*
     * Parse the command line arguments
     */
    for (i = 1; i < argc; i++)
    {
	if ((strcmp(argv[i], "-save-logfile") == 0)
                 && (i + 1 < argc))
        {
            if (strcmp(argv[i+1], "always") == 0)
            {
                save_logfile_always_flag    = 1;
                save_logfile_on_errors_flag = 0;
            }
            else
            {
                save_logfile_always_flag    = 0;
                save_logfile_on_errors_flag = 1;
            }
            i++;
        }
	else if(strcmp(argv[i], "-rsl") == 0)
	{
	    if(i + 1 < argc)
	    {
		rsl_spec = globus_libc_strdup(argv[++i]);
		debugging_without_client = 1;
	    }
	    else
	    {
		fprintf(stderr, "-rsl argument requires and rsl\n");
		exit(1);
	    }
	}
        else if (strcmp(argv[i], "-k") == 0)
        {
            krbflag = 1;
        }
        else if ((strcmp(argv[i], "-home") == 0)
                 && (i + 1 < argc))
        {
            home_dir = argv[i+1]; i++;
        }
        else if ((strcmp(argv[i], "-type") == 0)
                 && (i + 1 < argc))
        {
            conf.type = argv[i+1]; i++;
        }
        else if ((strcmp(argv[i], "-e") == 0)
                 && (i + 1 < argc))
        {
            libexecdir = argv[i+1]; i++;
        }
        else if (strcmp(argv[i], "-publish-jobs") == 0)
        {
            publish_jobs_flag = 1;
        }
	else if (strcmp(argv[i], "-scratch-dir-base") == 0)
	{
	    conf.scratch_dir_base = argv[++i];
	}
        else if (strcmp(argv[i], "-publish-users") == 0)
        {
            /* NOP */ ;
        }
        else if ((strcmp(argv[i], "-condor-arch") == 0)
                 && (i + 1 < argc))
        {
            conf.condor_arch = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-condor-os") == 0)
                 && (i + 1 < argc))
        {
            conf.condor_os = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-org-dn") == 0)
                 && (i + 1 < argc))
        {
            conf.org_dn = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-host") == 0)
                 && (i + 1 < argc))
        {
            conf.gate_host = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-port") == 0)
                 && (i + 1 < argc))
        {
            conf.gate_port = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-gatekeeper-subject") == 0)
                 && (i + 1 < argc))
        {
            conf.gate_subject = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-rdn") == 0)
                 && (i + 1 < argc))
        {
            conf.rdn = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-host-dn") == 0)
                 && (i + 1 < argc))
        {
            conf.host_dn = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-host-manufacturer") == 0)
                 && (i + 1 < argc))
        {
            conf.host_manufacturer = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-host-cputype") == 0)
                 && (i + 1 < argc))
        {
            conf.host_cputype = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-host-osname") == 0)
                 && (i + 1 < argc))
        {
            conf.host_osname = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-tcp-port-range") == 0)
                 && (i + 1 < argc))
        {
            conf.tcp_port_range = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-globus-host-osversion") == 0)
                 && (i + 1 < argc))
        {
            conf.host_osversion = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-machine-type") == 0)
                 && (i + 1 < argc))
        {
	    i++;  /* ignore */
        }
        else if ((strcmp(argv[i], "-state-file-dir") == 0)
                 && (i + 1 < argc))
        {
	    graml_job_state_file_dir = globus_libc_strdup(argv[i+1]); i++;
        }
        else if ((strcasecmp(argv[i], "-help" ) == 0) ||
                 (strcasecmp(argv[i], "--help") == 0))
        {
            fprintf(stderr,
                    "Usage: globus-gram-jobmanager\n"
                    "\n"
                    "Required Arguments:\n"
                    "\t-type jobmanager type, i.e. fork, lsf ...\n"
                    "\t-rdn relative domain name\n"
                    "\t-globus-org-dn organization's domain name\n"
                    "\t-globus-host-dn host domain name\n"
                    "\t-globus-host-manufacturer manufacturer\n"
                    "\t-globus-host-cputype cputype\n"
                    "\t-globus-host-osname osname\n"
                    "\t-globus-host-osversion osversion\n"
                    "\t-globus-gatekeeper-host host\n"
                    "\t-globus-gatekeeper-port port\n"
                    "\t-globus-gatekeeper-subject subject\n"
                    "\n"
                    "Non-required Arguments:\n"
                    "\t-home globus_location\n"
                    "\t-e libexec dir\n"
                    "\t-condor-arch arch, i.e. SUN4x\n"
                    "\t-condor-os os, i.e. SOLARIS26\n"
                    "\t-publish-jobs\n"
                    "\t-save-logfile [ always | on_errors ]\n"
		    "\t-scratch-dir-base scratch-directory\n"
                    "\t-globus-tcp-port-range <min port #>,<max port #>\n"
                    "\n"
                    "Note: if type=condor then\n"
                    "      -condor-os & -condor-arch are required.\n"
                    "\n");
            exit(1);
        }
        else
        {
            fprintf(stderr, "Warning: Ignoring unknown argument %s\n\n",
                    argv[i]);
        }
    }
    graml_env_home = globus_l_gram_getenv_var("HOME", NULL);
    if (!graml_env_home)
    {
        /* we have to have HOME because we might need it for the default
         * directory for the user's job
         */
        fprintf(stderr, "ERROR: unable to get HOME from the environment.\n");
        exit(1);
    }

    if ((sleeptime_str = globus_libc_getenv("GLOBUS_JOB_MANAGER_SLEEP")))
    {
	sleeptime = atoi(sleeptime_str);
	globus_libc_usleep(sleeptime * 1000 * 1000);
    }

    if (save_logfile_always_flag || save_logfile_on_errors_flag)
    {
        /*
         * Open the gram logfile just for testing!
         */
        sprintf(tmp_buffer, "%s/gram_job_mgr_%lu.log",
                graml_env_home,
                (unsigned long) getpid());

        if ((request->jobmanager_log_fp = fopen(tmp_buffer, "a")) == NULL)
        {
            sprintf(tmp_buffer, "/tmp/gram_job_mgr_%lu.log",
                   (unsigned long) getpid());

            if ((request->jobmanager_log_fp = fopen(tmp_buffer, "a")) == NULL)
            {
                fprintf(stderr, "JM: Cannot open gram logfile.\n");
            }
            else
            {
                sprintf(tmp_buffer, "/dev/null");
            }
        }
    }
    else
    {
        /* don't write a log file */
        sprintf(tmp_buffer, "/dev/null");
    }

    if (!request->jobmanager_log_fp)
    {
	request->jobmanager_log_fp = fopen("/dev/null", "w");
    }
    setbuf(request->jobmanager_log_fp,NULL);
    graml_log_fp = request->jobmanager_log_fp;

    request->jobmanager_logfile = (char *) globus_libc_strdup(tmp_buffer);

    globus_jobmanager_log( request->jobmanager_log_fp,
          "-----------------------------------------\n");
    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: Entering gram_job_manager main().\n");

    if (conf.type == GLOBUS_NULL)
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
              "JM: Jobmanager service misconfigured. "
              "jobmanager Type not defined.\n");
	return(GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED);
    }

    if (! conf.rdn)
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
            "JM: -rdn parameter required\n");
        return(GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED);
    }

    request->jobmanager_type = (char *) globus_libc_strdup(conf.type);

    if (strcasecmp(request->jobmanager_type, "condor") == 0)
    {
        if (conf.condor_arch == NULL)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JMI: Condor_arch must be specified when "
                "jobmanager type is condor\n");
	   return(GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_ARCH);
        }
        if (conf.condor_os == NULL)
        {
           globus_jobmanager_log( request->jobmanager_log_fp,
                "JMI: Condor_os must be specified when "
                "jobmanager type is condor\n");
	   return(GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_OS);
        }
        request->condor_arch = conf.condor_arch;
        request->condor_os = conf.condor_os;
    }

    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: HOME = %s\n", graml_env_home);

    graml_env_logname = globus_l_gram_getenv_var("LOGNAME", "noname");

    graml_env_globus_id =
         globus_l_gram_getenv_var("GLOBUS_ID", "unknown globusid");

    /*
     * Getting environment variables to be added to the job's environment.
     * LOGNAME and HOME will be added as well
     */
    conf.x509_cert_dir    = globus_l_gram_getenv_var("X509_CERT_DIR", NULL);

    if (conf.tcp_port_range)
    {
       globus_libc_setenv("GLOBUS_TCP_PORT_RANGE",
                          conf.tcp_port_range,
                          GLOBUS_TRUE);
    }

    /*
     * Getting the paths to the (relocatable) deploy and install trees.
     */

    if (home_dir)
        conf.globus_location = globus_libc_strdup(home_dir);
    else
    {
        error = globus_location(&conf.globus_location);
        if (error != GLOBUS_SUCCESS)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: globus_location failed \n");
            return(GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED);
        }
    }

    globus_jobmanager_log( request->jobmanager_log_fp,
        "JM: GLOBUS_DEPLOY_PATH = %s\n",
        (conf.globus_location) ? (conf.globus_location) : "NULL");

    globus_libc_setenv("GLOBUS_LOCATION",
		       conf.globus_location,
		       GLOBUS_TRUE);

    if (libexecdir)
    {
        request->jobmanager_libexecdir =
            globus_l_gram_genfilename(conf.globus_location, libexecdir, NULL);
    }
    else
    {
        request->jobmanager_libexecdir =
            globus_l_gram_genfilename(conf.globus_location, "libexec", NULL);
    }

    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: jobmanager_libexecdir = %s\n", request->jobmanager_libexecdir);

    if(! debugging_without_client)
    {
	char *  args_fd_str;

	args_fd_str = globus_libc_getenv("GRID_SECURITY_HTTP_BODY_FD");

	if ((!args_fd_str)
	    || ((args_fd = atoi(args_fd_str)) == 0))
	{
	    globus_mutex_unlock(&request->mutex);
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: Cannot open HTTP Body file\n" );
	    exit(1);

	}
        jrbuf_size = lseek(args_fd, 0, SEEK_END);
        lseek(args_fd, 0, SEEK_SET);
        if (jrbuf_size > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: RSL file to big\n");
            exit (1);
        }
        if (read(args_fd, buffer, jrbuf_size) != jrbuf_size)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: Error reading the RSL file\n");
            exit (1);
        }
        (void *) close(args_fd);

	rc = globus_gram_protocol_unpack_job_request(
	    buffer,
	    jrbuf_size,
	    &job_state_mask,
	    &client_contact_str,
	    &rsl_spec );
    }

    if (rc == GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH)
    {
	globus_jobmanager_log( request->jobmanager_log_fp,
		"JM: ERROR: globus gram protocol version mismatch!\n");
	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: gram protocol version = %d\n",
		       GLOBUS_GRAM_PROTOCOL_VERSION);
	fprintf( stderr,
		     "ERROR: globus gram protocol version mismatch!\n");
	fprintf( stderr,
		 "gram job manager version = %d\n",
		 GLOBUS_GRAM_PROTOCOL_VERSION);
    }
    else if (rc)
    {
	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: ERROR: globus gram protocol failure!\n");
	return(GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED);
    }

    if (!debugging_without_client)
    {
	if (globus_gss_assist_import_sec_context(
	    &minor_status,
	    &context_handle,
	    &token_status,
	    -1,
	    request->jobmanager_log_fp) != GSS_S_COMPLETE)
	{
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM:Failed to load security context\n");
	return(GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED);
	}

	globus_jobmanager_log(request->jobmanager_log_fp,
		      "JM: context loaded\n");
    }

    if (client_contact_str!=NULL)
    {
	client_contact_node = (globus_l_gram_client_contact_t *)
	    globus_libc_malloc(sizeof(globus_l_gram_client_contact_t));

	client_contact_node->contact        = client_contact_str;
	client_contact_node->job_state_mask = job_state_mask;
	client_contact_node->failed_count   = 0;

	globus_list_insert(&globus_l_gram_client_contacts,
			   (void *) client_contact_node);

	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: client contact = %s\n", client_contact_str);
    }

    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: rsl_specification = %s\n", rsl_spec);
    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: job status mask = %d\n",job_state_mask);


    /* create listener port that will be used by client API funcs */
    rc = globus_gram_protocol_allow_attach(&my_url_base,
					   globus_l_jm_http_query_callback,
	                                    request);

    if (rc != GLOBUS_SUCCESS)
    {
	globus_mutex_unlock(&request->mutex);
	return GLOBUS_GRAM_PROTOCOL_ERROR_JM_FAILED_ALLOW_ATTACH;
    }

    my_pid = getpid();
    my_time = time(0);

    sprintf(tmp_buffer,
	    "%s%lu/%lu/",
	    my_url_base,
	    my_pid,
	    my_time);

    if (debugging_without_client)
    {
	printf("Job Contact: %s\n", tmp_buffer);
    }

    graml_job_contact = (char *) globus_libc_strdup (tmp_buffer);

    globus_libc_setenv("GLOBUS_GRAM_JOB_CONTACT", graml_job_contact, 1);

    request->cache_tag = (char *) globus_libc_strdup (graml_job_contact);

    sprintf(tmp_buffer, "%lu.%lu", my_pid, my_time);
    request->uniq_id = (char *)globus_libc_strdup (tmp_buffer);

    /* call the RSL routine to parse the user request
     */
    rsl_tree = globus_rsl_parse(rsl_spec);
    globus_free(rsl_spec);
    rsl_spec = GLOBUS_NULL;
    if (!rsl_tree)
    {
        rc = GLOBUS_FAILURE;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
    }
    else
    {
        /*
         * build symbol table for RSL evaluation.
         * variable found in the RSL will be replaced with these values.
         */
        symbol_table = (globus_symboltable_t *) globus_libc_malloc
                            (sizeof(globus_symboltable_t));

        globus_symboltable_init(symbol_table,
                              globus_hashtable_string_hash,
                              globus_hashtable_string_keyeq);

        globus_symboltable_create_scope(symbol_table);

        globus_symboltable_insert(symbol_table,
                                (void *) "HOME",
                                (void *) graml_env_home);

        globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_GRAM_JOB_CONTACT",
                                (void *) graml_job_contact);
        if (graml_env_logname)
            globus_symboltable_insert(symbol_table,
                                (void *) "LOGNAME",
                                (void *) graml_env_logname);
        if (graml_env_globus_id)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_ID",
                                (void *) graml_env_globus_id);
        if (conf.org_dn)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_ORG_DN",
                                (void *) conf.org_dn);
        if (conf.rdn)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_GRAM_RDN",
                                (void *) conf.rdn);
        if (conf.host_dn)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_DN",
                                (void *) conf.host_dn);
        if (conf.host_manufacturer)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_MANUFACTURER",
                                (void *) conf.host_manufacturer);
        if (conf.host_cputype)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_CPUTYPE",
                                (void *) conf.host_cputype);
        if (conf.host_osname)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_OSNAME",
                                (void *) conf.host_osname);
        if (conf.host_osversion)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_OSVERSION",
                                (void *) conf.host_osversion);
        if (conf.gate_host)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_GATEKEEPER_HOST",
                                (void *) conf.gate_host);
        if (conf.gate_port)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_GATEKEEPER_PORT",
                                (void *) conf.gate_port);
        if (conf.gate_subject)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_GATEKEEPER_SUBJECT",
                                (void *) conf.gate_subject);
        if (conf.condor_os)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_CONDOR_OS",
                                (void *) conf.condor_os);
        if (conf.condor_arch)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_CONDOR_ARCH",
                                (void *) conf.condor_arch);
        if (conf.globus_location)
	{
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_LOCATION",
                                (void *) conf.globus_location);
	}

	globus_jobmanager_log( request->jobmanager_log_fp,
		              "JM: before canonicalization: %s\n",
		              globus_rsl_unparse(rsl_tree));
	/*
	 * Canonize the RSL attributes.  This will remove underscores
	 * and lowercase all characters.  For example, givin the RSL relation
	 * "(Max_Time=20)" the attribute "Max_Time" will be altered in the
	 * rsl_tree to be "maxtime".
	 */
	if (globus_rsl_assist_attributes_canonicalize(rsl_tree) != 0)
	{
	    /* Can't canonicalize the tree, bail! */
	    rc = GLOBUS_FAILURE;
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	}
	else
	{
	    rc = globus_l_gram_job_manager_eval_one_attribute(
		rsl_tree,
		"restart",
		symbol_table,
		&request->jm_restart);

	    if(rc == GLOBUS_SUCCESS && !request->jm_restart)
	    {
		rc = globus_l_gram_job_manager_create_scratchdir(
			request,
			conf.scratch_dir_base,
			symbol_table,
			rsl_tree);
	    }

	}

    }

    if (rc == GLOBUS_SUCCESS)
    {
        rc = globus_gass_cache_open(NULL, &request->cache_handle);

        if( rc != GLOBUS_SUCCESS )
        {
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE;
        }

    }

    request->rsl = rsl_tree;

    if (rc == GLOBUS_SUCCESS && request->jm_restart == NULL)
    {
	char *				validation_file;

	globus_symboltable_insert(
		symbol_table,
		(void *) "GLOBUS_CACHED_STDOUT",
		globus_i_gram_job_manager_output_get_cache_name(
			request,
			"stdout"));
	globus_symboltable_insert(
		symbol_table,
		(void *) "GLOBUS_CACHED_STDERR",
		globus_i_gram_job_manager_output_get_cache_name(
			request,
			"stderr"));

	if (globus_rsl_eval(rsl_tree, symbol_table) != 0)
	{
	    rc = GLOBUS_FAILURE;
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code =
		 GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	}

	if ((final_rsl_spec = globus_rsl_unparse(rsl_tree)) != GLOBUS_NULL)
	{
	    globus_jobmanager_log( request->jobmanager_log_fp,
	      "JM: final rsl specification >>>>\n");
	    globus_jobmanager_log( request->jobmanager_log_fp,
	      "%s\n", final_rsl_spec);
	    globus_jobmanager_log( request->jobmanager_log_fp,
	      "JM: <<<< final rsl specification\n");
	}
	validation_file = globus_l_gram_genfilename(
		conf.globus_location,
		"share/globus-gram-job-manager",
		"submit.rvf");

	rc = globus_gram_job_manager_validate_rsl(
		request,
		validation_file,
		NULL);
	/*
	 * Eval again, as some default parameters may have to be
	 * RSL-substituted
	 */
	rc = globus_rsl_eval(rsl_tree, symbol_table);
	if (rc != GLOBUS_SUCCESS)
	{
	    rc = GLOBUS_FAILURE;
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code =
		 GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	}

        /* fill the request structure with values from the RSL
         */
        rc = globus_l_gram_request_fill(rsl_tree, request);
    }

    if (rc == GLOBUS_SUCCESS && request->jm_restart != NULL)
    {
	char *orig_rsl;
	globus_rsl_t *restart_rsl_tree;

	restart_rsl_tree = rsl_tree;

	sscanf( request->jm_restart,
		"https://%*[^:]:%*d/%lu/%lu/",
		&my_pid,
		&my_time);

	sprintf(tmp_buffer, "%s%lu/%lu//", my_url_base, my_pid, my_time);
	graml_job_contact = (char *) globus_libc_strdup (tmp_buffer);

	sprintf(tmp_buffer, "%lu.%lu", my_pid, my_time);
	request->uniq_id = (char *)globus_libc_strdup (tmp_buffer);

	globus_l_gram_set_state_file(request->uniq_id);

	globus_symboltable_insert(
		symbol_table,
		(void *) "GLOBUS_CACHED_STDOUT",
		globus_i_gram_job_manager_output_get_cache_name(
			request,
			"stdout"));
	globus_symboltable_insert(
		symbol_table,
		(void *) "GLOBUS_CACHED_STDERR",
		globus_i_gram_job_manager_output_get_cache_name(
			request,
			"stderr"));
	if (globus_rsl_eval(rsl_tree, symbol_table) != 0)
	{
	    rc = GLOBUS_FAILURE;
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code =
		 GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	}

	if ((final_rsl_spec = globus_rsl_unparse(rsl_tree)) != GLOBUS_NULL)
	{
	    globus_jobmanager_log( request->jobmanager_log_fp,
	      "JM: final rsl specification >>>>\n");
	    globus_jobmanager_log( request->jobmanager_log_fp,
	      "%s\n", final_rsl_spec);
	    globus_jobmanager_log( request->jobmanager_log_fp,
	      "JM: <<<< final rsl specification\n");
	}
	rc = globus_l_gram_read_state_file(request, &orig_rsl);

	if (rc == GLOBUS_SUCCESS &&
	    (request->status ==	GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE ||
	     request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED ||
	     request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED))
	{
	    graml_jm_done = GLOBUS_TRUE;
	}

	if (rc == GLOBUS_SUCCESS)
	{
	    char *			validation_file;

	    rsl_tree = globus_rsl_parse( orig_rsl );
	    request->rsl = rsl_tree;

	    validation_file = globus_l_gram_genfilename(
		    conf.globus_location,
		    "share/globus-gram-job-manager",
		    "submit.rvf");

	    rc = globus_gram_job_manager_validate_rsl(
		    request,
		    validation_file,
		    NULL);

	    /*
	     * Eval again, as some default parameters may have to be
	     * RSL-substituted
	     */
	    rc = globus_rsl_eval(rsl_tree, symbol_table);

	    free(orig_rsl);
	}

	if (rc == GLOBUS_SUCCESS)
	{
	    char *			validation_file;

	    request->rsl = restart_rsl_tree;

	    validation_file = globus_l_gram_genfilename(
		    conf.globus_location,
		    "share/globus-gram-job-manager",
		    "restart.rvf");

	    rc = globus_gram_job_manager_validate_rsl(
		    request,
		    validation_file,
		    NULL);

	    /*
	     * Eval again, as some default parameters may have to be
	     * RSL-substituted
	     */
	    rc = globus_rsl_eval(request->rsl, symbol_table);

	    /* Augment the submission RSL with the new validated parameters
	     * from the restart rsl
	     */

	    request->rsl = globus_l_gram_job_manager_merge_rsl(
		    rsl_tree,
		    restart_rsl_tree);

	    globus_rsl_free_recursive(rsl_tree);
	    globus_rsl_free_recursive(restart_rsl_tree);

	    rsl_tree = request->rsl;

	    rc = globus_l_gram_request_fill(request->rsl, request);
	}

	if (rc != GLOBUS_SUCCESS && request->failure_code == 0)
	{
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RESTART_FAILED;
	}
	if (request->failure_code != 0)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	}
    }

    if (rc == GLOBUS_SUCCESS && graml_remote_io_url != NULL)
    {
	rc = globus_l_gram_job_manager_create_remote_io_file(
		request,
		graml_remote_io_url,
		request->cache_tag);
    }

    if (rc == GLOBUS_SUCCESS)
    {
        /*
         * append some values from the conf file to the job environment
         */
	if (conf.x509_cert_dir)
	{
	    globus_l_gram_rsl_env_add(
		request->rsl,
		"X509_CERT_DIR",
		conf.x509_cert_dir);
	}

	if (graml_job_contact)
	{
	    globus_l_gram_rsl_env_add(
		request->rsl,
		"GLOBUS_GRAM_JOB_CONTACT",
		graml_job_contact);
	}

	if (conf.globus_location)
	{
	    globus_l_gram_rsl_env_add(
		    request->rsl,
		    "GLOBUS_LOCATION",
		    conf.globus_location);
	}

	if (conf.tcp_port_range)
	{
	    globus_l_gram_rsl_env_add(
		    request->rsl,
		    "GLOBUS_TCP_PORT_RANGE",
		    conf.tcp_port_range);
	}
    }
    /* Create local file to cache output and error */
    request->local_stdout = globus_i_gram_job_manager_output_local_name(
	    request,
	    GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM);
    request->local_stderr = globus_i_gram_job_manager_output_local_name(
	    request,
	    GLOBUS_GRAM_PROTOCOL_STDERR_PARAM);

    /* Open output destinations */
    globus_i_gram_job_manager_output_open(request);

    if ((!krbflag) && (!debugging_without_client))
    {
	if (rc == GLOBUS_SUCCESS)
	{
	    /*
	     * define the Globus object ids
	     * This is regestered as a private enterprise
	     * via IANA
	     * http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
	     *
	     * iso.org.dod.internet.private.enterprise (1.3.6.1.4.1)
	     * globus 3536
	     * security 1
	     * gssapi_ssleay 1
	     */
	    gss_OID_desc 			gsi_mech=
		{9, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01"};
	    gss_OID_set				mechs;
	    int					present = 0;

	    /*
	     * relocate the user proxy to the gass cache and
	     * return the local file name.
	     */
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: user proxy relocation\n");

	    /*
	     * Figure out if we're using GSI
	     */
	    major_status = gss_indicate_mechs(&minor_status,
					      &mechs);
	    if(major_status == GSS_S_COMPLETE)
	    {
		major_status = gss_test_oid_set_member(
			&minor_status,
			&gsi_mech,
			mechs,
			&present);
		if(major_status != GSS_S_COMPLETE)
		{
		    present = 0;
		}
		gss_release_oid_set(&minor_status, &mechs);
	    }

	    /* If so, relocate our delegated proxy */
	    if (present)
	    {
		graml_env_x509_user_proxy =
		    globus_l_gram_user_proxy_relocate(request);
		globus_jobmanager_log( request->jobmanager_log_fp,
		      "JM: GSSAPI type is GSI\n");

		if ((!graml_env_x509_user_proxy))
		{
		    request->failure_code =
			GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;
		    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
		    rc = GLOBUS_FAILURE;
		}
		else
		{
		    globus_l_gram_rsl_env_add(
			    request->rsl,
			    "X509_USER_PROXY",
			    graml_env_x509_user_proxy);
		}
	    }
	}
	else
	{
	    graml_env_x509_user_proxy = (char *) getenv("X509_USER_PROXY");
	    if (graml_env_x509_user_proxy)
	    {
		if (remove(graml_env_x509_user_proxy) != 0)
		{
		    globus_jobmanager_log( request->jobmanager_log_fp,
		      "JM: Cannot remove user proxy file --> %s\n",
		      graml_env_x509_user_proxy);
		}
		else
		{
		    globus_jobmanager_log( request->jobmanager_log_fp,
		      "JM: request failed at startup removed user proxy --> %s\n",
		      graml_env_x509_user_proxy);
		}
	    }
	}
    } /*krbflag */

    if (graml_env_x509_user_proxy)
    {
	gss_cred_id_t			cred;
	OM_uint32			lifetime;
	globus_reltime_t		delay_time;

	globus_libc_setenv( "X509_USER_PROXY",
			    graml_env_x509_user_proxy,
			    GLOBUS_TRUE );

	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: set JM env X509_USER_PROXY to point to %s\n",
		       graml_env_x509_user_proxy);

	major_status = globus_gss_assist_acquire_cred(
		&minor_status,
		GSS_C_BOTH,
		&cred);

	if(major_status != GSS_S_COMPLETE)
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
			  "JM: problem reading user proxy\n");
	}
	else
	{
	    major_status = gss_inquire_cred(
		    &minor_status,
		    cred,
		    NULL,
		    &lifetime,
		    NULL,
		    NULL);

	    if(major_status == GSS_S_COMPLETE)
	    {
		if (lifetime - 300 <= 0)
		{
		    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
		    request->failure_code =
			GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
		    rc = GLOBUS_FAILURE;
		    globus_jobmanager_log(
			    request->jobmanager_log_fp,
			    "JM: user proxy lifetime is less than minimum (5 minutes)\n");
		}
		else
		{
		    /* set timer */
		    GlobusTimeReltimeSet(delay_time, lifetime - 300, 0);
		    globus_callback_register_oneshot(&proxy_expiration_handle,
						     &delay_time,
						     globus_l_gram_proxy_expiration,
						     (void *)request,
						     GLOBUS_NULL,
						     GLOBUS_NULL);
		}

	    }
	    else
	    {
		globus_jobmanager_log(request->jobmanager_log_fp,
			      "JM: problem reading user proxy\n");
	    }
	}
    }

    if (rc == GLOBUS_SUCCESS && request->save_state == GLOBUS_TRUE)
    {
	globus_reltime_t          delay_time;
	globus_reltime_t          period_time;

	if ( graml_job_state_file == NULL )
	    globus_l_gram_set_state_file( request->uniq_id );

	if ((final_rsl_spec = globus_rsl_unparse(request->rsl)) == GLOBUS_NULL)
	    final_rsl_spec = (char *) globus_libc_strdup("RSL UNKNOWN");

	rc = globus_l_gram_write_state_file(request,
		                            request->status,
					    request->failure_code,
					    request->job_id, final_rsl_spec);
	if (rc != GLOBUS_SUCCESS)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;
	    rc = GLOBUS_FAILURE;
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: error writing the state file\n");
	}

	GlobusTimeReltimeSet(delay_time, 0, 0);
	GlobusTimeReltimeSet(period_time, GRAM_JOB_MANAGER_TTL_UPDATE, 0);
	request->ttl_limit = GRAM_JOB_MANAGER_TTL_LIMIT;
	globus_callback_register_periodic(&ttl_update_handle,
					  &delay_time,
					  &period_time,
					  globus_l_gram_ttl_update,
					  request,
					  GLOBUS_NULL,
					  GLOBUS_NULL);
    }

    if (request->two_phase_commit != 0)
    {
	int my_rc;

	/* Send reply to submitter before the actual request if we're
	 * doing 2-phase commit.
	 */
	if(!debugging_without_client)
	{
	    my_rc = globus_gram_protocol_pack_job_request_reply(
		(rc == GLOBUS_SUCCESS) ?
		        GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT :
		        request->failure_code,
                (rc == GLOBUS_SUCCESS) ? graml_job_contact : GLOBUS_NULL,
		&reply,
		&replysize);

	    if (my_rc==GLOBUS_SUCCESS)
	    {
		my_rc = globus_gram_protocol_frame_reply(
		       200,
		       reply,
		       replysize,
		       &sendbuf,
		       &sendsize);
	    }
	    if (my_rc!=GLOBUS_SUCCESS)
	    {
		my_rc = globus_gram_protocol_frame_reply(
                       400,
		       GLOBUS_NULL,
		       0,
		       &sendbuf,
		       &sendsize);
	    }
	}

	if (reply)
	    globus_libc_free(reply);

	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: before sending to client: rc=%d (%s)\n",
		       rc, globus_gram_protocol_error_string(my_rc));

	if (my_rc == GLOBUS_SUCCESS && !debugging_without_client)
	{
	    globus_jobmanager_log( request->jobmanager_log_fp,
		  "JM: sending to client;\n");
	    for (i=0; i<sendsize; i++)
		globus_libc_fprintf( request->jobmanager_log_fp,
			       "%c", sendbuf[i] );
	    globus_jobmanager_log( request->jobmanager_log_fp,
		  "-------------\n");

	    /* send this reply back down the socket to the client */
	    major_status = globus_gss_assist_wrap_send(
				   &minor_status,
				   context_handle,
				   (char *) sendbuf,
				   sendsize,
				   &token_status,
				   globus_gss_assist_token_send_fd,
				   stdout,
				   request->jobmanager_log_fp);

	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: major=%x minor=%x\n",
			   major_status, minor_status);

	    /*
	     * close the connection (both stdin and stdout are connected
	     * to the socket)
	     */
	    close(0);
	    close(1);

	    /*
	     * Reopen stdin and stdout to /dev/null (the jobmanager library
	     * expects them to be open).
	     */
	    open("/dev/null",O_RDONLY);
	    open("/dev/null",O_WRONLY);

	    globus_libc_free(sendbuf);
	}

	if ( rc == GLOBUS_SUCCESS )
	{
	    rc = my_rc;
	}

	/*
	 * If the reply reported failure or wasn't sent, suppress a later
	 * callback for the some failure.
	 */
	if(rc != GLOBUS_SUCCESS)
	{
	    sent_request_failure = GLOBUS_TRUE;
	}

    }

    fflush(request->jobmanager_log_fp);

    if (rc == GLOBUS_SUCCESS && request->two_phase_commit != 0)
    {
	int start_time = time(GLOBUS_NULL);
	int save_errno;
	while(!graml_jm_commit_request && !graml_jm_cancel)
	{
	    globus_abstime_t timeout;
	    timeout.tv_sec = start_time + request->two_phase_commit +
		             graml_commit_time_extend;
	    timeout.tv_nsec = 0;
	    save_errno = globus_cond_timedwait(&request->cond,
					       &request->mutex,
					       &timeout);
	    if(save_errno == ETIMEDOUT)
	    {
		globus_jobmanager_log( request->jobmanager_log_fp,
			       "JM: timed out waiting for commit signal\n");

		rc = GLOBUS_FAILURE;
		request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT;
		break;
	    }
	}
	if (graml_jm_cancel)
	{
	    rc = GLOBUS_FAILURE;
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;
	}
    }

    if (graml_jm_ttl_expired)
    {
	rc = GLOBUS_FAILURE;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_TTL_EXPIRED;
    }

    if (rc == GLOBUS_SUCCESS && !graml_jm_done)
    {
	if (request->save_state == GLOBUS_TRUE)
	{
	    globus_l_gram_write_state_file(
		    request,
		    GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED,
		    GLOBUS_GRAM_PROTOCOL_ERROR_SUBMIT_UNKNOWN,
		    request->job_id,
		    final_rsl_spec);
	}

        rc = globus_jobmanager_request(request);

	if ( rc == GLOBUS_SUCCESS )
	{
	    graml_jm_request_made = GLOBUS_TRUE;
	}
    }

    if (rc == GLOBUS_SUCCESS && request->save_state == GLOBUS_TRUE)
    {
	globus_l_gram_write_state_file(
		request,
		request->status,
		request->failure_code,
		request->job_id,
		final_rsl_spec);
    }

    /*
     * Send reply with the job contact or error status
     */
    if (rc == GLOBUS_SUCCESS)
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
              "JM: request was successful, sending message to client\n");

	/* This should probably go somewhere else! */
	if ((request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE) ||
	    (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED) ||
	    (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED))
	{
	    graml_jm_done = GLOBUS_TRUE;
	}

	/* On restart, report an unsubmitted job as a failure condition */
	if (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED &&
	    request->jm_restart != NULL)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_UNSUBMITTED;
	}
    }
    else
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: request failed with error %d (%s), "
		       "sending message to client\n",
		       request->failure_code,
		       globus_gram_protocol_error_string(request->failure_code));
	graml_jm_request_failed = GLOBUS_TRUE;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    }

    if (request->two_phase_commit == 0)
    {
	if(!debugging_without_client)
	{
	    if (graml_jm_request_failed)
		sent_request_failure = GLOBUS_TRUE;

	    rc = globus_gram_protocol_pack_job_request_reply(
	       (graml_jm_request_failed) ? request->failure_code : GLOBUS_SUCCESS,
	       (graml_jm_request_failed) ? GLOBUS_NULL           : graml_job_contact,
	       &reply,
	       &replysize);

	    if (rc==GLOBUS_SUCCESS)
	    {
		rc = globus_gram_protocol_frame_reply(
		    200,
		    reply,
		    replysize,
		    &sendbuf,
		    &sendsize);
	    }
	    if (rc!=GLOBUS_SUCCESS)
	    {
		rc = globus_gram_protocol_frame_reply(
		    400,
		    GLOBUS_NULL,
		    0,
		    &sendbuf,
		    &sendsize);
	    }
	}

	if (reply)
	    globus_libc_free(reply);

	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: before sending to client: rc=%d (%s)\n",
		       rc, globus_gram_protocol_error_string(rc));

	if (rc == GLOBUS_SUCCESS && !debugging_without_client)
	{
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: sending to client:\n");
	    for (i=0; i<sendsize; i++)
		globus_libc_fprintf( request->jobmanager_log_fp,
			       "%c", sendbuf[i] );
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "-------------\n");

	    /* send this reply back down the socket to the client */
	    major_status = globus_gss_assist_wrap_send(
	                           &minor_status,
				   context_handle,
				   (char *) sendbuf,
				   sendsize,
				   &token_status,
				   globus_gss_assist_token_send_fd,
				   stdout,
				   request->jobmanager_log_fp);

	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: major=%x minor=%x\n",
			   major_status, minor_status);

	    /*
	     * close the connection (both stdin and stdout are connected
	     * to the socket)
	     */
	    close(0);
	    close(1);
	    globus_libc_free(sendbuf);
	}
    }

    if (!graml_jm_request_failed)
    {
        globus_reltime_t          delay_time;
        globus_reltime_t          period_time;

        if (!request->job_id)
            request->job_id = (char *) globus_libc_strdup ("UNKNOWN");

        /* send callback with the status */
	if(!graml_jm_done)
	{
	    globus_l_gram_client_callback(request->status,
					  request->failure_code);
	}


        /* if we are publishing jobs, then setup the necessary variables */
        if (publish_jobs_flag)
        {
            if ((final_rsl_spec = globus_rsl_unparse(rsl_tree)) == GLOBUS_NULL)
                final_rsl_spec = (char *) globus_libc_strdup("RSL UNKNOWN");

            job_status_dir = globus_l_gram_genfilename(conf.globus_location,
						       "var",
						       NULL);

            sprintf( job_status_file_path,
		     "%s/%s_%s.%s",
		     job_status_dir,
		     conf.rdn,
		     graml_env_logname,
		     request->job_id );

            globus_jobmanager_log( request->jobmanager_log_fp,
                 "JM: job_status_file_path = %s\n", job_status_file_path);

            globus_l_gram_status_file_gen(final_rsl_spec,
                                          job_status_file_path,
                                          graml_env_globus_id,
                                          request->job_id,
					  request->status);
	}

        if (request->poll_frequency == 0)
        {
            request->poll_frequency = GRAM_JOB_MANAGER_POLL_FREQUENCY;
        }

        globus_jobmanager_log( request->jobmanager_log_fp,
              "JM: poll frequency = %d\n", request->poll_frequency);

        GlobusTimeReltimeSet(delay_time, 0, 0);
        GlobusTimeReltimeSet(period_time, GRAM_JOB_MANAGER_STAT_FREQUENCY, 0);
	globus_callback_register_periodic(&stat_cleanup_poll_handle,
					  &delay_time,
					  &period_time,
					  globus_l_gram_status_file_cleanup,
					  (void *) job_status_dir,
					  GLOBUS_NULL,
					  GLOBUS_NULL);

        while (!graml_jm_done && !graml_jm_ttl_expired)
        {
	    /*
	     * The only thing that can wake this up prematurely is a request
	     * from the client to cancel the job.
	     */
	    GRAM_TIMED_WAIT(request->poll_frequency);

	    /*
	     * stuff may have occurred while we were unlocked,
	     * so we need to poll file descriptors, etc to see
	     * if state change occurred
	     */
	    if (!graml_jm_done)
	    {
		/* check if cancel handler was called */
		if (publish_jobs_flag)
		{
		    /* touch the file so we know we did not crash */
		    if ( utime(job_status_file_path, NULL) != 0 )
		    {
			if(errno == ENOENT)
			{
			    globus_jobmanager_log( request->jobmanager_log_fp,
					   "JM: job status file not found, "
					   "rewritting it with current "
					   "status.\n");

			    globus_l_gram_status_file_gen(final_rsl_spec,
							  job_status_file_path,
                                                          graml_env_globus_id,
							  request->job_id,
							  request->status);
			}
		    }
		}
		rc = globus_jobmanager_request_check(request);

		if ( rc == GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED ||
		     rc == GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED )
		{
		    if (request->save_state == GLOBUS_TRUE)
		    {
			globus_l_gram_update_state_file( request->status,
						     request->failure_code );
		    }

		    if (rc == GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED)
		    {
			/*
			 * unable to get a status for the job.
			 * often the result of a broken poll script.
			 */
			globus_jobmanager_request_cancel(request);
			request->status=GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
		    }

		    if ((request->status ==
			 GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE) ||
			(request->status ==
			 GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED))
		    {
			globus_jobmanager_log( request->jobmanager_log_fp,
				       "JM: request check returned DONE or "
				       "FAILED\n");
			graml_jm_done = 1;
		    }
		    else
		    {
			/* send callback of new status
			 * The tmp_status variable is needed because
			 * a cancel request could come in and set the flag
			 * before this callback completes.  Also, we cannot
			 * be lock when doing a send_rsr which is done in
			 * the client_callback routine.
			 */
			tmp_status = request->status;
			globus_l_gram_client_callback(tmp_status,
						      request->failure_code);
			globus_l_gram_status_file_gen(final_rsl_spec,
						      job_status_file_path,
						      graml_env_globus_id,
						      request->job_id,
						      request->status);
		    }
		}
	    }
        } /* endwhile */

	while (request->in_handler)
	{
	    globus_cond_wait(&request->cond, &request->mutex);
	}

	globus_callback_unregister(stat_cleanup_poll_handle);
    } /* endif */

    if (request->save_state == GLOBUS_TRUE)
    {
	globus_callback_unregister(ttl_update_handle);
    }

    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: we're done.  doing cleanup\n");

    if (!graml_jm_ttl_expired)
    {
	/* This blocks until all stdout and stderr data has been sent to
	 * all interested destinations.
	 */
	globus_i_gram_job_manager_output_close(request);
    }
    /* set the failure code for the callback */
    if (graml_jm_ttl_expired)
    {
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_TTL_EXPIRED;
    }

    if(graml_jm_ttl_expired || graml_jm_stop || (!sent_request_failure &&
       ((request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE) ||
        (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED) ||
	(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED))))
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
              "JM: sending final callback.\n");

	graml_commit_time_extend = 0;

	if (graml_jm_ttl_expired || graml_jm_stop)
	{
	    globus_l_gram_client_callback(GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED,
					  request->failure_code);
	}
	else
	{
	    globus_l_gram_client_callback(request->status,
					  request->failure_code);
	}

	if (request->two_phase_commit != 0)
	{
	    int start_time = time(GLOBUS_NULL);
	    int save_errno;

	    if (request->save_state == GLOBUS_TRUE &&
		request->failure_code != GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT)
	    {
		globus_l_gram_update_state_file( request->status,
						 request->failure_code );
	    }

	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: waiting for commit signal\n" );

	    while(!graml_jm_commit_end && !graml_jm_ttl_expired &&
		  !graml_jm_stop && request->failure_code !=
		      GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT)
	    {
		globus_abstime_t timeout;
		timeout.tv_sec = start_time + request->two_phase_commit +
		                 graml_commit_time_extend;
		timeout.tv_nsec = 0;
		save_errno = globus_cond_timedwait(&request->cond,
						   &request->mutex,
						   &timeout);
		if(save_errno == ETIMEDOUT)
		{
		    globus_jobmanager_log( request->jobmanager_log_fp,
			       "JM: timed out waiting for commit signal\n");
		    break;
		}
	    }
	}

        /*
         * Check to see if the job status file exists.  If so, then delete it.
         */
        if (stat(job_status_file_path, &statbuf) == 0)
        {
            if (remove(job_status_file_path) != 0)
            {
                globus_jobmanager_log( request->jobmanager_log_fp,
                      "JM: Failed to remove job status file --> %s\n",
                      job_status_file_path);
            }
        }
    }

    if (globus_l_gram_client_contact_list_free(globus_l_gram_client_contacts)
        != GLOBUS_SUCCESS)
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
              "JM: Error freeing client contact list.\n");
    }

    if (!graml_jm_ttl_expired && !graml_jm_stop &&
	!(request->two_phase_commit != 0 && !graml_jm_commit_end &&
	  request->save_state != 0))
    {
	/* Remove the scratch directory */
	globus_jobmanager_request_rm_scratchdir(request);

	/* clear any other cache entries which contain the gram job id as
	 * the tag
	 */
	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: Cleaning GASS cache\n");

	rc = globus_gass_cache_list(&request->cache_handle,
				    &cache_entries,
				    &cache_size);
	if(rc == GLOBUS_SUCCESS)
	{
	    for(i=0; i<cache_size; i++)
	    {
		for(tag_index=0;
		    tag_index<cache_entries[i].num_tags;
		    tag_index++)
		{
		    if (!strcmp(cache_entries[i].tags[tag_index].tag,
				request->cache_tag))
		    {
			globus_jobmanager_log(request->jobmanager_log_fp,
			     "Trying to clean up with <url=%s> <tag=%s>\n",
			     cache_entries[i].url,
			     request->cache_tag);

			globus_gass_cache_cleanup_tag(&request->cache_handle,
						      cache_entries[i].url,
						      request->cache_tag);
		    }
		} /* for each tags */
	    } /* for each cache entries */
	    globus_gass_cache_list_free(cache_entries, cache_size);
	}

        /*
         * Check to see if the job state file exists.  If so, then delete it.
         */
        if (graml_job_state_file != NULL &&
	    stat(graml_job_state_file, &statbuf) == 0)
        {
            if (remove(graml_job_state_file) != 0)
            {
                globus_jobmanager_log( request->jobmanager_log_fp,
                      "JM: Failed to remove job statue file --> %s\n",
                      graml_job_state_file);
            }
        }

    }
    else if (!graml_jm_ttl_expired)
    {

	/*
	 * We're leaving the state file behind. Set the TTL in it to the
	 * current time since we're about to exit.
	 */
	if ( graml_job_state_file != NULL ) {
	    request->ttl_limit = 0;
	    globus_l_gram_ttl_update(NULL, request);
	}

    }

    globus_gass_cache_close(&request->cache_handle);

    globus_mutex_unlock(&request->mutex);

    fflush(request->jobmanager_log_fp);

    globus_jobmanager_log( request->jobmanager_log_fp, "JM: freeing RSL.\n");

    if (request->rsl)
        globus_rsl_free_recursive(request->rsl);

    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: starting deactivate routines.\n");

    globus_gram_protocol_callback_disallow(graml_job_contact);

    /*
     * If we ran without a client, display final state and error if applicable
     */
    if(debugging_without_client)
    {
	fprintf(stderr,
		"Final Job Status: %d%s%s%s\n",
		request->status,
		request->failure_code ? " (failed because " : "",
		request->failure_code
		    ? globus_gram_protocol_error_string(request->failure_code)
		    : "",
		request->failure_code ? ")" : "");
    }
    rc = globus_module_deactivate_all();
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "deactivation failed with rc=%d\n",
		rc);
	exit(1);
    }

    globus_jobmanager_log(
	    request->jobmanager_log_fp,
	    "JM: exiting globus_gram_job_manager.\n");

    if ( save_logfile_always_flag ||
         (save_logfile_on_errors_flag &&
          graml_jm_request_failed &&
          !request->dry_run)
       )
    {
	;
    }
    else if (strcmp(request->jobmanager_logfile, "/dev/null") != 0)
    {
        /*
         * Check to see if the jm log file exists.  If so, then delete it.
         */
        if (stat(request->jobmanager_logfile, &statbuf) == 0)
        {
	    if (remove(request->jobmanager_logfile) != 0)
            {
	        fprintf(stderr, "failed to remove job manager log file = %s\n",
                        request->jobmanager_logfile);
            }
        }
    }

    return(0);
} /* main() */


/******************************************************************************
Function:       globus_l_gram_conf_values_init()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_conf_values_init( globus_l_gram_conf_values_t * conf )
{
    if (!conf)
       return;

    conf->type              = GLOBUS_NULL;
    conf->condor_arch       = GLOBUS_NULL;
    conf->condor_os         = GLOBUS_NULL;
    conf->rdn               = GLOBUS_NULL;
    conf->host_dn           = GLOBUS_NULL;
    conf->org_dn            = GLOBUS_NULL;
    conf->gate_dn           = GLOBUS_NULL;
    conf->gate_host         = GLOBUS_NULL;
    conf->gate_port         = GLOBUS_NULL;
    conf->gate_subject      = GLOBUS_NULL;
    conf->host_osname       = GLOBUS_NULL;
    conf->host_osversion    = GLOBUS_NULL;
    conf->host_cputype      = GLOBUS_NULL;
    conf->host_manufacturer = GLOBUS_NULL;
    conf->x509_cert_dir     = GLOBUS_NULL;
    conf->globus_location   = GLOBUS_NULL;
    conf->tcp_port_range    = GLOBUS_NULL;
    conf->scratch_dir_base  = GLOBUS_NULL;

    return;

} /* globus_l_gram_conf_values_init() */


/******************************************************************************
Function:       globus_l_gram_client_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_client_callback(int status, int failure_code)
{
    int                                 rc;
    globus_byte_t *                     message;
    globus_size_t                       msgsize;
    globus_list_t *                     tmp_list;
    globus_l_gram_client_contact_t *    client_contact_node;

    tmp_list = globus_l_gram_client_contacts;
    message = GLOBUS_NULL;

    globus_jobmanager_log( graml_log_fp,
        "JM: %s empty client callback list.\n", (tmp_list) ? ("NOT") : "" );

    if (tmp_list)
    {
	rc = globus_gram_protocol_pack_status_update_message(
	    graml_job_contact,
	    status,
	    failure_code,
	    &message,
	    &msgsize);

	if (rc != GLOBUS_SUCCESS)
	{
	    globus_jobmanager_log( graml_log_fp,
			   "JM: error %d while creating status message\n" );
	    return;
	}
    }

    while(!globus_list_empty(tmp_list))
    {
        client_contact_node = (globus_l_gram_client_contact_t *)
             globus_list_first(tmp_list);

        if ((status & client_contact_node->job_state_mask) &&
            client_contact_node->failed_count < 4)
        {
            globus_jobmanager_log( graml_log_fp,
                "JM: sending callback of status %d (failure code %d) to %s.\n",
                status, failure_code, client_contact_node->contact);

	    rc = globus_gram_protocol_post(
		    client_contact_node->contact,
		    GLOBUS_NULL /* Ignore handle */,
		    GLOBUS_NULL /* default attr */,
		    message,
		    msgsize,
		    GLOBUS_NULL /* Ignore reply */,
		    GLOBUS_NULL);

	    if (rc!=GLOBUS_SUCCESS)
	    {
		/* connect failed, most likely */
		globus_jobmanager_log( graml_log_fp,
			       "JM: callback failed, rc = %d, \"%s\"\n",
			       rc,
			       globus_gram_protocol_error_string (rc));
                client_contact_node->failed_count++;
	    }
        }

        tmp_list = globus_list_rest (tmp_list);
    }

    /* this is safe, as the post() has copied the message to another buffer
       and framed it with HTTP headers etc. */
    if (message)
	globus_libc_free(message);

} /* globus_l_gram_client_callback() */


/******************************************************************************
Function:       globus_l_gram_status_file_gen()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_status_file_gen(char * request_string,
                              char * job_status_file_path,
                              char * globus_id,
                              char * job_id,
			      int status)
{
    FILE *       status_fp;
    char         status_str[64];
    struct stat  statbuf;

    globus_jobmanager_log( graml_log_fp,
			   "JM: in globus_l_gram_status_file_gen\n");

    switch(status)
    {
        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
            strcpy(status_str, "PENDING   ");
            break;
        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
            strcpy(status_str, "ACTIVE    ");
            break;
        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
            strcpy(status_str, "FAILED    ");
            break;
        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
            strcpy(status_str, "DONE      ");
            break;
        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED:
            strcpy(status_str, "SUSPENDED ");
            break;
        default:
            strcpy(status_str, "UNKNOWN   ");
    }

    if (stat(job_status_file_path, &statbuf) == 0)
    {
        /* the file exists, so just update the first line which is the
         * job status
         */
        if ((status_fp = fopen(job_status_file_path, "r+")) == NULL)
        {
            globus_jobmanager_log( graml_log_fp,
                 "JM: Failed opening job status file %s\n",
                 job_status_file_path);
            return(1);
        }
        fprintf(status_fp, "%s\n", status_str);
    }
    else
    {
        if ((status_fp = fopen(job_status_file_path, "w")) == NULL)
        {
           globus_jobmanager_log(graml_log_fp,
               "JM: Failed opening job status file %s\n",
               job_status_file_path);
           return(1);
        }
        else
        {
            fprintf(status_fp, "%s\n", status_str);
            fprintf(status_fp, "%s\n", request_string);
            fprintf(status_fp, "%s\n", graml_job_contact);
            fprintf(status_fp, "%s\n", job_id);
            fprintf(status_fp, "%s\n", globus_id);

        }
    }

    fclose(status_fp);

    return(0);
} /* globus_l_gram_status_file_gen() */


/**
 * Add an environment variable to the job RSL.
 *
 * This function adds a single environment variable to the job RSL. If
 * there is no environment relation in the RSL, then one is added. Both
 * the variable name and value are copied into the RSL, so the original
 * values passed in may be static strings or pointers to data which is
 * freed or overwritten once this function returns.
 *
 * @param ast_node
 *        A pointer to the RSL tree to update. This should point to the
 *        root of the rsl tree (the boolean &) on the invocation of the
 *        function, but will point to various relations in the RSL as
 *        it calls itself recursively.
 * @param var
 *        A pointer to a string containing the variable to be added to
 *        the RSL. No checking is done to see if this environment variable
 *        is already defined in the RSL. This will be duplicated and inserted
 *        into the RSL.
 * @param value
 *        The value of the environment variable named @a var. This will
 *        be duplicated and inserted into the RSL.
 * 
 * @retval 0
 *         The environment variable was added to the RSL.
 * @retval 1
 *         The @a ast_node points to a relation other than an environment
 *         relation
 * @retval 2
 *         The @a ast_node points to some unexpected part of the RSL.
 */
static
int
globus_l_gram_rsl_env_add(
    globus_rsl_t *			ast_node,
    char *				var,
    char *				value)
{
    globus_rsl_t *			tmp_rsl_ptr;
    globus_list_t *			tmp_rsl_list;
    globus_list_t *			new_list;
    char *				tmp_rsl_str;
    int					rc;

    if (globus_rsl_is_boolean(ast_node))
    {
        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);

            rc = globus_l_gram_rsl_env_add( tmp_rsl_ptr, var, value);
	    if(rc == 0)
	    {
		return rc;
	    }

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);

        }
	/* Didn't find environment in the RSL: add it! */
	tmp_rsl_str = globus_libc_malloc(
		    strlen("environment = (%s %s)") +
		    strlen(var) +
		    strlen(value));

	sprintf(tmp_rsl_str, "environment = (%s %s)", var, value);
	tmp_rsl_ptr = globus_rsl_parse(tmp_rsl_str);

	globus_libc_free(tmp_rsl_str);

	globus_list_insert(
		globus_rsl_boolean_get_operand_list_ref(ast_node),
		tmp_rsl_ptr);

	return 0;
    }
    else if (globus_rsl_is_relation(ast_node))
    {
        if (!globus_rsl_is_relation_attribute_equal(ast_node, "environment"))
        {
            return(1);
        }

        new_list = NULL;

        globus_list_insert(&new_list, (void *)
            globus_rsl_value_make_literal(globus_libc_strdup(value)));

        globus_list_insert(&new_list, (void *)
            globus_rsl_value_make_literal(globus_libc_strdup(var)));

        globus_list_insert(
            globus_rsl_value_sequence_get_list_ref(
                 globus_rsl_relation_get_value_sequence(ast_node)),
                 (void *) globus_rsl_value_make_sequence(new_list));

        return(0);
    }
    else
    {
        return(2);
    }
} /* globus_l_gram_rsl_env_add() */


/**
 * Fill request structure from RSL tree.
 *
 * In this function, we look through the job request RSL to find attributes
 * which we need to process in the job manager program (not in the scripts).
 */
static int
globus_l_gram_request_fill(
    globus_rsl_t *			rsl_tree,
    globus_gram_jobmanager_request_t *	request)
{
    int					x;
    char **				tmp_param;
    char *				gram_myjob;
    char *				ptr;
    int					count;
    int					rc;

    if (rsl_tree == NULL)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_SPECIFICATION_TREE;
        return(GLOBUS_FAILURE);
    }

    /* Canonize the RSL attributes.  This will remove underscores and lowercase
     * all character.  For example, givin the RSL relation "(Max_Time=20)" the
     * attribute "Max_Time" will be altered in the rsl_tree to be "maxtime".
     *
     */
    if (globus_rsl_assist_attributes_canonicalize(rsl_tree) != GLOBUS_SUCCESS)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_SPECIFICATION_TREE;
        return(GLOBUS_FAILURE);
    }

    /* Process stdout */
    rc = globus_i_gram_job_manager_output_set_urls(
	    request,
	    GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
	    globus_rsl_param_get_values(
		rsl_tree,
		GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM),
	    globus_rsl_param_get_values(
		rsl_tree,
		GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM));

    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_FAILURE;
    }

    /* Process stderr */
    rc = globus_i_gram_job_manager_output_set_urls(
	    request,
	    GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
	    globus_rsl_param_get_values(
		rsl_tree,
		GLOBUS_GRAM_PROTOCOL_STDERR_PARAM),
	    globus_rsl_param_get_values(
		rsl_tree,
		GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM));

    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_FAILURE;
    }

    /**********************************
     *  GET COUNT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_COUNT_PARAM,
		             &tmp_param) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_COUNT;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {

        x = atoi(tmp_param[0]);

        if (x < 1)
        {
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COUNT;
            return(GLOBUS_FAILURE);
        }
        else
        {
            count = x;
        }
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET MYJOB PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_MYJOB_PARAM,
		             &tmp_param) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MYJOB;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        gram_myjob = globus_libc_strdup(tmp_param[0]);
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET DRY_RUN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_DRY_RUN_PARAM,
		             &tmp_param) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_DRYRUN;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "yes", 3) == 0)
	{
            request->dry_run = GLOBUS_TRUE;
	}
        else
	{
            request->dry_run = GLOBUS_FALSE;
	}

    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET SAVE_STATE PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_SAVE_STATE_PARAM,
		             &tmp_param) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SAVE_STATE;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "yes", 3) == 0)
            request->save_state = GLOBUS_TRUE;
        else
            request->save_state = GLOBUS_FALSE;

    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET TWO_PHASE_COMMIT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM,
		             &tmp_param) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_TWO_PHASE_COMMIT;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "yes", 3) == 0)
	{
            request->two_phase_commit = GRAM_JOB_MANAGER_COMMIT_TIMEOUT;
	}
        else
	{
	    x = (int) strtol(tmp_param[0], &ptr, 10);

	    if (strlen(ptr) > 0 || x < 0)
	    {
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_TWO_PHASE_COMMIT;
		return(GLOBUS_FAILURE);
	    }
	    else
	    {
		request->two_phase_commit = x;
	    }
	}
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /**********************************
     *  GET REMOTE IO URL PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_PROTOCOL_REMOTE_IO_URL_PARAM,
		             &tmp_param) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        graml_remote_io_url = globus_libc_strdup(tmp_param[0]);
    }
    globus_libc_free(tmp_param);
    tmp_param = GLOBUS_NULL;

    /* Initialize a duct control handle and add appropriate environment
     * variables to the job execution environment.
     *
     * (Depends on myjob and count parameters)
     */
    globus_l_gram_setup_duct(request, count, gram_myjob);

    globus_libc_free(gram_myjob);

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_request_fill() */

/**
 * Generate an absolute pathname.
 *
 * This function creates a dynamically allocated string containing
 * an absolute pathname constructed from the prefixp, pathp, and suffixp
 * strings.
 *
 * @param prefixp
 *        The prefix of the path string.
 * @param pathp
 *        The middle portion of the path. If this is absolute path, then
 *        prefixp is ignored.
 * @param sufixp
 *        The suffix of the path. "/" followed by sufixp will be appended
 *        to pathp to construct the end of the path, if sufixp is non-null.
 */
static
char *
globus_l_gram_genfilename(
    char *				prefixp,
    char *				pathp,
    char *				sufixp)
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
              strcat(newfilename, "/");
          }
          strcat(newfilename, path);
          if ((pathl != 0)
              && (sufixl != 0)
              && (path[pathl-1] != '/') && sufix[0] != '/')
            strcat(newfilename, "/");
          strcat(newfilename, sufix);
        }
        return newfilename;
}
/* globus_l_gram_genfilename */

/**
 * Create duct control handler.
 *
 * This function creates a duct_control structure to handle coordinating
 * intra-job communication. The duct contact string is added to the 
 * job's environment RSL relation.
 *
 * @param request
 *        The request which is being processed.
 * @param count
 *        The value o fthe job RSL's count relation.
 * @param myjob
 *        The value of the job RSL's GramMyJob relation.
 *
 *
 * @retval GLOBUS_SUCCESS
 *         The duct control handle was successfully created and
 *         the contact added to the environment for the job.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_DUCT_LSP_FAILED
 *         The duct control handle was not successfully created.
 */
static
int
globus_l_gram_setup_duct(
    globus_gram_jobmanager_request_t *	request,
    int					count,
    char *				myjob)
{
    globus_duct_control_t *		duct;
    int					rc;
    char *				newval;

    duct = globus_libc_malloc(sizeof(globus_duct_control_t));

    if(strcmp(myjob, "collective") != 0)
    {
	count = 1;
    }
    rc = globus_duct_control_init(duct,
				  count,
				  GLOBUS_NULL,
				  GLOBUS_NULL);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_jobmanager_log( graml_log_fp,
		       "JM: duct_control_init_failed: %d\n",
		       rc);
	return GLOBUS_GRAM_PROTOCOL_ERROR_DUCT_INIT_FAILED;
    }

    rc = globus_duct_control_contact_url(duct,
					 &newval);

    if(rc != GLOBUS_SUCCESS)
    {
	globus_jobmanager_log( graml_log_fp,
		       "JM: duct_control_contact_url failed: %d\n",
		       rc);

	return(GLOBUS_GRAM_PROTOCOL_ERROR_DUCT_LSP_FAILED);
    }
    rc = globus_l_gram_rsl_env_add(
	    request->rsl,
	    "GLOBUS_GRAM_MYJOB_CONTACT",
	    newval);

    globus_libc_free(newval);

    return rc;
}
/* globus_l_gram_seutp_duct()*/

/******************************************************************************
Function:       globus_l_gram_getenv_var()
Description:
Parameters:
Returns:
******************************************************************************/
static char *
globus_l_gram_getenv_var(char * env_var,
                         char * default_val)
{
    char * tmp_env_val;
    char * env_val;

    tmp_env_val = (char *) globus_libc_getenv(env_var);

    if (tmp_env_val)
    {
        env_val = (char *) globus_libc_strdup (tmp_env_val);
	if(graml_log_fp)
	{
	    globus_jobmanager_log( graml_log_fp, "JM: %s = %s\n",
				   env_var, env_val);
	}
    }
    else
    {
	if(graml_log_fp)
	{
	    globus_jobmanager_log( graml_log_fp,
			   "JM: unable to get %s from the environment.\n",
			   env_var);
	}
        if (default_val)
        {
            env_val = (char *) globus_libc_strdup (default_val);
	    if(graml_log_fp)
	    {
		globus_jobmanager_log( graml_log_fp, "JM: %s = %s\n", env_var, env_val);
	    }
        }
        else
        {
            env_val = GLOBUS_NULL;
        }
    }

    return(env_val);

} /* globus_l_gram_getenv_var() */

/******************************************************************************
Function:       globus_l_gram_status_file_cleanup()
Description:
Parameters:
Returns:
******************************************************************************/
static globus_bool_t
globus_l_gram_status_file_cleanup(
    globus_abstime_t *         		time_stop,
    void *				callback_arg)
{
    DIR *            status_dir;
    char * job_status_dir;
    struct dirent *  dir_entry = GLOBUS_NULL;
    char             logname_string[256];
    char             stat_file_path[1024];
    struct stat      statbuf;
    unsigned long    now;
    globus_bool_t    status = GLOBUS_FALSE;

    job_status_dir = (char *) callback_arg;

    if(job_status_dir == GLOBUS_NULL)
    {
        if (graml_cleanup_print_flag)
        {
           graml_cleanup_print_flag = 0;
           globus_jobmanager_log( graml_log_fp,
               "JM: status directory not specified, cleanup cannot proceed.\n");
        }
        return GLOBUS_FALSE;
    }

    status_dir = globus_libc_opendir(job_status_dir);
    if(status_dir == GLOBUS_NULL)
    {
        globus_jobmanager_log( graml_log_fp,
            "JM: unable to open status directory, aborting cleanup process.\n");
        return GLOBUS_FALSE;
    }

    sprintf(logname_string, "_%s.", graml_env_logname);
    now = (unsigned long) time(NULL);

    for(globus_libc_readdir_r(status_dir, &dir_entry);
        dir_entry != GLOBUS_NULL &&
        globus_callback_has_time_expired() > 0;
        globus_free(dir_entry),
        globus_libc_readdir_r(status_dir, &dir_entry))
    {
        if (strstr(dir_entry->d_name, logname_string) != NULL)
        {
            sprintf(stat_file_path, "%s/%s", job_status_dir, dir_entry->d_name);
            globus_jobmanager_log( graml_log_fp,
                   "JM: found user file --> %s\n", stat_file_path);
            if (stat(stat_file_path, &statbuf) == 0)
            {
                if ( (now - (unsigned long) statbuf.st_mtime) >
                      GRAM_JOB_MANAGER_STATUS_FILE_SECONDS )
                {
                    globus_jobmanager_log( graml_log_fp,
                        "JM: status file has not been modified in %d seconds\n",
                        GRAM_JOB_MANAGER_STATUS_FILE_SECONDS);
                    if (remove(stat_file_path) != 0)
                    {
                        globus_jobmanager_log( graml_log_fp,
                               "JM: Cannot remove old status file --> %s\n",
                               stat_file_path);
                    }
                    else
                    {
                        globus_jobmanager_log( graml_log_fp,
                               "JM: Removed old status file --> %s\n",
                               stat_file_path);
			status = GLOBUS_TRUE;
                    }
                }
            }
        }
    }

    if (dir_entry != GLOBUS_NULL) globus_free(dir_entry);

    globus_libc_closedir(status_dir);

    return status;
} /* globus_l_gram_status_file_cleanup() */


/******************************************************************************
Function:       globus_l_gram_user_proxy_relocate()
Description:
Parameters:
Returns:
******************************************************************************/
static char *
globus_l_gram_user_proxy_relocate(globus_gram_jobmanager_request_t * request)
{
    int            rc;
    int            proxy_fd, new_proxy_fd;
    char           buf[512];
    char *         user_proxy_path;
    char *         cache_user_proxy_filename;
    char *         unique_file_name;
    unsigned long  timestamp;

    globus_jobmanager_log( request->jobmanager_log_fp,
          "JM: Relocating user proxy file to the gass cache\n");

    user_proxy_path = (char *) getenv("X509_USER_PROXY");
    if (!user_proxy_path)
    {
        return(GLOBUS_NULL);
    }

    unique_file_name = globus_libc_malloc(strlen(request->cache_tag) +
                                    strlen("x509_user_proxy") + 2);

    globus_libc_sprintf(unique_file_name,
                        "%s/%s",
                        request->cache_tag,
                        "x509_user_proxy");

    rc = globus_gass_cache_add(&request->cache_handle,
                               unique_file_name,
                               request->cache_tag,
                               GLOBUS_TRUE,
                               &timestamp,
                               &cache_user_proxy_filename);

    if ( rc == GLOBUS_GASS_CACHE_ADD_EXISTS ||
         rc == GLOBUS_GASS_CACHE_ADD_NEW )
    {

	char *tmp_file_name = globus_libc_malloc(strlen(cache_user_proxy_filename)+5);

	sprintf(tmp_file_name, "%s.tmp", cache_user_proxy_filename);

        if ((proxy_fd = open(user_proxy_path, O_RDONLY)) < 0)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: Unable to open (source) user proxy file %s\n",
                user_proxy_path);
            globus_libc_free(unique_file_name);
	    globus_libc_free(tmp_file_name);
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
            return(GLOBUS_NULL);
        }

        if ((new_proxy_fd = open(tmp_file_name,
                                 O_CREAT|O_WRONLY|O_TRUNC,
				 0600)) < 0)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: Unable to open temp cache file for the user proxy %s\n",
                tmp_file_name);
            globus_libc_free(unique_file_name);
	    globus_libc_free(tmp_file_name);
            request->failure_code =
                  GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
            return(GLOBUS_NULL);
        }

        globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: Copying user proxy file from --> %s\n",
                user_proxy_path);
        globus_jobmanager_log( request->jobmanager_log_fp,
                "JM:                         to   --> %s\n",
                cache_user_proxy_filename);

        while((rc = read(proxy_fd, buf, sizeof(buf))) > 0)
        {
             write(new_proxy_fd, buf, rc);
        }

        close(proxy_fd);
        close(new_proxy_fd);

	chmod(cache_user_proxy_filename, 0600);

	if (rename( tmp_file_name, cache_user_proxy_filename ) < 0)
	{
	    globus_jobmanager_log( request->jobmanager_log_fp,
		    "JM: Unable rename temp cache file for user proxy %s\n",
		    cache_user_proxy_filename);
	    globus_libc_free(unique_file_name);
	    globus_libc_free(tmp_file_name);
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
	    return(GLOBUS_NULL);
	}

	chmod(cache_user_proxy_filename, 0400);

	globus_libc_free(tmp_file_name);

        rc = globus_gass_cache_add_done(&request->cache_handle,
                                        unique_file_name,
                                        request->cache_tag,
                                        timestamp);
        if(rc != GLOBUS_SUCCESS)
        {
	    globus_jobmanager_log( request->jobmanager_log_fp,
			   "JM: globus_gass_cache_add_done failed for user proxy file --> %s\n",
			   user_proxy_path);
            if (remove(user_proxy_path) != 0)
            {
                globus_jobmanager_log( request->jobmanager_log_fp,
                  "JM: Cannot remove user proxy file %s\n",user_proxy_path);
            }
            globus_libc_free(unique_file_name);
            return(GLOBUS_NULL);
        }
    }
    else
    {
	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: Cannot get a cache entry for user proxy file %s : %s\n",
		       unique_file_name, globus_gass_cache_error_string(rc));
        if (remove(user_proxy_path) != 0)
        {
            globus_jobmanager_log( request->jobmanager_log_fp,
                "JM: Cannot remove user proxy file %s\n",user_proxy_path);
        }
        globus_libc_free(unique_file_name);
        return(GLOBUS_NULL);
    }

    if (remove(user_proxy_path) != 0)
    {
        globus_jobmanager_log( request->jobmanager_log_fp,
            "JM: Cannot remove user proxy file %s\n",user_proxy_path);
    }

    return(cache_user_proxy_filename);

} /* globus_l_gram_user_proxy_relocate() */

/******************************************************************************
Function:       globus_l_gram_tokenize()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_tokenize(char * command, char ** args, int * n)
{
  int i, x;
  char * cp;
  char * cp2;
  char ** arg;
  char * tmp_str = NULL;

  arg = args;
  i = *n - 1;

  for (cp = strtok(command, " \t\n"); cp != 0; )
  {
      if ( cp[0] == '\'' && cp[strlen(cp) - 1] != '\'' )
      {
         cp2 = strtok(NULL, "'\n");
         tmp_str = malloc(sizeof(char *) * (strlen(cp) + strlen(cp2) + 2));
         sprintf(tmp_str, "%s %s", &cp[1], cp2);
      }
      else if ( cp[0] == '"' && cp[strlen(cp) - 1] != '"' )
      {
         cp2 = strtok(NULL, "\"\n");
         tmp_str = malloc(sizeof(char *) * (strlen(cp) + strlen(cp2) + 2));
         sprintf(tmp_str, "%s %s", &cp[1], cp2);
      }
      else
      {
         if (( cp[0] == '"' && cp[strlen(cp) - 1] == '"' ) ||
             ( cp[0] == '\'' && cp[strlen(cp) - 1] == '\'' ))
         {
             tmp_str = malloc(sizeof(char *) * strlen(cp));
             x = strlen(cp)-2;
             strncpy(tmp_str, &cp[1], x);
             tmp_str[x] = '\0';
         }
         else
         {
             tmp_str = cp;
         }
      }

      *arg = tmp_str;
      i--;
      if (i == 0)
          return(-1); /* too many args */
      arg++;
      cp = strtok(NULL, " \t\n");
  }

  *arg = (char *) 0;
  *n = *n - i - 1;
  return(0);

} /* globus_l_gram_tokenize() */


/******************************************************************************
Function:       globus_l_gram_jm_write()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_jm_write(int fd, globus_byte_t *buffer, size_t length)
{
    ssize_t rc;
    size_t written;
    written = 0;

    while(written < length)
    {
        rc = globus_libc_write(fd, buffer + written, length-written);
        if(rc < 0)
        {
            switch(errno)
            {
                case EAGAIN:
                case EINTR:
                    break;
                default:
                    return (int) rc;
            }
        }
        else
        {
            written += rc;
        }
    }

    return (int) written;

} /* globus_l_gram_jm_write() */


/******************************************************************************
Function:       globus_l_gram_jm_read()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_jm_read(int fd, globus_byte_t *buffer, size_t length)
{
    ssize_t rc;
    size_t amount_read;
    amount_read = 0;

    while(amount_read < length)
    {
        rc = globus_libc_read(fd, buffer + amount_read, length-amount_read);
        if(rc < 0)
        {
            switch(errno)
            {
                case EAGAIN:
                case EINTR:
                    break;
                default:
                    return (int) rc;
            }
        }
	else if (rc == 0)
	{
	    break;
	}
        else
        {
            amount_read += rc;
        }
    }

    return (int) amount_read;

} /* globus_l_gram_jm_read() */


/******************************************************************************
Function:       globus_l_gram_client_contact_list_free()
Description:
Parameters:
Returns:
******************************************************************************/
int globus_l_gram_client_contact_list_free(globus_list_t *contact_list)
{
    globus_l_gram_client_contact_t *    client_contact_node;

    while(!globus_list_empty(contact_list))
    {
        client_contact_node = (globus_l_gram_client_contact_t *)
            globus_list_remove (&contact_list, contact_list);
        globus_libc_free (client_contact_node->contact);
        globus_libc_free (client_contact_node);
    }

    return GLOBUS_SUCCESS;

} /* globus_l_gram_client_contact_list_free() */

void
globus_l_gram_update_remote_file(
    int                                 local_fd,
    int                                 remote_fd,
    int *                               position)
{
    globus_byte_t buf[1024];
    int amt_read = 0;
    int amt_written = 0;

    if (local_fd < 0 || remote_fd < 0)
	return;

    if (lseek(local_fd, 0, SEEK_CUR) <= *position)
	return;

    lseek(local_fd, *position, SEEK_SET);

    do {

	amt_read = globus_l_gram_jm_read(local_fd, buf, 1024);

	if (amt_read > 0)
	{
	    amt_written = globus_l_gram_jm_write(remote_fd, buf, amt_read);
	    if (amt_written < 0)
	    {
		amt_read = -1;
		break;
	    }
	    *position += amt_written;
	}

    } while ( amt_read > 0 );

}

/******************************************************************************
Function:       globus_gram_protocol_query_callback()
Description:
Parameters:
Returns:
******************************************************************************/

#define my_malloc(type,count) (type *) globus_libc_malloc(count*sizeof(type))

/*
 * I'm not sure why this callback doesn't process the query directly
 * here--it's been like this for a long time.
 * -joe
 */
void
globus_l_jm_http_query_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					errorcode)
{
    globus_l_jm_http_query_t *		query_args;
    globus_callback_handle_t		query_handle;
    globus_reltime_t			delay_time;

    query_args = (globus_l_jm_http_query_t *)
	globus_libc_malloc(sizeof(globus_l_jm_http_query_t));
    query_args->arg = arg;
    query_args->handle = handle;
    query_args->buf = globus_libc_malloc(nbytes+1);
    memcpy(query_args->buf, buf, nbytes);
    query_args->buf[nbytes] = '\0';
    query_args->nbytes = nbytes;
    query_args->errorcode = errorcode;

    GlobusTimeReltimeSet(delay_time, 0, 0);

    globus_callback_register_oneshot( &query_handle,
				      &delay_time,
				      globus_l_jm_http_query_handler,
				      (void *)query_args,
				      GLOBUS_NULL,
				      GLOBUS_NULL );
}

globus_bool_t
globus_l_jm_http_query_handler( 
    globus_abstime_t *      		time_stop,
    void *				callback_arg)
{
    globus_gram_jobmanager_request_t *   request;
    globus_l_gram_client_contact_t *     callback;
    globus_list_t *                      tmp_list;
    globus_list_t *                      next_list;
    globus_size_t                        replysize;
    globus_byte_t *                      reply             = GLOBUS_NULL;
    char *                               query             = GLOBUS_NULL;
    char *                               rest;
    char *                               url;
    int                                  mask;
    int                                  status;
    int					 code;
    int                                  rc;
    globus_bool_t                        done;
    char *                               after_signal;
    globus_l_jm_http_query_t *		query_args = callback_arg;
    globus_gram_protocol_handle_t	handle = query_args->handle;
    globus_byte_t *			buf = query_args->buf;
    globus_size_t			nbytes = query_args->nbytes;

    request = query_args->arg;

    globus_libc_free( query_args );

    globus_mutex_lock(&request->mutex);
    request->in_handler = GLOBUS_TRUE;
    done = graml_jm_done;
    globus_mutex_unlock(&request->mutex);

    rc = globus_gram_protocol_unpack_status_request( buf, nbytes, &query );

    /* The "user" callback has to free the read buffer */
    globus_libc_free(buf);

    if (rc != GLOBUS_SUCCESS)
	goto globus_l_jm_http_query_send_reply;

    globus_jobmanager_log( request->jobmanager_log_fp,
		   "JM : in globus_l_gram_http_query_callback, query=%s\n",
		   query);

    rest = strchr(query,' ');
    if (rest)
	*rest++ = '\0';

    /*
     * do opposite of what API says: let rc (==failure_code) decide whether to
     * trust status, no the opposite (if status==FAILED, read failure_code).
     */

    rc     = GLOBUS_SUCCESS;
    status = GLOBUS_SUCCESS;

    if (strcmp(query,"cancel")==0)
    {
        if (done)
	{
	   rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
	}
	else
	{
	    globus_mutex_lock(&request->mutex);
	    if ( graml_jm_request_made )
	    {
		rc = globus_jobmanager_request_cancel(request);
	    }
 	    /*
	     * NOTE: old code set state to FAILED. Shouldn't it be DONE?
	     */
	    status = request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    	    /*
	     * wake up the timed() wait in the main routine
	     */
            graml_jm_cancel = GLOBUS_TRUE;
	    graml_jm_done = GLOBUS_TRUE;
	    globus_cond_signal(&request->cond);
	    globus_mutex_unlock(&request->mutex);
	}
    }
    else if (strcmp(query,"status")==0)
    {
	globus_mutex_lock(&request->mutex);
	status = request->status;
	globus_mutex_unlock(&request->mutex);
    }
    else if (strcmp(query,"signal")==0)
    {
	if (sscanf(rest,"%d", (int *) &request->signal) != 1)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	}
	else
	{
	    int out_sz = -1;
	    int err_sz = -1;

            after_signal = strchr(rest,' ');
            if (after_signal)
                *after_signal++ = '\0';

	    switch( request->signal ) {
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL:
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_SUSPEND:
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_RESUME:
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_PRIORITY:
		if (after_signal && (strlen(after_signal) > 0))
		{
		    request->signal_arg = globus_libc_strdup(after_signal);

		    if (done)
		    {
			rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
			goto globus_l_jm_http_query_send_reply;
		    }
		    globus_mutex_lock(&request->mutex);
		    rc = globus_jobmanager_request_signal(request);
		    globus_mutex_unlock(&request->mutex);
		} else {
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
		}
		break;
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST:
		if (request->two_phase_commit == 0)
		{
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT;
		} else {
		    globus_mutex_lock(&request->mutex);
		    if (graml_jm_commit_request == GLOBUS_FALSE)
		    {
			graml_jm_commit_request = GLOBUS_TRUE;
			globus_cond_signal(&request->cond);
		    }
		    globus_mutex_unlock(&request->mutex);
		}
		break;
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END:
		if (request->two_phase_commit == 0 ||
		    (!done && !graml_jm_request_failed))
		{
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT;
		} else {
		    globus_mutex_lock(&request->mutex);
		    if (graml_jm_commit_end == GLOBUS_FALSE)
		    {
			graml_jm_commit_end = GLOBUS_TRUE;
			globus_cond_signal(&request->cond);
		    }
		    globus_mutex_unlock(&request->mutex);
		}
		break;
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_EXTEND:
		if (after_signal && (strlen(after_signal) > 0))
		{
		    globus_mutex_lock(&request->mutex);
		    graml_commit_time_extend += atoi(after_signal);
		    globus_cond_signal(&request->cond);
		    globus_mutex_unlock(&request->mutex);
		} else {
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
		}
		break;
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_UPDATE:
		if (done)
		{
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
		}
		else if (after_signal && (strlen(after_signal) > 0))
		{
		    /* handle stdio update */
		}
		else
		{
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
		}
		break;
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_SIZE:
		if (after_signal && sscanf(after_signal, "%d %d", &out_sz,
					   &err_sz) > 0) {
		    globus_mutex_lock(&request->mutex);
		    globus_mutex_unlock(&request->mutex);
		} else {
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
		}
		break;
	    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STOP_MANAGER:
		globus_mutex_lock(&request->mutex);
		graml_jm_done = GLOBUS_TRUE;
		graml_jm_stop = GLOBUS_TRUE;
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;
		globus_cond_signal(&request->cond);
		globus_mutex_unlock(&request->mutex);
		break;
	    default:
		rc = GLOBUS_GRAM_PROTOCOL_ERROR_UNKNOWN_SIGNAL_TYPE;
	    }

	    if (rc == GLOBUS_SUCCESS)
	    {
		status = request->status;
	    }
	}
    }
    else if (strcmp(query,"register")==0)
    {
        if (done)
	{
	   rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
	}
	else
	{
	    url = globus_libc_strdup(rest);
	    if (sscanf(rest,"%d %s", &mask, url) != 2)
	        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	    else
	    {
	        callback = my_malloc(globus_l_gram_client_contact_t,1);
	        callback->contact = globus_libc_strdup(url);
	        callback->job_state_mask = mask;
	        callback->failed_count   = 0;

	        globus_mutex_lock(&request->mutex);
	        rc = globus_list_insert(
		    &globus_l_gram_client_contacts,
		    (void *) callback);
	        status = request->status;
	        globus_mutex_unlock(&request->mutex);

	        if (rc != GLOBUS_SUCCESS)
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INSERTING_CLIENT_CONTACT;
	    }
	    globus_libc_free(url);
        }
    }
    else if (strcmp(query,"unregister")==0)
    {
        if (done)
	{
	   rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
	}
	else
	{
	    url = rest;
	    if (!url || strlen(url)==0)
	        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	    else
	    {
	        rc = GLOBUS_GRAM_PROTOCOL_ERROR_CLIENT_CONTACT_NOT_FOUND;
	        globus_mutex_lock(&request->mutex);
	        tmp_list = globus_l_gram_client_contacts;
	        while(!globus_list_empty(tmp_list))
	        {
		    next_list = globus_list_rest(tmp_list);

		    callback = (globus_l_gram_client_contact_t *)
		                globus_list_first(tmp_list);

		    if (strcmp(url, callback->contact) == 0)
		    {
		        callback  = (globus_l_gram_client_contact_t *)
			    globus_list_remove( &globus_l_gram_client_contacts,
					        tmp_list);
		        globus_libc_free (callback->contact);
		        globus_libc_free (callback);
		        rc = GLOBUS_SUCCESS;
		    }
		    tmp_list = next_list;
	        }
	        status = request->status;
	        globus_mutex_unlock(&request->mutex);
	    }
	}
    }
    else
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
    }

globus_l_jm_http_query_send_reply:

    if (rc != GLOBUS_SUCCESS)
	status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

    globus_jobmanager_log( request->jobmanager_log_fp,
		   "JM : reply: (status=%d failure code=%d (%s))\n",
		   status, rc, globus_gram_protocol_error_string(rc));

    if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
    {
	rc = globus_gram_protocol_pack_status_reply(
	    status,
	    rc,
	    request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED &&
	        rc == GLOBUS_SUCCESS ? request->failure_code : 0,
	    &reply,
	    &replysize );
    }
    if (rc == GLOBUS_SUCCESS)
    {
	code = 200;
    }
    else
    {
	code = 400;

	globus_libc_free(reply);
	reply = GLOBUS_NULL;
	replysize = 0;
    }
    if (query)
	globus_libc_free(query);

    {
	int i;
	globus_jobmanager_log(request->jobmanager_log_fp,
		              "JM : sending reply:\n");
	for (i=0; i<replysize; i++)
	{
	    globus_libc_fprintf(request->jobmanager_log_fp,
		                "%c", reply[i]);
	}
	globus_jobmanager_log(request->jobmanager_log_fp,
		              "-------------------\n");
    }

    globus_gram_protocol_reply(handle,
	                       code,
			       reply,
			       replysize);

    if(reply)
    {
	globus_libc_free(reply);
    }

    globus_mutex_lock(&request->mutex);
    request->in_handler = GLOBUS_FALSE;
    globus_mutex_unlock(&request->mutex);

    return GLOBUS_FALSE;
}

globus_bool_t
globus_l_gram_proxy_expiration(
    globus_abstime_t *      		time_stop,
    void *				callback_arg)
{
    globus_gram_jobmanager_request_t *	request;

    request = callback_arg;

    globus_jobmanager_log(graml_log_fp,
		  "JM: User proxy expired! Abort, but leave job running!\n");
    globus_mutex_lock(&request->mutex);
    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
    graml_jm_stop = GLOBUS_TRUE;
    graml_jm_done = GLOBUS_TRUE;
    globus_cond_signal(&request->cond);
    globus_mutex_unlock(&request->mutex);

    return GLOBUS_FALSE;
}

void
globus_l_gram_set_state_file(char *uniq_id)
{
    char				buffer[1024];
    char 				my_host[MAXHOSTNAMELEN];

    globus_libc_gethostname(my_host, sizeof(my_host));

    if (graml_job_state_file_dir == GLOBUS_NULL)
    {
	sprintf(buffer, "%s/.globus/job.%s.%s", graml_env_home, my_host,
		uniq_id);
    }
    else
    {
	sprintf(buffer, "%s/job.%s.%s", graml_job_state_file_dir, my_host,
		uniq_id);
    }

    graml_job_state_file = (char *) globus_libc_strdup (buffer);
}

int
globus_l_gram_write_state_file(
    globus_gram_jobmanager_request_t *	request,
    int					status,
    int					failure_code,
    char *				job_id,
    char *				rsl)
{
    int					rc = GLOBUS_SUCCESS;
    long				new_ttl;
    FILE *				fp;
    char				tmp_file[1024];

    /*
     * We want the file update to be "atomic", so create a new temp file,
     * write the new information, close the new file, then rename the new
     * file on top of the old one. The rename is the atomic update action.
     */

    strcpy( tmp_file, graml_job_state_file );
    strcat( tmp_file, ".tmp" );

    globus_jobmanager_log(graml_log_fp, "JM: Writing state file\n");

    new_ttl = time(NULL) + GRAM_JOB_MANAGER_TTL_LIMIT;
    graml_jm_ttl = new_ttl;

    fp = fopen( tmp_file, "w" );
    if ( fp == NULL )
    {
	globus_jobmanager_log(graml_log_fp, "JM: Failed to open state file %s\n",
		      tmp_file);
	return GLOBUS_FAILURE;
    }

    fprintf( fp, "%4d\n", status );
    fprintf( fp, "%4d\n", failure_code );
    fprintf( fp, "%10ld\n", new_ttl );
    fprintf( fp, "%s\n", job_id ? job_id : " " );
    fprintf( fp, "%s\n", rsl );
    fprintf( fp, "%s\n", request->cache_tag );

    fclose( fp );

    rc = rename( tmp_file, graml_job_state_file );
    if (rc != 0)
    {
	globus_jobmanager_log(graml_log_fp, "JM: Failed to rename state file\n");
	rc = GLOBUS_FAILURE;
    }

    return rc;
}

globus_bool_t
globus_l_gram_ttl_update(
    globus_abstime_t *      		time_stop,
    void *				callback_arg)
{
    globus_gram_jobmanager_request_t *	request;
    long curr_time = time(NULL);

    request = callback_arg;

    /*
     * We're doing a single write, which is atomic enough, so don't bother
     * with creating a new file and renaming it over the old one.
     */

    if(curr_time < graml_jm_ttl)
    {
	FILE *fp;
	long new_ttl = curr_time + request->ttl_limit;

	graml_jm_ttl = new_ttl;

	globus_jobmanager_log(graml_log_fp, "JM: Updating state file TTL to %d\n",
		      new_ttl);

	fp = fopen( graml_job_state_file, "r+" );
	if ( fp == NULL )
	{
	    globus_jobmanager_log(graml_log_fp, "JM: Failed to open state file %s\n",
			  graml_job_state_file);
	    return GLOBUS_FAILURE;
	}

	/* seek past the status and failure_code lines (4 characters plus
	 * newline for each)
	 */
	fseek(fp, 10, SEEK_SET);

	fprintf( fp, "%10ld\n", new_ttl );

	fclose(fp);
    }
    else
    {
	globus_jobmanager_log(graml_log_fp,
		      "JM: TTL expired! Abort, but leave job running!\n");
	globus_mutex_lock(&request->mutex);
	graml_jm_ttl_expired = GLOBUS_TRUE;
	graml_jm_done = GLOBUS_TRUE;
	globus_cond_signal(&request->cond);
	globus_mutex_unlock(&request->mutex);
    }

    return GLOBUS_FALSE;
}

int
globus_l_gram_update_state_file( int status, int failure_code )
{
    int rc = GLOBUS_SUCCESS;
    FILE *fp;
    char buffer[11];

    /*
     * We're doing a single write, which is atomic enough, so don't bother
     * with creating a new file and renaming it over the old one.
     */

    if ( status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED )
    {
	sprintf( buffer, "%4d\n%4d\n", status, failure_code );
    }
    else
    {
	sprintf( buffer, "%4d\n%4d\n", status, 0 );
    }

    fp = fopen( graml_job_state_file, "r+" );
    if ( fp == NULL )
	return GLOBUS_FAILURE;

    fprintf( fp, "%s", buffer );
    fclose( fp );

    return rc;
}

int
globus_l_gram_update_state_file_io()
{
    int rc = GLOBUS_SUCCESS;
    FILE *new_fp;
    FILE *old_fp;
    char tmp_file[1024];
    char buffer[8192];

    strcpy( tmp_file, graml_job_state_file );
    strcat( tmp_file, ".tmp" );

    /*
     * We want the file update to be "atomic", so create a new temp file,
     * copy over the file contents we're not changing, write the new io
     * information, close both files, then rename the new file on top of
     * the old one. The rename is the atomic update action.
     */
    old_fp = fopen( graml_job_state_file, "r" );
    if ( old_fp == NULL )
    {
	globus_jobmanager_log(graml_log_fp, "JM: Failed to open state file %s\n",
		      graml_job_state_file);
	return GLOBUS_FAILURE;
    }

    new_fp = fopen( tmp_file, "w" );
    if ( new_fp == NULL )
    {
	fclose(old_fp);
	globus_jobmanager_log(graml_log_fp, "JM: Failed to open state file %s\n",
		      tmp_file);
	return GLOBUS_FAILURE;
    }

    /* Copy the information we're not changing from the old state file */
    /* Make sure this is kept in sync with globus_l_gram_write_state_file */
    fscanf( old_fp, "%[^\n]%*c", buffer );	/* status */
    fprintf( new_fp, "%s\n", buffer );
    fscanf( old_fp, "%[^\n]%*c", buffer );	/* failure code */
    fprintf( new_fp, "%s\n", buffer );
    fscanf( old_fp, "%[^\n]%*c", buffer );	/* ttl */
    fprintf( new_fp, "%s\n", buffer );
    fscanf( old_fp, "%[^\n]%*c", buffer );	/* job id */
    fprintf( new_fp, "%s\n", buffer );
    fscanf( old_fp, "%[^\n]%*c", buffer );	/* rsl */
    fprintf( new_fp, "%s\n", buffer );
    fscanf( old_fp, "%[^\n]%*c", buffer );	/* gass cache tag */
    fprintf( new_fp, "%s\n", buffer );

    fclose( old_fp );
    fclose( new_fp );

    rc = rename( tmp_file, graml_job_state_file );
    if (rc != 0)
    {
	globus_jobmanager_log(graml_log_fp, "JM: Failed to rename state file\n");
	rc = GLOBUS_FAILURE;
    }

    return rc;
}

int
globus_l_gram_read_state_file( globus_gram_jobmanager_request_t *request,
			       char **rsl )
{
    int rc = GLOBUS_SUCCESS;
    long curr_time;
    long ttl;
    FILE *fp;
    char buffer[8192];
    globus_gass_cache_entry_t *cache_entries;
    int cache_size;
    struct stat statbuf;

    globus_jobmanager_log(graml_log_fp, "JM: Attempting to read state file %s\n",
		  graml_job_state_file);

    curr_time = time(NULL);

    if (stat(graml_job_state_file, &statbuf) != 0)
    {
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
	return GLOBUS_FAILURE;
    }

    fp = fopen( graml_job_state_file, "r" );
    if ( fp == NULL )
    {
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;
	return GLOBUS_FAILURE;
    }

    fscanf( fp, "%[^\n]%*c", buffer );
    request->status = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->failure_code = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    ttl = atoi( buffer );

    if(ttl > curr_time)
    {
	long new_ttl;
	globus_abstime_t abs;

	globus_jobmanager_log(graml_log_fp,
		      "JM: state file TTL hasn't expired yet. Waiting...\n");

	fseek( fp, 0, SEEK_SET );

	abs.tv_sec = ttl + 1;
	abs.tv_nsec = 0;
	while(globus_cond_timedwait(&request->cond, &request->mutex, &abs) !=
	      ETIMEDOUT);

	fscanf( fp, "%[^\n]%*c", buffer );
	request->status = atoi( buffer );
	fscanf( fp, "%[^\n]%*c", buffer );
	request->failure_code = atoi( buffer );
	fscanf( fp, "%[^\n]%*c", buffer );
	new_ttl = atoi( buffer );

	if (new_ttl != ttl)
	{
	    globus_jobmanager_log(graml_log_fp,
			  "JM: TTL was renewed! Old JM is still around.\n");
	    fclose(fp);
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;
	    return GLOBUS_FAILURE;
	}
    }

    globus_jobmanager_log(graml_log_fp,
		  "JM: TTL has expired. Proceeding with restart.\n");

    rc = globus_gass_cache_list(&request->cache_handle,
                                &cache_entries,
                                &cache_size);
    if (rc != GLOBUS_SUCCESS)
    {
	fclose(fp);
	return GLOBUS_FAILURE;
    }

    fscanf( fp, "%[^\n]%*c", buffer );
    request->job_id = strdup( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    *rsl = strdup( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->cache_tag = strdup( buffer );

    fclose( fp );

    globus_gass_cache_list_free(cache_entries, cache_size);

    return rc;
}

/******************************************************************************
Function: globus_l_jobmanager_fault_callback()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_jobmanager_fault_callback(void *user_arg, int fault_code)
{
    if(graml_log_fp)
    {
	globus_jobmanager_log(
	    graml_log_fp,
	    "jobmanager received nexus fault code %d\n",
	    fault_code);
    }

    return 0;
} /* globus_l_jobmanager_fault_callback() */

static
int
globus_l_gram_job_manager_eval_one_attribute(
    globus_rsl_t *			rsl_tree,
    char *				attribute,
    globus_symboltable_t *		symbol_table,
    char **				value)
{
    globus_list_t *			operands;
    globus_rsl_t *			attribute_rsl = GLOBUS_NULL;

    *value = GLOBUS_NULL;

    if(globus_rsl_is_boolean_and(rsl_tree))
    {
	operands = globus_rsl_boolean_get_operand_list(rsl_tree);

	while(!globus_list_empty(operands))
	{
	    rsl_tree = globus_list_first(operands);

	    if(globus_rsl_is_relation_eq(rsl_tree))
	    {
		if(globus_rsl_is_relation_attribute_equal(
			    rsl_tree,
			    attribute))
		{
		    attribute_rsl = rsl_tree;
		    break;
		}
	    }
	    operands = globus_list_rest(operands);
	}
	if(attribute_rsl)
	{
	    globus_rsl_eval(attribute_rsl, symbol_table);
	    *value = globus_rsl_value_literal_get_string(
			globus_rsl_relation_get_single_value(
			    attribute_rsl));

	    return GLOBUS_SUCCESS;
	}
	else
	{
	    return GLOBUS_SUCCESS;
	}
    }
    else
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
    }
}
/* globus_l_gram_job_manager_eval_one_attribute() */
    
static
int
globus_l_gram_job_manager_create_scratchdir(
    globus_gram_jobmanager_request_t *	request,
    const char *			scratch_dir_base,
    globus_symboltable_t *		symbol_table,
    globus_rsl_t *			rsl_tree)
{
    int					rc;
    const char *			base = scratch_dir_base
	                                    ? scratch_dir_base
					    : graml_env_home;
    char *				tmp_scratch;

    rc = globus_l_gram_job_manager_eval_one_attribute(
	    rsl_tree,
	    "scratchdir",
	    symbol_table,
	    &tmp_scratch);

    if(rc != GLOBUS_SUCCESS || tmp_scratch == GLOBUS_NULL)
    {
	return rc;
    }

    if(tmp_scratch[0] == '/')
    {
	request->scratch_dir_base = globus_libc_strdup(tmp_scratch);
    }
    else
    {
	request->scratch_dir_base = globus_libc_malloc(
		strlen(base) + strlen(tmp_scratch) + 2);
	sprintf(request->scratch_dir_base, "%s/%s", base, request->scratch_dir_base);


    }
    /* This will fill request->scratchdir from the script */
    rc = globus_jobmanager_request_scratchdir(request);

    /* Insert the new value of scratchdir into the symbol table */
    globus_symboltable_insert(symbol_table,
			      "SCRATCH_DIRECTORY",
			      request->scratchdir);
    return rc;
}
/* globus_l_gram_job_manager_create_scratchdir() */

static
int
globus_l_gram_job_manager_rsl_match(
    void *				datum,
    void *				arg)
{
    globus_rsl_t *			relation = datum;
    char *				attribute = arg;
    char *				test;

    test = globus_rsl_relation_get_attribute(relation);

    return (strcmp(test, attribute)==0);
}
/* globus_l_gram_job_manager_rsl_match() */

/**
 * Merge two sets of RSL relations.
 *
 * Create a new RSL consisting of the merging of the base_rsl and override_rsl.
 * The result after completion is one RSL containing all of the relations
 * from the base_rsl and the override_rsl with any conflicting definitions
 * resolved by the override_rsl winning. The base_rsl and override_rsl
 * are unmodified in this process.
 */
static
globus_rsl_t *
globus_l_gram_job_manager_merge_rsl(
    globus_rsl_t *			base_rsl,
    globus_rsl_t *			override_rsl)
{
    globus_rsl_t *			tmp;
    globus_list_t **			base_relations;
    globus_list_t *			override_relations;
    globus_rsl_t *			result;
    char *				attribute;
    globus_list_t *			node;

    globus_assert(globus_rsl_is_boolean_and(base_rsl));
    globus_assert(globus_rsl_is_boolean_and(override_rsl));

    result = globus_rsl_copy_recursive(base_rsl);

    base_relations = globus_rsl_boolean_get_operand_list_ref(result);
    override_relations = globus_rsl_boolean_get_operand_list(override_rsl);

    while(!globus_list_empty(override_relations))
    {
	tmp = globus_list_first(override_relations);
	override_relations = globus_list_rest(override_relations);
	attribute = globus_rsl_relation_get_attribute(tmp);

	node = globus_list_search_pred(*base_relations,
		                       globus_l_gram_job_manager_rsl_match,
				       attribute);
	if(node)
	{
	    globus_rsl_free_recursive(globus_list_remove(base_relations, node));
	}
	globus_list_insert(base_relations, globus_rsl_copy_recursive(tmp));
    }
    return result;
}
/* globus_l_gram_job_manager_merge_rsl() */

static
int
globus_l_gram_job_manager_create_remote_io_file(
    globus_gram_jobmanager_request_t *	request,
    char *				remote_io_url,
    char *				cache_tag)
{
    FILE *				fp;
    unsigned long			timestamp;
    char *				fname;
    char *				tmp_buffer;
    globus_bool_t			cache_locked = GLOBUS_FALSE;
    int					rc;

    tmp_buffer = globus_libc_malloc(strlen("%sdev/remote_io_url") +
	                            strlen(cache_tag));
    if(!tmp_buffer)
    {
	goto error_exit;
    }

    globus_libc_sprintf(
	    tmp_buffer,
	    "%sdev/remote_io_url",
	    cache_tag);

    rc = globus_gass_cache_add(&request->cache_handle,
			       tmp_buffer,
			       cache_tag,
			       GLOBUS_TRUE,
			       &timestamp,
			       &fname);

    if(rc != GLOBUS_GASS_CACHE_ADD_EXISTS &&
       rc != GLOBUS_GASS_CACHE_ADD_NEW)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JM: error adding remote io url file cache entry\n");

	goto free_buffer_exit;
    }

    cache_locked = GLOBUS_TRUE;

    fp = fopen( fname, "w" );

    if (fp == NULL)
    {
	globus_jobmanager_log( request->jobmanager_log_fp,
		       "JM: error opening remote io url file\n");

	goto cache_remove_exit;
    }
    graml_remote_io_url_file = (char *)globus_libc_strdup(fname);

    fprintf( fp, "%s\n", graml_remote_io_url );

    fclose( fp );

    rc = globus_gass_cache_add_done(&request->cache_handle,
				    tmp_buffer,
				    request->cache_tag,
				    timestamp);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JM: error completing remote io url file cache entry add\n");

	goto free_remote_io_url_file;
    }

    cache_locked = GLOBUS_FALSE;

    rc = globus_l_gram_rsl_env_add(
	    request->rsl,
	    "GLOBUS_REMOTE_IO_URL",
	    graml_remote_io_url_file);
    
    if(rc != GLOBUS_SUCCESS)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JM: error updating RSL with remote io file environment\n");
	cache_locked = GLOBUS_FALSE;

	goto free_remote_io_url_file;
    }

    globus_libc_free(fname);
    globus_libc_free(tmp_buffer);

    return GLOBUS_SUCCESS;

free_remote_io_url_file:
    globus_libc_free(graml_remote_io_url_file);
    graml_remote_io_url_file = GLOBUS_NULL;

cache_remove_exit:
    globus_gass_cache_delete(
	    &request->cache_handle,
	    tmp_buffer,
	    cache_tag,
	    timestamp,
	    cache_locked);
    globus_libc_free(fname);

free_buffer_exit:
    globus_libc_free(tmp_buffer);

error_exit:
    return GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;
}
/* globus_l_gram_job_manager_create_remote_io_file() */
