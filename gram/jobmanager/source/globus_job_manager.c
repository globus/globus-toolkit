/******************************************************************************
globus_gram_job_manager.c 

Description:
    Resource Allocation Job Manager

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

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

#include <gssapi.h>
#include <globus_gss_assist.h>

#include "globus_nexus.h"
#include "globus_gram_client.h"
#include "globus_gram_job_manager.h"
#include "globus_i_gram_version.h"
#include "globus_i_gram_handlers.h"
#include "grami_fprintf.h"
#include "globus_rsl.h"
#include "globus_gass_file.h"
#include "globus_gass_cache.h"
#include "globus_gass_client.h"
#include "globus_duct_control.h"

/******************************************************************************
                               Type definitions
******************************************************************************/

typedef struct globus_l_gram_output_s
{
    off_t            last_written;
    off_t            last_size;
    char *           cache_file;
    globus_bool_t    ok;
    int              poll_frequency;
    int              poll_counter;
} globus_l_gram_output_t;

typedef struct globus_l_gram_client_contact_s
{
    char *           contact;
    int              job_state_mask;
    int              failed_count;
} globus_l_gram_client_contact_t;

typedef struct globus_l_gram_conf_values_s
{
    char *    type;
    char *    condor_arch;
    char *    condor_os;
    char *    rdn;
    char *    host_dn;
    char *    org_dn;
    char *    gate_dn;
    char *    gate_host;
    char *    gate_port;
    char *    gate_subject;
    char *    host_osname;
    char *    host_osversion;
    char *    host_cputype;
    char *    host_manufacturer;
    char *    x509_cert_dir;
    char *    install_path;
    char *    deploy_path;
    char *    tools_path;
    char *    services_path;
    int       num_env_adds;
} globus_l_gram_conf_values_t;

/* Only poll once every GRAM_JOB_MANAGER_POLL_FREQUENCY seconds */
#define GRAM_JOB_MANAGER_POLL_FREQUENCY 10

/* Only do status file cleanup once every 
 * GRAM_JOB_MANAGER_STAT_FREQUENCY seconds
 */
#define GRAM_JOB_MANAGER_STAT_FREQUENCY 60

/******************************************************************************
                          Module specific prototypes
******************************************************************************/

static int
globus_l_gram_jm_read(int fd, globus_byte_t *buffer, size_t length);

static int
globus_l_gram_jm_write(int fd, globus_byte_t *buffer, size_t length);

char *
globus_i_filename_callback_func(int stdout_flag);

static void 
globus_l_gram_cancel_handler(nexus_endpoint_t * endpoint,
                             nexus_buffer_t * buffer,
                             globus_bool_t is_non_threaded_handler);

static void
globus_l_gram_status_handler(nexus_endpoint_t * endpoint,
                             nexus_buffer_t * buffer,
                             globus_bool_t is_non_threaded_handler);

static void 
globus_l_gram_register_handler(nexus_endpoint_t * endpoint,
                               nexus_buffer_t * buffer,
                               globus_bool_t is_non_threaded_handler);

static void 
globus_l_gram_unregister_handler(nexus_endpoint_t * endpoint,
                                 nexus_buffer_t * buffer,
                                 globus_bool_t is_non_threaded_handler);

static void 
globus_l_gram_start_time_handler(nexus_endpoint_t * endpoint,
                                 nexus_buffer_t * buffer,
                                 globus_bool_t is_non_threaded_handler);

static int 
globus_l_gram_attach_requested(void * arg,
                               char * url,
                               nexus_startpoint_t * sp);

static int 
globus_l_gram_status_file_gen(char * request_string,
                              char * job_status_file_path,
                              char * globus_id,
                              char * job_id);

static char *
globus_l_gram_genfilename(char * prefix,
                          char * path,
                          char * sufix);

static int
globus_l_gram_stage_file(char *url,
                         char **staged_file_path,
                         int mode);

static int
globus_l_gram_rsl_env_add(globus_rsl_t * ast_node,
                          char * var,
                          char * value);

static int
globus_l_gram_duct_environment(int count,
			       char *myjob,
			       char **newvar,
			       char **newval);
static void 
globus_l_gram_client_callback(int status, int failure_code);

static int 
globus_l_gram_request_fill(globus_rsl_t * rsl_tree,
                           globus_gram_jobmanager_request_t * req);

static int 
globus_l_gram_request_environment_append(globus_gram_jobmanager_request_t * req,
                                         globus_l_gram_conf_values_t * conf);

static int
globus_l_gram_client_contact_list_free(globus_list_t * contact_list);

static void
globus_l_gram_check_file_list(int check_fd,
                              globus_list_t * file_list);

static void
globus_l_gram_delete_file_list(int check_fd,
                               globus_list_t ** file_list);

static int
globus_l_gram_check_file(int out_fd,
                         globus_l_gram_output_t * output);

static char *
globus_l_gram_getenv_var(char * env_var_name,
                         char * default_name);

static char *
globus_l_gram_user_proxy_relocate();

static void
globus_l_gram_status_file_cleanup(char * job_status_dir);

static int
globus_l_gram_tokenize(char * command,
                       char ** args,
                       int * n);

static void 
globus_l_gram_conf_values_init(globus_l_gram_conf_values_t * conf);

/******************************************************************************
                       Define variables for external use
******************************************************************************/

extern int errno;

/******************************************************************************
                       Define module specific variables
******************************************************************************/

/* In threaded nexus, nexus_attach() will deadlock if the called from a
 * non-threaded handler
 */
static globus_nexus_handler_t graml_handlers[] =
{ 
#ifdef BUILD_LITE
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED, globus_l_gram_cancel_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED, globus_l_gram_start_time_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED, globus_l_gram_status_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED, globus_l_gram_register_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED, globus_l_gram_unregister_handler},
#else
    {GLOBUS_NEXUS_HANDLER_TYPE_THREADED, globus_l_gram_cancel_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_THREADED, globus_l_gram_start_time_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_THREADED, globus_l_gram_status_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_THREADED, globus_l_gram_register_handler},
    {GLOBUS_NEXUS_HANDLER_TYPE_THREADED, globus_l_gram_unregister_handler},
#endif  /* BUILD_LITE */
};

/*
 *                                                reason needed
 *                                                --------------
 */
static char * graml_env_x509_user_proxy = NULL;   /* security */
static char * graml_env_krb5ccname = NULL;        /* security */
static char * graml_env_nlspath = NULL;           /* poe fork */
static char * graml_env_logname = NULL;           /* all */
static char * graml_env_home = NULL;              /* all */
static char * graml_env_tz = NULL;                /* all */


/*
 * other GRAM local variables 
 */
static FILE *         graml_log_fp = NULL;
static char *         graml_job_contact = NULL;
static char *         graml_env_globus_id = NULL;
static globus_rsl_t * graml_rsl_tree = NULL;

/* gass cache handle */
static globus_gass_cache_t         globus_l_cache_handle;

/* structures to manage line-buffered stdout and stderr */
static globus_list_t *  globus_l_gram_stdout_files = GLOBUS_NULL;
static globus_list_t *  globus_l_gram_stderr_files = GLOBUS_NULL;
static int              globus_l_gram_stdout_fd=-1;
static int              globus_l_gram_stderr_fd=-1;

globus_list_t *  globus_l_gram_client_contacts = GLOBUS_NULL;

static int                         graml_my_count;
static nexus_endpointattr_t        graml_EpAttr;
static nexus_endpoint_t            graml_GlobalEndpoint;
static globus_mutex_t              graml_api_mutex;
static int                         graml_api_mutex_is_initialized = 0;
static int                         graml_jm_done = 0;
static int                         graml_stdout_count;
static int                         graml_stderr_count;
 
#define GRAM_LOCK { \
    int err; \
    assert (graml_api_mutex_is_initialized==1); \
    err = globus_mutex_lock (&graml_api_mutex); assert (!err); \
}

#define GRAM_UNLOCK { \
    int err; \
    err = globus_mutex_unlock (&graml_api_mutex); assert (!err); \
}

/******************************************************************************
Function:       main()
Description:
Parameters:
Returns:
******************************************************************************/
int 
main(int argc,
     char **argv)
{
    int                    i;
    int                    x;
    int                    tag_index;
    int                    size;
    int                    rc;
    int                    len;
    int                    length;
    int                    count;
    int                    gram_version;
    int                    job_state_mask;
    int                    n_nodes;
    int                    format;
    int                    job_status;
    int                    message_handled;
    int                    print_debug_flag = 0;
    int                    skip_poll = 0;
    int                    skip_stat = 0;
    int                    tmp_status;
    int                    publish_jobs_flag = 0;
    char                   rsl_spec[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
    char                   read_rsl_file[256];
    char                   write_rsl_file[256];
    char                   tmp_buffer[256];
    char                   job_status_file_path[512];
    char *                 job_status_dir = GLOBUS_NULL;
    char *                 home_dir = NULL;
    char *                 tmp_ptr;
    char *                 client_contact_str;
    char *                 my_host;
    char *                 dash_pos;
    char *                 libexecdir;
    char *                 final_rsl_spec = GLOBUS_NULL;
    unsigned short         my_port;
    FILE *                 args_fp;
    FILE *                 fp;
    FILE *                 test_fp;
    struct stat            statbuf;
    globus_byte_t          type;
    globus_byte_t *        ptr;
    globus_byte_t                       buffer[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
    globus_nexus_buffer_t               reply_buffer;
    globus_nexus_startpoint_t           reply_sp;
    globus_rsl_t *                      rsl_tree;
    globus_gass_cache_entry_t *         cache_entries;
    int                                 cache_size;
    globus_symboltable_t *              symbol_table; 
    globus_gram_jobmanager_request_t *  request;
    globus_bool_t                       jm_request_failed = GLOBUS_FALSE;
    globus_l_gram_client_contact_t *    client_contact_node;
    globus_l_gram_conf_values_t         conf;
    globus_result_t                     error;
	
    /* gssapi */

    OM_uint32			major_status = 0;
    OM_uint32			minor_status = 0;
    int					token_status = 0;
    gss_ctx_id_t		context_handle = GSS_C_NO_CONTEXT;
    char				tmp_version[64];
	
    char *				jrbuf;
    size_t				jrbuf_size;

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

    rc = globus_module_activate(GLOBUS_NEXUS_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "nexus activation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_activate(GLOBUS_GASS_CLIENT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_client activation failed with rc=%d\n", rc);
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

    rc = globus_module_activate(GLOBUS_GRAM_JOBMANAGER_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "%s activation failed with rc=%d\n",
		GLOBUS_GRAM_JOBMANAGER_MODULE->module_name, rc);
	exit(1);
    }

    globus_nexus_enable_fault_tolerance(NULL, NULL);

    if ( graml_api_mutex_is_initialized == 0 )
    {
        /* initialize mutex which makes the client thread-safe */
        int err;
		 
        err = globus_mutex_init (&graml_api_mutex, NULL); assert (!err);
        graml_api_mutex_is_initialized = 1;
    }

    GRAM_LOCK;

    *read_rsl_file = '\0';
    *write_rsl_file = '\0';
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

    /*
     * Parse the command line arguments
     */
    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-read_rsl_file") == 0)
                 && (i + 1 < argc))
        {
            strcpy(read_rsl_file, argv[i+1]); i++;
        }
        else if ((strcmp(argv[i], "-write_rsl_file") == 0)
                 && (i + 1 < argc))
        {
            strcpy(write_rsl_file, argv[i+1]); i++;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            print_debug_flag = 1;
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
        else if (strcmp(argv[i], "-publish_jobs") == 0)
        {
            publish_jobs_flag = 1;
        }
        else if ((strcmp(argv[i], "-condor_arch") == 0)
                 && (i + 1 < argc))
        {
            conf.condor_arch = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-condor_os") == 0)
                 && (i + 1 < argc))
        {
            conf.condor_os = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_org_dn") == 0)
                 && (i + 1 < argc))
        {
            conf.org_dn = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_gatekeeper_host") == 0)
                 && (i + 1 < argc))
        {
            conf.gate_host = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_gatekeeper_port") == 0)
                 && (i + 1 < argc))
        {
            conf.gate_port = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_gatekeeper_subject") == 0)
                 && (i + 1 < argc))
        {
            conf.gate_subject = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-rdn") == 0)
                 && (i + 1 < argc))
        {
            conf.rdn = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_host_dn") == 0)
                 && (i + 1 < argc))
        {
            conf.host_dn = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_host_manufacturer") == 0)
                 && (i + 1 < argc))
        {
            conf.host_manufacturer = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_host_cputype") == 0)
                 && (i + 1 < argc))
        {
            conf.host_cputype = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_host_osname") == 0)
                 && (i + 1 < argc))
        {
            conf.host_osname = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_host_osversion") == 0)
                 && (i + 1 < argc))
        {
            conf.host_osversion = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcmp(argv[i], "-globus_install_path") == 0)
                 && (i + 1 < argc))
        {
            conf.install_path = globus_libc_strdup(argv[i+1]); i++;
            conf.num_env_adds++;
        }
        else if ((strcasecmp(argv[i], "-help" ) == 0) ||
                 (strcasecmp(argv[i], "--help") == 0))
        {
            fprintf(stderr, "Usage: %s\n", argv[0]);
            fprintf(stderr, "\n");
            fprintf(stderr, "Required Arguments:\n");
            fprintf(stderr, "\t-type jobmanager type, i.e. fork, lsf ...\n");
            fprintf(stderr, "\t-rdn relative domain name\n");
            fprintf(stderr, "\t-globus_org_dn organization's domain name\n");
            fprintf(stderr, "\t-globus_host_dn host domain name\n");
            fprintf(stderr, "\t-globus_host_manufacturer manufacturer\n");
            fprintf(stderr, "\t-globus_host_cputype cputype\n");
            fprintf(stderr, "\t-globus_host_osname osname\n");
            fprintf(stderr, "\t-globus_host_osversion osversion\n");
            fprintf(stderr, "\t-globus_gatekeeper_host host\n");
            fprintf(stderr, "\t-globus_gatekeeper_port port\n");
            fprintf(stderr, "\t-globus_gatekeeper_subject subject\n");
            fprintf(stderr, "\nNon-required Arguments:\n");
            fprintf(stderr, "\t-home deploy dir\n");
            fprintf(stderr, "\t-e libexec dir\n");
            fprintf(stderr, "\t-e globus_install_path dir\n");
            fprintf(stderr, "\t-e condor_arch arch, i.e. SUN4x\n");
            fprintf(stderr, "\t-e condor_os os, i.e. SOLARIS26\n");
            fprintf(stderr, "\t-d write a log file in the users home dir\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "Note: if type=condor then\n");
            fprintf(stderr, "      -condor_os & -condor_arch are required.\n");
            fprintf(stderr, "\n");
            exit(1);
        }
        else
        {
            fprintf(stderr, "Warning: Ignoring unknown argument %s\n", argv[i]);
            fprintf(stderr, "\n");
        }
    }

    if (globus_jobmanager_request_init(&request) != GLOBUS_SUCCESS)
    {
        fprintf(stderr, 
            "ERROR: globus_jobmanager_request_init() failed.\n");
        exit(1);
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

    if (! conf.rdn)
    {
        grami_fprintf( request->jobmanager_log_fp,
            "JM: -rdn parameter required\n");
        return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
    }

    if (print_debug_flag)
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
                GRAM_UNLOCK;
                fprintf(stderr, "JM: Cannot open gram logfile.\n");
                exit(1);
            }
        }
        graml_log_fp = request->jobmanager_log_fp;
		setbuf(request->jobmanager_log_fp,NULL);
    }
    else
    {
        strcpy(tmp_buffer, "/dev/null");
    }

    request->jobmanager_logfile = (char *) globus_libc_strdup(tmp_buffer);

    grami_fprintf( request->jobmanager_log_fp,
          "-----------------------------------------\n");
    grami_fprintf( request->jobmanager_log_fp,
          "JM: Entering gram_job_manager main().\n");

    if (conf.type == GLOBUS_NULL)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: Jobmanager service misconfigured. "
              "jobmanager Type not defined.\n");
	return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
    }
    
    request->jobmanager_type = (char *) globus_libc_strdup(conf.type);

    if (strcasecmp(request->jobmanager_type, "condor") == 0)
    {
        if (conf.condor_arch == NULL)
        {
            grami_fprintf( request->jobmanager_log_fp,
                "JMI: Condor_arch must be specified when "
                "jobmanager type is condor\n");
	   return(GLOBUS_GRAM_CLIENT_ERROR_CONDOR_ARCH);
        }
        if (conf.condor_os == NULL)
        {
           grami_fprintf( request->jobmanager_log_fp,
                "JMI: Condor_os must be specified when "
                "jobmanager type is condor\n");
	   return(GLOBUS_GRAM_CLIENT_ERROR_CONDOR_OS);
        }
        request->condor_arch = conf.condor_arch;
        request->condor_os = conf.condor_os;
    }

    /* tell the API to use this callback function for filenames */
    request->filename_callback_func = (globus_gram_job_manager_callback_func_t)
        globus_i_filename_callback_func;

    grami_fprintf( request->jobmanager_log_fp,
          "JM: HOME = %s\n", graml_env_home);

    graml_env_logname = globus_l_gram_getenv_var("LOGNAME", "noname");

    graml_env_globus_id =
         globus_l_gram_getenv_var("GLOBUS_ID", "unknown globusid");
 
    /*
     * Getting environment variables to be added to the job's environment.
     * LOGNAME and HOME will be added as well
     */
    conf.x509_cert_dir    = globus_l_gram_getenv_var("X509_CERT_DIR", NULL);
    graml_env_krb5ccname  = globus_l_gram_getenv_var("KRB5CCNAME", NULL);
    graml_env_nlspath     = globus_l_gram_getenv_var("NLSPATH", NULL);
    graml_env_tz          = globus_l_gram_getenv_var("TZ", NULL);

    if (conf.x509_cert_dir)
    {
       conf.num_env_adds++;
    }

    /*
     * Getting the paths to the (relocatable) deploy and install trees.
     */

    if (home_dir)
        conf.deploy_path = globus_libc_strdup(home_dir);
    else
    {
        error = globus_common_deploy_path(&conf.deploy_path);
        if (error != GLOBUS_SUCCESS)
        {
            grami_fprintf( request->jobmanager_log_fp,
                "JM: globus_common_deploy_path failed \n");
            return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
        }
    }

    grami_fprintf( request->jobmanager_log_fp,
        "JM: GLOBUS_DEPLOY_PATH = %s\n",
        (conf.deploy_path) ? (conf.deploy_path) : "NULL");
    conf.num_env_adds++;

    if (!conf.install_path)
    {
	error = globus_common_install_path_from_config_file(
	    conf.deploy_path,
	    &conf.install_path );
	if (error != GLOBUS_SUCCESS)
	{
	    grami_fprintf( request->jobmanager_log_fp,
		   "JM: failed to get GLOBUS_INSTALL_PATH from config file\n");
	    return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
	}
        conf.num_env_adds++;
    }

    grami_fprintf( request->jobmanager_log_fp,
	   "JM: GLOBUS_INSTALL_PATH = %s\n",
	   (conf.install_path) ? (conf.install_path) : "NULL");

    globus_libc_setenv("GLOBUS_INSTALL_PATH",
		       conf.install_path,
		       GLOBUS_TRUE);

    globus_libc_setenv("GLOBUS_DEPLOY_PATH",
		       conf.deploy_path,
		       GLOBUS_TRUE);

    error = globus_common_tools_path( &conf.tools_path );
    if (error != GLOBUS_SUCCESS)
    {
	grami_fprintf( request->jobmanager_log_fp,
		       "JM: globus_common_tools_path failed\n");
	return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
    }
    conf.num_env_adds++;
    
    error = globus_common_services_path( &conf.services_path );
    if (error != GLOBUS_SUCCESS)
    {
	grami_fprintf( request->jobmanager_log_fp,
		       "JM: globus_common_services_path failed\n");
	return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
    }
    conf.num_env_adds++;

    if (libexecdir)
    {
        request->jobmanager_libexecdir = 
            globus_l_gram_genfilename(conf.deploy_path, libexecdir, NULL);
    }
    else
    {
        request->jobmanager_libexecdir = 
            globus_l_gram_genfilename(conf.deploy_path, "libexec", NULL);
    }

    grami_fprintf( request->jobmanager_log_fp,
          "JM: jobmanager_libexecdir = %s\n", request->jobmanager_libexecdir);

    /*
     *  if a read_rsl_file has been defined, read data from the file 
     *  instead of from stdin.
     *  This is just the data, no length field.
     *  DEE We could change this if needed. 
     *  In this case, there is not client, and no security
     *  context to import.  
     */

    if (strlen(read_rsl_file) > 0)
    {
        int args_fd;

        if ((args_fd = open(read_rsl_file, O_RDONLY)) == -1)
        {
            GRAM_UNLOCK;
            grami_fprintf( request->jobmanager_log_fp,
                  "JM: Cannot open test file %s.\n", read_rsl_file);
            exit(1);
        }
        jrbuf_size = lseek(args_fd, 0, SEEK_END);
        lseek(args_fd, 0, SEEK_SET);
        if (jrbuf_size > GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE) 
        {
            grami_fprintf( request->jobmanager_log_fp,
                "JM: test file to big\n");
            exit (1);
        }
        if (read(args_fd, buffer, jrbuf_size) != jrbuf_size)
        {
            grami_fprintf( request->jobmanager_log_fp,
                "JM: Error reading the test file\n");
            exit (1);
        }
        (void *) close(args_fd);
    }
    else
    {
        /*
         * Stdin and stdout point at the client socket.
         * Gatekeeper has done authentication and authorization
         * we will now import security context,
         * send version number, then get the job
         * request buffer using gssapi wrap and unwrap
         */

        if (globus_gss_assist_import_sec_context(&minor_status,
                                                &context_handle,
                                                &token_status,
                                                -1,
                            request->jobmanager_log_fp) != GSS_S_COMPLETE)
        {
            grami_fprintf( request->jobmanager_log_fp,
                "JM:Failed to load security context\n");
            return(GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
        }

        grami_fprintf(request->jobmanager_log_fp,
            "JM: context loaded\n");

        /* context loaded */
        /* Send the version number */

        sprintf(tmp_version,"VERSION=%d\n\0", GLOBUS_GRAM_PROTOCOL_VERSION);

        if (globus_gss_assist_wrap_send( &minor_status,
                                         context_handle,
                                         tmp_version,
                                         strlen(tmp_version)+1,
                                         &token_status,
                                         globus_gss_assist_token_send_fd,
                                         stdout,
                                         request->jobmanager_log_fp)
           != GSS_S_COMPLETE)
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
        }

        grami_fprintf(request->jobmanager_log_fp,"JM: version sent\n");

        /* Get the job request from client as wrapped message */

        major_status = globus_gss_assist_get_unwrap(&minor_status,
                                                context_handle,
                                                &jrbuf,
                                                &jrbuf_size,
                                                &token_status,
                                                globus_gss_assist_token_get_fd,
                                                stdin,
                                                request->jobmanager_log_fp);

        if (major_status != GSS_S_COMPLETE)
        {
            grami_fprintf(request->jobmanager_log_fp,
                "JM: get_unwraped failed\n");
            return(GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
        }

        grami_fprintf(request->jobmanager_log_fp,
                "JM: Got wrap size=%ld\n",
                jrbuf_size);

        if (jrbuf_size > GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE)
        {
            grami_fprintf( request->jobmanager_log_fp,
                "JM: Job request to big\n");
            return(GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
        }

        /* copy request to buffer so rest of code is not changed much */

        memcpy(buffer, jrbuf, jrbuf_size);
        free(jrbuf);
        jrbuf = NULL;
    }

    /*
     *  if a test_dat_file has been defined, pass data to the file and
     *  return immediately.
     */
    if (strlen(write_rsl_file) > 0)
    {
        /*
         * Open the test jm data file
         */
        if ((test_fp = fopen(write_rsl_file, "w")) == NULL)
        {
	    grami_fprintf( request->jobmanager_log_fp,
		       "JM: Cannot open test data file\n");
            exit(1);
        }
        setbuf(test_fp, NULL);

        /*
         * Pass the message data on to the test data file
         */
        fwrite(buffer, 1, jrbuf_size, test_fp);
        fclose(test_fp);

        exit(0);
    }

    ptr = buffer;

    /*
     * Read the format incoming message.
     */
    format = (int)*ptr;
    ptr++;

    globus_nexus_user_get_int(&ptr, &gram_version, 1, format);

    if (GLOBUS_GRAM_PROTOCOL_VERSION != gram_version)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: ERROR: globus gram protocol version mismatch!\n");
        grami_fprintf( request->jobmanager_log_fp,
              "JM: gram client version      = %d\n", gram_version);
        grami_fprintf( request->jobmanager_log_fp,
              "JM: gram protocol version = %d\n",
              GLOBUS_GRAM_PROTOCOL_VERSION);
        fprintf(stderr, "ERROR: globus gram protocol version mismatch!\n");
        fprintf(stderr, "gram client version      = %d\n", gram_version);
        fprintf(stderr, "gram job manager version = %d\n",
                                                 GLOBUS_GRAM_PROTOCOL_VERSION);
        return(GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH);
    }

    /*
     * Read the size incoming message.
     */
    globus_nexus_user_get_int(&ptr, &count, 1, format);

    globus_nexus_user_get_int(&ptr, &len, 1, format);
    globus_nexus_user_get_char(&ptr, rsl_spec, len, format);
    *(rsl_spec+len)= '\0';
    globus_nexus_user_get_int(&ptr, &job_state_mask, 1, format);
    globus_nexus_user_get_int(&ptr, &len, 1, format);
    if (len > 0)
    {
        client_contact_str = globus_libc_malloc (sizeof(char)*(len + 1));
        globus_nexus_user_get_char(&ptr, client_contact_str, len, format);
        client_contact_str[len] = '\0';

        client_contact_node = (globus_l_gram_client_contact_t *)
            globus_libc_malloc(sizeof(globus_l_gram_client_contact_t));

        client_contact_node->contact        = client_contact_str;
        client_contact_node->job_state_mask = job_state_mask;
        client_contact_node->failed_count   = 0;

        globus_list_insert(&globus_l_gram_client_contacts,
                       (void *) client_contact_node);

        grami_fprintf( request->jobmanager_log_fp,
              "JM: client contact = %s\n", client_contact_str);
    }
    globus_nexus_user_get_startpoint(&ptr, &reply_sp, 1, format);

    grami_fprintf( request->jobmanager_log_fp,
          "JM: rsl_specification = %s\n", rsl_spec);
    grami_fprintf( request->jobmanager_log_fp,
          "JM: job status mask = %d\n",job_state_mask);

    /*
     * Create an endpoint that will be used by globus_l_gram_attach_requested
     * when other attach to this job manager
     */
    globus_nexus_endpointattr_init(&graml_EpAttr);
    globus_nexus_endpointattr_set_handler_table(&graml_EpAttr,
                         graml_handlers,
                         sizeof(graml_handlers)/sizeof(globus_nexus_handler_t));
    globus_nexus_endpoint_init(&graml_GlobalEndpoint, &graml_EpAttr);
    globus_nexus_endpoint_set_user_pointer(&graml_GlobalEndpoint, request);

    /* allow other Nexus programs to attach to us */
    my_port = 0;
    rc = globus_nexus_allow_attach(&my_port,                /* port      */
                            &my_host,                       /* host      */
                            globus_l_gram_attach_requested, /*approval_func()*/
                            NULL);
    if (rc != 0)
    {
        GRAM_UNLOCK;
        return(GLOBUS_GRAM_CLIENT_ERROR_JM_FAILED_ALLOW_ATTACH);
    }
    else
    {
        sprintf(tmp_buffer, "x-nexus://%s:%hu/%lu/%lu/",
                              my_host,
                              my_port,
                              (unsigned long) getpid(),
                              (unsigned long) time(0));

        graml_job_contact = (char *) globus_libc_strdup (tmp_buffer);

        grami_setenv("GLOBUS_GRAM_JOB_CONTACT", graml_job_contact, 1);
        conf.num_env_adds++;
    }

    /* call the RSL routine to parse the user request
     */
    rsl_tree = globus_rsl_parse(rsl_spec);
    if (!rsl_tree)
    {
        rc = GLOBUS_FAILURE;
        request->failure_code = GLOBUS_GRAM_CLIENT_ERROR_BAD_RSL;
    }
    else
    {

        /* printf("\n------------  after parse  ---------------\n\n");
         * globus_rsl_print_recursive(rsl_tree);
         */

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
        if (conf.deploy_path)
	{
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_DEPLOY_PREFIX",
                                (void *) conf.deploy_path);
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_DEPLOY_PATH",
                                (void *) conf.deploy_path);
	}
        if (conf.install_path)
	{
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_INSTALL_PREFIX",
                                (void *) conf.install_path);
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_INSTALL_PATH",
                                (void *) conf.install_path);
	}
        if (conf.tools_path)
	{
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_TOOLS_PREFIX",
                                (void *) conf.tools_path);
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_TOOLS_PATH",
                                (void *) conf.tools_path);
	}
        if (conf.services_path)
	{
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_SERVICES_PREFIX",
                                (void *) conf.services_path);
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_SERVICES_PATH",
                                (void *) conf.services_path);
	}
    
        if (globus_rsl_eval(rsl_tree, symbol_table) != 0)
        {
            rc = GLOBUS_FAILURE;
            request->failure_code = 
                 GLOBUS_GRAM_CLIENT_ERROR_RSL_EVALUATION_FAILED;
        }

    }

    if (rc == GLOBUS_SUCCESS)
    {
        rc = globus_gass_cache_open(NULL, &globus_l_cache_handle);

        if( rc != GLOBUS_SUCCESS )
        {
            request->failure_code = GLOBUS_GRAM_CLIENT_ERROR_OPENING_CACHE;
        }

    }
 
    if (rc == GLOBUS_SUCCESS)
    {
        /* fill the request structure with values from the RSL
         */
        rc = globus_l_gram_request_fill(rsl_tree, request);
    }

    if (rc == GLOBUS_SUCCESS)
    {
        /*
         * append to the req->environment with values from the conf file
         */
        rc = globus_l_gram_request_environment_append(request, &conf);
    }

    if (rc == GLOBUS_SUCCESS)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: opening stdout fd\n");

        /* open "real" stdout descriptor
         */
        globus_l_gram_stdout_fd = globus_gass_open(request->my_stdout,
                                           O_WRONLY|O_APPEND|O_CREAT,
                                           0777);
        if (globus_l_gram_stdout_fd < 0)
        {
            request->failure_code = GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDOUT;
            rc = GLOBUS_FAILURE;
	    grami_fprintf( request->jobmanager_log_fp,
			   "JM: error opening outfile \n");
        }
	else
	{
	    if (request->my_stdout_tag != GLOBUS_NULL)
	    {
		char * filename;
		unsigned long timestamp;
		/* try to add the specific tag to the cache entry */
		/* will prevent automatic deletion of the stdout  */
		/* when the job finish; usefull for "batch jobs"  */
		/* Use the option Do Not Create: I want to add it */
		/* to the cache only if I have an x-gass-cache URL*/
		/* (in which case the globus_open(stdout) has     */
		/* previously created this cache entry.           */
		rc = globus_gass_cache_add(&globus_l_cache_handle,
					   request->my_stdout,
					   request->my_stdout_tag,
					   GLOBUS_FALSE,           
					   &timestamp,
					   &filename);
		if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
		{
		    rc = globus_gass_cache_add_done(&globus_l_cache_handle,
					       request->my_stdout,
					       request->my_stdout_tag,
					       timestamp);
		    if (rc != GLOBUS_SUCCESS)
		    {
			request->failure_code =
			    GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDOUT;
			grami_fprintf( request->jobmanager_log_fp,
				       "JM: error add done stdout tag \n");
		    }
		    else
		    {
			globus_free(filename);
			rc = GLOBUS_SUCCESS;
		    }
		}
		else
		{
		    if (rc != GLOBUS_GASS_CACHE_URL_NOT_FOUND)
		    {
			request->failure_code =
			    GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDOUT;
			rc = GLOBUS_FAILURE;
			grami_fprintf( request->jobmanager_log_fp,
				       "JM: error adding stdout tag \n");
		    }
		    else
		    {
			rc = GLOBUS_SUCCESS;
		    }
		}
		
	    }
	}

    }

    if (rc == GLOBUS_SUCCESS)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: opening stderr fd\n");

        /* open "real" stderr descriptor
         */
	globus_l_gram_stderr_fd = globus_gass_open(request->my_stderr,
						   O_WRONLY|O_APPEND|O_CREAT,
						   0777);
	if (globus_l_gram_stderr_fd < 0)
	{
	    request->failure_code = GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDERR;
	    rc = GLOBUS_FAILURE;
	}	
	else
	{
	    if (request->my_stderr_tag != GLOBUS_NULL)
	    {
		char * filename;
		unsigned long timestamp;
		/* try to add the specific tag to the cache entry */
		/* will prevent automatic deletion of the stderr  */
		/* when the job finish; usefull for "batch jobs"  */
		/* Use the option Do Not Create: I want to add it */
		/* to the cache only if I have an x-gass-cache URL*/
		/* (in which case the globus_open(stderr) has     */
		/* previously created this cache entry.           */
		rc = globus_gass_cache_add(&globus_l_cache_handle,
					   request->my_stderr,
					   request->my_stderr_tag,
					   GLOBUS_FALSE,           
					   &timestamp,
					   &filename);
		if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
		{
		    rc = globus_gass_cache_add_done(&globus_l_cache_handle,
					       request->my_stderr,
					       request->my_stderr_tag,
					       timestamp);
		    if (rc != GLOBUS_SUCCESS)
		    {
			request->failure_code =
			    GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDERR;
			grami_fprintf( request->jobmanager_log_fp,
				       "JM: error add done stderr tag \n");
		    }
		    else
		    {
			globus_free(filename);
			rc = GLOBUS_SUCCESS;
		    }
		}
		else
		{
		    if (rc != GLOBUS_GASS_CACHE_URL_NOT_FOUND)
		    {
			request->failure_code =
			    GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDERR;
			rc = GLOBUS_FAILURE;
			grami_fprintf( request->jobmanager_log_fp,
				       "JM: error adding stderr tag \n");
		    }
		    else
		    {
			rc = GLOBUS_SUCCESS;
		    }
		}
	    }
	}
    }

    if (rc == GLOBUS_SUCCESS)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: user proxy relocation\n");
                            
        /* relocate the user proxy to the gass cache and 
         * return the local file name.
         */
        graml_env_x509_user_proxy = globus_l_gram_user_proxy_relocate(request);
        if (strlen(GLOBUS_GSSAPI_IMPLEMENTATION) > 0)
        {
            grami_fprintf( request->jobmanager_log_fp,
                  "JM: GSSAPI type is %s\n", GLOBUS_GSSAPI_IMPLEMENTATION);
                            
            if ((strncmp(GLOBUS_GSSAPI_IMPLEMENTATION, "ssleay", 6) == 0) &&
                (!graml_env_x509_user_proxy)) 
            {
                request->failure_code =
                    GLOBUS_GRAM_CLIENT_ERROR_USER_PROXY_NOT_FOUND;
               rc = GLOBUS_FAILURE;
            }
        }

        if (graml_env_x509_user_proxy)
        {
            for(x = 0; request->environment[x] != GLOBUS_NULL; x++)
            {
                ;
            }
            request->environment = (char **)
                globus_libc_realloc(request->environment,
                    (x+3) * sizeof(char *));

            request->environment[x] = "X509_USER_PROXY";
            ++x;
            request->environment[x] = graml_env_x509_user_proxy;
            ++x;
            request->environment[x] = GLOBUS_NULL;
        }
    }
    else
    {
        graml_env_x509_user_proxy = (char *) getenv("X509_USER_PROXY");
        if (graml_env_x509_user_proxy)
        {
            if (remove(graml_env_x509_user_proxy) != 0)
            {
                grami_fprintf( request->jobmanager_log_fp, 
                  "JM: Cannot remove user proxy file --> %s\n",
                  graml_env_x509_user_proxy);
            }
            else
            {
                grami_fprintf( request->jobmanager_log_fp, 
                  "JM: request failed at startup removed user proxy --> %s\n",
                  graml_env_x509_user_proxy);
            }
        }
    }

    fflush(request->jobmanager_log_fp);

    if (rc == GLOBUS_SUCCESS)
    {
        graml_rsl_tree = rsl_tree;
        rc = globus_jobmanager_request(request);
    }

    /*
     * If the request was successful reply with the job contact else
     * send error status.
     */
    if (rc == GLOBUS_SUCCESS)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: request was successful, sending message to client\n");
                            
        count= strlen(graml_job_contact);
	size = globus_nexus_sizeof_int(1);
	size += globus_nexus_sizeof_int(1);
	size += globus_nexus_sizeof_int(1);
	size += globus_nexus_sizeof_char(count);
	globus_nexus_buffer_init(&reply_buffer, size, 0);
        globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
        globus_nexus_put_int(&reply_buffer, &rc, 1);
        globus_nexus_put_int(&reply_buffer, &count, 1);
	globus_nexus_put_char(&reply_buffer, graml_job_contact, count);

        if (!request->job_id)
        {
            request->job_id = (char *) globus_libc_strdup ("UNKNOWN");
        }

        globus_nexus_send_rsr(&reply_buffer,
                       &reply_sp,
                       GLOBUS_I_GRAM_CLIENT_REPLY_HANDLER_ID,
                       GLOBUS_TRUE,
                       GLOBUS_FALSE);

        globus_nexus_startpoint_destroy(&reply_sp);

        /* send callback with the status */
        globus_l_gram_client_callback(request->status, request->failure_code);

        /* if we are publishing jobs, then setup the necessary variables */
        if (publish_jobs_flag)
        {
            if ((final_rsl_spec = globus_rsl_unparse(rsl_tree)) == GLOBUS_NULL)
            {
                final_rsl_spec = (char *) globus_libc_strdup("RSL UNKNOWN");
            }

            job_status_dir = globus_l_gram_genfilename(conf.deploy_path,
                                                                "tmp",
                                                                 NULL);
            sprintf(job_status_file_path, "%s/%s_%s.%s",
                                           job_status_dir,
                                           conf.rdn,
                                           graml_env_logname,
                                           request->job_id );

            grami_fprintf( request->jobmanager_log_fp,
                 "JM: job_status_file_path = %s\n", job_status_file_path);

            globus_l_gram_status_file_gen(final_rsl_spec,
                                          job_status_file_path,
                                          graml_env_globus_id,
                                          request->job_id);
        }

    }
    else
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: request failed, sending message to client\n");
                            
	size = globus_nexus_sizeof_int(2);
	globus_nexus_buffer_init(&reply_buffer, size, 0);
        globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
        globus_nexus_put_int(&reply_buffer, &request->failure_code, 1);

        globus_nexus_send_rsr(&reply_buffer,
                       &reply_sp,
                       GLOBUS_I_GRAM_CLIENT_REPLY_HANDLER_ID,
                       GLOBUS_TRUE,
                       GLOBUS_FALSE);

        globus_nexus_startpoint_destroy(&reply_sp);
	jm_request_failed = GLOBUS_TRUE;

    }
 
    GRAM_UNLOCK;

    if (!jm_request_failed)
    {
        if (request->poll_frequency == 0)
        {
            request->poll_frequency = GRAM_JOB_MANAGER_POLL_FREQUENCY;
        }

        grami_fprintf( request->jobmanager_log_fp,
              "JM: poll frequency = %d\n", request->poll_frequency);

        skip_poll = request->poll_frequency;
        skip_stat = GRAM_JOB_MANAGER_STAT_FREQUENCY;
        while (!graml_jm_done)
        {
            globus_libc_usleep(1000000);

            globus_nexus_fd_handle_events(GLOBUS_NEXUS_FD_POLL_NONBLOCKING_ALL, 
                                   &message_handled);
            GRAM_LOCK;

            /* handler may have occurred while we were unlocked,
	       so we need to poll file descriptors, etc
	       if state change occurred
	     */
            if ( (--skip_poll <= 0) || (graml_jm_done) )
            {
                /* check if cancel handler was called */
                if ( ! graml_jm_done )
                {
                    if (publish_jobs_flag)
                    {
                        /* touch the file so we know we did not crash */
                        if ( utime(job_status_file_path, NULL) != 0 )
                        {
                            if(errno == ENOENT)
                            {
                                grami_fprintf( request->jobmanager_log_fp,
                                    "JM: job status file not found, "
                                    "rewritting it with current status.\n");

                                globus_l_gram_status_file_gen(final_rsl_spec,
                                                         job_status_file_path,
                                                         graml_env_globus_id,
                                                         request->job_id);
                            }
                        }
                    }
                    rc = globus_jobmanager_request_check(request);

                    if ( rc == GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED ||
                         rc == GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED )
                    {
                        if (rc == GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED)
                        {
                            /* unable to get a status for the job.
                             * often the result of a broken poll script.
                             */
                            globus_jobmanager_request_cancel(request);
                            request->status=GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
                        }

                        if ((request->status ==
                                 GLOBUS_GRAM_CLIENT_JOB_STATE_DONE) ||
                            (request->status ==
                                 GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED))
                        {
                            grami_fprintf( request->jobmanager_log_fp,
                                "JM: request check returned DONE or FAILED\n");

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
                            GRAM_UNLOCK;
                            globus_l_gram_client_callback(tmp_status,
                                                       request->failure_code);
                            GRAM_LOCK;
                        }
                    }
                }
	    	skip_poll = request->poll_frequency;
	    }

            if ((request->status != GLOBUS_GRAM_CLIENT_JOB_STATE_DONE) &&
                (request->status != GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED))
            {
                globus_l_gram_check_file_list(globus_l_gram_stdout_fd,
                                         globus_l_gram_stdout_files);
                globus_l_gram_check_file_list(globus_l_gram_stderr_fd,
                                         globus_l_gram_stderr_files);
            }

	    if (--skip_stat <= 0)
	    {
                globus_l_gram_status_file_cleanup(job_status_dir);
		skip_stat = GRAM_JOB_MANAGER_STAT_FREQUENCY;
	    }
            GRAM_UNLOCK;
        } /* endwhile */
    } /* endif */

    globus_nexus_disallow_attach(my_port);

    grami_fprintf( request->jobmanager_log_fp,
          "JM: we're done.  doing cleanup\n");
                            
    if (globus_l_gram_stdout_fd != -1)
    {
        globus_l_gram_delete_file_list(globus_l_gram_stdout_fd,
                                       &globus_l_gram_stdout_files);
        globus_gass_close(globus_l_gram_stdout_fd);
    }
    if (globus_l_gram_stderr_fd != -1)
    {
        globus_l_gram_delete_file_list(globus_l_gram_stderr_fd,
                                       &globus_l_gram_stderr_files);
        globus_gass_close(globus_l_gram_stderr_fd);
    }

    if(!jm_request_failed &&
       ((request->status == GLOBUS_GRAM_CLIENT_JOB_STATE_DONE) || 
        (request->status == GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED)))
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: sending final callback.\n");
                            
        globus_l_gram_client_callback(request->status,
                                      request->failure_code);
        
        /*
         * Check to see if the job status file exists.  If so, then delete it.
         */
        if (stat(job_status_file_path, &statbuf) == 0)
        {
            if (remove(job_status_file_path) != 0)
            {
                grami_fprintf( request->jobmanager_log_fp,
                      "JM: Failed to remove job status file --> %s\n",
                      job_status_file_path);
            }
        }
    }
   
    if (globus_l_gram_client_contact_list_free(globus_l_gram_client_contacts)
        != GLOBUS_SUCCESS)
    {
        grami_fprintf( request->jobmanager_log_fp,
              "JM: Error freeing client contact list.\n");
    }

    /* clear any other cache entries which contain the gram job id as
     * the tag
     */
    grami_fprintf( request->jobmanager_log_fp, "JM: Cleaning GASS cache\n");

    rc = globus_gass_cache_list(&globus_l_cache_handle,
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
                     graml_job_contact))
                {
                    grami_fprintf(request->jobmanager_log_fp,
                         "Trying to clean up with <url=%s> <tag=%s>\n",
                         cache_entries[i].url,
                         graml_job_contact);

                    globus_gass_cache_cleanup_tag(&globus_l_cache_handle,
                                                  cache_entries[i].url,
                                                  graml_job_contact);
                }
            } /* for each tags */
        } /* for each cache entries */
        globus_gass_cache_list_free(cache_entries, cache_size);
    }

    globus_gass_cache_close(&globus_l_cache_handle);

    fflush(request->jobmanager_log_fp);

    grami_fprintf( request->jobmanager_log_fp, "JM: freeing RSL.\n");

    if (graml_rsl_tree)
        globus_rsl_free_recursive(graml_rsl_tree);

    grami_fprintf( request->jobmanager_log_fp,
          "JM: starting deactivate routines.\n");

    rc = globus_module_deactivate(GLOBUS_GRAM_JOBMANAGER_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "%s deactivation failed with rc=%d\n",
		GLOBUS_GRAM_JOBMANAGER_MODULE->module_name, rc);
	exit(1);
    }
    
    rc = globus_module_deactivate(GLOBUS_DUCT_CONTROL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "%s deactivation failed with rc=%d\n",
		GLOBUS_DUCT_CONTROL_MODULE->module_name, rc);
	exit(1);
    }
    
    rc = globus_module_deactivate(GLOBUS_GASS_FILE_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_file deactivation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_deactivate(GLOBUS_GASS_CACHE_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass_cache deactivation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_deactivate(GLOBUS_GASS_CLIENT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "gass client deactivation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_deactivate(GLOBUS_NEXUS_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "nexus deactivation failed with rc=%d\n", rc);
	exit(1);
    }

    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "common deactivation failed with rc=%d\n", rc);
	exit(1);
    }

    grami_fprintf( request->jobmanager_log_fp,
          "JM: exiting globus_gram_job_manager.\n");

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
    conf->install_path      = GLOBUS_NULL;
    conf->deploy_path       = GLOBUS_NULL;
    conf->tools_path        = GLOBUS_NULL;
    conf->services_path     = GLOBUS_NULL;
    conf->num_env_adds      = 0;

    return;

} /* globus_l_gram_conf_values_init() */


/******************************************************************************
Function:       globus_l_gram_attach_requested()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_gram_attach_requested(void * arg,
                 char * url,
                 globus_nexus_startpoint_t * sp)
{
    globus_nexus_startpoint_bind(sp, &graml_GlobalEndpoint);

    return(0);

} /* globus_l_gram_attach_requested() */


/******************************************************************************
Function:       globus_l_gram_client_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_gram_client_callback(int status, int failure_code)
{
    int                size;
    int                count;
    int                rc;
    globus_nexus_startpoint_t sp;
    globus_nexus_buffer_t     reply_buffer;
    globus_list_t *           tmp_list;
    globus_l_gram_client_contact_t *    client_contact_node;
    
    tmp_list = globus_l_gram_client_contacts;

    grami_fprintf( graml_log_fp,
        "JM: %s empty client callback list.\n", (tmp_list) ? ("NOT") : "" );

    while(!globus_list_empty(tmp_list))
    {
        client_contact_node = (globus_l_gram_client_contact_t *)
             globus_list_first(tmp_list);

        if (status & client_contact_node->job_state_mask &&
            client_contact_node->failed_count < 4)
        {
            grami_fprintf( graml_log_fp,
                "JM: sending callback of status %d to %s.\n", status,
                client_contact_node->contact);

            /* This will block if called from a non-threaded handler
             */
            rc = globus_nexus_attach(client_contact_node->contact, &sp);
    
            if (rc == 0)
            {
                size  = globus_nexus_sizeof_int(1);
                size += globus_nexus_sizeof_int(1);
                size += globus_nexus_sizeof_char(strlen(graml_job_contact));
                size += globus_nexus_sizeof_int(1);
                size += globus_nexus_sizeof_int(1);

                count= strlen(graml_job_contact);
                globus_nexus_buffer_init(&reply_buffer, size, 0);
                globus_nexus_put_int(&reply_buffer,
                                     &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
                globus_nexus_put_int(&reply_buffer, &count, 1);
                globus_nexus_put_char(&reply_buffer, graml_job_contact, count);
                globus_nexus_put_int(&reply_buffer, &status, 1);
                globus_nexus_put_int(&reply_buffer, &failure_code, 1);

                globus_nexus_send_rsr(&reply_buffer,
                               &sp,
                               0,
                               GLOBUS_TRUE,
                               GLOBUS_FALSE);

                globus_nexus_startpoint_destroy(&sp);

            }
            else
            {
                client_contact_node->failed_count++;
            }

            tmp_list = globus_list_rest (tmp_list);
        }
    }
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
                              char * job_id)
{
    FILE *             status_fp;

    grami_fprintf( graml_log_fp, "JM: in globus_l_gram_status_file_gen\n");

    if ((status_fp = fopen(job_status_file_path, "w")) == NULL)
    {
        grami_fprintf( graml_log_fp,"JM: Failed opening job status file %s\n",
                       job_status_file_path);
        return(1);
    }
    else
    {
        fprintf(status_fp, "%s\n", request_string);
        fprintf(status_fp, "%s\n", graml_job_contact);
        fprintf(status_fp, "%s\n", job_id);
        fprintf(status_fp, "%s\n", globus_id);

        fclose(status_fp);
    }

    return(0);

} /* globus_l_gram_status_file_gen() */


/******************************************************************************
Function:       globus_l_gram_rsl_env_add()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_rsl_env_add(globus_rsl_t * ast_node,
                          char * var,
                          char * value)
{
    globus_rsl_t * tmp_rsl_ptr;
    globus_list_t * tmp_rsl_list;
    globus_list_t * tmp_value_list;
    globus_list_t * new_list;
    globus_rsl_value_t * tmp_rsl_value_ptr;
    char * tmp_value;
    int value_ctr = 0;

    if (globus_rsl_is_boolean(ast_node))
    {
        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);

            globus_l_gram_rsl_env_add(tmp_rsl_ptr,
                                      var,
                                      value);

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);
        }
    }
    else if (globus_rsl_is_relation(ast_node))
    {
        if (!globus_rsl_is_relation_attribute_equal(ast_node, "environment"))
        {
            return(0);
        }

        new_list = NULL;

        globus_list_insert(&new_list, (void *)
            globus_rsl_value_make_literal(value));

        globus_list_insert(&new_list, (void *)
            globus_rsl_value_make_literal(var));

        globus_list_insert(
            globus_rsl_value_sequence_get_list_ref(
                 globus_rsl_relation_get_value_sequence(ast_node)),
                 (void *) globus_rsl_value_make_sequence(new_list));
 
        return(0);
    }
    else
    {
        return(1);
    }

    return(0);

} /* globus_l_gram_rsl_env_add() */


/******************************************************************************
Function:       globus_l_gram_request_fill()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_gram_request_fill(globus_rsl_t * rsl_tree,
                           globus_gram_jobmanager_request_t * req)
{
    int x;
    char ** tmp_param;
    char * gram_myjob;
    char * staged_file_path;

    if (rsl_tree == NULL)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_NULL_SPECIFICATION_TREE;
        return(GLOBUS_FAILURE);
    }
 
    /********************************** 
     *  GET PROGRAM (executable) PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_EXECUTABLE_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_EXECUTABLE;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        req->executable = (tmp_param)[0];
    else
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_UNDEFINED_EXE;
        return(GLOBUS_FAILURE);
    }

    /********************************** 
     *  GET PROGRAM ARGUMENTS PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                       GLOBUS_RSL_PARAM_MULTI_LITERAL,
		       GLOBUS_GRAM_CLIENT_ARGUMENTS_PARAM, 
                       &(req->arguments)) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_ARGUMENTS;
        return(GLOBUS_FAILURE);
    }

    /********************************** 
     *  GET DIR PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
		             GLOBUS_GRAM_CLIENT_DIR_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_DIRECTORY;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        req->directory = tmp_param[0];
    else
        req->directory = graml_env_home;

    /*
     * change to the right directory, so that std* files
     * are interpreted relative to this directory
     */
    if (chdir(req->directory) != 0)
    {
        grami_fprintf( req->jobmanager_log_fp,
            "JM: Couldn't change to directory %s\n", req->directory );
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_BAD_DIRECTORY;
        return(GLOBUS_FAILURE);
    }

    /********************************** 
     *  GET STDIN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_STDIN_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_STDIN;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        req->my_stdin = tmp_param[0];
    else
        req->my_stdin = GLOBUS_GRAM_CLIENT_DEFAULT_STDIN;

    /********************************** 
     *  GET STDOUT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
			     GLOBUS_RSL_PARAM_MULTI_LITERAL,
                             GLOBUS_GRAM_CLIENT_STDOUT_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_STDOUT;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        req->my_stdout = tmp_param[0];

	if (tmp_param[1])
	{
	    req->my_stdout_tag = tmp_param[1];

	    if (tmp_param[2])
	    {
		/* error: stdout can be of the form URL or URL TAG only */
		req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_STDOUT;
		return(GLOBUS_FAILURE);	
	    }  	 
	}
	else
	{
	    req->my_stdout_tag = GLOBUS_NULL;
	}
    }
    else
    {
        req->my_stdout = GLOBUS_GRAM_CLIENT_DEFAULT_STDOUT;
    }

    /********************************** 
     *  GET STDERR PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
			     GLOBUS_RSL_PARAM_MULTI_LITERAL,
                             GLOBUS_GRAM_CLIENT_STDERR_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_STDERR;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        req->my_stderr = tmp_param[0];

	if (tmp_param[1])
	{
	    req->my_stderr_tag = tmp_param[1];

	    if (tmp_param[2])
	    {
		/* error: stdout can be of the form URL or URL TAG only */
		req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_STDERR;
		return(GLOBUS_FAILURE);	
	    }  	 
	}
	else
	{
	    req->my_stderr_tag = GLOBUS_NULL;
	}
    }
    else
    {
        req->my_stderr = GLOBUS_GRAM_CLIENT_DEFAULT_STDERR;
    }
    
    /********************************** 
     *  GET COUNT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_COUNT_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_COUNT;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {

        x = atoi(tmp_param[0]);

        if (x < 1)
        {
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_INVALID_COUNT;
            return(GLOBUS_FAILURE);
        }
        else
        {
            req->count = x;
        }
    }
    else
    {
        req->count = 1;
    }

    /* save count parameter for reporting to MDS */ 
    graml_my_count = req->count;

    /********************************** 
     *  GET MAXTIME PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_MAXTIME_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_MAXTIME;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        x = atoi(tmp_param[0]);

        if (x < 1)
        {
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAXTIME;
            return(GLOBUS_FAILURE);
        }
        else
        {
            req->maxtime = x;
        }
    }
    else
    {
        req->maxtime = 0;
    }

    /********************************** 
     *  GET HOST_COUNT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_HOST_COUNT_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_HOST_COUNT;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        x = atoi(tmp_param[0]);

        if (x < 1)
        {
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_INVALID_HOST_COUNT;
            return(GLOBUS_FAILURE);
        }
        else
        {
            req->host_count = x;
        }
    }
    else
    {
        req->host_count = 0;
    }

    /********************************** 
     *  GET PARADYN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_PARADYN_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_PARADYN;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        req->paradyn = tmp_param[0];
    else
        req->paradyn = NULL;

    /********************************** 
     *  GET JOBTYPE PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_JOBTYPE_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_JOBTYPE;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        if (strncmp(tmp_param[0], "mpi", 3) == 0)
            req->jobtype = GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MPI;
        else if (strncmp(tmp_param[0], "single", 6) == 0)
            req->jobtype = GLOBUS_GRAM_JOBMANAGER_JOBTYPE_SINGLE;
        else if (strncmp(tmp_param[0], "multiple", 8) == 0)
            req->jobtype = GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MULTIPLE;
        else if (strncmp(tmp_param[0], "condor", 6) == 0)
            req->jobtype = GLOBUS_GRAM_JOBMANAGER_JOBTYPE_CONDOR;
        else
        {
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBTYPE;
            return(GLOBUS_FAILURE);
        }
    }
    else
    {
        req->jobtype = GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MULTIPLE;
    }

    /********************************** 
     *  GET MYJOB PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_MYJOB_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_MYJOB;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
    {
        if ((strncmp(tmp_param[0], "collective", 10) != 0) &&
            (strncmp(tmp_param[0], "independent", 11) != 0))
        {
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_INVALID_GRAM_MYJOB;
            return(GLOBUS_FAILURE);
        }

        gram_myjob = tmp_param[0];
    }
    else
        gram_myjob = GLOBUS_GRAM_CLIENT_DEFAULT_MYJOB;

    /********************************** 
     *  GET DRYRUN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_DRYRUN_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_DRYRUN;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        if (strncmp(tmp_param[0], "yes", 3) == 0)
            req->dryrun = GLOBUS_TRUE;
        else
            req->dryrun = GLOBUS_FALSE;
    else
        req->dryrun = GLOBUS_FALSE;

    /**********************************
     *  GET QUEUE PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_QUEUE_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_QUEUE;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        req->queue = tmp_param[0];
    else
        req->queue = NULL;
 
    /**********************************
     *  GET PROJECT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_PROJECT_PARAM,
		             &tmp_param) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_PROJECT;
        return(GLOBUS_FAILURE);
    }

    if (tmp_param[0])
        req->project = tmp_param[0];
    else
        req->project = NULL;

    /********************************** 
     *  GET ENVIRONMENT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SEQUENCE,
	                     GLOBUS_GRAM_CLIENT_ENVIRONMENT_PARAM, 
                             &(req->environment)) != 0)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_RSL_ENVIRONMENT;
        return(GLOBUS_FAILURE);
    }


    {
	char *newvar;
	char *newval;
	int i;
	int rc;

	/* add duct environment string to environment */
	rc = globus_l_gram_duct_environment(req->count,
					    gram_myjob,
					    &newvar,
					    &newval);
	if(rc == GLOBUS_SUCCESS)
	{
	    for(i = 0; req->environment[i] != GLOBUS_NULL; i++)
	    {
		;
	    }
	    
	    req->environment = (char **)
		globus_libc_realloc(req->environment,
				    (i+3) * sizeof(char *));
	    req->environment[i] = newvar;
	    ++i;
	    req->environment[i] = newval;
	    ++i;
	    req->environment[i] = GLOBUS_NULL;

            if (globus_l_gram_rsl_env_add(rsl_tree, newvar, newval) != 0)
            {
                grami_fprintf( req->jobmanager_log_fp, 
                        "JM: ERROR adding %s to the environment= parameter "
                        "of the RSL.\n", newvar);
            }
	}
    }
    
    /* GEM: Stage executable and stdin to local filesystem, if they are URLs.
     * Do this before paradyn rewriting.
     */

    if (globus_l_gram_stage_file(req->executable,
                                 &staged_file_path,
                                 0700) != GLOBUS_SUCCESS)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_STAGING_EXECUTABLE;
        return(GLOBUS_FAILURE);
    }

    if (staged_file_path)
    {
        req->executable = staged_file_path;
        grami_fprintf( req->jobmanager_log_fp, 
              "JM: executable staged filename is %s\n", staged_file_path);
    }

    if (globus_l_gram_stage_file(req->my_stdin,
                                 &staged_file_path,
                                 0400) != GLOBUS_SUCCESS)
    {
        req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_STAGING_STDIN;
        return(GLOBUS_FAILURE);
    }

    if (staged_file_path)
    {
        req->my_stdin = staged_file_path;
        grami_fprintf( req->jobmanager_log_fp, 
              "JM: stdin staged filename is %s\n", staged_file_path);
    }

    if (grami_is_paradyn_job(req))
    {
	if (!grami_paradyn_rewrite_params(req))
	{
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_INVALID_PARADYN;
            return(GLOBUS_FAILURE);
	}

        if (globus_l_gram_stage_file(req->executable,
                                     &staged_file_path,
                                     0700) != GLOBUS_SUCCESS)
        {
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_STAGING_EXECUTABLE;
            return(GLOBUS_FAILURE);
        }

        if (staged_file_path)
        {
            req->executable = staged_file_path;
        }
    }

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_request_fill() */


/******************************************************************************
Function:       globus_l_gram_request_environment_append()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_gram_request_environment_append(globus_gram_jobmanager_request_t * req,
                                         globus_l_gram_conf_values_t * conf)
{
    int x;

    /*
     * if there are no additional environment variables then just return.
     */
    if (conf->num_env_adds < 1)
    {
        return(GLOBUS_SUCCESS);
    }

    /*
     * determine the number of environment vars in the request.
     */
    for(x = 0; req->environment[x] != GLOBUS_NULL; x++)
    {
        ;
    }
    
    /*
     * Allocate additional space to hold the default environment variables.
     */
    req->environment = (char **) globus_libc_realloc(req->environment,
                    (conf->num_env_adds*2+x+1) * sizeof(char *));

    if (conf->x509_cert_dir)
    {
        req->environment[x] = "X509_CERT_DIR";             ++x;
        req->environment[x] = conf->x509_cert_dir;         ++x;
    }

    if (graml_job_contact)
    {
        req->environment[x] = "GLOBUS_GRAM_JOB_CONTACT";   ++x;
        req->environment[x] = graml_job_contact;           ++x;
    }

    if (conf->condor_arch)
    {
        req->environment[x] = "GLOBUS_CONDOR_ARCH";        ++x;
        req->environment[x] = conf->condor_arch;           ++x;
    }

    if (conf->condor_os)
    {
        req->environment[x] = "GLOBUS_CONDOR_OS";          ++x;
        req->environment[x] = conf->condor_os;             ++x;
    }

    if (conf->org_dn)
    {
        req->environment[x] = "GLOBUS_ORG_DN";             ++x;
        req->environment[x] = conf->org_dn;                ++x;
    }

    if (conf->rdn)
    {
        req->environment[x] = "GLOBUS_GRAM_RDN";           ++x;
        req->environment[x] = conf->rdn;                   ++x;
    }

    if (conf->host_dn)
    {
        req->environment[x] = "GLOBUS_HOST_DN";            ++x;
        req->environment[x] = conf->host_dn;               ++x;
    }

    if (conf->host_manufacturer)
    {
        req->environment[x] = "GLOBUS_HOST_MANUFACTURER";  ++x;
        req->environment[x] = conf->host_manufacturer;     ++x;
    }

    if (conf->host_cputype)
    {
        req->environment[x] = "GLOBUS_HOST_CPUTYPE";       ++x;
        req->environment[x] = conf->host_cputype;          ++x;
    }

    if (conf->host_osname)
    {
        req->environment[x] = "GLOBUS_HOST_OSNAME";        ++x;
        req->environment[x] = conf->host_osname;           ++x;
    }

    if (conf->host_osversion)
    {
        req->environment[x] = "GLOBUS_HOST_OSVERSION";     ++x;
        req->environment[x] = conf->host_osversion;        ++x;
    }

    if (conf->gate_host)
    {
        req->environment[x] = "GLOBUS_GATEKEEPER_HOST";    ++x;
        req->environment[x] = conf->gate_host;             ++x;
    }

    if (conf->gate_port)
    {
        req->environment[x] = "GLOBUS_GATEKEEPER_PORT";    ++x;
        req->environment[x] = conf->gate_port;             ++x;
    }

    if (conf->gate_subject)
    {
        req->environment[x] = "GLOBUS_GATEKEEPER_SUBJECT"; ++x;
        req->environment[x] = conf->gate_subject;          ++x;
    }

    if (conf->deploy_path)
    {
        req->environment[x] = "GLOBUS_DEPLOY_PATH";        ++x;
        req->environment[x] = conf->deploy_path;           ++x;
    }

    if (conf->install_path)
    {
        req->environment[x] = "GLOBUS_INSTALL_PATH";       ++x;
        req->environment[x] = conf->install_path;          ++x;
    }

    if (conf->tools_path)
    {
        req->environment[x] = "GLOBUS_TOOLS_PATH";         ++x;
        req->environment[x] = conf->tools_path;            ++x;
    }

    if (conf->services_path)
    {
        req->environment[x] = "GLOBUS_SERVICES_PATH";      ++x;
        req->environment[x] = conf->services_path;         ++x;
    }

    req->environment[x] = GLOBUS_NULL;

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_request_environment_append() */


/******************************************************************************
Function:       globus_l_gram_cancel_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_gram_cancel_handler(globus_nexus_endpoint_t * endpoint,
                             globus_nexus_buffer_t * buffer,
                             globus_bool_t is_non_threaded_handler)
{
    int                                rc;
    int                                size;
    int                                gram_version;
    globus_nexus_startpoint_t          reply_sp;
    globus_nexus_buffer_t              reply_buffer;
    globus_gram_jobmanager_request_t * request;

    request = (globus_gram_jobmanager_request_t * )
                        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf( request->jobmanager_log_fp,
          "JM : in globus_l_gram_cancel_handler\n");

    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        grami_fprintf( request->jobmanager_log_fp, 
               "JM: ERROR received a version mismatch in cancel handler "
               "ignoring request.\n");
        grami_fprintf( request->jobmanager_log_fp, 
               "JM: job manager version is %d  client version is %d\n",
               GLOBUS_GRAM_PROTOCOL_VERSION, gram_version);
    }

    globus_nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    globus_nexus_buffer_destroy(buffer);

    GRAM_LOCK;

    rc = globus_jobmanager_request_cancel(request);

    size = globus_nexus_sizeof_int(2);
    globus_nexus_buffer_init(&reply_buffer, size, 0);
    globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_int(&reply_buffer, &rc, 1);

    request->status = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
    graml_jm_done = 1;

    GRAM_UNLOCK;

    globus_nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   GLOBUS_TRUE,
                   is_non_threaded_handler);

    globus_nexus_startpoint_destroy(&reply_sp);

} /* globus_l_gram_cancel_handler() */


/******************************************************************************
Function:       globus_l_gram_register_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_gram_register_handler(globus_nexus_endpoint_t * endpoint,
                               globus_nexus_buffer_t * buffer,
                               globus_bool_t is_non_threaded_handler)
{
    int                                rc;
    int                                size;
    int                                gram_version;
    int                                job_state_mask;
    int                                job_status;
    int                                len;
    int                                register_status;
    globus_nexus_startpoint_t          reply_sp;
    globus_nexus_buffer_t              reply_buffer;
    globus_gram_jobmanager_request_t * request;
    char *                             client_contact_str;
    globus_l_gram_client_contact_t *   client_contact_node;

    request = (globus_gram_jobmanager_request_t * )
                        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf( request->jobmanager_log_fp,
          "JM: in globus_l_gram_register_handler\n");

    globus_nexus_get_int(buffer, &gram_version, 1);

    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        grami_fprintf( request->jobmanager_log_fp, 
               "JM: ERROR received a version mismatch in register handler "
               "ignoring request.\n");
        grami_fprintf( request->jobmanager_log_fp, 
               "JM: job manager version is %d  client version is %d\n",
               GLOBUS_GRAM_PROTOCOL_VERSION, gram_version);
    }

    globus_nexus_get_startpoint(buffer, &reply_sp, 1);
    globus_nexus_get_int(buffer, &len, 1);
    client_contact_str = globus_libc_malloc (sizeof(char)*(len + 1));
    globus_nexus_get_char(buffer, client_contact_str, len);
    client_contact_str[len] = '\0';
    globus_nexus_get_int(buffer, &job_state_mask, 1);

    GRAM_LOCK;

    client_contact_node = (globus_l_gram_client_contact_t *)
        globus_libc_malloc(sizeof(globus_l_gram_client_contact_t));

    client_contact_node->contact        = client_contact_str;
    client_contact_node->job_state_mask = job_state_mask;
    client_contact_node->failed_count   = 0;

    if ((register_status = globus_list_insert(&globus_l_gram_client_contacts,
                       (void *) client_contact_node)) != GLOBUS_SUCCESS)
    {
        register_status = GLOBUS_GRAM_CLIENT_ERROR_INSERTING_CLIENT_CONTACT;
    }

    /* clean-up */
    globus_nexus_buffer_destroy(buffer);

    job_status = request->status;

    size = globus_nexus_sizeof_int(3);
    globus_nexus_buffer_init(&reply_buffer, size, 0);
    globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_int(&reply_buffer, &job_status, 1);
    globus_nexus_put_int(&reply_buffer, &register_status, 1);

    GRAM_UNLOCK;

    globus_nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   GLOBUS_TRUE,
                   is_non_threaded_handler);

    globus_nexus_startpoint_destroy(&reply_sp);

} /* globus_l_gram_register_handler() */


/******************************************************************************
Function:       globus_l_gram_unregister_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_gram_unregister_handler(globus_nexus_endpoint_t * endpoint,
                                 globus_nexus_buffer_t * buffer,
                                 globus_bool_t is_non_threaded_handler)
{
    int                                rc;
    int                                size;
    int                                gram_version;
    int                                len;
    int                                job_status;
    int                                unregister_status;
    globus_nexus_startpoint_t          reply_sp;
    globus_nexus_buffer_t              reply_buffer;
    globus_gram_jobmanager_request_t * request;
    char *                             client_contact_str;
    globus_l_gram_client_contact_t *   client_contact_node;
    globus_list_t *                    tmp_list;
    globus_list_t *                    next_list;

    request = (globus_gram_jobmanager_request_t * )
                        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf( request->jobmanager_log_fp,
          "JM: in globus_l_gram_unregister_handler\n");

    /* initialize the flag to failed.  Change to GLOBUS_SUCCESS if successful */

    globus_nexus_get_int(buffer, &gram_version, 1);

    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        grami_fprintf( request->jobmanager_log_fp, 
               "JM: ERROR received a version mismatch in unregister handler "
               "ignoring request.\n");
        grami_fprintf( request->jobmanager_log_fp, 
               "JM: job manager version is %d  client version is %d\n",
               GLOBUS_GRAM_PROTOCOL_VERSION, gram_version);
    }

    globus_nexus_get_startpoint(buffer, &reply_sp, 1);
    globus_nexus_get_int(buffer, &len, 1);
    client_contact_str = globus_libc_malloc (sizeof(char)*(len + 1));
    globus_nexus_get_char(buffer, client_contact_str, len);

    client_contact_str[len] = '\0';

    /* clean-up */
    globus_nexus_buffer_destroy(buffer);

    GRAM_LOCK;

    /* find client_contact and remove it. */

    unregister_status = GLOBUS_GRAM_CLIENT_ERROR_CLIENT_CONTACT_NOT_FOUND;

    tmp_list = globus_l_gram_client_contacts;
    while(!globus_list_empty(tmp_list))
    {
        client_contact_node = (globus_l_gram_client_contact_t *)
             globus_list_first(tmp_list);

        if (strcmp(client_contact_str, client_contact_node->contact) == 0)
        {
            next_list = globus_list_rest (tmp_list);

            client_contact_node = (globus_l_gram_client_contact_t *)
               globus_list_remove (&globus_l_gram_client_contacts, tmp_list);

            tmp_list = next_list;

           globus_libc_free (client_contact_node->contact);
           globus_libc_free (client_contact_node);
           unregister_status = GLOBUS_SUCCESS;
        }
        else
        {
            tmp_list = globus_list_rest (tmp_list);
        }
    }

    job_status = request->status;

    size = globus_nexus_sizeof_int(3);
    globus_nexus_buffer_init(&reply_buffer, size, 0);
    globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_int(&reply_buffer, &job_status, 1);
    globus_nexus_put_int(&reply_buffer, &unregister_status, 1);

    GRAM_UNLOCK;

    globus_nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   GLOBUS_TRUE,
                   is_non_threaded_handler);

    globus_nexus_startpoint_destroy(&reply_sp);

} /* globus_l_gram_unregister_handler() */


/******************************************************************************
Function:       globus_l_gram_status_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_status_handler(globus_nexus_endpoint_t * endpoint,
                             globus_nexus_buffer_t * buffer,
                             globus_bool_t is_non_threaded_handler)
{
    int                                rc;
    int                                size;
    int                                gram_version;
    globus_nexus_startpoint_t          reply_sp;
    globus_nexus_buffer_t              reply_buffer;
    globus_gram_jobmanager_request_t * request;
    int job_status;

    
    request = (globus_gram_jobmanager_request_t * )
                        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf( request->jobmanager_log_fp,
          "JM: in globus_l_gram_status_handler\n");

    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        grami_fprintf( request->jobmanager_log_fp,
               "JM: ERROR received a version mismatch in status handler "
               "ignoring request.\n");
        grami_fprintf( request->jobmanager_log_fp,
               "JM: job manager version is %d  client version is %d\n",
               GLOBUS_GRAM_PROTOCOL_VERSION, gram_version);
    }

    globus_nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    globus_nexus_buffer_destroy(buffer);

    GRAM_LOCK;

    job_status = request->status;

    size = globus_nexus_sizeof_int(2);
    globus_nexus_buffer_init(&reply_buffer, size, 0);
    globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_int(&reply_buffer, &job_status, 1);

    GRAM_UNLOCK;

    globus_nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   GLOBUS_TRUE,
                   is_non_threaded_handler);

    globus_nexus_startpoint_destroy(&reply_sp);

} /* globus_l_gram_status_handler() */


/******************************************************************************
Function:       globus_l_gram_start_time_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_gram_start_time_handler(globus_nexus_endpoint_t * endpoint,
                                 globus_nexus_buffer_t * buffer,
                                 globus_bool_t is_non_threaded_handler)
{
    int                         rc;
    int                         size;
    int                         message_handled;
    float                       confidence;
    globus_nexus_startpoint_t   reply_sp;
    globus_nexus_buffer_t       reply_buffer;
    globus_gram_client_time_t   estimate;
    globus_gram_client_time_t   interval_size;

    grami_fprintf( graml_log_fp, "JM: in globus_l_gram_start_time_handler\n");

    globus_nexus_get_float(buffer, &confidence, 1);
    globus_nexus_get_startpoint(buffer, &reply_sp, 1);

    globus_nexus_buffer_destroy(buffer);

    grami_fprintf( graml_log_fp, 
                   "JM: confidence passed = %f\n", confidence);

    GRAM_LOCK;

/*
    rc = grami_jm_job_start_time(graml_callback_contact,
                                 confidence,
                                 &estimate,
                                 &interval_size);
*/

    size  = globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_int(1);

    globus_nexus_buffer_init(&reply_buffer, size, 0);
    globus_nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_int(&reply_buffer, &rc, 1);
    globus_nexus_put_int(&reply_buffer, &estimate.dumb_time, 1);
    globus_nexus_put_int(&reply_buffer, &interval_size.dumb_time, 1);

    globus_nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   GLOBUS_TRUE,
                   GLOBUS_FALSE);

    globus_nexus_startpoint_destroy(&reply_sp);

    GRAM_UNLOCK;

}

/******************************************************************************
Function:       globus_l_gram_genfilename()
Description:    generate an absolute file name given a starting prefix,
                                a relative or absolute path, and a sufix
                                Only use prefix if path is relative.
Parameters:
Returns:                a pointer to a string which could be freeded.
******************************************************************************/
static char *
globus_l_gram_genfilename(char * prefixp, char * pathp, char * sufixp)
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
} /* globus_l_gram_genfilename */

/******************************************************************************
Function:       globus_l_gram_stage_file()
Description:    
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_stage_file(char *url, char **staged_file_path, int mode)
{
    globus_url_t gurl;
    int rc;
    int error_flag = 0;

    *staged_file_path = GLOBUS_NULL;

    if (url == GLOBUS_NULL)
    {
        return(GLOBUS_FAILURE);
    }

    if (strlen(url) == 0)
    {
        return(GLOBUS_FAILURE);
    }
    grami_fprintf( graml_log_fp, "JM: staging file = %s\n", url);

    rc = globus_url_parse(url, &gurl);
    if(rc == GLOBUS_SUCCESS)	/* this is a valid URL */
    {
	unsigned long timestamp;
	
	rc = globus_gass_cache_add(&globus_l_cache_handle,
				   url,
				   graml_job_contact,
				   GLOBUS_TRUE,
				   &timestamp,
				   staged_file_path);
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_add_done(&globus_l_cache_handle,
				       url,
				       graml_job_contact,
				       timestamp);
	}
	else if(rc == GLOBUS_GASS_CACHE_ADD_NEW)
	{
	    int fd = open(*staged_file_path,
			  O_WRONLY|O_TRUNC,
			  mode);
	    if(gurl.scheme_type == GLOBUS_URL_SCHEME_FILE)
	    {
		char buf[512];
		int ofd = open(gurl.url_path, O_RDONLY);
		
		while((rc = read(ofd, buf, sizeof(buf))) > 0)
		{
		    write(fd, buf, rc);
		}

		close(ofd);
	    }
	    else
	    {
		error_flag = globus_gass_client_get_fd(url,
					  GLOBUS_NULL,
					  fd,
					  GLOBUS_GASS_LENGTH_UNKNOWN,
					  &timestamp,
					  GLOBUS_NULL,
					  GLOBUS_NULL);
	    }
	    close(fd);
	    globus_gass_cache_add_done(&globus_l_cache_handle,
				       url,
				       graml_job_contact,
				       timestamp);
	}
    }
    globus_url_destroy(&gurl);
    grami_fprintf( graml_log_fp, "JM: new name = %s\n", url);

    if (error_flag != GLOBUS_SUCCESS)
    {
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_stage_file */

/******************************************************************************
Function:       globus_l_gram_duct_environment()
Description:    
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_duct_environment(int count,
			       char *myjob,
			       char **newvar,
			       char **newval)
{
    globus_duct_control_t *duct;
    int rc;
    
    duct = globus_libc_malloc(sizeof(globus_duct_control_t));
	
    if(strcmp(myjob, "collective") != 0)
    {
	count=1;
    }
    
    rc = globus_duct_control_init(duct,
				  count,
				  GLOBUS_NULL,
				  GLOBUS_NULL);
    if(rc != GLOBUS_SUCCESS)
    {
	grami_fprintf( graml_log_fp,
		       "JM: duct_control_init_failed: %d\n",
		       rc);
	return GLOBUS_GRAM_CLIENT_ERROR_DUCT_INIT_FAILED;
    }

    rc = globus_duct_control_contact_url(duct,
					 newval);

    if(rc != GLOBUS_SUCCESS)
    {
	grami_fprintf( graml_log_fp,
		       "JM: duct_control_contact_url failed: %d\n",
		       rc);
	
	return(GLOBUS_GRAM_CLIENT_ERROR_DUCT_LSP_FAILED);
    }

    (*newvar) = globus_libc_strdup("GLOBUS_GRAM_MYJOB_CONTACT");

    return GLOBUS_SUCCESS;
} /* globus_l_gram_duct_environment */

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
        grami_fprintf( graml_log_fp, "JM: %s = %s\n", env_var, env_val);
    }
    else
    {
        grami_fprintf( graml_log_fp, 
                       "JM: unable to get %s from the environment.\n",
                       env_var);
        if (default_val)
        {
            env_val = (char *) globus_libc_strdup (default_val);
            grami_fprintf( graml_log_fp, "JM: %s = %s\n", env_var, env_val);
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
static void
globus_l_gram_status_file_cleanup(char * job_status_dir)
{
    DIR *            status_dir;
    struct dirent *  dir_entry;
    char             logname_string[256];
    char             stat_file_path[1024];
    struct stat      statbuf;
    unsigned long    now;
 
    if(job_status_dir == GLOBUS_NULL)
    {
        grami_fprintf( graml_log_fp, 
            "JM: status directory not specified, cleanup cannot proceed.\n");
        return;
    }
 
    status_dir = globus_libc_opendir(job_status_dir);
    if(status_dir == GLOBUS_NULL)
    {
        grami_fprintf( graml_log_fp, 
            "JM: unable to open status directory, aborting cleanup process.\n");
        return;
    }

    sprintf(logname_string, "_%s.", graml_env_logname);
    now = (unsigned long) time(NULL);

    for(globus_libc_readdir_r(status_dir, &dir_entry);
        dir_entry != GLOBUS_NULL;
        globus_libc_readdir_r(status_dir, &dir_entry))
    {
        if (strstr(dir_entry->d_name, logname_string) != NULL)
        {
            sprintf(stat_file_path, "%s/%s", job_status_dir, dir_entry->d_name);
            grami_fprintf( graml_log_fp, 
                   "JM: found user file --> %s\n", stat_file_path);
            if (stat(stat_file_path, &statbuf) == 0)
            {
                if ( (now - (unsigned long) statbuf.st_mtime) >
                      GRAM_JOB_MANAGER_STATUS_FILE_SECONDS )
                {
                    grami_fprintf( graml_log_fp, 
                        "JM: status file has not been modified in %d seconds\n",
                        GRAM_JOB_MANAGER_STATUS_FILE_SECONDS);
                    if (remove(stat_file_path) != 0)
                    {
                        grami_fprintf( graml_log_fp, 
                               "JM: Cannot remove old status file --> %s\n",
                               stat_file_path);
                    }
                    else
                    {
                        grami_fprintf( graml_log_fp, 
                               "JM: Removed old status file --> %s\n",
                               stat_file_path);
                    }
                }
            }
        }
    }
    globus_libc_closedir(status_dir);

} /* globus_l_gram_status_file_cleanup() */


/******************************************************************************
Function:       globus_l_gram_user_proxy_relocate()
Description:
Parameters:
Returns:
******************************************************************************/
static char *
globus_l_gram_user_proxy_relocate(globus_gram_jobmanager_request_t * req)
{
    int            rc;
    int            proxy_fd, new_proxy_fd;
    char           buf[512];
    char *         user_proxy_path;
    char *         cache_user_proxy_filename;
    char *         unique_file_name;
    unsigned long  timestamp;

    grami_fprintf( req->jobmanager_log_fp, 
          "JM: Relocating user proxy file to the gass cache\n");

    user_proxy_path = (char *) getenv("X509_USER_PROXY");
    if (!user_proxy_path)
    {
        return(GLOBUS_NULL);
    }

    unique_file_name = globus_libc_malloc(strlen(graml_job_contact) +
                                    strlen("x509_user_proxy") + 2);

    globus_libc_sprintf(unique_file_name,
                        "%s/%s",
                        graml_job_contact,
                        "x509_user_proxy");

    rc = globus_gass_cache_add(&globus_l_cache_handle,
                               unique_file_name,
                               graml_job_contact,
                               GLOBUS_TRUE,
                               &timestamp,
                               &cache_user_proxy_filename);

    if ( rc == GLOBUS_GASS_CACHE_ADD_EXISTS ||
         rc == GLOBUS_GASS_CACHE_ADD_NEW )
    {

        if ((proxy_fd = open(user_proxy_path, O_RDONLY)) < 0)
        {
            grami_fprintf( req->jobmanager_log_fp, 
                "JM: Unable to open (source) user proxy file %s\n",
                user_proxy_path);
            globus_libc_free(unique_file_name);
            req->failure_code = GLOBUS_GRAM_CLIENT_ERROR_OPENING_USER_PROXY;
            return(GLOBUS_NULL);
        }

        if ((new_proxy_fd = open(cache_user_proxy_filename,
                                 O_CREAT|O_WRONLY|O_TRUNC, 0400)) < 0)
        {
            grami_fprintf( req->jobmanager_log_fp, 
                "JM: Unable to open cache file for the user proxy %s\n",
                cache_user_proxy_filename);
            globus_libc_free(unique_file_name);
            req->failure_code =
                  GLOBUS_GRAM_CLIENT_ERROR_OPENING_CACHE_USER_PROXY;
            return(GLOBUS_NULL);
        }

        grami_fprintf( req->jobmanager_log_fp, 
                "JM: Copying user proxy file from --> %s\n",
                user_proxy_path);
        grami_fprintf( req->jobmanager_log_fp, 
                "JM:                         to   --> %s\n",
                cache_user_proxy_filename);

        while((rc = read(proxy_fd, buf, sizeof(buf))) > 0)
        {
             write(new_proxy_fd, buf, rc);
        }

        close(proxy_fd);
        close(new_proxy_fd);
        
        rc = globus_gass_cache_add_done(&globus_l_cache_handle,
                                        unique_file_name,
                                        graml_job_contact,
                                        timestamp);
        if(rc != GLOBUS_SUCCESS)
        {
	    grami_fprintf( req->jobmanager_log_fp, 
			   "JM: globus_gass_cache_add_done failed for user proxy file --> %s\n",
			   user_proxy_path);
            if (remove(user_proxy_path) != 0)
            {
                grami_fprintf( req->jobmanager_log_fp, 
                  "JM: Cannot remove user proxy file --> %s\n",user_proxy_path);
            }
            globus_libc_free(unique_file_name);
            return(GLOBUS_NULL);
        }
    }
    else
    {
	grami_fprintf( req->jobmanager_log_fp, 
		       "JM: Cannot get a cache entry for user proxy file %s : %s\n",
		       unique_file_name, globus_gass_cache_error_string(rc));
        if (remove(user_proxy_path) != 0)
        {
            grami_fprintf( req->jobmanager_log_fp, 
                "JM: Cannot remove user proxy file --> %s\n",user_proxy_path);
        }
        globus_libc_free(unique_file_name);
        return(GLOBUS_NULL);
    }

    if (remove(user_proxy_path) != 0)
    {
        grami_fprintf( req->jobmanager_log_fp, 
            "JM: Cannot remove user proxy file --> %s\n",user_proxy_path);
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
Function:       globus_i_filename_callback_func()
Description:
Parameters:
Returns:
******************************************************************************/
char *
globus_i_filename_callback_func(int stdout_flag)
{
    int                       rc;
    char                      url[1024];
    unsigned long             timestamp;
    globus_l_gram_output_t *  output_handle;

    output_handle = (globus_l_gram_output_t *)
        globus_libc_malloc(sizeof(globus_l_gram_output_t));

    if(output_handle == GLOBUS_NULL)
    {
        return GLOBUS_NULL;
    }

    /* Create url for cache file
     * <job_contact>/dev/std{out,err}[1..count]
     */
    if (stdout_flag)
    {
        globus_libc_sprintf(url,
                            "%sdev/stdout%03d",
                            graml_job_contact,
                            graml_stdout_count);
    }
    else
    {
        globus_libc_sprintf(url,
                            "%sdev/stderr%03d",
                            graml_job_contact,
                            graml_stderr_count);
    }

    rc = globus_gass_cache_add(&globus_l_cache_handle,
                               url,
                               graml_job_contact,
                               GLOBUS_TRUE,
                               &timestamp,
                               &output_handle->cache_file);

    if(rc != GLOBUS_GASS_CACHE_ADD_EXISTS &&
       rc != GLOBUS_GASS_CACHE_ADD_NEW)
    {
        globus_libc_free(output_handle);
        return GLOBUS_NULL;
    }

    output_handle->last_written = (off_t) 0;
    output_handle->last_size = (off_t) 0;
    output_handle->ok = GLOBUS_TRUE;
    output_handle->poll_frequency = 1;
    output_handle->poll_counter = 1;

    if (stdout_flag)
    {
        globus_list_insert(&globus_l_gram_stdout_files,
                           (void *) output_handle);
        graml_stdout_count++;
    }
    else
    {
        globus_list_insert(&globus_l_gram_stderr_files,
                           (void *) output_handle);
        graml_stderr_count++;
    }

    return output_handle->cache_file;

} /* globus_i_filename_callback_func() */

/******************************************************************************
Function:       globus_l_gram_check_file_list()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_check_file_list(int check_fd, globus_list_t *file_list)
{
    globus_list_t *           tmp_list;
    globus_l_gram_output_t *  output;

    tmp_list = file_list;
    while(!globus_list_empty(tmp_list))
    {
        struct stat file_status;

        output = (globus_l_gram_output_t *) globus_list_first(tmp_list);
        output->poll_counter--;
        if (output->poll_counter < 1)
        {
            if (globus_l_gram_check_file(check_fd, output) == 0)
            {
                output->poll_frequency++; 
            }
            else
            {
                output->poll_frequency = 1; 
            }
            
            output->poll_counter = output->poll_frequency;
        }
        
        tmp_list = globus_list_rest(tmp_list);

    }
} /* globus_l_gram_check_file_list() */

/******************************************************************************
Function:       globus_l_gram_check_file()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_check_file(int out_fd,
                         globus_l_gram_output_t * output)
{
    globus_byte_t *  buf = globus_libc_malloc(1024);
    int              fd;
    int              rc;
    int              file_changed = 0;

    struct stat      file_status;

    if(output->ok != GLOBUS_TRUE)
    {
        goto check_done;
    }

    rc = stat(output->cache_file, &file_status);
    while((rc = stat(output->cache_file, &file_status)) < 0)
    {
        if(errno != EINTR)
        {
            break;
        }
    }
    if(rc != 0)
    {
        goto check_done;
    }

    /* check the file if it has grown since we last looked */
    if(file_status.st_size != output->last_size)
    {
        char tmp_char;
        off_t loc;
        off_t last_nl = (off_t) output->last_written;
        file_changed = 1;
        fd = globus_libc_open(output->cache_file,
                              O_RDONLY);
        rc = lseek(fd,
                   output->last_written,
                   SEEK_SET);

        loc = output->last_written;
        
        output->last_size = file_status.st_size;
        
        /* find the last newline in the file */
        while(globus_libc_read(fd, &tmp_char, 1) == 1)
        {
            loc++;
            if(tmp_char == '\n')
            {
                last_nl = loc;
            }
            if(loc == file_status.st_size)
            {
                break;
            }
        }

        if ((output->last_size - output->last_written > 4096) &&
            (last_nl == (off_t) output->last_written))
        {
            last_nl = output->last_size;
        }
            
        /* read the file until the newline above, writing as we go */
        if(last_nl != output->last_written)
        {
            off_t amt_to_write = last_nl - output->last_written;
            off_t written = 0;
            lseek(fd,
                  output->last_written,
                  SEEK_SET);

            /* write in 1K chunks */
            while(amt_to_write > 1024 && output->ok)
            {
                if (globus_l_gram_jm_read(fd, buf, 1024) < 0)
                {
                    amt_to_write = -1;
                    output->ok = GLOBUS_FALSE;
                    break;
                }

                /* out_fd can be closed if a globus_gass_server
                   which served this URL deactivates */
                if(out_fd < 0)
                {
                    output->ok = GLOBUS_FALSE;
                }
                else
                {
                    if (globus_l_gram_jm_write(out_fd, buf, 1024) < 0)
                    {
                        amt_to_write = -1;
                        output->ok = GLOBUS_FALSE;
                        break;
                    }
                    amt_to_write -= 1024;
                }
            }
            /* write leftovers (< !K) */
            if(amt_to_write > 0 && output->ok)
            {
                if (globus_l_gram_jm_read(fd, buf, amt_to_write) < 0)
                {
                    amt_to_write = -1;
                    output->ok = GLOBUS_FALSE;
                }
                /* out_fd can be closed if a globus_gass_server
                   which served this URL deactivates */
                if(out_fd < 0)
                {
                    output->ok = GLOBUS_FALSE;
                }
                else
                {
                    if (globus_l_gram_jm_write(out_fd, buf, amt_to_write)
                        < 0)
                    {
                        amt_to_write = -1;
                        output->ok = GLOBUS_FALSE;
                    }
                }
            }
            output->last_written = last_nl;
        }
        
        globus_libc_close(fd);
    }

check_done:

    globus_libc_free(buf);
    return (file_changed);

} /* globus_l_gram_check_file() */

/******************************************************************************
Function:       globus_l_gram_delete_file_list()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_delete_file_list(int output_fd, globus_list_t **handle_list)
{
    globus_list_t *           tmp_list;
    globus_l_gram_output_t *  output;
    globus_byte_t *           buf = globus_libc_malloc(1024);
    int                       fd;
    int                       rc;

    while(!globus_list_empty(*handle_list))
    {
        struct stat file_status;

        output = globus_list_remove(handle_list, *handle_list);

        if(output->ok != GLOBUS_TRUE)
        {
            continue;
        }

        rc = stat(output->cache_file, &file_status);
        while((rc = stat(output->cache_file, &file_status)) < 0)
        {
            if(errno != EINTR)
            {
                break;
            }
        }

        if(rc != 0)
        {
            continue;
        }

        if(output->last_written != file_status.st_size)
        {
            off_t amt_to_write = file_status.st_size - output->last_written;

            fd = globus_libc_open(output->cache_file,
                                  O_RDONLY);
            
            lseek(fd,
                  output->last_written,
                  SEEK_SET);

            /* write in 1K chunks */
            while(amt_to_write > 1024)
            {
                if (globus_l_gram_jm_read(fd, buf, 1024) < 0)
                {
                    amt_to_write = -1;
                    output->ok = GLOBUS_FALSE;
                    break;
                }

                if (globus_l_gram_jm_write(output_fd, buf, 1024) < 0)
                {
                    amt_to_write = -1;
                    output->ok = GLOBUS_FALSE;
                    break;
                }
                amt_to_write -= 1024;
            }
            /* write leftovers (< !K) */
            if(amt_to_write > 0)
            {
                if (globus_l_gram_jm_read(fd, buf, amt_to_write) < 0)
                {
                    amt_to_write = -1;
                    output->ok = GLOBUS_FALSE;
                    break;
                }
                if (globus_l_gram_jm_write(output_fd, buf, amt_to_write) < 0)
                {
                    amt_to_write = -1;
                    output->ok = GLOBUS_FALSE;
                    break;
                }
            }
            globus_libc_close(fd);

            globus_libc_free(output->cache_file);
            globus_libc_free(output);
        }
    }    
    globus_libc_free(buf);

} /* globus_l_gram_delete_file_list() */


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
