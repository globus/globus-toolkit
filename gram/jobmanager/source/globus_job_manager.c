/******************************************************************************
gram_job_manager.c 

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

#include "globus_nexus.h"
#include "globus_gram_client.h"
#include "globus_i_gram_version.h"
#include "globus_i_gram_handlers.h"
#include "grami_fprintf.h"
#include "globus_rsl.h"
#include "globus_i_gram_jm.h"
#include "globus_gass_file.h"
#include "globus_gass_cache.h"
#include "globus_gass_client.h"
#include "globus_duct_control.h"

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct _graml_jm_monitor_t
{
    nexus_mutex_t          mutex;
    nexus_cond_t           cond;
    volatile nexus_bool_t  done;
} graml_jm_monitor_t;

/* Only poll once every GRAM_JOB_MANAGER_POLL_FREQUENCY seconds */
#define GRAM_JOB_MANAGER_POLL_FREQUENCY 10

/* Only do status file cleanup once every 
 * GRAM_JOB_MANAGER_STAT_FREQUENCY seconds
 */
#define GRAM_JOB_MANAGER_STAT_FREQUENCY 60

/* remove old status files after no activity for
 * GRAM_JOB_MANAGER_STATUS_FILE_SECONDS
 */
#define GRAM_JOB_MANAGER_STATUS_FILE_SECONDS 60

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static void 
graml_cancel_handler(nexus_endpoint_t * endpoint,
                     nexus_buffer_t * buffer,
                     nexus_bool_t is_non_threaded_handler);

static void 
graml_start_time_handler(nexus_endpoint_t * endpoint,
                         nexus_buffer_t * buffer,
                         nexus_bool_t is_non_threaded_handler);

static int 
graml_attach_requested(void * arg,
                       char * url,
                       nexus_startpoint_t * sp);

static int 
globus_l_jm_status_file_gen(int job_status);

static char *
globus_l_jm_genfilename(char * prefix, char * path, char * sufix);

static int
globus_l_jm_stage_file(char **url, int mode);

static int
globus_l_jm_rsl_env_add(globus_rsl_t * ast_node,
                        char * var,
                        char * value);

static int
globus_l_job_manager_duct_environment(int count,
				      char *myjob,
				      char **newvar,
				      char **newval);
static char *
globus_l_jm_getenv_var(char * env_var_name,
                       char * default_name);

static int 
globus_l_jm_rsl_add(char * attribute_name, 
                    char * attribute_value);

static void
globus_l_jm_basename(char * filepath,
                     char ** ptr_to_basename);

static void
globus_l_jm_status_file_cleanup(void);

static int
globus_l_jm_tokenize(char * command, char ** args, int * n);

/******************************************************************************
                       Define variables for external use
******************************************************************************/

/*
 * these are used by fork and shell to set environment variables for the job.
 *
 *                                         reason needed
 *                                         --------------
 */
char * grami_env_x509_user_proxy = NULL;   /* security */
char * grami_env_x509_cert_dir = NULL;     /* security */
char * grami_env_krb5ccname = NULL;        /* security */
char * grami_env_nlspath = NULL;           /* poe fork */
char * grami_env_logname = NULL;           /* all */
char * grami_env_home = NULL;              /* all */
char * grami_env_tz = NULL;                /* all */
char * grami_relocate_user_proxy = NULL;   /* security only used for 
                                              easymcs and loadleveler */

/*
 * other GRAM internal variables 
 */
char * grami_jm_libexecdir = GLOBUS_LIBEXECDIR;
char * grami_script_arg_file = NULL;
char * grami_jm_type = NULL;
char * grami_logfile = NULL;
FILE * grami_log_fp = NULL;
int    grami_current_job_state = -1;

extern int errno;

/******************************************************************************
                       Define module specific variables
******************************************************************************/

/* In threaded nexus, nexus_attach() will deadlock if the called from a
 * non-threaded handler
 */
static nexus_handler_t graml_handlers[] =
{ 
#ifdef BUILD_LITE
    {NEXUS_HANDLER_TYPE_NON_THREADED, graml_cancel_handler},
    {NEXUS_HANDLER_TYPE_NON_THREADED, graml_start_time_handler},
#else
    {NEXUS_HANDLER_TYPE_THREADED, graml_cancel_handler},
    {NEXUS_HANDLER_TYPE_THREADED, graml_start_time_handler},
#endif  /* BUILD_LITE */
};

static char graml_callback_contact[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
static char *  graml_job_contact = NULL;
static char    graml_job_status_file[1024];
static char *  graml_env_globus_id = NULL;
static char *  graml_job_status  = NULL;
static char *  graml_nickname  = NULL;
static globus_rsl_t * graml_rsl_tree;

static char *                      graml_jm_status_dir = NULL;
static int                         graml_my_count;
static graml_jm_monitor_t          graml_jm_monitor;
static nexus_endpointattr_t        graml_EpAttr;
static nexus_endpoint_t            graml_GlobalEndpoint;
static nexus_mutex_t               graml_api_mutex;
static int                         graml_api_mutex_is_initialized = 0;
static int                         graml_job_state_mask;
 
#define GRAM_LOCK { \
    int err; \
    assert (graml_api_mutex_is_initialized==1); \
    err = nexus_mutex_lock (&graml_api_mutex); assert (!err); \
}

#define GRAM_UNLOCK { \
    int err; \
    err = nexus_mutex_unlock (&graml_api_mutex); assert (!err); \
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
    int                    size;
    int                    rc;
    int                    count;
    int                    gram_version;
    int                    n_nodes;
    int                    format;
    int                    job_status;
    int                    message_handled;
    int                    print_debug_flag = 0;
    int                    save_files_flag = 0;
    char                   rsl_spec[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
    char                   test_dat_file[256];
    char                   tmp_buffer[256];
    char *                 jm_home_dir = NULL;
    char *                 arg_libexecdir = NULL;
    char *                 tmp_ptr;
    char *                 my_host;
    unsigned short         my_port;
    FILE *                 args_fp;
    nexus_byte_t           type;
    nexus_byte_t *         ptr;
    nexus_byte_t           bformat;
    nexus_byte_t           buffer[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
    nexus_buffer_t         reply_buffer;
    nexus_startpoint_t     reply_sp;
    globus_rsl_t *         rsl_tree;
    globus_gass_cache_t           cache_handle;
    globus_gass_cache_entry_t   * cache_entries;
    int                    cache_size;
    globus_symboltable_t * symbol_table; 
    char *                 jm_globus_site_dn = NULL;
    char *                 jm_globus_gram_dn = NULL;
    char *                 jm_globus_host_dn = NULL;
    char *                 jm_globus_host_manufacturer = NULL;
    char *                 jm_globus_host_cputype = NULL;
    char *                 jm_globus_host_osname = NULL;
    char *                 jm_globus_host_osversion = NULL;
    char *                 jm_globus_prefix;

    /* Initialize modules that I use */
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
		GLOBUS_DUCT_CONTROL_MODULE->module_name,
		rc);
	exit(1);
    }

    nexus_enable_fault_tolerance(NULL, NULL);

    if ( graml_api_mutex_is_initialized == 0 )
    {
        /* initialize mutex which makes the client thread-safe */
        int err;
		 
        err = nexus_mutex_init (&graml_api_mutex, NULL); assert (!err);
        graml_api_mutex_is_initialized = 1;
    }

    GRAM_LOCK;

    *test_dat_file = '\0';

    /* if -jmconf is passed then get the arguments from the file
     * specified
     */
    if (argc == 3 && !strcmp(argv[1],"-conf"))
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
        {
	    fprintf(stderr, "Unable to read parameters from configuration "
                            "file\n");
	    exit(1);
        }
        newbuf[i] = '\0';
        close(pfd);

        newargv[0] = argv[0];
        newargc--;
        globus_l_jm_tokenize(newbuf, &newargv[1], &newargc);
        argv = newargv;
        argc = newargc + 1;
    }

    /*
     * Parse the command line arguments
     */
    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-t") == 0)
                 && (i + 1 < argc))
        {
            strcpy(test_dat_file, argv[i+1]);
            i++;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            print_debug_flag = 1;
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            save_files_flag = 1;
        }
        else if ((strcmp(argv[i], "-home") == 0)
                 && (i + 1 < argc))
        {
            jm_home_dir = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-nickname") == 0)
                 && (i + 1 < argc))
        {
            graml_nickname = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-type") == 0)
                 && (i + 1 < argc))
        {
            grami_jm_type = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-e") == 0)
                 && (i + 1 < argc))
        {
            arg_libexecdir = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-globus_site_dn") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_site_dn = strdup(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-globus_gram_dn") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_gram_dn = strdup(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-globus_host_dn") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_host_dn = strdup(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-globus_host_manufacturer") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_host_manufacturer = strdup(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-globus_host_cputype") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_host_cputype = strdup(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-globus_host_osname") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_host_osname = strdup(argv[i+1]);
            i++;
        }
        else if ((strcmp(argv[i], "-globus_host_osversion") == 0)
                 && (i + 1 < argc))
        {
            jm_globus_host_osversion = strdup(argv[i+1]);
            i++;
        }
        else
        {
	    GRAM_UNLOCK;
            fprintf(stderr, "Unknown argument %s\n", argv[i]);
            fprintf(stderr, "Usage: %s %s %s %s %s %s %s %s %s %s\n",
                    argv[0],
                    "[-home deploy home dir ] [-e lib exe dir]",
                    "[-d debug print] [-s save files]",
                    "[-nickname resource manager nickname]",
                    "[-type resource manager type] [-globus_site_dn dn]",
                    "[-globus_gram_dn dn] [-globus_host_dn dn]",
                    "[-globus_host_manufacturer manufacturer]",
                    "[-globus_host_cputype cputype]",
                    "[-globus_host_osname osname]",
                    "[-globus_host_osversion osversion ] [-t test dat file]"
                   );
            exit(1);
        }
    }

    grami_env_home = globus_l_jm_getenv_var("HOME", NULL);
    if (!grami_env_home)
    {
        /* we have to have HOME because we might need it for the default
         * directory for the user's job
         */
        fprintf(stderr, "ERROR: unable to get HOME from the environment.\n");
	exit(1);
    }

    if (print_debug_flag)
    {
        /*
         * Open the gram logfile just for testing!
         */
        sprintf(tmp_buffer, "%s/gram_job_mgr_%lu.log",
                grami_env_home,
                (unsigned long) getpid());

        if ((grami_log_fp = fopen(tmp_buffer, "a")) == NULL)
        {
            sprintf(tmp_buffer, "/tmp/gram_job_mgr_%lu.log",
                   (unsigned long) getpid());

            if ((grami_log_fp = fopen(tmp_buffer, "a")) == NULL)
            {
	        GRAM_UNLOCK;
                fprintf(stderr, "JM: Cannot open gram logfile.\n");
                exit(1);
            }
        }
    }
    else
    {
        strcpy(tmp_buffer, "/dev/null");
    }

    grami_logfile = (char *) globus_malloc (strlen(tmp_buffer) + 1);
    strcpy(grami_logfile, tmp_buffer);

    grami_fprintf(grami_log_fp,"-----------------------------------------\n");
    grami_fprintf(grami_log_fp, "JM: Entering gram_job_manager main()\n");

    if (!graml_nickname)
    {
        graml_nickname = globus_malloc (sizeof(char *) * 11);
        strcpy(graml_nickname, "nonickname");
    }

    grami_fprintf( grami_log_fp, "JM: nickname = %s\n", graml_nickname);
    grami_fprintf( grami_log_fp, "JM: HOME = %s\n", grami_env_home);

    /*
     * Getting environment variables for RSL substitution.
     */
    grami_env_logname = globus_l_jm_getenv_var("LOGNAME", "noname");

    /*
     * Getting environment variables to be added to RSL.
     */
    graml_env_globus_id =
         globus_l_jm_getenv_var("GLOBUS_ID", "unknown globusid");
 
    /*
     * Getting environment variables to be added to the job's environment.
     * LOGNAME and HOME will be added as well
     */
    grami_env_x509_user_proxy= globus_l_jm_getenv_var("X509_USER_PROXY", NULL);
    grami_env_x509_cert_dir  = globus_l_jm_getenv_var("X509_CERT_DIR", NULL);
    grami_env_krb5ccname     = globus_l_jm_getenv_var("KRB5CCNAME", NULL);
    grami_env_nlspath        = globus_l_jm_getenv_var("NLSPATH", NULL);
    grami_env_tz             = globus_l_jm_getenv_var("TZ", NULL);

    if (jm_home_dir)
    {
        graml_jm_status_dir = globus_l_jm_genfilename(jm_home_dir, "tmp", NULL);
        sprintf(graml_job_status_file, "%s/%s_%s_%s.%lu",
                                       graml_jm_status_dir,
                                       STATUS_FILE_PREFIX,
                                       graml_nickname,
                                       grami_env_logname,
                                       (unsigned long) getpid() );

        grami_fprintf( grami_log_fp, "JM: graml_job_status_file = %s\n", 
                       graml_job_status_file);

        if (arg_libexecdir)
        {
            grami_jm_libexecdir = globus_l_jm_genfilename(jm_home_dir,
                                              arg_libexecdir, NULL);
        }
        else
        {
            grami_jm_libexecdir = globus_l_jm_genfilename(jm_home_dir,
                                              "libexec", NULL);
        }
    }
    else
    {
        /* in this case a status file will not be written */
        graml_jm_status_dir = NULL;
        graml_job_status_file[0] = '\0';
    }

    grami_fprintf( grami_log_fp, "JM: grami_jm_libexecdir = %s\n", 
                   grami_jm_libexecdir);

    /*
     *  if a test_dat_file has been defined, read data from the file 
     *  instead of from stdin.
     */
    if (strlen(test_dat_file) > 0)
    {
        if ((args_fp = fopen(test_dat_file, "r")) == NULL)
        {
	    GRAM_UNLOCK;
            grami_fprintf( grami_log_fp, "JM: Cannot open test file %s.\n",
                           test_dat_file);
            exit(1);
        }
    }
    else
    {
         args_fp = stdin;
    }

    /*
     * Read the format incoming message.
     */
    if (fread(buffer, 1, 1, args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read format of message buffer.\n");
    }
    format = (int)buffer[0];

    /*
     * Read the globus gram protocol version number.
     */
    if (fread(buffer, 1, nexus_dc_sizeof_remote_int(1, format), args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read gram protocol version number.\n");
    }
    ptr = buffer;
    nexus_user_get_int(&ptr, &gram_version, 1, format);

    if (GLOBUS_GRAM_PROTOCOL_VERSION != gram_version)
    {
        grami_fprintf(grami_log_fp, 
              "JM: ERROR: globus gram protocol version mismatch!\n");
        grami_fprintf(grami_log_fp, 
              "JM: gram client version      = %d\n", gram_version);
        grami_fprintf(grami_log_fp, 
              "JM: gram job manager version = %d\n",
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
    if (fread(buffer, 1, nexus_dc_sizeof_remote_int(1, format), args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read size of message buffer.\n");
    }
    ptr = buffer;
    nexus_user_get_int(&ptr, &count, 1, format);

    /*
     * Read the remainder of the incoming message.
     */
    if (fread(buffer, 1, count - nexus_dc_sizeof_remote_int(1, format) + 1,
        args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read the message buffer.\n");
    }

    ptr = buffer;
    nexus_user_get_int(&ptr, &count, 1, format);
    nexus_user_get_char(&ptr, rsl_spec, count, format);
    *(rsl_spec+count)= '\0';
    nexus_user_get_int(&ptr, &graml_job_state_mask, 1, format);
    nexus_user_get_int(&ptr, &count, 1, format);
    if (count == 0)
    {
        *(graml_callback_contact) = '\0';
    }
    else
    {
        nexus_user_get_char(&ptr, graml_callback_contact, count, format);
        *(graml_callback_contact+count)= '\0';
    }
    nexus_user_get_startpoint(&ptr, &reply_sp, 1, format);

    grami_fprintf( grami_log_fp,
                   "JM: rsl_specification = %s\n", rsl_spec);
    grami_fprintf( grami_log_fp, 
                   "JM: job state mask = %i\n",graml_job_state_mask);
    grami_fprintf( grami_log_fp, 
                   "JM: callback contact = %s\n", graml_callback_contact);

    /* Initialize termination monitor */
    nexus_mutex_init(&graml_jm_monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&graml_jm_monitor.cond, (nexus_condattr_t *) NULL);
    graml_jm_monitor.done = NEXUS_FALSE;

    /*
     * Create an endpoint that will be used by graml_attach_requested
     * when other attach to this job manager
     */
    nexus_endpointattr_init(&graml_EpAttr);
    nexus_endpointattr_set_handler_table(&graml_EpAttr,
                             graml_handlers,
                             sizeof(graml_handlers)/sizeof(nexus_handler_t));
    nexus_endpoint_init(&graml_GlobalEndpoint, &graml_EpAttr);

    /* allow other Nexus programs to attach to us */
    my_port = 0;
    rc = nexus_allow_attach(&my_port,               /* port            */
                            &my_host,               /* host            */
                            graml_attach_requested, /* approval_func() */
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

        graml_job_contact = (char *) globus_malloc (sizeof(char *) *
                                     (strlen(tmp_buffer) + 1));
        strcpy(graml_job_contact, tmp_buffer);

        grami_setenv("GRAM_JOB_CONTACT", graml_job_contact, 1);
    }

    /* call the RSL routine to parse the user request
     */
    rsl_tree = globus_rsl_parse(rsl_spec);
    if (!rsl_tree)
    {
        job_status = GLOBUS_GRAM_CLIENT_ERROR_BAD_RSL;
    }
    else
    {

/*
        printf("\n------------  after parse  ---------------\n\n");
        globus_rsl_print_recursive(rsl_tree);
*/

        jm_globus_prefix = (char *) globus_malloc(sizeof(char *) * 
                                            strlen(GLOBUS_PREFIX) + 1);
        strcpy(jm_globus_prefix, GLOBUS_PREFIX);


        /*
         * build symbol table for RSL evaluation.
         * variable found in the RSL will be replaced with these values.
         */
        symbol_table = (globus_symboltable_t *) globus_malloc 
                            (sizeof(globus_symboltable_t));

        globus_symboltable_init(symbol_table,
                              globus_hashtable_string_hash,
                              globus_hashtable_string_keyeq);

        globus_symboltable_create_scope(symbol_table);

        globus_symboltable_insert(symbol_table,
                                (void *) "HOME",
                                (void *) grami_env_home);
        if (grami_env_logname)
            globus_symboltable_insert(symbol_table,
                                (void *) "LOGNAME",
                                (void *) grami_env_logname);
        if (graml_env_globus_id)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_ID",
                                (void *) graml_env_globus_id);
        if (jm_globus_site_dn)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_SITE_DN",
                                (void *) jm_globus_site_dn);
        if (jm_globus_gram_dn)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_GRAM_DN",
                                (void *) jm_globus_gram_dn);
        if (jm_globus_host_dn)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_DN",
                                (void *) jm_globus_host_dn);
        if (jm_globus_host_manufacturer)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_MANUFACTURER",
                                (void *) jm_globus_host_manufacturer);
        if (jm_globus_host_cputype)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_CPUTYPE",
                                (void *) jm_globus_host_cputype);
        if (jm_globus_host_osname)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_OSNAME",
                                (void *) jm_globus_host_osname);
        if (jm_globus_host_osversion)
            globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_HOST_VERSION",
                                (void *) jm_globus_host_osversion);
        globus_symboltable_insert(symbol_table,
                                (void *) "GLOBUS_PREFIX",
                                (void *) jm_globus_prefix);
    
        if (globus_rsl_eval(rsl_tree, symbol_table) != 0)
        {
            job_status = GLOBUS_GRAM_CLIENT_ERROR_RSL_EVALUATION_FAILED;
        }
        else
        {
/*
            printf("\n------------  after eval  ---------------\n\n");
            globus_rsl_print_recursive(rsl_tree);
*/

            graml_rsl_tree = rsl_tree;

            /*
             * Start the job.  If successful reply with graml_job_contact else
             * send error status.
             */
            job_status = grami_jm_job_request(graml_job_contact, rsl_tree);
        }
    }


    if (job_status == 0)
    {
        count= strlen(graml_job_contact);
	size = nexus_sizeof_int(1);
	size += nexus_sizeof_int(1);
	size += nexus_sizeof_int(1);
	size += nexus_sizeof_char(count);
	nexus_buffer_init(&reply_buffer, size, 0);
        nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
        nexus_put_int(&reply_buffer, &job_status, 1);
        nexus_put_int(&reply_buffer, &count, 1);
	nexus_put_char(&reply_buffer, graml_job_contact, count);
    }
    else
    {
	size = nexus_sizeof_int(2);
	nexus_buffer_init(&reply_buffer, size, 0);
        nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
        nexus_put_int(&reply_buffer, &job_status, 1);
    }
 
    nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   GLOBUS_I_GRAM_CLIENT_REPLY_HANDLER_ID,
                   NEXUS_TRUE,
                   NEXUS_FALSE);

    nexus_startpoint_destroy(&reply_sp);

    GRAM_UNLOCK;

    grami_fprintf( grami_log_fp, 
                   "JM: job status from grami_jm_job_request = %d\n",
                   job_status);

    if (job_status == 0)
    {
	int skip_poll = GRAM_JOB_MANAGER_POLL_FREQUENCY;
	int skip_stat = GRAM_JOB_MANAGER_STAT_FREQUENCY;
        while (!graml_jm_monitor.done)
        {
            /*
            nexus_cond_wait(&graml_jm_monitor.cond, 
                            &graml_jm_monitor.mutex);
            */
	    globus_libc_usleep(1000000);

    	    nexus_fd_handle_events(GLOBUS_NEXUS_FD_POLL_NONBLOCKING_ALL, 
                                   &message_handled);
	    if (--skip_poll <= 0)
	    {
                GRAM_LOCK;
                /* touch the file so we know we did not crash */
                if ( utime(graml_job_status_file, NULL) != 0 )
                {
                    if(errno == ENOENT)
                    {
                        globus_l_jm_status_file_gen(grami_current_job_state);
                    }
                }
		grami_jm_poll();
                GRAM_UNLOCK;
		skip_poll = GRAM_JOB_MANAGER_POLL_FREQUENCY;
	    }
	    if (--skip_stat <= 0)
	    {
                GRAM_LOCK;
                globus_l_jm_status_file_cleanup();
                GRAM_UNLOCK;
		skip_stat = GRAM_JOB_MANAGER_STAT_FREQUENCY;
	    }
        } /* endwhile */
    }

    if (save_files_flag)
    {
        grami_fprintf( grami_log_fp, 
            "JM: NOTICE, flag set to NOT DELETE script argument file --> %s\n",
            grami_script_arg_file);
        grami_fprintf( grami_log_fp, 
            "JM: NOTICE, flag set to NOT DELETE user proxy file --> %s\n",
            grami_env_x509_user_proxy);
    }
    else
    {
        if (grami_script_arg_file)
        {
            if (remove(grami_script_arg_file) != 0)
            {
                grami_fprintf( grami_log_fp, 
                         "JM: Cannot remove argument file --> %s\n",
                         grami_script_arg_file);
            }
            else
            {
                grami_fprintf( grami_log_fp, 
                         "JM: Removed argument file --> %s\n",
                         grami_script_arg_file);
            }
            free(grami_script_arg_file);
        }

        if (grami_env_x509_user_proxy)
        {
            if (remove(grami_env_x509_user_proxy) != 0)
            {
                grami_fprintf( grami_log_fp, 
                         "JM: Cannot remove user proxy file --> %s\n",
                         grami_env_x509_user_proxy);
            }
            else
            {
                grami_fprintf( grami_log_fp, 
                         "JM: Removed user proxy file --> %s\n",
                         grami_env_x509_user_proxy);
            }
        }
    }

    /* clear any other cache entries which contain this job contact as
       the tag
     */
    grami_fprintf( grami_log_fp,
		   "JM: Cleaning GASS cache\n");
    rc = globus_gass_cache_open(NULL,
				&cache_handle);
    if(rc == GLOBUS_SUCCESS)
    {
	rc = globus_gass_cache_list(&cache_handle,
				    &cache_entries,
				    &cache_size);
	if(rc == GLOBUS_SUCCESS)
	{
	    for(i=0; i<cache_size; i++)
	    {
		grami_fprintf(grami_log_fp,
			      "Trying to clean up with <url=%s> <tag=%s>\n",
			      cache_entries[i].url,
			      graml_job_contact);
		globus_gass_cache_cleanup_tag(&cache_handle,
					      cache_entries[i].url,
					      graml_job_contact);
	    }
	}
	fflush(grami_log_fp);
	globus_gass_cache_list_free(cache_entries,
				    cache_size);
	globus_gass_cache_close(&cache_handle);
    }

    grami_fprintf( grami_log_fp, "JM: freeing RSL.\n");
    globus_rsl_free_recursive(graml_rsl_tree);

    nexus_disallow_attach(my_port);

    nexus_mutex_destroy(&graml_jm_monitor.mutex);
    nexus_cond_destroy(&graml_jm_monitor.cond);

    grami_fprintf( grami_log_fp, "JM: starting deactivate routines.\n");

    rc = globus_module_deactivate(GLOBUS_DUCT_CONTROL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "%s deactivation failed with rc=%d\n",
		GLOBUS_DUCT_CONTROL_MODULE->module_name,
		rc);
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

    grami_fprintf( grami_log_fp, "JM: exiting gram_job_request\n");

    return(0);

} /* main() */

/******************************************************************************
Function:       graml_attach_requested()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
graml_attach_requested(void * arg,
                 char * url,
                 nexus_startpoint_t * sp)
{
    grami_fprintf( grami_log_fp, "JM: in graml_attach_requested callback\n");

    nexus_startpoint_bind(sp, &graml_GlobalEndpoint);

    return(0);
} /* graml_attach_requested() */


/******************************************************************************
Function:       grami_jm_callback()
Description:
Parameters:
Returns:
******************************************************************************/
void 
grami_jm_callback(int state, int errorcode)
{
    int                size;
    int                count;
    int                rc;
    nexus_startpoint_t sp;
    nexus_buffer_t     reply_buffer;
    
    grami_fprintf( grami_log_fp, "JM: in grami_jm_callback\n");

    if (graml_jm_status_dir)
    {
       globus_l_jm_status_file_gen(state); 
    }

    if (strlen(graml_callback_contact) != 0 && 
        (state & graml_job_state_mask))
    {
        /* This will block if called from a non-threaded handler
         */
        rc = nexus_attach(graml_callback_contact, &sp);
    
        if (rc == 0)
        {
            size  = nexus_sizeof_int(1);
            size += nexus_sizeof_int(1);
            size += nexus_sizeof_char(strlen(graml_job_contact));
            size += nexus_sizeof_int(1);
            size += nexus_sizeof_int(1);

            count= strlen(graml_job_contact);
            nexus_buffer_init(&reply_buffer, size, 0);
            nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
            nexus_put_int(&reply_buffer, &count, 1);
            nexus_put_char(&reply_buffer, graml_job_contact, count);
            nexus_put_int(&reply_buffer, &state, 1);
            nexus_put_int(&reply_buffer, &errorcode, 1);

            nexus_send_rsr(&reply_buffer,
                           &sp,
                           0,
                           NEXUS_TRUE,
                           NEXUS_FALSE);

            nexus_startpoint_destroy(&sp);
       }
   }

} /* grami_jm_callback() */

/******************************************************************************
Function:       globus_l_jm_status_file_gen()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_jm_status_file_gen(int job_status)
{
    FILE *             status_fp;
    struct stat        statbuf;
    char *             request_string = NULL;
    char *             tmp_attribute;

    grami_fprintf( grami_log_fp, "JM: in globus_l_jm_status_file_gen\n");

    if (!graml_jm_status_dir)
    {
       return(0); 
    }

    /*
     * Check to see if the status file exists.  If so, then delete it.
     */
    if (stat(graml_job_status_file, &statbuf) == 0)
    {
        if (remove(graml_job_status_file) != 0)
        {
            grami_fprintf( grami_log_fp, "\n--------------------------\n");
            grami_fprintf( grami_log_fp, 
                  "JM: Cannot remove status file --> %s\n",
                  graml_job_status_file);
            grami_fprintf( grami_log_fp, "--------------------------\n");
            return(1);
        }
    }
 
    /*
     *  don't output a status file when the job has terminated
     */
    if ((job_status != GLOBUS_GRAM_CLIENT_JOB_STATE_DONE) && 
        (job_status != GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED))
    {

        if ((status_fp = fopen(graml_job_status_file, "a")) == NULL)
        {
            grami_fprintf( grami_log_fp, "\n--------------------------\n");
            grami_fprintf( grami_log_fp, 
                           "JM: Cannot open status file --> %s\n",
                           graml_job_status_file);
            grami_fprintf( grami_log_fp, "JM: job contact = %s\n",
                           graml_job_contact);
            grami_fprintf( grami_log_fp, "JM: MDS will NOT be updated!!!\n");
            grami_fprintf( grami_log_fp, "--------------------------\n\n");
            return(1);
        }
        else
        {
            /* if the job status variable has not been initialized then
             * add the job data to the rsl only this once.
             */ 
            if (graml_job_status == NULL)
            {
                tmp_attribute = (char *) globus_malloc(sizeof(char *) * 12);
                strcpy(tmp_attribute, "job_contact");
                
                /*
                 * create the RSL relation for the job contact
                 */
                if (globus_l_jm_rsl_add(tmp_attribute, graml_job_contact) != 0)
                {
                    grami_fprintf( grami_log_fp, 
                        "JM: ERROR adding %s to the RSL.\n", tmp_attribute);
                }

                /*
                 * create the RSL relation for the globusid
                 */
                tmp_attribute = (char *) globus_malloc(sizeof(char *) * 10);
                strcpy(tmp_attribute, "globus_id");
                
                if (globus_l_jm_rsl_add(tmp_attribute, graml_env_globus_id) != 0)
                {
                    grami_fprintf( grami_log_fp, 
                        "JM: ERROR adding %s to the RSL.\n", tmp_attribute);
                }

                /*
                 * create the RSL relation for the job status
                 */
                tmp_attribute = (char *) globus_malloc(sizeof(char *) * 11);
                strcpy(tmp_attribute, "job_status");
                
                /* large enough to handle any states and then some */
                graml_job_status = (char *) globus_malloc(sizeof(char *) * 51);

                if (globus_l_jm_rsl_add(tmp_attribute, graml_job_status) != 0)
                {
                    grami_fprintf( grami_log_fp, 
                        "JM: ERROR adding %s to the RSL.\n", tmp_attribute);
                }
            }

            /* convert status integer to a string.  graml_job_status will
             * update the JM_job_status parameter in the RSL  
             */
            switch(job_status)
            {
                case GLOBUS_GRAM_CLIENT_JOB_STATE_PENDING:
                    strcpy(graml_job_status, "PENDING");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_ACTIVE:
                    strcpy(graml_job_status, "ACTIVE");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_DONE:
                    strcpy(graml_job_status, "DONE");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED:
                    strcpy(graml_job_status, "FAILED");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_SUSPENDED:
                    strcpy(graml_job_status, "SUSPENDED");
                    break;
                default:
                    strcpy(graml_job_status, "UNKNOWN");
                    break;
            }

            /* output data into the status file in the format that the
             * gram-reporter is expecting it.
             */
            fprintf(status_fp, "---___start___---\n");

            if ((request_string = globus_rsl_unparse(graml_rsl_tree)) == NULL)
            {
                fprintf(status_fp, "Job data unknown\n"); 
            }
            else
            {
                fprintf(status_fp, "%s\n", request_string);

                grami_fprintf(grami_log_fp, "=== REQUEST STRING ===\n\n%s\n",
                          request_string);
            }

            fprintf(status_fp, "---___end___---\n");
            fclose(status_fp);
        }
    }

    return(0);

} /* globus_l_jm_status_file_gen() */

int
globus_l_jm_rsl_env_add(globus_rsl_t * ast_node,
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

            globus_l_jm_rsl_env_add(tmp_rsl_ptr,
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
}

/******************************************************************************
Function:       globus_l_jm_rsl_add()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_jm_rsl_add(char * attribute_name, 
                    char * attribute_value)
{
   globus_list_t * new_list;

   if (globus_rsl_is_boolean(graml_rsl_tree))
   {
       new_list = NULL;

       globus_list_insert(&new_list, (void *)
           globus_rsl_value_make_literal(attribute_value));

       globus_list_insert(
           globus_rsl_boolean_get_operand_list_ref(graml_rsl_tree),
           (void *) globus_rsl_make_relation(
                         GLOBUS_RSL_EQ,
                         attribute_name,
                         globus_rsl_value_make_sequence(new_list)));
   }
   else
   {
       return(1);
   }

   return(0);

} /* globus_l_jm_rsl_add() */



/******************************************************************************
Function:       grami_jm_request_params()
Description:
Parameters:
Returns:
******************************************************************************/
int 
grami_jm_request_params(globus_rsl_t * rsl_tree,
                        gram_request_param_t * params)
{
    char * tmp_dir;
    int tmp_fd;
    int x;
    struct stat statbuf;
    char ** tmp_param;
    char * proxy_file_name;

    if (rsl_tree == NULL)
        return(GLOBUS_GRAM_CLIENT_ERROR_NULL_SPECIFICATION_TREE);
 
    /********************************** 
     *  GET PROGRAM (executable) PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_EXECUTABLE_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->pgm = (tmp_param)[0];
    else
    {
        params->pgm = GLOBUS_GRAM_CLIENT_DEFAULT_EXE;
    }

    /********************************** 
     *  GET PROGRAM ARGUMENTS PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                       GLOBUS_RSL_PARAM_MULTI_LITERAL,
		       GLOBUS_GRAM_CLIENT_ARGUMENTS_PARAM, 
                       &(params->pgm_args)) != 0)
    {
        return(1);
    }

    /********************************** 
     *  GET DIR PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
		             GLOBUS_GRAM_CLIENT_DIR_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->dir = tmp_param[0];
    else
        params->dir = grami_env_home;

    /********************************** 
     *  GET STDIN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_STDIN_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->std_in = tmp_param[0];
    else
        params->std_in = GLOBUS_GRAM_CLIENT_DEFAULT_STDIN;

    /********************************** 
     *  GET STDOUT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_STDOUT_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->std_out = tmp_param[0];
    else
        params->std_out = GLOBUS_GRAM_CLIENT_DEFAULT_STDOUT;

    /********************************** 
     *  GET STDERR PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_STDERR_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->std_err = tmp_param[0];
    else
        params->std_err = GLOBUS_GRAM_CLIENT_DEFAULT_STDERR;

    /********************************** 
     *  GET COUNT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_COUNT_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
    {

        params->count = atoi(tmp_param[0]);

        if (params->count < 1)
            return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_COUNT);
    }
    else
    {
        params->count = 1;
    }

    /* save count parameter for reporting to MDS */ 
    graml_my_count = params->count;

    /********************************** 
     *  GET MAXTIME PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_MAXTIME_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
    {
        params->maxtime = atoi(tmp_param[0]);

        if (params->maxtime < 1)
            return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAXTIME);
    }
    else
    {
        params->maxtime = 0;
    }

    /********************************** 
     *  GET HOST_COUNT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_HOST_COUNT_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
    {
        params->host_count = atoi(tmp_param[0]);

        if (params->host_count < 1)
            return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_HOST_COUNT);
    }
    else
    {
        params->host_count = 0;
    }

    /********************************** 
     *  GET PARADYN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_PARADYN_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->paradyn = tmp_param[0];
    else
        params->paradyn = NULL;

    /********************************** 
     *  GET JOBTYPE PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_JOBTYPE_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->jobtype = tmp_param[0];
    else
        params->jobtype = GLOBUS_GRAM_CLIENT_DEFAULT_JOBTYPE;

    /********************************** 
     *  GET MYJOB PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_MYJOB_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->gram_myjob = tmp_param[0];
    else
        params->gram_myjob = GLOBUS_GRAM_CLIENT_DEFAULT_MYJOB;

    /********************************** 
     *  GET DRYRUN PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_DRYRUN_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->dryrun = tmp_param[0];
    else
        params->dryrun = GLOBUS_GRAM_CLIENT_DEFAULT_DRYRUN;

    /**********************************
     *  GET QUEUE PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_QUEUE_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->queue = tmp_param[0];
    else
        params->queue = NULL;
 
    /**********************************
     *  GET PROJECT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                             GLOBUS_GRAM_CLIENT_PROJECT_PARAM,
		             &tmp_param) != 0)
    {
        return(1);
    }

    if (tmp_param[0])
        params->project = tmp_param[0];
    else
        params->project = NULL;

    /********************************** 
     *  GET ENVIRONMENT PARAM
     */
    if (globus_rsl_param_get(rsl_tree,
                             GLOBUS_RSL_PARAM_SEQUENCE,
	                     GLOBUS_GRAM_CLIENT_ENVIRONMENT_PARAM, 
                             &(params->pgm_env)) != 0)
    {
        return(1);
    }

    /*
     * Check for X509 variables and add them to the environment that is
     * passed to the schedulers.
     */
    if (grami_env_x509_cert_dir)
    {
	for(x = 0; params->pgm_env[x] != GLOBUS_NULL; x++)
	{
	    ;
	}
	    
	params->pgm_env = (char **)
            globus_libc_realloc(params->pgm_env,
                    (x+3) * sizeof(char *));

        params->pgm_env[x] = "X509_CERT_DIR";
        ++x;
        params->pgm_env[x] = grami_env_x509_cert_dir;
        ++x;
        params->pgm_env[x] = GLOBUS_NULL;

    }

    if (grami_env_x509_user_proxy)
    {
	for(x = 0; params->pgm_env[x] != GLOBUS_NULL; x++)
	{
	    ;
	}
	    
	params->pgm_env = (char **)
            globus_libc_realloc(params->pgm_env,
                    (x+3) * sizeof(char *));

        params->pgm_env[x] = "X509_USER_PROXY";
        ++x;

        if (strcmp(grami_jm_type,"loadleveler") == 0 ||
            strcmp(grami_jm_type,"easymcs") == 0 )
        {
            globus_l_jm_basename(grami_env_x509_user_proxy, &proxy_file_name);

            if (proxy_file_name == NULL)
            {
                return(GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_RELOCATION_FAILED);
            }
            grami_relocate_user_proxy = globus_malloc(strlen(grami_env_home) +
                                             strlen(proxy_file_name) + 2);
            sprintf(grami_relocate_user_proxy, "%s/%s", grami_env_home,
                                               proxy_file_name);
            params->pgm_env[x] = grami_relocate_user_proxy;
        }
        else
        {
            params->pgm_env[x] = grami_env_x509_user_proxy;
        }
        ++x;
        params->pgm_env[x] = GLOBUS_NULL;
    }

    {
	char *newvar;
	char *newval;
	int i;
	int rc;

	/* add duct environment string to environment */
	rc = globus_l_job_manager_duct_environment(params->count,
						   params->gram_myjob,
						   &newvar,
						   &newval);
	if(rc == GLOBUS_SUCCESS)
	{
	    for(i = 0; params->pgm_env[i] != GLOBUS_NULL; i++)
	    {
		;
	    }
	    
	    params->pgm_env = (char **)
		globus_libc_realloc(params->pgm_env,
				    (i+3) * sizeof(char *));
	    params->pgm_env[i] = newvar;
	    ++i;
	    params->pgm_env[i] = newval;
	    ++i;
	    params->pgm_env[i] = GLOBUS_NULL;
            if (globus_l_jm_rsl_env_add(rsl_tree, newvar, newval) != 0)
            {
                grami_fprintf( grami_log_fp, 
                        "JM: ERROR adding %s to the environment= parameter "
                        "of the RSL.\n", newvar);
            }
	}
    }
    
    /* GEM: Stage pgm and std_in to local filesystem, if they are URLs.
       Do this before paradyn rewriting.
     */
    if (globus_l_jm_stage_file(&(params->pgm), 0700) != GLOBUS_SUCCESS)
    {
        return(GLOBUS_GRAM_CLIENT_ERROR_STAGING_EXECUTABLE);
    }

    if (globus_l_jm_stage_file(&(params->std_in), 0400) != GLOBUS_SUCCESS)
    {
        return(GLOBUS_GRAM_CLIENT_ERROR_STAGING_STDIN);
    }
    
    if (grami_is_paradyn_job(params))
    {
	if (!grami_paradyn_rewrite_params(params))
	{
            return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_PARADYN);
	}

        if (globus_l_jm_stage_file(&(params->pgm), 0700) != GLOBUS_SUCCESS)
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_STAGING_EXECUTABLE);
        }
    }

    return(0);

} /* grami_jm_request_params() */


/******************************************************************************
Function:       grami_jm_terminate()
Description:    breaks out of main() loop
Parameters:
Returns:
******************************************************************************/
void 
grami_jm_terminate()
{
    nexus_mutex_lock(&(graml_jm_monitor.mutex));
    graml_jm_monitor.done = NEXUS_TRUE;
    nexus_cond_signal(&(graml_jm_monitor.cond));
    nexus_mutex_unlock(&(graml_jm_monitor.mutex));
} /* grami_jm_terminate() */


/******************************************************************************
Function:       graml_cancel_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
graml_cancel_handler(nexus_endpoint_t * endpoint,
                     nexus_buffer_t * buffer,
                     nexus_bool_t is_non_threaded_handler)
{
    int                      rc;
    int                      size;
    int                      gram_version;
    nexus_startpoint_t       reply_sp;
    nexus_buffer_t           reply_buffer;

    grami_fprintf( grami_log_fp, "JM: in graml_cancel_handler\n");

    nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        grami_fprintf( grami_log_fp, 
               "JM: ERROR received a version mismatch in cancel handler "
               "ignoring request.\n");
        grami_fprintf( grami_log_fp, 
               "JM: job manager version is %d  client version is %d\n",
               GLOBUS_GRAM_PROTOCOL_VERSION, gram_version);
    }

    nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    nexus_buffer_destroy(buffer);

    GRAM_LOCK;

    rc = grami_jm_job_cancel();

    size = nexus_sizeof_int(2);
    nexus_buffer_init(&reply_buffer, size, 0);
    nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    nexus_put_int(&reply_buffer, &rc, 1);

    nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   NEXUS_TRUE,
                   NEXUS_FALSE);

    nexus_startpoint_destroy(&reply_sp);

    GRAM_UNLOCK;

    if (rc == 0)
    {
        grami_jm_terminate();
    }

} /* graml_cancel_handler() */

/******************************************************************************
Function:       graml_start_time_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
graml_start_time_handler(nexus_endpoint_t * endpoint,
                         nexus_buffer_t * buffer,
                         nexus_bool_t is_non_threaded_handler)
{
    int                      rc;
    int                      size;
    int                      message_handled;
    float                    confidence;
    nexus_startpoint_t       reply_sp;
    nexus_buffer_t           reply_buffer;
    globus_gram_client_time_t              estimate;
    globus_gram_client_time_t              interval_size;

    grami_fprintf( grami_log_fp, "JM: in graml_start_time_handler\n");

    nexus_get_float(buffer, &confidence, 1);
    nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    nexus_buffer_destroy(buffer);

    grami_fprintf( grami_log_fp, 
                   "JM: confidence passed = %f\n", confidence);
    grami_fprintf( grami_log_fp, 
                   "JM: callback contact = %s\n", graml_callback_contact);

    GRAM_LOCK;

    rc = grami_jm_job_start_time(graml_callback_contact,
                                 confidence,
                                 &estimate,
                                 &interval_size);

    size  = nexus_sizeof_int(1);
    size += nexus_sizeof_int(1);
    size += nexus_sizeof_int(1);
    size += nexus_sizeof_int(1);

    nexus_buffer_init(&reply_buffer, size, 0);
    nexus_put_int(&reply_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    nexus_put_int(&reply_buffer, &rc, 1);
    nexus_put_int(&reply_buffer, &estimate.dumb_time, 1);
    nexus_put_int(&reply_buffer, &interval_size.dumb_time, 1);

    nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   NEXUS_TRUE,
                   NEXUS_FALSE);

    nexus_startpoint_destroy(&reply_sp);

    GRAM_UNLOCK;

} /* graml_start_time_handler() */

/******************************************************************************
Function:       globus_l_jm_genfilename()
Description:    generate an absolute file name given a starting prefix,
                                a relative or absolute path, and a sufix
                                Only use prefix if path is relative.
Parameters:
Returns:                a pointer to a string which could be freeded.
******************************************************************************/
static char *
globus_l_jm_genfilename(char * prefixp, char * pathp, char * sufixp)
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
} /* globus_l_jm_genfilename */

/******************************************************************************
Function:       globus_l_jm_stage_file()
Description:    
Parameters:
Returns:
******************************************************************************/
static int
globus_l_jm_stage_file(char **url, int mode)
{
    globus_url_t gurl;
    int rc;
    int error_flag = 0;

    if(url == NULL)
    {
        return(GLOBUS_FAILURE);
    }

    if(strlen(*url) == 0)
    {
        return(GLOBUS_FAILURE);
    }
    grami_fprintf( grami_log_fp, 
                   "JM: staging file = %s\n", *url);

    rc = globus_url_parse(*url, &gurl);
    if(rc == GLOBUS_SUCCESS)	/* this is a valid URL */
    {
	globus_gass_cache_t cache;
	unsigned long timestamp;
	char *tmpname;
	
	globus_gass_cache_open(GLOBUS_NULL,
			       &cache);
	
	rc = globus_gass_cache_add(&cache,
				   *url,
				   graml_job_contact,
				   GLOBUS_TRUE,
				   &timestamp,
				   &tmpname);
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_add_done(&cache,
				       *url,
				       graml_job_contact,
				       timestamp);
	}
	else if(rc == GLOBUS_GASS_CACHE_ADD_NEW)
	{
	    int fd = open(tmpname,
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
		error_flag = globus_gass_client_get_fd(*url,
					  GLOBUS_NULL,
					  fd,
					  GLOBUS_GASS_LENGTH_UNKNOWN,
					  &timestamp,
					  GLOBUS_NULL,
					  GLOBUS_NULL);
	    }
	    close(fd);
	    globus_gass_cache_add_done(&cache,
				       *url,
				       graml_job_contact,
				       timestamp);
	}
	globus_free(*url);
        *url = tmpname;
	globus_gass_cache_close(&cache);
    }
    globus_url_destroy(&gurl);
    grami_fprintf( grami_log_fp, 
                   "JM: new name = %s\n", *url);

    if (error_flag != GLOBUS_SUCCESS)
    {
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);

} /* globus_l_jm_stage_file */

/******************************************************************************
Function:       globus_l_job_manager_duct_environment()
Description:    
Parameters:
Returns:
******************************************************************************/
static int
globus_l_job_manager_duct_environment(int count,
				      char *myjob,
				      char **newvar,
				      char **newval)
{
    globus_duct_control_t *duct;
    int rc;
    
    duct = globus_malloc(sizeof(globus_duct_control_t));
	
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
	grami_fprintf( grami_log_fp,
		       "JM: duct_control_init_failed: %d\n",
		       rc);
	return GLOBUS_GRAM_CLIENT_ERROR_DUCT_INIT_FAILED;
    }

    rc = globus_duct_control_contact_url(duct,
					 newval);

    if(rc != GLOBUS_SUCCESS)
    {
	grami_fprintf( grami_log_fp,
		       "JM: duct_control_contact_url failed: %d\n",
		       rc);
	
	return(GLOBUS_GRAM_CLIENT_ERROR_DUCT_LSP_FAILED);
    }

    (*newvar) = strdup("GLOBUS_GRAM_MYJOB_CONTACT");

    return GLOBUS_SUCCESS;
} /* globus_l_job_manager_duct_environment */

/******************************************************************************
Function:       globus_l_jm_getenv_var()
Description:    
Parameters:
Returns:
******************************************************************************/
static char *
globus_l_jm_getenv_var(char * env_var_name,
                       char * default_name)
{
    char * tmp_env_var;
    char * env_var;

    tmp_env_var = (char *) getenv(env_var_name);

    if (tmp_env_var)
    {
        env_var = (char *) globus_malloc(sizeof(char *) * 
                                         strlen(tmp_env_var) + 1);
        strcpy(env_var, tmp_env_var);
        grami_fprintf( grami_log_fp, "JM: %s = %s\n", env_var_name, env_var);
    }
    else
    {
        grami_fprintf( grami_log_fp, 
                       "JM: unable to get %s from the environment.\n",
                       env_var_name);
        if (default_name)
        {
            env_var = (char *) globus_malloc (sizeof(char *) *
                                            strlen(default_name) + 1);
            strcpy(env_var, default_name);
            grami_fprintf( grami_log_fp, "JM: %s = %s\n", env_var_name,
                 env_var);
        }
        else
        {
            env_var = NULL;
        }
    }

    return(env_var);

} /* globus_l_jm_getenv_var() */

/******************************************************************************
Function:       globus_l_jm_basename()
Description:    
Parameters:
Returns:
******************************************************************************/
static void
globus_l_jm_basename(char * filepath,
                     char ** ptr_to_basename)
{
    if (filepath == NULL)
    {
        *ptr_to_basename = NULL;
    }
    else
    {
        if ((*ptr_to_basename = strrchr(filepath, '/')) == NULL)
        {
            *ptr_to_basename = NULL;
        }
        else
        {
            *ptr_to_basename = *ptr_to_basename + 1;
        }
    }
} /* globus_l_jm_basename() */

/******************************************************************************
Function:       globus_l_jm_status_file_cleanup()
Description:    
Parameters:
Returns:
******************************************************************************/
static void
globus_l_jm_status_file_cleanup(void)
{
    DIR *            status_dir;
    struct dirent *  dir_entry;
    char             logname_string[256];
    char             stat_file_path[1024];
    struct stat      statbuf;
    unsigned long    now;
 
    if(graml_jm_status_dir == GLOBUS_NULL)
    {
        grami_fprintf( grami_log_fp, 
            "JM: status directory not specified, cleanup cannot proceed.\n");
        return;
    }
 
    status_dir = opendir(graml_jm_status_dir);
    if(status_dir == GLOBUS_NULL)
    {
        grami_fprintf( grami_log_fp, 
            "JM: unable to open status directory, aborting cleanup process.\n");
        return;
    }

    sprintf(logname_string, "_%s.", grami_env_logname);
    now = (unsigned long) time(NULL);

    for(globus_libc_readdir_r(status_dir, &dir_entry);
        dir_entry != GLOBUS_NULL;
        globus_libc_readdir_r(status_dir, &dir_entry))
    {
        if (strstr(dir_entry->d_name, logname_string) != NULL)
        {
            sprintf(stat_file_path, "%s/%s", graml_jm_status_dir,
                                      dir_entry->d_name);
            grami_fprintf( grami_log_fp, 
                   "JM: found user file --> %s\n", stat_file_path);
            if (stat(stat_file_path, &statbuf) == 0)
            {
                if ( (now - (unsigned long) statbuf.st_mtime) >
                      GRAM_JOB_MANAGER_STATUS_FILE_SECONDS )
                {
                    grami_fprintf( grami_log_fp, 
                        "JM: status file has not been modified in %d seconds\n",
                        GRAM_JOB_MANAGER_STATUS_FILE_SECONDS);
                    if (remove(stat_file_path) != 0)
                    {
                        grami_fprintf( grami_log_fp, 
                               "JM: Cannot remove old status file --> %s\n",
                               stat_file_path);
                    }
                    else
                    {
                        grami_fprintf( grami_log_fp, 
                               "JM: Removed old status file --> %s\n",
                               stat_file_path);
                    }
                }
            }
        }
    }
    globus_libc_closedir(status_dir);

} /* globus_l_jm_status_file_cleanup() */

/******************************************************************************
Function:       globus_l_jm_tokenize()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_jm_tokenize(char * command, char ** args, int * n)
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

} /* globus_l_jm_tokenize() */
