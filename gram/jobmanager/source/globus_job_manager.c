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
graml_status_file_gen(int job_status);

static char *
genfilename(char * prefix, char * path, char * sufix);

static void
graml_stage_file(char *url, int mode);

static int
globus_l_job_manager_duct_environment(int count,
				      char *myjob,
				      char **newvar,
				      char **newval);

/******************************************************************************
                       Define variables for external use
******************************************************************************/
char * grami_jm_libexecdir = GLOBUS_LIBEXECDIR;
char * grami_user_proxy_path = NULL;
char * grami_script_arg_file = NULL;
char * grami_logfile = NULL;
FILE * grami_log_fp = NULL;


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

static char * graml_my_env_home;
static char graml_callback_contact[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
static char graml_job_contact[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
static char graml_my_globusid[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];

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
    int                    n_nodes;
    int                    format;
    int                    job_status;
    int                    message_handled;
    int                    print_debug_flag = 0;
    int                    save_files_flag = 0;
    char                   description[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
    char                   test_dat_file[256];
    char                   tmp_buffer[256];
    char *                 jm_home_dir = NULL;
    char *                 arg_libexecdir = NULL;
    char *                 tmp_ptr;
    char *                 my_host;
    char *                 globusid_ptr;
    unsigned short         my_port;
    FILE *                 args_fp;
    nexus_byte_t           type;
    nexus_byte_t *         ptr;
    nexus_byte_t           bformat;
    nexus_byte_t           buffer[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];
    nexus_buffer_t         reply_buffer;
    nexus_startpoint_t     reply_sp;
    globus_rsl_t *         description_tree;
    globus_gass_cache_t           cache_handle;
    globus_gass_cache_entry_t   * cache_entries;
    int                    cache_size;
    globus_symboltable_t * symbol_table; 
    char *                 my_env_path;
    char *                 my_env_user;

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
        else if ((strcmp(argv[i], "-e") == 0)
                 && (i + 1 < argc))
        {
            arg_libexecdir = argv[i+1];
            i++;
        }
        else
        {
	    GRAM_UNLOCK;
            fprintf(stderr, "Usage: %s [-home deploy home dir ] "
                                      "[-e lib exe dir] "
                                      "[-d debug print] "
                                      "[-t test dat file]\n", argv[0]);
            exit(1);
        }
    }

    graml_my_env_home = (char *) getenv("HOME");
    if (!graml_my_env_home)
    {
        fprintf(stderr, "ERROR: unable to get HOME from the environment.\n");
	exit(1);
    }

    if (print_debug_flag)
    {
        /*
         * Open the gram logfile just for testing!
         */
        sprintf(tmp_buffer, "%s/gram_job_mgr_%lu.log",
                graml_my_env_home,
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

    grami_fprintf( grami_log_fp, "-----------------------------------------\n");
    grami_fprintf( grami_log_fp, "JM: Entering gram_job_manager main()\n");

    grami_fprintf( grami_log_fp, "JM: HOME = %s\n", graml_my_env_home);

    my_env_path = (char *) getenv("PATH");
    if (!my_env_path)
    {
        grami_fprintf( grami_log_fp, 
                       "ERROR: unable to get PATH from the environment.\n");
    }
    grami_fprintf( grami_log_fp, "JM: PATH = %s\n", my_env_path);

    my_env_user = (char *) getenv("USER");
    if (!my_env_user)
    {
        grami_fprintf( grami_log_fp, 
                       "ERROR: unable to get USER from the environment.\n");
    }
    grami_fprintf( grami_log_fp, "JM: USER = %s\n", my_env_user);

    if (jm_home_dir)
    {
        graml_jm_status_dir = genfilename(jm_home_dir, "tmp", NULL);

        if (arg_libexecdir)
        {
            grami_jm_libexecdir = genfilename(jm_home_dir,
                                              arg_libexecdir, NULL);
        }
        else
        {
            grami_jm_libexecdir = genfilename(jm_home_dir,
                                              "libexec", NULL);
        }
    }
    else
    {
        graml_jm_status_dir = NULL;
    }

    grami_fprintf( grami_log_fp, "JM: grami_jm_libexecdir = %s\n", 
                   grami_jm_libexecdir);

    if ((grami_user_proxy_path = 
        (char *) getenv("X509_USER_PROXY")) == NULL)
    {
        grami_fprintf( grami_log_fp, 
            "JM: X509_USER_PROXY not defined.\n");
    }
    else
    {
        grami_fprintf( grami_log_fp, 
                       "JM: X509_USER_PROXY = %s\n",
                       grami_user_proxy_path);
    }
 
    if ((globusid_ptr = (char*) getenv("GLOBUSID")) == NULL)
    {
        strcpy(graml_my_globusid, "unknown_globusid");
    }
    else
    {
        strcpy(graml_my_globusid, globusid_ptr);
    }
 
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
     * Read the format incomming message.
     */
    if (fread(buffer, 1, 1, args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read format of message buffer.\n");
    }
    format = (int)buffer[0];

    /*
     * Read the size incomming message.
    if (fread(buffer, 1, 4, args_fp) <= 0)
     */
    if (fread(buffer, 1, nexus_dc_sizeof_remote_int(1, format), args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read size of message buffer.\n");
    }
    ptr = buffer;
    nexus_dc_get_int(&ptr, &count, 1, format);

    /*
     * Read the remainder of the incomming message.
     */
    if (fread(buffer, 1, count - nexus_dc_sizeof_remote_int(1, format) + 1,
        args_fp) <= 0)
    {
        grami_fprintf( grami_log_fp, 
                       "JM: failed to read the message buffer.\n");
    }

    ptr = buffer;
    nexus_user_get_int(&ptr, &count, 1, format);
    nexus_user_get_char(&ptr, description, count, format);
    *(description+count)= '\0';
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
                   "JM: description = %s\n", description);
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
        sprintf(graml_job_contact, "x-nexus://%s:%hu/%lu/%lu/", 
                              my_host,
                              my_port,
                              (unsigned long) getpid(),
                              (unsigned long) time(0));
        grami_setenv("GRAM_JOB_CONTACT", graml_job_contact, 1);
    }

    /* call the RSL routine to parse the user request
     */
    description_tree = globus_rsl_parse(description);

    symbol_table = (globus_symboltable_t *) globus_malloc 
                            (sizeof(globus_symboltable_t));

    globus_symboltable_init(symbol_table,
                          globus_hashtable_string_hash,
                          globus_hashtable_string_keyeq);

    globus_symboltable_create_scope(symbol_table);

    globus_symboltable_insert(symbol_table,
                            (void *) "HOME",
                            (void *) graml_my_env_home);
    globus_symboltable_insert(symbol_table,
                            (void *) "PATH",
                            (void *) my_env_path);
    globus_symboltable_insert(symbol_table,
                            (void *) "USER",
                            (void *) my_env_user);
    globus_symboltable_insert(symbol_table,
			    (void *) "GLOBUS_PREFIX",
			    (void *) GLOBUS_PREFIX);
    
    globus_rsl_eval(description_tree, symbol_table);

    /*
     * Start the job.  If successful reply with graml_job_contact else
     * send error status.
     */
    job_status = grami_jm_job_request(graml_job_contact, description_tree);

    if (job_status == 0)
    {
        count= strlen(graml_job_contact);
	size = nexus_sizeof_int(1);
	size += nexus_sizeof_int(1);
	size += nexus_sizeof_char(count);
	nexus_buffer_init(&reply_buffer, size, 0);
        nexus_put_int(&reply_buffer, &job_status, 1);
        nexus_put_int(&reply_buffer, &count, 1);
	nexus_put_char(&reply_buffer, graml_job_contact, count);
    }
    else
    {
	size = nexus_sizeof_int(1);
	nexus_buffer_init(&reply_buffer, size, 0);
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
		grami_jm_poll();
                GRAM_UNLOCK;
		skip_poll = GRAM_JOB_MANAGER_POLL_FREQUENCY;
	    }
        } /* endwhile */
    }

    if (!save_files_flag)
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

        if (grami_user_proxy_path)
        {
            if (remove(grami_user_proxy_path) != 0)
            {
                grami_fprintf( grami_log_fp, 
                         "JM: Cannot remove user proxy file --> %s\n",
                         grami_user_proxy_path);
            }
            else
            {
                grami_fprintf( grami_log_fp, 
                         "JM: Removed user proxy file --> %s\n",
                         grami_user_proxy_path);
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
    globus_rsl_free_recursive(description_tree);

    nexus_disallow_attach(my_port);

    nexus_mutex_destroy(&graml_jm_monitor.mutex);
    nexus_cond_destroy(&graml_jm_monitor.cond);

    grami_fprintf( grami_log_fp, "JM: exiting gram_job_request\n");

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
       graml_status_file_gen(state); 
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
            size += nexus_sizeof_char(strlen(graml_job_contact));
            size += nexus_sizeof_int(1);
            size += nexus_sizeof_int(1);

            nexus_buffer_init(&reply_buffer, size, 0);
            count= strlen(graml_job_contact);
            nexus_put_int(&reply_buffer, &count, 1);
            nexus_put_char(&reply_buffer, graml_job_contact,
                           strlen(graml_job_contact));
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
Function:       graml_status_file_gen()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
graml_status_file_gen(int job_status)
{
    char               status_file[256];
    FILE *             status_fp;
    struct stat        statbuf;
    char               job_status_str[80];

    grami_fprintf( grami_log_fp, "JM: in graml_status_file_gen\n");

    sprintf(status_file, "%s/%s_%lu",
            graml_jm_status_dir,
            STATUS_FILE_PREFIX,
            (unsigned long) getpid() );

    /*
     * Check to see if the status file exists.  If so, then delete it.
     */
    if (stat(status_file, &statbuf) == 0)
    {
        if (remove(status_file) != 0)
        {
            grami_fprintf( grami_log_fp, "\n--------------------------\n");
            grami_fprintf( grami_log_fp, 
                  "JM: Cannot remove status file --> %s\n", status_file);
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

        if ((status_fp = fopen(status_file, "a")) == NULL)
        {
            grami_fprintf( grami_log_fp, "\n--------------------------\n");
            grami_fprintf( grami_log_fp, 
                           "JM: Cannot open status file --> %s\n",
                           status_file);
            grami_fprintf( grami_log_fp, "JM: job contact = %s\n",
                           graml_job_contact);
            grami_fprintf( grami_log_fp, "JM: MDS will NOT be updated!!!\n");
            grami_fprintf( grami_log_fp, "--------------------------\n\n");
            return(1);
        }
        else
        {
            /* convert status integer to a string for printing
             */
            switch(job_status)
            {
                case GLOBUS_GRAM_CLIENT_JOB_STATE_PENDING:
                    strcpy(job_status_str, "PENDING");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_ACTIVE:
                    strcpy(job_status_str, "ACTIVE");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_DONE:
                    strcpy(job_status_str, "DONE");
                    break;
                case GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED:
                    strcpy(job_status_str, "FAILED");
                    break;
                default:
                    strcpy(job_status_str, "UNKNOWN");
                    break;
            }

            /* output data into the status file in the format that the
             * gram-reporter is expecting it.
             *
             */
            fprintf(status_fp, "%s;%s;%s;%d\n",
		    graml_my_globusid,
		    job_status_str,
		    graml_job_contact,
		    graml_my_count);
            fclose(status_fp);
        }
    }

    return(0);

} /* graml_status_file_gen() */

/******************************************************************************
Function:       grami_jm_request_params()
Description:
Parameters:
Returns:
******************************************************************************/
int 
grami_jm_request_params(globus_rsl_t * description_tree,
                        gram_request_param_t * params)
{
    char * tmp_dir;
    int tmp_fd;
    struct stat statbuf;
    char ** tmp_param;

    if (description_tree == NULL)
        return(GLOBUS_GRAM_CLIENT_ERROR_NULL_SPECIFICATION_TREE);
 
    /********************************** 
     *  GET PROGRAM (executable) PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_EXECUTABLE_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->pgm = (tmp_param)[0];
    else
    {
        params->pgm = GLOBUS_GRAM_CLIENT_DEFAULT_EXE;
    }

    /********************************** 
     *  GET PROGRAM ARGUMENTS PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_ARGUMENTS_PARAM, 
                       &(params->pgm_args));

    /********************************** 
     *  GET DIR PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_DIR_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->dir = tmp_param[0];
    else
        params->dir = graml_my_env_home;

    /********************************** 
     *  GET STDIN PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_STDIN_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->std_in = tmp_param[0];
    else
        params->std_in = GLOBUS_GRAM_CLIENT_DEFAULT_STDIN;

    /********************************** 
     *  GET STDOUT PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_STDOUT_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->std_out = tmp_param[0];
    else
        params->std_out = GLOBUS_GRAM_CLIENT_DEFAULT_STDOUT;

    /********************************** 
     *  GET STDERR PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_STDERR_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->std_err = tmp_param[0];
    else
        params->std_err = GLOBUS_GRAM_CLIENT_DEFAULT_STDERR;

    /********************************** 
     *  GET COUNT PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_COUNT_PARAM,
		       &tmp_param);
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
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_MAXTIME_PARAM,
		       &tmp_param);
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
     *  GET MPITASKS PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_MPITASKS_PARAM,
		       &tmp_param);
    if (tmp_param[0])
    {
        params->mpitasks = atoi(tmp_param[0]);

        if (params->mpitasks < 1)
            return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_MPITASKS);
    }
    else
    {
        params->mpitasks = 0;
    }

    /********************************** 
     *  GET PARADYN PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_PARADYN_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->paradyn = tmp_param[0];
    else
        params->paradyn = NULL;

    /********************************** 
     *  GET JOBTYPE PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_JOBTYPE_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->jobtype = tmp_param[0];
    else
        params->jobtype = GLOBUS_GRAM_CLIENT_DEFAULT_JOBTYPE;

    /********************************** 
     *  GET MYJOB PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_MYJOB_PARAM,
		       &tmp_param);
    if (tmp_param[0])
        params->gram_myjob = tmp_param[0];
    else
        params->gram_myjob = GLOBUS_GRAM_CLIENT_DEFAULT_MYJOB;

    /**********************************
     *  GET QUEUE PARAM
     */
    globus_rsl_param_get(description_tree,
                       GLOBUS_GRAM_CLIENT_QUEUE_PARAM,
                       &tmp_param);
    if (tmp_param[0])
        params->queue = tmp_param[0];
    else
        params->queue = NULL;
 
    /**********************************
     *  GET PROJECT PARAM
     */
    globus_rsl_param_get(description_tree,
                       GLOBUS_GRAM_CLIENT_PROJECT_PARAM,
                       &tmp_param);
    if (tmp_param[0])
        params->project = tmp_param[0];
    else
        params->project = NULL;

    /********************************** 
     *  GET ENVIRONMENT PARAM
     */
    globus_rsl_param_get(description_tree,
		       GLOBUS_GRAM_CLIENT_ENVIRONMENT_PARAM, 
                       &(params->pgm_env));

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
	}
    }
    
    /* GEM: Stage pgm and std_in to local filesystem, if they are URLs.
       Do this before paradyn rewriting.
     */
    graml_stage_file(params->pgm, 0700);
    graml_stage_file(params->std_in, 0400);
    
    if (grami_is_paradyn_job(params))
    {
	if (!grami_paradyn_rewrite_params(params))
	{
            return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_PARADYN);
	}

        graml_stage_file(params->pgm, 0700);
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
    nexus_startpoint_t       reply_sp;
    nexus_buffer_t           reply_buffer;

    grami_fprintf( grami_log_fp, "JM: in graml_cancel_handler\n");

    nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    nexus_buffer_destroy(buffer);

    GRAM_LOCK;

    rc = grami_jm_job_cancel();

    size = nexus_sizeof_int(1);
    nexus_buffer_init(&reply_buffer, size, 0);
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

    nexus_buffer_init(&reply_buffer, size, 0);
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

/******************************************************************************
Function:       graml_stage_file()
Description:    
Parameters:
Returns:
******************************************************************************/
static void
graml_stage_file(char *url, int mode)
{
    globus_url_t gurl;
    int rc;

    if(url == NULL)
    {
        return;
    }
    if(strlen(url) == 0)
    {
	return;
    }
    grami_fprintf( grami_log_fp, 
                   "JM: staging file = %s\n", url);

    rc = globus_url_parse(url, &gurl);
    if(rc == GLOBUS_SUCCESS)	/* this is a valid URL */
    {
	globus_gass_cache_t cache;
	unsigned long timestamp;
	char *tmpname;
	
	globus_gass_cache_open(GLOBUS_NULL,
			       &cache);
	
	rc = globus_gass_cache_add(&cache,
				   url,
				   graml_job_contact,
				   GLOBUS_TRUE,
				   &timestamp,
				   &tmpname);
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_add_done(&cache,
				       url,
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
		globus_gass_client_get_fd(url,
					  GLOBUS_NULL,
					  fd,
					  GLOBUS_GASS_LENGTH_UNKNOWN,
					  &timestamp,
					  GLOBUS_NULL,
					  GLOBUS_NULL);
	    }
	    close(fd);
	    globus_gass_cache_add_done(&cache,
				       url,
				       graml_job_contact,
				       timestamp);
	}
	strncpy(url, tmpname, GLOBUS_GRAM_CLIENT_PARAM_SIZE);
	url[GLOBUS_GRAM_CLIENT_PARAM_SIZE-1] = '\0';
	globus_free(tmpname);
	globus_gass_cache_close(&cache);
    }
    globus_url_destroy(&gurl);
    grami_fprintf( grami_log_fp, 
                   "JM: new name = %s\n", url);
}

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
}
