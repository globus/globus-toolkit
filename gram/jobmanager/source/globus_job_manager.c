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
#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h> /* for strdup() */
#include <memory.h>
#include <nexus.h>
#include <fcntl.h>
#include "gram_client.h"
#include "grami_client.h"
#include "gram_rsl.h"
#include "grami_jm.h"

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct _gram_job_manager_monitor_t
{
    nexus_mutex_t          mutex;
    nexus_cond_t           cond;
    volatile nexus_bool_t  done;
} gram_job_manager_monitor_t;

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
attach_requested(void * arg,
                 char * url,
                 nexus_startpoint_t * sp);
static int 
status_file_gen(char * job_status);

static void 
tree_free(gram_specification_t * sp);

static char *
genfilename(char * prefix, char * path, char * sufix);

static void
notice(char * s);

/******************************************************************************
                       Define variables for external use
******************************************************************************/
char * grami_jm_libexecdir = GLOBUS_LIBEXECDIR;
int  gram_print_debug = 0;

/******************************************************************************
                       Define module specific variables
******************************************************************************/
static nexus_handler_t handlers[] =
{ 
#ifdef BUILD_LITE
    {NEXUS_HANDLER_TYPE_NON_THREADED, graml_cancel_handler},
    {NEXUS_HANDLER_TYPE_NON_THREADED, graml_start_time_handler},
#else
    {NEXUS_HANDLER_TYPE_THREADED, graml_cancel_handler},
    {NEXUS_HANDLER_TYPE_THREADED, graml_start_time_handler},
#endif  /* BUILD_LITE */
};

static char     tmpbuf[1024];
#define notice2(a,b) {sprintf(tmpbuf, a,b); notice(tmpbuf);}
#define notice3(a,b,c) {sprintf(tmpbuf, a,b,c); notice(tmpbuf);}
#define notice4(a,b,c,d) {sprintf(tmpbuf, a,b,c,d); notice(tmpbuf);}

static char * grami_jm_home_dir = NULL;
static char * grami_jm_arg_libexecdir = NULL;
static char * grami_jm_status_dir = NULL;
static gram_job_manager_monitor_t  job_manager_monitor;
static nexus_endpointattr_t        EpAttr;
static nexus_endpoint_t            GlobalEndpoint;
static char                        callback_contact[GRAM_MAX_MSG_SIZE];
static char                        job_contact[GRAM_MAX_MSG_SIZE];
static char                        my_globusid[GRAM_MAX_MSG_SIZE];
static int                         my_count;

static FILE *                      gram_log_fp;

static nexus_mutex_t gram_api_mutex;
static int gram_api_mutex_is_initialized = 0;
 
#define GRAM_API_LOCK { \
    int err; \
    assert (gram_api_mutex_is_initialized==1); \
    err = nexus_mutex_lock (&gram_api_mutex); assert (!err); \
}
	
#define GRAM_API_UNLOCK { \
    int err; \
    err = nexus_mutex_unlock (&gram_api_mutex); assert (!err); \
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
    int                    job_state_mask;
    int                    message_handled;
    char                   description[GRAM_MAX_MSG_SIZE];
    char                   test_dat_file[GRAM_MAX_MSG_SIZE];
    char                   gram_logfile[GRAM_MAX_MSG_SIZE];
    char *                 tmp_ptr;
    char *                 my_host;
    char *                 globusid_ptr;
    unsigned short         my_port;
    FILE *                 args_fp;
    nexus_byte_t           type;
    nexus_byte_t *         ptr;
    nexus_byte_t           bformat;
    nexus_byte_t           buffer[GRAM_MAX_MSG_SIZE];
    nexus_buffer_t         reply_buffer;
    nexus_startpoint_t     reply_sp;
    gram_specification_t * description_tree;


    /* Initialize nexus */
    rc = nexus_init(&argc,
		    &argv,
		    "NEXUS_ARGS", /* conf info env variable          */
		    "nx",         /* package designator              */
		    NULL);        /* additional modules              */
    if (rc != NEXUS_SUCCESS)
    {
	fprintf(stderr, "nexus_init() failed with rc=%d\n", rc);
	exit(1);
    }
    nexus_enable_fault_tolerance(NULL, NULL);

    if ( gram_api_mutex_is_initialized == 0 )
    {
        /* initialize mutex which makes the client thread-safe */
        int err;
		 
        err = nexus_mutex_init (&gram_api_mutex, NULL); assert (!err);
        gram_api_mutex_is_initialized = 1;
    }

    GRAM_API_LOCK;

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
            gram_print_debug = 1;
        }
        else if ((strcmp(argv[i], "-home") == 0)
                 && (i + 1 < argc))
        {
            grami_jm_home_dir = argv[i+1];
            i++;
        }
        else if ((strcmp(argv[i], "-e") == 0)
                 && (i + 1 < argc))
        {
            grami_jm_arg_libexecdir = argv[i+1];
            i++;
        }
        else
        {
	    GRAM_API_UNLOCK;
            fprintf(stderr, "Usage: %s [-h deploy home dir ] [-e lib exe dir] [-d debug print] [-t test dat file]\n", argv[0]);
            exit(1);
        }
    }

    if (gram_print_debug)
    {
        /*
         * Open the gram logfile just for testing!
         */
        sprintf(gram_logfile, "gram_job_mgr_%lu.log",
                (unsigned long) getpid());

        if ((gram_log_fp = fopen(gram_logfile, "a")) == NULL)
        {
            sprintf(gram_logfile, "/tmp/gram_job_mgr_%lu.log",
                   (unsigned long) getpid());

            if ((gram_log_fp = fopen(gram_logfile, "a")) == NULL)
            {
	        GRAM_API_UNLOCK;
                fprintf(stderr, "Cannot open gram logfile.\n");
                exit(1);
            }
        }

        setbuf(gram_log_fp, NULL);
    }

    notice("-------------------------------------------------");
    notice("entering gram_job_manager");

    if (grami_jm_home_dir)
    {
        grami_jm_status_dir = genfilename(grami_jm_home_dir, "tmp", NULL);

        if (grami_jm_arg_libexecdir)
        {
            grami_jm_libexecdir = genfilename(grami_jm_home_dir, grami_jm_arg_libexecdir, NULL);
        }
        else
        {
            grami_jm_libexecdir = genfilename(grami_jm_home_dir, "libexec", NULL);
        }
    }

    notice2("grami_jm_libexecdir = %s", grami_jm_libexecdir);

    if ((globusid_ptr = (char*) getenv("GLOBUSID")) == NULL)
    {
        strcpy(my_globusid, "unknown_globusid");
    }
    else
    {
        strcpy(my_globusid, globusid_ptr);
    }
 
    /*
     *  if a test_dat_file has been defined, read data from the file 
     *  instead of from stdin.
     */
    if (strlen(test_dat_file) > 0)
    {
        if ((args_fp = fopen(test_dat_file, "r")) == NULL)
        {
	    GRAM_API_UNLOCK;
            notice2("Cannot open test file %s.", test_dat_file);
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
        notice("fread() failed.");
    }
    format = (int)buffer[0];

    /*
     * Read the size incomming message.
    if (fread(buffer, 1, 4, args_fp) <= 0)
     */
    if (fread(buffer, 1, nexus_dc_sizeof_remote_int(1, format), args_fp) <= 0)
    {
        notice("fread() failed.");
    }
    ptr = buffer;
    nexus_dc_get_int(&ptr, &count, 1, format);

    /*
     * Read the remainder of the incomming message.
     */
    if (fread(buffer, 1, count - nexus_dc_sizeof_remote_int(1, format) + 1,
        args_fp) <= 0)
    {
        notice("fread() failed.");
    }

    ptr = buffer;
    nexus_user_get_int(&ptr, &count, 1, format);
    nexus_user_get_char(&ptr, description, count, format);
    *(description+count)= '\0';
    nexus_user_get_int(&ptr, &job_state_mask, 1, format);
    nexus_user_get_int(&ptr, &count, 1, format);
    nexus_user_get_char(&ptr, callback_contact, count, format);
    *(callback_contact+count)= '\0';
    nexus_user_get_startpoint(&ptr, &reply_sp, 1, format);

    notice2("description = %s", description);
    notice2("job state mask = %i",job_state_mask);
    notice2("callback contact = %s", callback_contact);

    /* Initialize termination monitor */
    nexus_mutex_init(&job_manager_monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&job_manager_monitor.cond, (nexus_condattr_t *) NULL);
    job_manager_monitor.done = NEXUS_FALSE;

    /*
     * Create an endpoint that will be used by attach_requested
     * when other attach to this job manager
     */
    nexus_endpointattr_init(&EpAttr);
    nexus_endpointattr_set_handler_table(&EpAttr,
                                    handlers,
                                    sizeof(handlers)/sizeof(nexus_handler_t));
    nexus_endpoint_init(&GlobalEndpoint, &EpAttr);

    /* allow other Nexus programs to attach to us */
    my_port = 0;
    rc = nexus_allow_attach(&my_port,         /* port            */
                            &my_host,         /* host            */
                            attach_requested, /* approval_func() */
                            NULL);
    if (rc != 0)
    {
        GRAM_API_UNLOCK;
        return(GRAM_ERROR_JM_FAILED_ALLOW_ATTACH);
    } 
    else
    {
        sprintf(job_contact, "x-nexus://%s:%hu/%lu/%lu/", 
                              my_host,
                              my_port,
                              (unsigned long) getpid(),
                              (unsigned long) time(0));
    }
    description_tree = gram_specification_parse(description);

    /*
     * Start the job.  If successful reply with job_contact else
     * send error status.
     */
    job_status = grami_jm_job_request(job_contact, description_tree);

    if (job_status == 0)
    {
        count= strlen(job_contact);
	size = nexus_sizeof_int(1);
	size += nexus_sizeof_int(1);
	size += nexus_sizeof_char(count);
	nexus_buffer_init(&reply_buffer, size, 0);
        nexus_put_int(&reply_buffer, &job_status, 1);
        nexus_put_int(&reply_buffer, &count, 1);
	nexus_put_char(&reply_buffer, job_contact, count);
    }
    else
    {
	size = nexus_sizeof_int(1);
	nexus_buffer_init(&reply_buffer, size, 0);
        nexus_put_int(&reply_buffer, &job_status, 1);
    }
 
    nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   GRAMI_CLIENT_REPLY_HANDLER_ID,
                   NEXUS_TRUE,
                   NEXUS_FALSE);

    nexus_startpoint_destroy(&reply_sp);

    GRAM_API_UNLOCK;
/*
    nexus_mutex_lock(&job_manager_monitor.mutex);
*/
    notice2("job status = %d", job_status);

    if (job_status == 0)
    {
	int skip_poll = GRAM_JOB_MANAGER_POLL_FREQUENCY;
        while (!job_manager_monitor.done)
        {
            /*
            nexus_cond_wait(&job_manager_monitor.cond, 
                            &job_manager_monitor.mutex);
            */
	    nexus_usleep(1000000);
    	    nexus_fd_handle_events(NEXUS_FD_POLL_NONBLOCKING_ALL, 
                                   &message_handled);
	    if (--skip_poll <= 0)
	    {
                GRAM_API_LOCK;
		grami_jm_poll();
                GRAM_API_UNLOCK;
		skip_poll = GRAM_JOB_MANAGER_POLL_FREQUENCY;
	    }
        } /* endwhile */
/*
        nexus_mutex_unlock(&job_manager_monitor.mutex);
*/
    }

    tree_free(description_tree);

    nexus_disallow_attach(my_port);

    nexus_mutex_destroy(&job_manager_monitor.mutex);
    nexus_cond_destroy(&job_manager_monitor.cond);

    notice("exiting gram_job_request");

    nexus_shutdown();

    return(0);

} /* main() */

/******************************************************************************
Function:       attach_requested()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
attach_requested(void * arg,
                 char * url,
                 nexus_startpoint_t * sp)
{
    notice("in attach_requested callback");

    nexus_startpoint_bind(sp, &GlobalEndpoint);

    return(0);
} /* attach_requested() */


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
    
    notice("in grami_jm_callback");

    if (grami_jm_home_dir)
    {
        if (state == GRAM_JOB_STATE_ACTIVE)
        {
           status_file_gen("ACTIVE");
        }
        else if (state == GRAM_JOB_STATE_PENDING)
        {
           status_file_gen("PENDING");
        }
        else if (state == GRAM_JOB_STATE_DONE)
        {
           status_file_gen("DONE");
        }
        else if (state == GRAM_JOB_STATE_FAILED)
        {
           status_file_gen("FAILED");
        }
        else
        {
           status_file_gen("UNKNOWN");
        }
    }
 
    rc = nexus_attach(callback_contact, &sp);
    
    if (rc == 0)
    {
        size  = nexus_sizeof_int(1);
        size += nexus_sizeof_char(strlen(job_contact));
        size += nexus_sizeof_int(1);
        size += nexus_sizeof_int(1);

        nexus_buffer_init(&reply_buffer, size, 0);
        count= strlen(job_contact);
        nexus_put_int(&reply_buffer, &count, 1);
        nexus_put_char(&reply_buffer, job_contact, strlen(job_contact));
        nexus_put_int(&reply_buffer, &state, 1);
        nexus_put_int(&reply_buffer, &errorcode, 1);

        nexus_send_rsr(&reply_buffer,
                       &sp,
                       0,
                       NEXUS_TRUE,
                       NEXUS_FALSE);

        nexus_startpoint_destroy(&sp);
    }

} /* grami_jm_callback() */

/******************************************************************************
Function:       status_file_gen()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
status_file_gen(char * my_job_status)
{
    char               status_file[256];
    FILE *             status_fp;
    struct stat        statbuf;

    notice("in status_file_gen");

    sprintf(status_file, "%s/%s_%lu",
            grami_jm_status_dir,
            STATUS_FILE_PREFIX,
            (unsigned long) getpid() );

    if (stat(status_file, &statbuf) == 0)
    {
        if (remove(status_file) != 0)
        {
            notice("\n--------------------------");
            notice2("Error: Cannot remove status file --> %s", status_file);
            notice("--------------------------\n");
            return(1);
        }
    }
 
    /*
     *  don't output a status file when the job has terminated
     */
    if ( (strcmp(my_job_status, "DONE") != 0) && 
         (strcmp(my_job_status, "FAILED") != 0) )
    {

        if ((status_fp = fopen(status_file, "a")) == NULL)
        {
            notice("\n--------------------------");
            notice2("Cannot open status file --> %s", status_file);
            notice2("job contact = %s", job_contact);
            notice("MDS will NOT be updated!!!");
            notice("--------------------------\n");
            return(1);
        }
        else
        {
            fprintf(status_fp, "%s;%s;%s;%d\n",
                my_globusid,
                my_job_status,
                job_contact,
                my_count);
            fclose(status_fp);
        }
    }

    return(0);
} /* status_file_gen() */

/******************************************************************************
Function:       grami_jm_request_params()
Description:
Parameters:
Returns:
******************************************************************************/
int 
grami_jm_request_params(gram_specification_t * description_tree,
                        gram_request_param_t * params)
{
    char pgm_count[GRAM_PARAM_SIZE];
    char pgm_maxtime[GRAM_PARAM_SIZE];
    char * tmp_dir;
    int tmp_fd;
    struct stat statbuf;

    if (description_tree == NULL)
        return(GRAM_ERROR_NULL_SPECIFICATION_TREE);
 
    *(params->pgm)       = '\0';
    *(params->pgm_args)  = '\0';
    *(params->pgm_env)   = '\0';
    *(params->dir)       = '\0';
    *(params->std_in)    = '\0';
    *(params->std_out)   = '\0';
    *(params->paradyn)   = '\0';
    *(params->std_err)   = '\0';
    *pgm_maxtime         = '\0';
    *pgm_count           = '\0';

    grami_jm_param_get(description_tree, GRAM_EXECUTABLE_PARAM, params->pgm);
    grami_jm_param_get(description_tree, GRAM_ARGUMENTS_PARAM, params->pgm_args);
    grami_jm_param_get(description_tree, GRAM_ENVIRONMENT_PARAM, params->pgm_env);
    grami_jm_param_get(description_tree, GRAM_DIR_PARAM, params->dir);
    grami_jm_param_get(description_tree, GRAM_COUNT_PARAM, pgm_count);
    grami_jm_param_get(description_tree, GRAM_STDIN_PARAM, params->std_in);
    grami_jm_param_get(description_tree, GRAM_STDOUT_PARAM, params->std_out);
    grami_jm_param_get(description_tree, GRAM_STDERR_PARAM, params->std_err);
    grami_jm_param_get(description_tree, GRAM_MAXTIME_PARAM, pgm_maxtime);

    grami_jm_param_get(description_tree, GRAM_PARADYN_PARAM, params->paradyn);

    if (grami_is_paradyn_job(params))
    {
	if (!grami_paradyn_rewrite_params(params))
	{
            return (GRAM_ERROR_INVALID_PARADYN);
	}
    }

    /*
     * set defaults for everything, if not specified
     */
    if (strlen(pgm_maxtime) == 0)
    {
        params->maxtime = 0;
    }
    else
    {
        params->maxtime = atoi(pgm_maxtime);
        if (params->maxtime < 1)
            return (GRAM_ERROR_INVALID_MAXTIME);
    }

    if (strlen(pgm_count) == 0)
        params->count = 1;
    else
        params->count = atoi(pgm_count);

    if (params->count < 1)
        return (GRAM_ERROR_INVALID_COUNT);

    /* save count parameter for reporting to MDS */ 
    my_count = params->count;

    if (strlen(params->pgm) == 0)
       strcpy(params->pgm, GRAM_DEFAULT_EXE);

    if (strlen(params->dir) == 0)
    {
        tmp_dir = getenv("HOME");
        strcpy(params->dir, tmp_dir);
    }

    if (strlen(params->std_in) == 0)
    {
       strcpy(params->std_in, GRAM_DEFAULT_STDIN);
    }

    if (strlen(params->std_out) == 0)
    {
       strcpy(params->std_out, GRAM_DEFAULT_STDOUT);
    }

    if (strlen(params->std_err) == 0)
    {
       strcpy(params->std_err, GRAM_DEFAULT_STDERR);
    }

    /*
     * change to the right directory, so that std* files
     * are interpreted relative to this directory
     */
    if (chdir(params->dir) != 0)
    {
	return(GRAM_ERROR_BAD_DIRECTORY);
    }

    /*
     * Verify the std_in file exists, Otherwise error out.
     */
    if (stat(params->std_in, &statbuf) != 0)
    {
        return(GRAM_ERROR_STDIN_NOTFOUND);
    }

    /*
     * create the std_out and std_err files
     */ 
    tmp_fd = open(params->std_out, O_WRONLY | O_CREAT | O_TRUNC, 0666 );
    close(tmp_fd);
    tmp_fd = open(params->std_err, O_WRONLY | O_CREAT | O_TRUNC, 0666 );
    close(tmp_fd);

    return(0);

} /* grami_jm_request_params() */


/******************************************************************************
Function:       grami_jm_param_get()
Description:
Parameters:
Returns:
******************************************************************************/
void 
grami_jm_param_get(gram_specification_t * sp,
                   char * param,
                   char * value)
{
    gram_specification_t * child;

    if (sp)
    {
        if (sp->type == GRAM_SPECIFICATION_BOOLEAN)
        {
            /* GRAM_SPECIFICATION_BOOLEAN */

            /* search thru children */
            for (child = sp->req.boolean.child_list;
                *value == '\0' && child; child = child->next)
                    grami_jm_param_get(child, param, value);
        }
        else
        {
            /* GRAM_SPECIFICATION_RELATION */
            if (strcmp(sp->req.relation.left_op, param) == 0)
               strcpy(value, sp->req.relation.right_op);
        } /* endif */
    } /* endif */
} /* grami_jm_param_get() */


/******************************************************************************
Function:       grami_jm_terminate()
Description:
Parameters:
Returns:
******************************************************************************/
void 
grami_jm_terminate()
{
    nexus_mutex_lock(&(job_manager_monitor.mutex));
    job_manager_monitor.done = NEXUS_TRUE;
    nexus_cond_signal(&(job_manager_monitor.cond));
    nexus_mutex_unlock(&(job_manager_monitor.mutex));
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
    notice("in graml_cancel_handler");

    /* clean-up */
    nexus_buffer_destroy(buffer);

    GRAM_API_LOCK;
    grami_jm_job_cancel();
    GRAM_API_UNLOCK;

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
    int                      size;
    int                      message_handled;
    float                    confidence;
    nexus_startpoint_t       reply_sp;
    nexus_buffer_t           reply_buffer;
    gram_time_t              estimate;
    gram_time_t              interval_size;

    notice("in graml_start_time_handler");

    nexus_get_float(buffer, &confidence, 1);
    nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    nexus_buffer_destroy(buffer);

    notice2("confidence passed = %f", confidence);
    notice2("callback contact = %s", callback_contact);

    GRAM_API_LOCK;

    grami_jm_job_start_time(callback_contact,
                            confidence,
                            &estimate,
                            &interval_size);

    size  = nexus_sizeof_int(1);
    size += nexus_sizeof_int(1);

    nexus_buffer_init(&reply_buffer, size, 0);
    nexus_put_int(&reply_buffer, &estimate.dumb_time, 1);
    nexus_put_int(&reply_buffer, &interval_size.dumb_time, 1);

    nexus_send_rsr(&reply_buffer,
                   &reply_sp,
                   0,
                   NEXUS_TRUE,
                   NEXUS_FALSE);

    nexus_startpoint_destroy(&reply_sp);

    GRAM_API_UNLOCK;

} /* graml_start_time_handler() */

/******************************************************************************
Function:       tree_free()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
tree_free(gram_specification_t * sp)
{
    gram_specification_t * child;

    if (sp)
    {
        if (sp->type == GRAM_SPECIFICATION_BOOLEAN)
        {
            /* GRAM_SPECIFICATION_BOOLEAN */

            /* freeing children */
            while (child = sp->req.boolean.child_list)
            {
                sp->req.boolean.child_list = child->next;
                tree_free(child);
            } /* endwhile */

            /* freeing myself */
            free(sp);
        }
        else
        {
            /* GRAM_SPECIFICATION_RELATION ... no children */
            free(sp);
        } /* endif */
    } /* endif */

} /* end tree_free() */

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
Function:       notice()
Description:
Parameters:
Returns:
******************************************************************************/
static void
notice(char * s)
{
    if (gram_print_debug)
    {
        fprintf(gram_log_fp, "Notice: %s\n", s);
    }
}
