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
#include <string.h> /* for strdup() */
#include <memory.h>
#include <nexus.h>
#include "gram.h"
#include "grami_rsl.h"
#include "grami_jm.h"
#include "gram_client.h"

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct _gram_job_manager_monitor_t
{
    nexus_mutex_t          mutex;
    nexus_cond_t           cond;
    volatile nexus_bool_t  done;
} gram_job_manager_monitor_t;

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
static void 
tree_free(gram_specification_t * sp);

/******************************************************************************
                       Define module specific variables
******************************************************************************/
static nexus_handler_t handlers[] =
{ 
    {NEXUS_HANDLER_TYPE_NON_THREADED, graml_cancel_handler},
    {NEXUS_HANDLER_TYPE_NON_THREADED, graml_start_time_handler},
};

static gram_job_manager_monitor_t  job_manager_monitor;
static nexus_endpointattr_t        EpAttr;
static nexus_endpoint_t            GlobalEndpoint;
static char                        callback_contact[GRAM_MAX_MSG_SIZE];
static char                        job_contact[GRAM_MAX_MSG_SIZE];

static FILE *                      log_fp;

/*
 * NexusExit() (required of all Nexus programs)
 */
void NexusExit(void)
{
} /* end NexusExit() */

/*
 * NexusAcquiredAsNode() (required of all Nexus programs)
 */
int NexusAcquiredAsNode(nexus_startpoint_t *startpoint)
{
    nexus_startpoint_bind(startpoint, &GlobalEndpoint);
    return 0;
} /* end NexusAcquiredAsNode() */

/*
 * NexusBoot() (required of all Nexus programs)
 */
int NexusBoot(nexus_startpoint_t * startpoint)
{
    nexus_endpointattr_init(&EpAttr);
    nexus_endpointattr_set_handler_table(&EpAttr,
                                    handlers,
                                    sizeof(handlers)/sizeof(nexus_handler_t));

    nexus_endpoint_init(&GlobalEndpoint, &EpAttr);
    nexus_startpoint_bind(startpoint, &GlobalEndpoint);

    return NEXUS_SUCCESS;

} /* end NexusBoot() */

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
    char *                 tmp_ptr;
    char *                 my_host;
    unsigned short         my_port;
    FILE *                 args_fp;
    nexus_byte_t           type;
    nexus_byte_t *         ptr;
    nexus_byte_t           bformat;
    nexus_byte_t           buffer[GRAM_MAX_MSG_SIZE];
    nexus_buffer_t         reply_buffer;
    nexus_node_t *         nodes;
    nexus_startpoint_t     reply_sp;
    gram_specification_t * description_tree;

    /*
     * Open the logfile just for testing!
     */
    if ((log_fp = fopen("job_mgr.tmp", "a")) == NULL)
    {
        printf("Cannot open logfile.\n");
        exit(1);
    }

    setbuf(log_fp, NULL);

    fprintf(log_fp,"-------------------------------------------------\n");
    fprintf(log_fp,"entering gram_job_manager\n");

    nexus_init(&argc,
                &argv,
               "NEXUS_ARGS", /* conf info env variable          */
               "nx",         /* package designator              */
               NULL,         /* package args init callback func */
               NULL,         /* usage message callback func     */
               NULL,         /* new process params func         */
               NULL,         /* module list                     */
               &nodes,
               &n_nodes);

    nexus_start_nonblocking();

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
        else
        {
            fprintf(stderr, "Usage: %s [-t test_dat_file]\n", argv[0]);
            exit(1);
        }
    }

    /*
     *  if a test_dat_file has been defined, read data from the file 
     *  instead of from stdin.
     */
    if (strlen(test_dat_file) > 0)
    {
        if ((args_fp = fopen(test_dat_file, "r")) == NULL)
        {
            printf("Cannot open test file.\n");
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
        fprintf(stderr, "fread() failed.\n");
    }
    format = (int)buffer[0];

    /*
     * Read the size incomming message.
    if (fread(buffer, 1, 4, args_fp) <= 0)
     */
    if (fread(buffer, 1, nexus_dc_sizeof_remote_int(format,1), args_fp) <= 0)
    {
        fprintf(log_fp, "fread() failed.\n");
        fprintf(stderr, "fread() failed.\n");
    }
    ptr = buffer;
    nexus_dc_get_int(&ptr, &count, 1, format);

    /*
     * Read the remainder of the incomming message.
     */
    if (fread(buffer, 1, count - nexus_dc_sizeof_remote_int(format,1) + 1,
        args_fp) <= 0)
    {
        fprintf(stderr, "fread() failed.\n");
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

    fprintf(log_fp,"description = %s\n", description);
    fprintf(log_fp,"job state mask = %i\n",job_state_mask);
    fprintf(log_fp,"callback contact = %s\n", callback_contact);

    /* Initialize termination monitor */
    nexus_mutex_init(&job_manager_monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&job_manager_monitor.cond, (nexus_condattr_t *) NULL);
    job_manager_monitor.done = NEXUS_FALSE;

    /* allow other Nexus programs to attach to us */
    my_port = 0;
    rc = nexus_allow_attach(&my_port,      /* port            */
                            &my_host,     /* host            */
                            attach_requested, /* approval_func() */
                            NULL);
    if (rc != 0)
    {
       return(GRAM_ERROR_INVALID_REQUEST);
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
                   REPLY_HANDLER_ID,
                   NEXUS_TRUE,
                   NEXUS_FALSE);
/*
    nexus_mutex_lock(&job_manager_monitor.mutex);
*/
    fprintf(log_fp,"job status = %d\n", job_status);

    if (job_status == 0)
    {
        while (!job_manager_monitor.done)
        {
            /*
            nexus_cond_wait(&job_manager_monitor.cond, 
                            &job_manager_monitor.mutex);
            */
	    nexus_usleep(1000000);
    	    nexus_fd_handle_events(NEXUS_FD_POLL_NONBLOCKING_ALL, 
                                   &message_handled);
	    grami_jm_poll(); 
        } /* endwhile */
/*
        nexus_mutex_unlock(&job_manager_monitor.mutex);
*/
    }

    tree_free(description_tree);

    nexus_disallow_attach(my_port);

    nexus_mutex_destroy(&job_manager_monitor.mutex);
    nexus_cond_destroy(&job_manager_monitor.cond);

    fprintf(log_fp,"exiting gram_job_request \n");

    nexus_shutdown_nonexiting();

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
    fprintf(log_fp, "in attach_requested callback\n");

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
    nexus_startpoint_t sp;
    nexus_buffer_t     reply_buffer;
    
    fprintf(log_fp, "in grami_jm_callback\n");

    nexus_attach(callback_contact, &sp);
    
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

} /* grami_jm_callback() */


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
    fprintf(log_fp, "in graml_cancel_handler\n");

    /* clean-up */
    nexus_buffer_destroy(buffer);

    grami_jm_job_cancel();

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

    fprintf(log_fp, "in graml_start_time_handler\n");

    nexus_get_float(buffer, &confidence, 1);
    nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    nexus_buffer_destroy(buffer);

    fprintf(log_fp, "confidence passed = %f\n", confidence);
    fprintf(log_fp, "callback contact = %s\n", callback_contact);

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
