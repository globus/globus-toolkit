/*
 * Nexus
 * Authors:     Stuart Martin
 *              Argonne National Laboratory
 *
 * grm_job_manager.c - Globus Resource Management Job Manager 
 *
 */

#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/time.h>
#include <string.h> /* for strdup() */
#include <memory.h>
#include <nexus.h>
#include "grm.h"
#include "gjm.h"

/* for print_tree() */
#define INDENT(LVL) { \
    int i; \
    for (i = 0; i < (LVL); i ++) printf("   "); \
    }

/***************************/
/*                         */
/* Nexus Handler Functions */
/*                         */
/***************************/

static void cancel_handler(nexus_endpoint_t *endpoint,
                           nexus_buffer_t *buffer,
                           nexus_bool_t is_non_threaded_handler);

static void start_time_handler(nexus_endpoint_t *endpoint,
                               nexus_buffer_t *buffer,
                               nexus_bool_t is_non_threaded_handler);

/*********************************/
/*                               */
/* Nexus Handler Functions Table */
/*                               */
/*********************************/

#define REPLY_HANDLER_ID         0

static nexus_handler_t handlers[] =
{ 
    {NEXUS_HANDLER_TYPE_NON_THREADED, cancel_handler},
    {NEXUS_HANDLER_TYPE_NON_THREADED, start_time_handler},
};

typedef struct _monitor_t
{
    nexus_mutex_t mutex;
    nexus_cond_t cond;
    nexus_bool_t done;
} monitor_t;

static monitor_t                Monitor;
static nexus_endpointattr_t     EpAttr;
static nexus_endpoint_t         GlobalEndpoint;
static char                     callback_contact[GRM_MAX_MSG_SIZE];
static char                     job_contact[GRM_MAX_MSG_SIZE];

static void      dc_puts(char *msg_buf);
FILE             *log_fp;

static void allow_attachments(unsigned short *attach_port,
                              char *attach_url);
static int attach_requested(void *arg,
                            char *url,
                            nexus_startpoint_t *sp);
static void print_tree();
static void free_tree();

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
int NexusBoot(nexus_startpoint_t *startpoint)
{
    nexus_endpointattr_init(&EpAttr);
    nexus_endpointattr_set_handler_table(&EpAttr,
                                    handlers,
                                    sizeof(handlers)/sizeof(nexus_handler_t));

    nexus_endpoint_init(&GlobalEndpoint, &EpAttr);
    nexus_startpoint_bind(startpoint, &GlobalEndpoint);

    return NEXUS_SUCCESS;

} /* end NexusBoot() */

/*
 * main()
 */
int main(int argc, char **argv)
{
    int              size;
    int              count, rc;
    int              job_status;
    int              job_state_mask;
    nexus_byte_t     type;
    char             description[GRM_MAX_MSG_SIZE];
    int              format;
    nexus_byte_t     bformat;
    nexus_byte_t     buffer[GRM_MAX_MSG_SIZE];
    unsigned short   my_port;
    nexus_byte_t     *ptr;
    FILE             *args_fp;
    nexus_startpoint_t reply_sp;
    nexus_buffer_t     reply_buffer;
    nexus_node_t *nodes;
    int n_nodes;
    int message_handled;
    grm_specification_t *description_tree;
    char *tmp_ptr;

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
    fprintf(log_fp,"entering grm_job_manager\n");

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

    /*
     * Read the format incomming message.
     */
#ifdef READFROMFILE
    /*
     * Open the test file
     */
    if ((args_fp = fopen("grm_job.dat", "r")) == NULL)
    {
        printf("Cannot open test file.\n");
        exit(1);
    }
#else
    args_fp = stdin;
#endif

    if (fread(buffer, 1, 1, args_fp) <= 0)
    {
        fprintf(stderr, "fread() failed.\n");
    }
    format = (int)buffer[0];

    /*
     * Read the size incomming message.
     */
    if (fread(buffer, 1, 4, args_fp) <= 0)
    {
        fprintf(log_fp, "fread() failed.\n");
        fprintf(stderr, "fread() failed.\n");
    }
    ptr = buffer;
    nexus_dc_get_int(&ptr, &count, 1, format);

    /*
     * Read the remainder of the incomming message.
     */
    if (fread(buffer, 1, count - 5, args_fp) <= 0)
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
    nexus_mutex_init(&Monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&Monitor.cond, (nexus_condattr_t *) NULL);
    Monitor.done = NEXUS_FALSE;

    allow_attachments(&my_port, job_contact);

    tmp_ptr = description;
    description_tree = grm_specification_parse(tmp_ptr);

    printf("====== Start User Spec\n");
    print_tree(description_tree, 0);
    printf("====== End User Spec\n");

    /*
     * Start the job.  If successful reply with job_contact else
     * send error status.
     */
    job_status = gjm_job_request(job_contact, description_tree);

    fprintf(log_fp,"after gjm_job_request\n");

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
    nexus_poll();
*/

/*
    nexus_mutex_lock(&Monitor.mutex);
*/
    if (job_status == 0)
    {
        while (!Monitor.done)
        {
            /*
            nexus_cond_wait(&Monitor.cond, &Monitor.mutex);
            */
	    nexus_usleep(1000000);
    	    nexus_fd_handle_events(NEXUS_FD_POLL_NONBLOCKING_ALL, &message_handled);
	    gjm_poll(); 
        } /* endwhile */
/*
        nexus_mutex_unlock(&Monitor.mutex);
*/
    }

    free_tree(description_tree);

    nexus_disallow_attach(my_port);

    nexus_mutex_destroy(&Monitor.mutex);
    nexus_cond_destroy(&Monitor.cond);

    fprintf(log_fp,"exiting grm_job_request \n");

    nexus_shutdown_nonexiting();

    return(0);

} /* main() */


/*
 * gjm_callback()
 *
 * int gjm_callback(char *callback_contact, char *job_contact, int state, int errorcode)
 */
void gjm_callback(int state,
                  int errorcode)
{
    nexus_startpoint_t sp;
    nexus_buffer_t     reply_buffer;
    int                size, count;
    
    fprintf(log_fp, "in gjm_callback\n");

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

/*
    nexus_poll();
*/

} /* gjm_callback() */


/*
 * gjm_get_param()
 */
void gjm_get_param(grm_specification_t *sp,
                   char *param,
                   char *value)
{
    grm_specification_t *child;

    if (sp)
    {
        if (sp->type == GRM_SPECIFICATION_BOOLEAN)
        {
            /* GRM_SPECIFICATION_BOOLEAN */

            /* search thru children */
            for (child = sp->req.boolean.child_list;
                *value == '\0' && child; child = child->next)
                    gjm_get_param(child, param, value);
        }
        else
        {
            /* GRM_SPECIFICATION_RELATION */
            if (strcmp(sp->req.relation.left_op, param) == 0)
               strcpy(value, sp->req.relation.right_op);
        } /* endif */
    } /* endif */
} /* gjm_get_param() */


/*
 * gjm_terminate()
 */
gjm_terminate()
{
    nexus_mutex_lock(&(Monitor.mutex));
    Monitor.done = NEXUS_TRUE;
    nexus_cond_signal(&(Monitor.cond));
    nexus_mutex_unlock(&(Monitor.mutex));
} /* gjm_terminate() */


/*
 * allow_attachments()
 */
static void allow_attachments(unsigned short *attach_port,
                              char *attach_url)
{
    int rc;
    char *attach_host;

    fprintf(log_fp, "in allow_attachments\n");

    /* allow other Nexus programs to attach to us */
    *attach_port = 0;
    rc = nexus_allow_attach(attach_port,      /* port            */
                            &attach_host,     /* host            */
                            attach_requested, /* approval_func() */
                            NULL);
    if (rc != 0)
    {
       /* must always nexus_stdio_lock/nexus_stdio_unlock when doing any I/O */
       nexus_stdio_lock();
       fprintf(stderr, "ERROR: nexus_allow_attach() failed: rc=%d\n", rc);
       nexus_stdio_unlock();
       nexus_abort();
    } /* endif */

    sprintf(attach_url, "x-nexus://%s:%hu/%lu/%lu/", attach_host, *attach_port, 
            (unsigned long) getpid(), (unsigned long) time(0));

} /* end allow_attachments() */

/*
 * attach_requested()
 */
static int attach_requested(void *arg, char *url, nexus_startpoint_t *sp)
{
    fprintf(log_fp, "in attach_requested callback\n");

    nexus_startpoint_bind(sp, &GlobalEndpoint);

    return(0);
} /* attach_requested() */

/*
 * cancel_handler()
 */
static void cancel_handler(nexus_endpoint_t *endpoint,
                            nexus_buffer_t *buffer,
                            nexus_bool_t is_non_threaded_handler)
{
    fprintf(log_fp, "in cancel_handler\n");

    /* clean-up */
    nexus_buffer_destroy(buffer);

    gjm_job_cancel();

} /* cancel_handler() */

/*
 * start_time_handler()
 */
static void start_time_handler(nexus_endpoint_t *endpoint,
                               nexus_buffer_t *buffer,
                               nexus_bool_t is_non_threaded_handler)
{
    float                    confidence;
    nexus_startpoint_t       reply_sp;
    nexus_buffer_t           reply_buffer;
    grm_time_t               estimate, interval_size;
    int                      size;
    int message_handled;

    fprintf(log_fp, "in start_time_handler\n");

    nexus_get_float(buffer, &confidence, 1);
    nexus_get_startpoint(buffer, &reply_sp, 1);

    /* clean-up */
    nexus_buffer_destroy(buffer);

    fprintf(log_fp, "confidence passed = %f\n", confidence);

    gjm_job_start_time(callback_contact, confidence, &estimate, &interval_size);

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

/*
    nexus_poll();
*/

} /* start_time_handler() */


/*
 * print_tree()
 */
static void print_tree(grm_specification_t *sp,
                       int lvl)
{
    if (sp)
    {
        if (sp->type == GRM_SPECIFICATION_BOOLEAN)
        {
            /* GRM_SPECIFICATION_BOOLEAN */
            INDENT(lvl) printf("BOOLEAN ");
            switch (sp->req.boolean.operator)
            {
                case GRM_AND:      printf("&\n"); break;
                case GRM_OR:       printf("|\n"); break;
                case GRM_MULTIREQ: printf("+\n"); break;
                default: 
                    printf("unknown %d\n", sp->req.boolean.operator); 
                    break;
            } /* end switch() */
            print_tree(sp->req.boolean.child_list, lvl+1);
        }
        else
        {
            /* GRM_SPECIFICATION_RELATION */
            INDENT(lvl) printf("RELATION ");
            printf("%s ", sp->req.relation.left_op);
            switch (sp->req.relation.operator)
            {
                case GRM_EQ: printf("= ");  break;
                case GRM_NE: printf("!= "); break;
                case GRM_LT: printf("< ");  break;
                case GRM_LE: printf("<= "); break;
                case GRM_GT: printf("> ");  break;
                case GRM_GE: printf(">= "); break;
                default: 
                    printf("unknown %d\n", sp->req.relation.operator); 
                    break;
            } /* end switch() */
            printf("%s\n", sp->req.relation.right_op);
        } /* endif */
        print_tree(sp->next, lvl);
    } /* endif */

} /* end print_tree() */

/*
 * free_tree()
 */
static void free_tree(grm_specification_t *sp)
{
    grm_specification_t *child;

    if (sp)
    {
        if (sp->type == GRM_SPECIFICATION_BOOLEAN)
        {
            /* GRM_SPECIFICATION_BOOLEAN */

            /* freeing children */
            while (child = sp->req.boolean.child_list)
            {
                sp->req.boolean.child_list = child->next;
                free_tree(child);
            } /* endwhile */

            /* freeing myself */
            free(sp);
        }
        else
        {
            /* GRM_SPECIFICATION_RELATION ... no children */
            free(sp);
        } /* endif */
    } /* endif */

} /* end free_tree() */
