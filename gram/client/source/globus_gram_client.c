/******************************************************************************
globus_gram_client.c

Description:
    Resource Managemant Client API's

    This file contains the Resource Management Client API funtion
    calls.  The resource management API provides functions for 
    submitting a job request to a RM, for asking when a job
    (submitted or not) might run, for cancelling a request,
    for requesting notification of state changes for a request,
    and for checking for pending notifications.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include <assert.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include <globus_nexus.h>
#include "globus_gram_client.h"
#include "grami_fprintf.h"
#include "globus_rsl.h"
#include "globus_gram_job_manager.h"
#if defined(TARGET_ARCH_SOLARIS)
#include <netdb.h>
#endif

#ifdef GSS_AUTHENTICATION
#include "grami_ggg.h"
#endif

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct
{
    globus_mutex_t mutex;
    globus_cond_t cond;
    volatile globus_bool_t done;
    int job_status;
    char job_contact_str[1000];
} globus_l_job_request_monitor_t;

typedef struct
{
    globus_mutex_t mutex;
    globus_cond_t cond;
    volatile globus_bool_t done;
    int start_time_status;
    int start_time_estimate;
    int start_time_interval_size;
} globus_l_start_time_monitor_t;

typedef struct
{
    globus_mutex_t mutex;
    globus_cond_t cond;
    volatile globus_bool_t done;
    int cancel_status;
} globus_l_cancel_monitor_t;

typedef struct
{
    globus_gram_client_callback_func_t callback_func;
    void * user_callback_arg;
    globus_nexus_endpoint_t endpoint;
} globus_l_callback_t;

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static void 
globus_l_write_callback(void * arg,
                     int fd,
                     char * buf,
                     size_t nbytes);

static void 
globus_l_write_error_callback(void * arg,
                           int fd,
                           char * buf,
                           size_t nbytes,
                           int error);

static int 
globus_l_callback_attach_approval(void * user_arg,
                               char * url,
                               globus_nexus_startpoint_t * sp);

static void 
globus_l_job_request_reply_handler(globus_nexus_endpoint_t * endpoint,
                                globus_nexus_buffer_t * buffer,
                                globus_bool_t is_non_threaded);

static void 
globus_l_callback_handler(globus_nexus_endpoint_t * endpoint,
                       globus_nexus_buffer_t * buffer,
                       globus_bool_t is_non_threaded);

static void 
globus_l_cancel_callback_handler(globus_nexus_endpoint_t * endpoint,
                              globus_nexus_buffer_t * buffer,
                              globus_bool_t is_non_threaded);

static void 
globus_l_start_time_callback_handler(globus_nexus_endpoint_t * endpoint,
                                  globus_nexus_buffer_t * buffer,
                                  globus_bool_t is_non_threaded);

#ifdef GSS_AUTHENTICATION
static int
grami_ggg_get_token_nexus(void * arg, void ** bufp, size_t * sizep);

static int 
grami_ggg_send_token_nexus( void * arg,  void * buf, size_t size);
#endif
/******************************************************************************
                       Define module specific variables
******************************************************************************/
globus_module_descriptor_t globus_gram_client_module = {
    "globus_gram_client",
    globus_i_gram_client_activate,
    globus_i_gram_client_deactivate,
    GLOBUS_NULL
};

static globus_nexus_handler_t globus_l_job_request_reply_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
       globus_l_job_request_reply_handler},
};

static globus_nexus_handler_t callback_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
       globus_l_callback_handler},
};

static globus_nexus_handler_t globus_l_cancel_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
     globus_l_cancel_callback_handler},
};

static globus_nexus_handler_t globus_l_start_time_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
     globus_l_start_time_callback_handler},
};

FILE *			globus_l_print_fp;
static globus_mutex_t	globus_l_mutex;
static int		globus_l_is_initialized = 0;

#define GLOBUS_L_LOCK { \
    int err; \
    assert (globus_l_is_initialized==1); \
    err = globus_mutex_lock (&globus_l_mutex); \
    assert (!err); \
}

#define GLOBUS_L_UNLOCK { \
    int err; \
    err = globus_mutex_unlock (&globus_l_mutex); \
    assert (!err); \
}

/******************************************************************************
Function:	grami_ggg_get_token_nexus()
Description:
Parameters:
Returns:
******************************************************************************/
static int
grami_ggg_get_token_nexus(void * arg, void ** bufp, size_t * sizep)
{
    unsigned char int_buf[4];
    int           size;
    void *        cp;
    int           err = 0;
    int *         fd = (int *)arg;
	
    if (_nx_read_blocking(*fd, int_buf, 4))
    {
        fprintf(stderr,
        "grami_ggg_get_token_nexus(): reading token length\n");
        return -1;
    }

    size = (  ( ((unsigned int) int_buf[0]) << 24)
            | ( ((unsigned int) int_buf[1]) << 16)
            | ( ((unsigned int) int_buf[2]) << 8)
            |   ((unsigned int) int_buf[3]) );

    grami_fprintf(globus_l_print_fp, "READ token size %d %8.8x\n", size, size);

    if (size > 1<<24 || size < 0) 
    {
        size = 80;
        err = 1;
    }

    cp = (char *) globus_malloc(size);
    if (!cp) 
    {
        return -1;
    }

    if (_nx_read_blocking(*fd, (char *) cp, size))
    {
        fprintf(stderr,
            "grami_ggg_get_token_nexus(): reading token\n");
        return -2;
    } 

    if (err)
    {
        fprintf (stderr," bad token  %c%c%c%c%s\n",
        int_buf[0], int_buf[1], int_buf[2], int_buf[3], cp);
        return (-3);
    }
    *bufp = cp;
    *sizep = size;

    return 0;
}

/******************************************************************************
Function:	grami_ggg_send_token_nexus()
Description:
Parameters:
Returns:
******************************************************************************/
static int
grami_ggg_send_token_nexus( void *arg,  void *buf, size_t size)
{
    unsigned char  int_buf[4];
    int *          fd = (int *) arg;

    int_buf[0] =  size >> 24;
    int_buf[1] =  size >> 16;
    int_buf[2] =  size >>  8;
    int_buf[3] =  size;

    if (_nx_write_blocking(*fd, int_buf, 4)) 
    {
        fprintf(stderr,
        "grami_ggg_send_token_nexus(): sending token length");
        return -1;
    }

    grami_fprintf(globus_l_print_fp, "WRITE token %d\n", size);

    if (_nx_write_blocking(*fd, (char *) buf, size))
    {
        fprintf(stderr,
        "grami_ggg_send_token_nexus: sending token length");
        return -2;
    }
    return 0;
}


/******************************************************************************
Function:	globus_i_gram_client_activate()
Description:	Initialize variables
		Call authorization routine for password entry.
Parameters:
Returns:
******************************************************************************/
int
globus_i_gram_client_activate(void)
{
    int rc;
    int i;

    /*
     * Initialize nexus
     */
    rc = globus_module_activate(GLOBUS_NEXUS_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    
    rc = globus_module_activate(GLOBUS_POLL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    
    if ( globus_l_is_initialized == 0 )
    {
	/* initialize mutex which makes the client thread-safe */
	int err;
	err = globus_mutex_init (&globus_l_mutex, NULL);
	assert (!err);
	globus_l_is_initialized = 1;
    }
    
    globus_l_print_fp = NULL;

    /* get the initial security credential for the client */ 
    /* Do it once up front incase it prompts or fails     */

    rc = grami_ggg_init_first();
    return (rc);

} /* globus_i_gram_client_activate() */


/******************************************************************************
Function:	globus_i_gram_client_deactivate()
Description:
Parameters:
Returns:
******************************************************************************/
int
globus_i_gram_client_deactivate(void)
{
    int rc;

    if ( globus_l_is_initialized == 0 )
    {
	return(GLOBUS_FAILURE);
    }
    else
    {
	int err;
	err = globus_mutex_destroy(&globus_l_mutex);
	assert (!err);
	globus_l_is_initialized = 0;
    }
    
    rc = globus_module_deactivate(GLOBUS_POLL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }

    rc = globus_module_deactivate(GLOBUS_NEXUS_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }

    return (GLOBUS_SUCCESS);
} /* globus_i_gram_client_deactivate() */


/******************************************************************************
Function:	globus_gram_client_debug()
Description:
Parameters:
Returns:
******************************************************************************/
void
globus_gram_client_debug(void)
{
    globus_l_print_fp = stdout;
    grami_fprintf(globus_l_print_fp,
		  "globus_gram_client: debug messages will be printed.\n");
} /* globus_gram_client_debug() */


/******************************************************************************
Function:	globus_gram_client_job_request()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_request(char * gatekeeper_url,
			       const char * description,
			       const int job_state_mask,
			       const char * callback_url,
			       char ** job_contact)
{
    int                          size;
    int                          contact_msg_size;
    int                          count;
    int                          rc;
    int                          gatekeeper_fd;
    char *                       gatekeeper_host;
    char *                       gatekeeper_princ;
    unsigned short               gatekeeper_port = 0;
    char *                       auth_msg_buf;
    size_t                       auth_msg_buf_size;
    globus_byte_t                type;
    globus_byte_t *              contact_msg_buffer;
    globus_byte_t *              tmp_buffer;
    globus_nexus_endpointattr_t  reply_epattr;
    globus_nexus_endpoint_t      reply_ep;
    globus_nexus_startpoint_t    reply_sp;
    globus_l_job_request_monitor_t  job_request_monitor;

    grami_fprintf(globus_l_print_fp, "in globus_gram_client_job_request()\n");

    GLOBUS_L_LOCK;

    globus_mutex_init(&job_request_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&job_request_monitor.cond, (globus_condattr_t *) NULL);
    job_request_monitor.done = GLOBUS_FALSE;

    globus_nexus_endpointattr_init(&reply_epattr);
    globus_nexus_endpointattr_set_handler_table(&reply_epattr,
				globus_l_job_request_reply_handler_table,
				1);
    globus_nexus_endpoint_init(&reply_ep, &reply_epattr);
    globus_nexus_endpoint_set_user_pointer(&reply_ep, &job_request_monitor);
    globus_nexus_startpoint_bind(&reply_sp, &reply_ep);

    type  = (globus_byte_t)(GLOBUS_DC_FORMAT_LOCAL);
    size  = globus_nexus_sizeof_byte(1);
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_char(strlen(description));
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_int(1);
    if (callback_url)
    {
        size += globus_nexus_sizeof_char(strlen(callback_url));
    }
    size += globus_nexus_sizeof_startpoint(&reply_sp, 1);

    grami_fprintf(globus_l_print_fp,
		  "test 1 globus_gram_client_job_request()\n");

    if (size >= GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE)
    {
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_INVALID_REQUEST);
    }

    /*
     * contact_msg_size includes the extra int added to the front of the 
     * message.
     * size is the size of the message without the extra int.
     */
    contact_msg_size = size + 4;
    tmp_buffer = (globus_byte_t *) globus_malloc(contact_msg_size);
    contact_msg_buffer = tmp_buffer;
    
    /*
     * Put 4-byte big-endian unsigned integer into front of message, to be
     * peeled off by the gram_gatekeeper
     */
    *tmp_buffer++ = (globus_byte_t) (((size) & 0xFF000000) >> 24);
    *tmp_buffer++ = (globus_byte_t) (((size) & 0xFF0000) >> 16);
    *tmp_buffer++ = (globus_byte_t) (((size) & 0xFF00) >> 8);
    *tmp_buffer++ = (globus_byte_t)  ((size) & 0xFF);

    /*
     * Pack the rest of the message that goes to the gram_job_manager
     */
    *tmp_buffer++ = (globus_byte_t) type;
    globus_nexus_user_put_int(&tmp_buffer, &size, 1);
    count= strlen(description);
    globus_nexus_user_put_int(&tmp_buffer, &count, 1);
    globus_nexus_user_put_char(&tmp_buffer, (char *) description,
			       strlen(description));
    globus_nexus_user_put_int(&tmp_buffer, (int *) &job_state_mask, 1);
    if (callback_url)
    {
        count= strlen(callback_url);
        globus_nexus_user_put_int(&tmp_buffer, &count, 1);
        globus_nexus_user_put_char(&tmp_buffer,
				   (char *) callback_url,
				   strlen(callback_url));
    }
    else
    {
        count=0;
        globus_nexus_user_put_int(&tmp_buffer, &count, 1);
    }

    globus_nexus_user_put_startpoint_transfer(&tmp_buffer, &reply_sp, 1);

    grami_fprintf(globus_l_print_fp,
		  "test 2 globus_gram_client_job_request()\n");

    {
        char *cp, *sp, *qp;

        if ((cp = strdup(gatekeeper_url)))
        {
            gatekeeper_host = gatekeeper_princ = cp;
            if ((sp = strchr(cp,':')))
            {
                *sp++ = '\0';
                if ((qp = strchr(sp, ':')))
                {
                    *qp++ = '\0';
                    gatekeeper_princ = qp;
                }
                gatekeeper_port = atoi(sp);
            }
            else
            {
                gatekeeper_port = 754;
            }
        } 
        else
        {
            fprintf(stderr,"strdup failed for gatekeeper_url");
            GLOBUS_L_UNLOCK;
            return(1);
        }
    }

    /* Connecting to the gatekeeper.
     */

    grami_fprintf(globus_l_print_fp, "Connecting to %s:%d:%s\n",
		  gatekeeper_host, gatekeeper_port, gatekeeper_princ);

    rc = globus_nexus_fd_connect(gatekeeper_host,
				 gatekeeper_port,
				 &gatekeeper_fd);
    if (rc != 0)
    {
        fprintf(stderr, " globus_nexus_fd_connect failed.  rc = %d\n", rc);
	GLOBUS_L_UNLOCK;
        return (GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED);
    }

    /* Do gss authentication here */
#ifdef GSS_AUTHENTICATION
    /* For now will will use the hostname as the globusid of the 
     * gatekeeper to which we whish to authenticate. Later theis will
     * need to be supplied. 
     * DEE 8/11/97
     */

    grami_fprintf(globus_l_print_fp,
		  "Starting authentication to %s\n", gatekeeper_host);

    rc =  grami_ggg_init(gatekeeper_princ,
			 grami_ggg_get_token_nexus,
			 (void *) &gatekeeper_fd,
			 grami_ggg_send_token_nexus,
			 (void *) &gatekeeper_fd);

    if (rc != 0)
    {
	fprintf(stderr, 
		"GSS authentication failed. rc = %8.8x\n", rc);
	globus_nexus_fd_close(gatekeeper_fd);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION);
    }

    if (grami_ggg_get_token_nexus((void *) &gatekeeper_fd,
				  (void **) &auth_msg_buf, &auth_msg_buf_size))
    {
	fprintf(stderr, "Authoirization message not received");
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION);
    }

    if (auth_msg_buf_size > 1 )
    {
	fprintf(stderr, auth_msg_buf);
	globus_nexus_fd_close(gatekeeper_fd);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION);
    }

    grami_fprintf(globus_l_print_fp,
		  "Authentication/authorization complete\n");
#else
    grami_fprintf(globus_l_print_fp,
		  "WARNING: No authentication performed\n");
#endif /* GSS_AUTHENTICATION */

    rc = globus_nexus_fd_register_for_write(gatekeeper_fd,
					    (char *) contact_msg_buffer,
					    contact_msg_size,
					    globus_l_write_callback,
					    globus_l_write_error_callback,
					    (void *) &job_request_monitor);
    if (rc != 0)
    {
	fprintf(stderr, "globus_nexus_fd_register_for_write failed\n");
	globus_nexus_fd_close(gatekeeper_fd);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    grami_fprintf(globus_l_print_fp,
		  "test 3 globus_gram_client_job_request()\n");

    globus_mutex_lock(&job_request_monitor.mutex);
    while (!job_request_monitor.done)
    {
	globus_cond_wait(&job_request_monitor.cond,
			 &job_request_monitor.mutex);
    }
    globus_mutex_unlock(&job_request_monitor.mutex);

    globus_mutex_destroy(&job_request_monitor.mutex);
    globus_cond_destroy(&job_request_monitor.cond);

    grami_fprintf(globus_l_print_fp,
		  "test 4 globus_gram_client_job_request()\n");

    if (job_request_monitor.job_status == 0)
    {
        * job_contact = (char *) 
           globus_malloc(strlen(job_request_monitor.job_contact_str) + 1);

        strcpy(* job_contact, job_request_monitor.job_contact_str);
    }

    globus_free(contact_msg_buffer);
    globus_nexus_fd_close(gatekeeper_fd);
    GLOBUS_L_UNLOCK;
    return(job_request_monitor.job_status);

} /* globus_gram_client_job_request() */


/******************************************************************************
Function:	globus_l_write_error_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_write_error_callback(void * arg,
                           int fd,
                           char * buf,
                           size_t nbytes,
                           int error)
{
    globus_l_job_request_monitor_t *job_request_monitor = 
          (globus_l_job_request_monitor_t *) arg;

    globus_mutex_lock(&job_request_monitor->mutex);

    job_request_monitor->job_status = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;

    job_request_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&job_request_monitor->cond);
    globus_mutex_unlock(&job_request_monitor->mutex);
} /* globus_l_write_error_callback() */


/******************************************************************************
Function:	globus_l_write_callback()
Description: called when the write completes, but we don't need to do anything.
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_write_callback(void * arg,
                     int fd,
                     char * buf,
                     size_t nbytes)
{
    grami_fprintf(globus_l_print_fp, "in globus_l_write_callback()\n");
} /* globus_l_write_callback() */


/******************************************************************************
Function:	globus_l_job_request_reply_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_job_request_reply_handler(globus_nexus_endpoint_t * endpoint,
                                globus_nexus_buffer_t * buffer,
                                globus_bool_t is_non_threaded)
{
    int               size;
    int               count = 0;
    int               format;
    globus_byte_t     bformat;
    globus_byte_t *   ptr;
    globus_l_job_request_monitor_t * job_request_monitor;

    job_request_monitor = (globus_l_job_request_monitor_t * )
                           globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_job_request_reply_handler()\n");

    globus_mutex_lock(&job_request_monitor->mutex);

    globus_nexus_get_int(buffer, &(job_request_monitor->job_status), 1);

    if (job_request_monitor->job_status == 0)
    {
        globus_nexus_get_int(buffer, &count, 1);
        globus_nexus_get_char(buffer,
			      job_request_monitor->job_contact_str,
			      count);
    }

    *(job_request_monitor->job_contact_str+count)= '\0';

    /* got all of the message */
    job_request_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&job_request_monitor->cond);
    globus_mutex_unlock(&job_request_monitor->mutex);
} /* globus_l_job_request_reply_handler() */


/******************************************************************************
Function:	globus_gram_client_job_check()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_check(char * gatekeeper_url,
               const char * description,
               float required_confidence,
               globus_gram_client_time_t * estimate,
               globus_gram_client_time_t * interval_size)
{
    return(0);
} /* globus_gram_client_job_check() */


/******************************************************************************
Function:	globus_gram_client_job_cancel()
Description:	sending cancel request to job manager
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_cancel(char * job_contact)
{
    int                             rc;
    int                             size;
    globus_nexus_buffer_t           buffer;
    globus_nexus_startpoint_t       sp_to_job_manager;
    globus_nexus_startpoint_t       sp;
    globus_nexus_endpoint_t         ep;
    globus_nexus_endpointattr_t     epattr;
    globus_l_cancel_monitor_t       cancel_monitor;

    grami_fprintf(globus_l_print_fp, "in globus_gram_client_job_cancel()\n");

    GLOBUS_L_LOCK;

    globus_mutex_init(&cancel_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&cancel_monitor.cond, (globus_condattr_t *) NULL);

    globus_mutex_lock(&cancel_monitor.mutex);
    cancel_monitor.done = GLOBUS_FALSE;
    globus_mutex_unlock(&cancel_monitor.mutex);

    globus_nexus_endpointattr_init(&epattr);
    globus_nexus_endpointattr_set_handler_table(&epattr,
						globus_l_cancel_handler_table,
						1);
    globus_nexus_endpoint_init(&ep, &epattr);
    globus_nexus_endpoint_set_user_pointer(&ep, &cancel_monitor);
    globus_nexus_startpoint_bind(&sp, &ep);

    rc = globus_nexus_attach(job_contact, &sp_to_job_manager);
    if (rc != 0)
    {
        printf("globus_nexus_attach returned %d\n", rc);
	GLOBUS_L_UNLOCK;
        return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    size = globus_nexus_sizeof_startpoint(&sp, 1);
    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = globus_nexus_send_rsr(&buffer,
			       &sp_to_job_manager,
			       GLOBUS_I_GRAM_JOB_MANAGER_CANCEL_HANDLER_ID,
			       GLOBUS_TRUE,
			       GLOBUS_FALSE);
    if (rc != 0)
    {
	printf("globus_nexus_send_rsr returned %d\n", rc);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    globus_nexus_startpoint_destroy(&sp_to_job_manager);

    globus_mutex_lock(&cancel_monitor.mutex);
    while (!cancel_monitor.done)
    {
        globus_cond_wait(&cancel_monitor.cond, &cancel_monitor.mutex);
    }
    globus_mutex_unlock(&cancel_monitor.mutex);

    globus_mutex_destroy(&cancel_monitor.mutex);
    globus_cond_destroy(&cancel_monitor.cond);

    GLOBUS_L_UNLOCK;
    return (cancel_monitor.cancel_status);

} /* globus_gram_client_job_cancel */ 


/******************************************************************************
Function:	globus_l_cancel_callback_handler()
Description:	
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_cancel_callback_handler(globus_nexus_endpoint_t * endpoint,
                              globus_nexus_buffer_t * buffer,
                              globus_bool_t is_non_threaded)
{
    globus_l_cancel_monitor_t * cancel_monitor;

    cancel_monitor = 
        (globus_l_cancel_monitor_t *)
	globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_cancel_callback_handler()\n");

    globus_mutex_lock(&cancel_monitor->mutex);
    globus_nexus_get_int(buffer, &cancel_monitor->cancel_status, 1);
    
    cancel_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&cancel_monitor->cond);
    globus_mutex_unlock(&cancel_monitor->mutex);

} /* globus_l_cancel_callback_handler() */


/******************************************************************************
Function:	globus_gram_client_callback_allow()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_callback_allow(
    globus_gram_client_callback_func_t callback_func,
    void * user_callback_arg,
    char ** callback_contact)
{
    int			  rc;
    unsigned short 	  port = 0;
    char * 		  host;
    globus_l_callback_t *	  callback;
    globus_nexus_endpointattr_t  epattr;

    grami_fprintf(globus_l_print_fp, 
		  "in globus_gram_client_callback_allow()\n");

    GLOBUS_L_LOCK;

    callback =
	(globus_l_callback_t *) globus_malloc(sizeof(globus_l_callback_t));
    callback->callback_func =
	(globus_gram_client_callback_func_t) callback_func;
    callback->user_callback_arg = user_callback_arg;
    globus_nexus_endpointattr_init(&epattr);
    globus_nexus_endpointattr_set_handler_table(&epattr,
						callback_handler_table,
						1);
    globus_nexus_endpoint_init(&(callback->endpoint), &epattr);
    globus_nexus_endpoint_set_user_pointer(&(callback->endpoint), callback);
    
    rc = globus_nexus_allow_attach(&port, &host,
	     	            globus_l_callback_attach_approval,
		            (void *) callback);
       
    if (rc != 0)
    {
        printf("globus_nexus_allow_attach returned %d\n", rc);
        return (1);
    }

    /*
     * add 13 for x-nexus stuff plus 1 for the null
     */
    *callback_contact = (char *) 
       globus_malloc(sizeof(port) + MAXHOSTNAMELEN + 13);

    sprintf(* callback_contact, "x-nexus://%s:%hu/", host, port);

    GLOBUS_L_UNLOCK;

    return(0);

} /* globus_gram_client_callback_allow() */


/******************************************************************************
Function:	globus_l_callback_attach_approval()
Description:	
Parameters:
Returns:
******************************************************************************/
static int
globus_l_callback_attach_approval(void * user_arg,
                                   char * url,
                                   globus_nexus_startpoint_t * sp)
{
    globus_l_callback_t * callback = (globus_l_callback_t *) user_arg;

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_callback_attach_approval()\n");

    globus_nexus_startpoint_bind(sp, &(callback->endpoint));

    return(0);
} /* globus_l_callback_attach_approval() */


/******************************************************************************
Function:	globus_l_callback_handler()
Description:	
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_callback_handler(globus_nexus_endpoint_t * endpoint,
                       globus_nexus_buffer_t * buffer,
                       globus_bool_t is_non_threaded)
{
    int count;
    int state;
    int errorcode;
    globus_l_callback_t * callback;
    char job_contact[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];

    grami_fprintf(globus_l_print_fp, "in globus_l_callback_handler()\n");

    callback = (globus_l_callback_t *)
	globus_nexus_endpoint_get_user_pointer(endpoint);
    
    globus_nexus_get_int(buffer, &count, 1);
    globus_nexus_get_char(buffer, job_contact, count);
    *(job_contact+count)= '\0';
    globus_nexus_get_int(buffer, &state, 1);
    globus_nexus_get_int(buffer, &errorcode, 1);
    
    (*callback->callback_func)(callback->user_callback_arg, 
			       job_contact, 
			       state,
			       errorcode);
} /* globus_l_callback_handler() */


/******************************************************************************
Function:	globus_gram_client_callback_disallow()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_callback_disallow(char * callback_contact)
{
    int			  rc;
    unsigned short 	  port = 0;
    char * 		  host;

    grami_fprintf(globus_l_print_fp,
 "in globus_gram_client_callback_disallow()\n");

    if (globus_nexus_split_url(callback_contact,
			       &host,
			       &port,
			       NULL) != 0)
    {
        printf(" invalid url.\n");
        return (1);
    }

    globus_nexus_disallow_attach(port);
       
    return(0);

} /* globus_gram_client_callback_allow() */


/******************************************************************************
Function:	globus_gram_client_job_start_time()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_start_time(char * job_contact,
                    float required_confidence,
                    globus_gram_client_time_t * estimate,
                    globus_gram_client_time_t * interval_size)
{
    int                               rc;
    int                               size;
    globus_nexus_buffer_t             buffer;
    globus_nexus_startpoint_t         sp_to_job_manager;
    globus_nexus_startpoint_t         sp;
    globus_nexus_endpoint_t           ep;
    globus_nexus_endpointattr_t       epattr;
    globus_l_start_time_monitor_t     start_time_monitor;

    grami_fprintf(globus_l_print_fp,
		  "in globus_gram_client_job_start_time()\n");

    GLOBUS_L_LOCK;

    globus_mutex_init(&start_time_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&start_time_monitor.cond, (globus_condattr_t *) NULL);

    globus_mutex_lock(&start_time_monitor.mutex);
    start_time_monitor.done = GLOBUS_FALSE;
    globus_mutex_unlock(&start_time_monitor.mutex);

    globus_nexus_endpointattr_init(&epattr);
    globus_nexus_endpointattr_set_handler_table(&epattr,
                                         globus_l_start_time_handler_table,
                                         1);
    globus_nexus_endpoint_init(&ep, &epattr);
    globus_nexus_endpoint_set_user_pointer(&ep, &start_time_monitor);
    globus_nexus_startpoint_bind(&sp, &ep);

    rc = globus_nexus_attach(job_contact, &sp_to_job_manager);
    if (rc != 0)
    {
	printf("globus_nexus_attach returned %d\n", rc);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    size  = globus_nexus_sizeof_float(1);
    size += globus_nexus_sizeof_startpoint(&sp, 1);

    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_float(&buffer, &required_confidence, 1);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = globus_nexus_send_rsr(&buffer,
			       &sp_to_job_manager,
			       GLOBUS_I_GRAM_JOB_MANAGER_START_TIME_HANDLER_ID,
			       GLOBUS_TRUE,
			       GLOBUS_FALSE);

    if (rc != 0)
    {
	printf("globus_nexus_send_rsr returned %d\n", rc);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    globus_nexus_startpoint_destroy(&sp_to_job_manager);

    globus_mutex_lock(&start_time_monitor.mutex);
    while (!start_time_monitor.done)
    {
        globus_cond_wait(&start_time_monitor.cond, &start_time_monitor.mutex);
    }
    globus_mutex_unlock(&start_time_monitor.mutex);

    globus_mutex_destroy(&start_time_monitor.mutex);
    globus_cond_destroy(&start_time_monitor.cond);

    rc = start_time_monitor.start_time_status;
    estimate->dumb_time = start_time_monitor.start_time_estimate;
    interval_size->dumb_time = start_time_monitor.start_time_interval_size;
 
    GLOBUS_L_UNLOCK;
    return (rc);

} /* globus_gram_client_job_start_time() */


/******************************************************************************
Function:	globus_l_start_time_callback_handler()
Description:	
Parameters:
Returns:
******************************************************************************/
static void 
globus_l_start_time_callback_handler(globus_nexus_endpoint_t * endpoint,
                                  globus_nexus_buffer_t * buffer,
                                  globus_bool_t is_non_threaded)
{
    globus_l_start_time_monitor_t * start_time_monitor;

    start_time_monitor = (globus_l_start_time_monitor_t *)
                         globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_start_time_callback_handler()\n");

    globus_mutex_lock(&start_time_monitor->mutex);

    globus_nexus_get_int(buffer, &start_time_monitor->start_time_status, 1);
    globus_nexus_get_int(buffer, &start_time_monitor->start_time_estimate, 1);
    globus_nexus_get_int(buffer,
			 &start_time_monitor->start_time_interval_size, 1);
    
    start_time_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&start_time_monitor->cond);
    globus_mutex_unlock(&start_time_monitor->mutex);

} /* globus_l_start_time_callback_handler() */


/******************************************************************************
Function:	globus_gram_client_callback_check()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_callback_check()
{
    grami_fprintf(globus_l_print_fp,
		  "in globus_gram_client_callback_check()\n");

    globus_poll_nonblocking();

    return(0);

} /* globus_gram_client_callback_check() */


/******************************************************************************
Function:	globus_gram_client_job_contact_free()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_contact_free(char * job_contact)
{
    grami_fprintf(globus_l_print_fp,
		  "in globus_gram_client_job_contact_free()\n");

    globus_free(job_contact);

    return (0);
} /* globus_gram_client_job_contact_free() */
