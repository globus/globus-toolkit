/******************************************************************************
gram_client.c

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
#include <sys/param.h>
#include <sys/time.h>
#include <nexus.h>
#include "gram_client.h"
#include "grami_fprintf.h"
#include "gram_rsl.h"
#include "gram_job_manager.h"
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
    nexus_mutex_t mutex;
    nexus_cond_t cond;
    volatile nexus_bool_t done;
    int job_status;
    char job_contact_str[1000];
} graml_job_request_monitor_s;

typedef struct
{
    nexus_mutex_t mutex;
    nexus_cond_t cond;
    volatile nexus_bool_t done;
    int start_time_status;
    int start_time_estimate;
    int start_time_interval_size;
} graml_start_time_monitor_s;

typedef struct
{
    nexus_mutex_t mutex;
    nexus_cond_t cond;
    volatile nexus_bool_t done;
    int cancel_status;
} graml_cancel_monitor_s;

typedef struct
{
    gram_callback_func_t callback_func;
    void * user_callback_arg;
    nexus_endpoint_t endpoint;
} callback_s;

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static void 
graml_write_callback(void * arg,
                     int fd,
                     char * buf,
                     size_t nbytes);

static void 
graml_write_error_callback(void * arg,
                           int fd,
                           char * buf,
                           size_t nbytes,
                           int error);

static int 
graml_callback_attach_approval(void * user_arg,
                               char * url,
                               nexus_startpoint_t * sp);

static void 
graml_job_request_reply_handler(nexus_endpoint_t * endpoint,
                                nexus_buffer_t * buffer,
                                nexus_bool_t is_non_threaded);

static void 
graml_callback_handler(nexus_endpoint_t * endpoint,
                       nexus_buffer_t * buffer,
                       nexus_bool_t is_non_threaded);

static void 
graml_cancel_callback_handler(nexus_endpoint_t * endpoint,
                              nexus_buffer_t * buffer,
                              nexus_bool_t is_non_threaded);

static void 
graml_start_time_callback_handler(nexus_endpoint_t * endpoint,
                                  nexus_buffer_t * buffer,
                                  nexus_bool_t is_non_threaded);

#ifdef GSS_AUTHENTICATION
static int
grami_ggg_get_token_nexus(void * arg, void ** bufp, size_t * sizep);

static int 
grami_ggg_send_token_nexus( void * arg,  void * buf, size_t size);
#endif
/******************************************************************************
                       Define module specific variables
******************************************************************************/
static nexus_handler_t gram_job_request_reply_handler_table[] =
{
    {NEXUS_HANDLER_TYPE_NON_THREADED,
       graml_job_request_reply_handler},
};

static nexus_handler_t callback_handler_table[] =
{
    {NEXUS_HANDLER_TYPE_NON_THREADED,
       graml_callback_handler},
};

static nexus_handler_t gram_cancel_handler_table[] =
{
    {NEXUS_HANDLER_TYPE_NON_THREADED,
     graml_cancel_callback_handler},
};

static nexus_handler_t gram_start_time_handler_table[] =
{
    {NEXUS_HANDLER_TYPE_NON_THREADED,
     graml_start_time_callback_handler},
};

FILE *                 graml_print_fp;
static nexus_mutex_t   graml_mutex;
static int             graml_mutex_is_initialized = 0;

#define GRAML_LOCK { \
  int err; \
  assert (graml_mutex_is_initialized==1); \
  err = nexus_mutex_lock (&graml_mutex); assert (!err); \
}

#define GRAML_UNLOCK { \
  int err; \
  err = nexus_mutex_unlock (&graml_mutex); assert (!err); \
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

    grami_fprintf(graml_print_fp, "READ token size %d %8.8x\n", size, size);

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

    grami_fprintf(graml_print_fp, "WRITE token %d\n", size);

    if (_nx_write_blocking(*fd, (char *) buf, size))
    {
        fprintf(stderr,
        "grami_ggg_send_token_nexus: sending token length");
        return -2;
    }
    return 0;
}

/******************************************************************************
Function:	gram_init()
Description:  Initialize variables, search argument list for ones gram_init
              cares about (i.e. -debug) and call authorization routine for
              password entry.
Parameters:
Returns:
******************************************************************************/
int 
gram_init(int * argc, char *** argv)
{
    int rc;
    int i;

    /*
     * Initialize nexus
     */
    rc = nexus_init(argc,
		    argv,
		    "NEXUS_ARGS",
		    "nx",
		    NULL);
    
    if (rc != NEXUS_SUCCESS && rc != NEXUS_ERROR_ALREADY_INITIALIZED)
    {
	return(rc);
    }
    
    if ( graml_mutex_is_initialized == 0 ) {
      /* initialize mutex which makes the client thread-safe */
      int err;

      err = nexus_mutex_init (&graml_mutex, NULL); assert (!err);
      graml_mutex_is_initialized = 1;
    }
    
    /*
     * Parse the command line arguments
     */
    if (argc && argv)
    {
	for (i = 1; i < *argc; i++)
	{
	    if (strcmp((*argv)[i], "-debug") == 0)
	    {
		graml_print_fp = stdout;
		grami_fprintf(graml_print_fp,
                        "gram_init() debug messages will be printed.\n");
	    }
	    else
	    {
		graml_print_fp = NULL;
	    }
	}
    }

    /* get the initial security credential for the client */ 
    /* Do it once up front incase it prompts or fails     */

    rc = grami_ggg_init_first();
    return (rc);

} /* gram_init() */

/******************************************************************************
Function:	gram_shutdown()
Description:
Parameters:
Returns:
******************************************************************************/
int
gram_shutdown()
{
    return (nexus_shutdown());
}

/******************************************************************************
Function:	gram_job_request()
Description:
Parameters:
Returns:
******************************************************************************/
int 
gram_job_request(char * gatekeeper_url,
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
    nexus_byte_t                 type;
    nexus_byte_t *               contact_msg_buffer;
    nexus_byte_t *               tmp_buffer;
    nexus_endpointattr_t         reply_epattr;
    nexus_endpoint_t             reply_ep;
    nexus_startpoint_t           reply_sp;
    graml_job_request_monitor_s  job_request_monitor;

    grami_fprintf(graml_print_fp, "in gram_job_request()\n");

    GRAML_LOCK;

    nexus_mutex_init(&job_request_monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&job_request_monitor.cond, (nexus_condattr_t *) NULL);
    job_request_monitor.done = NEXUS_FALSE;

    nexus_endpointattr_init(&reply_epattr);
    nexus_endpointattr_set_handler_table(&reply_epattr,
					 gram_job_request_reply_handler_table,
					 1);
    nexus_endpoint_init(&reply_ep, &reply_epattr);
    nexus_endpoint_set_user_pointer(&reply_ep, &job_request_monitor);
    nexus_startpoint_bind(&reply_sp, &reply_ep);

    type  = (nexus_byte_t)(NEXUS_DC_FORMAT_LOCAL);
    size  = nexus_sizeof_byte(1);
    size += nexus_sizeof_int(1);
    size += nexus_sizeof_int(1);
    size += nexus_sizeof_char(strlen(description));
    size += nexus_sizeof_int(1);
    size += nexus_sizeof_int(1);
    if (callback_url)
        size += nexus_sizeof_char(strlen(callback_url));
    size += nexus_sizeof_startpoint(&reply_sp, 1);

    grami_fprintf(graml_print_fp, "test 1 gram_job_request()\n");

    if (size >= GRAM_MAX_MSG_SIZE) {
      GRAML_UNLOCK;
      return (GRAM_ERROR_INVALID_REQUEST);
    }
    /*
     * contact_msg_size includes the extra int added to the front of the 
     * message.
     * size is the size of the message without the extra int.
     */
    contact_msg_size = size + 4;
    tmp_buffer = (nexus_byte_t *)globus_malloc(contact_msg_size);
    contact_msg_buffer = tmp_buffer;
    
    /*
     * Put 4-byte big-endian unsigned integer into front of message, to be
     * peeled off by the gram_gatekeeper
     */
    *tmp_buffer++ = (nexus_byte_t) (((size) & 0xFF000000) >> 24);
    *tmp_buffer++ = (nexus_byte_t) (((size) & 0xFF0000) >> 16);
    *tmp_buffer++ = (nexus_byte_t) (((size) & 0xFF00) >> 8);
    *tmp_buffer++ = (nexus_byte_t)  ((size) & 0xFF);

    /*
     * Pack the rest of the message that goes to the gram_job_manager
     */
    *tmp_buffer++ = (nexus_byte_t) type;
    nexus_user_put_int(&tmp_buffer, &size, 1);
    count= strlen(description);
    nexus_user_put_int(&tmp_buffer, &count, 1);
    nexus_user_put_char(&tmp_buffer, description, strlen(description));
    nexus_user_put_int(&tmp_buffer, &job_state_mask, 1);
    if (callback_url)
    {
        count= strlen(callback_url);
        nexus_user_put_int(&tmp_buffer, &count, 1);
        nexus_user_put_char(&tmp_buffer, callback_url, strlen(callback_url));
    }
    else
    {
        count=0;
        nexus_user_put_int(&tmp_buffer, &count, 1);
    }

    nexus_user_put_startpoint_transfer(&tmp_buffer, &reply_sp, 1);

    grami_fprintf(graml_print_fp, "test 2 gram_job_request()\n");
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
            GRAML_UNLOCK;
            return(1);
        }
    }

    /* Connecting to the gatekeeper.
     */

    grami_fprintf(graml_print_fp, "Connecting to %s:%d:%s\n",
	   gatekeeper_host, gatekeeper_port, gatekeeper_princ);

    rc = nexus_fd_connect(gatekeeper_host, gatekeeper_port, &gatekeeper_fd);
    if (rc != 0)
    {
        fprintf(stderr, " nexus_fd_connect failed.  rc = %d\n", rc);
	GRAML_UNLOCK;
        return (GRAM_ERROR_CONNECTION_FAILED);
    }

    /* Do gss authentication here */
#ifdef GSS_AUTHENTICATION
    /* For now will will use the hostname as the globusid of the 
     * gatekeeper to which we whish to authenticate. Later theis will
     * need to be supplied. 
     * DEE 8/11/97
     */

    grami_fprintf(graml_print_fp, "Starting authentication to %s\n", gatekeeper_host);

    rc =  grami_ggg_init(gatekeeper_princ,
                   grami_ggg_get_token_nexus,
                   (void *) &gatekeeper_fd,
                   grami_ggg_send_token_nexus,
                   (void *) &gatekeeper_fd);

    if (rc != 0)
    {
      fprintf(stderr, 
	      "GSS authentication failed. rc = %8.8x\n", rc);
      nexus_fd_close(gatekeeper_fd);
      GRAML_UNLOCK;
      return (GRAM_ERROR_AUTHORIZATION);
    }

    if (grami_ggg_get_token_nexus((void *) &gatekeeper_fd,
				  (void **) &auth_msg_buf, &auth_msg_buf_size))
    {
      fprintf(stderr, "Authoirization message not received");
      GRAML_UNLOCK;
      return (GRAM_ERROR_AUTHORIZATION);
    }

    if (auth_msg_buf_size > 1 ) {
      fprintf(stderr, auth_msg_buf);
      nexus_fd_close(gatekeeper_fd);
      GRAML_UNLOCK;
      return (GRAM_ERROR_AUTHORIZATION);
    }

    grami_fprintf(graml_print_fp, "Authentication/authorization complete\n");
#else
    grami_fprintf(graml_print_fp, "WARNING: No authentication performed\n");
#endif /* GSS_AUTHENTICATION */

    rc = nexus_fd_register_for_write(gatekeeper_fd,
                                    (char *) contact_msg_buffer,
                                     contact_msg_size,
                                     graml_write_callback,
                                     graml_write_error_callback,
                                     (void *) &job_request_monitor);
    if (rc != 0)
    {
      fprintf(stderr, "nexus_fd_register_for_write failed\n");
      nexus_fd_close(gatekeeper_fd);
      GRAML_UNLOCK;
      return (GRAM_ERROR_PROTOCOL_FAILED);
    }

    grami_fprintf(graml_print_fp, "test 3 gram_job_request()\n");

    nexus_mutex_lock(&job_request_monitor.mutex);
    while (!job_request_monitor.done) {
      nexus_cond_wait(&job_request_monitor.cond, &job_request_monitor.mutex);
    }
    nexus_mutex_unlock(&job_request_monitor.mutex);

    nexus_mutex_destroy(&job_request_monitor.mutex);
    nexus_cond_destroy(&job_request_monitor.cond);

    grami_fprintf(graml_print_fp, "test 4 gram_job_request()\n");

    if (job_request_monitor.job_status == 0)
    {
        * job_contact = (char *) 
           globus_malloc(strlen(job_request_monitor.job_contact_str) + 1);

        strcpy(* job_contact, job_request_monitor.job_contact_str);
    }

    globus_free(contact_msg_buffer);
    nexus_fd_close(gatekeeper_fd);
    GRAML_UNLOCK;
    return(job_request_monitor.job_status);

} /* gram_job_request() */

/******************************************************************************
Function:	graml_write_error_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
graml_write_error_callback(void * arg,
                           int fd,
                           char * buf,
                           size_t nbytes,
                           int error)
{
    graml_job_request_monitor_s *job_request_monitor = 
          (graml_job_request_monitor_s *) arg;

    nexus_mutex_lock(&job_request_monitor->mutex);

    job_request_monitor->job_status = GRAM_ERROR_PROTOCOL_FAILED;

    job_request_monitor->done = NEXUS_TRUE;
    nexus_cond_signal(&job_request_monitor->cond);
    nexus_mutex_unlock(&job_request_monitor->mutex);
} /* graml_write_error_callback() */

/******************************************************************************
Function:	graml_write_callback()
Description: called when the write completes, but we don't need to do anything.
Parameters:
Returns:
******************************************************************************/
static void 
graml_write_callback(void * arg,
                     int fd,
                     char * buf,
                     size_t nbytes)
{
    grami_fprintf(graml_print_fp, "in graml_write_callback()\n");
} /* graml_write_callback() */

/******************************************************************************
Function:	graml_job_request_reply_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void 
graml_job_request_reply_handler(nexus_endpoint_t * endpoint,
                                nexus_buffer_t * buffer,
                                nexus_bool_t is_non_threaded)
{
    int              size;
    int              count = 0;
    int              format;
    nexus_byte_t     bformat;
    nexus_byte_t *   ptr;
    graml_job_request_monitor_s * job_request_monitor;

    job_request_monitor = (graml_job_request_monitor_s * )
                           nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(graml_print_fp, "in graml_job_request_reply_handler()\n");

    nexus_mutex_lock(&job_request_monitor->mutex);

    nexus_get_int(buffer, &(job_request_monitor->job_status), 1);

    if (job_request_monitor->job_status == 0)
    {
        nexus_get_int(buffer, &count, 1);
        nexus_get_char(buffer, job_request_monitor->job_contact_str, count);
    }

    *(job_request_monitor->job_contact_str+count)= '\0';

    /* got all of the message */
    job_request_monitor->done = NEXUS_TRUE;
    nexus_cond_signal(&job_request_monitor->cond);
    nexus_mutex_unlock(&job_request_monitor->mutex);
} /* graml_job_request_reply_handler() */

/******************************************************************************
Function:	gram_job_check()
Description:
Parameters:
Returns:
******************************************************************************/
int 
gram_job_check(char * gatekeeper_url,
               const char * description,
               float required_confidence,
               gram_time_t * estimate,
               gram_time_t * interval_size)
{
    return(0);
} /* gram_job_check() */

/******************************************************************************
Function:	gram_job_cancel()
Description:	sending cancel request to job manager
Parameters:
Returns:
******************************************************************************/
int 
gram_job_cancel(char * job_contact)
{
    int                      rc;
    int                      size;
    nexus_buffer_t           buffer;
    nexus_startpoint_t       sp_to_job_manager;
    nexus_startpoint_t       sp;
    nexus_endpoint_t         ep;
    nexus_endpointattr_t     epattr;
    graml_cancel_monitor_s   cancel_monitor;

    grami_fprintf(graml_print_fp, "in gram_job_cancel()\n");

    GRAML_LOCK;

    nexus_mutex_init(&cancel_monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&cancel_monitor.cond, (nexus_condattr_t *) NULL);

    nexus_mutex_lock(&cancel_monitor.mutex);
    cancel_monitor.done = NEXUS_FALSE;
    nexus_mutex_unlock(&cancel_monitor.mutex);

    nexus_endpointattr_init(&epattr);
    nexus_endpointattr_set_handler_table(&epattr,
                                         gram_cancel_handler_table,
                                         1);
    nexus_endpoint_init(&ep, &epattr);
    nexus_endpoint_set_user_pointer(&ep, &cancel_monitor);
    nexus_startpoint_bind(&sp, &ep);

    rc = nexus_attach(job_contact, &sp_to_job_manager);
    if (rc != 0)
    {
        printf("nexus_attach returned %d\n", rc);
	GRAML_UNLOCK;
        return (GRAM_ERROR_PROTOCOL_FAILED);
    }

    size = nexus_sizeof_startpoint(&sp, 1);
    nexus_buffer_init(&buffer, size, 0);
    nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = nexus_send_rsr(&buffer,
                        &sp_to_job_manager,
                        CANCEL_HANDLER_ID,
                        NEXUS_TRUE,
                        NEXUS_FALSE);
    if (rc != 0)
    {
      printf("nexus_send_rsr returned %d\n", rc);
      GRAML_UNLOCK;
      return (GRAM_ERROR_PROTOCOL_FAILED);
    }

    nexus_startpoint_destroy(&sp_to_job_manager);

    nexus_mutex_lock(&cancel_monitor.mutex);
    while (!cancel_monitor.done)
    {
        nexus_cond_wait(&cancel_monitor.cond, &cancel_monitor.mutex);
    }
    nexus_mutex_unlock(&cancel_monitor.mutex);

    nexus_mutex_destroy(&cancel_monitor.mutex);
    nexus_cond_destroy(&cancel_monitor.cond);

    GRAML_UNLOCK;
    return (cancel_monitor.cancel_status);

} /* gram_job_cancel */ 

/******************************************************************************
Function:	graml_cancel_callback_handler()
Description:	
Parameters:
Returns:
******************************************************************************/
static void 
graml_cancel_callback_handler(nexus_endpoint_t * endpoint,
                              nexus_buffer_t * buffer,
                              nexus_bool_t is_non_threaded)
{
    graml_cancel_monitor_s * cancel_monitor;

    cancel_monitor = 
        (graml_cancel_monitor_s *)nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(graml_print_fp, "in graml_cancel_callback_handler()\n");

    nexus_mutex_lock(&cancel_monitor->mutex);
    nexus_get_int(buffer, &cancel_monitor->cancel_status, 1);
    
    cancel_monitor->done = NEXUS_TRUE;
    nexus_cond_signal(&cancel_monitor->cond);
    nexus_mutex_unlock(&cancel_monitor->mutex);

} /* graml_cancel_callback_handler() */

/******************************************************************************
Function:	gram_callback_allow()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
gram_callback_allow(gram_callback_func_t callback_func,
                    void * user_callback_arg,
                    char ** callback_contact)
{
    int			  rc;
    unsigned short 	  port = 0;
    char * 		  host;
    callback_s *	  callback;
    nexus_endpointattr_t  epattr;

    grami_fprintf(graml_print_fp, "in gram_callback_allow()\n");

    GRAML_LOCK;

    callback = (callback_s *) globus_malloc(sizeof(callback_s));
    callback->callback_func = (gram_callback_func_t) callback_func;
    callback->user_callback_arg = user_callback_arg;
    nexus_endpointattr_init(&epattr);
    nexus_endpointattr_set_handler_table(&epattr, callback_handler_table, 1);
    nexus_endpoint_init(&(callback->endpoint), &epattr);
    nexus_endpoint_set_user_pointer(&(callback->endpoint), callback);
    
    rc = nexus_allow_attach(&port, &host,
	     	            graml_callback_attach_approval,
		            (void *) callback);
       
    if (rc != 0)
    {
        printf("nexus_allow_attach returned %d\n", rc);
        return (1);
    }

    /* add 13 for x-nexus stuff plus 1 for the null */
    * callback_contact = (char *) 
       globus_malloc(sizeof(port) + MAXHOSTNAMELEN + 13);

    sprintf(* callback_contact, "x-nexus://%s:%hu/", host, port);

    GRAML_UNLOCK;

    return(0);

} /* gram_callback_allow() */


/******************************************************************************
Function:	graml_callback_attach_approval()
Description:	
Parameters:
Returns:
******************************************************************************/
static int
graml_callback_attach_approval(void * user_arg,
                                   char * url,
                                   nexus_startpoint_t * sp)
{
    callback_s * callback = (callback_s *) user_arg;

    grami_fprintf(graml_print_fp, "in graml_callback_attach_approval()\n");

    nexus_startpoint_bind(sp, &(callback->endpoint));

    return(0);
} /* graml_callback_attach_approval() */

/******************************************************************************
Function:	graml_callback_handler()
Description:	
Parameters:
Returns:
******************************************************************************/
static void 
graml_callback_handler(nexus_endpoint_t * endpoint,
                       nexus_buffer_t * buffer,
                       nexus_bool_t is_non_threaded)
{
    int count;
    int state;
    int errorcode;
    callback_s * callback;
    char job_contact[GRAM_MAX_MSG_SIZE];

    grami_fprintf(graml_print_fp, "in graml_callback_handler()\n");

    callback = (callback_s *) nexus_endpoint_get_user_pointer(endpoint);
    
    nexus_get_int(buffer, &count, 1);
    nexus_get_char(buffer, job_contact, count);
    *(job_contact+count)= '\0';
    nexus_get_int(buffer, &state, 1);
    nexus_get_int(buffer, &errorcode, 1);
    
    (*callback->callback_func)(callback->user_callback_arg, job_contact, state, errorcode);
} /* graml_callback_handler() */

/******************************************************************************
Function:	gram_callback_disallow()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
gram_callback_disallow(char * callback_contact)
{
    int			  rc;
    unsigned short 	  port = 0;
    char * 		  host;

    grami_fprintf(graml_print_fp, "in gram_callback_disallow()\n");

    if (nexus_split_url(callback_contact,
                        &host,
                        &port,
                        NULL) != 0)
    {
        printf(" invalid url.\n");
        return (1);
    }

    nexus_disallow_attach(port);
       
    return(0);

} /* gram_callback_allow() */

/******************************************************************************
Function:	gram_job_start_time()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
gram_job_start_time(char * job_contact,
                    float required_confidence,
                    gram_time_t * estimate,
                    gram_time_t * interval_size)
{
    int                        rc;
    int                        size;
    nexus_buffer_t             buffer;
    nexus_startpoint_t         sp_to_job_manager;
    nexus_startpoint_t         sp;
    nexus_endpoint_t           ep;
    nexus_endpointattr_t       epattr;
    graml_start_time_monitor_s  start_time_monitor;

    grami_fprintf(graml_print_fp, "in gram_job_start_time()\n");

    GRAML_LOCK;

    nexus_mutex_init(&start_time_monitor.mutex, (nexus_mutexattr_t *) NULL);
    nexus_cond_init(&start_time_monitor.cond, (nexus_condattr_t *) NULL);

    nexus_mutex_lock(&start_time_monitor.mutex);
    start_time_monitor.done = NEXUS_FALSE;
    nexus_mutex_unlock(&start_time_monitor.mutex);

    nexus_endpointattr_init(&epattr);
    nexus_endpointattr_set_handler_table(&epattr,
                                         gram_start_time_handler_table,
                                         1);
    nexus_endpoint_init(&ep, &epattr);
    nexus_endpoint_set_user_pointer(&ep, &start_time_monitor);
    nexus_startpoint_bind(&sp, &ep);

    rc = nexus_attach(job_contact, &sp_to_job_manager);
    if (rc != 0)
    {
      printf("nexus_attach returned %d\n", rc);
      GRAML_UNLOCK;
      return (GRAM_ERROR_PROTOCOL_FAILED);
    }

    size  = nexus_sizeof_float(1);
    size += nexus_sizeof_startpoint(&sp, 1);

    nexus_buffer_init(&buffer, size, 0);
    nexus_put_float(&buffer, &required_confidence, 1);
    nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = nexus_send_rsr(&buffer,
                        &sp_to_job_manager,
                        START_TIME_HANDLER_ID,
                        NEXUS_TRUE,
                        NEXUS_FALSE);

    if (rc != 0)
    {
      printf("nexus_send_rsr returned %d\n", rc);
      GRAML_UNLOCK;
      return (GRAM_ERROR_PROTOCOL_FAILED);
    }

    nexus_startpoint_destroy(&sp_to_job_manager);

    nexus_mutex_lock(&start_time_monitor.mutex);
    while (!start_time_monitor.done)
    {
        nexus_cond_wait(&start_time_monitor.cond, &start_time_monitor.mutex);
    }
    nexus_mutex_unlock(&start_time_monitor.mutex);

    nexus_mutex_destroy(&start_time_monitor.mutex);
    nexus_cond_destroy(&start_time_monitor.cond);

    rc = start_time_monitor.start_time_status;
    estimate->dumb_time = start_time_monitor.start_time_estimate;
    interval_size->dumb_time = start_time_monitor.start_time_interval_size;
 
    GRAML_UNLOCK;
    return (rc);

} /* gram_job_start_time() */

/******************************************************************************
Function:	graml_start_time_callback_handler()
Description:	
Parameters:
Returns:
******************************************************************************/
static void 
graml_start_time_callback_handler(nexus_endpoint_t * endpoint,
                                  nexus_buffer_t * buffer,
                                  nexus_bool_t is_non_threaded)
{
    graml_start_time_monitor_s * start_time_monitor;

    start_time_monitor = (graml_start_time_monitor_s *)
                         nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(graml_print_fp, "in graml_start_time_callback_handler()\n");

    nexus_mutex_lock(&start_time_monitor->mutex);

    nexus_get_int(buffer, &start_time_monitor->start_time_status, 1);
    nexus_get_int(buffer, &start_time_monitor->start_time_estimate, 1);
    nexus_get_int(buffer, &start_time_monitor->start_time_interval_size, 1);
    
    start_time_monitor->done = NEXUS_TRUE;
    nexus_cond_signal(&start_time_monitor->cond);
    nexus_mutex_unlock(&start_time_monitor->mutex);

} /* graml_start_time_callback_handler() */

/******************************************************************************
Function:	gram_callback_check()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
gram_callback_check()
{
    grami_fprintf(graml_print_fp, "in gram_callback_check()\n");

    nexus_poll();

    return(0);

} /* gram_callback_check() */

/******************************************************************************
Function:	gram_job_contact_free()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
gram_job_contact_free(char * job_contact)
{
    grami_fprintf(graml_print_fp, "in gram_job_contact_free()\n");

    globus_free(job_contact);

    return (0);
} /* gram_job_contact_free() */
