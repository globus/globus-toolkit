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
#include <globus_io.h>
#include "globus_i_gram_version.h"
#include "globus_gram_client.h"
#include "grami_fprintf.h"
#include "globus_rsl.h"
/*
#include "globus_gram_job_manager.h"
*/
#include "globus_i_gram_handlers.h"
#if defined(TARGET_ARCH_SOLARIS)
#include <netdb.h>
#endif

#ifdef GSS_AUTHENTICATION
#include "globus_gss_assist.h"
#include <gssapi.h>
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
    globus_mutex_t mutex;
    globus_cond_t cond;
    volatile globus_bool_t done;
    int job_status;
} globus_l_status_monitor_t;

typedef struct
{
    globus_mutex_t mutex;
    globus_cond_t cond;
    volatile globus_bool_t done;
    int job_status;
    int register_status;
} globus_l_register_monitor_t;

typedef struct
{
    globus_mutex_t mutex;
    globus_cond_t cond;
    volatile globus_bool_t done;
    int job_status;
    int unregister_status;
} globus_l_unregister_monitor_t;

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
globus_l_job_request_reply_data_handler(void * arg,
					globus_io_handle_t * handle,
					globus_result_t result,
					globus_byte_t * buf,
					globus_size_t nbytes);

static void 
globus_l_callback_handler(globus_nexus_endpoint_t * endpoint,
                          globus_nexus_buffer_t * buffer,
                          globus_bool_t is_non_threaded);

static void 
globus_l_cancel_callback_handler(globus_nexus_endpoint_t * endpoint,
                                 globus_nexus_buffer_t * buffer,
                                 globus_bool_t is_non_threaded);

static void
globus_l_job_status_callback_handler(globus_nexus_endpoint_t * endpoint,
                                     globus_nexus_buffer_t * buffer,
                                     globus_bool_t is_non_threaded);

static void
globus_l_job_callback_register_handler(globus_nexus_endpoint_t * endpoint,
                                       globus_nexus_buffer_t * buffer,
                                       globus_bool_t is_non_threaded);

static void
globus_l_job_callback_unregister_handler(globus_nexus_endpoint_t * endpoint,
                                         globus_nexus_buffer_t * buffer,
                                         globus_bool_t is_non_threaded);

static void 
globus_l_start_time_callback_handler(globus_nexus_endpoint_t * endpoint,
                                     globus_nexus_buffer_t * buffer,
                                     globus_bool_t is_non_threaded);

static int 
globus_l_gram_client_authenticate(char * gatekeeper_url,
                                  int gss_flags,
                                  globus_io_handle_t * gatekeeper_handle,
				  gss_ctx_id_t * pcontext_handle);

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

static globus_nexus_handler_t globus_l_job_status_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
     globus_l_job_status_callback_handler},
};

static globus_nexus_handler_t globus_l_job_register_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
     globus_l_job_callback_register_handler},
};

static globus_nexus_handler_t globus_l_job_unregister_handler_table[] =
{
    {GLOBUS_NEXUS_HANDLER_TYPE_NON_THREADED,
     globus_l_job_callback_unregister_handler},
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

#ifdef GSS_AUTHENTICATION
/*
 * GSSAPI - credential handle for this process
 */
static gss_cred_id_t credential_handle = GSS_C_NO_CREDENTIAL;
#endif

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
    OM_uint32 major_status;
    OM_uint32 minor_status;

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

    /*
     * Get the GSSAPI security credential for this process.
     * we save it in static storage, since it is only
     * done once and can be shared by many threads.
     * with some GSSAPI implementations a prompt to the user
     * may be done from this routine.
     *
     * we will use the assist version of acquire_cred
     */

    major_status = globus_gss_assist_acquire_cred(&minor_status,
                        GSS_C_INITIATE,
                        &credential_handle);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(stderr,
                "gram_init failure:",
                major_status,
                minor_status,
                0);

        return GRAM_ERROR_AUTHORIZATION; /* need better return code */
    }

    return 0;

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

 	/*
     * GSSAPI - cleanup of the credential
     * don't really care about returned status
     */

    if (credential_handle != GSS_C_NO_CREDENTIAL) 
	{
        OM_uint32 minor_status;
        gss_release_cred(&minor_status,
                         &credential_handle);
    }

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
Function:	globus_l_gram_client_authenticate()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_gram_client_authenticate(
    char *                           gatekeeper_url,
    int                              gss_flags,
    globus_io_handle_t *             gatekeeper_handle,
    gss_ctx_id_t *                   pcontext_handle)
{
    globus_io_attr_t             tcp_attr;
    int                          rc;
    globus_result_t              result;
    int                          tmp_version;
    char *                       gatekeeper_host;
    char *                       gatekeeper_princ;
    char * 			 gatekeeper_service = "jobmanager";
    unsigned short               gatekeeper_port = 0;
    char *cp, *sp, *qp, *pp;


    GLOBUS_L_LOCK;

    grami_fprintf(globus_l_print_fp,"in globus_l_gram_client_authenticate()\n");

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
			if ((pp = strchr(sp,'/')))
			{
				*pp++ = '\0';
				gatekeeper_service = pp;
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
        grami_fprintf(globus_l_print_fp, "strdup failed for gatekeeper_url\n");
        GLOBUS_L_UNLOCK;
        return(1);
    }

    /* Connecting to the gatekeeper.
     */

    grami_fprintf(globus_l_print_fp, "Connecting to %s:%d/%s:%s\n",
		  gatekeeper_host, gatekeeper_port, 
		  gatekeeper_service, gatekeeper_princ);

    /* We use globus_io security to authenticate w/ the gatekeeper
     * and wrap the session. */
    globus_io_tcpattr_init(&tcp_attr);

    result = globus_io_attr_set_secure_authentication_mode (
		   &tcp_attr,
		   GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI,
		   /* KARLCZ: fill in credential arg */);
    if ( result != GLOBUS_SUCCESS ) {
      /* KARLCZ: handle failure */
    }

    result = globus_io_attr_set_secure_channel_mode (
		   &tcp_attr,
		   GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP);
    if ( result != GLOBUS_SUCCESS ) {
      /* KARLCZ: handle failure */
    }

    if( (result = globus_io_tcp_connect(
				       gatekeeper_host,
				       gatekeeper_port,
				       &tcp_attr,
				       gatekeeper_handle))
	!= GLOBUS_SUCCESS )
    {
        grami_fprintf(globus_l_print_fp,
              " globus_io_tcp_connect failed.\n");
		free(gatekeeper_host);
	GLOBUS_L_UNLOCK;

	/* KARLCZ: interrogate result to choose the correct error code */
        return (GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED);
    }

    grami_fprintf(globus_l_print_fp,
		  "Authentication/authorization complete\n");

    free(gatekeeper_host);
    GLOBUS_L_UNLOCK;
    return(0);

} /* globus_l_gram_client_authenticate() */


/******************************************************************************
Function:	globus_gram_client_version()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_version(void)
{
    return(GLOBUS_GRAM_PROTOCOL_VERSION);

} /* globus_gram_client_version() */

/******************************************************************************
Function:	globus_gram_client_ping()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_ping(char * gatekeeper_url)
{
    int                  rc;
    globus_io_handle_t   gatekeeper_handle;


	gss_ctx_id_t  context_handle = GSS_C_NO_CONTEXT;
	OM_uint32     minor_status = 0;

    if ((rc = globus_l_gram_client_authenticate(gatekeeper_url,
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
			            GSS_C_GLOBUS_LIMITED_PROXY_FLAG |
#endif
                                    GSS_C_MUTUAL_FLAG,
                                    &gatekeeper_handle,
                                    &context_handle)) != 0)
    {
        if (rc != GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH)
            return(rc);
    }

    globus_io_close(&gatekeeper_handle);

    return(0);

} /* globus_gram_client_ping() */


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
    int                             size;
    int                             count;
    int                             rc;
    globus_io_handle_t              gatekeeper_handle;
    globus_byte_t *                 request_buffer;
    int                             request_buffer_size;
    globus_l_job_request_monitor_t  job_request_monitor;
    gss_ctx_id_t                    context_handle = GSS_C_NO_CONTEXT;

    grami_fprintf(globus_l_print_fp, "in globus_gram_client_job_request()\n");

    if (strlen(description) <= 0)
    {
        return(GLOBUS_GRAM_CLIENT_ERROR_ZERO_LENGTH_RSL);
    }

    /*
    * we will use the globus_io functions.
    * Since this is user to the gatekeeper, we want delegation
    * if possible. We specify the services we would like,
    * mutual authentication, delegation.
    * We might also want sequence, and integraty.
    * 
    */

    globus_mutex_init(&job_request_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&job_request_monitor.cond, (globus_condattr_t *) NULL);
    job_request_monitor.done = GLOBUS_FALSE;
    job_request_monitor.read_nbytes = 0;
    job_request_monitor.read_buffer = globus_malloc (
					     sizeof(globus_byte_t)
					     * KARLCZ_MAX_MESSAGE_SIZE);

    if ((rc = globus_l_gram_client_authenticate(
		  gatekeeper_url,
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
                  GSS_C_GLOBUS_LIMITED_PROXY_FLAG |
                  GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
#endif
                  GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG,
                  &gatekeeper_handle,
	          &context_handle)) != 0)
    {
      goto globus_l_gram_client_job_request_authenticate_error;
    }

    
    globus_io_register_read (&gatekeeper_handle,
			     job_request_monitor.read_buf 
			     + job_request_monitor.read_nbytes,
			     KARLCZ_MAX_MESSAGE_SIZE
			     - job_request_monitor.read_nbytes,
			     1 /* deliver immediately */,
			     0 /* flags ? */,
			     globus_l_gram_request_reply_data_handler,
			     (void *) & job_request_monitor);

    GLOBUS_L_LOCK;

    rc = globus_l_gram_pack_http_job_request (
		       &request_buffer,
		       &request_buffer_size,
		       description /* user's RSL */,
		       job_state_mask /* integer */,
		       callback_url /* user's state listener URL */);
    if (rc != GLOBUS_SUCCESS) {
      goto globus_l_gram_client_job_request_pack_error;
    }

    {
      int bytes_written;

      rc = globus_io_write (&gatekeeper_handle,
			    request_buffer,
			    request_buffer_size,
			    0 /* no flags? */,
			    &bytes_written);
      if (rc != GLOBUS_SUCCESS) {
	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	goto globusl_gram_client_job_request_write_error;
      }

      assert (bytes_written==request_buffer_size);
    }     

    globus_mutex_lock(&job_request_monitor.mutex);
    while (!job_request_monitor.done)
    {
         globus_cond_wait(&job_request_monitor.cond,
			  &job_request_monitor.mutex);
    }
    globus_mutex_unlock(&job_request_monitor.mutex);

    globus_mutex_destroy(&job_request_monitor.mutex);
    globus_cond_destroy(&job_request_monitor.cond);

    if ( (job_request_monitor.job_status == 0)
	 && (job_contact != NULL) )
    {
      * job_contact = globus_libc_strdup (job_request_monitor.job_contact_str);
    }

    globus_io_close(&gatekeeper_handle);

    GLOBUS_L_UNLOCK;
    return(job_request_monitor.job_status);


 globus_l_gram_client_job_request_send_error:
    globus_free (request_buffer);

 globus_l_gram_client_job_request_pack_error:
    globus_io_close (&gatekeeper_handle);
    GLOBUS_L_UNLOCK;

 globus_l_gram_client_job_request_authenticate_error:
    globus_free (job_request_monitor.read_buffer);
    globus_mutex_destroy(&job_request_monitor.mutex);
    globus_cond_destroy(&job_request_monitor.cond);
    
    return rc;
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
globus_l_job_request_reply_data_handler(
		void *               job_request_reply_monitor_vp,
		globus_io_handle_t * gatekeeper_handle,
		globus_result_t      read_result,
		globus_byte_t *      buffer,
		globus_size_t        nbytes)
					
{
    globus_l_job_request_monitor_t * job_request_monitor;

    job_request_monitor = ((globus_l_job_request_monitor_t * )
                           job_request_reply_monitor_vp);
    assert (job_request_monitor!=NULL);

    globus_mutex_lock (&(job_request_monitor.mutex));

    job_request_monitor.read_nbytes += nbytes;

    if ( KARLCZ_message_complete ) {
      job_request_monitor.status = KARLCZ_http_status;
      job_request_monitor.job_contact_str = KARLCZ_http_job_contact;

      job_request_monitor.read_nbytes = 0;
      job_request_monitor.done = GLOBUS_TRUE;
      globus_cond_broadcast (&(job_request_monitor.mutex));
    }
    else {
      /* message incomplete,
       * register to read more data as it arrives */
      globus_io_register_read (&gatekeeper_handle,
			       job_request_monitor.read_buffer 
			       + job_request_monitor.read_nbytes,
			       KARLCZ_MAX_MESSAGE_SIZE
			       - job_request_monitor.read_nbytes,
			       1 /* deliver immediately */,
			       0 /* flags ? */,
			       globus_l_gram_request_reply_data_handler,
			       (void *) & job_request_monitor);
    }

    globus_mutex_unlock (&(job_request_monitor.mutex));
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
    cancel_monitor.done = GLOBUS_FALSE;

    /* KARLCZ: globus_io connect w/ security to URL in job_contact
     * use cancel_monitor.handle */



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
globus_l_cancel_callback_handler()
{
    globus_l_cancel_monitor_t * cancel_monitor;

    cancel_monitor = ((globus_l_cancel_monitor_t * )
		      cancel_monitor_vp);
    assert (cancel_monitor!=NULL);

    globus_mutex_lock (&(cancel_monitor.mutex));

    cancel_monitor.read_nbytes += nbytes;

    if ( KARLCZ_message_complete ) {
      cancel_monitor.status = KARLCZ_http_status;
      cancel_monitor.done = GLOBUS_TRUE;
      globus_cond_broadcast (&(_monitor.mutex));
    }
    else {
      /* message incomplete,
       * register to read more data as it arrives */
      globus_io_register_read (&(cancel_monitor.handle),
			       cancel_monitor.read_buffer 
			       + cancel_monitor.read_nbytes,
			       KARLCZ_MAX_MESSAGE_SIZE
			       - cancel_monitor.read_nbytes,
			       1 /* deliver immediately */,
			       0 /* flags ? */,
			       globus_l_cancel_callback_handler,
			       (void *) cancel_monitor);
    }

    globus_mutex_unlock (&(cancel_monitor.mutex));
} /* globus_l_cancel_callback_handler() */


/******************************************************************************
Function:       globus_gram_client_job_status()
Description:    sending cancel request to job manager
Parameters:
Returns:
******************************************************************************/
int
globus_gram_client_job_status(char * job_contact,
                              int  * job_status,
                              int  * failure_code)
{

} /* globus_gram_client_job_status */


/******************************************************************************
Function:       globus_l_job_status_callback_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_job_status_callback_handler(globus_nexus_endpoint_t * endpoint,
                                     globus_nexus_buffer_t * buffer,
                                     globus_bool_t is_non_threaded)
{

} /* globus_l_job_status_callback_handler() */


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
Function:	globus_gram_client_job_callback_register()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_callback_register(char * job_contact,
                                         const int job_state_mask,
                                         const char * callback_contact,
                                         int * job_status,
                                         int * failure_code)
{

} /* globus_gram_client_job_callback_register() */


/******************************************************************************
Function:       globus_l_job_callback_register_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_job_callback_register_handler(globus_nexus_endpoint_t * endpoint,
                                       globus_nexus_buffer_t * buffer,
                                       globus_bool_t is_non_threaded)
{

} /* globus_l_job_callback_register_handler() */


/******************************************************************************
Function:	globus_gram_client_job_callback_unregister()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_callback_unregister(char * job_contact,
                                           const char * callback_contact,
                                           int * job_status,
                                           int * failure_code)
{

} /* globus_gram_client_job_callback_unregister() */


/******************************************************************************
Function:       globus_l_job_callback_unregister_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_job_callback_unregister_handler(globus_nexus_endpoint_t * endpoint,
                                         globus_nexus_buffer_t * buffer,
                                         globus_bool_t is_non_threaded)
{

} /* globus_l_job_callback_unregister_handler() */


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
