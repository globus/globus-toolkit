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
                                  int * gatekeeper_fd);

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
globus_l_gram_client_authenticate(char * gatekeeper_url,
                                  int gss_flags,
                                  int * gatekeeper_fd)
{
    int                          rc;
    globus_byte_t                tmp_version;
    char *                       gatekeeper_host;
    char *                       gatekeeper_princ;
    unsigned short               gatekeeper_port = 0;
    char *                       auth_msg_buf;
    size_t                       auth_msg_buf_size;
    /* GSSAPI assist variables */
    OM_uint32                    major_status = 0;
    OM_uint32                    minor_status = 0;
    int                          token_status = 0;
    OM_uint32                    ret_flags = 0;
    gss_ctx_id_t                 context_handle = GSS_C_NO_CONTEXT;
    char *cp, *sp, *qp;


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

    grami_fprintf(globus_l_print_fp, "Connecting to %s:%d:%s\n",
		  gatekeeper_host, gatekeeper_port, gatekeeper_princ);

    rc = globus_nexus_fd_connect(gatekeeper_host,
				 gatekeeper_port,
				 gatekeeper_fd);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
              " globus_nexus_fd_connect failed.  rc = %d\n", rc);
	GLOBUS_L_UNLOCK;
        return (GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED);
    }

#ifdef GSS_AUTHENTICATION
    /*
     * Now that TCP connection established, use the connection
     * to do the GSSAPI authentication to the gatekeeper
     * we will use the assist functions.
     * Since this is user to the gatekeeper, we want delegation
     * if possible. We specify the services we would like,
     * mutual authentication, delegation.
     * We might also want sequence, and integraty.
     */


    grami_fprintf(globus_l_print_fp,
		  "Starting authentication to %s\n", gatekeeper_princ);

    major_status = globus_gss_assist_init_sec_context(&minor_status,
                    credential_handle,
                    &context_handle,
                    gatekeeper_princ,
                    gss_flags,
                    &ret_flags,
                    &token_status,
                    globus_gss_assist_token_get_nexus,
                    (void *) gatekeeper_fd,
                    globus_gss_assist_token_send_nexus,
                    (void *) gatekeeper_fd);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status(stderr,
                    "GSS Authentication failure:globus_gram_client\n ",
                     major_status,
                     minor_status,
                     token_status);

        globus_nexus_fd_close(*gatekeeper_fd);
        GLOBUS_L_UNLOCK;
        return (GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION);
    }

    /* We still have the GSSAPI context setup and could use
     * some of the other routines, such as get_mic, verify_mic
     * at this point. But in this client we don't.
     * But we need to do the gss_delete_sec_context
     * sometime before returning from this module.
     */

     gss_delete_sec_context(&minor_status,
            &context_handle,
            GSS_C_NO_BUFFER);

    /*
     * Use the token_get routine to read a final status
     * message from the gatekeeper after the GSSAPI
     * authentication has completed. This is done
     * since authorization is done outside of GSSAPI.
     */

    if (globus_gss_assist_token_get_nexus((void *) gatekeeper_fd,
				  (void **) &auth_msg_buf, &auth_msg_buf_size))
    {
        grami_fprintf(globus_l_print_fp,
	      "Authorization message not received");
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION);
    }

    if (auth_msg_buf_size > 1 )
    { 
        grami_fprintf(globus_l_print_fp,
              "authorization buffer = %s\n", auth_msg_buf);
	globus_nexus_fd_close(*gatekeeper_fd);
	GLOBUS_L_UNLOCK;

        if (strncmp(auth_msg_buf, "ERROR: gatekeeper misconfigured", 31) == 0)
        {
	    return (GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED);
        }
        else
        {
	    return (GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION);
        }
    }
    else
    {
        tmp_version =  *auth_msg_buf;
        if (tmp_version != GLOBUS_GRAM_PROTOCOL_VERSION)
        {
            return (GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH);
        }
    }

    grami_fprintf(globus_l_print_fp,
		  "Authentication/authorization complete\n");

#else
    grami_fprintf(globus_l_print_fp,
		  "WARNING: No authentication performed\n");
#endif /* GSS_AUTHENTICATION */

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
    int rc;
    int gatekeeper_fd;

    if ((rc = globus_l_gram_client_authenticate(gatekeeper_url,
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
									GSS_C_GLOBUS_LIMITED_PROXY_FLAG |
#endif
                                    GSS_C_MUTUAL_FLAG,
                                    &gatekeeper_fd)) != 0)
    {
        if (rc != GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH)
            return(rc);
    }

    globus_nexus_fd_close(gatekeeper_fd);

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
    int                             contact_msg_size;
    int                             count;
    int                             rc;
    int                             gatekeeper_fd;
    globus_byte_t                   type;
    globus_byte_t *                 contact_msg_buffer;
    globus_byte_t *                 tmp_buffer;
    globus_nexus_endpointattr_t     reply_epattr;
    globus_nexus_endpoint_t         reply_ep;
    globus_nexus_startpoint_t       reply_sp;
    globus_l_job_request_monitor_t  job_request_monitor;


    grami_fprintf(globus_l_print_fp, "in globus_gram_client_job_request()\n");

    if (strlen(description) <= 0)
    {
        return(GLOBUS_GRAM_CLIENT_ERROR_ZERO_LENGTH_RSL);
    }

    /*
    * we will use the assist functions.
    * Since this is user to the gatekeeper, we want delegation
    * if possible. We specify the services we would like,
    * mutual authentication, delegation.
    * We might also want sequence, and integraty.
    * 
    * As a gram client, we will be delegating our proxy
    * to a foreign site, and want to limit its usefullness
    * in order to abide by the Globus security policy. 
    * Gatekeepers are set up to not accept a limited proxy
    * for authentication. 
    * We also only want to authenticate to real gatekeepers
    * not to limited proxy gatekeepers too. 
    */
    if ((rc = globus_l_gram_client_authenticate(gatekeeper_url,
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
       GSS_C_GLOBUS_LIMITED_PROXY_FLAG |
       GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
#endif
       GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG,
    &gatekeeper_fd)) != 0)
    {
        return(rc);
    }

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
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_char(strlen(description));
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_int(1);
    if (callback_url)
    {
        size += globus_nexus_sizeof_char(strlen(callback_url));
    }
    size += globus_nexus_sizeof_startpoint(&reply_sp, 1);

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
     * Put 4-byte big-endian unsigned integer into front of message,
     * this is the size of the message to be peeled off by the gatekeeper
     */
    *tmp_buffer++ = (globus_byte_t) (((size) & 0xFF000000) >> 24);
    *tmp_buffer++ = (globus_byte_t) (((size) & 0xFF0000) >> 16);
    *tmp_buffer++ = (globus_byte_t) (((size) & 0xFF00) >> 8);
    *tmp_buffer++ = (globus_byte_t)  ((size) & 0xFF);

    /*
     * Pack the rest of the message that goes to the gram_job_manager
     */
    *tmp_buffer++ = (globus_byte_t) type;
    globus_nexus_user_put_int(&tmp_buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
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

    rc = globus_nexus_fd_register_for_write(gatekeeper_fd,
                                           (char *) contact_msg_buffer,
                                           contact_msg_size,
                                           globus_l_write_callback,
                                           globus_l_write_error_callback,
                                           (void *) &job_request_monitor);

    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_fd_register_for_write returned %d\n", rc);
        globus_nexus_fd_close(gatekeeper_fd);
        GLOBUS_L_UNLOCK;
        return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
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
    int               gram_version;
    globus_byte_t     bformat;
    globus_byte_t *   ptr;
    globus_l_job_request_monitor_t * job_request_monitor;

    job_request_monitor = (globus_l_job_request_monitor_t * )
                           globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_job_request_reply_handler()\n");

    globus_mutex_lock(&job_request_monitor->mutex);

    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
       job_request_monitor->job_status = 
             GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else
    {

        globus_nexus_get_int(buffer, &(job_request_monitor->job_status), 1);

        if (job_request_monitor->job_status == 0)
        {
            globus_nexus_get_int(buffer, &count, 1);
            globus_nexus_get_char(buffer,
                                  job_request_monitor->job_contact_str,
                                  count);
        }
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
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_attach returned %d\n", rc);

	GLOBUS_L_UNLOCK;

        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER);
        }
        else if (rc == GLOBUS_NEXUS_ERROR_BAD_URL)
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT);
        }
        else
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
        }
    }

    size =  globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_startpoint(&sp, 1);
    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_int(&buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = globus_nexus_send_rsr(&buffer,
			       &sp_to_job_manager,
			       GLOBUS_I_GRAM_JOB_MANAGER_CANCEL_HANDLER_ID,
			       GLOBUS_TRUE,
			       GLOBUS_FALSE);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_attach returned %d\n", rc);
	GLOBUS_L_UNLOCK;
        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER);
        }
        else
        {
            return(GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
        }
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
    int gram_version;
    globus_l_cancel_monitor_t * cancel_monitor;

    cancel_monitor = 
        (globus_l_cancel_monitor_t *)
	globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_cancel_callback_handler()\n");

    globus_mutex_lock(&cancel_monitor->mutex);
    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        cancel_monitor->cancel_status = 
             GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else
    {
        globus_nexus_get_int(buffer, &cancel_monitor->cancel_status, 1);
    }
    
    cancel_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&cancel_monitor->cond);
    globus_mutex_unlock(&cancel_monitor->mutex);

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
    int                             rc;
    int                             size;
    globus_nexus_buffer_t           buffer;
    globus_nexus_startpoint_t       sp_to_job_manager;
    globus_nexus_startpoint_t       sp;
    globus_nexus_endpoint_t         ep;
    globus_nexus_endpointattr_t     epattr;
    globus_l_status_monitor_t       status_monitor;

    grami_fprintf(globus_l_print_fp, "in globus_gram_client_job_status()\n");

    GLOBUS_L_LOCK;

    globus_mutex_init(&status_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&status_monitor.cond, (globus_condattr_t *) NULL);

    globus_mutex_lock(&status_monitor.mutex);
    status_monitor.done = GLOBUS_FALSE;
    globus_mutex_unlock(&status_monitor.mutex);

    globus_nexus_endpointattr_init(&epattr);
    globus_nexus_endpointattr_set_handler_table(&epattr,
                                        globus_l_job_status_handler_table,
                                        1);
    globus_nexus_endpoint_init(&ep, &epattr);
    globus_nexus_endpoint_set_user_pointer(&ep, &status_monitor);
    globus_nexus_startpoint_bind(&sp, &ep);

    rc = globus_nexus_attach(job_contact, &sp_to_job_manager);

    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
               "globus_nexus_attach returned %d\n", rc);

        GLOBUS_L_UNLOCK;

        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER;
        }
        else if (rc == GLOBUS_NEXUS_ERROR_BAD_URL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
        }
        else
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
        }

        *job_status = 0;
        return(GLOBUS_FAILURE);
    }

    size =  globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_startpoint(&sp, 1);
    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_int(&buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = globus_nexus_send_rsr(&buffer,
                               &sp_to_job_manager,
                               GLOBUS_I_GRAM_JOB_MANAGER_STATUS_HANDLER_ID,
                               GLOBUS_TRUE,
                               GLOBUS_FALSE);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
               "globus_nexus_attach returned %d\n", rc);
        GLOBUS_L_UNLOCK;
        
        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER;
        }
        else
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
        }

        *job_status = 0;
        return(GLOBUS_FAILURE);
    }

    globus_nexus_startpoint_destroy(&sp_to_job_manager);

    globus_mutex_lock(&status_monitor.mutex);
    while (!status_monitor.done)
    {
        globus_cond_wait(&status_monitor.cond, &status_monitor.mutex);
    }
    globus_mutex_unlock(&status_monitor.mutex);

    globus_mutex_destroy(&status_monitor.mutex);
    globus_cond_destroy(&status_monitor.cond);

    GLOBUS_L_UNLOCK;
    *failure_code = 0;
    *job_status = status_monitor.job_status;
    return(GLOBUS_SUCCESS);

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
    int gram_version;
    globus_l_status_monitor_t * status_monitor;

    status_monitor = (globus_l_status_monitor_t *)
        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
                  "in globus_l_job_status_callback_handler()\n");

    globus_mutex_lock(&status_monitor->mutex);
    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        status_monitor->job_status =
             GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else
    {
        globus_nexus_get_int(buffer, &status_monitor->job_status, 1);
    }

    status_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&status_monitor->cond);
    globus_mutex_unlock(&status_monitor->mutex);

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
        grami_fprintf(globus_l_print_fp, 
              "globus_nexus_allow_attach returned %d\n", rc);
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
Function:	globus_gram_client_job_callback_register()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_callback_register(char * job_contact,
                                         const char * callback_contact,
                                         int job_state_mask,
                                         int * job_status,
                                         int * failure_code)
{
    int                             rc;
    int                             size;
    int                             count;
    globus_nexus_buffer_t           buffer;
    globus_nexus_startpoint_t       sp_to_job_manager;
    globus_nexus_startpoint_t       sp;
    globus_nexus_endpoint_t         ep;
    globus_nexus_endpointattr_t     epattr;
    globus_l_register_monitor_t     register_monitor;

    grami_fprintf(globus_l_print_fp,
                  "in globus_gram_client_job_callback_register()\n");

    GLOBUS_L_LOCK;

    globus_mutex_init(&register_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&register_monitor.cond, (globus_condattr_t *) NULL);

    globus_mutex_lock(&register_monitor.mutex);
    register_monitor.done = GLOBUS_FALSE;
    globus_mutex_unlock(&register_monitor.mutex);

    globus_nexus_endpointattr_init(&epattr);
    globus_nexus_endpointattr_set_handler_table(&epattr,
					globus_l_job_register_handler_table,
					1);
    globus_nexus_endpoint_init(&ep, &epattr);
    globus_nexus_endpoint_set_user_pointer(&ep, &register_monitor);
    globus_nexus_startpoint_bind(&sp, &ep);

    rc = globus_nexus_attach(job_contact, &sp_to_job_manager);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_attach returned %d\n", rc);

	GLOBUS_L_UNLOCK;

        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER;
        }
        else if (rc == GLOBUS_NEXUS_ERROR_BAD_URL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
        }
        else
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
        }

        *job_status = 0;
        return(GLOBUS_FAILURE);
    }

    count= strlen(callback_contact);

    size =  globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_startpoint(&sp, 1);
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_char(count);
    size += globus_nexus_sizeof_int(1);

    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_int(&buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    globus_nexus_put_int(&buffer, &count, 1);
    globus_nexus_put_char(&buffer, (char *) callback_contact, count);
    globus_nexus_put_int(&buffer, &job_state_mask, 1);

    rc = globus_nexus_send_rsr(&buffer,
			       &sp_to_job_manager,
			       GLOBUS_I_GRAM_JOB_MANAGER_REGISTER_HANDLER_ID,
			       GLOBUS_TRUE,
			       GLOBUS_FALSE);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_send_rsr returned %d\n", rc);
	GLOBUS_L_UNLOCK;

        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER;
        }
        else
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
        }

        *job_status = 0;
        return(GLOBUS_FAILURE);
    }

    globus_nexus_startpoint_destroy(&sp_to_job_manager);

    globus_mutex_lock(&register_monitor.mutex);
    while (!register_monitor.done)
    {
        globus_cond_wait(&register_monitor.cond, &register_monitor.mutex);
    }
    globus_mutex_unlock(&register_monitor.mutex);

    globus_mutex_destroy(&register_monitor.mutex);
    globus_cond_destroy(&register_monitor.cond);

    GLOBUS_L_UNLOCK;
    if (register_monitor.register_status == GLOBUS_SUCCESS)
    {
        *job_status = register_monitor.job_status;
        *failure_code = 0;
        return (GLOBUS_SUCCESS);
    }
    else
    {
        *job_status = 0;
        *failure_code = register_monitor.register_status;
        return (GLOBUS_FAILURE);
    }

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
    int gram_version;
    globus_l_register_monitor_t * register_monitor;

    register_monitor = (globus_l_register_monitor_t *)
        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
                  "in globus_l_job_callback_register_handler()\n");

    globus_mutex_lock(&register_monitor->mutex);
    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        register_monitor->register_status =
             GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else
    {
        globus_nexus_get_int(buffer, &register_monitor->job_status, 1);
        globus_nexus_get_int(buffer, &register_monitor->register_status, 1);
    }

    register_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&register_monitor->cond);
    globus_mutex_unlock(&register_monitor->mutex);

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
    int                             rc;
    int                             size;
    int                             count;
    globus_nexus_buffer_t           buffer;
    globus_nexus_startpoint_t       sp_to_job_manager;
    globus_nexus_startpoint_t       sp;
    globus_nexus_endpoint_t         ep;
    globus_nexus_endpointattr_t     epattr;
    globus_l_unregister_monitor_t   unregister_monitor;

    grami_fprintf(globus_l_print_fp,
                  "in globus_gram_client_job_callback_unregister()\n");

    GLOBUS_L_LOCK;

    globus_mutex_init(&unregister_monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&unregister_monitor.cond, (globus_condattr_t *) NULL);

    globus_mutex_lock(&unregister_monitor.mutex);
    unregister_monitor.done = GLOBUS_FALSE;
    globus_mutex_unlock(&unregister_monitor.mutex);

    globus_nexus_endpointattr_init(&epattr);
    globus_nexus_endpointattr_set_handler_table(&epattr,
					globus_l_job_unregister_handler_table,
					1);
    globus_nexus_endpoint_init(&ep, &epattr);
    globus_nexus_endpoint_set_user_pointer(&ep, &unregister_monitor);
    globus_nexus_startpoint_bind(&sp, &ep);

    rc = globus_nexus_attach(job_contact, &sp_to_job_manager);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_attach returned %d\n", rc);

	GLOBUS_L_UNLOCK;

        *job_status = 0;

        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER;
        }
        else if (rc == GLOBUS_NEXUS_ERROR_BAD_URL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
        }
        else
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
        }

        return(GLOBUS_FAILURE);
    }

    count= strlen(callback_contact);

    size =  globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_startpoint(&sp, 1);
    size += globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_char(count);

    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_int(&buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    globus_nexus_put_int(&buffer, &count, 1);
    globus_nexus_put_char(&buffer, (char *) callback_contact, count);

    rc = globus_nexus_send_rsr(&buffer,
			       &sp_to_job_manager,
			       GLOBUS_I_GRAM_JOB_MANAGER_UNREGISTER_HANDLER_ID,
			       GLOBUS_TRUE,
			       GLOBUS_FALSE);
    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_send_rsr returned %d\n", rc);

	GLOBUS_L_UNLOCK;

        *job_status = 0;

        if (rc == GLOBUS_NEXUS_ERROR_CONNECT_FAILED ||
            rc == GLOBUS_NEXUS_ERROR_BAD_PROTOCOL)
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER;
        }
        else
        {
            *failure_code=GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
        }

        return(GLOBUS_FAILURE);
    }

    globus_nexus_startpoint_destroy(&sp_to_job_manager);

    globus_mutex_lock(&unregister_monitor.mutex);
    while (!unregister_monitor.done)
    {
        globus_cond_wait(&unregister_monitor.cond, &unregister_monitor.mutex);
    }
    globus_mutex_unlock(&unregister_monitor.mutex);

    globus_mutex_destroy(&unregister_monitor.mutex);
    globus_cond_destroy(&unregister_monitor.cond);

    GLOBUS_L_UNLOCK;
    if (unregister_monitor.unregister_status == GLOBUS_SUCCESS)
    {
        *job_status = unregister_monitor.job_status;
        *failure_code = 0;
        return (GLOBUS_SUCCESS);
    }
    else
    {
        *job_status = 0;
        *failure_code = unregister_monitor.unregister_status;
        return (GLOBUS_FAILURE);
    }

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
    int gram_version;
    globus_l_unregister_monitor_t * unregister_monitor;

    unregister_monitor = (globus_l_unregister_monitor_t *)
        globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
                  "in globus_l_job_callback_unregister_handler()\n");

    globus_mutex_lock(&unregister_monitor->mutex);
    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        unregister_monitor->unregister_status =
             GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else
    {
        globus_nexus_get_int(buffer, &unregister_monitor->job_status, 1);
        globus_nexus_get_int(buffer, &unregister_monitor->unregister_status, 1);
    }

    unregister_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&unregister_monitor->cond);
    globus_mutex_unlock(&unregister_monitor->mutex);

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
    int gram_version;
    int count;
    int state;
    int errorcode;
    globus_l_callback_t * callback;
    char job_contact[GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE];

    grami_fprintf(globus_l_print_fp, "in globus_l_callback_handler()\n");

    callback = (globus_l_callback_t *)
	globus_nexus_endpoint_get_user_pointer(endpoint);
    
    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        strcpy(job_contact, "ERROR: globus gram version mismatch");
        state = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
        errorcode = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
    }
    else
    {
        globus_nexus_get_int(buffer, &count, 1);
        globus_nexus_get_char(buffer, job_contact, count);
        *(job_contact+count)= '\0';
        globus_nexus_get_int(buffer, &state, 1);
        globus_nexus_get_int(buffer, &errorcode, 1);
    }
    
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

    if (callback_contact == NULL)
    {
        grami_fprintf(globus_l_print_fp, "ERROR: NULL contact URL.\n");
        return (1);
    }

    grami_fprintf(globus_l_print_fp,
          "in globus_gram_client_callback_disallow()\n");

    if (globus_nexus_split_url(callback_contact,
			       &host,
			       &port,
			       NULL) != 0)
    {
        grami_fprintf(globus_l_print_fp, "ERROR: invalid contact url.\n");
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
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_attach returned %d\n", rc);
	GLOBUS_L_UNLOCK;
	return (GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    size  = globus_nexus_sizeof_int(1);
    size += globus_nexus_sizeof_float(1);
    size += globus_nexus_sizeof_startpoint(&sp, 1);

    globus_nexus_buffer_init(&buffer, size, 0);
    globus_nexus_put_int(&buffer, &GLOBUS_GRAM_PROTOCOL_VERSION, 1);
    globus_nexus_put_float(&buffer, &required_confidence, 1);
    globus_nexus_put_startpoint_transfer(&buffer, &sp, 1);

    rc = globus_nexus_send_rsr(&buffer,
			       &sp_to_job_manager,
			       GLOBUS_I_GRAM_JOB_MANAGER_START_TIME_HANDLER_ID,
			       GLOBUS_TRUE,
			       GLOBUS_FALSE);

    if (rc != 0)
    {
        grami_fprintf(globus_l_print_fp,
	       "globus_nexus_send_rsr returned %d\n", rc);
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
    int gram_version;
    globus_l_start_time_monitor_t * start_time_monitor;

    start_time_monitor = (globus_l_start_time_monitor_t *)
                         globus_nexus_endpoint_get_user_pointer(endpoint);

    grami_fprintf(globus_l_print_fp,
		  "in globus_l_start_time_callback_handler()\n");

    globus_mutex_lock(&start_time_monitor->mutex);

    globus_nexus_get_int(buffer, &gram_version, 1);
    if (gram_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        start_time_monitor->start_time_status = 
            GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
        start_time_monitor->start_time_estimate = 0;
        start_time_monitor->start_time_interval_size = 0;
    }
    else
    {
        globus_nexus_get_int(buffer,
                             &start_time_monitor->start_time_status, 1);
        globus_nexus_get_int(buffer, 
                             &start_time_monitor->start_time_estimate, 1);
        globus_nexus_get_int(buffer,
			     &start_time_monitor->start_time_interval_size, 1);
    }
    
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
