
/*****************************************************************************
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

/*****************************************************************************
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

#include "globus_i_gram_http.h"

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct
{
    globus_mutex_t           mutex;
    globus_cond_t            cond;
    volatile globus_bool_t   done;
    int                      job_status;
    char                     job_contact_str[1000];
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
    globus_mutex_t         mutex;
    globus_cond_t          cond;
    volatile globus_bool_t done;
    int                    cancel_status;
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
globus_l_job_request_reply_data_handler(void * arg,
					globus_io_handle_t * handle,
					globus_result_t result,
					globus_byte_t * buf,
					globus_size_t nbytes);

static int 
globus_l_gram_client_authenticate(
    char *                                 gatekeeper_url,
    globus_io_secure_delegation_mode_t     delegation_mode,
    globus_io_handle_t *                   gatekeeper_handle );

/******************************************************************************
                       Define module specific variables
******************************************************************************/
globus_module_descriptor_t globus_gram_client_module = {
    "globus_gram_client",
    globus_i_gram_client_activate,
    globus_i_gram_client_deactivate,
    GLOBUS_NULL
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

    rc = globus_module_activate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    
    #if GRAM_GOES_HTTP
    {
	rc = globus_gram_http_activate();
	if (rc != GLOBUS_SUCCESS)
	    return(rc);
    }
    #endif

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

    globus_gram_client_debug();
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
    
    #if GRAM_GOES_HTTP
    {
	rc = globus_gram_http_deactivate();
	if (rc != GLOBUS_SUCCESS)
	    return(rc);
    }
    #endif

    rc = globus_module_deactivate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
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
    char *                                 gatekeeper_url,
    globus_io_secure_delegation_mode_t     delegation_mode,
    globus_io_attr_t *                     attrp)
{
  globus_result_t                        res;
  globus_io_secure_authorization_data_t  auth_data;
  char *                                 gatekeeper_host;
  char *                                 gatekeeper_princ;
  char *                                 gatekeeper_service = "jobmanager";

  if ((cp = strdup(gatekeeper_url))) {
    gatekeeper_host = gatekeeper_princ = cp;
    if ((sp = strchr(cp,':'))) {
      *sp++ = '\0';
      if ((qp = strchr(sp, ':'))) {
	*qp++ = '\0';
	gatekeeper_princ = qp;
      }
 
      /*** TODO: this is wrong: the service is optional ***/
 
      if ((pp = strchr(sp,'/'))) {
	*pp++ = '\0';
	gatekeeper_service = pp;
      }
      gatekeeper_port = atoi(sp);
    }
    else {
      gatekeeper_port = 754;
    }
  } 
  else {
    grami_fprintf(globus_l_print_fp, "strdup failed for gatekeeper_url\n");
    GLOBUS_L_UNLOCK;
    return(1);
  }

  if ( (res = globus_io_tcpattr_init(attrp))
       || (res = globus_io_secure_authorization_data_initialize(
			     &auth_data))
       || (res = globus_io_attr_set_secure_authentication_mode(
			     attrp,
			     GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI,
			     GSS_C_NO_CREDENTIAL))
       || (res = globus_io_secure_authorization_data_set_identity(
			     &auth_data,
			     gatekeeper_princ))
       || (res = globus_io_attr_set_secure_authorization_mode(
		             attrp,
			     GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY,
			     &auth_data))
       || (res = globus_io_attr_set_secure_delegation_mode(
			     attrp,
			     delegation_mode))
       || (res = globus_io_attr_set_secure_channel_mode(
			     attrp,
			     GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP)) ) {
    globus_object_t *  err = globus_error_get(res);
    
    grami_fprintf(globus_l_print_fp, 
		  "setting up IO attributes failed\n");
    
    /* TODO: interrogate 'err' to choose the correct error code */
    
    globus_object_free(err);
    GLOBUS_L_UNLOCK;
    return GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED;
  }

  return GLOBUS_SUCCESS;
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
  int                          rc;
  globus_io_attr_t             attr;
  char                         query[GLOBUS_GRAM_HTTP_BUFSIZE];
  globus_gram_http_monitor_t   monitor;
  globus_size_t                querysize;

  if ( rc = globus_l_gram_client_authenticate( 
                   gatekeeper_url,
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
		   GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY,
#else
		   GLOBUS_IO_SECURE_DELEGATION_MODE_NO_PROXY,
#endif
		   &attr) ) {
    goto globus_gram_client_ping_authenticate_failed;
  }

  querysize = 0;

  globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
  globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
  monitor.done = GLOBUS_FALSE;

  /* TODO: pass attr into this */
  if ( rc = globus_gram_http_post_and_get(
				     gatekeeper_url,
				     (globus_byte_t *) query,
				     &querysize,
				     &monitor) ) {
    goto globus_gram_client_ping_post_failed;
  }

  globus_mutex_lock(&monitor.mutex);
  while (!monitor.done) {
    globus_cond_wait(&monitor.cond, &monitor.mutex);
  }
  rc = monitor.errorcode;
  globus_mutex_unlock(&monitor.mutex);

  /* TODO: check ping response for version?? */

  /* success, so fall through all cleanup code */
  rc = GLOBUS_SUCCESS;

 globus_gram_client_ping_post_failed:
  globus_mutex_destroy(&monitor.mutex);
  globus_cond_destroy(&monitor.cond);

  globus_io_tcpattr_destroy (&attr);
 globus_gram_client_ping_authenticate_failed:
  return rc;
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
#if 0
    int                          rc;
    int                          version;
    char                         query[GLOBUS_GRAM_HTTP_BUFSIZE];
    globus_size_t                querysize;
    globus_gram_http_monitor_t   monitor;
    globus_io_attr_t             attr;

    if ( rc = globus_l_gram_client_authenticate ( 
		    gatekeeper_url,
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAG
		    GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY,
#else
		    GLOBUS_IO_SECURE_DELEGATION_MODE_NO_PROXY,
#endif
		    &attr) ) {
      return rc;
    }

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    /* TODO: pass attr into this */
    rc = globus_l_gram_pack_http_job_request (
		       query,
		       &query_size,
		       job_state_mask /* integer */,
		       callback_url /* user's state listener URL */,
		       description /* user's RSL */);

    rc = globus_gram_http_post_and_get(
	    gatekeeper_url,
	    (globus_byte_t *) query,
	    &querysize,
	    &monitor);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_gram_client_job_request_done;

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    globus_mutex_unlock(&monitor.mutex);

    if (rc == GLOBUS_SUCCESS)
    {
      char * result_contact;
      int    result_status;

	if ( globus_gram_http_version (query) 
	     != GLOBUS_GRAM_PROTOCOL_VERSION ) {
	  rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
	}

	if ( globus_l_gram_unpack_http_job_request_result (
			   query,
			   &result_status, /* GLOBUS_SUCCESS or a failure */
			   &result_contact /* NULL if not SUCCESS */)
	     != GLOBUS_SUCCESS ) {
	  rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	}
	else {
	  rc = result_status;
	  if ( job_contact!=NULL ) {
	    (*job_contact) = ((job_status==GLOBUS_SUCCESS) 
			      ? globus_libc_strdup (result_contact)
			      : NULL);
	  }
	}
    }

globus_gram_client_job_request_done:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    globus_io_tcpattr_destroy (&attr);

    return rc;
#endif
} /* globus_gram_client_job_request() */




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
    int                           rc;
    int                           version;
    char                          query[GLOBUS_GRAM_HTTP_BUFSIZE];
    globus_size_t                 querysize;
    globus_gram_http_monitor_t    monitor;

    GLOBUS_L_LOCK;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    globus_libc_sprintf( query,
			 "%d %d\n",
			 GLOBUS_GRAM_PROTOCOL_VERSION,
			 GLOBUS_GRAM_HTTP_QUERY_JOB_CANCEL );

    querysize = strlen(query);

    rc = globus_gram_http_post_and_get(
	    job_contact,
	    (globus_byte_t *) query,
	    &querysize,
	    &monitor);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_gram_client_job_cancel_done;

    GLOBUS_L_UNLOCK;

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    globus_mutex_unlock(&monitor.mutex);

    GLOBUS_L_LOCK;

    if (rc == GLOBUS_SUCCESS && querysize > 0)
    {
	if (2 != sscanf(query, "%d %d", &version, &rc))
	    rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	else if (version != GLOBUS_GRAM_PROTOCOL_VERSION)
	    rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }

 globus_gram_client_job_cancel_done:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    GLOBUS_L_UNLOCK;
    return rc;
}


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
    int                          rc;
    int                          version;
    char                         query[GLOBUS_GRAM_HTTP_BUFSIZE];
    char                         url[1000];
    globus_size_t                querysize;
    globus_gram_http_monitor_t   monitor;

    GLOBUS_L_LOCK;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    globus_libc_sprintf(query,
			"%d %d",
			GLOBUS_GRAM_PROTOCOL_VERSION,
			GLOBUS_GRAM_HTTP_QUERY_JOB_STATUS );

    querysize = strlen(query);

    rc = globus_gram_http_post_and_get(
	    job_contact,
	    (globus_byte_t *) query,
	    &querysize,
	    &monitor);

    grami_fprintf(globus_l_print_fp,
		  "post and get returned %d\n",rc);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_gram_client_job_status_done;

    GLOBUS_L_UNLOCK;

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    globus_mutex_unlock(&monitor.mutex);

    grami_fprintf(globus_l_print_fp,
		  "monitor released, errcode=%d\n",rc);

    GLOBUS_L_LOCK;

    if (rc == GLOBUS_SUCCESS && querysize > 0)
    {
	if (4 != sscanf(query, "%d %s %d %d",
			&version, url, job_status, failure_code))
	    rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	else if (version != GLOBUS_GRAM_PROTOCOL_VERSION)
	    rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }

globus_gram_client_job_status_done:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    GLOBUS_L_UNLOCK;
    return rc;
}



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
    unsigned short            port;
    char *                    host;
    int                       rc;

    GLOBUS_L_LOCK;

    rc = globus_gram_http_allow_attach( &port,
					&host,
					(void *) callback_func,
					globus_gram_http_client_callback,
					user_callback_arg );

    if (rc==GLOBUS_SUCCESS && callback_contact)
    {
	/* 
	 * https+junk = 10, 6-digit port numbers, and null
	 */
	*callback_contact = globus_libc_malloc( strlen(host) + 10 + 6 + 1);
				
	globus_libc_sprintf(*callback_contact,
			    "https://%s:%hu/",
			    host,
			    port);
    }

    GLOBUS_L_UNLOCK;    

    return rc;
} /* globus_gram_client_callback_allow() */



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
    int                          rc;
    int                          version;
    char                         query[GLOBUS_GRAM_HTTP_BUFSIZE];
    char                         url[1000];
    globus_size_t                querysize;
    globus_gram_http_monitor_t   monitor;

    GLOBUS_L_LOCK;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    globus_libc_sprintf(query,
			"%d %d %d %s",
			GLOBUS_GRAM_PROTOCOL_VERSION,
			GLOBUS_GRAM_HTTP_QUERY_JOB_REGISTER,
			job_state_mask,
			callback_contact );

    querysize = strlen(query);

    rc = globus_gram_http_post_and_get(
	    job_contact,
	    (globus_byte_t *) query,
	    &querysize,
	    &monitor);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_gram_client_job_callback_register_done;

    GLOBUS_L_UNLOCK;

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    globus_mutex_unlock(&monitor.mutex);

    GLOBUS_L_LOCK;

    if (rc == GLOBUS_SUCCESS)
    {
	if (3 != sscanf(query,
			"%d %s %d %d",
			&version,
			url,
			job_status,
			failure_code))
	    rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	else if (version != GLOBUS_GRAM_PROTOCOL_VERSION)
	    rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }

globus_gram_client_job_callback_register_done:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    GLOBUS_L_UNLOCK;
    return rc;
}


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
    int                          rc;
    int                          version;
    char                         query[GLOBUS_GRAM_HTTP_BUFSIZE];
    globus_size_t                querysize;
    globus_gram_http_monitor_t   monitor;

    GLOBUS_L_LOCK;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    globus_libc_sprintf(query,
			"%d %d %s",
			GLOBUS_GRAM_PROTOCOL_VERSION,
			GLOBUS_GRAM_HTTP_QUERY_JOB_UNREGISTER,
			callback_contact );

    querysize = strlen(query);

    rc = globus_gram_http_post_and_get(
	    job_contact,
	    (globus_byte_t *) query,
	    &querysize,
	    &monitor);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_gram_client_job_callback_unregister_done;

    GLOBUS_L_UNLOCK;

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    globus_mutex_unlock(&monitor.mutex);

    GLOBUS_L_LOCK;

    if (rc == GLOBUS_SUCCESS)
    {
	if (3 != sscanf(query, "%d %d %d", &version, job_status, failure_code))
	    rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	else if (version != GLOBUS_GRAM_PROTOCOL_VERSION)
	    rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }

globus_gram_client_job_callback_unregister_done:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    GLOBUS_L_UNLOCK;
    return rc;
}




/******************************************************************************
Function:	globus_gram_client_callback_disallow()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_callback_disallow(char * callback_contact)
{
    return globus_gram_http_callback_disallow(callback_contact);
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
    grami_fprintf(globus_l_print_fp,
		  "in globus_gram_client_job_start_time()\n");

    return GLOBUS_SUCCESS;
} /* globus_gram_client_job_start_time() */



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
