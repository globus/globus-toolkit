
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
                          Module specific prototypes
******************************************************************************/
static int 
globus_l_gram_client_authenticate(
    char *                                 gatekeeper_url,
    globus_io_secure_delegation_mode_t     delegation_mode,
    globus_io_handle_t *                   gatekeeper_handle );


static int
globus_l_gram_client_parse_gatekeeper_contact( char *    contact_string,
					       char **   gatekeeper_url,
					       char **   gatekeeper_service,
					       char **   gatekeeper_dn );

static int 
globus_l_gram_client_setup_attr_t(
    globus_io_attr_t *                     attrp,
    globus_io_secure_delegation_mode_t     delegation_mode,
    char *                                 gatekeeper_dn );

/******************************************************************************
                       Define module specific variables
******************************************************************************/

globus_module_descriptor_t globus_gram_client_module = 
{
    "globus_gram_client",
    globus_i_gram_client_activate,
    globus_i_gram_client_deactivate,
    GLOBUS_NULL
};

FILE *			globus_l_print_fp;
static globus_mutex_t	globus_l_mutex;
static int		globus_l_is_initialized = 0;

#define GLOBUS_L_CHECK_IF_INITIALIZED assert(globus_l_is_initialized==1)

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
    OM_uint32 major_status;
    OM_uint32 minor_status;
    
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
Function:	globus_l_gram_client_parse_gatekeeper_url()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_client_parse_gatekeeper_contact( char *    contact_string,
					       char **   gatekeeper_url,
					       char **   gatekeeper_service,
					       char **   gatekeeper_dn )
{
    char *                duplicate;
    char *                host;
    char *                port;
    char *                dn;
    char *                service;
    unsigned short        iport;
    int			  portlen=0;

    /*
     *  the gatekeeper contact format: [https://]<host>:<port>[/<service>]:<dn>
     */    

    if ((duplicate = globus_libc_strdup(contact_string)))
    {
	host = duplicate;

	if (strncmp(duplicate,"https://", strlen("https://")) == 0)
	    host += strlen("https://");

	dn = host;
	if ((port = strchr(host,':')))
	{
	    *port++ = '\0';
	    if ((dn = strchr(port, ':'))) 
	    {
		*dn++ = '\0';
	    }
	    else
	    {
		globus_free(duplicate);
		return GLOBUS_GRAM_CLIENT_ERROR_BAD_GATEKEEPER_CONTACT;
	    }
	    iport = (unsigned short) atoi(port);
    
	    if (! (service = strchr(port,'/')))
		service = "/jobmanager";        /* yes, including the slash */

	}
	else
	    port = "754";
    } 
    else 
    {
	grami_fprintf(globus_l_print_fp, "strdup failed for contact_string\n");
	return(1);
    }
    
    *gatekeeper_url = globus_libc_malloc(strlen(host) +
					 5 + 
					 strlen("https://:/"));

    globus_libc_sprintf(*gatekeeper_url, "https://%s:%d/",
			host,
			(int) iport);    
    /* 
     * done with the port, can now put the slash back
     */
    *gatekeeper_service = globus_libc_strdup(service);
    *gatekeeper_dn = globus_libc_strdup(dn);
    globus_libc_free(duplicate);

    return GLOBUS_SUCCESS;
}


/******************************************************************************
Function:	globus_l_gram_client_setup_attr_t()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_gram_client_setup_attr_t(
    globus_io_attr_t *                     attrp,
    globus_io_secure_delegation_mode_t     delegation_mode,
    char *                                 gatekeeper_dn )
{
    globus_result_t                        res;
    globus_io_secure_authorization_data_t  auth_data;

    if ( (res = globus_io_tcpattr_init(attrp))
	 || (res = globus_io_secure_authorization_data_initialize(
	     &auth_data))
	 || (res = globus_io_attr_set_secure_authentication_mode(
	     attrp,
	     GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI,
	     GSS_C_NO_CREDENTIAL))
	 || (res = globus_io_secure_authorization_data_set_identity(
	     &auth_data,
	     gatekeeper_dn))
	 || (res = globus_io_attr_set_secure_authorization_mode(
	     attrp,
	     GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY,
	     &auth_data))
	 || (res = globus_io_attr_set_secure_delegation_mode(
	     attrp,
	     delegation_mode))
	 || (res = globus_io_attr_set_secure_channel_mode(
	     attrp,
	     GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP)) )
    {
	globus_object_t *  err = globus_error_get(res);
	
	grami_fprintf(globus_l_print_fp, 
		      "setting up IO attributes failed\n");
	
	/* TODO: interrogate 'err' to choose the correct error code */
	
	globus_object_free(err);
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }

    return GLOBUS_SUCCESS;
} /* globus_l_gram_client_setup_attr_t() */


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
globus_gram_client_ping(char * gatekeeper_contact)
{
    int                          rc;
    globus_io_attr_t             attr;
    globus_gram_http_monitor_t   monitor;
    char *                       url;
    char *                       service;
    char *                       dn;
    char *                       ping_service;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    rc = globus_l_gram_client_parse_gatekeeper_contact(
	gatekeeper_contact,
	&url,
	&service,
	&dn );
    if (rc != GLOBUS_SUCCESS)
	goto globus_gram_client_ping_parse_failed;

    rc = globus_l_gram_client_setup_attr_t( 
	&attr,
	GLOBUS_IO_SECURE_DELEGATION_MODE_NONE,
	dn );
    if (rc != GLOBUS_SUCCESS)
	goto globus_gram_client_ping_attr_failed;

    ping_service = globus_libc_malloc(strlen(service) + 5);
    globus_libc_sprintf(ping_service, "ping%s", service);
			 
    rc = globus_gram_http_post_and_get(
	         url,
		 ping_service,
		 &attr,
		 GLOBUS_NULL,
		 0,
		 GLOBUS_NULL,
		 0,
		 &monitor);

    if (rc != GLOBUS_SUCCESS)
	goto globus_gram_client_ping_post_failed;

    globus_mutex_lock(&monitor.mutex);
    {   
        while (!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
        rc = monitor.errorcode;
    }
    globus_mutex_unlock(&monitor.mutex);

globus_gram_client_ping_post_failed:
    globus_io_tcpattr_destroy (&attr);

globus_gram_client_ping_attr_failed:
    globus_libc_free(ping_service);
    globus_libc_free(url);
    globus_libc_free(service);
    globus_libc_free(dn);

globus_gram_client_ping_parse_failed:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    globus_io_tcpattr_destroy (&attr);
    return rc;
} /* globus_gram_client_ping() */


/******************************************************************************
Function:	globus_gram_client_job_request()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_request(char *           gatekeeper_contact,
			       const char *     description,
			       const int        job_state_mask,
			       const char *     callback_url,
			       char **          job_contact)
{
    int                          rc;
    int                          version;
    globus_byte_t *              query = GLOBUS_NULL;
    globus_byte_t *              reply = GLOBUS_NULL;
    globus_size_t                querysize; 
    globus_size_t                replysize;
    globus_gram_http_monitor_t   monitor;
    globus_io_attr_t             attr;
    char *                       url;
    char *                       service;
    char *                       dn;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    if ((rc = globus_l_gram_client_parse_gatekeeper_contact(
	            gatekeeper_contact,
		     &url,
		     &service,
		     &dn )) != GLOBUS_SUCCESS)
    {
	goto globus_gram_client_job_request_parse_failed;
    }

    if ((rc = globus_l_gram_client_setup_attr_t( 
	             &attr,
		     GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY,
		     dn )) 

	|| (rc = globus_gram_http_pack_job_request(
	             job_state_mask,
		     callback_url,
		     description,
		     &query,
		     &querysize)) )
    {
	goto globus_gram_client_job_request_pack_failed;
    }

    rc = globus_gram_http_post_and_get(
	         url,
		 service,
		 &attr,
		 query,
		 querysize,
		 &reply,
		 &replysize,
		 &monitor);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_gram_client_job_request_http_failed;

    globus_mutex_lock(&monitor.mutex);
    {
	while (!monitor.done)
	{
	    globus_cond_wait(&monitor.cond, &monitor.mutex);
	}
	rc = monitor.errorcode;
    }
    globus_mutex_unlock(&monitor.mutex);


    if (rc == GLOBUS_SUCCESS)
    {
	char * result_contact = GLOBUS_NULL;
	int    result_status;

	if ((rc = globus_gram_http_unpack_job_request_reply(
	             reply,
		     replysize,
		     &result_status,
		     &result_contact))
	    == GLOBUS_SUCCESS)
	{
	    rc = result_status;
	    if ( job_contact )
	    {
		(*job_contact) = ((result_status==GLOBUS_SUCCESS) 
				  ? globus_libc_strdup(result_contact)
				  : NULL);
	    }
	}
	if (result_contact)
	    globus_free(result_contact);
    }
    if (reply)
	globus_libc_free(reply);

globus_gram_client_job_request_http_failed:
    if (query)
	globus_libc_free(query);

globus_gram_client_job_request_pack_failed:
    globus_io_tcpattr_destroy (&attr);
    globus_libc_free(url);
    globus_libc_free(service);
    globus_libc_free(dn);

globus_gram_client_job_request_parse_failed:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    return rc;
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
Function:	globus_l_gram_client_to_jobmanager()
Description:	packing/sending to jobmanager URL/waiting/unpacking 
Parameters:
Returns:
******************************************************************************/
int
globus_l_gram_client_to_jobmanager(char *   job_contact,
				   char *   request,
				   int *    job_status,
				   int *    failure_code )
{
    int                           rc;
    globus_byte_t *               query = GLOBUS_NULL; 
    globus_byte_t *               reply = GLOBUS_NULL; 
    globus_size_t                 replysize;
    globus_size_t                 querysize;
    globus_gram_http_monitor_t    monitor;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    rc = globus_gram_http_pack_status_request(
	      request,
	      &query,
	      &querysize );

    if (rc!=GLOBUS_SUCCESS)
	goto globus_l_gram_client_to_jobmanager_pack_failed;
    
    rc = globus_gram_http_post_and_get(
	    job_contact,
	    job_contact,
	    GLOBUS_NULL,
	    query,
	    querysize,
	    &reply,
	    &replysize,
	    &monitor);

    if (rc!=GLOBUS_SUCCESS)
	goto globus_l_gram_client_to_jobmanager_http_failed;

    globus_mutex_lock(&monitor.mutex);
    {
	while (!monitor.done)
	{
	    globus_cond_wait(&monitor.cond, &monitor.mutex);
	}
	rc = monitor.errorcode;
    }
    globus_mutex_unlock(&monitor.mutex);

    if (rc == GLOBUS_SUCCESS)
    {
	rc = globus_gram_http_unpack_status_reply(
	          reply,
		  replysize,
		  job_status,
		  failure_code);
    }

    if (reply)
	globus_libc_free(reply);

globus_l_gram_client_to_jobmanager_http_failed:
    globus_libc_free(query);
    
globus_l_gram_client_to_jobmanager_pack_failed:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    return rc;
}




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
    int                           job_state;
    int                           failure_code;
    char *                        request = "cancel";

    GLOBUS_L_CHECK_IF_INITIALIZED;

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     request,
					     &job_state,
					     &failure_code );
    if (rc == GLOBUS_SUCCESS)
    {
	if (job_state==GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED)
	    rc = failure_code;
    }

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
    int       rc;
    char *    request = "status";

    GLOBUS_L_CHECK_IF_INITIALIZED;

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     request,
					     job_status,
					     failure_code );
    
    return rc;
}



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
    int       rc;
    char  *   request;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    /* 'register' = 8, allow 10-digit integer, 2 spaces and null  */
    request = (char *) globus_libc_malloc( 
	                  strlen(callback_contact)
			  + 8 + 10 + 2 + 1 );

    globus_libc_sprintf(request,
			"register %d %s",
			job_state_mask,
			callback_contact);

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     request,
					     job_status,
					     failure_code );

    globus_libc_free(request);

    return rc;
}


/******************************************************************************
Function:	globus_gram_client_job_callback_unregister()
Description:	
Parameters:
Returns:
******************************************************************************/
int 
globus_gram_client_job_callback_unregister(char *         job_contact,
					   const char *   callback_contact,
					   int *          job_status,
					   int *          failure_code)
{
    int       rc;
    char  *   request;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    /* 'unregister' = 10, a space and null  */
    request = (char *) globus_libc_malloc( 
	                  strlen(callback_contact)
			  + 10 + 1 + 1 );

    globus_libc_sprintf(request,
			"unregister %s",
			callback_contact);

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					   request,
					   job_status,
					   failure_code );

    globus_libc_free(request);

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

    GLOBUS_L_CHECK_IF_INITIALIZED;

    rc = globus_gram_http_allow_attach( &port,
					&host,
					(void *) callback_func,
					globus_gram_http_client_callback,
					user_callback_arg );

    if (rc==GLOBUS_SUCCESS && callback_contact)
    {
	/* 
	 * https+junk = 10, 6-digit port number, and null
	 */
	*callback_contact = globus_libc_malloc( strlen(host) + 10 + 6 + 1);
				
	globus_libc_sprintf(*callback_contact,
			    "https://%s:%hu/",
			    host,
			    port);
    }

    return rc;
} /* globus_gram_client_callback_allow() */


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

