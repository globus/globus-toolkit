#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_client.c
 * 
 * Resource Managemant Client APIs
 * 
 * This file contains the Resource Management Client API funtion
 * calls.  The resource management API provides functions for 
 * submitting a job request to a RM, for asking when a job
 * (submitted or not) might run, for cancelling a request,
 * for requesting notification of state changes for a request,
 * and for checking for pending notifications.
 * 
 * CVS Information:
 * 
 * - $Source$
 * - $Date$
 * - $Revision$
 * - $Author$
 */

/*
 * Include header files
 */

#include "globus_config.h"
#include "globus_gram_client.h"
#include "globus_gram_protocol.h"
#include "globus_rsl.h"

#include <assert.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include <globus_io.h>

#if defined(TARGET_ARCH_SOLARIS)
#include <netdb.h>
#endif
#include "version.h"

/*
 * Module specific prototypes
 */
int
globus_i_gram_client_activate(void);

int
globus_i_gram_client_deactivate(void);

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

static
void
globus_l_gram_client_callback( void *                 arg,
                               globus_io_handle_t *   handle,
                               globus_byte_t *        buf,
                               globus_size_t          nbytes,
                               int                    errorcode);

/*
 * Define module specific variables
 */

globus_module_descriptor_t globus_gram_client_module = 
{
    "globus_gram_client",
    globus_i_gram_client_activate,
    globus_i_gram_client_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

FILE *			globus_l_print_fp;
static globus_mutex_t	globus_l_mutex;
static int		globus_l_is_initialized = 0;

#define GLOBUS_L_CHECK_IF_INITIALIZED assert(globus_l_is_initialized==1)

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/*
 * globus_i_gram_client_activate()
 * Description:	Initialize variables
 * Call authorization routine for password entry.
 */
int
globus_i_gram_client_activate(void)
{
    int rc;
    
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
    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
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
    /* globus_gram_client_debug(); */

    return 0;
} /* globus_i_gram_client_activate() */


/*
 * globus_i_gram_client_deactivate()
 */
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
	globus_l_is_initialized = 0;
    }

    /* 
     * this will free any allocated space, but not malloc any new
     */
    globus_gram_protocol_error_7_hack_replace_message((const char*) GLOBUS_NULL);
    
    rc = globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }

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


/**
 * Enable debugging messages.
 * @ingroup globus_gram_client
 *
 * Enables the displaying of internal debugging information.
 *
 * @return void
 */
void
globus_gram_client_debug(void)
{
    globus_l_print_fp = stdout;
    globus_libc_fprintf(globus_l_print_fp,
		  "globus_gram_client: debug messages will be printed.\n");
} /* globus_gram_client_debug() */


/* globus_l_gram_client_parse_gatekeeper_url() */
static int
globus_l_gram_client_parse_gatekeeper_contact( char *    contact_string,
					       char **   gatekeeper_url,
					       char **   gatekeeper_service,
					       char **   gatekeeper_dn )
{
    char *                duplicate;
    char *                host = GLOBUS_NULL;
    char *                port = GLOBUS_NULL;
    char *                dn = GLOBUS_NULL;
    char *                service;
    int                   got_port = 0;
    int                   got_service = 0;
    char *                ptr;
    unsigned short        iport;
    globus_url_t          some_struct;

    /*
     *  the gatekeeper contact format: [https://]<host>:<port>[/<service>]:<dn>
     */    

    service = "jobmanager";
    iport = 2119;

    if ((duplicate = globus_libc_strdup(contact_string)))
    {
        host = duplicate;

        if (strncmp(duplicate,"https://", strlen("https://")) == 0)
            host += strlen("https://");

        dn = host;

        for (ptr = duplicate; *ptr != '\0'; ptr++)
        {
            if ( *ptr == ':' )
            {
                got_port = 1;
                *ptr++ = '\0';
                port = ptr;
                break;
            }
            if ( *ptr == '/' )
            {
                got_service = 1;
                *ptr++ = '\0';
                service = ptr;
                break;
            }
        }

        if (got_port || got_service) 
        {
	    if ((dn = strchr(ptr, ':')))
	    {
		*dn++ = '\0';
	    }

            if (got_port)
            {
	        if (service = strchr(port,'/'))
                {
                    if ((service - port) > 1)
                    {
	                iport = (unsigned short) atoi(port);
                    }
                    *service++ = '\0';
                }
                else
                {
                    service = "jobmanager";
	            if (strlen(port) > 0)
	               iport = (unsigned short) atoi(port);
                }
            }
        }
        else
        {
            dn = GLOBUS_NULL;
        }
    } 
    else 
    {
	if(globus_l_print_fp)
	{
	    globus_libc_fprintf(globus_l_print_fp,
		                "strdup failed for contact_string\n");
	}
        return(GLOBUS_GRAM_PROTOCOL_ERROR_BAD_GATEKEEPER_CONTACT);
    }
    
    if (! *host)
    {
       globus_libc_free(duplicate);
	if(globus_l_print_fp)
	{
	    globus_libc_fprintf(globus_l_print_fp,
		                "empty host value in contact_string\n");
	}
       return(GLOBUS_GRAM_PROTOCOL_ERROR_BAD_GATEKEEPER_CONTACT);
    }

    *gatekeeper_url = globus_libc_malloc(strlen(host) +
					 10 + 
					 strlen("https://:/"));

    globus_libc_sprintf(*gatekeeper_url, "https://%s:%d/",
			host,
			(int) iport);    

    if (globus_url_parse(*gatekeeper_url, &some_struct) != GLOBUS_SUCCESS)
    {
       globus_libc_free(*gatekeeper_url);
       globus_libc_free(duplicate);
       return(GLOBUS_GRAM_PROTOCOL_ERROR_BAD_GATEKEEPER_CONTACT);
    }
    globus_url_destroy(&some_struct);

    /* 
     * done with the port, can now put the slash back
     */
    *gatekeeper_service = globus_libc_malloc(strlen(service) + 2);

    globus_libc_sprintf(*gatekeeper_service, "/%s", service);

    if ((dn) && (*dn))
    {
   	*gatekeeper_dn = globus_libc_strdup(dn);
    }
    else
    {
   	*gatekeeper_dn = NULL;
    }
    globus_libc_free(duplicate);

    return GLOBUS_SUCCESS;
}


/*
 * globus_l_gram_client_setup_attr_t()
 */
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
	     globus_i_gram_protocol_credential))
	 ||  (gatekeeper_dn ? (res = globus_io_secure_authorization_data_set_identity(
	     &auth_data,
	     gatekeeper_dn)) : 0)
	 || (res = globus_io_attr_set_secure_authorization_mode(
	     attrp,
	     gatekeeper_dn ? GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY : GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST,
	     &auth_data))
	 || (res = globus_io_attr_set_secure_delegation_mode(
	     attrp,
	     delegation_mode))
	 || (res = globus_io_attr_set_secure_channel_mode(
	     attrp,
	     GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP)) )
    {
	globus_object_t *  err = globus_error_get(res);
	
	if(globus_l_print_fp)
	{
	    globus_libc_fprintf(globus_l_print_fp, 
				"setting up IO attributes failed\n");
	}
	
	/* TODO: interrogate 'err' to choose the correct error code */
	
	globus_object_free(err);
	return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }

    return GLOBUS_SUCCESS;
} /* globus_l_gram_client_setup_attr_t() */


/**
 * Version checking
 * @ingroup globus_gram_client
 *
 * Return the version of the GRAM protocol which this implementation of the
 * GRAM client library understands.
 *
 * @return An integer representing the protocol revision.
 */
int 
globus_gram_client_version(void)
{
    return(GLOBUS_GRAM_PROTOCOL_VERSION);

} /* globus_gram_client_version() */


/**
 * Verify that a gatekeeper is running.
 * @ingroup globus_gram_client_job_functions
 *
 * Sends a specially-formated GRAM protocol message which checks to
 * see if a Globus Gatekeeper is running on a given PORT, and whether that
 * Gatekeeper is configured to support the desired job manager service.
 * This is primarily used for diagnostic purposes.
 *
 * This function blocks while processing the ping request.
 *
 * @param resource_manager_contact
 *        A NULL-terminated character string containing a
 *        @link globus_gram_resource_manager_contact GRAM contact@endlink.
 *
 * @return
 * This funciton returns GLOBUS_SUCCESS if The gatekeeper contact is valid, the
 * client was able to authenticate with the Gatekeeper, and the Gatekeeper was
 * able to locate the requested service. Otherwise one of the
 * GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 */
int 
globus_gram_client_ping(char * resource_manager_contact)
{
    int                          rc;
    globus_io_attr_t             attr;
    globus_gram_protocol_monitor_t   monitor;
    char *                       url;
    char *                       service;
    char *                       dn;
    char *                       ping_service;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    rc = globus_l_gram_client_parse_gatekeeper_contact(
	resource_manager_contact,
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
			 
    rc = globus_gram_protocol_post_and_get(
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
    if (dn)
        globus_libc_free(dn);

globus_gram_client_ping_parse_failed:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    globus_io_tcpattr_destroy (&attr);
    return rc;
} /* globus_gram_client_ping() */


/**
 * Request a job be started.
 * @ingroup globus_gram_client_job_functions
 *
 * Request access to interactive resources at the current time. A job request
 * is atomic: either all of the requested processes are created, or none are
 * created. 
 *
 * @param resource_manager_contact
 *        A NULL-terminated character string containing a
 *        @link globus_gram_resource_manager_contact GRAM contact@endlink.
 * @param description
 *        An RSL description of the requested job. A GRAM RSL consists of
 *        a conjunction of
 *        @link globus_gram_rsl_parameters RSL parameters @endlink.
 * @param job_state_mask
 *         0, a bitwise OR of the GLOBUS_GRAM_PROTOCOL_JOB_STATE_* states, or
 *         GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL.
 * @param callback_contact
 *        The URL which will receive all messages about the job.
 * @param job_contact
 *        In a successful case, this is set to a unique identifier for each job.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful,
 * otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 *
 * @see @ref globus_gram_resource_manager_contact
 */
int 
globus_gram_client_job_request(char *           resource_manager_contact,
			       const char *     description,
			       const int        job_state_mask,
			       const char *     callback_contact,
			       char **          job_contact)
{
    int                          rc;
    globus_byte_t *              query = GLOBUS_NULL;
    globus_byte_t *              reply = GLOBUS_NULL;
    globus_size_t                querysize; 
    globus_size_t                replysize;
    globus_gram_protocol_monitor_t   monitor;
    globus_io_attr_t             attr;
    char *                       url;
    char *                       service;
    char *                       dn;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    if ((rc = globus_l_gram_client_parse_gatekeeper_contact(
	             resource_manager_contact,
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

	|| (rc = globus_gram_protocol_pack_job_request(
	             job_state_mask,
		     callback_contact,
		     description,
		     &query,
		     &querysize)) )
    {
	goto globus_gram_client_job_request_pack_failed;
    }

    rc = globus_gram_protocol_post_and_get(
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

	if ((rc = globus_gram_protocol_unpack_job_request_reply(
	             reply,
		     replysize,
		     &result_status,
		     &result_contact))
	    == GLOBUS_SUCCESS)
	{
	    rc = result_status;
	    if ( job_contact )
	    {
		(*job_contact) = ((result_status==GLOBUS_SUCCESS ||
		    result_status==GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
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
    if (dn)
        globus_libc_free(dn);

globus_gram_client_job_request_parse_failed:
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    return rc;
} /* globus_gram_client_job_request() */


/**
 * Error code translation.
 * @ingroup globus_gram_client
 *
 * This function takes the error code value and returns the associated error
 * code string. The string is statically allocated by the Globus GRAM Client
 * library and should not be modified or freed.
 *
 * @param error_code
 *        The error code to look up.
 *
 * @return An error string containing the reason for the error. The error
 *         string is written to be used in the context
 *         "[operation] failed because [error_string]".
 *
 */
const char *
globus_gram_client_error_string(int error_code)
{
    return globus_gram_protocol_error_string(error_code);
}

/*
 * packing/sending to jobmanager URL/waiting/unpacking 
 */
int
globus_l_gram_client_to_jobmanager(char *   job_contact,
				   char *   request,
				   int *    job_status,
				   int *    failure_code )
{
    int                           rc;
    int                           job_failure_code;
    globus_byte_t *               query = GLOBUS_NULL; 
    globus_byte_t *               reply = GLOBUS_NULL; 
    globus_size_t                 replysize;
    globus_size_t                 querysize;
    globus_gram_protocol_monitor_t    monitor;

    globus_mutex_init(&monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&monitor.cond, (globus_condattr_t *) NULL);
    monitor.done = GLOBUS_FALSE;

    rc = globus_gram_protocol_pack_status_request(
	      request,
	      &query,
	      &querysize );

    if (rc!=GLOBUS_SUCCESS)
	goto globus_l_gram_client_to_jobmanager_pack_failed;
    
    rc = globus_gram_protocol_post_and_get(
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
	rc = globus_gram_protocol_unpack_status_reply(
	          reply,
		  replysize,
		  job_status,
		  failure_code,
		  &job_failure_code);
    }

    if (reply)
	globus_libc_free(reply);

globus_l_gram_client_to_jobmanager_http_failed:
    if (rc != GLOBUS_SUCCESS)
    {
        if (rc == GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER;
            *failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER;
        }
        else
        {
            *failure_code = rc;
        }
    }
    else
    {
	if (*failure_code != GLOBUS_SUCCESS)
	{
	    rc = *failure_code;
	}
	if (job_failure_code != 0)
	{
	    *failure_code = job_failure_code;
	}
    }

    globus_libc_free(query);
    
globus_l_gram_client_to_jobmanager_pack_failed:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    
    return rc;
}




/**
 * Cancel a GRAM-managed job.
 * @ingroup globus_gram_client_job_functions
 *
 * Removes a @a PENDING job request, or kills all processes associated
 * with an @a ACTIVE job, releasing any associated resources
 *
 * @param  job_contact
 *         The job contact string of the job to contact. This is the same
 *         value returned from globus_gram_client_job_request().
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the cancellation
 *         was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_*
 *         values will be returned, indicating why the client could not cancel
 *         the job.
 */
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

    return rc;
}


/**
 * Signal a job manager.
 * @ingroup globus_gram_client_job_functions
 *
 * Send a signal to a GRAM job manager to modify the way it handles a job
 * request. Signals consist of a signal number, and an optional string
 * argument. The meanings of the signals supported by the GRAM job manager
 * are defined in the
 * @link globus_gram_protocol_constants GRAM Protocol documentation @endlink
 *
 * @param job_contact
 *         The job contact string of the job manager to signal.
 * @param signal
 *         The signal code to send to the job manager.
 * @param signal_arg
 *         Parameters for the signal, as described in the documentation
 *         for the globus_gram_protocol_job_signal_t.
 * @param job_status
 *         A pointer to an integer which will return the new job status,
 *         if the signal causes the job's state to change (for example,
 *         the GLOBUS_GRAM_PROTOCOL_JOB_CANCEL signal will cause the
 *         job to enter the #GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED).
 * @param failure_code
 *         An error code indicating why the job manager could not process
 *         the signal.
 *
 * @note
 *         Compatibility note: The Globus Toolkit(tm) Version 1.x does not
 *         support the use of signals.
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the signal
 *         was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_*
 *         values will be returned, indicating why the client could not signal
 *         the job.
 */
int 
globus_gram_client_job_signal(char * job_contact,
                              globus_gram_protocol_job_signal_t signal,
                              char * signal_arg,
			      int  * job_status,
                              int * failure_code)
{
    int       rc;
    char  *   request;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    if (signal_arg != NULL)
    {
	/* 'signal' = 6, allow 10-digit integer, 2 spaces and null  */
	request = (char *) globus_libc_malloc( strlen(signal_arg)
					       + 6 + 10 + 2 + 1 );

	globus_libc_sprintf(request,
			    "signal %d %s",
			    signal,
			    signal_arg);
    }
    else
    {
	/* 'signal' = 6, allow 10-digit integer, 1 space and null  */
	request = (char *) globus_libc_malloc( 6 + 10 + 1 + 1 );

	globus_libc_sprintf(request,
			    "signal %d",
			    signal);
    }

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     request,
					     job_status,
					     failure_code );

    globus_libc_free(request);

    return rc;
}


/**
 * Query a job's status.
 * @ingroup globus_gram_client_job_functions
 *
 * This function queries the status of the job associated with the job contact,
 * returning it's current job status and job failure reason if it has failed.
 *
 * @param job_contact
 *        The job contact string of the job to query. This is the same
 *        value returned from globus_gram_client_job_request().
 * @param job_status
 *        A pointer to an integer which will be populated with the current
 *        status of the job. This will be one of the
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_* values if this function is
 *        successful.
 * @param failure_code
 *        The reason why the job failed if the @a job_status is set to 
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 *
 * @return This function returns GLOBUS_SUCCESS if the job state query was
 * successfully. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values will
 * be returned, indicating why the client could not query the job state.
 */
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



/**
 * Register a callback contact for job state changes.
 * @ingroup globus_gram_client_job_functions
 *
 * @param job_contact
 *        The job contact string of the job to contact. This is the same
 *        value returned from globus_gram_client_job_request().
 * @param job_state_mask
 *        A mask indicating which job state changes should be sent to the
 *        @a callback_contact. This may be 0 (no job state changes), a
 *        bitwise-or  of the GLOBUS_GRAM_PROTOCOL_JOB_STATE_* states, or
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL to register for all job states.
 * @param callback_contact
 *        A URL string containing a GRAM client callback. This string should
 *        normally be generated by a process calling
 *        globus_gram_client_callback_allow().
 * @param failure_code
 *        Set to an error code when the job manager is unable to process
 *        this registration.
 *
 * @return This function returns GLOBUS_SUCCESS if the callback registration
 * was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values
 * will be returned, indicating why the client could not register the callback
 * contact.
 */
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


/**
 * Unregister a callback contact from future job state changes.
 * @ingroup globus_gram_client_job_functions
 *
 * @param job_contact
 *        The job contact string of the job manager to contact. This is the
 *        same value returned from globus_gram_client_job_request().
 * @param callback_contact
 *        A URL string containing a GRAM client callback. This string should
 *        normally be generated by a process calling
 *        globus_gram_client_callback_allow(). If this function returns
 *        successfully, the process managing the callback_contact should
 *        not receive future job state changes.
 * @param failure_code
 *        Set to an error code when the job manager is unable to process
 *        this registration.
 *
 * @return This function returns GLOBUS_SUCCESS if the callback unregistration
 * was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values
 * will be returned, indicating why the client could not unregister the
 * callback contact.
 */
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

/**
 * Create a callback contact.
 * @ingroup globus_gram_client_callback
 *
 * Creates a small GRAM server which can handle GRAM state updates from
 * job managers.  The contact information for this server is returned and
 * may be used with the globus_gram_client_job_request() or
 * globus_gram_client_callback_register() functions.
 *
 * @param callback_func
 *        A pointer to the user's callback function to be called when
 *        GRAM state changes are received from a Job Manager.
 * @param user_callback_arg
 *        A pointer to arbitrary data which is passed as the first
 *        parameter to the @a callback_func function when it is called.
 * @param callback_contact
 *        A pointer to a char *. This pointer will be initialized with
 *        a newly allocated string containing the information needed by
 *        the Job Manager to contact this GRAM callback server. This
 *        string should be freed by the user when it is no longer used.
 *
 * @return This function returns GLOBUS_SUCCESS if the callback contact
 * create was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_*
 * values will be returned, indicating why the client could not create the
 * callback contact.
 */
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

    rc = globus_gram_protocol_allow_attach( &port,
					&host,
					(void *) callback_func,
					globus_l_gram_client_callback,
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
    globus_libc_free(host);

    return rc;
} /* globus_gram_client_callback_allow() */


/**
 * Disable a callback handler.
 * @ingroup globus_gram_client_callback
 *
 * Disables the GRAM server created by calling
 * globus_gram_client_callback_allow(). This function blocks until all
 * pending job state updates being handled by this server are dispatched.
 *
 * This function can only be used to disable a callback created in
 * the current process.
 *
 * @param callback_contact
 *        The callback contact string returned by calling
 *        globus_gram_client_callback_allow.
 *
 * @return This function returns GLOBUS_SUCCESS if the callback contact
 * was disabled successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_*
 * values will be returned, indicating why the client could not disable the
 * callback contact.
 */
int 
globus_gram_client_callback_disallow(char * callback_contact)
{
    return globus_gram_protocol_callback_disallow(callback_contact);
} /* globus_gram_client_callback_allow() */



/**
 * Releases the resources storing a job contact string.
 * @ingroup globus_gram_client
 *
 * @param job_contact
 *        A job contact string returned in a successful call to
 *        globus_gram_client_job_request()
 */
int 
globus_gram_client_job_contact_free(char * job_contact)
{
    if(globus_l_print_fp)
    {
	globus_libc_fprintf(globus_l_print_fp,
		      "in globus_gram_client_job_contact_free()\n");
    }

    globus_free(job_contact);

    return (0);
} /* globus_gram_client_job_contact_free() */

static
void
globus_l_gram_client_callback( void *                 arg,
                               globus_io_handle_t *   handle,
                               globus_byte_t *        buf,
                               globus_size_t          nbytes,
                               int                    errorcode)
{
    globus_gram_client_callback_func_t     userfunc;
    globus_byte_t *                        reply;
    globus_size_t                          replysize;
    char *                                 url;
    int                                    job_status;
    int                                    failure_code;
    int                                    rc;

    rc = errorcode;

    if (rc != GLOBUS_SUCCESS || nbytes <= 0)
    {
        job_status   = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        failure_code = rc;
    }
    else
    {
        rc = globus_gram_protocol_unpack_status_update_message(
            buf,
            nbytes,
            &url,
            &job_status,
            &failure_code );
    }

    globus_libc_free(buf);

    rc = globus_gram_protocol_frame_reply( 200,
                                       GLOBUS_NULL,
                                       0,
                                       &reply,
                                       &replysize );
    
    globus_io_register_write( handle,
                              reply,
                              replysize,
                              globus_gram_protocol_close_after_write,
                              arg );

    globus_io_handle_get_user_pointer( handle,
                                       (void **) &userfunc );
    
    (userfunc)(arg, url, job_status, failure_code);

    globus_libc_free(url);
}             

