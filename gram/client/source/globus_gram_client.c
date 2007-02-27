/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include "globus_i_gram_client.h"
#include "globus_gram_protocol.h"
#include "globus_io.h"
#include "globus_rsl.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "version.h"

typedef
enum
{
    GLOBUS_GRAM_CLIENT_JOB_REQUEST,
    GLOBUS_GRAM_CLIENT_PING,
    GLOBUS_GRAM_CLIENT_STATUS,
    GLOBUS_GRAM_CLIENT_SIGNAL,
    GLOBUS_GRAM_CLIENT_CANCEL,
    GLOBUS_GRAM_CLIENT_CALLBACK_REGISTER,
    GLOBUS_GRAM_CLIENT_CALLBACK_UNREGISTER,
    GLOBUS_GRAM_CLIENT_RENEW
}
globus_l_gram_client_callback_type_t;

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_gram_protocol_handle_t	handle;
    globus_l_gram_client_callback_type_t
					type;
    volatile globus_bool_t		done;
    int					errorcode;

    /* For job request only */
    char *				contact;

    /* For job request / status */
    int					status;

    /* For job status only */
    int					job_failure_code;

    /* For register_job_request */
    globus_gram_client_nonblocking_func_t
					callback;
    void *				callback_arg;
} globus_l_gram_client_monitor_t;

typedef struct
{
    globus_gram_client_callback_func_t	callback;
    void *				callback_arg;
    char *				callback_contact;
}
globus_l_gram_client_callback_info_t;
/******************************************************************************
                          Module specific prototypes
******************************************************************************/

static
int
globus_l_gram_client_parse_gatekeeper_contact(
    const char *			contact_string,
    const char *			service_prefix,
    const char *                        username,
    char **				gatekeeper_url,
    char **				gatekeeper_dn);

static int 
globus_l_gram_client_setup_gatekeeper_attr(
    globus_io_attr_t *                     attrp,
    gss_cred_id_t                          credential,
    globus_io_secure_delegation_mode_t     delegation_mode,
    char *                                 gatekeeper_dn );

static int
globus_l_gram_client_setup_jobmanager_attr(
    globus_io_attr_t *                      attr,
    gss_cred_id_t                           credential);


static
int
globus_l_gram_client_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    globus_i_gram_client_attr_t *       iattr,
    const char *			callback_contact,
    globus_l_gram_client_monitor_t *	monitor);

static
int 
globus_l_gram_client_ping(
    const char *			resource_manager_contact,
    globus_i_gram_client_attr_t *       iattr,
    globus_l_gram_client_monitor_t *	monitor);

static
int
globus_l_gram_client_job_refresh_credentials(
    char *				job_contact,
    gss_cred_id_t			creds,
    globus_i_gram_client_attr_t *       iattr,
    globus_l_gram_client_monitor_t *	monitor);

static
void
globus_l_gram_client_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					errorcode,
    char *				uri);

static
void
globus_l_gram_client_monitor_callback(
    void *				user_arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri);

static
void
globus_l_gram_client_register_callback(
    void *				user_arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri);

static
int
globus_l_gram_client_monitor_init(
    globus_l_gram_client_monitor_t *	monitor,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

static
int
globus_l_gram_client_monitor_destroy(
    globus_l_gram_client_monitor_t *	monitor);

int
globus_i_gram_client_deactivate(void);

int
globus_i_gram_client_activate(void);
/******************************************************************************
                       Define module specific variables
******************************************************************************/

globus_module_descriptor_t globus_gram_client_module = 
{
    "globus_gram_client",
    globus_i_gram_client_activate,
    globus_i_gram_client_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static FILE *				globus_l_print_fp;
static int				globus_l_is_initialized = 0;
static globus_hashtable_t		globus_l_gram_client_contacts;

static globus_mutex_t		        globus_l_mutex;
static globus_mutex_t                   globus_l_rsl_mutex;

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

    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
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

        err = globus_mutex_init (&globus_l_rsl_mutex, NULL);
	assert (!err);

	globus_l_is_initialized = 1;

    }
    
    globus_l_print_fp = NULL;
    globus_hashtable_init(&globus_l_gram_client_contacts,
	                  16,
			  globus_hashtable_string_hash,
			  globus_hashtable_string_keyeq);


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

    rc = globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
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
    globus_hashtable_destroy(&globus_l_gram_client_contacts);

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


/******************************************************************************
Function:	globus_l_gram_client_parse_gatekeeper_url()
Description:
Parameters:
Returns:
******************************************************************************/
static
int
globus_l_gram_client_parse_gatekeeper_contact(
    const char *			contact_string,
    const char *			service_prefix,
    const char *                        username,
    char **				gatekeeper_url,
    char **				gatekeeper_dn)
{
    char *				duplicate;
    char *				host = GLOBUS_NULL;
    char *				port = GLOBUS_NULL;
    char *				dn = GLOBUS_NULL;
    char *				service;
    int					got_port = 0;
    int					got_service = 0;
    char *				ptr;
    unsigned short			iport;
    globus_url_t			some_struct;
    int                                 rc = GLOBUS_SUCCESS;

    /*
     *  the gatekeeper contact format: [https://]<host>:<port>[/<service>]:<dn>
     */    

    service = "jobmanager";
    iport = 2119;

    if ((duplicate = globus_libc_strdup(contact_string)))
    {
        host = duplicate;

        if (strncmp(duplicate,"https://", 8) == 0)
            host += 8;

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
	        if ((service = strchr(port,'/')) != NULL)
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
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto error_exit;
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

    (*gatekeeper_url) = globus_libc_malloc(11 /* https://:/\0 */ +
					   strlen(host) +
					   5 + /*unsigned short*/
					   strlen(service) +
					   ((service_prefix != GLOBUS_NULL)
					       ? strlen(service_prefix)
					       : 0) +
                                           ((username != NULL)
                                               ? strlen(username) + 1 : 0));

    if ((*gatekeeper_url) == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto free_duplicate_exit;
    }
    globus_libc_sprintf((*gatekeeper_url),
	                "https://%s:%hu%s/%s%s%s",
			host,
			(unsigned short) iport,
			((service_prefix != GLOBUS_NULL) ? service_prefix : ""),
			service,
                        (username != NULL) ? "@" : "",
                        (username != NULL) ? username : "");

    if (globus_url_parse(*gatekeeper_url, &some_struct) != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_GATEKEEPER_CONTACT;

        goto free_gatekeeper_url_exit;
    }
    globus_url_destroy(&some_struct);

    if ((dn) && (*dn))
    {
   	*gatekeeper_dn = globus_libc_strdup(dn);

        if((*gatekeeper_dn) == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto free_gatekeeper_url_exit;
        }
    }
    else
    {
   	*gatekeeper_dn = NULL;
    }
    globus_libc_free(duplicate);

    return rc;

free_gatekeeper_url_exit:
    globus_libc_free(*gatekeeper_url);
free_duplicate_exit:
    globus_libc_free(duplicate);
error_exit:

    return rc;
}


/*
 * globus_l_gram_client_setup_gatekeeper_attr()
 */
static int 
globus_l_gram_client_setup_gatekeeper_attr(
    globus_io_attr_t *                     attrp,
    gss_cred_id_t                          credential,
    globus_io_secure_delegation_mode_t     delegation_mode,
    char *                                 gatekeeper_dn )
{
    globus_result_t                        res;
    globus_io_secure_authorization_data_t  auth_data;

    res = globus_io_secure_authorization_data_initialize(&auth_data);
    if (res != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    res = globus_io_tcpattr_init(attrp);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_1;
    }
    res = globus_io_attr_set_socket_keepalive(attrp, GLOBUS_TRUE);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    
    res = globus_io_attr_set_secure_authentication_mode(
        attrp,
        GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL,
        (credential != GSS_C_NO_CREDENTIAL)
            ? credential 
            : globus_i_gram_protocol_credential);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    if(gatekeeper_dn)
    {
        res = globus_io_secure_authorization_data_set_identity(
            &auth_data,
            gatekeeper_dn);
        if (res != GLOBUS_SUCCESS)
        {
            goto destroy_2;
        }
    }
    res = globus_io_attr_set_secure_authorization_mode(
        attrp,
        gatekeeper_dn 
            ? GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY 
            : GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST,
        &auth_data);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    res = globus_io_attr_set_secure_delegation_mode(
        attrp,
        delegation_mode);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    res = globus_io_attr_set_secure_channel_mode(
        attrp,
        GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }

    globus_io_secure_authorization_data_destroy(&auth_data);

    return GLOBUS_SUCCESS;
    
destroy_2:
    globus_io_tcpattr_destroy(attrp);
destroy_1:
    globus_io_secure_authorization_data_destroy(&auth_data);
error_exit:
    if(globus_l_print_fp)
    {
        globus_libc_fprintf(globus_l_print_fp, 
            "setting up IO attributes failed\n");
    }
    globus_object_free(globus_error_get(res));
    
    return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
} /* globus_l_gram_client_setup_gatekeeper_attr() */

static int
globus_l_gram_client_setup_jobmanager_attr(
    globus_io_attr_t *                      attr,
    gss_cred_id_t                           credential)
{
    globus_result_t                        res;
    globus_io_secure_authorization_data_t  auth_data;

    res = globus_io_secure_authorization_data_initialize(&auth_data);
    if (res != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    res = globus_io_tcpattr_init(attr);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_1;
    }
    res = globus_io_attr_set_socket_keepalive(attr, GLOBUS_TRUE);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    res = globus_io_attr_set_secure_authentication_mode(
        attr,
        GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL,
        (credential != GSS_C_NO_CREDENTIAL)
            ? credential
            : globus_i_gram_protocol_credential);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    res = globus_io_attr_set_secure_authorization_mode(
        attr,
        GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
        &auth_data);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }
    res = globus_io_attr_set_secure_channel_mode(
        attr,
        GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP);
    if (res != GLOBUS_SUCCESS)
    {
        goto destroy_2;
    }

    globus_io_secure_authorization_data_destroy(&auth_data);

    return GLOBUS_SUCCESS;
    
destroy_2:
    globus_io_tcpattr_destroy(attr);
destroy_1:
    globus_io_secure_authorization_data_destroy(&auth_data);
error_exit:
    globus_object_free(globus_error_get(res));
    
    return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
} /* globus_l_gram_client_setup_jobmanager_attr() */

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


/*
 * globus_gram_client_set_credentials()
 */
int
globus_gram_client_set_credentials(gss_cred_id_t new_credentials)
{
    return globus_gram_protocol_set_credentials(new_credentials);
}


/**
 * Verify that a gatekeeper is running (nonblocking).
 * @ingroup globus_gram_client_job_functions
 *
 * Sends a specially-formated GRAM protocol message which checks to
 * see if a Globus Gatekeeper is running on a given PORT, and whether that
 * Gatekeeper is configured to support the desired job manager service.
 * This is primarily used for diagnostic purposes.
 *
 * If this function determines that the ping could not be processed before
 * contacting the gatekeeper (for example, a malformed
 * @a resource_manager_contact),  it will return an error, and the 
 * @a regiser_callback function will not be called.
 *
 * @param resource_manager_contact
 *        A NULL-terminated character string containing a
 *        @link globus_gram_resource_manager_contact GRAM contact@endlink.
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        The callback function to call when the ping request has
 *        completed. 
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if The gatekeeper contact is valid, the
 * client was able to authenticate with the Gatekeeper, and the Gatekeeper was
 * able to locate the requested service. Otherwise one of the
 * GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 */
int 
globus_gram_client_register_ping(
    const char *			resource_manager_contact,
    globus_gram_client_attr_t           attr,
    globus_gram_client_nonblocking_func_t
                                        register_callback,
    void *                              register_callback_arg)
{
    globus_i_gram_client_attr_t *       iattr = NULL;
    globus_l_gram_client_monitor_t *	monitor;
    int					rc;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));

    if(!monitor)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    iattr = (globus_i_gram_client_attr_t *) attr;

    globus_l_gram_client_monitor_init(
            monitor,
            register_callback,
            register_callback_arg);

    rc = globus_l_gram_client_ping(
            resource_manager_contact,
            iattr,
            monitor);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_l_gram_client_monitor_destroy(monitor);
        globus_libc_free(monitor);

    }
    return rc;
}
/* globus_gram_client_register_ping() */

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
 * This function returns GLOBUS_SUCCESS if The gatekeeper contact is valid, the
 * client was able to authenticate with the Gatekeeper, and the Gatekeeper was
 * able to locate the requested service. Otherwise one of the
 * GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 */
int 
globus_gram_client_ping(
    const char *			resource_manager_contact)
{
    int					rc;
    globus_l_gram_client_monitor_t	monitor;

    globus_l_gram_client_monitor_init(&monitor, NULL, NULL);

    rc = globus_l_gram_client_ping(
            resource_manager_contact,
            NULL,
            &monitor);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_l_gram_client_monitor_destroy(&monitor);

        return rc;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;

    globus_mutex_unlock(&monitor.mutex);

    globus_l_gram_client_monitor_destroy(&monitor);

    return rc;
}
/* globus_gram_client_ping() */


/**
 * Request a job be started (nonblocking).
 * @ingroup globus_gram_client_job_functions
 *
 * Request access to interactive resources at the current time. A job request
 * is atomic: either all of the requested processes are created, or none are
 * created.  This is the nonblocking version of
 * globus_gram_client_job_request(). Instead of waiting for the job manager
 * to acknowledge that the job has been submitted or started, this function
 * immediately returns after beginning the job submission. The
 * @a register_callback function will be called to let the caller know whether
 * the job request has been submitted successfully or not.
 *
 * If this function determines that the job request could not be processed
 * before contacting the job manager (for example, a malformed 
 * @a resource_manager_contact) it will return an error, and the
 * @a register_callback function will not be called.
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
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        The callback function to call when the job request submission has
 *        completed. This function will be passed a copy of the job_contact
 *        which the user must free, and an error code (the job status 
 *        value is undefined).
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful,
 * otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 *
 * @see @ref globus_gram_resource_manager_contact
 * @see globus_gram_client_job_request()
 */
int
globus_gram_client_register_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    const char *			callback_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    globus_i_gram_client_attr_t *       iattr = NULL;
    globus_l_gram_client_monitor_t *	monitor;
    int					rc;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));
    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    iattr = (globus_i_gram_client_attr_t *) attr;

    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    rc = globus_l_gram_client_job_request(resource_manager_contact,
	                                  description,
				          job_state_mask,
                                          iattr,
				          callback_contact,
				          monitor);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }
    return rc;
}
/* globus_gram_client_register_job_request() */

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
globus_gram_client_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    const char *			callback_contact,
    char **				job_contact)
{
    int					rc;
    globus_l_gram_client_monitor_t	monitor;

    if(job_contact)
    {
	*job_contact = GLOBUS_NULL;
    }

    globus_l_gram_client_monitor_init(&monitor,
	                              GLOBUS_NULL,
				      GLOBUS_NULL);

    rc = globus_l_gram_client_job_request(resource_manager_contact,
	                                  description,
					  job_state_mask,
                                          NULL,
					  callback_contact,
					  &monitor);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(&monitor);

	return rc;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    if(job_contact)
    {
	*job_contact = globus_libc_strdup(monitor.contact);
    }
    globus_mutex_unlock(&monitor.mutex);

    globus_l_gram_client_monitor_destroy(&monitor);

    return rc;
}
/* globus_gram_client_job_request() */

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
globus_l_gram_client_to_jobmanager(
    const char *			job_contact,
    const char *			request,
    globus_i_gram_client_attr_t *       iattr,
    globus_l_gram_client_callback_type_t
    					request_type,
    globus_l_gram_client_monitor_t *	monitor)
{
    int					rc;
    globus_byte_t *			query = GLOBUS_NULL; 
    globus_size_t			querysize;
    globus_io_attr_t                    attr;
    globus_bool_t                       use_attr = GLOBUS_FALSE;

    if (iattr != NULL && iattr->credential != GSS_C_NO_CREDENTIAL)
    {
        rc = globus_l_gram_client_setup_jobmanager_attr( 
	             &attr,
                     iattr->credential);
        if (rc != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
        use_attr = GLOBUS_TRUE;
    }
    rc = globus_gram_protocol_pack_status_request(
	      request,
	      &query,
	      &querysize);

    if (rc!=GLOBUS_SUCCESS)
    {
	goto free_attr_exit;
    }
    
    globus_mutex_lock(&monitor->mutex);
    monitor->type = request_type;

    rc = globus_gram_protocol_post(
	         job_contact,
		 &monitor->handle,
		 use_attr ? &attr : NULL,
		 query,
		 querysize,
		 (monitor->callback != GLOBUS_NULL) 
		    ? globus_l_gram_client_register_callback
		    : globus_l_gram_client_monitor_callback,
		 monitor);

    globus_mutex_unlock(&monitor->mutex);

    if(rc != GLOBUS_SUCCESS)
    {
        if(rc == GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER;
	    monitor->errorcode =
		GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER;
	}
    }

    if(query)
    {
	globus_libc_free(query);
    }
free_attr_exit:
    if(use_attr)
    {
        globus_io_tcpattr_destroy (&attr);
    }
error_exit:
    return rc;
}
/* globus_l_gram_client_to_jobmanager() */

/**
 * Cancel a GRAM-managed job.
 * @ingroup globus_gram_client_job_functions
 *
 * Removes a @a PENDING job request, or kills all processes associated
 * with an @a ACTIVE job, releasing any associated resources
 *
 * @param  job_contact
 *         The job contact string of the job to contact. This is the same
 *         value returned from globus_gram_client_job_request() or
 *         globus_gram_client_register_job_request().
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the cancellation
 *         was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_*
 *         values will be returned, indicating why the client could not cancel
 *         the job.
 *
 * @see globus_gram_client_register_job_cancel()
 */
int
globus_gram_client_job_cancel(
    const char *			job_contact)
{
    int                           	rc;
    globus_l_gram_client_monitor_t	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    globus_l_gram_client_monitor_init(&monitor,
	                              GLOBUS_NULL,
				      GLOBUS_NULL);

    rc = globus_l_gram_client_to_jobmanager( job_contact,
	    				     "cancel",
                                             NULL,
					     GLOBUS_GRAM_CLIENT_CANCEL,
					     &monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(&monitor);

	return rc;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;

    globus_mutex_unlock(&monitor.mutex);

    globus_l_gram_client_monitor_destroy(&monitor);

    return rc;
}
/* globus_gram_client_job_cancel() */

/**
 * Nonblocking cancel of a GRAM-managed job.
 * @ingroup globus_gram_client_job_functions
 *
 * Removes a @a PENDING job request, or kills all processes associated
 * with an @a ACTIVE job, releasing any associated resources
 *
 * @param  job_contact
 *         The job contact string of the job to contact. This is the same
 *         value returned from globus_gram_client_job_request() or
 *         globus_gram_client_register_job_request().
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        The callback function to call when the job request cancel has
 *        completed. 
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful,
 * otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 *
 * @see globus_gram_client_job_cancel()
 */
int
globus_gram_client_register_job_cancel(
    const char *			job_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    int                           	rc;
    globus_l_gram_client_monitor_t *	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));

    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    rc = globus_l_gram_client_to_jobmanager( job_contact,
	    				     "cancel",
                                             (globus_i_gram_client_attr_t*)attr,
					     GLOBUS_GRAM_CLIENT_CANCEL,
					     monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }
    return rc;
}
/* globus_gram_client_register_job_cancel() */

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
 * @return
 *         This function returns GLOBUS_SUCCESS if the signal
 *         was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_*
 *         values will be returned, indicating why the client could not signal
 *         the job.
 *
 * @see globus_gram_client_register_job_signal()
 */
int 
globus_gram_client_job_signal(
    const char  *			job_contact,
    globus_gram_protocol_job_signal_t	signal,
    const char *			signal_arg,
    int *				job_status,
    int *				failure_code)
{
    int       rc;
    char  *   request;
    globus_l_gram_client_monitor_t	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    globus_l_gram_client_monitor_init(&monitor,
	                              GLOBUS_NULL,
				      GLOBUS_NULL);

    if (signal_arg != NULL)
    {
	/* 'signal' = 6, allow 10-digit integer, 2 spaces and null  */
	request = (char *) globus_libc_malloc( strlen(signal_arg)
					       + 6 + 10 + 2 + 1 );
        if (request == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto error_exit;
        }

	globus_libc_sprintf(request,
			    "signal %d %s",
			    signal,
			    signal_arg);
    }
    else
    {
	/* 'signal' = 6, allow 10-digit integer, 1 space and null  */
	request = (char *) globus_libc_malloc( 6 + 10 + 1 + 1 );
        if (request == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto error_exit;
        }

	globus_libc_sprintf(request,
			    "signal %d",
			    signal);
    }

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     request,
                                             NULL,
					     GLOBUS_GRAM_CLIENT_SIGNAL,
					     &monitor);
    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;

    globus_mutex_unlock(&monitor.mutex);

error_exit:
    if(job_status)
    {
	*job_status = monitor.status;
    }
    if(failure_code)
    {
	*failure_code = monitor.errorcode ?
	    monitor.errorcode :
	    monitor.job_failure_code;
    }
    globus_l_gram_client_monitor_destroy(&monitor);
    if (request != NULL)
    {
        globus_libc_free(request);
    }

    return rc;
}
/* globus_gram_client_job_signal() */

/**
 * Nonblocking signal a job manager.
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
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        The callback function to call when the job signal has
 *        completed. 
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful,
 * otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR values is returned.
 */
int 
globus_gram_client_register_job_signal(
    const char  *			job_contact,
    globus_gram_protocol_job_signal_t	signal,
    const char *			signal_arg,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    int					rc;
    char *				request;
    globus_l_gram_client_monitor_t *	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));
    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    if (signal_arg != NULL)
    {
	/* 'signal' = 6, allow 10-digit integer, 2 spaces and null  */
	request = (char *) globus_libc_malloc( strlen(signal_arg)
					       + 6 + 10 + 2 + 1 );
        if (request == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto error_exit;
        }

	globus_libc_sprintf(request,
			    "signal %d %s",
			    signal,
			    signal_arg);
    }
    else
    {
	/* 'signal' = 6, allow 10-digit integer, 1 space and null  */
	request = (char *) globus_libc_malloc( 6 + 10 + 1 + 1 );
        if (request == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto error_exit;
        }

	globus_libc_sprintf(request,
			    "signal %d",
			    signal);
    }

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     request,
                                             attr,
					     GLOBUS_GRAM_CLIENT_SIGNAL,
					     monitor);
    globus_libc_free(request);
error_exit:
    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }

    return rc;
}
/* globus_gram_client_register_job_signal() */

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
globus_gram_client_job_status(
    const char *			job_contact,
    int *				job_status,
    int *				failure_code)
{
    int					rc;
    globus_l_gram_client_monitor_t 	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    globus_l_gram_client_monitor_init(&monitor,
	                              GLOBUS_NULL,
				      GLOBUS_NULL);

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     "status",
                                             NULL,
					     GLOBUS_GRAM_CLIENT_STATUS,
					     &monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;

    globus_mutex_unlock(&monitor.mutex);

error_exit:
    if(job_status)
    {
	*job_status = monitor.status;
    }
    if(failure_code)
    {
	*failure_code = monitor.errorcode ?
	    monitor.errorcode :
	    monitor.job_failure_code;
    }
    globus_l_gram_client_monitor_destroy(&monitor);

    return rc;
}
/* globus_gram_client_job_status() */

/**
 * Nonblocking query of a job's status.
 * @ingroup globus_gram_client_job_functions
 *
 * This function queries the status of the job associated with the job contact,
 * returning it's current job status and job failure reason if it has failed.
 *
 * @param job_contact
 *        The job contact string of the job to query. This is the same
 *        value returned from globus_gram_client_job_request().
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        Callback function to be called when the job status query has
 *        been processed.
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return This function returns GLOBUS_SUCCESS if the job state query was
 * successfully. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values will
 * be returned, indicating why the client could not query the job state.
 */
int
globus_gram_client_register_job_status(
    const char *			job_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    int					rc;
    globus_l_gram_client_monitor_t * 	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));
    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    rc = globus_l_gram_client_to_jobmanager( job_contact,
					     "status",
                                             attr,
					     GLOBUS_GRAM_CLIENT_STATUS,
					     monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }
    return rc;
}
/* globus_gram_client_register_job_status() */

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
 * @param job_status
 *        A pointer to an integer which will be populated with the current
 *        status of the job. This will be one of the
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_* values if this function is
 *        successful.
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
globus_gram_client_job_callback_register(
    const char *			job_contact,
    int					job_state_mask,
    const char *			callback_contact,
    int *				job_status,
    int *				failure_code)
{
    int					rc;
    char  *				request;
    globus_l_gram_client_monitor_t	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;
    globus_l_gram_client_monitor_init(&monitor, GLOBUS_NULL, GLOBUS_NULL);

    /* 'register' = 8, allow 10-digit integer, 2 spaces and null  */
    request = (char *) globus_libc_malloc( 
	                  strlen(callback_contact)
			  + 8 + 10 + 2 + 1 );

    if (request == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto error_exit;
    }

    globus_libc_sprintf(request,
			"register %d %s",
			job_state_mask,
			callback_contact);

    rc = globus_l_gram_client_to_jobmanager(
	    job_contact,
	    request,
            NULL,
	    GLOBUS_GRAM_CLIENT_CALLBACK_REGISTER,
	    &monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;

    globus_mutex_unlock(&monitor.mutex);

error_exit:
    if(job_status)
    {
	*job_status = monitor.status;
    }
    if(failure_code)
    {
	*failure_code = monitor.errorcode ?
	    monitor.errorcode :
	    monitor.job_failure_code;
    }
    globus_l_gram_client_monitor_destroy(&monitor);
    if (request != NULL)
    {
        globus_libc_free(request);
    }

    return rc;
}
/* globus_gram_client_job_callback_register() */

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
 * @param job_status
 *        A pointer to an integer which will be populated with the current
 *        status of the job. This will be one of the
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_* values if this function is
 *        successful.
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
globus_gram_client_job_callback_unregister(
    const char *			job_contact,
    const char *			callback_contact,
    int *				job_status,
    int *				failure_code)
{
    int					rc;
    char *				request;
    globus_l_gram_client_monitor_t	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    globus_l_gram_client_monitor_init(&monitor, GLOBUS_NULL, GLOBUS_NULL);

    /* 'unregister' = 10, a space and null  */
    request = (char *) globus_libc_malloc( 
	                  strlen(callback_contact)
			  + 10 + 1 + 1 );

    if (request == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto error_exit;
    }

    globus_libc_sprintf(request,
			"unregister %s",
			callback_contact);

    rc = globus_l_gram_client_to_jobmanager(
	    job_contact,
	    request,
            NULL,
	    GLOBUS_GRAM_CLIENT_CALLBACK_UNREGISTER,
	    &monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;

    globus_mutex_unlock(&monitor.mutex);

error_exit:
    if(job_status)
    {
	*job_status = monitor.status;
    }
    if(failure_code)
    {
	*failure_code = monitor.errorcode ?
	    monitor.errorcode :
	    monitor.job_failure_code;
    }
    globus_l_gram_client_monitor_destroy(&monitor);

    if (request != NULL)
    {
        globus_libc_free(request);
    }

    return rc;
}
/* globus_gram_client_job_callback_unregister() */

/**
 * Delegate new credentials to a job manager.
 * @ingroup globus_gram_client_job_functions
 *
 * This function performs a new delegation handshake with the job
 * manager, updating it with a new user proxy. This will allow the job
 * manager to continue to send job state callbacks after the original
 * proxy would have expired.
 *
 * @param job_contact
 *        The job contact string of the job manager to contact. This is the
 *        same value returned from globus_gram_client_job_request().
 * @param creds
 *        A credential which should be used to contact the job manager. This
 *        may be GSS_C_NO_CREDENTIAL to use the process's default
 *        credential.
 *
 * @return This function returns GLOBUS_SUCCESS if the delegation
 * was successful. Otherwise one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values
 * will be returned, indicating why the client could not unregister the
 * callback contact.
 */
int
globus_gram_client_job_refresh_credentials(
    char *				job_contact,
    gss_cred_id_t			creds)
{
    globus_l_gram_client_monitor_t	monitor;
    int					rc;

    globus_l_gram_client_monitor_init(&monitor,
	                              GLOBUS_NULL,
				      GLOBUS_NULL);

    rc = globus_l_gram_client_job_refresh_credentials(
	    job_contact,
	    creds,
            NULL,
	    &monitor);

    if (rc != GLOBUS_SUCCESS)
    {
	goto end;
    }

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = monitor.errorcode;
    globus_mutex_unlock(&monitor.mutex);

end:
    globus_l_gram_client_monitor_destroy(&monitor);

    return rc;
}
/* globus_gram_client_job_refresh_credentials() */

/**
 * Delegate new credentials to a job manager (nonblocking).
 * @ingroup globus_gram_client_job_functions
 *
 * This function performs the same operation as globus_gram_client_job_refresh_credentials(), but without blocking the calling thread. Once the delegation
 * has completed, it's final status will be reported in the
 * @a register_callback.
 *
 * @param job_contact
 *        The job contact string of the job manager to contact. This is the
 *        same value returned from globus_gram_client_job_request().
 * @param creds
 *        A credential which should be used to contact the job manager. This
 *        may be GSS_C_NO_CREDENTIAL to use the process's default
 *        credential.
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        Callback function to be called when the job refresh has
 *        been processed.
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 */
int
globus_gram_client_register_job_refresh_credentials(
    char *				job_contact,
    gss_cred_id_t			creds,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    globus_l_gram_client_monitor_t *	monitor;
    int					rc;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));

    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    rc = globus_l_gram_client_job_refresh_credentials(
	    job_contact,
	    creds,
            attr,
	    monitor);

    if (rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }

    return rc;
}
/**
 * Nonblocking register a callback contact for job state changes.
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
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        The callback function to call when the job signal has
 *        completed. 
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return This function returns GLOBUS_SUCCESS if the successfull, otherwise
 * one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values
 * will be returned, indicating why the operation failed.
 *
 * @see globus_gram_client_job_callback_register()
 */
int 
globus_gram_client_register_job_callback_registration(
    const char *			job_contact,
    int					job_state_mask,
    const char *			callback_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    int					rc;
    char  *				request;
    globus_l_gram_client_monitor_t *	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));
    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    /* 'register' = 8, allow 10-digit integer, 2 spaces and null  */
    request = (char *) globus_libc_malloc( 
	                  strlen(callback_contact)
			  + 8 + 10 + 2 + 1 );

    if (request == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto error_exit;
    }

    globus_libc_sprintf(request,
			"register %d %s",
			job_state_mask,
			callback_contact);

    rc = globus_l_gram_client_to_jobmanager(
	    job_contact,
	    request,
            NULL,
	    GLOBUS_GRAM_CLIENT_CALLBACK_REGISTER,
	    monitor);

error_exit:
    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }

    if(request != NULL)
    {
        globus_libc_free(request);
    }

    return rc;
}
/* globus_gram_client_register_job_callback_registration() */

/**
 * Nonblocking unregistration of a callback contact.
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
 * @param attr
 *        Client attributes to be used. Should be set to
 *        GLOBUS_GRAM_CLIENT_NO_ATTR if no attributes are to be used.
 * @param register_callback
 *        The callback function to call when the job signal has
 *        completed. 
 * @param register_callback_arg
 *        A pointer to user data which will be passed to the callback as
 *        it's @a user_callback_arg.
 *
 * @return This function returns GLOBUS_SUCCESS if the successfull, otherwise
 * one of the GLOBUS_GRAM_PROTOCOL_ERROR_* values
 * will be returned, indicating why the operation failed.
 *
 * @see globus_gram_client_job_callback_unregister()
 */
int 
globus_gram_client_register_job_callback_unregistration(
    const char *			job_contact,
    const char *			callback_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    int					rc;
    char *				request;
    globus_l_gram_client_monitor_t *	monitor;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    monitor = globus_libc_malloc(sizeof(globus_l_gram_client_monitor_t));
    if(!monitor)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    globus_l_gram_client_monitor_init(monitor,
	                              register_callback,
				      register_callback_arg);

    /* 'unregister' = 10, a space and null  */
    request = (char *) globus_libc_malloc( 
	                  strlen(callback_contact)
			  + 10 + 1 + 1 );
    if (request == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto error_exit;
    }

    globus_libc_sprintf(request,
			"unregister %s",
			callback_contact);

    rc = globus_l_gram_client_to_jobmanager(
	    job_contact,
	    request,
            attr,
	    GLOBUS_GRAM_CLIENT_CALLBACK_UNREGISTER,
	    monitor);

error_exit:
    if(rc != GLOBUS_SUCCESS)
    {
	globus_l_gram_client_monitor_destroy(monitor);
	globus_libc_free(monitor);
    }
    if(request != NULL)
    {
        globus_libc_free(request);
    }

    return rc;
}
/* globus_gram_client_register_job_callback_unregistration() */

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
    int					rc;
    globus_l_gram_client_callback_info_t *
					callback_info;

    GLOBUS_L_CHECK_IF_INITIALIZED;

    if (callback_contact == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;
    }

    *callback_contact = NULL;

    callback_info = globus_libc_malloc(
	                sizeof(globus_l_gram_client_callback_info_t));

    if (callback_info == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto error_exit;
    }

    callback_info->callback = callback_func;
    callback_info->callback_arg = user_callback_arg;

    rc = globus_gram_protocol_allow_attach(
	    &callback_info->callback_contact,
	    globus_l_gram_client_callback,
	    callback_info);

    if (rc != GLOBUS_SUCCESS)
    {
        goto free_callback_info_exit;
    }

    globus_mutex_lock(&globus_l_mutex);
    rc = globus_hashtable_insert(&globus_l_gram_client_contacts,
	                    callback_info->callback_contact,
	                    callback_info);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto disallow_exit;
    }
    globus_mutex_unlock(&globus_l_mutex);

    *callback_contact = globus_libc_strdup(callback_info->callback_contact);

    if (*callback_contact == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto remove_from_hashtable_exit;
    }
    return rc;

remove_from_hashtable_exit:
    globus_mutex_lock(&globus_l_mutex);
    globus_hashtable_remove(&globus_l_gram_client_contacts,
            (void *) callback_info->callback_contact);
    globus_mutex_unlock(&globus_l_mutex);

disallow_exit:
    globus_gram_protocol_callback_disallow(callback_info->callback_contact);
    globus_libc_free(callback_info->callback_contact);
free_callback_info_exit:
    globus_libc_free(callback_info);

error_exit:
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
globus_gram_client_callback_disallow(
    char *				callback_contact)
{
    int					rc;
    globus_l_gram_client_callback_info_t *
					callback_info;

    globus_mutex_lock(&globus_l_mutex);

    callback_info = globus_hashtable_remove(
	    &globus_l_gram_client_contacts,
	    (void *) callback_contact);

    globus_mutex_unlock(&globus_l_mutex);

    if(callback_info != GLOBUS_NULL)
    {
	rc = globus_gram_protocol_callback_disallow(callback_contact);

	globus_libc_free(callback_info->callback_contact);
	globus_libc_free(callback_info);
    }
    else
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_CALLBACK_NOT_FOUND;
    }

    return rc;
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
globus_gram_client_job_contact_free(
    char *				job_contact)
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
int
globus_l_gram_client_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    globus_i_gram_client_attr_t *       iattr,
    const char *			callback_contact,
    globus_l_gram_client_monitor_t *	monitor)
{
    int					rc;
    globus_byte_t *			query = GLOBUS_NULL;
    globus_size_t			querysize; 
    globus_io_attr_t			attr;
    char *				url;
    char *				dn;
    globus_rsl_t *                      rsl;
    char *                              username = NULL;

    /* The lexer used by the RSL Parser is not reentrant. The lex source
     * is somewhat lost from the rest of CVS, so we can't fix that directly.
     */
    globus_mutex_lock(&globus_l_rsl_mutex);
    rsl = globus_rsl_parse((char *) description);
    globus_mutex_unlock(&globus_l_rsl_mutex);

    if (rsl != NULL)
    {
        char **                         username_value = NULL;
        rc = globus_rsl_param_get(
                rsl,
                GLOBUS_RSL_PARAM_SINGLE_LITERAL,
                GLOBUS_GRAM_PROTOCOL_USER_NAME,
                &username_value);

        if (rc == 0 && username_value != NULL && username_value[0] != NULL)
        {
            username = globus_libc_strdup(username_value[0]);
        }

        if (username_value != NULL)
        {
            globus_libc_free(username_value);
        }

        globus_rsl_free_recursive(rsl);
        rsl = NULL;
    }

    if ((rc = globus_l_gram_client_parse_gatekeeper_contact(
	             resource_manager_contact,
		     GLOBUS_NULL,
                     username,
		     &url,
		     &dn )) != GLOBUS_SUCCESS)
    {
	goto globus_gram_client_job_request_parse_failed;
    }

    if ((rc = globus_l_gram_client_setup_gatekeeper_attr( 
	             &attr,
                     (iattr != NULL)
                         ? iattr->credential : GSS_C_NO_CREDENTIAL,
		     (iattr != NULL)
                         ? iattr->delegation_mode
                         : GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY,
		     dn )) != GLOBUS_SUCCESS)
    {
        goto globus_gram_client_job_request_attr_failed;
    }

    if ((rc = globus_gram_protocol_pack_job_request(
	             job_state_mask,
		     callback_contact,
		     description,
		     &query,
		     &querysize)) != GLOBUS_SUCCESS )
    {
	goto globus_gram_client_job_request_pack_failed;
    }

    globus_mutex_lock(&monitor->mutex);
    monitor->type = GLOBUS_GRAM_CLIENT_JOB_REQUEST;
    rc = globus_gram_protocol_post(
	         url,
		 &monitor->handle,
		 &attr,
		 query,
		 querysize,
		 (monitor->callback != GLOBUS_NULL)
		     ?  globus_l_gram_client_register_callback
		     : globus_l_gram_client_monitor_callback,
		 monitor);
    globus_mutex_unlock(&monitor->mutex);

    if (query)
	globus_libc_free(query);

globus_gram_client_job_request_pack_failed:
    globus_io_tcpattr_destroy (&attr);

globus_gram_client_job_request_attr_failed:
    globus_libc_free(url);
    if (dn)
        globus_libc_free(dn);

globus_gram_client_job_request_parse_failed:
    return rc;
}
/* globus_l_gram_client_job_request() */

static
int 
globus_l_gram_client_ping(
    const char *			resource_manager_contact,
    globus_i_gram_client_attr_t *       iattr,
    globus_l_gram_client_monitor_t *	monitor)
{
    int					rc;
    char *                              url;
    char *                              dn;
    globus_io_attr_t                    attr;

    rc = globus_l_gram_client_parse_gatekeeper_contact(
	resource_manager_contact,
	"ping",
        NULL,
	&url,
	&dn );

    if (rc != GLOBUS_SUCCESS)
    {
	goto globus_gram_client_ping_parse_failed;
    }

    rc = globus_l_gram_client_setup_gatekeeper_attr( 
	&attr,
        (iattr != NULL) ? iattr->credential : GSS_C_NO_CREDENTIAL,
	GLOBUS_IO_SECURE_DELEGATION_MODE_NONE,
	dn );

    if (rc != GLOBUS_SUCCESS)
    {
	goto globus_gram_client_ping_attr_failed;
    }

    globus_mutex_lock(&monitor->mutex);
    monitor->type = GLOBUS_GRAM_CLIENT_PING;

    rc = globus_gram_protocol_post(
	         url,
		 &monitor->handle,
		 &attr,
		 GLOBUS_NULL,
		 0,
                 (monitor->callback != NULL)
                     ? globus_l_gram_client_register_callback
                     : globus_l_gram_client_monitor_callback,
                 monitor);
    globus_mutex_unlock(&monitor->mutex);

    globus_io_tcpattr_destroy (&attr);

globus_gram_client_ping_attr_failed:
    globus_libc_free(url);
    if (dn)
        globus_libc_free(dn);

globus_gram_client_ping_parse_failed:
    return rc;
}
/* globus_l_gram_client_ping() */

static
int
globus_l_gram_client_job_refresh_credentials(
    char *				job_contact,
    gss_cred_id_t			creds,
    globus_i_gram_client_attr_t *       attr,
    globus_l_gram_client_monitor_t *	monitor)
{
    int					rc;
    globus_byte_t *			query = GLOBUS_NULL;
    globus_size_t			querysize;
    OM_uint32                           reqflags = 0;

    globus_mutex_lock(&monitor->mutex);

    if (attr)
    {
        switch (attr->delegation_mode)
        {
            case GLOBUS_IO_SECURE_DELEGATION_MODE_NONE:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_DELEGATION_FAILED;
                goto end;
            case GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY:
                reqflags = GSS_C_DELEG_FLAG |
                           GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG; 
                break;
            case GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY:
                reqflags = GSS_C_DELEG_FLAG;
                break;
        }
    }
    else
    {
        reqflags = GSS_C_DELEG_FLAG | GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG; 
    }
    reqflags |= GSS_C_GLOBUS_SSL_COMPATIBLE;

    monitor->type = GLOBUS_GRAM_CLIENT_RENEW;

    rc = globus_gram_protocol_pack_status_request(
	 "renew",
	 &query,
	 &querysize);

    if (rc!=GLOBUS_SUCCESS)
      goto end;

    /* Send the request to the job manager, if successful, delegate a
     * credential to the job manager. call back when all is done.
     */
    rc = globus_gram_protocol_post_delegation(
	 job_contact,
	 &monitor->handle,
	 GLOBUS_NULL,
	 query,
	 querysize,
	 creds,
	 GSS_C_NO_OID_SET,
	 GSS_C_NO_BUFFER_SET,
         reqflags,
	 0,
	 (monitor->callback != GLOBUS_NULL)
	     ?  globus_l_gram_client_register_callback
	     : globus_l_gram_client_monitor_callback,
	 monitor);

    if(query)
    {
	globus_libc_free(query);
    }

end:
    globus_mutex_unlock(&monitor->mutex);

    return rc;
}
/* globus_l_gram_client_job_refresh_credentials() */

static
void
globus_l_gram_client_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					errorcode,
    char *				uri)
{
    globus_l_gram_client_callback_info_t *
					info;
    char *				url;
    int					job_status;
    int					failure_code;
    int					rc;
    gss_ctx_id_t                        context;

    info = arg;
    
    rc = errorcode;

    if (rc != GLOBUS_SUCCESS || nbytes <= 0)
    {
        job_status   = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        failure_code = rc;
    }
    else
    {
        if(globus_gram_protocol_get_sec_context(handle,
                                                &context))
        {
            job_status   = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;
        }
        else if(context != GSS_C_NO_CONTEXT &&
                globus_gram_protocol_authorize_self(context)
                == GLOBUS_FALSE)
        {
            job_status   = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;
        }
        else
        { 
            rc = globus_gram_protocol_unpack_status_update_message(
                buf,
                nbytes,
                &url,
                &job_status,
                &failure_code);
        }
    }

    rc = globus_gram_protocol_reply(handle,
	                            200,
				    GLOBUS_NULL,
				    0);
    
    info->callback(info->callback_arg,
	           url,
		   job_status,
		   failure_code);

    globus_libc_free(url);
}

static
void
globus_l_gram_client_monitor_callback(
    void *				user_arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri)
{
    globus_l_gram_client_monitor_t *	monitor;
    int					rc;

    monitor = user_arg;

    globus_mutex_lock(&monitor->mutex);

    monitor->errorcode = errorcode;
    monitor->done = GLOBUS_TRUE;

    /* 
     * Connection failed error means "couldn't connect to gatekeeper". For
     * non-job request messages, we were talking to the job manager, so we'll
     * map to another error.
     */
    if(monitor->errorcode == GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED &&
       monitor->type != GLOBUS_GRAM_CLIENT_JOB_REQUEST)
    {
	monitor->errorcode = GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER;
    }

    if(!errorcode)
    {
	switch(monitor->type)
	{
	  case GLOBUS_GRAM_CLIENT_JOB_REQUEST:
	    rc = globus_gram_protocol_unpack_job_request_reply(
		    message,
		    msgsize,
		    &monitor->status,
		    &monitor->contact);
	    if(rc != GLOBUS_SUCCESS)
	    {
		monitor->errorcode = rc;
	    }
	    else
	    {
		monitor->errorcode = monitor->status;
	    }
	    break;

	  case GLOBUS_GRAM_CLIENT_PING:
	  case GLOBUS_GRAM_CLIENT_RENEW:
	    break;
	  case GLOBUS_GRAM_CLIENT_STATUS:
	  case GLOBUS_GRAM_CLIENT_SIGNAL:
	  case GLOBUS_GRAM_CLIENT_CANCEL:
	  case GLOBUS_GRAM_CLIENT_CALLBACK_REGISTER:
	  case GLOBUS_GRAM_CLIENT_CALLBACK_UNREGISTER:
	    rc = globus_gram_protocol_unpack_status_reply(
		    message,
		    msgsize,
		    &monitor->status,
		    &monitor->errorcode,
		    &monitor->job_failure_code);
	    if(rc != GLOBUS_SUCCESS)
	    {
		monitor->errorcode = rc;
	    }
	    break;
	}
    }
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_gram_client_monitor_callback() */

static
void
globus_l_gram_client_register_callback(
    void *				user_arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri)
{
    globus_l_gram_client_monitor_t *	monitor;
    int					rc;

    monitor = user_arg;

    globus_mutex_lock(&monitor->mutex);

    monitor->status = 0;
    monitor->job_failure_code = 0;
    monitor->errorcode = errorcode;
    monitor->done = GLOBUS_TRUE;

    /* 
     * Connection failed error means "couldn't connect to gatekeeper". For
     * non-job request messages, we were talking to the job manager, so we'll
     * map to another error.
     */
    if(monitor->errorcode == GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED &&
       monitor->type != GLOBUS_GRAM_CLIENT_JOB_REQUEST)
    {
	monitor->errorcode = GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER;
    }
    if(!errorcode)
    {
	switch(monitor->type)
	{
	  case GLOBUS_GRAM_CLIENT_JOB_REQUEST:
	    rc = globus_gram_protocol_unpack_job_request_reply(
		    message,
		    msgsize,
		    &monitor->errorcode,
		    &monitor->contact);
	    if(rc != GLOBUS_SUCCESS)
	    {
		monitor->errorcode = rc;
	    }
	    break;

	  case GLOBUS_GRAM_CLIENT_PING:
	  case GLOBUS_GRAM_CLIENT_RENEW:
	    break;
	  case GLOBUS_GRAM_CLIENT_STATUS:
	  case GLOBUS_GRAM_CLIENT_SIGNAL:
	  case GLOBUS_GRAM_CLIENT_CANCEL:
	  case GLOBUS_GRAM_CLIENT_CALLBACK_REGISTER:
	  case GLOBUS_GRAM_CLIENT_CALLBACK_UNREGISTER:
	    rc = globus_gram_protocol_unpack_status_reply(
		    message,
		    msgsize,
		    &monitor->status,
		    &monitor->errorcode,
		    &monitor->job_failure_code);
	    if(rc != GLOBUS_SUCCESS)
	    {
		monitor->errorcode = rc;
	    }
	    break;
	}
    }

    globus_mutex_unlock(&monitor->mutex);

    monitor->callback(monitor->callback_arg,
	              monitor->errorcode,
	              monitor->contact,
		      monitor->status,
		      monitor->job_failure_code);

    globus_l_gram_client_monitor_destroy(monitor);
    globus_libc_free(monitor);
}
/* globus_l_gram_client_register_callback() */

static
int
globus_l_gram_client_monitor_init(
    globus_l_gram_client_monitor_t *	monitor,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg)
{
    memset(monitor, '\0', sizeof(globus_l_gram_client_monitor_t));

    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->cond, GLOBUS_NULL);
    monitor->done = GLOBUS_FALSE;
    monitor->callback = register_callback;
    monitor->callback_arg = register_callback_arg;

    return GLOBUS_SUCCESS;
}
/* globus_l_gram_client_monitor_init() */

static
int
globus_l_gram_client_monitor_destroy(
    globus_l_gram_client_monitor_t *	monitor)
{

    if (monitor->contact != GLOBUS_NULL)
    {
        globus_gram_client_job_contact_free(monitor->contact);
        monitor->contact = GLOBUS_NULL;
    }

    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);

    return GLOBUS_SUCCESS;
}
/* globus_l_gram_client_monitor_destroy() */
