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
 * @file globus_gram_protocol.c
 * @brief GRAM Protocol
 */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#include "globus_i_gram_protocol.h"
#include "version.h"

/**
 * @defgroup globus_gram_protocol_functions Functions
 * @ingroup globus_gram_protocol
 * @brief GRAM Functions
 */
gss_cred_id_t				globus_i_gram_protocol_credential;
globus_mutex_t				globus_i_gram_protocol_mutex;
globus_cond_t				globus_i_gram_protocol_cond;

globus_list_t *				globus_i_gram_protocol_listeners;
globus_list_t *				globus_i_gram_protocol_connections;
globus_list_t *				globus_i_gram_protocol_old_creds;
globus_bool_t 				globus_i_gram_protocol_shutdown_called;
globus_io_attr_t			globus_i_gram_protocol_default_attr;
int					globus_i_gram_protocol_num_connects;
int                                     globus_i_gram_protocol_max_concurrency;
globus_gram_protocol_handle_t		globus_i_gram_protocol_handle;
const int GLOBUS_GRAM_PROTOCOL_DEFAULT_MAX_CONCURRENCY = 50;

static int globus_l_gram_protocol_activate(void);
static int globus_l_gram_protocol_deactivate(void);

globus_module_descriptor_t globus_i_gram_protocol_module =
{
    "globus_gram_protocol",
    globus_l_gram_protocol_activate,
    globus_l_gram_protocol_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


static
int
globus_l_gram_protocol_activate(void)
{
    OM_uint32				major_status;
    OM_uint32				minor_status;
    int					result;
    char *				message;
    char *                              max_concurrency;

    result = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if(result != GLOBUS_SUCCESS)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }

    result = globus_module_activate(GLOBUS_IO_MODULE);
    if(result != GLOBUS_SUCCESS)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }

    globus_thread_key_create(
            &globus_i_gram_protocol_error_key,
            globus_i_gram_protocol_error_destroy);

    max_concurrency = globus_module_getenv("GLOBUS_GRAM_PROTOCOL_MAX_CONCURRENCY");
    if (max_concurrency)
    {
        globus_i_gram_protocol_max_concurrency = atoi(max_concurrency);
    }
    if (globus_i_gram_protocol_max_concurrency <= 0)
    {
        globus_i_gram_protocol_max_concurrency =
            GLOBUS_GRAM_PROTOCOL_DEFAULT_MAX_CONCURRENCY;
    }
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
                        GSS_C_BOTH,
                        &globus_i_gram_protocol_credential);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(
		&message,
                "gram_init failure:",
                major_status,
                minor_status,
                0);
	globus_gram_protocol_error_7_hack_replace_message(message);

	globus_module_deactivate(GLOBUS_IO_MODULE);

        return GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION; /* need better return code */
    }

    globus_i_gram_protocol_listeners = GLOBUS_NULL;
    globus_i_gram_protocol_connections = GLOBUS_NULL;
    globus_i_gram_protocol_old_creds = GLOBUS_NULL;
    globus_i_gram_protocol_shutdown_called = GLOBUS_FALSE;
    globus_i_gram_protocol_num_connects = 0;
    globus_mutex_init(&globus_i_gram_protocol_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_i_gram_protocol_cond, GLOBUS_NULL);
    globus_gram_protocol_setup_attr(&globus_i_gram_protocol_default_attr);

    return GLOBUS_SUCCESS;
}


static int
globus_l_gram_protocol_deactivate(void)
{
    globus_i_gram_protocol_listener_t *  listener;

    /*
     * wait for in-progress commands to complete
     */
    globus_mutex_lock( &globus_i_gram_protocol_mutex );
    {
	globus_i_gram_protocol_shutdown_called = GLOBUS_TRUE;

	/* finish all outstanding accepts */
	while (!globus_list_empty(globus_i_gram_protocol_listeners))
	{
	    listener = (globus_i_gram_protocol_listener_t *)
		globus_list_first(globus_i_gram_protocol_listeners);

	    globus_i_gram_protocol_callback_disallow(listener);
	}

	/* wait for all outgoing connections to get replies */
	while (globus_i_gram_protocol_num_connects != 0)
	{
	    globus_cond_wait(&globus_i_gram_protocol_cond,
			     &globus_i_gram_protocol_mutex);
	}
    }
    globus_mutex_unlock(&globus_i_gram_protocol_mutex);
    globus_io_tcpattr_destroy(&globus_i_gram_protocol_default_attr);
    globus_mutex_destroy(&globus_i_gram_protocol_mutex);

    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_deactivate(GLOBUS_IO_MODULE);
    /*
     * GSSAPI - cleanup of the credential
     * don't really care about returned status
     */
    if (globus_i_gram_protocol_credential != GSS_C_NO_CREDENTIAL)
    {
        OM_uint32 minor_status;
        gss_release_cred(&minor_status,
                         &globus_i_gram_protocol_credential);
	globus_i_gram_protocol_credential = GSS_C_NO_CREDENTIAL;
    }

    globus_i_gram_protocol_listeners = GLOBUS_NULL;
    return GLOBUS_SUCCESS;
}

/************************* help function *********************************/

/**
 * @brief Create default I/O attribute for GRAM
 * @ingroup globus_gram_protocol_io
 *
 * @details
 * The globus_gram_protocol_setup_attr() function creates a new
 * globus_io attribute containing the default set of values needed for
 * communication between a GRAM client and a job manager. These attributes
 * include:
 * - SO_KEEPALIVE
 * - GSSAPI Mutual Authentication
 * - GSSAPI Self Authorization
 * - SSL-compatible message wrapping
 *
 * @param attr
 *     A pointer to a @a globus_io_attr_t structure which will be initialized
 *     by this function.
 *
 * @return
 *     Upon success, globus_gram_protocol_setup_attr() modifies the @a attr
 *     parameter to point to a new attribute and returns the value
 *     @a GLOBUS_SUCCESS. When this occurs, the caller must destroy
 *     the attribute when no longer needed by calling
 *     globus_io_tcpattr_destroy(). If an error occurs, its value will be
 *     returned and the attribute pointed to by the @a attr parameter will be
 *     set to an uninitialized state.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED
 *     Error initializing attribute
 */
int
globus_gram_protocol_setup_attr(globus_io_attr_t *  attr)
{
    globus_result_t                        res;
    globus_io_secure_authorization_data_t  auth_data;

    /* acquire mutex */
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
        globus_i_gram_protocol_credential);
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

    /* release mutex */
    return GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED;
}

/**
 * @brief Determine if a GSSAPI context has the same source and target identities
 * @ingroup globus_gram_protocol_io
 *
 * @details
 * The globus_gram_protocol_authorize_self() function implements a predicate
 * which returns true if the source and destination identities used to
 * establish the GSSAPI security context are the same.
 *
 * @param context
 *     A GSSAPI security context which has been previously established. The
 *     source and target names of this context will be inspected by this 
 *     function.
 * 
 * @return
 *     If the source and target identiies are the same, then
 *     @a #globus_gram_protocol_authorize_self() returns @a GLOBUS_TRUE,
 *     otherwise, this function returns @a GLOBUS_FALSE.
 *
 * @retval GLOBUS_TRUE
 *     The source and target identities are the same.
 * @retval GLOBUS_FALSE
 *     The source and target identities are not the same or this function is
 *     unabled to inspect the security context.
 */
globus_bool_t
globus_gram_protocol_authorize_self(
    gss_ctx_id_t                        context)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_name_t                          source_name;
    gss_name_t                          target_name;
    int                                 equal;
    globus_bool_t                       result = GLOBUS_FALSE;
    
    major_status = gss_inquire_context(&minor_status,
                                       context,
                                       &source_name,
                                       &target_name,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL);
    if(GSS_ERROR(major_status))
    {
        goto exit;
    }

    major_status = gss_compare_name(&minor_status,
                                    source_name,
                                    target_name,
                                    &equal);
    if(GSS_ERROR(major_status))
    {
        goto free_names;
    }

    if(equal)
    {
        result = GLOBUS_TRUE;
    }
    
 free_names:
    gss_release_name(&minor_status,
                     &source_name);
    gss_release_name(&minor_status,
                     &target_name);
 exit:

    return result;
    
}
/* globus_gram_protocol_authorize_self */
