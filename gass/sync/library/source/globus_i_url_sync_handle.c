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
 * @file globus_i_url_sync_handle.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_i_url_sync_handle.h"
#include "globus_ftp_client.h"
#include "globus_common.h"
#include "version.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/* Types */

typedef enum {
    inactive,
    active,
    aborted
} globus_l_url_sync_handle_state_t;

/* Fields */

/**
 * Synchronize handle. Handles cannot be used to perform more than one operation
 * at a time. The structure's elements are private.
 * @ingroup globus_url_sync_handle
 */
typedef struct globus_l_url_sync_handle_s
{
    globus_l_url_sync_handle_state_t        state;
    globus_bool_t                           cache_connections;
    globus_bool_t                           recursion;
    globus_url_sync_endpoint_t *            source;
    globus_url_sync_endpoint_t *            dest;
    globus_url_sync_complete_callback_t     complete_callback;
    globus_url_sync_result_callback_t       result_callback;
    void *                                  user_arg;
    globus_url_sync_comparator_t *          comparator;
    globus_mutex_t                          mutex;
} globus_l_url_sync_handle_t;

/* Initialization and Destruction */
globus_result_t
globus_url_sync_handle_init(
    globus_url_sync_handle_t *		    handle,
    globus_url_sync_comparator_t *          comparator)
{
    globus_l_url_sync_handle_t *            i_handle;
    GlobusFuncName(globus_url_sync_handle_init);

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("handle"));
    }

    if(comparator == GLOBUS_NULL)
    {
	return globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("comparator"));
    }

    /* Allocate handle */
    i_handle = globus_libc_malloc(sizeof(globus_l_url_sync_handle_t));
    if(i_handle == GLOBUS_NULL)
    {
	return globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_OUT_OF_MEMORY());
    }
    *handle = (globus_url_sync_handle_t) i_handle;

    /* Initialize handle fields */
    i_handle->state = inactive;
    i_handle->source = GLOBUS_NULL;
    i_handle->dest = GLOBUS_NULL;
    i_handle->complete_callback = GLOBUS_NULL;
    i_handle->user_arg = GLOBUS_NULL;
    i_handle->comparator = comparator;
    globus_mutex_init(&(i_handle->mutex), GLOBUS_NULL);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_url_sync_handle_destroy(
    globus_url_sync_handle_t *		    handle)
{
    globus_l_url_sync_handle_t *	    i_handle;
    GlobusFuncName(globus_url_sync_handle_destroy);

    if(handle == GLOBUS_NULL || *handle == GLOBUS_NULL)
    {
	return globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("handle"));
    }
    i_handle = *(globus_l_url_sync_handle_t **) handle;

    globus_mutex_destroy(&i_handle->mutex);

    if (i_handle->source)
    {
//    globus_libc_free(i_handle->source.ftp_handle); TODO: DE-Init
        globus_i_url_sync_endpoint_destroy(i_handle->source);
    }

    if (i_handle->dest)
    {
//    globus_libc_free(i_handle->dest.ftp_handle); TODO: DE-Init
        globus_i_url_sync_endpoint_destroy(i_handle->dest);
    }

    globus_libc_free(i_handle);
    *handle = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

/* Lock and Unlock */

int
globus_i_url_sync_handle_lock(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return globus_mutex_lock(&handle->mutex);
}

int
globus_i_url_sync_handle_unlock(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return globus_mutex_unlock(&handle->mutex);
}

/* Activation and Deactivation */

globus_result_t
globus_i_url_sync_handle_activate(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    globus_assert(handle->state != active);
    handle->state = active;
    /* In the future, activation should add this handle to a list of active
     * handles. */
    return GLOBUS_SUCCESS;
}

/* Setters and Getters */

globus_bool_t
globus_url_sync_handle_get_cache_connections(
    globus_url_sync_handle_t                handle)
{
	globus_assert(handle);
	return handle->cache_connections;
}

void
globus_url_sync_handle_set_cache_connections(
    globus_url_sync_handle_t                handle,
    globus_bool_t                           cache_connections)
{
    globus_assert(handle);
    handle->cache_connections = cache_connections;
}

globus_bool_t
globus_url_sync_handle_get_recursion(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return handle->recursion;
}

void
globus_url_sync_handle_set_recursion(
    globus_url_sync_handle_t                handle,
    globus_bool_t                           recursion)
{
    globus_assert(handle);
    handle->recursion = recursion;
}

globus_url_sync_endpoint_t *
globus_i_url_sync_handle_get_source(
    globus_url_sync_handle_t                handle)
{
    globus_url_sync_endpoint_t *          endpoint;
    globus_assert(handle);
    endpoint = handle->source;
    return endpoint;
}

void
globus_i_url_sync_handle_set_source(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            source)
{
    globus_assert(handle);
    globus_assert(source);
    handle->source = source;
}

globus_url_sync_endpoint_t *
globus_i_url_sync_handle_get_destination(
    globus_url_sync_handle_t                handle)
{
    globus_url_sync_endpoint_t *          endpoint;
    globus_assert(handle);
    endpoint = handle->dest;
    return endpoint;
}

void
globus_i_url_sync_handle_set_destination(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            destination)
{
    globus_assert(handle);
    globus_assert(destination);
    handle->source = destination;
}

globus_bool_t
globus_i_url_sync_handle_is_active(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return (handle->state == active) ? GLOBUS_TRUE : GLOBUS_FALSE;
}

globus_bool_t
globus_i_url_sync_handle_is_inactive(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return (handle->state == inactive) ? GLOBUS_TRUE : GLOBUS_FALSE;
}

void
globus_i_url_sync_handle_set_complete_callback(
    globus_url_sync_handle_t                handle,
    globus_url_sync_complete_callback_t     complete_callback)
{
    globus_assert(handle);
    handle->complete_callback = complete_callback;
}

globus_url_sync_complete_callback_t
globus_i_url_sync_handle_get_complete_callback(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return handle->complete_callback;
}

void
globus_i_url_sync_handle_set_result_callback(
    globus_url_sync_handle_t                handle,
    globus_url_sync_result_callback_t       result_callback)
{
    globus_assert(handle);
    handle->result_callback = result_callback;
}

globus_url_sync_result_callback_t
globus_i_url_sync_handle_get_result_callback(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return handle->result_callback;
}

void
globus_i_url_sync_handle_set_user_arg(
    globus_url_sync_handle_t                handle,
    void *                                  user_arg)
{
    globus_assert(handle);
    handle->user_arg = user_arg;
}

void *
globus_i_url_sync_handle_get_user_arg(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return handle->user_arg;
}

globus_url_sync_comparator_t *
globus_i_url_sync_handle_get_comparator(
    globus_url_sync_handle_t                handle)
{
    globus_assert(handle);
    return handle->comparator;
}

/** Endpoint operations **/

/**
 * Allocates an endpoint structure and initializes the url and ftp_handle. It
 * copies the address of the url and will free the url when the endpoint is
 * destroyed. The ftp handle remains the responsibility of the caller.
 */
globus_result_t
globus_i_url_sync_endpoint_init(
    globus_url_sync_endpoint_t **           endpoint_out,
    const char *                            url,
    globus_ftp_client_handle_t *            ftp_handle)
{
    globus_assert(endpoint_out);
    *endpoint_out = globus_libc_malloc(sizeof(globus_url_sync_endpoint_t));
    memset(*endpoint_out, 0, sizeof(globus_url_sync_endpoint_t));
    globus_assert(*endpoint_out);
    globus_assert(url);
    /* allow room for a trailing "/", in case it's needed */
    (*endpoint_out)->url = globus_libc_malloc(strlen(url)+2);
    strcpy((*endpoint_out)->url, url);
    (*endpoint_out)->ftp_handle = ftp_handle;
    return GLOBUS_SUCCESS;
}

/**
 * Frees the endpoint structure and the endpoint.url. It does not destroy or
 * free the ftp_handle.
 */
globus_result_t
globus_i_url_sync_endpoint_destroy(
    globus_url_sync_endpoint_t *            endpoint)
{
    globus_assert(endpoint);
    globus_assert(endpoint->url);
    globus_libc_free(endpoint->url);
	if (endpoint->mlst_buffer != GLOBUS_NULL) {
		globus_libc_free(endpoint->mlst_buffer);
	}
    globus_libc_free(endpoint);
    return GLOBUS_SUCCESS;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
