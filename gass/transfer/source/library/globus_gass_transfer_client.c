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
 * @file globus_gass_transfer_client.c Client Interface
 *
 * This module implements the client interface to the GASS transfer library
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#endif

#include "globus_i_gass_transfer.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_bool_t				done;
    int						rc;
    globus_mutex_t				mutex;
    globus_cond_t				cond;
} globus_gass_transfer_monitor_t;

static
void
globus_l_gass_transfer_monitor_callback(
    void *					arg,
    globus_gass_transfer_request_t		request);
#endif

/**
 * Nonblocking file get.
 * @ingroup globus_gass_transfer_client
 *
 * This function initiates a new "get" request of the file named by @a url.
 * The entire file will be transfered from the server if the file exists and
 * user is authorized to do so. This function does not block; instead, the
 * user's callback function will be called once the GASS library has
 * determined whether the file can be retrieved or not.
 *
 * Upon returning from this function, the request handle is initialized to
 * refer to the @a get request's state.
 *
 * If the server can't store the file at @a url, but
 * has an alternative location for the user to store to, then the 
 * callback function will be called with the
 * request's status set to @em GLOBUS_GASS_TRANSFER_REQUEST_REFERRED.
 *
 * @param request
 *        A pointer to an uninitialized request handle.
 * @param attr
 *        Request attributes.
 * @param url
 *        URL to get
 * @param callback
 *        Function to call once the URL has been accepted, referred, or
 *        denied by the server.
 * @param user_arg
 *        User-supplied argument to the callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The get was successfully initiated.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         One of request, attr, or callback was GLOBUS_NULL. The get
 *         could not be processed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         An internal resource was not available to process the get.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing a get on this URL type is implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 *
 * @see globus_gass_transfer_get()
 */
int
globus_gass_transfer_register_get(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg)
{
    int						rc;

    if(request == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(url == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(callback == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }

    /* Initialize request structure, and obtain a handle to it */
    globus_i_gass_transfer_request_init(request,
					attr,
					url,
					GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET,
					callback,
					user_arg);
    if(*request == GLOBUS_NULL_HANDLE)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR;
    }

    /*
     * Call the protocol-specific connection handler
     */
    rc = globus_i_gass_transfer_client_request(request);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_gass_transfer_request_destroy(*request);
    }
    return rc;
}
/* globus_gass_transfer_register_get() */

/**
 * Blocking file get.
 * @ingroup globus_gass_transfer_client
 *
 * This function initiates a new "get" request of the file named by @a url.
 * The entire file will be transfered from the server if the file exists and
 * user is authorized to do so. This function blocks until the 
 * GASS library has determined whether the file may be retrievied by the
 * caller, may not because it is a referral to another URL or URLs, or
 * the server has denied the request.
 *
 * Upon returning from this function, the request handle is initialized to
 * refer to the @a get request's state. This request handle must be destroyed
 * after the user has finished processing the data associated with the
 * callback.
 *
 * If the file doesn't exist at @a url, but
 * a referral does, then this function will return with the
 * request's status set to @em GLOBUS_GASS_TRANSFER_REQUEST_REFERRED.
 *
 * @param request
 *        A pointer to an uninitialized request handle.
 * @param attr
 *        Request attributes.
 * @param url
 *        URL to get
 *
 * @retval GLOBUS_SUCCESS
 *         The get was successfully initiated.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         One of request or attr was GLOBUS_NULL. The get
 *         could not be processed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         An internal resource was not available to process the get.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing a get on this URL type is implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 *
 * @see globus_gass_transfer_register_get()
 */
int
globus_gass_transfer_get(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url)
{
    globus_gass_transfer_monitor_t		monitor;
    int						rc;

    monitor.done = GLOBUS_FALSE;
    monitor.rc = 0;
    globus_mutex_init(&monitor.mutex,
		      GLOBUS_NULL);
    globus_cond_init(&monitor.cond,
		      GLOBUS_NULL);

    rc = globus_gass_transfer_register_get(request,
					   attr,
					   url,
					   globus_l_gass_transfer_monitor_callback,
					   &monitor);
    globus_mutex_lock(&monitor.mutex);
    if(rc != GLOBUS_SUCCESS)
    {
	monitor.rc = rc;
	monitor.done = GLOBUS_TRUE;
    }

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    return monitor.rc;
}
/* globus_gass_transfer_get() */

/**
 * Nonblocking file put.
 * @ingroup globus_gass_transfer_client
 *
 * This function initiates a new "put" request of the file named by @a url.
 * The entire file will be transfered to the server if the 
 * user is authorized to do so. This function does not block; instead, the
 * user's callback function will be called once the GASS library has
 * determined whether the file may be stored or not.
 *
 * Upon returning from this function, the request handle is initialized to
 * refer to the @a put request's state.
 *
 * If the server can't store the file at @a url, but
 * has an alternative location for the user to store to, then the callback
 * function will be called with the request's status set to @em
 * GLOBUS_GASS_TRANSFER_REQUEST_REFERRED.
 *
 * @param request
 *        A pointer to an uninitialized request handle.
 * @param attr
 *        Request attributes.
 * @param url
 *        URL to put.
 * @param length
 *        The length of the data to put to the url, if known. If this
 *        parameter is set to @a GLOBUS_GASS_LENGTH_UNKNOWN, then the put
 *        may fail if the protocol does not support arbitrarily-length files.
 * @param callback
 *        Function to call once the URL has been accepted, referred, or
 *        denied by the server.
 * @param user_arg
 *        User-supplied argument to the callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The put was successfully initiated.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         One of request, attr, or callback was GLOBUS_NULL. The put
 *         could not be processed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         An internal resource was not available to process the put.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing a put on this URL type is implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 *
 * @see globus_gass_transfer_put()
 */
int
globus_gass_transfer_register_put(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg)
{
    int						rc;

    if(request == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(url == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(callback == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }

    /* Initialize request structure, and obtain a handle to it */
    globus_i_gass_transfer_request_init(request,
					attr,
					url,
					GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT,
					callback,
					user_arg);

    if(*request == GLOBUS_NULL_HANDLE)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR;
    }

    globus_gass_transfer_request_set_length(*request,
					    length);
    /*
     * Call the protocol-specific connection handler
     */
    rc = globus_i_gass_transfer_client_request(request);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_gass_transfer_request_destroy(*request);
    }
    return rc;
}
/* globus_gass_transfer_register_put() */

/**
 * Blocking file put.
 * @ingroup globus_gass_transfer_client
 *
 * This function initiates a new "put" request of the file named by @a url.
 * The entire file will be transfered to the server if the 
 * user is authorized to do so. This function blocks until the 
 * GASS library has determined whether the file may be retrieved by the
 * caller, may not because it is a referral to another URL or URLs, or
 * the server has denied the request.
 *
 * Upon returning from this function, the request handle is initialized to
 * refer to the @a put request's state.
 *
 * If the server can't store the file at @a url, but
 * has an alternative location for the user to store to, then this function
 * return with request's status set to @em
 * GLOBUS_GASS_TRANSFER_REQUEST_REFERRED.
 *
 * @param request
 *        A pointer to an uninitialized request handle.
 * @param attr
 *        Request attributes.
 * @param url
 *        URL to put.
 * @param length
 *        The length of the data to put to the url, if known. If this
 *        parameter is set to @a GLOBUS_GASS_LENGTH_UNKNOWN, then the put
 *        may fail if the protocol does not support arbitrarily-length files.
 *
 * @retval GLOBUS_SUCCESS
 *         The get was successfully initiated.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         One of request or attr was GLOBUS_NULL. The get
 *         could not be processed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         An internal resource was not available to process the get.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing a put on this URL type is implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 *
 * @see globus_gass_transfer_register_put()
 */
int
globus_gass_transfer_put(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length)
{
    globus_gass_transfer_monitor_t		monitor;
    int						rc;

    monitor.done = GLOBUS_FALSE;
    monitor.rc = 0;
    globus_mutex_init(&monitor.mutex,
		      GLOBUS_NULL);
    globus_cond_init(&monitor.cond,
		      GLOBUS_NULL);

    rc = globus_gass_transfer_register_put(request,
					   attr,
					   url,
					   length,
					   globus_l_gass_transfer_monitor_callback,
					   &monitor);
    globus_mutex_lock(&monitor.mutex);
    if(rc != GLOBUS_SUCCESS)
    {
	monitor.rc = rc;
	monitor.done = GLOBUS_TRUE;
    }

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    return monitor.rc;
}
/* globus_gass_transfer_put() */

/**
 * Nonblocking file append.
 * @ingroup globus_gass_transfer_client
 *
 * This function initiates a new "append" request of the file named by @a url.
 * The entire file will be transfered to the server if the 
 * user is authorized to do so. This function does not block; instead, the
 * user's callback function will be called once the GASS library has
 * determined whether the file may be stored or not.
 *
 * Upon returning from this function, the request handle is initialized to
 * refer to the @a append request's state.
 *
 * If the server can't store the file at @a url, but
 * has an alternative location for the user to store to, then the callback
 * function will be called with the request's status set to @em
 * GLOBUS_GASS_TRANSFER_REQUEST_REFERRED.
 *
 * @param request
 *        A pointer to an uninitialized request handle.
 * @param attr
 *        Request attributes.
 * @param url
 *        URL to append to.
 * @param length
 *        The length of the data to append to the url, if known. If this
 *        parameter is set to @a GLOBUS_GASS_LENGTH_UNKNOWN, then the append
 *        may fail if the protocol does not support arbitrarily-length files.
 * @param callback
 *        Function to call once the URL has been accepted, referred, or
 *        denied by the server.
 * @param user_arg
 *        User-supplied argument to the callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The put was successfully initiated.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         One of request, attr, or callback was GLOBUS_NULL. The put
 *         could not be processed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         An internal resource was not available to process the put.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing a append on this URL type is
 *         implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 *
 * @see globus_gass_transfer_append()
 */
int
globus_gass_transfer_register_append(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg)
{
    int						rc;

    if(request == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(url == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(callback == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }

    /* Initialize request structure, and obtain a handle to it */
    globus_i_gass_transfer_request_init(request,
					attr,
					url,
					GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND,
					callback,
					user_arg);

    if(*request == GLOBUS_NULL_HANDLE)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR;
    }

    globus_gass_transfer_request_set_length(*request,
					    length);
    /*
     * Call the protocol-specific connection handler
     */
    rc = globus_i_gass_transfer_client_request(request);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_gass_transfer_request_destroy(*request);
    }
    return rc;
}
/* globus_gass_transfer_register_append() */

/**
 * Blocking file append.
 * @ingroup globus_gass_transfer_client
 *
 * This function initiates a new "append" request of the file named by @a url.
 * The entire file will be transfered to the server if the 
 * user is authorized to do so.  This function blocks until the 
 * GASS library has determined whether the file may be retrieved by the
 * caller, may not because it is a referral to another URL or URLs, or
 * the server has denied the request.
 *
 * Upon returning from this function, the request handle is initialized to
 * refer to the @a append request's state.
 *
 * If the server can't store the file at @a url, but
 * has an alternative location for the user to store to, then this function
 * return with request's status set to @em
 * GLOBUS_GASS_TRANSFER_REQUEST_REFERRED.
 *
 * @param request
 *        A pointer to an uninitialized request handle.
 * @param attr
 *        Request attributes.
 * @param url
 *        URL to append to.
 * @param length
 *        The length of the data to append to the url, if known. If this
 *        parameter is set to @a GLOBUS_GASS_LENGTH_UNKNOWN, then the append
 *        may fail if the protocol does not support arbitrarily-length files.
 * @param callback
 *        Function to call once the URL has been accepted, referred, or
 *        denied by the server.
 * @param user_arg
 *        User-supplied argument to the callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The put was successfully initiated.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         One of request, attr, or callback was GLOBUS_NULL. The put
 *         could not be processed.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         An internal resource was not available to process the put.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing a append on this URL type is
 *         implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 *
 * @see globus_gass_transfer_register_append()
 */
int
globus_gass_transfer_append(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length)
{
    globus_gass_transfer_monitor_t		monitor;
    int						rc;

    monitor.done = GLOBUS_FALSE;
    monitor.rc = 0;
    globus_mutex_init(&monitor.mutex,
		      GLOBUS_NULL);
    globus_cond_init(&monitor.cond,
		      GLOBUS_NULL);

    rc = globus_gass_transfer_register_append(
	request,
	attr,
	url,
	length,
	globus_l_gass_transfer_monitor_callback,
	&monitor);

    globus_mutex_lock(&monitor.mutex);
    if(rc != GLOBUS_SUCCESS)
    {
	monitor.rc = rc;
	monitor.done = GLOBUS_TRUE;
    }

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    return monitor.rc;
}
/* globus_gass_transfer_append() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Call the protocol-specific URL handler to process a request.
 *
 * @param request
 *        A pointer to the request handle to process.
 *
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         No protocol handler for doing the desired operation on this URL
 *         type is implemented.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_BAD_URL
 *         The URL could not be parsed.
 */
int
globus_i_gass_transfer_client_request(
    globus_gass_transfer_request_t *            request)
{
    globus_url_t				url;
    int						rc;
    globus_gass_transfer_proto_descriptor_t *	protocol;
    globus_gass_transfer_proto_new_request_t 	request_func;
    globus_gass_transfer_request_struct_t *	req;

    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     (*request));

    /* determine the protocol module to use for the request */
    rc = globus_url_parse(req->url,
		          &url);
    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_BAD_URL;
    }

    globus_i_gass_transfer_lock();

    protocol = (globus_gass_transfer_proto_descriptor_t *)
	globus_hashtable_lookup(&globus_i_gass_transfer_protocols,
				(void *) url.scheme);
    globus_url_destroy(&url);

    /* verify that the operation is supported by the protocol module */
    if(protocol == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED;
	goto error_exit;
    }

    req->client_side = GLOBUS_TRUE;

    request_func = protocol->new_request;

    globus_i_gass_transfer_unlock();

    /* call protocol-module-specific handler */
    request_func(*request,
		 &req->attr);

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
    return rc;
}
/* globus_i_gass_transfer_client_request() */

/**
 * Blocking function monitor callback.
 *
 * This function is used as the callback function internally to implement
 * the blocking functions globus_gass_transfer_get(),
 * globus_gass_transfer_put(), and globus_gass_transfer_append(),
 *
 * @param arg
 *        A monitor created by the blocking function, with a condition
 *        variable used to signal the blocked function.
 * @param request
 *        The request handle associated with the request.
 */
static
void
globus_l_gass_transfer_monitor_callback(
    void *					arg,
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_monitor_t *		monitor;

    monitor = (globus_gass_transfer_monitor_t *) arg;	

    globus_mutex_lock(&monitor->mutex);

    monitor->rc = GLOBUS_SUCCESS;
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);

    return;
}
/* globus_l_gass_transfer_monitor_callback() */
#endif
