/******************************************************************************
globus_gass_transfer_client.c
 
Description:
    This module implements the client interface to the GASS transfer library
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_i_gass_transfer.h"

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

/* Client Interface */
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
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(url == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(callback == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }

    /* Initialize request structure, and obtain a handle to it */
    globus_i_gass_transfer_request_init(request,
					attr,
					url,
					GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET,
					callback,
					user_arg);
    if(*request == GLOBUS_HANDLE_TABLE_NO_HANDLE)
    {
	return GLOBUS_GASS_ERROR_INTERNAL_ERROR;
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
    globus_mutex_lock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    return monitor.rc;
}
/* globus_gass_transfer_get() */

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
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(url == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(callback == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }

    /* Initialize request structure, and obtain a handle to it */
    globus_i_gass_transfer_request_init(request,
					attr,
					url,
					GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT,
					callback,
					user_arg);

    if(*request == GLOBUS_HANDLE_TABLE_NO_HANDLE)
    {
	return GLOBUS_GASS_ERROR_INTERNAL_ERROR;
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
    globus_mutex_lock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    return monitor.rc;
}
/* globus_gass_transfer_put() */

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
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(url == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(callback == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }

    /* Initialize request structure, and obtain a handle to it */
    globus_i_gass_transfer_request_init(request,
					attr,
					url,
					GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND,
					callback,
					user_arg);

    if(*request == GLOBUS_HANDLE_TABLE_NO_HANDLE)
    {
	return GLOBUS_GASS_ERROR_INTERNAL_ERROR;
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
    globus_mutex_lock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    return monitor.rc;
}
/* globus_gass_transfer_append() */

int
globus_i_gass_transfer_client_request(
    globus_gass_transfer_request_t *            request)
{
    globus_url_t				url;
    int						rc;
    globus_gass_transfer_proto_descriptor_t *	protocol;
    globus_gass_transfer_proto_new_request_t 	request_func;
    globus_gass_transfer_request_struct_t *	req;

    req = globus_handle_table_lookup(&globus_i_gass_transfer_requests,
				     (*request));

    /* determine the protocol module to use for the request */
    rc = globus_url_parse(req->url,
		          &url);
    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_GASS_ERROR_BAD_URL;
    }

    globus_i_gass_transfer_lock();

    protocol = (globus_gass_transfer_proto_descriptor_t *)
	globus_hashtable_lookup(&globus_i_gass_transfer_protocols,
				(void *) url.scheme);
    globus_url_destroy(&url);

    /* verify that the operation is supported by the protocol module */
    if(protocol == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_NOT_IMPLEMENTED;
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

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);

    return;
}
