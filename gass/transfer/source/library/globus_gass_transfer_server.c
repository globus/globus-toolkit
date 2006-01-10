/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gass_transfer_server.c GASS Server
 * 
 * This module implements the gass server functionality of the GASS
 * transfer library
 *
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#endif

#include "globus_i_gass_transfer.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
static
void
globus_l_gass_transfer_callback_close_callback(
    void *					arg);
#endif


/**
 * Create a new protocol-specific listener socket for a GASS server.
 * @ingroup globus_gass_transfer_server
 * 
 * This function creates a new socket to listen for client connections
 * as a GASS server. The listener handle pointer is initialized to
 * contain the a new handle which can be used in subsequent server
 * operations.
 *
 * After calling this function, a user may call the
 * globus_gass_transfer_register_listen() or
 * globus_gass_transfer_close_listener() functions with this
 * listener handle.
 * 
 * @param listener
 *        A new listener handle to initialize.
 * @param attr
 *        Protocol-specific attributes for the new listener.
 * @param scheme
 *        The protocol scheme to implement for the listener.
 *
 * @retval GLOBUS_SUCCESS
 *         The listener was successfully created.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         The @a listener or @a scheme parameter was NULL
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         The @a scheme is not supported by any protocol module.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_MALLOC_FAILED
 *         Data structures associated with the transfer could not be
 *         allocated.
 */
int
globus_gass_transfer_create_listener(
    globus_gass_transfer_listener_t *		listener,
    globus_gass_transfer_listenerattr_t *	attr,
    char *					scheme)
{
    int						rc;
    globus_gass_transfer_listener_struct_t *	l;
    globus_gass_transfer_proto_descriptor_t *	protocol;

    if(listener == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }
    if(scheme == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
    }

    globus_i_gass_transfer_lock();
    protocol = (globus_gass_transfer_proto_descriptor_t *)
	globus_hashtable_lookup(&globus_i_gass_transfer_protocols,
				(void *) scheme);
    if(protocol == GLOBUS_NULL ||
       protocol->new_listener == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED;
	goto error_exit;
    }
    l = globus_malloc(sizeof(globus_gass_transfer_listener_struct_t));
    if(l == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_MALLOC_FAILED;
	goto error_exit;
    }
    l->base_url = GLOBUS_NULL;
    l->status = GLOBUS_GASS_TRANSFER_LISTENER_INVALID;
    l->user_pointer = GLOBUS_NULL;

    *listener = globus_handle_table_insert(&globus_i_gass_transfer_listener_handles,
					   (void *) l,
					   2);
    globus_list_insert(&globus_i_gass_transfer_listeners,
		       (void *) (*listener));
    
    rc = protocol->new_listener(*listener,
				attr,
				scheme,
				&l->base_url,
				&l->proto);

    if(rc != GLOBUS_SUCCESS)
    {
	goto destroy_handle;
    }

    l->status = GLOBUS_GASS_TRANSFER_LISTENER_STARTING;

    globus_i_gass_transfer_unlock();

    return GLOBUS_SUCCESS;

  destroy_handle:
    /* These calls end up freeing l and its members */
    globus_i_gass_transfer_listener_destroy(*listener);
    globus_i_gass_transfer_listener_destroy(*listener);

  error_exit:
    globus_i_gass_transfer_unlock();

    return rc;
}
/* globus_gass_transfer_create_listener() */

/**
 * Close a GASS listener.
 * @ingroup globus_gass_transfer_server
 *
 * This function calls the protocol specific function needed to close
 * a GASS server listener port. Callbacks for any outstanding accepts will
 * be called before the close callback is invoked.
 *
 * @param listener
 *        Listener handle created by calling
 *        globus_gass_transfer_create_listener().
 * @param callback
 *        Function to call once the listener handle has been closed.
 * @param user_arg
 *        Argument to be passed to the @a callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The close operation was successfully registered on the listener.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         The listener handle was invalid.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED
 *         The listener handle was not properly initialized.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_DONE
 *         A close has already been registered on the listener.
 */
int
globus_gass_transfer_close_listener(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_close_callback_t 	callback,
    void *					user_arg)
{
    globus_gass_transfer_listener_struct_t *	l;
    int						rc;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	rc =  GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto finish;
    }

    rc = globus_i_gass_transfer_close_listener(
	listener,
	l,
	callback,
	user_arg);
    
 finish:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_close_listener() */

/**
 * Listen for new client connections.
 * @ingroup globus_gass_transfer_server
 *
 * This function causes the listener handle to listen for new client
 * connections. When one is ready, it calls the specified @a callback
 * function, letting the server implementer continue to accept the
 * connection and process the request.
 *
 * @param listener
 *        The listener handle to register for new connections.
 * @param callback
 *        Function to call when a new connection may be accepted.
 * @param user_arg
 *        Argument to be passed to the callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The listen callback has been registered with the protocol module.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         An invalid @a listener handle was passed to this function.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED
 *         An uninitialized @a listener handle was passed to this function.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_ALREADY_REGISTERED
 *         The listener has already been registered for a new connection.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_DONE
 *         The listener has been registered for closing.
 *
 * @see globus_gass_transfer_register_accept();
 */
int
globus_gass_transfer_register_listen(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_listen_callback_t	callback,
    void *					user_arg)
{
    globus_gass_transfer_listener_struct_t *	l;
    int						rc;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	rc =  GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(callback == GLOBUS_NULL)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
	goto error_exit;
    }
    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED;
	goto error_exit;

      case GLOBUS_GASS_TRANSFER_LISTENER_STARTING:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_LISTENING;
	l->listen_callback = callback;
	l->listen_callback_arg = user_arg;
	l->proto->listen(l->proto,
			 listener);
	break;

      case GLOBUS_GASS_TRANSFER_LISTENER_READY:
      case GLOBUS_GASS_TRANSFER_LISTENER_LISTENING:
      case GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING:
	rc = GLOBUS_GASS_TRANSFER_ERROR_ALREADY_REGISTERED;
        goto error_exit;

      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	rc = GLOBUS_GASS_TRANSFER_ERROR_DONE;
        goto error_exit;
    }
    
    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;
  error_exit:
    globus_i_gass_transfer_unlock();

    return rc;
}
/* globus_gass_transfer_register_listener() */

/**
 * Accept new client connections.
 * @ingroup globus_gass_transfer_server
 *
 * This function causes the listener handle to accept a new connection
 * on the listener and parse the file request. Once the file request has
 * been parsed, the specified @a callback function will be called. The
 * server implementation must then either authorize, deny, or refer this
 * request.
 *
 * @param request
 *        A pointer to a new request handle. This request handle will
 *        be initialized when the callback function is invoked.
 * @param listener
 *        The listener handle to register for the new request.
 * @param callback
 *        Function to call when the protocol module has parsed the file
 *        request.
 * @param user_arg
 *        Argument to be passed to the callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The listen callback has been registered with the protocol module.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         An invalid @a listener handle was passed to this function.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED
 *         An uninitialized @a listener handle was passed to this function.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR
 *         The request could not be initialized due to some internal resource
 *         depletion.
 * @retval GLOBUS_GASS_NOT_REGISTERED.
 *         The globus_gass_transfer_register_listen() function has not
 *         yet been called.
 * @retval GLOBUS_GASS_ALREADY_REGISTERED.
 *         The listener is already processing a new request.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_DONE
 *         The listener has been registered for closing.
 *
 * @see globus_gass_transfer_register_listen();
 */
int
globus_gass_transfer_register_accept(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg)
{
    globus_gass_transfer_listener_struct_t *	l;
    int						rc;
    globus_gass_transfer_request_struct_t *	req;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	rc =  GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(request == GLOBUS_NULL || callback == GLOBUS_NULL)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
	goto error_exit;
    }
    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED;
	goto error_exit;
      case GLOBUS_GASS_TRANSFER_LISTENER_READY:
	globus_i_gass_transfer_request_init(request,
					    attr,
					    GLOBUS_NULL,
					    GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID,
					    callback,
					    user_arg);

	if(*request == GLOBUS_NULL_HANDLE)
	{
	    rc = GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR;
	    goto error_exit;
	}

	req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
					 (*request));

	if(req== GLOBUS_NULL)
	{
	    rc = GLOBUS_GASS_TRANSFER_ERROR_INTERNAL_ERROR;
	    goto error_exit;
	}
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING;

	l->status = GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING;
	l->proto->accept(l->proto,
			 listener,
			 *request,
			 attr);
	break;
      case GLOBUS_GASS_TRANSFER_LISTENER_STARTING:
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_REGISTERED;
	goto error_exit;
      case GLOBUS_GASS_TRANSFER_LISTENER_LISTENING:
      case GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING:
	rc = GLOBUS_GASS_TRANSFER_ERROR_ALREADY_REGISTERED;
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	rc = GLOBUS_GASS_TRANSFER_ERROR_DONE;
	break;
    }
    
    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;
  error_exit:
    globus_i_gass_transfer_unlock();

    return rc;
}
/* globus_gass_transfer_register_accept() */


/**
 * Get the user pointer associated with a listener.
 * @ingroup globus_gass_transfer_server
 *
 * This function will query the listener's user_pointer field
 * and return it's value.
 *
 * @param listener
 *        The listener handle.
 *
 * @return
 * If the listener handle is invalid or the user_pointer's value has not
 * been set, then GLOBUS_NULL will be returned. Otherwise, the value of
 * the user pointer will be returned.
 *
 * @see globus_gass_transfer_listener_set_user_pointer()
 */
void *
globus_gass_transfer_listener_get_user_pointer(
    globus_gass_transfer_listener_t		listener)
{
    globus_gass_transfer_listener_struct_t *	l;

    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    else
    {
	return l->user_pointer;
    }
}
/* globus_gass_transfer_listener_get_user_pointer() */

/**
 * Set the user pointer associated with a listener.
 * @ingroup globus_gass_transfer_server
 *
 * This function will set the listener's user_pointer field. The pointer
 * may be used to associate any pointer-sized data with a listener handle.
 *
 * @param listener
 *        The listener handle.
 * @param user_pointer
 *        The value of the user pointer.
 *
 * @retval GLOBUS_SUCCESS
 *         The user pointer was successfully set.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         The @a listener handle was invalid.
 *
 * @see globus_gass_transfer_listener_get_user_pointer()
 */
int
globus_gass_transfer_listener_set_user_pointer(
    globus_gass_transfer_listener_t		listener,
    void *					user_pointer)
{
    globus_gass_transfer_listener_struct_t *	l;

    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
    }
    else
    {
	l->user_pointer = user_pointer;
	return GLOBUS_SUCCESS;
    }
}
/* globus_gass_transfer_listener_set_user_pointer() */

/**
 * Get the base URL of a listener.
 * @ingroup globus_gass_transfer_server
 *
 * This function queries a listener handle for the base URL which the
 * server is listening on. For most protocols, this contains the protocol
 * scheme, host, and port that the listener has registered itself on.
 *
 * @param listener
 *        The listener handle to query.
 *
 * @return This function returns a pointer to a string containing the
 *         base URL. This string must not be freed or modified by the
 *         caller. It may not be referred to after the function
 *         globus_gass_transfer_listener_close() has been called.
 */
char *
globus_gass_transfer_listener_get_base_url(
    globus_gass_transfer_listener_t		listener)
{
    globus_gass_transfer_listener_struct_t *	l;
    char *					base_url;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	goto error_exit;
    }

    base_url = l->base_url;

    globus_i_gass_transfer_unlock();
    return base_url;

  error_exit:
    globus_i_gass_transfer_unlock();
    return GLOBUS_NULL;
}
/* globus_gass_transfer_listener_get_base_url() */

/**
 * Refer a request.
 * @ingroup globus_gass_transfer_server
 *
 * This function causes the request to be referred to another URL or 
 * list of URLs. It should be called in response to a request accept
 * callback when the server wants to refer the client to another server
 * or servers to process the request.
 *
 * @param request
 *        A new request handle, passed to the server in an accept callback.
 * @param urls
 *        An array of strings, each being a URL pointing to sources of
 *        the same data as the original URL.
 * @param num_urls
 *        The length of the @a urls array.
 *
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         The request handle was not valid, not created by calling
 *         globus_gass_transfer_register_accept(), or has already been
 *         denied or authorized.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         The protocol module does not support referrals.
 *
 * @see globus_gass_transfer_deny(), globus_gass_transfer_authorize()
 */
int
globus_gass_transfer_refer(
    globus_gass_transfer_request_t		request,
    char **					urls,
    globus_size_t				num_urls)
{
    globus_gass_transfer_request_struct_t *	req;
    int						rc;
    globus_size_t				i;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(req->proto == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(req->client_side == GLOBUS_TRUE)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(urls == GLOBUS_NULL)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;
	goto error_exit;
    }
    else if(req->proto->refer == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED;
	goto error_exit;
    }

    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_REFERRED;

	/* Copy the referral into the request structure */
	req->referral_url = (char **) globus_malloc(num_urls * sizeof(char *));
	req->referral_count = num_urls;

	for(i = 0; i < req->referral_count; i++)
	{
	    req->referral_url[i] = globus_libc_strdup(urls[i]);
	}

	req->proto->refer(req->proto,
			  request);

	req->proto->destroy(req->proto,
			    request);

	/* Destroy our reference to the request */
	globus_i_gass_transfer_request_destroy(request);
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	/* delete our reference to this request and proto */
	req->proto->destroy(req->proto,
			    request);
	globus_i_gass_transfer_request_destroy(request);
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;

}
/* globus_gass_transfer_refer() */

/**
 * Authorize a request.
 * @ingroup globus_gass_transfer_server
 *
 * This function causes the request to be authorized for processing.
 * It should be called in response to a request accept
 * callback when the server wants to agree to process this request.
 * After calling this function, the server implementation should call
 * globus_gass_transfer_send_bytes() or globus_gass_transfer_receive_bytes()
 * to send or receive the data associated with the URL.
 *
 * @param request
 *        A new request handle, passed to the server in an accept callback.
 * @param total_length
 *        For a "get" request, the total_length of the file to be retrieved
 *        if known. This value may be GLOBUS_GASS_LENGTH_UNKNOWN if the
 *        protocol supports transferring arbitrarily-sized files.
 *
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         The request handle was not valid, not created by calling
 *         globus_gass_transfer_register_accept(), or has already been
 *         denied or authorized.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         The protocol module does not support authorizing requests.
 *
 * @see globus_gass_transfer_refer(), globus_gass_transfer_deny()
 */
int
globus_gass_transfer_authorize(
    globus_gass_transfer_request_t		request,
    globus_size_t				total_length)
{
    globus_gass_transfer_request_struct_t *	req;
    int						rc;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(req->proto == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(req->proto->authorize == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED;
	goto error_exit;
    }

    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_STARTING3;

	/* Copy the total length (if this is a GET request),
	 * into the request structure
	 */
	if(req->type == GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET)
	{
	    req->length = total_length;
	}

	req->proto->authorize(req->proto,
			      request);
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	/* delete our reference to this request and proto */
	req->proto->destroy(req->proto,
			    request);
	globus_i_gass_transfer_request_destroy(request);
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }

    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_authorize() */

/**
 * Deny a request.
 * @ingroup globus_gass_transfer_server
 *
 * This function causes the request to be denied for further processing.
 * It should be called in response to a request ccept
 * callback when the server wants to refuse processing this request for
 * the client.  After calling this function, the server implementation need
 * do nothing further with the request handle.
 *
 * @param request
 *        A new request handle, passed to the server in an accept callback.
 * @param reason
 *        A protocol-specific reason code.
 * @param message
 *        An informational message to be sent to the client.
 *
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE
 *         The request handle was not valid, not created by calling
 *         globus_gass_transfer_register_accept(), or has already been
 *         denied or authorized.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED
 *         The protocol module does not support denying requests.
 *
 * @see globus_gass_transfer_refer(), globus_gass_transfer_authorize()
 */
int
globus_gass_transfer_deny(
    globus_gass_transfer_request_t		request,
    int						reason,
    char *					message)
{
    globus_gass_transfer_request_struct_t *	req;
    int						rc;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(req->proto == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }
    else if(req->proto->deny == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_IMPLEMENTED;
	goto error_exit;
    }

    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_DENIED;

	/* Copy the denial message into the request structure */
	req->denial_reason = reason;
	req->denial_message = globus_libc_strdup(message);

	req->proto->deny(req->proto,
			 request);

	req->proto->destroy(req->proto,
			    request);

	/* Destroy our reference to the request */
	globus_i_gass_transfer_request_destroy(request);
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	/* delete our reference to this request and proto */
	req->proto->destroy(req->proto,
			    request);
	globus_i_gass_transfer_request_destroy(request);
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
	goto error_exit;
    }

    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_deny() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
int
globus_i_gass_transfer_close_listener(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_listener_struct_t *	l,
    globus_gass_transfer_close_callback_t 	callback,
    void *					user_arg)
{
    int						rc = GLOBUS_SUCCESS;
    globus_reltime_t                            delay_time;

    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	rc = GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED;
	break;

      case GLOBUS_GASS_TRANSFER_LISTENER_STARTING:
      case GLOBUS_GASS_TRANSFER_LISTENER_READY:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_CLOSED;
	l->proto->close_listener(l->proto,
				 listener);
	l->proto->destroy(l->proto,
			  listener);

	l->close_callback = callback;
	l->close_callback_arg = user_arg;

        GlobusTimeReltimeSet(delay_time, 0, 0);
	globus_callback_register_oneshot(
	    GLOBUS_NULL,
	    &delay_time,
	    globus_l_gass_transfer_callback_close_callback,
	    (void *) listener);

	break;

      case GLOBUS_GASS_TRANSFER_LISTENER_LISTENING:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1;

	l->close_callback = callback;
	l->close_callback_arg = user_arg;

	l->proto->close_listener(l->proto,
				 listener);
	break;
	
      case GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2;

	l->close_callback = callback;
	l->close_callback_arg = user_arg;
	l->proto->close_listener(l->proto,
				 listener);
	break;

      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	rc = GLOBUS_GASS_TRANSFER_ERROR_DONE;
	break;
    }

    return rc;
}

static
void
globus_l_gass_transfer_callback_close_callback(
    void *					arg)
{
    globus_gass_transfer_listener_t 		listener;
    globus_gass_transfer_listener_struct_t * 	l;
    globus_gass_transfer_close_callback_t	callback;
    void *					callback_arg;

    listener = (globus_gass_transfer_listener_t) arg;

    l = (globus_gass_transfer_listener_struct_t *) arg;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);
    globus_assert(l != GLOBUS_NULL);

    callback = l->close_callback;
    callback_arg = l->close_callback_arg;

    globus_i_gass_transfer_listener_destroy(listener);

    globus_i_gass_transfer_unlock();
    callback(callback_arg,
	     listener);

    globus_i_gass_transfer_lock();
    globus_i_gass_transfer_listener_destroy(listener);
    globus_i_gass_transfer_unlock();
}
/* globus_l_gass_transfer_callback_close_callback() */

int
globus_i_gass_transfer_listener_destroy(
    globus_gass_transfer_listener_t		listener)
{
    globus_bool_t				referenced;
    globus_gass_transfer_listener_struct_t *	l;

    l =
	globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);
    if(l == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;
    }

    referenced =
	globus_handle_table_decrement_reference(&globus_i_gass_transfer_listener_handles,
						listener);
    if(!referenced)
    {
	globus_list_t *				tmp;

	tmp = globus_list_search(globus_i_gass_transfer_listeners,
				 (void *) listener);

	globus_list_remove(&globus_i_gass_transfer_listeners,
			   tmp);
	globus_cond_signal(&globus_i_gass_transfer_shutdown_cond);
	
	if(l->base_url)
	{
	    globus_free(l->base_url);
	}
	globus_free(l);

	return GLOBUS_SUCCESS;
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
}
/* globus_i_gass_transfer_listener_destroy() */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
