/******************************************************************************
globus_gass_transfer_server.c
 
Description:
    This module implements the gass server functionality of the GASS
    transfer library
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_i_gass_transfer.h"

static
globus_bool_t
globus_l_gass_transfer_callback_close_callback(
    globus_time_t				time_can_block,
    void *					arg);

/* Server Interface */

/*
 * Function: globus_gass_transfer_create_listener()
 * 
 * Description: Creates a new protocol-specific listener for the GASS server.
 *              This function initializes the listener struct, and then
 *              calls into the GASS protocol module specific
 *              to the URL scheme to really create a listener.
 * 
 * Parameters:  A new listener (listener)
 *              Protocol-specific Attributes for that listener
 *              The protocol scheme to implement for the listener.
 * 
 * Returns:  
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
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    if(scheme == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }

    globus_i_gass_transfer_lock();
    protocol = (globus_gass_transfer_proto_descriptor_t *)
	globus_hashtable_lookup(&globus_i_gass_transfer_protocols,
				(void *) scheme);
    if(protocol == GLOBUS_NULL ||
       protocol->new_listener == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_NOT_IMPLEMENTED;
	goto error_exit;
    }
    l = globus_malloc(sizeof(globus_gass_transfer_listener_struct_t));
    if(l == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_MALLOC_FAILED;
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
	goto listener_exit;
    }

    l->status = GLOBUS_GASS_TRANSFER_LISTENER_STARTING;

    globus_i_gass_transfer_unlock();

    return GLOBUS_SUCCESS;

  listener_exit:
    if(l->base_url != GLOBUS_NULL)
    {
	globus_free(l->base_url);
    }
    globus_free(l);

  error_exit:
    globus_i_gass_transfer_unlock();

    return rc;
}
/* globus_gass_transfer_create_listener() */

int
globus_i_gass_transfer_close_listener(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_listener_struct_t *	l,
    globus_gass_transfer_close_callback_t 	callback,
    void *					user_arg)
{
    int						rc = GLOBUS_SUCCESS;

    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
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

	globus_callback_register_oneshot(
	    GLOBUS_NULL /* callback handle */,
	    (globus_time_t) 0,
	    globus_l_gass_transfer_callback_close_callback,
	    (void *) listener,
	    GLOBUS_NULL /* wakeup func */,
	    GLOBUS_NULL /* wakeup arg */);

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
	rc = GLOBUS_GASS_ERROR_DONE;
	break;
    }

    return rc;
}

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
	rc =  GLOBUS_GASS_ERROR_INVALID_USE;
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
	rc =  GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }
    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
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
	rc = GLOBUS_GASS_ERROR_ALREADY_REGISTERED;

      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	rc = GLOBUS_GASS_ERROR_DONE;
	break;
    }
    
    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;
  error_exit:
    globus_i_gass_transfer_unlock();

    return rc;
}
/* globus_gass_transfer_register_listener() */

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
	rc =  GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }
    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
      case GLOBUS_GASS_TRANSFER_LISTENER_READY:
	globus_i_gass_transfer_request_init(request,
					    attr,
					    GLOBUS_NULL,
					    GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID,
					    callback,
					    user_arg);

	if(*request == GLOBUS_HANDLE_TABLE_NO_HANDLE)
	{
	    rc = GLOBUS_GASS_ERROR_INTERNAL_ERROR;
	    goto error_exit;
	}

	req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
					 (*request));

	if(req== GLOBUS_NULL)
	{
	    rc = GLOBUS_GASS_ERROR_INTERNAL_ERROR;
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
	rc = GLOBUS_GASS_ERROR_NOT_REGISTERED;
	goto error_exit;
      case GLOBUS_GASS_TRANSFER_LISTENER_LISTENING:
      case GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING:
	rc = GLOBUS_GASS_ERROR_ALREADY_REGISTERED;
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	rc = GLOBUS_GASS_ERROR_DONE;
	break;
    }
    
    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;
  error_exit:
    globus_i_gass_transfer_unlock();

    return rc;
}
/* globus_gass_transfer_register_accept() */


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
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else
    {
	l->user_pointer = user_pointer;
	return GLOBUS_SUCCESS;
    }
}

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

    if(req== GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }

    if(req->proto->refer == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_NOT_IMPLEMENTED;
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
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }
    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;

}
/* globus_gass_transfer_refer() */

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

    if(req== GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }

    if(req->proto->authorize == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_NOT_IMPLEMENTED;
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
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }

    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_authorize() */

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

    if(req== GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }

    if(req->proto->deny == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_NOT_IMPLEMENTED;
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
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto error_exit;
    }

    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_deny() */

static
globus_bool_t
globus_l_gass_transfer_callback_close_callback(
    globus_time_t				time_can_block,
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
    return GLOBUS_TRUE;
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
	return GLOBUS_GASS_ERROR_INVALID_USE;
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
