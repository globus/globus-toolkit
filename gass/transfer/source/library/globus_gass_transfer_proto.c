/******************************************************************************
globus_gass_transfer_proto.c
 
Description:
    This module implements the GASS transfer protocol module library
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_i_gass_transfer.h"

static
void
globus_l_gass_transfer_operation_complete(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				nbytes,
    globus_bool_t				failed,
    globus_bool_t				last_data,
    globus_gass_transfer_dispatch_func_t	dispatcher);
/*
 * Function: globus_gass_transfer_proto_send_complete()
 * 
 * 
 * Description: Called by protocol module when a pending send for a request
 *              has completed. 
 */
void
globus_gass_transfer_proto_send_complete(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				nbytes,
    globus_bool_t				failed,
    globus_bool_t				last_data)
{
    globus_l_gass_transfer_operation_complete(request,
					      bytes,
					      nbytes,
					      failed,
					      last_data,
					      globus_i_gass_transfer_send_dispatcher);
}
/* globus_gass_transfer_proto_send_complete() */

void
globus_gass_transfer_proto_receive_complete(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				nbytes,
    globus_bool_t				failed,
    globus_bool_t				last_data)
{
    globus_l_gass_transfer_operation_complete(request,
					      bytes,
					      nbytes,
					      failed,
					      last_data,
					      globus_i_gass_transfer_recv_dispatcher);
}
/* globus_gass_transfer_proto_receive_complete() */

static
void
globus_l_gass_transfer_operation_complete(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				nbytes,
    globus_bool_t				failed,
    globus_bool_t				last_data,
    globus_gass_transfer_dispatch_func_t	dispatcher)
{
    globus_gass_transfer_request_struct_t *	req;
    globus_gass_transfer_pending_t *		head;
    globus_gass_transfer_callback_t		fail_callback=GLOBUS_NULL;
    void *					callback_arg;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	goto finish;
    }

    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
	if(! last_data)
	{
	    /*
	     * normal operation, go back to pending state, callback
	     * to user
	     */
	    req->status = GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING;

	    while(req->status == GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING ||
		  (
		      (req->status == GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING ||
		       req->status == GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING)
		   && !globus_fifo_empty(&req->pending_data)))
	    {
		head = globus_fifo_dequeue(&req->pending_data);

		/* Call back to user */
		globus_i_gass_transfer_unlock();
		head->callback(head->callback_arg,
			       request,
			       head->bytes,
			       nbytes,
			       last_data);
		globus_i_gass_transfer_lock();
		nbytes = 0;
		last_data = GLOBUS_TRUE;

		globus_free(head);

		if(req->status == GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING)
		{
		    req->status = GLOBUS_GASS_TRANSFER_REQUEST_PENDING;
		}
	    }
	    if(req->status == GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
	    {
		/* dispatch next, if available */
		dispatcher(request);
		break;
	    }
	    else if(req->status == GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING)
	    {
		req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
		fail_callback = req->fail_callback;
		callback_arg = req->fail_callback_arg;

		/* free up references to request and proto */
		req->proto->destroy(req->proto,
				    request);
		/* free up the GASS's reference to this request */
		globus_i_gass_transfer_request_destroy(request);
		
		globus_i_gass_transfer_unlock();
		if(fail_callback != GLOBUS_NULL)
		{
		    fail_callback(callback_arg,
				  request);
		}
		globus_i_gass_transfer_lock();
	    }
	}
	else
	{
	    /* failed or done */
	    if(failed)
	    {
		req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILING;
		last_data = GLOBUS_TRUE;
	    }
	    else
	    {
		req->status = GLOBUS_GASS_TRANSFER_REQUEST_FINISHING;
	    }

	    while(!globus_fifo_empty(&req->pending_data))
	    {
		head = globus_fifo_dequeue(&req->pending_data);

		/* Call back to user */
		globus_i_gass_transfer_unlock();
		head->callback(head->callback_arg,
			       request,
			       head->bytes,
			       nbytes,
			       last_data);

		globus_i_gass_transfer_lock();

		nbytes = 0;
		globus_free(head);
	    }
	    fail_callback = req->fail_callback;
	    callback_arg = req->fail_callback_arg;

	    /* free up references to request and proto */
	    req->proto->destroy(req->proto,
				request);
	    /* free up the proto's and GASS's reference to this request */
	    globus_i_gass_transfer_request_destroy(request);

	    globus_i_gass_transfer_unlock();
	    if(fail_callback != GLOBUS_NULL)
	    {
		fail_callback(callback_arg,
			      request);
	    }
	    globus_i_gass_transfer_lock();
	}

	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILING;
	last_data = GLOBUS_TRUE;

	while(!globus_fifo_empty(&req->pending_data))
	{
	    head = globus_fifo_dequeue(&req->pending_data);

	    /* Call back to user */
	    globus_i_gass_transfer_unlock();
	    head->callback(head->callback_arg,
			   request,
			   head->bytes,
			   nbytes,
			   last_data);

	    globus_free(head);

	    nbytes = 0;
	    globus_i_gass_transfer_lock();
	}
	fail_callback = req->fail_callback;
	callback_arg = req->fail_callback_arg;
	/* free up references to request and proto */
	req->proto->destroy(req->proto,
			    request);
	/* free up the proto's and GASS's reference to this request */
	globus_i_gass_transfer_request_destroy(request);

	globus_i_gass_transfer_unlock();
	fail_callback(callback_arg,
		      request);
	return;

      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_REFERRING;
	last_data = GLOBUS_TRUE;

	while(!globus_fifo_empty(&req->pending_data))
	{
	    head = globus_fifo_dequeue(&req->pending_data);

	    /* Call back to user */
	    globus_i_gass_transfer_unlock();
	    head->callback(head->callback_arg,
			   request,
			   head->bytes,
			   nbytes,
			   last_data);

	    globus_free(head);

	    nbytes = 0;
	    globus_i_gass_transfer_lock();
	}
	/* free up references to request and proto */
	req->proto->destroy(req->proto,
			    request);
	/* free up the proto's and GASS's reference to this request */
	globus_i_gass_transfer_request_destroy(request);

	globus_i_gass_transfer_unlock();

	return;

      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_PENDING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_DENIED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_DONE);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_STARTING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_STARTING2);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_STARTING3);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FINISHING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRING);
	goto finish;
      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	goto finish;
    }

  finish:
    globus_i_gass_transfer_unlock();
    return;
}
/* globus_l_gass_transfer_operation_complete() */

void
globus_gass_transfer_proto_listener_ready(
    globus_gass_transfer_listener_t		listener)
{
    globus_gass_transfer_listener_struct_t *	l;
    globus_gass_transfer_listen_callback_t	callback;
    void *					callback_arg;
    globus_gass_transfer_listen_callback_t	close_callback = GLOBUS_NULL;
    void *					close_callback_arg;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	goto error_exit;
    }
    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
	goto error_exit;
      case GLOBUS_GASS_TRANSFER_LISTENER_LISTENING:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_READY;
	callback = l->listen_callback;
	callback_arg = l->listen_callback_arg;
	globus_i_gass_transfer_unlock();

	callback(callback_arg,
		 listener);

	return;
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_CLOSED;
	callback = l->listen_callback;
	callback_arg = l->listen_callback_arg;

	close_callback = l->close_callback;
	close_callback_arg = l->close_callback_arg;
	
	/* Destroy our reference to the proto */
	l->proto->destroy(l->proto,
			  listener);
	/*
	 * Destroy GASS's reference
	 * to this listener
	 */
	globus_i_gass_transfer_listener_destroy(listener);

	globus_i_gass_transfer_unlock();

	callback(callback_arg,
		 listener);
	if(close_callback)
	{
	    close_callback(close_callback_arg,
			   listener);
	}
	globus_i_gass_transfer_lock();
	globus_i_gass_transfer_listener_destroy(listener);
	globus_i_gass_transfer_unlock();
	return;

      case GLOBUS_GASS_TRANSFER_LISTENER_READY:
      case GLOBUS_GASS_TRANSFER_LISTENER_STARTING:
      case GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_READY);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_STARTING);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_CLOSED);
	break;
    }
    
    globus_i_gass_transfer_unlock();
    return;
  error_exit:
    globus_i_gass_transfer_unlock();
}
/* globus_gass_transfer_proto_listener_ready() */

int
globus_gass_transfer_proto_register_protocol(
    globus_gass_transfer_proto_descriptor_t *	proto_desc)
{
    globus_hashtable_insert(&globus_i_gass_transfer_protocols,
			    proto_desc->url_scheme,
			    proto_desc);
    return GLOBUS_SUCCESS;
}


int
globus_gass_transfer_proto_unregister_protocol(
    globus_gass_transfer_proto_descriptor_t *	proto_desc)
{
    globus_gass_transfer_proto_descriptor_t *	tmp;
    
    tmp = globus_hashtable_lookup(&globus_i_gass_transfer_protocols,
				  proto_desc->url_scheme);
    if(tmp)
    {
	tmp = globus_hashtable_remove(&globus_i_gass_transfer_protocols,
				      proto_desc->url_scheme);
	return GLOBUS_SUCCESS;
    }
    else
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
}
/*
 * Function: globus_gass_transfer_proto_request_ready()
 * 
 * Description: Called by protocol module when a request has been submitted
 *              to a server (in the client case), or received from a client
 * 	     (in the server case)
 * 
 * Parameters:  A new request (request)
 *              A protocol instance bound to that request (proto)
 * 
 * Returns:  
 */
void
globus_gass_transfer_proto_request_ready(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_proto_t *	proto)
{
    globus_gass_transfer_request_struct_t *	req;
    globus_gass_transfer_callback_t		callback;
    void *					callback_arg;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	goto finish;
    }
    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_PENDING;
	req->proto = proto;

	if(req->type == GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT ||
	   req->type == GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND)
	{
	    globus_i_gass_transfer_recv_dispatcher(request);
	}
	else
	{
	    globus_i_gass_transfer_send_dispatcher(request);
	}
	globus_i_gass_transfer_unlock();
	return;
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_PENDING;
	req->proto = proto;

	callback = req->callback;
	callback_arg = req->callback_arg;

	globus_i_gass_transfer_unlock();
	callback(callback_arg,
		 request);
	return;
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	req->proto = proto;

	callback = req->callback;
	callback_arg = req->callback_arg;

	globus_i_gass_transfer_unlock();
	callback(callback_arg,
		 request);
	globus_i_gass_transfer_lock();
	/* free up references to request and proto */
	req->proto->destroy(req->proto,
			    request);
	/* free up GASS's reference to this request */
	globus_i_gass_transfer_request_destroy(request);
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_PENDING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_DENIED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_DONE);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_STARTING2);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FINISHING);
	/* FALLSTHROUGH */
      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	goto finish;
    }

  finish:
    globus_i_gass_transfer_unlock();
    return;
}
/* globus_gass_transfer_proto_request_ready() */

/*
 * Function: globus_gass_transfer_proto_new_listener_request()
 * 
 * 
 * Description: Called by protocol module when a new request has been
 *		parsed to be given to a listener to authorize, deny,
 *		or refer.
 */
void
globus_gass_transfer_proto_new_listener_request(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_proto_t *	proto)
{
    globus_gass_transfer_listener_struct_t *	l;
    globus_gass_transfer_request_struct_t *	req;

    globus_i_gass_transfer_lock();
    l = globus_handle_table_lookup(&globus_i_gass_transfer_listener_handles,
				   listener);

    if(l == GLOBUS_NULL)
    {
	globus_i_gass_transfer_unlock();
	return;
    }

    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);
    if(req == GLOBUS_NULL)
    {
	globus_i_gass_transfer_unlock();
	return;
    }

    req->proto = proto;

    switch(l->status)
    {
      case GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_STARTING;

	if(proto == GLOBUS_NULL)
	{
	    req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	}
	else
	{
	    req->status = GLOBUS_GASS_TRANSFER_REQUEST_STARTING2;

	    globus_assert(req->type !=
			  GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID);
	}

	/* Callback to user, regarding this request */
	globus_i_gass_transfer_unlock();
	req->callback(req->callback_arg,
		      request);
	return;
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2:
	l->status = GLOBUS_GASS_TRANSFER_LISTENER_CLOSED;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;

	/* Callback to user, regarding this request */
	globus_i_gass_transfer_unlock();

	req->callback(req->callback_arg,
		      request);
	globus_i_gass_transfer_lock();
	/*
	 * Fail and destroy this request, since the user
	 * has called the close function on this listener
	 */
	if(req->proto)
	{
	    req->proto->fail(req->proto,
			     request);
	    req->proto->destroy(req->proto,
				request);
	}
	
	/* Destroy GASS's reference to this request proto */
	globus_i_gass_transfer_request_destroy(request);

	/* Callback to user, regarding this listener */
	globus_i_gass_transfer_unlock();
	l->close_callback(l->close_callback_arg,
			  listener);
	globus_i_gass_transfer_lock();

	/* Destroy GASS's reference to this listener */
	globus_i_gass_transfer_listener_destroy(listener);

	globus_i_gass_transfer_unlock();

	return;
      case GLOBUS_GASS_TRANSFER_LISTENER_STARTING:
      case GLOBUS_GASS_TRANSFER_LISTENER_INVALID:
      case GLOBUS_GASS_TRANSFER_LISTENER_READY:
      case GLOBUS_GASS_TRANSFER_LISTENER_LISTENING:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1:
      case GLOBUS_GASS_TRANSFER_LISTENER_CLOSED:
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_STARTING);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_INVALID);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_READY);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_LISTENING);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1);
	globus_assert(l->status != GLOBUS_GASS_TRANSFER_LISTENER_CLOSED);
    }

    globus_i_gass_transfer_unlock();

    return;
}
/* globus_gass_transfer_proto_new_listener_request() */

void
globus_gass_transfer_proto_request_denied(
    globus_gass_transfer_request_t		request,
    int						reason,
    char *					message)
{
    globus_gass_transfer_request_struct_t *	req;
    globus_gass_transfer_callback_t		callback;
    void *					callback_arg;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	goto finish;
    }
    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_DENIED;

	req->denial_reason = reason;
	req->denial_message = message;

	callback = req->callback;
	callback_arg = req->callback_arg;

	globus_i_gass_transfer_unlock();
	callback(callback_arg,
		 request);
	globus_i_gass_transfer_lock();

	/* free up proto's and GASS's reference to the request */
	globus_i_gass_transfer_request_destroy(request);

	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_DENIED);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_DONE);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_PENDING);
	globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILED);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_STARTING2);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_STARTING3);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILING);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FINISHING);
	goto finish;
      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	goto finish;
    }

  finish:
    globus_i_gass_transfer_unlock();
    return;
}
/* globus_gass_transfer_proto_request_denied() */

void
globus_gass_transfer_proto_request_referred(
    globus_gass_transfer_request_t		request,
    char **					url,
    globus_size_t				num_urls)
{
    globus_gass_transfer_request_struct_t *	req;
    globus_gass_transfer_callback_t		callback;
    void *					callback_arg;
    globus_size_t				i;
    globus_gass_transfer_pending_t *		head;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
	goto finish;
    }
    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_REFERRED;
	req->referral_url = url;
	req->referral_count = num_urls;

	callback = req->callback;
	callback_arg = req->callback_arg;

	globus_i_gass_transfer_unlock();
	callback(callback_arg,
		 request);
	globus_i_gass_transfer_lock();

	/* free up GASS's reference to the request */
	globus_i_gass_transfer_request_destroy(request);

	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	req->referral_url = url;
	req->referral_count = num_urls;

	callback = req->callback;
	callback_arg = req->callback_arg;

	globus_i_gass_transfer_unlock();
	callback(callback_arg,
		 request);
	globus_i_gass_transfer_lock();

	/* free up GASS's reference to the request */
	globus_i_gass_transfer_request_destroy(request);

	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
	/* request is in progress, when operation completes,
	 * the callback queue will be drained
	 */
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING;
	req->referral_url = url;
	req->referral_count = num_urls;

	break;


      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_REFERRING;
	
	while(!globus_fifo_empty(&req->pending_data))
	{
	    head = globus_fifo_dequeue(&req->pending_data);

	    /* Call back to user */
	    globus_i_gass_transfer_unlock();
	    head->callback(head->callback_arg,
			   request,
			   head->bytes,
			   0,
			   GLOBUS_TRUE);
	    globus_i_gass_transfer_lock();

	    globus_free(head);

	    req->status = GLOBUS_GASS_TRANSFER_REQUEST_REFERRED;
	}
	/* free up references to request and proto */
	req->proto->destroy(req->proto,
			    request);
	/* free up the GASS's reference to this request */
	globus_i_gass_transfer_request_destroy(request);
	
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
	/* user callback in progress */
        req->status = GLOBUS_GASS_TRANSFER_REQUEST_REFERRING;
	req->referral_url = url;
	req->referral_count = num_urls;

	/* callbacks are going to occur after the current
	 * one completes (in the operation_complete function
	 * above)
	 */
	break;

      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
        /* free urls, no state change */
        goto free_urls;

      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRING);
        globus_assert(req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING);
        goto free_urls;
	
      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	goto finish;
    }
  finish:
    globus_i_gass_transfer_unlock();
    return;

  free_urls:
    for(i = 0; i < num_urls; i++)
    {
	globus_free(url[i]);
    }
    globus_free(url);

    return;
}
/* globus_gass_transfer_proto_request_referred() */
