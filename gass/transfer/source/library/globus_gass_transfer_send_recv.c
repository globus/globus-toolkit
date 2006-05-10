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
 *
 * @file globus_gass_transfer_send_recv.c Send/Receive Data
 *
 * This module implements the send and receive functionality of the
 * GASS transfer library.
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
/**
 * @name Module Specific Functions
 */
/* @{ */
static
int
globus_l_gass_transfer_state_check(
    globus_gass_transfer_request_struct_t *	request);

static
int
globus_l_gass_transfer_size_check(
    globus_gass_transfer_request_struct_t *	request,
    globus_size_t 				send_length);

static
void
globus_l_gass_transfer_drain_callbacks(
    void *					arg);
/* @} */
#endif

/**
 * Send a byte array associated with a request handle.
 * @ingroup globus_gass_transfer_data
 *
 * This function sends a block of data to a server or client as
 * part of the processing for a request. Multiple data blocks may be
 * registered with the GASS transfer library at once.
 *
 * When processing a server request, this function may only be used in
 * conjunction with "get" requests. The user must call
 * globus_gass_transfer_authorize() before calling this function.
 *
 * When processing a client request, this function may only be used in
 * conjunction with "put" or "append" requests. This function may not
 * be called before either the callback function has been invoked, or the
 * blocking globus_gass_tranfser_put() or globus_gass_transfer_append()
 * function has returned.
 *
 * @param request
 *        The request handle with which this block of bytes is associated.
 * @param bytes
 *        A user-supplied buffer containing the data associated with the
 *        request.
 * @param send_length
 *        The lenght of the @a bytes array.
 * @param last_data
 *        A flag to indicate whether this is the final block of data
 *        for the request. If this is true, then the @a callback
 *        function will be delayed until the server acknowledges that
 *        the file has been completely received.
 * @param callback
 *        Function to call once the @a bytes array has been sent.
 * @param user_arg
 *        Argument to be passed to the @a callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The @a bytes array was successfully registered with the GASS
 *         transfer library. The @a callback function will be invoked once
 *         it has been sent.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         The @a bytes or @a callback parameter was NULL.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USER
 *         The @a request was invalid, or it is not one on which bytes
 *         can be sent.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED
 *         The callback to a non-blocking file request has not been invoked
 *         yet, a blocking file request has not returned, or the request has
 *         not yet been authorized.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_REQUEST_FAILED
 *         The @a request has failed by either the client, server, or protocol
 *         module implementation.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_DONE
 *         The @a request has already been completed.
 */
int
globus_gass_transfer_send_bytes(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				send_length,
    globus_bool_t				last_data,
    globus_gass_transfer_bytes_callback_t	callback,
    void *					user_arg)
{
    int						rc;
    globus_gass_transfer_pending_t *		pending;
    globus_gass_transfer_request_struct_t *	req;

    globus_i_gass_transfer_lock();

    /* Sanity check on passed arguments */
    if(bytes == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;

	goto error_exit;
    }
    if(callback == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;

	goto error_exit;
    }
    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);

    if(req == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto error_exit;
    }
    else if(req->client_side == GLOBUS_FALSE &&
	    req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto error_exit;
    }
    else if(req->client_side != GLOBUS_FALSE &&
	    req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT &&
	    req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto error_exit;
    }

    /*
     * Verify that the request is in a state that allows new data
     * blocks to be sent
     */
    rc = globus_l_gass_transfer_state_check(req);
    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    /*
     * Verify that the sending this amount of data won't overflow the
     * original request size. 
     */
    rc = globus_l_gass_transfer_size_check(req,
					   send_length);
    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    /*
     * Create a pending data structure, to be queued up in the request's
     * fifo.
     */
    pending = (globus_gass_transfer_pending_t *)
	globus_malloc(sizeof(globus_gass_transfer_pending_t));

    if(pending == GLOBUS_NULL)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_MALLOC_FAILED;
	goto error_exit;
    }
    pending->last_data		= last_data;
    pending->length		= send_length;
    pending->pending		= GLOBUS_FALSE;
    pending->request		= request;
    pending->bytes		= bytes;
    pending->callback		= callback;
    pending->callback_arg	= user_arg;

    /*
     * Posted length is the total amount of data which has been queued
     * for this request. It is used for detecting overflows.
     */
    req->posted_length += send_length;
    globus_fifo_enqueue(&req->pending_data,
			pending);

    /*
     * Call the send dispatcher to (maybe) send some more data to the
     * protocol module to send over the connection.
     */
    globus_i_gass_transfer_send_dispatcher(request);

    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_send_bytes() */

/**
 * Receive a byte array associated with a request handle.
 * @ingroup globus_gass_transfer_data
 *
 * This function receives a block of data from a server or client as
 * part of the processing for a request. Multiple data blocks may be
 * registered with the GASS transfer library at once.
 *
 * When processing a server request, this function may only be used in
 * conjunction with "put" or "append" requests. The user must call
 * globus_gass_transfer_authorize() before calling this function.
 *
 * When processing a client request, this function may only be used in
 * conjunction with "get" requests. This function may not
 * be called before either the callback function has been invoked, or the
 * blocking globus_gass_tranfser_put() or globus_gass_transfer_append()
 * function has returned.
 *
 * @param request
 *        The request handle with which this block of bytes is associated.
 * @param bytes
 *        A user-supplied buffer containing the data associated with the
 *        request.
 * @param max_length
 *        The lenght of the @a bytes array.
 * @param wait_for_length
 *        The minimum amount of data to wait for before invoking the @a
 *        callback function. A partial byte array of at least this amount
 *        will be returned in the callback, unless end-of-file is reached
 *        before this amount.
 * @param callback
 *        Function to call once the @a bytes array has been received.
 * @param user_arg
 *        Argument to be passed to the @a callback function.
 *
 * @retval GLOBUS_SUCCESS
 *         The @a bytes array was successfully registered with the GASS
 *         transfer library. The @a callback function will be invoked once
 *         it has been received.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER
 *         The @a bytes or @a callback parameter was NULL.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_INVALID_USER
 *         The @a request was invalid, or it is not one on which bytes
 *         can be sent.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED
 *         The callback to a non-blocking file request has not been invoked
 *         yet, a blocking file request has not returned, or the request has
 *         not yet been authorized.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_REQUEST_FAILED
 *         The @a request has failed by either the client, server, or protocol
 *         module implementation.
 * @retval GLOBUS_GASS_TRANSFER_ERROR_DONE
 *         The @a request has already been completed.
 */
int
globus_gass_transfer_receive_bytes(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				max_length,
    globus_size_t				wait_for_length,
    globus_gass_transfer_bytes_callback_t	callback,
    void *					user_arg)
{
    int						rc;
    globus_gass_transfer_pending_t *		pending;
    globus_gass_transfer_request_struct_t *	req;

    globus_i_gass_transfer_lock();

    /* Sanity check on passed arguments */
    if(bytes == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;

	goto error_exit;
    }
    if(callback == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;

	goto error_exit;
    }
    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);

    if(req == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto error_exit;
    }
    /*
     * Verify that the request is in a state that allows new data
     * blocks to be received
     */
    rc = globus_l_gass_transfer_state_check(req);
    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    if(req->client_side == GLOBUS_FALSE &&
	    req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT &&
	    req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto error_exit;
    }
    else if(req->client_side != GLOBUS_FALSE &&
	    req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto error_exit;
    }
    /*
     * Create a pending data structure, to be queued up in the request's
     * fifo.
     */
    pending = (globus_gass_transfer_pending_t *)
	globus_malloc(sizeof(globus_gass_transfer_pending_t));

    if(pending == GLOBUS_NULL)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_MALLOC_FAILED;
	goto error_exit;
    }
    pending->last_data		= GLOBUS_FALSE;
    pending->length		= max_length;
    pending->wait_for_length	= wait_for_length;
    pending->pending		= GLOBUS_FALSE;
    pending->request		= request;
    pending->bytes		= bytes;
    pending->callback		= callback;
    pending->callback_arg	= user_arg;

    globus_fifo_enqueue(&req->pending_data,
			pending);

    /*
     * Call the recv dispatcher to (maybe) receive some more data from the
     * protocol module.
     */
    globus_i_gass_transfer_recv_dispatcher(request);

    globus_i_gass_transfer_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_receive_bytes() */

/*
 * Function: globus_gass_transfer_fail()
 * 
 * Description: User-triggered error. Signal failure to the
 *              protocol module, and call any oustanding callbacks
 * 
 * Parameters: 
 * 
 * Returns: 
 */
int
globus_gass_transfer_fail(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_callback_t		callback,
    void *					callback_arg)
{
    globus_gass_transfer_request_struct_t *	req;
    int						rc = GLOBUS_SUCCESS;

    globus_i_gass_transfer_lock();
    req = globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				     request);

    if(req == GLOBUS_NULL)
    {
        rc = GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE;

	goto finish;
    }
    if(callback == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER;

	goto finish;
    }

    rc = globus_i_gass_transfer_fail(request,
				     req,
				     callback,
				     callback_arg);
  finish:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_fail() */


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
int
globus_i_gass_transfer_fail(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_struct_t *	req,
    globus_gass_transfer_callback_t		callback,
    void *					callback_arg)
{
    int						rc = GLOBUS_SUCCESS;
    globus_reltime_t                            delay_time; 

    switch(req->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
	req->fail_callback = callback;
	req->fail_callback_arg = callback_arg;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING;
	req->proto->fail(req->proto,
			 request);
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
	rc = GLOBUS_GASS_TRANSFER_ERROR_DONE;
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
	req->fail_callback = callback;
	req->fail_callback_arg = callback_arg;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	req->proto->fail(req->proto,
			 request);

	/* Drain queue of pending data requests,
	 * call fail callback, and destroy the request
	 */
        GlobusTimeReltimeSet(delay_time, 0, 0);
	globus_callback_register_oneshot(
	    GLOBUS_NULL,
	    &delay_time,
	    globus_l_gass_transfer_drain_callbacks,
	    (void *) request);
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_REFERRING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
	rc = GLOBUS_GASS_TRANSFER_ERROR_DONE;
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
	req->fail_callback = callback;
	req->fail_callback_arg = callback_arg;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1;
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
	req->fail_callback = callback;
	req->fail_callback_arg = callback_arg;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2;
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	req->fail_callback = callback;
	req->fail_callback_arg = callback_arg;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3;
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
	req->fail_callback = callback;
	req->fail_callback_arg = callback_arg;
	req->status = GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL;
	break;
      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	break;
    }

    return rc;
}
/* globus_i_gass_transfer_fail() */

/*
 * Function: globus_l_gass_transfer_state_check()
 * 
 * Description: Verify that the request structure is in the proper state
 *              for this send or receive.
 * 
 * Parameters: 
 * 
 * Returns: 
 */
static
int
globus_l_gass_transfer_state_check(
    globus_gass_transfer_request_struct_t *	request)
{
    if(request->type == GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID)
    {
	return GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED;
    }
    switch(request->status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	return GLOBUS_SUCCESS;
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
      case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
      case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
      case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
	return GLOBUS_GASS_TRANSFER_ERROR_REQUEST_FAILED;
      case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
	return GLOBUS_GASS_TRANSFER_ERROR_DONE;
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
      case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
      case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
      default:
	return GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED;
    }
}
/* globus_l_gass_transfer_state_check() */

/*
 * Function: globus_l_gass_transfer_size_check()
 * 
 * Description: Verify that the amount of data being sent or received
 *              won't overflow the request's size limit.
 * 
 * Parameters: 
 * 
 * Returns: 
 */
static
int
globus_l_gass_transfer_size_check(
    globus_gass_transfer_request_struct_t *	request,
    globus_size_t				send_length)
{
    if(request->length == GLOBUS_GASS_TRANSFER_LENGTH_UNKNOWN)
    {
	/* can't go wrong here */
	return GLOBUS_SUCCESS;
    }
    else if(request->posted_length + send_length >
	    request->length)
    {
	/* enough is specified to detect overflow */
	return GLOBUS_GASS_TRANSFER_ERROR_TOO_LARGE;
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
}
/* globus_l_gass_transfer_size_check() */

/*
 * Function: globus_i_gass_transfer_send_disaptcher()
 * 
 * Description: if the head of the pending fifo should be
 *              sent over, send it.
 * 
 * Parameters: 
 * 
 * Returns: 
 */
void
globus_i_gass_transfer_send_dispatcher(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_pending_t *		head;
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);

    if(req == GLOBUS_NULL)
    {
	return;
    }
    /* If we are not in the PENDING state, we should not look at the queue */
    if(req->status != GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
    {
	return;
    }

    /* If the fifo is empty, there is nothing to do */
    if(globus_fifo_empty(&req->pending_data))
    {
	return;
    }
    head = globus_fifo_peek(&req->pending_data);

    if(head->pending == GLOBUS_TRUE)
    {
	/*
	 * If the first in the fifo has already been sent to
	 * the protocol module, there is nothing to do
	 */
	return;
    }
    else
    {
	head->pending = GLOBUS_TRUE;
        req->status = GLOBUS_GASS_TRANSFER_REQUEST_ACTING;

	globus_i_gass_transfer_unlock();
	req->proto->send_buffer(req->proto,
				request,
				head->bytes,
				head->length,
				head->last_data);
	globus_i_gass_transfer_lock();
    }
}
/* globus_i_gass_transfer_send_dispatcher() */


/*
 * Function: globus_i_gass_transfer_recv_disaptcher()
 * 
 * Description: check if the head of the pending fifo should be
 *              given to the protocol module for a receive
 * 
 * Parameters: 
 * 
 * Returns: 
 */
void
globus_i_gass_transfer_recv_dispatcher(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_pending_t *		head;
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);

    /* If we are not in the PENDING state, we should not look at the queue */
    if(req->status != GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
    {
	return;
    }

    /* If the fifo is empty, there is nothing to do */
    if(globus_fifo_empty(&req->pending_data))
    {
	return;
    }

    head = globus_fifo_peek(&req->pending_data);

    if(head->pending == GLOBUS_TRUE)
    {
	/*
	 * If the first in the fifo has already been sent to
	 * the protocol module, there is nothing to do
	 */
	return;
    }
    else
    {
	head->pending = GLOBUS_TRUE;
        req->status = GLOBUS_GASS_TRANSFER_REQUEST_ACTING;

	globus_i_gass_transfer_unlock();
	req->proto->recv_buffer(req->proto,
				request,
				head->bytes,
				head->length,
				head->wait_for_length);
	globus_i_gass_transfer_lock();
    }
}
/* globus_i_gass_transfer_recv_dispatcher() */

static
void
globus_l_gass_transfer_drain_callbacks(
    void *					arg)
{
    globus_gass_transfer_request_t		request;
    globus_gass_transfer_request_struct_t *	req;
    globus_gass_transfer_callback_t		callback;
    void *					callback_arg;

    request = (globus_gass_transfer_request_t) arg;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return;
    }

    if(globus_i_gass_transfer_deactivating)
    {
	callback = globus_i_gass_transfer_deactivate_callback;
	callback_arg = GLOBUS_NULL;
    }
    else
    {
	callback = req->fail_callback;
	callback_arg = req->fail_callback_arg;
    }

    /* drain queue of pending data requests */
    while(!globus_fifo_empty(&req->pending_data))
    {
	globus_gass_transfer_pending_t *	pending;
	
	pending = globus_fifo_dequeue(&req->pending_data);
	
	if(!globus_i_gass_transfer_deactivating)
	{
	    globus_i_gass_transfer_unlock();
	    pending->callback(pending->callback_arg,
			      request,
			      pending->bytes,
			      0,
			      GLOBUS_TRUE);
	    globus_i_gass_transfer_lock();
	}
	globus_free(pending);
    }

    /* free up references to request and proto */
    req->proto->destroy(req->proto,
			request);
    /* free up GASS's reference to this request */
    globus_i_gass_transfer_request_destroy(request);

    if(callback)
    {
	callback(callback_arg,
		 request);
    }
}
/* globus_l_gass_transfer_drain_callbacks() */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
