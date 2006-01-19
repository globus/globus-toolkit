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
 * @file globus_io_common.c Globus I/O toolset
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */

/**
 * RCS Identification of this source file
 */
static char *rcsid = "$Header$";
#endif

/*
 * Include header files
 */
#include "globus_l_io.h"

/*
 * Module Specific Type Definitions
 */
typedef struct
{
    void *				callback_arg;
    globus_io_callback_t		callback;
} globus_io_close_info_t;

static
void
globus_l_io_close_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

void
globus_i_io_default_destructor(
    void *				arg);

/**
 * Asynchronously close the file or connection described by handle.
 *
 * When this function returns successfully, no further operations may
 * be done on this handle. Any outstanding requests on this handle
 * with be cancelled with their callbacks invoked before the close
 * completes.
 *
 * No other callbacks may be registered with the globus_io system for
 * this handle after this function is called. Close registrations may
 * not be canceled.
 *
 * @param handle The handle to close. Any valid handle may be closed
 * by calling this function.
 * @param callback The callback function is called after all of the
 * cancelled callbacks
 * have been dispatched and have reached their thread conversion point
 * or completed
 * @param callback_arg Parameter passed to the callback function.
 *
 * @return
 * This function returns GLOBUS_SUCCESS, or a result pointing to one of 
 * these error object types:
 * @retval
 * GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER 
 * The handle parameter was equal to NULL, so the close could not be
 * processed. 
 * @retval
 * GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED 
 * The handle parameter was not correctly initialized properly, so it
 * couldn't be closed. 
 * @retval
 * GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED 
 * The handle parameter was already registered for closing, so this
 * registration failed. 
 *
 * @see globus_io_register_cancel(), globus_io_cancel(), globus_io_close() 
 * @ingroup common
 */
globus_result_t
globus_io_register_close(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback,
    void *				callback_arg)
{
    globus_object_t *			err = GLOBUS_NULL;
    globus_io_close_info_t *		close_info;
    static char *			myname="globus_io_register_close";

    globus_i_io_debug_printf(2,
		            (stderr, "%s(): entering: handle=%p, handle->state = %d, fd=%d\n",
			     myname, (void *)handle, handle->state, handle->fd));
    if(handle == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);
	return globus_error_put(err);
    }
    
    globus_i_io_mutex_lock();
    
    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_INVALID:
	err = globus_io_error_construct_not_initialized(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);
	goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	err = globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle);
	
	goto error_exit;
      default:
        break;
    }
    
    handle->state = GLOBUS_IO_HANDLE_STATE_CLOSING;

    close_info = (globus_io_close_info_t *)
	globus_malloc(sizeof(globus_io_close_info_t));
    
    close_info->callback_arg = callback_arg;
    close_info->callback = callback;
    
    globus_i_io_register_cancel(handle,
				GLOBUS_TRUE,
				globus_l_io_close_callback,
				close_info,
				globus_i_io_default_destructor);

    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();
    
    return globus_error_put(err);
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Callback to finish closing a handle.
 *
 * This function is invoked after the cancel has been processed and
 * all callbacks have completed, or reached their thread conversion point.
 * The handle's descriptor is closed, and then the user callback is invoked.
 *
 * @param arg pointer to a globus_io_close_info_t structure containing
 * the callback information.
 * @param handle the handle which is ready to be closed
 * @param result the response of the cancellation. The result is propagated
 * to the user callback.
 *
 * @retval void
 * @ingroup common
 */
static
void
globus_l_io_close_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_io_close_info_t *		close_info;
    globus_io_callback_t		callback;
    void *				tmp_arg;
    globus_result_t			rc;
    globus_object_t *			err = GLOBUS_NULL;
    
    close_info = (globus_io_close_info_t *) arg;

    globus_i_io_mutex_lock();
    {
	rc = globus_i_io_close(handle);

	if(rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_get(rc);
	}
	globus_i_io_handle_destroy(handle);
    }
    globus_i_io_mutex_unlock();

    tmp_arg = close_info->callback_arg;
    callback = close_info->callback;

    globus_free(close_info);
    
    if(rc != GLOBUS_SUCCESS)
    {
	rc = globus_error_put(err);
    }
    callback(tmp_arg, handle, rc);
}
#endif

/**
 * Cancel any outstanding operation registered with the specified handle.
 * @ingroup common
 *
 * This is a blocking form of globus_io_register_cancel(). This
 * function blocks until the cancellation is completely processed.
 *
 * @param handle The handle to cancel. Any valid handle may be closed
 * by calling this function.
 * @param perform_callbacks If this parameter is set to GLOBUS_TRUE,
 * then this function will block until all outstanding callbacks for
 * this handle have been invoked and either completed or reached their
 * conversion point. Otherwise, this will unregister any pending
 * callbacks, and they will not be called.
 * @return This function returns GLOBUS_SUCCESS, or a result pointing
 * to one of these error object types:
 * @retval
 * GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER 
 * The handle parameter was equal to NULL, so the cancel could not be
 * processed.
 * @retval
 * GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED 
 * The handle parameter was not correctly initialized properly, so it
 * couldn't be closed. 
 * @retval
 * GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED 
 * The handle parameter was already registered for closing, so the cancel
 * could not be processed.
 *
 * @bug Cancel may succeed without cancelling anything, or causing any
 * callbacks  to be invoked.
 * @bug There currently is no way to cancel specific registered
 * callbacks without cancelling every registered operation.
 *
 * @see globus_io_register_cancel(), globus_io_register_close(),
 * globus_io_close()
 */
globus_result_t
globus_io_cancel(
    globus_io_handle_t *		handle,
    globus_bool_t                       perform_callbacks)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result;
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    handle->blocking_cancel = GLOBUS_TRUE;
    
    result = globus_io_register_cancel(handle,
				      perform_callbacks,
				      globus_i_io_monitor_callback,
				      (void *) &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	monitor.done = GLOBUS_TRUE;
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor.mutex);    

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);
    
    handle->blocking_cancel = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor.mutex);

    globus_cond_destroy(&monitor.cond);

    if(monitor.use_err)
    {
	return globus_error_put(monitor.err);
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
}
/* globus_io_cancel() */


/**
 * Close the file or connection associated with a handle.
 *
 * No further operations may be done on this handle. Any outstanding
 * requests on this handle with be cancelled (globus_io_cancel() will
 * be called with perform_callbacks set to true).  This may be called
 * for any handle type. This function blocks until any cancelled
 * callbacks have been dispatched and have either reached their thread
 * conversion point or completed.
 *
 * @param handle The handle to be closed.
 *
 * @return This function returns GLOBUS_SUCCESS, or a result pointing
 * to one of these error object types:
 * @retval
 * GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER 
 * The handle parameter was equal to NULL, so the close could not be
 * processed.
 * @retval
 * GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not correctly initialized properly, so it
 * couldn't be closed. 
 * @retval
 * GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED 
 * The handle parameter was already registered for closing, so this
 * registration failed.
 *
 * @see globus_io_register_close(), globus_io_register_cancel(),
 * globus_io_cancel()
 * @ingroup common
 */
globus_result_t
globus_io_close(
    globus_io_handle_t *		handle)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result;
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    handle->blocking_cancel = GLOBUS_TRUE;
    
    result = globus_io_register_close(handle,
				      globus_i_io_monitor_callback,
				      (void *) &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	monitor.done = GLOBUS_TRUE;
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor.mutex);    

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);
    
    handle->blocking_cancel = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor.mutex);

    globus_cond_destroy(&monitor.cond);

    if(monitor.use_err)
    {
	return globus_error_put(monitor.err);
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
    
}
/* globus_io_close() */

/*
 * Function:	globus_io_register_listen()
 *
 * Description: 
 *
 * Arguments:
 *
 */
globus_result_t
globus_io_register_listen(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback,
    void *				callback_arg)
{
    globus_result_t			rc;
    globus_object_t *			err;
    static char *			myname="globus_io_register_listen";
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif

    if(handle == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);
	
	return globus_error_put(err);
    }
    
    if(callback == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "callback",
	    2,
	    myname);
	
	return globus_error_put(err);
    }

    globus_i_io_mutex_lock();
    
    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_LISTENING:
	  break;
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	err = globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle);
	
	goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_INVALID:
      default:
	err = globus_io_error_construct_not_initialized(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);

	goto error_exit;
    }

    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER &&
       handle->type != GLOBUS_IO_HANDLE_TYPE_UDSS_LISTENER)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER or GLOBUS_IO_HANDLE_TYPE_UDSS_LISTENER");
	
	goto error_exit;
    }
    
#ifdef TARGET_ARCH_WIN32
	// check to make sure that no accepted socket exists from a previous
	// call to listen
	if ( handle->winIoOperation_structure.acceptedSocket != 
	 INVALID_SOCKET )
	{
		err = globus_io_error_construct_registration_error (
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle );
		goto error_exit;
	}
#endif

    rc = globus_i_io_register_quick_operation(
        handle,
        callback,
        callback_arg,
        GLOBUS_NULL,
        GLOBUS_TRUE,
        GLOBUS_I_IO_READ_OPERATION);

#ifdef TARGET_ARCH_WIN32
	if ( rc == GLOBUS_SUCCESS )
	{
		// post an accept
		returnCode= globus_i_io_winsock_accept( handle );
		if ( returnCode ) // a fatal error occurred
		{
			// unregister the quick read operation
            globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
				GLOBUS_I_IO_READ_OPERATION);

			err = globus_io_error_construct_system_failure(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle,
					returnCode );
			goto error_exit;
		}
	}
#endif

    globus_i_io_mutex_unlock();

    return rc;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_register_listen() */

/*
 * Function:	globus_io_listen()
 *
 * Description:	block until an accept will not block, or an exception has
 *		occurred.
 */
globus_result_t
globus_io_listen(
    globus_io_handle_t *		handle)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result;
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    handle->blocking_read = GLOBUS_TRUE;
    
    result = globus_io_register_listen(handle,
				       globus_i_io_monitor_callback,
				       (void *) &monitor);

    if(result != GLOBUS_SUCCESS)
    {
	monitor.done = GLOBUS_TRUE;
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
    }
    
    globus_mutex_lock(&monitor.mutex);

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor.mutex);

    globus_cond_destroy(&monitor.cond);

    if(monitor.use_err)
    {
	return globus_error_put(monitor.err);
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
    
}
/* globus_io_listen() */


/*
 * Function:	globus_io_get_user_pointer()
 *
 * Description: pull the user pointer out of the globus_io_handle_t and
 *		return it.
 *
 * Arguments:
 */
globus_result_t
globus_io_handle_get_user_pointer(
        globus_io_handle_t *		handle,
	void **				user_pointer)
    
{
    (*user_pointer) = handle->user_pointer;
    return GLOBUS_SUCCESS;
}
/* globus_io_handle_get_user_pointer() */


/*
 * Function:	globus_io_set_user_pointer()
 *
 * Description: pull the user pointer out of the globus_io_handle_t and
 *		return it.
 *
 * Arguments:
 */
globus_result_t
globus_io_handle_set_user_pointer(
        globus_io_handle_t *		handle,
	void *				arg)
    
{
    handle->user_pointer = arg;
    return GLOBUS_SUCCESS;
}
/* globus_io_handle_set_user_pointer() */


/*
 * Function:	globus_io_get_handle_type()
 *
 * Description: pull the handle type out of the globus_io_handle_t and
 *		return it.
 *
 * Arguments:
 */
globus_io_handle_type_t
globus_io_get_handle_type(
    globus_io_handle_t *		handle)
{
    return handle->type;
}
/* globus_io_get_handle_type() */


void
globus_i_io_handle_destroy(
    globus_io_handle_t *		handle)
{
    OM_uint32				maj,min;

    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    if(handle->context != GSS_C_NO_CONTEXT)
    {
	maj = gss_delete_sec_context(&min,
				     &handle->context,
				     GLOBUS_NULL);
	handle->context = GSS_C_NO_CONTEXT;
    }
    handle->context = GSS_C_NO_CONTEXT;
    if(handle->delegated_credential != GSS_C_NO_CREDENTIAL)
    {
	maj = gss_release_cred(&min,
		               &handle->delegated_credential);
	handle->delegated_credential = GSS_C_NO_CREDENTIAL;
    }
    if(handle->securesocket_attr.credential != GSS_C_NO_CREDENTIAL &&
       handle->securesocket_attr.internal_credential)
    {
	maj = gss_release_cred(&min,
			       &handle->securesocket_attr.credential);
       handle->securesocket_attr.credential = GSS_C_NO_CREDENTIAL;
    }
    
    globus_callback_space_destroy(handle->socket_attr.space);
}

/* callbacks */


/**
 * Wake up blocking calls.
 *
 * This function is used in most blocking I/O functions as the
 * callback. It simply wakes up the main thread by signalling the
 * moitor's mutex.
 *
 * @param arg
 *        A globus_i_io_monitor_t which a blocking globus_io_*()
 *	  call is blocking on.
 * @param handle
 *	  the handle passed to the blocking call
 * @param result
 *        The result which will be returned by the blocking call.
 */
void
globus_i_io_monitor_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_i_io_monitor_t *		monitor;
    globus_object_t *			err;
    globus_bool_t			use_err = GLOBUS_FALSE;
    
    monitor = (globus_i_io_monitor_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	use_err = GLOBUS_TRUE;
    }
    
    globus_mutex_lock(&monitor->mutex);

    if(use_err)
    {
	monitor->use_err = GLOBUS_TRUE;
	monitor->err = err;	
    }
    
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_i_io_monitor_callback() */



/**
 * Check whether a Globus error object is an EOF object.
 * @ingroup common
 *
 * @param err Error to check
 *
 * @return GLOBUS_TRUE if the error is an EOF error,
 * GLOBUS_FALSE otherwise.
 */
globus_bool_t
globus_io_eof(
    globus_object_t *			err)
{
    const globus_object_type_t *	type;
    
    if(err == GLOBUS_NULL)
    {
	return GLOBUS_FALSE;
    }
    
    type = globus_object_get_type(err);
    
    if(type == GLOBUS_NULL)
    {
	return GLOBUS_FALSE;
    }
    if(type != GLOBUS_IO_ERROR_TYPE_EOF)
    {
	return GLOBUS_FALSE;
    }
    else
    {
	return GLOBUS_TRUE;
    }
}
/* globus_io_eof() */

void
globus_i_io_default_destructor(
    void *				arg)
{
    globus_free(arg);
}


void
globus_i_io_connect_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_i_io_callback_info_t *	info;
    globus_bool_t                       sock_err = 0;
    int                                 sock_errlen;

    info = (globus_i_io_callback_info_t *) callback_arg;

    if(result == GLOBUS_SUCCESS)
    {
        sock_errlen = sizeof(sock_err);
		errno = 0;

#ifndef TARGET_ARCH_WIN32
		if(getsockopt(handle->fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_errlen) < 0)
		{
#else
		// perhaps change this to get the value of SOL_CONNECT_TIME?
		if(getsockopt((SOCKET)handle->io_handle, SOL_SOCKET, SO_ERROR, 
			&sock_err, &sock_errlen) == SOCKET_ERROR )
		{
			globus_i_io_winsock_get_last_error();
#endif
			sock_err = errno;
		}
		if(sock_err)
		{
			result = globus_error_put(
				globus_io_error_construct_system_failure(GLOBUS_IO_MODULE,
														GLOBUS_NULL,
														handle,
														sock_err));
		}
    }
    if(result == GLOBUS_SUCCESS)
    {
        handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    }
    else
    {
        globus_libc_close(handle->fd);
	handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    }
    
    info->callback(info->callback_arg, handle, result);

    globus_free(info);
}

void
globus_i_io_accept_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_i_io_callback_info_t *	info;
    globus_object_t *			err;

    info = (globus_i_io_callback_info_t *) callback_arg;

    err = globus_error_get(result);

    if(result == GLOBUS_SUCCESS)
    {
	handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;

	info->callback(info->callback_arg,
		       handle,
		       result);
    }
    else
    {
	globus_i_io_mutex_lock();

	handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
	globus_i_io_close(handle);

	globus_i_io_mutex_unlock();

	info->callback(info->callback_arg,
		       handle,
		       globus_error_put(err));


    }

    globus_free(info);
}

globus_result_t
globus_i_io_initialize_handle(
    globus_io_handle_t *                handle,
    globus_io_handle_type_t		type)
{
    handle->fd = -1;
    handle->context = GSS_C_NO_CONTEXT;
    handle->delegated_credential = GSS_C_NO_CREDENTIAL;
    handle->max_wrap_length = 0;
    memset(&handle->socket_attr,
           '\0',
           sizeof(globus_i_io_socketattr_instance_t));
    memset(&handle->securesocket_attr,
           '\0',
           sizeof(globus_i_io_securesocketattr_instance_t));
    memset(&handle->tcp_attr,
           '\0',
           sizeof(globus_i_io_tcpattr_instance_t));
    memset(&handle->udp_attr,
	   '\0',
	   sizeof(globus_i_io_udpattr_instance_t));
    handle->file_attr.file_type = GLOBUS_IO_FILE_TYPE_BINARY;

    handle->type = type;
    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    handle->user_pointer = GLOBUS_NULL;
    
    globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE);
    handle->socket_attr.space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    handle->blocking_read = GLOBUS_FALSE;
    handle->blocking_write = GLOBUS_FALSE;
    handle->blocking_except = GLOBUS_FALSE;
    handle->blocking_cancel = GLOBUS_FALSE;
    
    handle->read_operation = GLOBUS_NULL;
    handle->write_operation = GLOBUS_NULL;
    handle->except_operation = GLOBUS_NULL;
    handle->nl_handle = NULL;
    
    return GLOBUS_SUCCESS;
}


#ifndef TARGET_ARCH_WIN32
/**
 * Set or clear the close-on-exec flag for a handle.
 *
 * This function is used to modify the close-on-exec flag for an
 * I/O handle.
 *
 * @param handle
 *	  the handle passed to the blocking call
 * @param value
 *        The new value of the close-on-exec flag.
 */
globus_result_t
globus_io_set_close_on_exec(
    globus_io_handle_t *                handle,
    globus_bool_t                       value)
{
    int                                 rc;
    int                                 save_errno;
    globus_object_t *                   err;
    static char *                       myname="globus_io_set_close_on_exec";

    if(handle == GLOBUS_NULL)
    {
        err = globus_io_error_construct_null_parameter(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            "handle",
            1,
            myname);
        
        return globus_error_put(err);
    }
    
    globus_i_io_mutex_lock();
    
    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
        err = globus_io_error_construct_close_already_registered(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle);
        
        goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_INVALID:
      default:
        err = globus_io_error_construct_not_initialized(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            "handle",
            1,
            myname);

        goto error_exit;
    }

    while ((rc = fcntl(handle->fd, F_SETFD, (value ? FD_CLOEXEC : 0))) < 0)
    {
        save_errno = errno;

        if (errno != EINTR)
        {
            err = globus_io_error_construct_system_failure(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle,
                    save_errno);

            goto error_exit;
        }
    }

    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

error_exit:
    globus_i_io_mutex_unlock();
    return globus_error_put(err);
}
#endif /* TARGET_ARCH_WIN32 */
/* globus_io_set_close_on_exec() */
