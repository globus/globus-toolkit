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
 * @file globus_io_read.c Read Functions.
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * State information for asynchronous reads.
 * @internal
 */
typedef struct
{
    /** read destination buffer */
    globus_byte_t *			buf;
    /** read buffer size */
    globus_size_t			max_nbytes;
    /** minimum to read before callback */
    globus_size_t			wait_for_nbytes;
    /** amount of data currently read */
    globus_size_t			nbytes_read;
    /** User's read complete callback function */
    globus_io_read_callback_t		callback;
    /** Parameter to user's callback function */
    void *				arg;
} globus_io_read_info_t;
#endif

/*
 * Module specific prototypes
 */
static
void
globus_l_io_blocking_read_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes_read);

static
void
globus_l_io_read_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);


/*
 * API Functions
 */

/**
 * Asynchronous TCP or file read.
 *
 * @param handle The handle to read from. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE. If the
 * handle is a TCP socket, and the handle's security channel mode is either 
 * GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then all data will expected to be
 * sent in packets compatible with the GSSAPI.
 * @param buf The buffer to read data into.
 * @param max_nbytes The maximum number of bytes which will be read.
 * @param wait_for_nbytes The minimum number of bytes to read before calling
 * the callback function.
 * @param callback Funtion which is executed when the read has been satisfied.
 * @param callback_arg Parameter to the callback function.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or callback parameter was equal to GLOBUS_NULL, so the
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the read
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * registrations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED
 * The handle parameter was already registered for reading. 
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter is
 * not one of the types which supports the read operation.
 *
 * @see globus_io_read_callback_t, globus_io_read(), globus_io_try_read()
 * @ingroup common
 */
globus_result_t 
globus_io_register_read( 
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t			wait_for_nbytes,
    globus_io_read_callback_t		callback,
    void *				callback_arg)
{
    globus_result_t			rc;
    globus_object_t *			err;
    static char *			myname="globus_io_register_read";
    
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
    
    globus_i_io_debug_printf(3,
			     (stderr, "globus_io_register_read(): entering, "
			      "fd=%d, max=%lu, min=%lu\n",
			      handle->fd,
                              (unsigned long) max_nbytes,
                              (unsigned long) wait_for_nbytes));

    globus_i_io_mutex_lock();

    switch(handle->type)
    {
      case GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED:
      case GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED:
      case GLOBUS_IO_HANDLE_TYPE_FILE:
	break;
      default:
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE");
	goto error_exit;
    }
    
    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CONNECTED:
	break;
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	err = globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle);
	goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_CONNECTING:
      case GLOBUS_IO_HANDLE_STATE_ACCEPTING:
      case GLOBUS_IO_HANDLE_STATE_AUTHENTICATING:
      case GLOBUS_IO_HANDLE_STATE_LISTENING:
      case GLOBUS_IO_HANDLE_STATE_INVALID:
	err = globus_io_error_construct_not_initialized(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);
	goto error_exit;
    }
    if(handle->securesocket_attr.channel_mode !=
       GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR)
    {
        rc = globus_i_io_securesocket_register_read(handle,
						    buf,
						    max_nbytes,
						    wait_for_nbytes,
						    callback,
						    callback_arg);
        if(rc == GLOBUS_SUCCESS)
        {
	    goto done;
        } 
	else
	{
	    err = globus_error_get(rc);

	    goto error_exit;
	}
    }

    rc = globus_i_io_register_read(handle,
			           buf,
			           max_nbytes,
			           wait_for_nbytes,
			           callback,
			           callback_arg);
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	
	goto error_exit;
    }
  done:
    globus_i_io_mutex_unlock();
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();
    return globus_error_put(err);
}
/* globus_io_register_read() */


/**
 * Nonblocking TCP or file read
 *
 * globus_io_try_read() will read whatever data is immediatedly
 * available from the handle without blocking. The value of
 * nbytes_read will be updated to contain the amount of data actually
 * read from this handle. 
 *
 * @param handle The handle to read from. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE.
 * @param buf The buffer to read data into.
 * @param max_nbytes The maximum number of bytes which can be read. 
 * @param nbytes_read A pointer to a variable which will be set to the
 * number of bytes which were successfully read. This may be set to
 * a non-zero, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, buf, or nbytes_read parameter was equal to GLOBUS_NULL,
 * so the operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the read
 * operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * operations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED
 * The handle parameter was already registered for reading. 
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_POINTER
 * The buf parameter was not NULL, but was invalid. 
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * Some unexpectd I/O error occurred. 
 * @retval GLOBUS_IO_ERROR_TYPE_EOF
 * An end-of-file occurred on the read.
 *
 * @bug this function will always return 0 bytes read for TCP
 * connections which are configured to use GSSAPI or SSL data wrapping.
 *
 * @see globus_io_read(), globus_io_register_read()
 *
 * @ingroup common
 */
globus_result_t
globus_io_try_read(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t *			nbytes_read)
{
    globus_object_t *			err;
    globus_result_t			rc;
    static char *			myname= "globus_io_try_read";

    if(nbytes_read == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "nbytes_read",
	    4,
	    myname);

	return globus_error_put(err);
    }
    if(handle == GLOBUS_NULL)
    {
	*nbytes_read = 0;

	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);
	
	return globus_error_put(err);
    }
    if(buf == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "buf",
	    2,
	    myname);

	return globus_error_put(err);
    }
    
    globus_i_io_mutex_lock();

    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CONNECTED:
	break;
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	err = globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle);
	goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_CONNECTING:
      case GLOBUS_IO_HANDLE_STATE_ACCEPTING:
      case GLOBUS_IO_HANDLE_STATE_AUTHENTICATING:
      case GLOBUS_IO_HANDLE_STATE_LISTENING:
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
    
    if(handle->securesocket_attr.channel_mode !=
       GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR)
    {
	*nbytes_read = 0;

        globus_i_io_mutex_unlock();
	return GLOBUS_SUCCESS;
    }
    rc = globus_i_io_try_read(handle,
			      buf,
			      max_nbytes,
			      nbytes_read);
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);

	if(globus_object_get_type(err) == GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER)
	{
	    globus_io_error_bad_parameter_set_function(
		err,
		myname);
	    switch(globus_io_error_bad_parameter_get_position(err))
	    {
	      case 1:
		globus_io_error_bad_parameter_set_name(
		    err,
		    "handle");
		break;
	      case 2:
		globus_io_error_bad_parameter_set_name(
		    err,
		    "buf");
		break;
	      case 3:
		globus_io_error_bad_parameter_set_name(
		    err,
		    "max_nbytes");
		break;
	      case 4:
		globus_io_error_bad_parameter_set_name(
		    err,
		    "nbytes_read");
		break;
	    }
	}
	goto error_exit;
    }
			      
    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_try_read() */

/**
 * Blocking TCP or file read
 *
 * Perform a blocking read on the handle. This will block until buf is
 * filled with at least wait_for_nbytes and at most max_nbytes of data
 * from handle, or end-of-file is reached.
 *
 * @param handle The handle to read from. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE.
 * If the handle is a TCP socket, and the handle's security channel
 * mode is either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then all data will expected
 * to be sent in packets compatible with the GSSAPI.
 * @param buf The buffer to read data into.
 * @param max_nbytes The maximum number of bytes which can be read.
 * @param wait_for_nbytes The minimum number of bytes to read before
 * returning.
 * @param nbytes_read  A pointer to a variable which will be set to the
 * number of bytes which were successfully read. This may be set to
 * a non-zero, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or nbytes_read parameter was equal to GLOBUS_NULL, so the
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the read
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * registrations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED
 * The handle parameter was already registered for reading. 
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter is
 * not one of the types which supports the read operation.
 *
 * @see globus_io_register_read(), globus_io_try_read()
 *
 * @ingroup common
 */
globus_result_t
globus_io_read(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t			wait_for_nbytes,
    globus_size_t *			nbytes_read)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result; 
    globus_size_t			try_read;

    result = globus_io_try_read(handle, buf, max_nbytes, nbytes_read);
    if(result != GLOBUS_SUCCESS)
    {
	return result;
    }
    if(*nbytes_read >= wait_for_nbytes)
    {
	return result;
    }
    try_read = *nbytes_read;
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.nbytes = 0;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;

    handle->blocking_read = GLOBUS_TRUE;
    
    result = globus_io_register_read(handle,
				     buf + try_read,
				     max_nbytes - try_read,
				     wait_for_nbytes - try_read,
				     globus_l_io_blocking_read_callback,
				     &monitor);

    if(result != GLOBUS_SUCCESS)
    {
	monitor.done = GLOBUS_TRUE;
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;

	/* TODO: re-write parameter errors to match the parameter names
	   and function name here */
    }

    globus_mutex_lock(&monitor.mutex);
    
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);	
    }

    globus_mutex_unlock(&monitor.mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    
    if(nbytes_read)
    {
	*nbytes_read = monitor.nbytes + try_read;
    }

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
/* globus_io_read() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal
 *
 * nonblocking read without selecting
 */
globus_result_t
globus_i_io_try_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_read)
{
    globus_object_t *			err;
    ssize_t				n_read;
    globus_size_t			num_read;
    globus_bool_t			done = GLOBUS_FALSE;
    int					save_errno;
    char                                tag_str[256];
    static char *			myname="globus_i_io_try_read";

    num_read=0;
    *nbytes_read = 0;
    for (done = GLOBUS_FALSE; !done; )
    {
        /*
         *  NETLOGGER information
         */ 
        if(handle->nl_handle != GLOBUS_NULL)
        {
            sprintf(tag_str, "SOCK=%d", handle->fd);
            globus_netlogger_write(
                handle->nl_handle, 
                GLOBUS_IO_NL_EVENT_START_READ,
                "GIOTR",
                "Important",
                tag_str);
        }
#ifndef TARGET_ARCH_WIN32
	n_read =
	    globus_libc_read(
		handle->fd,
		buf + num_read,
		max_nbytes - num_read);
#else
		// NOTE: If the handle encapsulates a file, the following
		// call will always return -1 and set errno to EWOULDBLOCK
		// (see globus_i_io_windows_file_read() for an explanation)
		n_read= globus_i_io_windows_read( 
			handle, 
			buf + num_read, 
			max_nbytes - num_read, 
			0 );
#endif /* TARGET_ARCH_WIN32 */

        /*
         *  NETLOGGER write
         */
        if(handle->nl_handle != GLOBUS_NULL)
        {
            sprintf(tag_str, 
                "SOCK=%d GLOBUS_IO_NBYTES=%d", 
                handle->fd,
                n_read);
            globus_netlogger_write(
                handle->nl_handle, 
                GLOBUS_IO_NL_EVENT_END_READ,
                "GIOTR",
                "Important",
                tag_str);
        }
	save_errno = errno;
	globus_i_io_debug_printf(
	    5,
	    (stderr, "%s(): read returned n_read=%d\n",
	      myname, (int) n_read));
	
	/*
	 * n_read: is > 0 if it successfully read some bytes
	 *         is < 0 on error -- need to check errno
	 *         is 0 on EOF
	 */
	if (n_read > 0)
	{
	    *nbytes_read += n_read;
	    num_read += n_read;
            if(num_read >= max_nbytes)
            {
                return GLOBUS_SUCCESS;
            }
	}
	else if (n_read == 0)
	{
	    err =
		globus_io_error_construct_eof(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    handle);
		
	    goto error_exit;
	}
	else /* n_read < 0 */
	{
	    if (save_errno == EINTR)
	    {
		/* Try again */
	    }
	    else if (save_errno == EAGAIN || save_errno == EWOULDBLOCK)
	    {
		/* We've read all we can for now. */
		done = GLOBUS_TRUE;
	    }
	    else
	    {
		err = globus_io_error_construct_system_failure(
		              GLOBUS_IO_MODULE,
			      GLOBUS_NULL,
			      handle,
			      save_errno);
		goto error_exit;
	    }
	}
    }
    return GLOBUS_SUCCESS;

  error_exit:
    return globus_error_put(err);
}
/* globus_i_io_try_read() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal
 */
globus_result_t
globus_i_io_register_read(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t			wait_for_nbytes,
    globus_io_read_callback_t		callback,
    void *				callback_arg)
{
    globus_io_read_info_t *		read_info;
    globus_result_t			rc;
    globus_object_t *			err;
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif

    read_info = (globus_io_read_info_t *)
	globus_malloc(sizeof(globus_io_read_info_t));
    
    read_info->buf = buf;
    read_info->max_nbytes = max_nbytes;
    read_info->wait_for_nbytes = wait_for_nbytes;
    read_info->nbytes_read = 0;
    read_info->arg = callback_arg;
    read_info->callback = callback;
    
    rc = globus_i_io_start_operation(
        handle,
        GLOBUS_I_IO_READ_OPERATION);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_read_callback,
            read_info,
            globus_i_io_default_destructor,
            GLOBUS_TRUE,
            GLOBUS_I_IO_READ_OPERATION);
        
        if(rc != GLOBUS_SUCCESS)
        {
            globus_i_io_end_operation(handle, GLOBUS_I_IO_READ_OPERATION);
        }
    }
    
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	globus_free(read_info);
	
	goto error_exit;
    }
    
#ifdef TARGET_ARCH_WIN32
	// post the initial read
	returnCode= globus_i_io_windows_read( handle, buf, max_nbytes, 1 );
	if ( returnCode == -1 ) // potentially fatal error occurred
	{
		if ( handle->type == GLOBUS_IO_HANDLE_TYPE_FILE &&
		 errno == GLOBUS_WIN_EOF ) 
		{
			// post a fake packet to trigger the callback
			returnCode= globus_i_io_windows_post_completion( 
			 handle, WinIoReading );
			if ( returnCode == 0 )
				return GLOBUS_SUCCESS;
		}
		// yep- definitely a fatal error
		// unregister the read operation
		// this call will not only unregister the operation,
		// but it will also destroy the read_info object
		// and end the operation as well
		globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
			GLOBUS_I_IO_READ_OPERATION);

			err = globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				errno );
		goto error_exit;
	}
#endif

    return GLOBUS_SUCCESS;
    
  error_exit:

    return globus_error_put(err);
}
/* globus_i_io_register_read() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal
 *
 */
static
void
globus_l_io_blocking_read_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes_read)
{
    globus_i_io_monitor_t *		read_monitor;
    globus_object_t *			err;

    err = globus_error_get(result);

    read_monitor = (globus_i_io_monitor_t *) arg;

    globus_mutex_lock(&read_monitor->mutex);

    read_monitor->nbytes = nbytes_read;
    read_monitor->done = GLOBUS_TRUE;
    if(result != GLOBUS_SUCCESS)
    {
	read_monitor->use_err = GLOBUS_TRUE;
	read_monitor->err = err;
    }
    
    globus_cond_signal(&read_monitor->cond);
    globus_mutex_unlock(&read_monitor->mutex);
}
 /* globus_l_io_blocking_read_callback() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal
 */
static
void
globus_l_io_read_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_io_read_info_t *		read_info;
    long				n_read;
    int					save_errno;
    globus_bool_t			done;
    globus_object_t *			err;
    char                                tag_str[64];
    static char *			myname="globus_l_io_read_callback";
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif

    read_info = (globus_io_read_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto error_exit;
    }

    globus_i_io_debug_printf(5,(stderr, "%s(): entering\n",myname));

    for (done = GLOBUS_FALSE; !done; )
    {
	globus_i_io_debug_printf(
	    5,
	    (stderr, "%s(): calling read, fd=%i, buf=%p, size=%lu\n",
	     myname,
	     handle->fd,
	     (read_info->buf + read_info->nbytes_read),
	     (unsigned long)
                  (read_info->max_nbytes - read_info->nbytes_read)));

        /*
         *  NETLOGGER information
         */
        if(handle->nl_handle != GLOBUS_NULL)
        {
            sprintf(tag_str, "SOCK=%d", 
                handle->fd);
            globus_netlogger_write(
                handle->nl_handle, 
                GLOBUS_IO_NL_EVENT_START_READ,
                "GIOR",
				"Important",
                tag_str);
        }
#ifndef TARGET_ARCH_WIN32
	n_read =
	    globus_libc_read(
		handle->fd,
		(read_info->buf + read_info->nbytes_read),
		(read_info->max_nbytes - read_info->nbytes_read));
#else
		n_read= handle->winIoOperation_read.numberOfBytesProcessed;
		// if the handle is a file, update the file pointer
		if ( n_read > 0 && handle->type == GLOBUS_IO_HANDLE_TYPE_FILE )
		{
			int rc;
			LARGE_INTEGER numberOfBytes;
			numberOfBytes.QuadPart= n_read;
			rc= globus_i_io_windows_move_file_pointer( handle,
			 numberOfBytes, NULL );
			if ( rc )
			{
				err = globus_io_error_construct_system_failure(
							GLOBUS_IO_MODULE,
							GLOBUS_NULL,
							handle,
							errno );
				goto error_exit;
			}
		}
#endif /* TARGET_ARCH_WIN32 */

        /*
         *  NETLOGGER information
         */
        if(handle->nl_handle != GLOBUS_NULL)
        {
            sprintf(tag_str, "SOCK=%d GLOBUS_IO_NBYTES=%ld", 
                handle->fd,
                n_read);
            globus_netlogger_write(
                handle->nl_handle, 
                GLOBUS_IO_NL_EVENT_END_READ,
                "GIOR",
				"Important",
                tag_str);
		}
 
		save_errno = errno;
		globus_i_io_debug_printf(
			5,
			(stderr, "%s(): read returned n_read=%li\n",
			myname,
			n_read));
		
		/*
		* n_read: is > 0 if it successfully read some bytes
		*         is < 0 on error -- need to check errno
		*         is 0 on EOF
		*/
		if (n_read > 0 ||
			(n_read == 0 &&
			read_info->max_nbytes == 0))
		{
			read_info->nbytes_read += n_read;
			if (read_info->nbytes_read >= read_info->wait_for_nbytes)
			{
				globus_i_io_mutex_lock();
				globus_i_io_end_operation(handle, GLOBUS_I_IO_READ_OPERATION);
				globus_i_io_mutex_unlock();
		        
				(*read_info->callback)(read_info->arg,
						handle,
						GLOBUS_SUCCESS,
						read_info->buf,
						read_info->nbytes_read);
				globus_free(read_info);
				done = GLOBUS_TRUE;
			}
			else
			{
				globus_i_io_mutex_lock();
	            
				result = globus_i_io_register_operation(
					handle,
					globus_l_io_read_callback,
					read_info,
					globus_i_io_default_destructor,
					GLOBUS_TRUE,
					GLOBUS_I_IO_READ_OPERATION);
	            
#ifdef TARGET_ARCH_WIN32
				if( result == GLOBUS_SUCCESS)
				{
					// post another read
					rc= globus_i_io_windows_read( handle, 
						read_info->buf + read_info->nbytes_read,
						read_info->max_nbytes - read_info->nbytes_read, 1 );
					if ( rc == -1 ) // a fatal error occurred
					{
						// unregister the read operation
						globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
							GLOBUS_I_IO_READ_OPERATION);

						// Check for end of file condition if the handle is 
						// encapsulating a file
						if ( handle->type == GLOBUS_IO_HANDLE_TYPE_FILE 
						 && errno == GLOBUS_WIN_EOF )
						{
							err= globus_io_error_construct_eof(
									GLOBUS_IO_MODULE,
									GLOBUS_NULL,
									handle);
						}
						else
							err = globus_io_error_construct_system_failure(
								GLOBUS_IO_MODULE,
								GLOBUS_NULL,
								handle,
								errno );

						globus_i_io_mutex_unlock();
						goto error_exit;
					}
				}
#endif
				globus_i_io_mutex_unlock();
	            
				if(result != GLOBUS_SUCCESS)
				{
					err = globus_error_get(result);
					goto error_exit;
				}
	            
	            done = GLOBUS_TRUE;
		    }
		}
		else if (n_read == 0)
		{
			err =
			globus_io_error_construct_eof(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle);
		    
			goto error_exit;
		}
		else /* n_read < 0 */
		{
#ifndef TARGET_ARCH_WIN32
/* If we're using Windows, n_read will never be < 0; but just to
 *	make sure that nothing goes wrong I'll #ifdef this part out. 
 *	(just 'cause you're paranoid doesn't mean people aren't out
 *	to get you)
 *	Michael Lebman	4-26-02
 */
			globus_i_io_debug_printf(
			3,
			(stderr, "%s(): ERROR, errno=%d, fd=%d\n",
			myname,
			save_errno,
			handle->fd));
		    
			if (save_errno == EINTR)
			{
				/* Try again */
			}
			else if (save_errno == EAGAIN || save_errno == EWOULDBLOCK)
			{
				/* We've read all we can for now.  So repost the read. */
				globus_i_io_mutex_lock();
				
				result = globus_i_io_register_operation(
							handle,
							globus_l_io_read_callback,
							read_info,
							globus_i_io_default_destructor,
							GLOBUS_TRUE,
							GLOBUS_I_IO_READ_OPERATION);
				
				globus_i_io_mutex_unlock();
				
				if(result != GLOBUS_SUCCESS)
				{
					err = globus_error_get(result);
					goto error_exit;
				}
		            
				done = GLOBUS_TRUE;
			}
			else
#endif /* TARGET_ARCH_WIN32 */
			{
				err = globus_io_error_construct_system_failure(
								GLOBUS_IO_MODULE,
							GLOBUS_NULL,
							handle,
						save_errno);
				goto error_exit;
			}
		}
    }

    globus_i_io_debug_printf(5, (stderr, "%s(): exiting\n",myname));

    return;
    
  error_exit: 
    globus_i_io_mutex_lock();
    globus_i_io_end_operation(handle, GLOBUS_I_IO_READ_OPERATION);
    globus_i_io_mutex_unlock();
	        
    (*read_info->callback)(read_info->arg,
			   handle,
			   globus_error_put(err),
			   read_info->buf,
			   read_info->nbytes_read);
    
    globus_free(read_info);
    return;
} /* globus_l_io_read_callback() */
#endif
