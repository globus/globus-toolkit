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
 * @file globus_io_write.c Write/Send support functions.
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/*
 * Module Specific Type Definitions
 */

/**
 * State for asynchronous write and writev.
 *
 * @see globus_io_register_write(), globus_io_register_writev()
 * @see globus_l_io_write_callback(), globus_l_io_writev_callback()
 * @see globus_l_io_write_info_init(), globus_l_io_write_info_destroy()
 * @ingroup common
 */
typedef struct
{
    /** original data if specified as a byte array */
    globus_byte_t *			buf;
    /** original data, if specified as an iovec array */
    struct iovec *      		orig_iov;
    /** length of original iovec array */
    globus_size_t              		orig_iovcnt;
    /**
     * length of original data--either the length of buf,
     * or the sum of the orig_iov lengths.
     **/
    globus_size_t			nbytes;

    /** working copy of iov */
    struct iovec *      		iov;
    /** remaining data in the working copy */
    globus_size_t              		iovcnt;

    /**
     * original copy of secure iov. This is used to track the
     * pointer to the data that we've allocated
     */
    struct iovec *			orig_secure_iov;
    /**
     * length of the secure iovec.
     */
    globus_size_t			orig_secure_iovcnt;

    /** original pointers and lengths of working copy. This is used
     * to track the pointer to data we've allocated
     */
    struct iovec *			orig_malloced_iov;
    /**
     * length of working copy iovec.
     */
    globus_size_t			orig_malloced_iovcnt;

    /** amount of data written so far */
    globus_size_t              		nbytes_written;
    /** callback for globus_io_register_writev() */
    globus_io_writev_callback_t		iov_callback;
    /** callback for globus_io_register_write() */
    globus_io_write_callback_t		buf_callback;
    /** argument to callback */
    void *              		arg;

    int					send_flags;
} globus_io_write_info_t;
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/*
 * Module Specific Prototypes
 */
static
globus_io_write_info_t *
globus_l_io_write_info_init(
    globus_byte_t *			buffer,
    globus_size_t			buflen,
    struct iovec *			original_iov,
    globus_size_t			original_iovcnt,
    struct iovec *			secure_iov,
    globus_size_t			secure_iovcnt,
    int					send_flags,
    globus_io_write_callback_t		buffer_callback,
    globus_io_writev_callback_t		iov_callback,
    void *				callback_arg);

static
void
globus_l_io_write_info_destroy(
    void *				arg);

static
globus_result_t
globus_l_io_try_send(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    int					flags,
    globus_size_t *			nbytes_sent);

static
void
globus_l_io_write_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

static
void
globus_l_io_send_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

static
void
globus_l_io_writev_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

static
void
globus_l_io_sendmsg_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

static
void
globus_l_io_blocking_write_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);

static
void
globus_l_io_blocking_writev_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_size_t			nbytes);
#endif

/* API Functions */
/**
 * Asynchronous TCP or file write.
 *
 * Perform a write on the handle. 
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE. If
 * the handle is a TCP socket, and the handle's security channel mode is
 * either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then the data will be protected
 * by calls to the GSSAPI.
 * @param buf The data to be written.
 * @param nbytes The size of the data buffer.
 * @param callback Function which is executed when the write has completed.
 * @param callback_arg Parameter to the callback function.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing to an
 * object of one of the the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or callback parameter was equal to GLOBUS_NULL, so the
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * registrations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing. 
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter
 * is not one of the types which supports the write operation.
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION
 * The handle cannot protect the data using the GSSAPI. The data
 * cannot be written.
 *
 * @bugs In the case of an error during a protected data transfer, the
 * amount of data passed to the callback is not particularly reliable.
 *
 * @see globus_io_write_callback_t, globus_io_write(),
 * globus_io_try_write() 
 *
 * @ingroup common
 */
globus_result_t 
globus_io_register_write( 
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    globus_io_write_callback_t		callback,
    void *				callback_arg)
{
    globus_result_t			rc;
    globus_object_t *			err;
    struct iovec *			iov;
    globus_size_t			iovcnt;
    globus_io_write_info_t *		info;
    static char *			myname="globus_io_register_write";
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
	    4,
	    myname);

	return globus_error_put(err);
    }
    globus_i_io_mutex_lock();
    
    globus_i_io_debug_printf(3,
			     (stderr, "%s(): entering, "
			      "fd=%d, nbytes=%lu\n",
			      myname,
			      handle->fd,
			      (unsigned long) nbytes));

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
    /* Attempt to wrap this buffer, if it is needed. If
     * no wrapping is done, then iovcnt will be set to 0
     * upon return, otherwise, it will contain the
     * number of iovec structs created to hold the
     * GSSAPI tokens.
     */
    rc = globus_i_io_securesocket_wrap_buffer(handle,
                                              buf,
					      nbytes,
					      &iov,
					      &iovcnt);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_start_operation(
            handle,
            GLOBUS_I_IO_WRITE_OPERATION);
    }
    
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);

	goto error_exit;
    }
	
    info = globus_l_io_write_info_init(buf,
				       nbytes,
				       GLOBUS_NULL,
				       0,
				       iov,
				       iovcnt,
				       0,
				       callback,
				       GLOBUS_NULL,
				       callback_arg);
    if(iovcnt == 0)
    {
	/* No security wrapping was done, so we can send the buffer
	 * with a single write
	 */
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_write_callback,
            info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if ( rc == GLOBUS_SUCCESS )
		{
			// post the initial write
			returnCode= globus_i_io_windows_write( handle, 
						info->buf, 
						info->nbytes, 
						1, 0 );
			if ( returnCode == -1 ) // a fatal error occurred
			{
				// unregister the write operation
				// this call will not only unregister the operation,
				// but it will also destroy the write_info object
				// and end the operation as well
                globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
				 GLOBUS_I_IO_WRITE_OPERATION);

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						errno );
				goto error_exit;
			}
		}
#endif /* TARGET_ARCH_WIN32 */
    }
    else
    {
	/* Security wrapping was done, so the data may be spread over
	 * multiple GSSAPI tokens in the iovec array.
	 */
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_writev_callback,
            info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if ( rc == GLOBUS_SUCCESS )
		{
			// post the initial write
			returnCode= globus_i_io_windows_write( handle, 
						info->iov[0].iov_base,
						info->iov[0].iov_len, 
						1, 0 );
			if ( returnCode == -1 ) // a fatal error occurred
			{
				// unregister the write operation
				// this call will not only unregister the operation,
				// but it will also destroy the write_info object
				// and end the operation as well
                globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
				 GLOBUS_I_IO_WRITE_OPERATION);

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						errno );
				goto error_exit;
			}
		}
#endif /* TARGET_ARCH_WIN32 */
    }
    if(rc != GLOBUS_SUCCESS)
    {
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
		err = globus_error_get(rc);
		globus_l_io_write_info_destroy(info);

		goto error_exit;
    }
    
    globus_i_io_mutex_unlock();

    globus_i_io_debug_printf(3,
			    (stderr, "globus_io_register_write(): exiting\n"));
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_register_write() */

/**
 * Asynchronous TCP or file write.
 *
 * Perform a send on the handle. 
 *
 * @param handle The handle to send on. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED.
 * If the handle is a TCP socket, and the handle's security channel mode is
 * either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then the data will be protected
 * by calls to the GSSAPI.
 * @param buf The data to be written.
 * @param nbytes The size of the data buffer.
 * @param flags Flags to be passed to the send() call.
 * @param callback Function which is executed when the write has completed.
 * @param callback_arg Parameter to the callback function.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing to an
 * object of one of the the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or callback parameter was equal to GLOBUS_NULL, so the
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * registrations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing. 
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter
 * is not one of the types which supports the write operation.
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION
 * The handle cannot protect the data using the GSSAPI. The data
 * cannot be written.
 *
 * @bugs In the case of an error during a protected data transfer, the
 * amount of data passed to the callback is not particularly reliable.
 *
 * @see globus_io_write_callback_t, globus_io_send(), globus_io_try_send() 
 *
 * @ingroup common
 */
globus_result_t 
globus_io_register_send( 
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					flags,
    globus_io_write_callback_t		callback,
    void *				callback_arg)
{
    globus_result_t			rc;
    globus_object_t *			err;
    struct iovec *			iov;
    globus_size_t			iovcnt;
    globus_io_write_info_t *		info;
    static char *			myname="globus_io_register_send";
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
	    5,
	    myname);

	return globus_error_put(err);
    }
    globus_i_io_mutex_lock();
    
    globus_i_io_debug_printf(3,
			     (stderr, "%s(): entering, "
			      "fd=%d, nbytes=%lu\n",
			      myname,
			      handle->fd,
			      (unsigned long) nbytes));

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
    switch(handle->type)
    {
      case GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED:
      case GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED:
        break;

      default:
	err = globus_error_construct_type_mismatch(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL);
	goto error_exit;
    }

    /* Attempt to wrap this buffer, if it is needed. If
     * no wrapping is done, then iovcnt will be set to 0
     * upon return, otherwise, it will contain the
     * number of iovec structs created to hold the
     * GSSAPI tokens.
     */
    rc = globus_i_io_securesocket_wrap_buffer(handle,
                                              buf,
					      nbytes,
					      &iov,
					      &iovcnt);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_start_operation(
            handle,
            GLOBUS_I_IO_WRITE_OPERATION);
    }
    
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);

	goto error_exit;
    }
	
    info = globus_l_io_write_info_init(buf,
				       nbytes,
				       GLOBUS_NULL,
				       0,
				       iov,
				       iovcnt,
				       flags,
				       callback,
				       GLOBUS_NULL,
				       callback_arg);
    if(iovcnt == 0)
    {
	/* No security wrapping was done, so we can send the buffer
	 * with a single write
	 */
	    rc = globus_i_io_register_operation(
            handle,
            globus_l_io_send_callback,
            info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
    }
    else
    {
	/* Security wrapping was done, so the data may be spread over
	 * multiple GSSAPI tokens in the iovec array.
	 */
	    rc = globus_i_io_register_operation(
            handle,
            globus_l_io_sendmsg_callback,
            info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
    }
    if(rc != GLOBUS_SUCCESS)
    {
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
	err = globus_error_get(rc);
	globus_l_io_write_info_destroy(info);

	goto error_exit;
    }
    
#ifdef TARGET_ARCH_WIN32
	// trigger the callback; because the buffer used by 
	// globus_l_io_sendmsg_callback() hasn't been created yet we
	// will only post a fake completion packet
	returnCode= globus_i_io_windows_post_completion( 
				 handle, 
				 WinIoWriting );
	if ( returnCode ) // a fatal error occurred
	{
		// unregister the write operation
		globus_i_io_unregister_operation( handle, GLOBUS_TRUE,
			GLOBUS_I_IO_WRITE_OPERATION );

		err = globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				returnCode );
		goto error_exit;
	}
#endif

    globus_i_io_mutex_unlock();

    globus_i_io_debug_printf(3,
			    (stderr, "globus_io_register_write(): exiting\n"));
    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_register_send() */

/**
 *
 * Asynchronous TCP or file writev.
 *
 * Perform a writev on the handle. Multiple non-contiguous data buffers
 * can be registered to be written at once.
 *
 * @e Note: This function works independent of any system-specific
 * iov length restrictions.
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE. If
 * the handle is a TCP socket, and the handle's security channel mode is
 * either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then the data will be protected
 * by calls to the GSSAPI.
 * @param iov The data vector to be written.
 * @param iovcnt The number of data buffers in the vector.
 * @param callback Function which is executed when the write has completed.
 * @param callback_arg Parameter to the callback function.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing to an
 * object of one of the the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, callback, or iov parameter was equal to GLOBUS_NULL, so the
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * registrations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing. 
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The type of handle passed to the function by the handle parameter
 * is not one of the types which supports the write operation.
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION
 * The handle cannot protect the data using the GSSAPI. The data
 * cannot be written.
 *
 * @bug In the case of an error during a protected data transfer, the
 * amount of data passed to the callback is not particularly reliable.
 *
 * @see globus_io_writev_callback_t, globus_io_writev() 
 *
 * @ingroup common
 */
globus_result_t
globus_io_register_writev(
    globus_io_handle_t *		handle,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_io_writev_callback_t		callback,
    void *				callback_arg)
{
    globus_result_t                     rc;
    globus_object_t *			err;
    struct iovec *			new_iov;
    globus_size_t			new_iovcnt;
    globus_io_write_info_t *		writev_info;
    static char *			myname="globus_io_register_writev";
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
	    4,
	    myname);

	return globus_error_put(err);
    }
    if(iov == GLOBUS_NULL)
    {
        err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "iov",
	    2,
	    myname);

	return globus_error_put(err);
    }

    globus_i_io_debug_printf(3,
                          (stderr, "globus_io_register_writev(): entering\n"));


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
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED &&
       handle->type != GLOBUS_IO_HANDLE_TYPE_FILE &&
       handle->type != GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or " 
	    "GLOBUS_IO_HANDLE_TYPE_FILE or " 
	    "GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED");
	
	goto error_exit;
    }
    rc = globus_i_io_securesocket_wrap_iov(handle,
                                           iov,
					   iovcnt,
					   &new_iov,
					   &new_iovcnt);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_start_operation(
            handle,
            GLOBUS_I_IO_WRITE_OPERATION);
    }
    
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);

	goto error_exit;
    }

    writev_info = 
	globus_l_io_write_info_init(GLOBUS_NULL, /* for buffer write */
				    0, /* for buffer write */
				    iov, /* original iov */
				    iovcnt, /* length of orig iov */
				    new_iov, /* secure iov */
				    new_iovcnt, /* length of secure iov */
				    0, /* send flags */
				    GLOBUS_NULL,/* buffer callback */
				    callback, /* iov_callback */
				    callback_arg); /*argument*/

    rc = globus_i_io_register_operation(
        handle,
        globus_l_io_writev_callback,
        writev_info,
        globus_l_io_write_info_destroy,
        GLOBUS_TRUE,
        GLOBUS_I_IO_WRITE_OPERATION);
            
    if(rc != GLOBUS_SUCCESS)
    {
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
	err = globus_error_get(rc);
	
	globus_l_io_write_info_destroy(writev_info);
	
	goto error_exit;
    }

#ifdef TARGET_ARCH_WIN32
	// post the initial write
	returnCode= globus_i_io_windows_write( handle, 
				 writev_info->iov[0].iov_base,
				 writev_info->iov[0].iov_len, 
				 1, 0 );
	if ( returnCode == -1 )
	{
		// unregister the write operation, end it and destroy the
		// write info object
		globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
			GLOBUS_I_IO_WRITE_OPERATION);

		err = globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				errno );

		goto error_exit;
	}
#endif

    globus_i_io_mutex_unlock();

    globus_i_io_debug_printf(3, 
        (stderr, "nexus_fd_register_for_writev(): exiting\n"));

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_register_writev() */
    
/**
 * Nonblocking TCP or file write
 *
 * globus_io_try_write() will write whatever data can immediately
 * processed by the operating system without blocking. The value of
 * nbytes_written will be updated to contain the amount of data actually
 * written to the handle. 
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE.
 * @param buf The data to write.
 * @param max_nbytes The maximum number of bytes which can be written. 
 * @param nbytes_written A pointer to a variable which will be set to the
 * number of bytes which were successfully written. This may be set to
 * a non-zero value, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, buf, or nbytes_written parameter was equal to GLOBUS_NULL,
 * so the operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * operations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing. 
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_POINTER
 * The buf parameter was not NULL, but was invalid.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @bug This function will always return 0 bytes written for TCP
 * connections which are configured to use GSSAPI or SSL data wrapping.
 *
 * @see globus_io_write(), globus_io_register_write()
 *
 * @ingroup common
 */
globus_result_t
globus_io_try_write(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t *			nbytes_written)
{
    globus_object_t *			err;
    globus_result_t			rc;
    static char *			myname="globus_io_try_write";

    if(nbytes_written == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "nbytes_written",
	    4,
	    myname);
	
	return globus_error_put(err);
    }
    if(handle == GLOBUS_NULL)
    {
	*nbytes_written = 0;
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
	*nbytes_written = 0;
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
	*nbytes_written = 0;

        globus_i_io_mutex_unlock();
	return GLOBUS_SUCCESS;
    }

    rc = globus_i_io_try_write(
	handle,
	buf,
        max_nbytes,
	nbytes_written);

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
		    "nbytes_written");
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
/* globus_io_try_write() */

/**
 * Nonblocking TCP or file send
 *
 * globus_io_try_send() will send whatever data can immediately
 * processed by the operating system without blocking. The value of
 * nbytes_written will be updated to contain the amount of data actually
 * written to the handle. 
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE.
 * @param buf The data to write.
 * @param max_nbytes The maximum number of bytes which can be written. 
 * @param flags The flags to be passed to the send system call.
 * @param nbytes_written A pointer to a variable which will be set to the
 * number of bytes which were successfully written. This may be set to
 * a non-zero value, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, buf, or nbytes_written parameter was equal to GLOBUS_NULL,
 * so the operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * operations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing. 
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_POINTER
 * The buf parameter was not NULL, but was invalid.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @bug This function will always return 0 bytes written for TCP
 * connections which are configured to use GSSAPI or SSL data wrapping.
 *
 * @see globus_io_write(), globus_io_register_write()
 *
 * @ingroup common
 */
globus_result_t
globus_io_try_send(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    int					flags,
    globus_size_t *			nbytes_written)
{
    globus_object_t *			err;
    globus_result_t			rc;
    static char *			myname="globus_io_try_send";

    if(nbytes_written == GLOBUS_NULL)
    {
	err = globus_io_error_construct_null_parameter(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "nbytes_written",
	    5,
	    myname);
	
	return globus_error_put(err);
    }
    if(handle == GLOBUS_NULL)
    {
	*nbytes_written = 0;
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
	*nbytes_written = 0;
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
	*nbytes_written = 0;

        globus_i_io_mutex_unlock();
	return GLOBUS_SUCCESS;
    }

    rc = globus_l_io_try_send(
	handle,
	buf,
        max_nbytes,
	flags,
	nbytes_written);

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
		    "nbytes_written");
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
/* globus_io_try_send() */

/**
 * Blocking TCP or file write.
 *
 * Perform a blocking write operation on the handle. This will block
 * until the contents of buf are written to the network or file, or an
 * error occurs.
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE.
 * If the handle is a TCP socket, and the handle's security channel
 * mode is either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then all data will protected
 * by calls to the GSSAPI before being sent.
 * @param buf The data to write.
 * @param max_nbytes The maximum number of bytes which can be written.
 * @param nbytes_written  A pointer to a variable which will be set to the
 * number of bytes which were successfully written. This may be set to
 * a non-zero, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or nbytes_written parameter was equal to GLOBUS_NULL, so the
 * write could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * operations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing.
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter is
 * not one of the types which supports the write operation.
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION
 * The handle cannot protect the data using the GSSAPI. The data
 * cannot be written.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @bug In the case of an error during a protected data transfer, the
 * value pointed to by nbytes_written is not necesarily reliable.
 *
 * @see globus_io_register_write(), globus_io_try_write()
 *
 * @ingroup common
*/
globus_result_t
globus_io_write(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    globus_size_t *			nbytes_written)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result; 
    globus_size_t			try_wrote = 0;

    result = globus_io_try_write(handle, buf, nbytes, nbytes_written);
    if(result != GLOBUS_SUCCESS)
    {
	return result;
    }
    if((*nbytes_written) == nbytes)
    {
	return GLOBUS_SUCCESS;
    }
    try_wrote = *nbytes_written;

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.nbytes = 0;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    handle->blocking_write = GLOBUS_TRUE;
    
    result = globus_io_register_write(handle,
				     buf + try_wrote,
				     nbytes - try_wrote,
				     globus_l_io_blocking_write_callback,
				     &monitor);

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
    
    handle->blocking_write = GLOBUS_FALSE;
    
    if(nbytes_written)
    {
	*nbytes_written = monitor.nbytes + try_wrote;
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
/* globus_io_write() */

/**
 * Blocking TCP or UDP send.
 *
 * Perform a blocking send operation on the handle. This will block
 * until the contents of buf are written to the network, or an
 * error occurs.
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or 
 * GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED.
 * If the handle is a TCP socket, and the handle's security channel
 * mode is either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then all data will protected
 * by calls to the GSSAPI before being sent.
 * @param buf The data to write.
 * @param max_nbytes The maximum number of bytes which can be written.
 * @param flags Flags to be passed to the send system call.
 * @param nbytes_written  A pointer to a variable which will be set to the
 * number of bytes which were successfully written. This may be set to
 * a non-zero, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or nbytes_written parameter was equal to GLOBUS_NULL, so the
 * write could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the write
 * operation could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * operations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing.
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter is
 * not one of the types which supports the write operation.
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION
 * The handle cannot protect the data using the GSSAPI. The data
 * cannot be written.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @bug In the case of an error during a protected data transfer, the
 * value pointed to by nbytes_written is not necesarily reliable.
 *
 * @see globus_io_register_write(), globus_io_try_write()
 *
 * @ingroup common
*/
globus_result_t
globus_io_send(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					flags,
    globus_size_t *			nbytes_written)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result; 
    globus_size_t			try_wrote = 0;
    
    result = globus_io_try_send(handle, 
				buf, 
				nbytes, 
				flags,
				nbytes_written);
    if(result != GLOBUS_SUCCESS)
    {
	return result;
    }
    if((*nbytes_written) == nbytes)
    {
	return GLOBUS_SUCCESS;
    }
    try_wrote = *nbytes_written;
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.nbytes = 0;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    handle->blocking_write = GLOBUS_TRUE;
    
    result = globus_io_register_send(handle,
				     buf + try_wrote,
				     nbytes - try_wrote,
				     flags,
				     globus_l_io_blocking_write_callback,
				     &monitor);

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
    
    handle->blocking_write = GLOBUS_FALSE;
        
    if(nbytes_written)
    {
	*nbytes_written = monitor.nbytes + try_wrote;
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
/* globus_io_send() */

/**
 * Blocking TCP or file writev.
 *
 * Perform a blocking write operation on the handle. This will block
 * until the data in the iov array is written to the network or file,
 * or an error occurs.
 *
 * @param handle The handle to write to. It must be a handle of type
 * GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED or GLOBUS_IO_HANDLE_TYPE_FILE.
 * If the handle is a TCP socket, and the handle's security channel
 * mode is either GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP or
 * GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then all data will protected
 * by calls to the GSSAPI before being sent.
 * @param iov The data vector to write.
 * @param iovcnt The number of data buffers in the vector.
 * @param nbytes_written  A pointer to a variable which will be set to the
 * number of bytes which were successfully written. This may be set to
 * a non-zero, even if an error result code is returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or nbytes_written parameter was equal to GLOBUS_NULL, so the
 * write could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter was not initialized or ready, so the read
 * registration could not be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter was already registered for closing, so no more
 * operations can occur on this handle.
 * @retval GLOBUS_IO_ERROR_TYPE_WRITE_ALREADY_REGISTERED
 * The handle parameter was already registered for writing.
 * @retval GLOBUS_ERROR_TYPE_TYPE_MISMATCH
 * The type of handle passed to the function by the handle parameter is
 * not one of the types which supports the writev operation.
 * @retval GLOBUS_IO_ERROR_TYPE_BAD_PROTECTION
 * The handle cannot protect the data using the GSSAPI. The data
 * cannot be written.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @bug In the case of an error during a protected data transfer, the
 * value pointed to by nbytes_written is not necesarily reliable.
 *
 * @see globus_io_register_write(), globus_io_try_write()
 *
 * @ingroup common
 */
globus_result_t
globus_io_writev(
    globus_io_handle_t *		handle,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_size_t *			nbytes_written)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result; 

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.nbytes = 0;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    handle->blocking_write = GLOBUS_TRUE;
    
    result = globus_io_register_writev(handle,
				       iov,
				       iovcnt,
				       globus_l_io_blocking_writev_callback,
				       &monitor);

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
    
    handle->blocking_write = GLOBUS_FALSE;
    
    if(nbytes_written)
    {
	*nbytes_written = monitor.nbytes;
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
/* globus_io_write() */


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal write some data on a handle without blocking.
 *
 * @param handle
 * @param buf
 * @param max_nbytes
 * @param nbytes_written
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @ingroup common
 */
globus_result_t
globus_i_io_try_write(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t *			nbytes_written)
{
    globus_size_t 			num_written;
    globus_object_t *			err;
    globus_bool_t			done;
    ssize_t				n_written;
    int					save_errno;
    char                                tag_str[256];

    num_written=0;
    *nbytes_written = 0;
    for (done = GLOBUS_FALSE; !done; )
    {
        /*
         *  NETLOGGER information
         */
        if(handle->nl_handle) 
        {
            sprintf(tag_str, "SOCK=%d",
                handle->fd);
            globus_netlogger_write(
                handle->nl_handle,
                GLOBUS_IO_NL_EVENT_START_WRITE,
                "GIOTW",
                "Important",
                tag_str);
        }
#ifndef TARGET_ARCH_WIN32
	n_written = globus_libc_write(
	    handle->fd,
	    buf+num_written,
	    max_nbytes-num_written);
#else
		// NOTE: If the handle encapsulates a file, the following
		// call will always return -1 and set errno to EWOULDBLOCK
		// (see globus_i_io_windows_file_write() for an explanation)
		n_written= globus_i_io_windows_write( 
			handle,
			buf+num_written,
			max_nbytes-num_written, 
			0, 0 );
#endif /* TARGET_ARCH_WIN32 */

        /*
         *  NETLOGGER information
         */
        if(handle->nl_handle) 
        {
            sprintf(tag_str, 
                "SOCK=%d GLOBUS_IO_NBYTES=%d",
                handle->fd,
                n_written);
            globus_netlogger_write(
                handle->nl_handle,
                GLOBUS_IO_NL_EVENT_END_WRITE,
                "GIOTW",
                "Important",
                tag_str);
        }

	save_errno = errno;

	globus_i_io_debug_printf(
	    5,
	    (stderr, "globus_i_io_try_write(): write returned n_written=%d\n",
	      (int) n_written));

	/*
	 * n_written: is > 0 on success -- number of bytes written
	 *          is < 0 on error -- need to check errno
	 *          is 0 (SysV) or (-1 && errno==EWOULDBLOCK) (BSD)
	 *              if the write would block without writing anything
	 */
	if (n_written > 0 || (n_written == 0 && max_nbytes == 0))
	{
	    (*nbytes_written) += n_written;
            num_written += n_written;
	    if(*nbytes_written >= max_nbytes)
	    {
		done = GLOBUS_TRUE;
	    }
	}
	else if (   (n_written == 0)
		 || (n_written < 0 &&
                        (save_errno == EAGAIN || save_errno == EWOULDBLOCK)))
	{
	    done = GLOBUS_TRUE;
	}
	else /* n_written < 0 */
	{
	    globus_i_io_debug_printf(
		5,
        (stderr, "globus_i_io_try_write(): write returned -1 with errno=%d\n",
		 (int) save_errno));
	    
	    if (save_errno == EINTR)
	    {
		/* Try again */
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
/* globus_i_io_try_write() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal send some data on a handle without blocking.
 *
 * @param handle
 * @param buf
 * @param max_nbytes
 * @param flags
 * @param nbytes_written
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The send call failed with an unexpected error. The errno returned
 * by send() is accessible from the error object.
 *
 * @ingroup common
 */
static
globus_result_t
globus_l_io_try_send(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    int					flags,
    globus_size_t *			nbytes_sent)
{
    globus_size_t 			num_written;
    globus_object_t *			err;
    globus_bool_t			done;
    ssize_t				n_written;
    int					save_errno;

    num_written=0;
    *nbytes_sent = 0;
    for (done = GLOBUS_FALSE; !done; )
    {
#ifndef TARGET_ARCH_WIN32
	n_written = send(
	    handle->fd,
	    buf+num_written,
	    max_nbytes-num_written,
	    flags);
#else
		n_written= globus_i_io_windows_write( 
			handle,
			buf+num_written,
			max_nbytes-num_written, 
			0, flags );
#endif /* TARGET_ARCH_WIN32 */
	save_errno = errno;
	
	globus_i_io_debug_printf(
	    5,
	    (stderr, "globus_i_io_try_write(): write returned n_written=%d\n",
	      (int) n_written));
	
	/*
	 * n_written: is > 0 on success -- number of bytes written
	 *          is < 0 on error -- need to check errno
	 *          is 0 (SysV) or (-1 && errno==EWOULDBLOCK) (BSD)
	 *              if the write would block without writing anything
	 */

	if (n_written > 0 || (n_written == 0 && max_nbytes == 0))
	{
	    (*nbytes_sent) += n_written;
            num_written += n_written;
	    if(*nbytes_sent >= max_nbytes)
	    {
		done = GLOBUS_TRUE;
	    }
	}
	else if (   (n_written == 0)
		 || (n_written < 0 &&
                        (save_errno == EAGAIN || save_errno == EWOULDBLOCK)))
	{
	    done = GLOBUS_TRUE;
	}
	else /* n_written < 0 */
	{
	    if (save_errno == EINTR)
	    {
		/* Try again */
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
/* globus_i_io_try_send() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal write some data on a handle without blocking.
 *
 * @param handle
 * @param iov
 * @param iovcnt
 * @param max_nbytes
 * @param nbytes_written
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The write called failed with an unexpected error. The errno returned
 * by write() is accessible from the error object.
 *
 * @ingroup common
 */
/* NOTE: This function is not used on Windows.
 */
globus_result_t
globus_i_io_try_writev(
    globus_io_handle_t *		handle,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_size_t *			nbytes_written)
{
    globus_size_t 			num_written;
    globus_object_t *			err;
    globus_bool_t			done;
    ssize_t				n_written;
    int					save_errno;
    char                                tag_str[256];

    num_written=0;
    *nbytes_written = 0;
    for (done = GLOBUS_FALSE; !done; )
    {
	int				count_used;

	count_used = (int) (iovcnt > IOV_MAX) ? IOV_MAX : iovcnt;

    /*
     *  NETLOGGER information
     */
    if(handle->nl_handle) 
    {
        sprintf(tag_str, "SOCK=%d",
            handle->fd);
        globus_netlogger_write(
            handle->nl_handle,
            GLOBUS_IO_NL_EVENT_START_WRITE,
            "GIOTWV",
            "Important",
            tag_str);
    }
	n_written = globus_libc_writev(
	    handle->fd,
	    iov,
	    count_used);

    if(handle->nl_handle) 
    {
        sprintf(tag_str, "SOCK=%d GLOBUS_IO_NBYTES=%d",
            handle->fd,
            n_written);
        globus_netlogger_write(
            handle->nl_handle,
            GLOBUS_IO_NL_EVENT_END_WRITE,
            "GIOTWV",
            "Important",
            tag_str);
    }
	save_errno = errno;
	
	globus_i_io_debug_printf(
	    5,
	    (stderr, "globus_i_io_try_writev(): writev returned n_written=%d\n",
	      (int) n_written));
	
	/*
	 * n_written: is > 0 on success -- number of bytes written
	 *          is < 0 on error -- need to check errno
	 *          is 0 (SysV) or (-1 && errno==EWOULDBLOCK) (BSD)
	 *              if the write would block without writing anything
	 */

	if (n_written > 0 || (n_written == 0 && iov[0].iov_len == 0))
	{
	    (*nbytes_written) += n_written;
	    done = GLOBUS_TRUE;
	}
	else if (   (n_written == 0)
		 || (n_written < 0 &&
                        (save_errno == EAGAIN || save_errno == EWOULDBLOCK)))
	{
	    done = GLOBUS_TRUE;
	}
	else /* n_written < 0 */
	{
	    if (save_errno == EINTR)
	    {
		/* Try again */
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
/* globus_i_io_try_writev() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal send some data on a handle without blocking.
 *
 * @param handle
 * @param msghdr
 * @param flags
 * @param nbytes_written
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing
 * to an object of the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The sendmsg call failed with an unexpected error. The errno returned
 * by sendmsg() is accessible from the error object.
 *
 * @ingroup common
 */
#ifndef TARGET_ARCH_WIN32
globus_result_t
globus_i_io_try_sendmsg(
    globus_io_handle_t *		handle,
    struct msghdr *			msg_hdr,
    int					flags,
    globus_size_t *			nbytes_written)
{
    globus_size_t 			num_written;
    globus_object_t *			err;
    globus_bool_t			done;
    ssize_t				n_written;
    int					save_errno;

    num_written=0;
    *nbytes_written = 0;
    for (done = GLOBUS_FALSE; !done; )
    {
	globus_size_t			count_used;
	globus_size_t			tmp_count;
	
	tmp_count = msg_hdr->msg_iovlen;
	count_used = (int) (msg_hdr->msg_iovlen > IOV_MAX) 
	    ? IOV_MAX 
	    : msg_hdr->msg_iovlen;

	msg_hdr->msg_iovlen = count_used;

	n_written = sendmsg(
	    handle->fd,
	    msg_hdr,
	    flags);

	msg_hdr->msg_iovlen = tmp_count;

	save_errno = errno;
	
	globus_i_io_debug_printf(
	    5,
	 (stderr, "globus_i_io_try_sendmsg(): sendmsg returned n_written=%d\n",
	      (int) n_written));
	
	/*
	 * n_written: is > 0 on success -- number of bytes written
	 *          is < 0 on error -- need to check errno
	 *          is 0 (SysV) or (-1 && errno==EWOULDBLOCK) (BSD)
	 *              if the write would block without writing anything
	 */

	if (n_written > 0 || (n_written == 0 && 
			      msg_hdr->msg_iov[0].iov_len == 0))
	{
	    (*nbytes_written) += n_written;
	    done = GLOBUS_TRUE;
	}
	else if (   (n_written == 0)
		 || (n_written < 0 &&
                        (save_errno == EAGAIN || save_errno == EWOULDBLOCK)))
	{
	    done = GLOBUS_TRUE;
	}
	else /* n_written < 0 */
	{
	    if (save_errno == EINTR)
	    {
		/* Try again */
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
/* globus_i_io_try_sendmsg() */
#endif /* TARGET_ARCH_WIN32 */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @internal
 * allocate and initialize a write info structure
 *
 * @param buffer The original data to be written, when
 * globus_io_register_write() is called by the user; otherwise, it
 * is NULL.
 * @param buflen The amount of data in the buffer.
 * @param original_iov The original data to be written, when
 * globus_io_register_writev() is called by the user; otherwise, it
 * is NULL.
 * @param original_iovcnt The length of original_iov array.
 * @param secure_iov An array of security-wrapped iovec 
 * structures to be written. If security wrapping is not being
 * used on the handle that this operation is being executed on,
 * then this is NULL.
 * @param secure_iovcnt The length of the secure_iov array.
 * @param send_flags Flags to pass to send().
 * @param buffer_callback The callback to be invoked once the
 * write completes, if the user called globus_io_register_write();
 * otherwise, it is NULL.
 * @param iov_callback  The callback to be invoked once the
 * write completes, if the user called globus_io_register_writev();
 * otherwise, it is NULL.
 * @param callback_arg The user-specified pointer passed to the callback
 * function.
 *
 * @return A globus_io_write_info_t usable as an argument to the
 * write or writev callbacks.
 *
 * @see globus_io_write_info_t, globus_l_io_write_info_destroy()
 *
 * @ingroup common
 */
static
globus_io_write_info_t *
globus_l_io_write_info_init(
    globus_byte_t *			buffer,
    globus_size_t			buflen,
    struct iovec *			original_iov,
    globus_size_t			original_iovcnt,
    struct iovec *			secure_iov,
    globus_size_t			secure_iovcnt,
    int					send_flags,
    globus_io_write_callback_t		buffer_callback,
    globus_io_writev_callback_t		iov_callback,
    void *				callback_arg)
{
    globus_io_write_info_t *		info;

    info = (globus_io_write_info_t *)
	globus_malloc(sizeof(globus_io_write_info_t));
	
    info->buf = buffer;

    info->orig_iov = original_iov;
    info->orig_iovcnt = original_iovcnt;
    
    info->send_flags = send_flags;

    info->buf_callback = buffer_callback;
    info->iov_callback = iov_callback;
    info->arg = callback_arg;

    if(buflen)
    {
        info->nbytes = buflen;
    }
    else
    {
        /* compute the original length for the user. because
         * we may be sending a wrapped buffer, we may send more
         * than the user actually gave us. We shouldn't confuse
         * them by reporting that as the amount written.
         */
        info->nbytes = 0;
        if(original_iovcnt > 0)
        {
	    int i;
    
	    for(i = 0; i < original_iovcnt; i++)
	    {
	        info->nbytes += original_iov[i].iov_len;
	    }
        }
    }
    if(secure_iovcnt == 0)
    {
	/* no security wrap */
	info->orig_secure_iov = GLOBUS_NULL;
	info->orig_secure_iovcnt = 0;

	/* create working copy of iovec, if we are doing a writev */
	if(original_iovcnt != 0)
	{
	    info->iov = (struct iovec *)
	        globus_malloc(sizeof(struct iovec) * original_iovcnt);
	    memcpy(info->iov,
	           original_iov,
	           sizeof(struct iovec) * original_iovcnt);
	}
	else
	{
	    info->iov = GLOBUS_NULL;
	}

	info->iovcnt = original_iovcnt;
	    
	/* original pointers returned from malloc() for working copy */
	info->orig_malloced_iov = info->iov;
	info->orig_malloced_iovcnt = info->iovcnt;
	
	info->nbytes_written = 0;
    }
    else
    {
	/* original pointers to secure copy of data */
	info->orig_secure_iov = secure_iov;
	info->orig_secure_iovcnt = secure_iovcnt;

	/* create working copy of iov, since we're doing a writev */
	info->iov = (struct iovec *)
	    globus_malloc(sizeof(struct iovec) * secure_iovcnt);
	memcpy(info->iov,
	       secure_iov,
	       sizeof(struct iovec) * secure_iovcnt);
	info->iovcnt = secure_iovcnt;
	    
	/* original pointers to working copy */
	info->orig_malloced_iov = info->iov;
	info->orig_malloced_iovcnt = info->iovcnt;
	    
	info->nbytes_written = 0;
    }
    return info;
}
/* globus_l_io_write_info_init() */
#endif


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Destroy a dynamically allocated globus_io_write_info_t structure,
 * freeing the structure, and any dynamic data associated with the
 * structure. The structue should, of course, not be referenced after
 * this function is called.
 *
 * @param arg A pointer to the structure to destroy.
 *
 * @return void
 *
 * @see globus_l_io_write_info_init(), globus_io_write_info_t
 *
 */
static
void
globus_l_io_write_info_destroy(
    void *				arg)
{
    globus_io_write_info_t *		writev_info;

    writev_info = (globus_io_write_info_t *) arg;

    if(writev_info->orig_secure_iov)
    {
        int i;

        for(i = 0; i < writev_info->orig_secure_iovcnt; i++)
        {
    	    globus_free(writev_info->orig_secure_iov[i].iov_base);
        }
	globus_free(writev_info->orig_secure_iov);
    }
    if(writev_info->orig_malloced_iov)
    {
	globus_free(writev_info->orig_malloced_iov);
    }
    globus_free(writev_info);
}
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Implementation of asynchronous write()s.
 *
 * This function is called by the Globus I/O event driver when
 * it decides that the file descriptor is ready for writing. We use
 * the same code as globus_io_try_write() to actually do the I/O
 * on the handle.
 *
 * If all of the data is written successfully, or any I/O
 * error occurs, then the user's callback is invoked, with the
 * result parameter pointing to the final status of the write.
 *
 * Otherwise, the write is re-registered with the Globus I/O event
 * driver.
 *
 * @param arg A pointer to the state of the write. The state structure is 
 * of type globus_io_write_info_t. It contains a pointer to the buffer
 * to write, the lenght of the buffer, and the amount currently written.
 * @param handle The handle to write to.
 * @param result Either GLOBUS_SUCCESS, or a result pointing to an
 * error object to propagate to the user.
 *
 * @return void
 *
 * @see globus_io_write_info_t, globus_io_register_write(), 
 * @see globus_i_io_try_write()
 */
static
void
globus_l_io_write_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_io_write_info_t *		write_info;
    globus_size_t			n_written;
    globus_size_t			nbytes;
    globus_byte_t *			buf;
    globus_object_t *			err;
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif

    write_info = (globus_io_write_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	
	goto error_exit;
    }

#ifndef TARGET_ARCH_WIN32
    buf = (write_info->buf + write_info->nbytes_written);
    nbytes = (write_info->nbytes - write_info->nbytes_written);
    result = globus_i_io_try_write(handle, buf, nbytes, &n_written);

    write_info->nbytes_written += n_written;
    if(result != GLOBUS_SUCCESS)
    {
		err = globus_error_get(result);

		goto error_exit;
    }
#else
	write_info->nbytes_written+= 
	 handle->winIoOperation_write.numberOfBytesProcessed;
	// if the handle is a file, update the file pointer
	if ( handle->winIoOperation_write.numberOfBytesProcessed > 0 && 
	 handle->type == GLOBUS_IO_HANDLE_TYPE_FILE )
	{
		LARGE_INTEGER numberOfBytes;
		numberOfBytes.QuadPart= 
		 handle->winIoOperation_write.numberOfBytesProcessed;
		returnCode= globus_i_io_windows_move_file_pointer( handle,
			numberOfBytes, NULL );
		if ( returnCode )
		{
			err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						errno );
			goto error_exit;
		}
	}
#endif

    if(write_info->nbytes_written >= write_info->nbytes)
    {
        globus_i_io_mutex_lock();
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
        globus_i_io_mutex_unlock();
        
		/* Write is satisfied, call back to user */
		(*write_info->buf_callback)(write_info->arg,
						handle,
						result,
						write_info->buf,
						write_info->nbytes_written);
		globus_l_io_write_info_destroy(write_info);
    }
    else
    {
        /* write not yet satisfied, so reregister with the event driver */
        globus_i_io_mutex_lock();
        
        result = globus_i_io_register_operation(
                handle,
                globus_l_io_write_callback,
                write_info,
                globus_l_io_write_info_destroy,
                GLOBUS_TRUE,
                GLOBUS_I_IO_WRITE_OPERATION);

#ifdef TARGET_ARCH_WIN32
        if( result == GLOBUS_SUCCESS )
		{
			// post another write
			returnCode= globus_i_io_windows_write( handle,
			 write_info->buf + write_info->nbytes_written,
			 write_info->nbytes - write_info->nbytes_written, 
			 1, 0 );
			if ( returnCode == -1 ) // a fatal error occurred
			{
				// unregister the write operation
				// NOTE: Do not destroy the write info object because it
				// is needed for the user callback; the error exit
				// will destroy it as well as end the operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
					GLOBUS_I_IO_WRITE_OPERATION);

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
    }

    return;
    
  error_exit:
    
    globus_i_io_mutex_lock();
    globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
    globus_i_io_mutex_unlock();
        
    (*write_info->buf_callback)(write_info->arg,
				handle,
				globus_error_put(err),
				write_info->buf,
				write_info->nbytes_written);

    globus_l_io_write_info_destroy(write_info);
}
/* globus_l_io_write_callback() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Implementation of asynchronous write()s.
 *
 * This function is called by the Globus I/O event driver when
 * it decides that the file descriptor is ready for writing. We use
 * the same code as globus_io_try_write() to actually do the I/O
 * on the handle.
 *
 * If all of the data is written successfully, or any I/O
 * error occurs, then the user's callback is invoked, with the
 * result parameter pointing to the final status of the write.
 *
 * Otherwise, the write is re-registered with the Globus I/O event
 * driver.
 *
 * @param arg A pointer to the state of the write. The state structure is 
 * of type globus_io_write_info_t. It contains a pointer to the buffer
 * to write, the lenght of the buffer, and the amount currently written.
 * @param handle The handle to write to.
 * @param result Either GLOBUS_SUCCESS, or a result pointing to an
 * error object to propagate to the user.
 *
 * @return void
 *
 * @see globus_io_write_info_t, globus_io_register_send(), 
 * @see globus_i_io_try_send()
 */
static
void
globus_l_io_send_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_io_write_info_t *		write_info;
    globus_size_t			n_written;
    globus_size_t			nbytes;
    globus_byte_t *			buf;
    globus_object_t *			err;
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif

    write_info = (globus_io_write_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	
	goto error_exit;
    }

#ifndef TARGET_ARCH_WIN32
    buf = (write_info->buf + write_info->nbytes_written);
    nbytes = (write_info->nbytes - write_info->nbytes_written);
    result = globus_l_io_try_send(handle, 
				  buf, 
				  nbytes, 
				  write_info->send_flags,
				  &n_written);
				  
    write_info->nbytes_written += n_written;
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto error_exit;
    }
#else
	write_info->nbytes_written+= 
	 handle->winIoOperation_write.numberOfBytesProcessed;
	// if the handle is a file, update the file pointer
	if ( handle->winIoOperation_write.numberOfBytesProcessed > 0 && 
	 handle->type == GLOBUS_IO_HANDLE_TYPE_FILE )
	{
		LARGE_INTEGER numberOfBytes;
		numberOfBytes.QuadPart= 
		 handle->winIoOperation_write.numberOfBytesProcessed;
		returnCode= globus_i_io_windows_move_file_pointer( handle,
			numberOfBytes, NULL );
		if ( returnCode )
		{
			err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						errno );
			goto error_exit;
		}
	}
#endif
    if(write_info->nbytes_written >= write_info->nbytes)
    {
        globus_i_io_mutex_lock();
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
        globus_i_io_mutex_unlock();
        
	/* Write is satisfied, call back to user */
	(*write_info->buf_callback)(write_info->arg,
				    handle,
				    result,
				    write_info->buf,
				    write_info->nbytes_written);
	globus_l_io_write_info_destroy(write_info);

    }
    else
    {
        /* write not yet satisfied, so reregister with the event driver */
        globus_i_io_mutex_lock();
        
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_send_callback,
            write_info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);

#ifdef TARGET_ARCH_WIN32
        if( result == GLOBUS_SUCCESS )
		{
			// post another write
			returnCode= globus_i_io_windows_write( handle,
			 write_info->buf + write_info->nbytes_written,
			 write_info->nbytes - write_info->nbytes_written, 
			 1, write_info->send_flags );
			if ( returnCode == -1 ) // a fatal error occurred
			{
				// unregister the write operation
				// NOTE: Do not destroy the write info object because it
				// is needed for the user callback; the error exit
				// will destroy it as well as end the operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
					GLOBUS_I_IO_WRITE_OPERATION);

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
    }

    return;
    
  error_exit:
    globus_i_io_mutex_lock();
    globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
    globus_i_io_mutex_unlock();
    
    (*write_info->buf_callback)(write_info->arg,
				handle,
				globus_error_put(err),
				write_info->buf,
				write_info->nbytes_written);

    globus_l_io_write_info_destroy(write_info);
}
/* globus_l_io_send_callback() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Implementation of asynchronous writev()s.
 *
 * This function is called by the Globus I/O event driver when
 * it decides that the file descriptor is ready for writing.
 *
 * This function attempts to write the user's data vector to the
 * handle without blocking. If the writev() would block, then the
 * handle is re-registered for writing, and the function returns.
 *
 * If all of the data is written successful, or any I/O
 * error occurs, then the user's callback is invoked, with the
 * result parameter pointing to the final status of the write.
 *
 * @param arg A pointer to the state of the write. The state structure
 * is of type globus_io_write_info_t. It contains a pointer to the
 * vector of data to write, the length of the vector, and the amount
 * currently written.
 * @param handle The handle to write to.
 * @param result Either GLOBUS_SUCCESS, or a result pointing to an
 * error object to propagate to the user.
 *
 * @return void
 * @see globus_io_write_info_t, globus_io_register_writev() */
static
void
globus_l_io_writev_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_io_write_info_t *		writev_info;
    globus_size_t			n_written;
    globus_object_t *			err;
    globus_size_t			report_amt;
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif
    
    writev_info = (globus_io_write_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto error_exit;
    }

#ifndef TARGET_ARCH_WIN32
    result = globus_i_io_try_writev(handle,
				    writev_info->iov,
				    writev_info->iovcnt,
				    &n_written);
    writev_info->nbytes_written += n_written;
#else
	// update the number of bytes written
	n_written= handle->winIoOperation_write.numberOfBytesProcessed;
    writev_info->nbytes_written += n_written;
	// if the handle is a file, update the file pointer
	if ( handle->winIoOperation_write.numberOfBytesProcessed > 0 && 
	 handle->type == GLOBUS_IO_HANDLE_TYPE_FILE )
	{
		LARGE_INTEGER numberOfBytes;
		numberOfBytes.QuadPart= 
		 handle->winIoOperation_write.numberOfBytesProcessed;
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
#endif

    /* Adjust the iov array so that we can find the starting
     * point in the iovect array for the next writev
     */
    while (n_written > 0)
    {
	if (n_written >= writev_info->iov->iov_len)
	{
	    n_written -= writev_info->iov->iov_len;
	    writev_info->iov++;
	    writev_info->iovcnt--;
	}
	else
	{
	    writev_info->iov->iov_base =
		(void *) (((globus_byte_t *) writev_info->iov->iov_base)
			  + n_written);
	    writev_info->iov->iov_len -= n_written;
	    n_written = 0;
	}
    }
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto error_exit;
    }
    if (writev_info->iovcnt == 0)
    {
	/* Hmm... we may write more than the original IOVs
	 * add up to, if we are using security wrapping,
	 * so we will just say we wrote what were expected
	 * to.
	 */
	report_amt = writev_info->nbytes_written;
	
	if(writev_info->nbytes < writev_info->nbytes_written)
	{
	    report_amt = writev_info->nbytes;
	}
	
	globus_i_io_mutex_lock();
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
        globus_i_io_mutex_unlock();
    
	if(writev_info->iov_callback)
	{
	    (*writev_info->iov_callback)(writev_info->arg,
					 handle,
					 GLOBUS_SUCCESS,
					 writev_info->orig_iov,
					 writev_info->orig_iovcnt,
					 report_amt);
	}
	else
	{
	    (*writev_info->buf_callback)(writev_info->arg,
					 handle,
					 GLOBUS_SUCCESS,
					 writev_info->buf,
					 report_amt);
	}
	
	globus_l_io_write_info_destroy(writev_info);
    }
    else
    {
        globus_i_io_mutex_lock();
        
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_writev_callback,
            writev_info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);

#ifdef TARGET_ARCH_WIN32
		if ( result == GLOBUS_SUCCESS )
		{
			// post another write operation
			// for now, just fake the vectored write call
			// TODO: add an array of WSABUF structs in order to handle
			// actual vectored I/O
			rc= globus_i_io_windows_write( handle, 
				writev_info->iov[0].iov_base,
				writev_info->iov[0].iov_len, 
				1, 0 );
			if ( rc == -1 ) // a fatal error occurred
			{
				// unregister the write operation
                globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
				 GLOBUS_I_IO_WRITE_OPERATION);

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
    }
    return;

  error_exit:
    globus_i_io_mutex_lock();
    globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
    globus_i_io_mutex_unlock();
    
    /* Hmm... we may write more than the original IOVs
     * add up to, if we are using security wrapping,
     * so we will just say we wrote what were expected
     * to.
     */
    report_amt = writev_info->nbytes_written;

    if(writev_info->iov_callback)
    {
	(*writev_info->iov_callback)(writev_info->arg,
				     handle,
				     globus_error_put(err),
				     writev_info->orig_iov,
				     writev_info->orig_iovcnt,
				     report_amt);
    }
    else
    {
	(*writev_info->buf_callback)(writev_info->arg,
				     handle,
				     globus_error_put(err),
				     writev_info->buf,
				     report_amt);
    }
    globus_l_io_write_info_destroy(writev_info);

}
/* globus_io_writev_callback() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Implementation of asynchronous sendmsg()s.
 *
 * This function is called by the Globus I/O event driver when
 * it decides that the file descriptor is ready for writing.
 *
 * This function attempts to write the user's data vector to the
 * handle without blocking. If the sendmsg() would block, then the
 * handle is re-registered for writing, and the function returns.
 *
 * If all of the data is sent successfully, or any I/O
 * error occurs, then the user's callback is invoked, with the
 * result parameter pointing to the final status of the sendmsg.
 *
 * @param arg A pointer to the state of the sendmsg. The state structure
 * is of type globus_io_write_info_t. It contains a pointer to the
 * vector of data to write, the length of the vector, and the amount
 * currently written.
 * @param handle The handle to write to.
 * @param result Either GLOBUS_SUCCESS, or a result pointing to an
 * error object to propagate to the user.
 *
 * @return void
 * @see globus_io_write_info_t, globus_io_register_writev() */
static
void
globus_l_io_sendmsg_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_io_write_info_t *		writev_info;
    globus_size_t			n_written;
    globus_object_t *			err;
    globus_size_t			report_amt;
#ifndef TARGET_ARCH_WIN32
    struct msghdr			msg_hdr;
#else
	int rc;
#endif
    
    writev_info = (globus_io_write_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto error_exit;
    }

#ifndef TARGET_ARCH_WIN32
    memset(&msg_hdr, sizeof(msg_hdr), 0);
    msg_hdr.msg_name = GLOBUS_NULL;
    msg_hdr.msg_namelen = 0;
    msg_hdr.msg_iov = writev_info->iov;
    msg_hdr.msg_iovlen = writev_info->iovcnt;

    result = globus_i_io_try_sendmsg(handle,
				     &msg_hdr,
				     writev_info->send_flags,
				     &n_written);
    writev_info->nbytes_written += n_written;
#else /* TARGET_ARCH_WIN32 */
	n_written= 0;
#endif

    /* Adjust the iov array so that we can find the starting
     * point in the iovect array for the next writev
     */
    while (n_written > 0)
    {
	if (n_written >= writev_info->iov->iov_len)
	{
	    n_written -= writev_info->iov->iov_len;
	    writev_info->iov++;
	    writev_info->iovcnt--;
	}
	else
	{
	    writev_info->iov->iov_base =
		(void *) (((globus_byte_t *) writev_info->iov->iov_base)
			  + n_written);
	    writev_info->iov->iov_len -= n_written;
	    n_written = 0;
	}
    }
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto error_exit;
    }
    if (writev_info->iovcnt == 0)
    {
	/* Hmm... we may write more than the original IOVs
	 * add up to, if we are using security wrapping,
	 * so we will just say we wrote what were expected
	 * to.
	 */
	report_amt = writev_info->nbytes_written;
	
	if(writev_info->nbytes < writev_info->nbytes_written)
	{
	    report_amt = writev_info->nbytes;
	}
	
	globus_i_io_mutex_lock();
        globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
        globus_i_io_mutex_unlock();
    
	if(writev_info->iov_callback)
	{
	    (*writev_info->iov_callback)(writev_info->arg,
					 handle,
					 GLOBUS_SUCCESS,
					 writev_info->orig_iov,
					 writev_info->orig_iovcnt,
					 report_amt);
	}
	else
	{
	    (*writev_info->buf_callback)(writev_info->arg,
					 handle,
					 GLOBUS_SUCCESS,
					 writev_info->buf,
					 report_amt);
	}
	
	globus_l_io_write_info_destroy(writev_info);
    }
    else
    {
        globus_i_io_mutex_lock();
        
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_writev_callback,
            writev_info,
            globus_l_io_write_info_destroy,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);

#ifdef TARGET_ARCH_WIN32
		if ( result == GLOBUS_SUCCESS )
		{
			// post another write operation
			// for now, just fake the vectored write call
			// TODO: add an array of WSABUF structs in order to handle
			// actual vectored I/O
			rc= globus_i_io_windows_write( handle, 
				writev_info->iov[0].iov_base,
				writev_info->iov[0].iov_len, 
				1, 0 );
			if ( rc == -1 ) // a fatal error occurred
			{
				// unregister the write operation
                globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
				 GLOBUS_I_IO_WRITE_OPERATION);

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
    }
    return;

  error_exit:
    globus_i_io_mutex_lock();
    globus_i_io_end_operation(handle, GLOBUS_I_IO_WRITE_OPERATION);
    globus_i_io_mutex_unlock();
    
    /* Hmm... we may write more than the original IOVs
     * add up to, if we are using security wrapping,
     * so we will just say we wrote what were expected
     * to.
     */
    report_amt = writev_info->nbytes_written;

    if(writev_info->iov_callback)
    {
	(*writev_info->iov_callback)(writev_info->arg,
				     handle,
				     globus_error_put(err),
				     writev_info->orig_iov,
				     writev_info->orig_iovcnt,
				     report_amt);
    }
    else
    {
	(*writev_info->buf_callback)(writev_info->arg,
				     handle,
				     globus_error_put(err),
				     writev_info->buf,
				     report_amt);
    }
    globus_l_io_write_info_destroy(writev_info);

}
/* globus_l_io_sendmsg_callback() */
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Wake up a blocking write.
 *
 * When a blocking write is done using an asynchronous
 * write, this function is registered as the asynchronous write's
 * callback function. It simply propagates the return values from
 * the asynchronous operation and wakes the blocking write thread.
 *
 * @param arg A pointer to the monitor that the blocking write
 * function is waiting in.
 * @param handle The handle which we did the write on.
 * @param result The result of the write. This is propagated
 * to the blocking write function via the monitor.
 * @param buf The data block that we wrote. It is ignored in this
 * callback
 * @param nbytes The amount of data which we wrote. This is propagated
 * to the blocking write function via the monitor.
 * @return void
 *
 * @see globus_io_write(), globus_io_register_write(), 
 * @see globus_l_io_write_callback()
 */
static
void
globus_l_io_blocking_write_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes)
{
    globus_i_io_monitor_t *		write_monitor;
    globus_object_t *			err;

    err = globus_error_get(result);
    
    write_monitor = (globus_i_io_monitor_t *) arg;

    globus_mutex_lock(&write_monitor->mutex);

    write_monitor->nbytes = nbytes;
    if(result != GLOBUS_SUCCESS)
    {
	write_monitor->use_err = GLOBUS_TRUE;
	write_monitor->err = err;
    }
    write_monitor->done = GLOBUS_TRUE;
    
    globus_cond_signal(&write_monitor->cond);
    globus_mutex_unlock(&write_monitor->mutex);
} /* globus_l_io_blocking_write_callback() */
#endif


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Wake up a blocking writev.
 *
 * When a blocking writev is done using an asynchronous
 * writev, this function is registered as the asynchronous write's
 * callback function. It simply propagates the return values from
 * the asynchronous operation and wakes the blocking writev thread.
 *
 * @param arg A pointer to the monitor that the blocking write
 * function is waiting in.
 * @param handle The handle which we did the write on.
 * @param result The result of the write. This is propagated
 * to the blocking write function via the monitor.
 * @param iov The data vector that we wrote. It is ignored in this
 * callback.
 * @param iovcnt The number of buffers in the data vector that we wrote.
 *  It is ignored in this callback.
 * @param nbytes The amount of data which we wrote. This is propagated
 * to the blocking write function via the monitor.
 * @return void
 *
 * @see globus_io_writev(), globus_io_register_writev(), 
 * @see globus_l_io_writev_callback()
 */
static
void
globus_l_io_blocking_writev_callback(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_size_t                       nbytes)
{
    globus_i_io_monitor_t *             write_monitor;
    globus_object_t *                   err;

    err = globus_error_get(result);
    
    write_monitor = (globus_i_io_monitor_t *) arg;

    globus_mutex_lock(&write_monitor->mutex);

    write_monitor->nbytes = nbytes;
    if(result != GLOBUS_SUCCESS)
    {
        write_monitor->use_err = GLOBUS_TRUE;
        write_monitor->err = err;
    }
    write_monitor->done = GLOBUS_TRUE;
    
    globus_cond_signal(&write_monitor->cond);
    globus_mutex_unlock(&write_monitor->mutex);
}
/* globus_l_io_blocking_writev_callback() */
#endif
