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
 * @file globus_io_tcp.c Globus I/O toolset for TCP/IP sockets.
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


/**
 * @defgroup tcp TCP Sockets
 *
 * The API functions in this section deal with the establishment of
 * TCP connections, both server-side (listen) and client-side (connect).
 * There are hooks to the security code in this file, but all GSSAPI
 * calls live in the globus_io_securesocket.c file.
 *
 * As with the other operations supported by Globus I/O, there are both
 * blocking and an asynchronous API functions for each operation.
 */


/*
 * Include header files
 */
#include "globus_l_io.h"

/* one of the things I don't like about UNIX */
#if defined(EACCES) && !defined(EACCESS)
#   define EACCESS EACCES
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/*
 * Module Specific Prototypes
 */
static
globus_result_t
globus_l_io_tcp_create_socket(
    globus_io_handle_t *		handle);

static
void
globus_l_io_tcp_handle_destroy(
    globus_io_handle_t *		handle);
    
static
globus_result_t
globus_l_io_setup_tcp_socket(
    globus_io_handle_t *		handle);

static
globus_object_t *
globus_l_io_tcp_bind_socket(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr,
    unsigned short *			port);
#endif

/*
 * API Functions
 */

/**
 * Asynchronous TCP connection establishment.
 * 
 * Connect a TCP socket on the specified host/port pair. The connection
 * will be started by this function, and a callback will be invoked when
 * the connection is established.
 *
 * @param host The host to connect to.
 * @param port The TCP port number of the server.
 * @param attr TCP socket attributes. The attr, if non-NULL, should be
 * initialized by a call to globus_io_tcp_attr_init(). The attribute
 * settings for the attr structure can be modified by any of the
 * globus_io_tcp, globus_io_securesocket, or globus_io_socket attribute
 * accessors.  The security attributes must be compatible with those of
 * the server handle.
 * @param callback Function to be called when the connection operation is
 * completed. For secure connections, this function will called after the
 * security handshake is completed.
 * @param callback_arg User-supplied parameter to the callback function.
 * @param handle Globus I/O handle to be initialized when the connection
 * is completed. The application must not use this handle until the callback
 * function has been called.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. If the connection fails after
 * globus_io_tcp_register_connect() returns, the callback function will
 * be invoked with the result argument pointing to the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, host, or callback functions were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND
 * The host name parameter could not be resolved.
 * @see globus_io_tcp_connect()
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_register_connect(
    char *				host,
    unsigned short			port,
    globus_io_attr_t *			attr,
    globus_io_callback_t		callback,
    void *				callback_arg,
    globus_io_handle_t *		handle)
{
    struct sockaddr_in			his_addr;
    struct sockaddr_in			use_his_addr;
    struct hostent *			hp;
    int					save_errno;
    struct hostent			hp2;
    char				hp_tsdbuffer[4096];
    int					hp_errnop;
    globus_bool_t			connect_succeeded;
    globus_result_t			rc;
    globus_object_t *			err;
    unsigned short			myport = 0;
    globus_i_io_callback_info_t *       info;
    static char *			myname=
	                                "globus_io_tcp_register_connect";
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "handle",
	        6,
	        myname));
    }
    if(host == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "host",
	        1,
	        myname));
    }
    if(callback == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
		"callback",
		4,
		myname));
    }
    
    rc = globus_i_io_initialize_handle(handle,
                                       GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_i_io_copy_tcpattr_to_handle(attr,
					    handle);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    /* 
     * NETLOGGER
     */
    handle->nl_handle = GLOBUS_NULL;
    handle->nl_event_id = GLOBUS_NULL;
    if(attr != GLOBUS_NULL)
    {
        handle->nl_handle = attr->nl_handle;
    }

    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    
    hp = globus_libc_gethostbyname_r(host,
				     &hp2,
				     hp_tsdbuffer,
				     4096,
				     &hp_errnop);
    if (hp == NULL)
    {
	err = globus_io_error_construct_host_not_found(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "host",
	    1,
	    myname,
	    host);

	goto error_exit;
    }

    memset(&his_addr, '\0', sizeof(his_addr));
    his_addr.sin_family = hp->h_addrtype;
    memcpy(&his_addr.sin_addr,
	   hp->h_addr,
	   hp->h_length);
    his_addr.sin_port = htons(port);
    
    rc = globus_l_io_tcp_create_socket(handle);

    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    /* bind socket (using restrict port for firewalls and interface
     * for high-performance connections)
     */
    err = globus_l_io_tcp_bind_socket(handle, attr, &myport);

	/*	The following line of code was originally placed beneath the
	 *	codeblock that begins with the call to 
	 *	globus_i_io_setup_nonblocking(). I moved it here so that it
	 *	apply to both the Unix and Windows versions.
	 */
    handle->type = GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED;

#ifndef TARGET_ARCH_WIN32
    /* get it ready for nonblocking I/O */
    if ((rc = globus_i_io_setup_nonblocking(handle)) != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	
	globus_i_io_debug_printf(2,
				 (stderr, "%s(): "
				  "globus_i_io_setup_nonblocking() failed\n",
				  myname));
	globus_libc_close(handle->fd);

	goto error_exit;
    }  

    /* start connecting */
    connect_succeeded = GLOBUS_FALSE;
    while (!connect_succeeded)
    {
	use_his_addr = his_addr;

	if (connect(handle->fd,
		    (struct sockaddr *)&use_his_addr,
		    sizeof(use_his_addr)) == 0)
	{
	    connect_succeeded = GLOBUS_TRUE;
	}
	else
	{
	    save_errno = errno;
	    if (save_errno == EINPROGRESS)
	    {
		/*
		 * man connect: EINPROGRESS:
		 *   The socket is non-blocking and the connection cannot be
		 *   completed immediately.  It is possible to select(2) for
		 *   completion by selecting the socket for writing.
		 * So this connect has, for all practical purposes, succeeded.
		 */
		connect_succeeded = GLOBUS_TRUE;
	    }
	    else if (save_errno == EINTR)
	    {
		/*
		 * Do nothing.  Just try again.
		 */
	    }
	    else if (save_errno == ETIMEDOUT)
	    {
		/*
		 * Might as well give other threads a chance to run before
		 * trying again.
		 */
	        globus_thread_yield();
	    }
	    else
	    {
		globus_libc_close(handle->fd);

		/* something else (bad) occurred */
		err = globus_io_error_construct_system_failure(
		            GLOBUS_IO_MODULE,
			    GLOBUS_NULL,
			    handle,
			    save_errno);

		goto error_exit;
	    }
	}
    }
#else
	// FOR NOW- This call will block (per discussion with Steve) because
	// the I/O completion port model does not support the connect() call
	// TODO- change this so that an asynchronous model for calling
	// connect() can be supported
	use_his_addr= his_addr;
	if ( connect( (SOCKET)handle->io_handle, 
	 (struct sockaddr *)&use_his_addr, 
	  sizeof(use_his_addr)) == SOCKET_ERROR )
	{
		int save_error;
		globus_i_io_winsock_get_last_error();
		save_error= errno;
		err = globus_io_error_construct_system_failure(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			handle,
			save_error );

		globus_i_io_winsock_close( handle );

		goto error_exit;
	}
    /* get it ready for nonblocking I/O */
    if ((rc = globus_i_io_setup_nonblocking(handle)) != GLOBUS_SUCCESS)
    {
		err = globus_error_get(rc);
		
		globus_i_io_debug_printf(2,
					("%s(): "
					"globus_i_io_setup_nonblocking() failed\n",
					myname));
		globus_i_io_winsock_close( handle );
		goto error_exit;
    }
#endif /* TARGET_ARCH_WIN32 */

    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTING;
    
    info = (globus_i_io_callback_info_t *)
            globus_malloc(sizeof(globus_i_io_callback_info_t));
    info->callback = callback;
    info->callback_arg = callback_arg;
        
    globus_i_io_mutex_lock();
    
    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        rc = globus_i_io_register_quick_operation(
            handle,
            globus_i_io_connect_callback,
            info,
            globus_i_io_default_destructor,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
    }
    else
    {
        rc = globus_i_io_start_operation(
            handle,
            GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
        if(rc == GLOBUS_SUCCESS)
        {
            rc = globus_i_io_register_operation(
                handle,
                globus_i_io_securesocket_register_connect_callback,
                info,
                globus_i_io_default_destructor,
                GLOBUS_TRUE,
                GLOBUS_I_IO_WRITE_OPERATION);
            
            if(rc != GLOBUS_SUCCESS)
            {
                globus_i_io_end_operation(
                    handle, 
                    GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
            }
        }
    }
#ifdef TARGET_ARCH_WIN32
    if( rc == GLOBUS_SUCCESS )
	{
		// post a packet in order to trigger the callback
		returnCode= globus_i_io_windows_post_completion( 
					handle, 
					WinIoConnecting );
		if ( returnCode ) // a fatal error occurred
		{
			// unregister the quick write operation
            globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
				GLOBUS_I_IO_WRITE_OPERATION);

			err = globus_io_error_construct_system_failure(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle,
					returnCode );
		    globus_i_io_mutex_unlock();
			goto error_exit;
		}
	}
#endif

    globus_i_io_mutex_unlock();

    if(rc != GLOBUS_SUCCESS)
    {
        globus_free(info);
        err = globus_error_get(rc);
        goto error_exit;
    }
    
    return GLOBUS_SUCCESS;

  error_exit:
    globus_l_io_tcp_handle_destroy(handle);
    
    return globus_error_put(err);
}
/* globus_io_tcp_register_connect() */

/**
 * Blocking TCP connection establishment.
 *
 * Connect a TCP socket on the specified host/port pair.
 *
 * @param host The host to connect to.
 * @param port The TCP port number of the server.
 * @param attr TCP socket attributes. The attr, if non-NULL, should be
 * initialized by a call to globus_io_tcp_attr_init(). The attribute
 * settings for the attr structure can be modified by any of the
 * globus_io_tcp, globus_io_securesocket, or globus_io_socket attribute
 * accessors.  The security attributes must be compatible with those of
 * the server handle.
 * @param handle Globus I/O handle to be initialized when the connection
 * is completed. The application must not use this handle until this 
 * function has returned.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, host, or callback parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND
 * The host name parameter could not be resolved.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The connect failed with an unexpected error. The errno returned
 * by the system call is accessible from the error object.
 * @see globus_io_tcp_register_connect()
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_connect(
    char *				host,
    unsigned short			port,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result;
    globus_callback_space_t             saved_space;

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.use_err = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    
    /* we're going to poll on global space, save users space */
    if(attr)
    {
        globus_io_attr_get_callback_space(attr, &saved_space);
        /* need to hold a reference to that space for new handle */
        globus_callback_space_reference(saved_space);
        globus_io_attr_set_callback_space(attr, GLOBUS_CALLBACK_GLOBAL_SPACE);
    }

    result = globus_io_tcp_register_connect(host,
					    port,
					    attr,
					    globus_i_io_monitor_callback,
					    (void *) &monitor,
					    handle);
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
    
    if(attr)
    {
        globus_io_attr_set_callback_space(attr, saved_space);
        
        if(handle)
        {
            globus_i_io_set_callback_space(handle, saved_space);
        }
        else
        {
            globus_callback_space_destroy(saved_space);
        }
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
/* globus_io_tcp_connect() */

/**
 * Create a TCP server socket.
 *
 * This function creates a socket handle capable of accepting new
 * TCP connections from other hosts or processes.
 *
 * In order to actively listen for connections, you must call
 * globus_io_tcp_register_listen() or globus_io_tcp_listen() with the
 * new handle returned by this function.
 *
 * @param port The TCP port that the socket will listen for
 * connections on. If the port number is 0, then an arbitrary TCP port
 * will be selected.  If this is true, and the restrict_port attribute
 * is set to TRUE (the default) and the GLOBUS_TCP_PORT_RANGE
 * environment variable was set when Globus I/O was initialized, then
 * the port will be selected from that range. Otherwise, any port number
 * may be chosen.
 * @param backlog The backlog parameter indicates the maximum length
 * of the system's queue of pending connections. Any connection attempts
 * when the queue is full will fail. If backlog is equal to -1, then the
 * system-specific maximum queue length will be used.
 * @param attr The attributes of this server. The attributes will be
 * used as the default for handles created by accepting a connection
 * on this handle.
 * @param handle The new handle which will be created for this server.
 * It can only be used for listening for and establishing connections, and
 * may be closed by calling globus_io_register_close() or globus_io_close();
 * other I/O operations on this handle will fail.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, host, or callback parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_HOST_NOT_FOUND
 * The host name parameter could not be resolved.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The connect failed with an unexpected error. The errno returned
 * by the system call is accessible from the error object.
 *
 * @see globus_io_tcp_register_listen(), globus_io_tcp_listen()
 * @see globus_io_tcp_register_accept(), globus_io_tcp_accept()
 *
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_create_listener(
    unsigned short *			port,
    int					backlog,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_result_t			rc;
    int					save_errno;
    globus_object_t *			err = GLOBUS_SUCCESS;
    struct sockaddr_in			my_addr;
    static char *			myname =
	                                "globus_io_tcp_create_listener";

    globus_netlen_t			len;

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		4,
		myname));
    }
    if(port == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"port",
		1,
		myname));
    }

    rc = globus_i_io_initialize_handle(handle,
                                       GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    globus_i_io_debug_printf(3,
			     (stderr, "%s(): entering\n", myname));

    rc = globus_i_io_copy_tcpattr_to_handle(attr,
					    handle);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    /*
     *  For now set net logger info to null.
     *  Only use for reads and writes, not listen
     *
     *  NETLOGGER
     */
    handle->nl_event_id = GLOBUS_NULL;
    handle->nl_handle = GLOBUS_NULL;

    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;

    len = sizeof(my_addr);
    rc = globus_l_io_tcp_create_socket(handle);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    /* get it ready for nonblocking I/O */
    if ((rc = globus_i_io_setup_nonblocking(handle)) != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	
	globus_i_io_debug_printf(2,
				 (stderr, "%s(): "
				  "globus_i_io_setup_nonblocking() failed\n",
				  myname));

	goto error_exit;
    }

    err = globus_l_io_tcp_bind_socket(handle, attr, port);

    if(err != GLOBUS_SUCCESS)
    {

	goto error_exit;
    }
    
#ifndef TARGET_ARCH_WIN32
    if(listen(handle->fd,
	      (backlog < 0 ? SOMAXCONN : backlog)) < 0)
    {
#else
    if(listen( (SOCKET)handle->io_handle,
		(backlog < 0 ? SOMAXCONN : backlog)) == SOCKET_ERROR )
    {
		globus_i_io_winsock_get_last_error();
#endif /*TARGET_ARCH_WIN32 */
	save_errno = errno;

	globus_assert(GLOBUS_FALSE && "listen() failed");

	err = globus_io_error_construct_internal_error(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    myname);

	goto error_exit;    
    }

#ifndef TARGET_ARCH_WIN32
    if(getsockname(handle->fd,
		   (struct sockaddr *) & my_addr,
		   &len) < 0)
    {
#else
    if(getsockname( (SOCKET)handle->io_handle,
		   (struct sockaddr *) & my_addr,
		   &len) == SOCKET_ERROR )
	{
		globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32 */
        save_errno = errno;

        err = globus_io_error_construct_system_failure(
                  GLOBUS_IO_MODULE,
	          GLOBUS_NULL,
	          handle,
		  save_errno);

	goto error_exit;    
    }
    
    *port = ntohs(my_addr.sin_port);

    handle->state = GLOBUS_IO_HANDLE_STATE_LISTENING;

#ifdef TARGET_ARCH_WIN32
	// create a buffer to hold addresses obtained when accepting
	handle->winIoOperation_structure.addressInfo= globus_malloc( 
	 2 * sizeof(SOCKADDR_IN) + 32 );
	if ( handle->winIoOperation_structure.addressInfo == NULL )
	{
        err = globus_io_error_construct_system_failure(
               GLOBUS_IO_MODULE,
	           GLOBUS_NULL,
	           handle,
			   ERROR_OUTOFMEMORY );

		goto error_exit;    
	}
#endif
    
    globus_i_io_debug_printf(3,
			     (stderr, "%s(): exiting\n", myname));
    return GLOBUS_SUCCESS;
    
  error_exit:
#ifndef TARGET_ARCH_WIN32
    globus_libc_close(handle->fd);
#else
	globus_i_io_windows_close( handle );
#endif /* TARGET_ARCH_WIN32 */
    globus_l_io_tcp_handle_destroy(handle);
    
    return globus_error_put(err);
}
/* globus_io_tcp_create_listener() */

/**
 * Asynchronous server-side TCP connection establishment.
 *
 * Once the connection has been accepted, the callback function will
 * be called, with the callback_arg and a newly created, connected,
 * handle argument passed to the callback.
 *
 * @param listener_handle A Globus I/O handle created by
 * globus_io_tcp_create_listener(). 
 * @param attr The attributes of the new connection. If this is GLOBUS_NULL,
 * than the attributes passed to globus_io_tcp_create_listener will be used.
 * The attributes should be compatible with those passed to that function.
 * Security attributes can not be changed between those two calls.
 * @param new_handle A handle to the new connection. This handle must not
 * be used for any operation until the callback function is called.
 * @param callback The function to be called once the connection is
 * established, and any security exchange has taken place. The
 * "handle" passed to the callback will be the "new_handle" pointer
 * passed to this function.
 * @param callback_arg User-specific parameter to the callback function.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, new_handle, or callback parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter refers to a Globus I/O handle which is already
 * in the process of closing down.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter refers to a Globus I/O handle which has not
 * had the globus_io_tcp_register_listen() or globus_io_tcp_listen()
 * function recently called on it.
 * The attribute structure is non-NULL, but not initialized.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The attribute structure is not a TCP attribute, but some other
 * attribute type.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The accept() system call failed. The connection could not be
 * established. The errno returned by the system call is accessible
 * from the error object.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_register_accept(
    globus_io_handle_t *		listener_handle,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		new_handle,
    globus_io_callback_t 		callback,
    void *				callback_arg)
{
    struct sockaddr			addr;
    globus_result_t			rc;
    int					save_errno;
    globus_bool_t			proceed;
    globus_io_attr_t 			listener_attr;
    globus_object_t *			err;
    static char *			myname="globus_io_tcp_register_accept";
    globus_netlen_t			addrlen;
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif
    
    if(listener_handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"listener_handle",
		1,
		myname));
    }
    if(new_handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"new_handle",
		3,
		myname));
    }
    if(callback == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"callback",
		4,
		myname));
    }
    
    globus_i_io_debug_printf(
	1,
	(stderr, "%s(): enter, listener fd=%d",
	 myname,
	 listener_handle->fd));
    
    globus_i_io_mutex_lock();

    switch(listener_handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	err = globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    listener_handle);

	goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_LISTENING:
        break;
      default:
	err = globus_io_error_construct_not_initialized(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "listener_handle",
	    1,
	    myname);

        goto error_exit;
    }

    /* if passed in, verify attributes are OK */
    if(attr != GLOBUS_NULL)
    {
	if(attr->attr == GLOBUS_NULL)
	{
	    err = globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		2,
		myname);

	    goto error_exit;
	}
	if(globus_object_get_type(attr->attr) != GLOBUS_IO_OBJECT_TYPE_TCPATTR)
	{
	    err = globus_io_error_construct_invalid_type(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    "attr",
		    2,
		    myname,
		    "GLOBUS_IO_OBJECT_TYPE_TCPATTR");

	    goto error_exit;
	}
    }

#ifdef TARGET_ARCH_WIN32
	// make sure that the user called a Globus listen function
	// successfully before calling this function
	if ( listener_handle->winIoOperation_structure.acceptedSocket ==
		INVALID_SOCKET )
	{
		err = globus_io_error_construct_not_initialized(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			"listener_handle",
			1,
			myname);

		goto error_exit;
	}
#endif

    /* Keep a copy of the listener's defaults, so we can restore once
     * we're done with this accept.
     */
    rc = globus_io_tcp_get_attr(listener_handle,
				&listener_attr);
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	
	goto error_exit;
    }

    if(attr == GLOBUS_NULL)
    {
	/*
	 * If the user did not specify an attr, we use the defaults
	 * from the listener.
	 */
        attr = &listener_attr;
    }
    else
    {
	/* temporarily change listener to desired attributes */
        rc = globus_io_tcp_set_attr(listener_handle,
                                    attr);
	if(rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_get(rc);
	
	    globus_io_tcpattr_destroy(&listener_attr);

	    goto error_exit;
	}
    }


    rc = globus_i_io_initialize_handle(new_handle,
				       GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);

	goto restore_listener_error_exit;
    }
    
    /* Set state of new handle to be the same as the modified listener */
    rc = globus_i_io_copy_tcpattr_to_handle(attr,
					    new_handle);
   
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	
	goto restore_listener_error_exit;
    }

    /* 
     *  NETLOGGER
     */
    new_handle->nl_event_id = GLOBUS_NULL;
    new_handle->nl_handle = GLOBUS_NULL;
    if(attr != GLOBUS_NULL)
    {
        new_handle->nl_handle = attr->nl_handle;
    }
 
    addrlen = sizeof(struct sockaddr);

    proceed = GLOBUS_FALSE;

#ifndef TARGET_ARCH_WIN32
    /* make the new socket by calling accept() */
    while(!proceed)
    {
	int				fd;
	
	fd = accept(listener_handle->fd,
		    &addr,
		    &addrlen);
	if(fd < 0)
	{
	    save_errno = errno;
	    if(save_errno == EINTR)
	    {
		continue;
	    }
	    else
	    {
		globus_i_io_debug_printf(2,
					 (stderr, "globus_io_tcp_accept(): "
					  "accept() failed\n"));

                err = globus_io_error_construct_system_failure(
		            GLOBUS_IO_MODULE,
			    GLOBUS_NULL,
			    new_handle,
			    save_errno);

		goto restore_listener_error_exit;
	    }
	}
	else
	{
	    new_handle->fd = fd;
	    proceed = GLOBUS_TRUE;
	}
    }
#else
	// store the newly-accepted socket into it's own Globus handle
	new_handle->io_handle= (HANDLE)
	 listener_handle->winIoOperation_structure.acceptedSocket;
	// reset the listener's handle
	listener_handle->winIoOperation_structure.acceptedSocket= 
	 INVALID_SOCKET;
	globus_i_io_winsock_store_addresses( new_handle, listener_handle );
#endif

    /* The new socket is nearly ready now. We now restore the listener
     * to it's original state.
     */
    if(attr != GLOBUS_NULL)
    {
        rc = globus_io_tcp_set_attr(listener_handle,
                                    &listener_attr);
	/*
	 * This is kind of bad. We've changed the listener's default
	 * state. Not much we can do here, I'm afraid.
	 */
	if(rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_get(rc);
	
	    globus_io_tcpattr_destroy(&listener_attr);

            globus_libc_close(new_handle->fd);
	    goto error_exit;
	}
    }

    /* We are done with this guy now, so let's free him up */
    globus_io_tcpattr_destroy(&listener_attr);

    /* get it ready for nonblocking I/O */
    if ((rc = globus_i_io_setup_nonblocking(new_handle)) != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	
	globus_i_io_debug_printf(2,
				 (stderr, "%s(): "
				  "globus_i_io_setup_nonblocking() failed\n",
				  myname));
#ifndef TARGET_ARCH_WIN32
	globus_libc_close(new_handle->fd);
#else
		globus_i_io_windows_close( new_handle );
#endif /* TARGET_ARCH_WIN32 */

	goto error_exit;
    }

    new_handle->state = GLOBUS_IO_HANDLE_STATE_ACCEPTING;

#ifdef TARGET_ARCH_WIN32
	// initialize the WinIoOperation structs
	globus_i_io_windows_init_io_operations( new_handle );
	/* associate the new socket with the completion port */
	if ( CreateIoCompletionPort( new_handle->io_handle,
		completionPort, (ULONG_PTR)new_handle, 0 ) == NULL )
	{
		err = globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				new_handle,
				globus_i_io_windows_get_last_error() );
	
		globus_i_io_windows_close( new_handle );

		goto error_exit;
	}
#endif

	/* if no authentication is to be done, callback now */
    if(new_handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        new_handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
        
        rc = globus_i_io_register_quick_operation(
            new_handle,
            callback,
            callback_arg,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if( rc == GLOBUS_SUCCESS)
		{
			// post a packet in order to trigger the callback
			returnCode= globus_i_io_windows_post_completion( 
						new_handle, 
						WinIoWriting );
			if ( returnCode ) // a fatal error occurred
			{
				// unregister the quick write operation
				globus_i_io_unregister_operation( new_handle, 
					GLOBUS_TRUE, GLOBUS_I_IO_WRITE_OPERATION);

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						new_handle,
						returnCode );
				goto error_exit;
			}
		}
#endif
    }
    else
    {
        globus_i_io_callback_info_t *   info;
        
        info = (globus_i_io_callback_info_t *)
            globus_malloc(sizeof(globus_i_io_callback_info_t));
        info->callback = callback;
        info->callback_arg = callback_arg;
        
        rc = globus_i_io_securesocket_register_accept(
            new_handle,
            globus_i_io_accept_callback,
            info);
    }
    
    if(rc != GLOBUS_SUCCESS)
    {
        err = globus_error_get(rc);
	globus_libc_close(new_handle->fd);
        goto error_exit;
    }
    
    globus_i_io_debug_printf(1, (stderr, "%s(): exit\n",
				 myname));

    globus_i_io_mutex_unlock();
    return GLOBUS_SUCCESS;

  restore_listener_error_exit:
    /*
     * The accept failed, in general, but we want to restore state
     * on the listener.
     */
    if(attr != GLOBUS_NULL)
    {
        rc = globus_io_tcp_set_attr(listener_handle,
                                    &listener_attr);
	/*
	 * This is kind of bad. We've changed the listener's default
	 * state. Not much we can do here, I'm afraid.
	 */
	if(rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_get(rc);
	
	}
    }

    globus_io_tcpattr_destroy(&listener_attr);
  error_exit:
    globus_i_io_mutex_unlock();
    new_handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;

    return globus_error_put(err);
}
/* globus_io_tcp_register_accept() */

/**
 * Blocking server-side TCP connection establishment.
 *
 * @param listener_handle A Globus I/O handle created by
 * globus_io_tcp_create_listener(). 
 * @param attr The attributes of the new connection. If this is GLOBUS_NULL,
 * than the attributes passed to globus_io_tcp_create_listener will be used.
 * The attributes should be compatible with those passed to that function.
 * Security attributes can not be changed between those two calls.
 * @param new_handle A handle to the new connection. This handle must not
 * be used for any operation until this function returns successfully.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, new_handle, or callback parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle parameter refers to a Globus I/O handle which is already
 * in the process of closing down.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle parameter refers to a Globus I/O handle which has not
 * had the globus_io_tcp_register_listen() or globus_io_tcp_listen()
 * function recently called on it.
 * The attribute structure is non-NULL, but not initialized.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The attribute structure is not a TCP attribute, but some other
 * attribute type.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The accept() system call failed. The connection could not be
 * established. The errno returned by the system call is accessible
 * from the error object.
 * @retval GLOBUS_IO_ERROR_TYPE_AUTHENTICATION_FAILED
 * The security authentication exchanged failed. This may be caused by
 * an invalid security environment on the client or server side, or 
 * the client and server having incompatible security attributes.
 * @retval GLOBUS_IO_ERROR_TYPE_AUTHORIZATION_FAILED
 * Security authorization failed. This occurs when the authentication
 * exchange completes successfully, but the listener_handle's
 * security authorization attributes prohibit the client from
 * connecting to this server.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_accept(
    globus_io_handle_t *		listener_handle,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_i_io_monitor_t		monitor;
    globus_result_t			result;
    globus_callback_space_t             saved_space;
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.use_err = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    
    /* we're going to poll on global space, save users space */
    if(attr)
    {
        globus_io_attr_get_callback_space(attr, &saved_space);
        /* need to hold a reference to that space for new handle */
        globus_callback_space_reference(saved_space);
        globus_io_attr_set_callback_space(attr, GLOBUS_CALLBACK_GLOBAL_SPACE);
    }
    else
    {
        globus_i_io_get_callback_space(listener_handle, &saved_space);
        globus_i_io_set_callback_space(
            listener_handle, GLOBUS_CALLBACK_GLOBAL_SPACE);
    }
    
    result = globus_io_tcp_register_accept(listener_handle,
					   attr,
					   handle,
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

    /* restore user attr */
    if(attr)
    {
        globus_io_attr_set_callback_space(attr, saved_space);
        
        if(handle)
        {
            globus_i_io_set_callback_space(handle, saved_space);
        }
        else
        {
            globus_callback_space_destroy(saved_space);
        }
    }
    else
    {
        globus_i_io_set_callback_space(listener_handle, saved_space);
        
        if(handle)
        {
            globus_callback_space_reference(saved_space);
            globus_i_io_set_callback_space(handle, saved_space);
        }
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
/* globus_io_tcp_accept() */


/**
 * Extract the TCP attributes from a Globus I/O handle.
 *
 * @param handle The Globus I/O handle to query
 * @param attr The attribute structure to be initialized to
 * the same attributes as the Globus I/O handle.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or attr parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle is not a valid TCP handle.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_get_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr)
{
    globus_result_t			rc;
    globus_i_io_tcpattr_instance_t *	instance;
    globus_object_t *			err;
    static char *			myname="globus_io_tcp_get_attr";
    
    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }

    if(handle->state == GLOBUS_IO_HANDLE_STATE_INVALID)
    {
        return globus_error_put(
            globus_io_error_construct_not_initialized(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
    }

    /* null check here */
    rc = globus_io_tcpattr_init(attr);
    
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);

	/* massage the error into one from this call */
	if(globus_object_type_match(globus_object_get_type(err),
				    GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER))
	{
	    globus_io_error_bad_parameter_set_position(err,2);
	    globus_io_error_bad_parameter_set_name(err,"attr");
	    globus_io_error_bad_parameter_set_function(err,myname);
	}
	goto error_exit;
    }

    globus_i_io_securesocket_get_attr(handle,
				      attr);

    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(attr->attr);

    globus_i_io_tcp_copy_attr(
	instance,
	&handle->tcp_attr);
    
    return GLOBUS_SUCCESS;

  error_exit:
    return globus_error_put(err);
}
/* globus_io_tcp_get_attr() */

/**
 * Apply a new attribute structure to a Globus I/O TCP handle.
 * 
 * This function attempts to apply a new set of TCP attributes to
 * a handle. If any attribute setting fails, then this function will
 * attempt to restore the handle to it's original state.
 *
 * @param handle The handle to modify
 * @param attr The new attribute set to apply to this handle.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or attr parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle is not a valid TCP handle.
 * The attribute structure is not valid.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The setting of the TCP socket attributes failed in an system call.
 * @retval GLOBUS_IO_ERROR_TYPE_IMMUTABLE_ATTRIBUTE
 * Attr does not match the handles current attribute for one which
 * cannot be changed, such as the restrict-port attribute, or security
 * attributes.
 *
 * @bug The restoration of the attribute state on an error may fail 
 * if system resources are scarce.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_set_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr)
{
    globus_result_t			rc;
    globus_object_t *			err;
    globus_i_io_tcpattr_instance_t *	instance;
    int					save_errno;
    static char *			myname="globus_io_tcp_set_attr";
    
    /* verify arguments */
    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }
    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		2,
		myname));
    }
    if(attr->attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_not_initialized(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		2,
		myname));
    }
    if(globus_object_get_type(attr->attr) != GLOBUS_IO_OBJECT_TYPE_TCPATTR)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		2,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_TCPATTR"));
    }
    
    instance = (globus_i_io_tcpattr_instance_t *)
	globus_object_get_local_instance_data(attr->attr);

    handle->nl_handle = attr->nl_handle;

    /* set local socket options */
    if(instance->nodelay != handle->tcp_attr.nodelay)
    {
#ifndef TARGET_ARCH_WIN32
	if(setsockopt(handle->fd,
		      IPPROTO_TCP,
		      TCP_NODELAY,
		      (char *) &instance->nodelay,
		      sizeof(instance->nodelay)) < 0)
	{
#else
		if(setsockopt( (SOCKET)handle->io_handle,
				IPPROTO_TCP,
				TCP_NODELAY,
				(char *) &instance->nodelay,
				sizeof(instance->nodelay)) == SOCKET_ERROR )
		{
			globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32 */
	    save_errno = errno;

	    err = globus_io_error_construct_system_failure(
		        GLOBUS_IO_MODULE,
		        GLOBUS_NULL,
			handle,
		        save_errno);

	    goto error_exit;
	}
    }

    if(instance->restrict_port != handle->tcp_attr.restrict_port)
    {
	/* port restriction can not be changed */
	err = globus_io_error_construct_immutable_attribute(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "attr",
	    2,
	    myname,
	    "restrict_port");

	goto undo_nodelay;
    }

    /* set lower-level socket options */
    rc = globus_i_io_securesocket_set_attr(handle,
					   attr);
    if(rc != GLOBUS_SUCCESS)
    {
	int pos;

	err = globus_error_get(rc);
	if(globus_object_type_match(globus_object_get_type(err),
				    GLOBUS_IO_ERROR_TYPE_BAD_PARAMETER))
	{
	    pos = globus_io_error_bad_parameter_get_position(err);

	    if(pos == 1)
	    {
		globus_io_error_bad_parameter_set_position(err,1);
		globus_io_error_bad_parameter_set_name(err,"handle");
		globus_io_error_bad_parameter_set_function(err,myname);
	    }
	    else if(pos == 2)
	    {
		globus_io_error_bad_parameter_set_position(err,2);
		globus_io_error_bad_parameter_set_name(err,"attr");
		globus_io_error_bad_parameter_set_function(err,myname);
	    }
	}

	goto undo_nodelay;
    }

    /* commit any changes to the handle structure */
    if(instance->nodelay != handle->tcp_attr.nodelay)
    {
	handle->tcp_attr.nodelay = instance->nodelay;
    }
    
    return GLOBUS_SUCCESS;
    
  undo_nodelay:
    if(instance->nodelay != handle->tcp_attr.nodelay)
    {
#ifndef TARGET_ARCH_WIN32
	setsockopt(handle->fd,
#else
		setsockopt( (SOCKET)handle->io_handle,
#endif
		   IPPROTO_TCP,
		   TCP_NODELAY,
		   (char *) &handle->tcp_attr.nodelay,
		   sizeof(handle->tcp_attr.nodelay));
    }
    
  error_exit:
    return globus_error_put(err);
}
/* globus_io_tcp_set_attr() */

/**
 * Extract the security context from a Globus I/O handle.
 *
 * @param handle The Globus I/O handle to query.
 * @param context The handle's context will be copied into this
 * parameter. Note that a shallow copy operation is done. If the context
 * is needed beyond the lifetime of the handle, it should be exported
 * and then re-imported using the gssapi. If message integrity is desired
 * it is often easier to use the secure channel modes defined by Globus I/O.
 * If no security attributes are set on the handle, then this parameter
 * will be set to GSS_C_NO_CONTEXT.
 *
 * @bug Using the context may interfere with Globus I/O correctly wrapping
 * and unwrapping data on a secure channel.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or context parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The handle is not a TCP handle.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle is not connected.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_get_security_context(
    globus_io_handle_t *		handle,
    gss_ctx_id_t *			context)
{
   globus_object_t *			err;
   static char *			myname="globus_io_tcp_get_security_context";

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }
    if(context == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"context",
		2,
		myname));
    }
    globus_i_io_mutex_lock();
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED");

	goto error_exit;
    }

    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CONNECTED:
	break;
      default:
	err = globus_io_error_construct_not_initialized(
	   GLOBUS_IO_MODULE,
	   GLOBUS_NULL,
	   "handle",
	   1,
	   myname);
	goto error_exit;
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *context = GSS_C_NO_CONTEXT;
    }
    else
    {
        *context = handle->context;
    }

    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_tcp_get_security_context() */

/**
 * Extract the delegated credential from a Globus I/O handle.
 *
 * @param handle
 *        The Globus I/O handle to query. This may only be used on handles
 *        created by calling globus_io_tcp_register_accept() or
 *        globus_io_tcp_accept().
 * @param cred
 *        The handle's delegated credential will be copied into this parameter.
 *        Note that a shallow copy operation is done. If the credential is
 *        needed beyond the lifetime of the handle, it should be exported and
 *        then re-imported using the gssapi. If no security attributes are set
 *        on the handle, then this parameter will be set to GSS_C_NO_CONTEXT.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or context parameters were GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The handle is not a TCP handle.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle is not connected.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_get_delegated_credential(
    globus_io_handle_t *		handle,
    gss_cred_id_t *			cred)
{
   globus_object_t *			err;
   static char *			myname="globus_io_tcp_get_delegated_credential";

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }
    if(cred == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"cred",
		2,
		myname));
    }
    globus_i_io_mutex_lock();
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED");

	goto error_exit;
    }

    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CONNECTED:
	break;
      default:
	err = globus_io_error_construct_not_initialized(
	   GLOBUS_IO_MODULE,
	   GLOBUS_NULL,
	   "handle",
	   1,
	   myname);
	goto error_exit;
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *cred = GSS_C_NO_CREDENTIAL;
    }
    else
    {
        *cred = handle->delegated_credential;
    }

    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_tcp_get_delegated_credential() */

/**
 * @name TCP Attributes
 */
/* @{ */
/**
 * Initialize a TCP attribute structure.
 *
 * @param attr Attribute to initialize.
 * 
 * <b>Default TCP Attributes:</b>
 * @code
 * nodelay: FALSE
 * restrict_port: TRUE
 * reuseaddr: FALSE
 * keepalive: FALSE
 * linger: FALSE
 * OOB-inline:  FALSE
 * sndbuf: <system default>
 * rcvbuf: <system default>
 * authentication_mode: GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE
 * authorization_mode: GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE
 * channel_mode: GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR
 * delegation_mode: GLOBUS_IO_SECURE_DELEGATION_MODE_NONE
 * credential: GSS_C_NO_CREDENTIAL
 * authorized_identity: NULL
 * auth_callback: NULL
 * auth_callback_arg: NULL
 * @endcode
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The attr was GLOBUS_NULL.
 *
 * @see globus_io_tcpattr_destroy()
 * @ingroup attr
 */
globus_result_t
globus_io_tcpattr_init(
    globus_io_attr_t *			attr)
{
    static char *			myname="globus_io_tcpattr_init";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    attr->attr = globus_i_io_tcpattr_construct();

    /*
     *  NETLOGGER
     */
    attr->nl_handle = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}
/* globus_tcpattr_init() */

/**
 * Destroy a previously allocated TCP attribute structure.
 *
 * All memory allocated upon creation of the attribute structure is
 * freed. The attribute is no longer usable in any Globus I/O TCP
 * connection establishment functions.
 *
 * @param attr The attribute structure to destroy.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The attr parameter was equal to GLOBUS_NULL.
 *
 * @see globus_io_tcpattr_init()
 * @ingroup tcp
 */
globus_result_t
globus_io_tcpattr_destroy(
    globus_io_attr_t *			attr)
{
    static char *			myname="globus_io_tcpattr_destroy";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    globus_object_free(attr->attr);
    attr->attr = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}
/* globus_io_tcpattr_destroy() */
/* @} */

/**
 * Convert a POSIX-style socket file descriptor to a Globus I/O handle.
 *
 * @param socket The socket descriptor to be used with Globus I/O. The
 * socket descriptor should not be used once this function
 * returns. 
 * @param attributes The attributes which will be applied to the socket when
 * possible. Not all attributes can be applied to a socket after it has been
 * connected.
 * @param handle The new handle which can be used to refer to this socket
 * connection. All subsequent I/O on this socket should be done using
 * the Globus I/O interface with this handle.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL.
 *
 * @bug The "attributes" parameter is currently ignored.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_posix_convert(
    int					socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle)
{
    globus_callback_space_t             space;
    static char *			myname="globus_io_tcp_posix_convert";

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "handle",
	        3,
	        myname));
    }
    globus_i_io_initialize_handle(handle,
                                  GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    handle->fd = socket;
    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    if(attributes)
    {
        globus_io_attr_get_callback_space(attributes, &space);
    }
    else
    {
        space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    }
    
    globus_callback_space_reference(space);
    globus_i_io_set_callback_space(handle, space);
    
    return GLOBUS_SUCCESS;
}
/* globus_io_tcp_posix_convert() */

/**
 * Convert a POSIX-style socket file descriptor to a Globus I/O handle.
 *
 * @param socket
 *        The socket descriptor to be used with Globus I/O. The
 *        socket descriptor should not be used once this function
 *        returns. 
 * @param attributes
 *        The attributes which will be applied to the socket when possible. Not
 *        all attributes can be applied to a socket after it has been
 *        connected.
 * @param handle
 *        The new handle which can be used to refer to this socket listener.
 *        All subsequent I/O on this socket should be done using the Globus I/O
 *        interface with this handle.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL.
 *
 * @bug The "attributes" parameter is currently ignored.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_posix_convert_listener(
    int					socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle)
{
    globus_callback_space_t             space;
    static char *			myname="globus_io_tcp_posix_convert_listener";

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "handle",
	        3,
	        myname));
    }
    globus_i_io_initialize_handle(handle,
                                  GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    handle->fd = socket;
    handle->state = GLOBUS_IO_HANDLE_STATE_LISTENING;
    if(attributes)
    {
        globus_io_attr_get_callback_space(attributes, &space);
    }
    else
    {
        space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    }
    
    globus_callback_space_reference(space);
    globus_i_io_set_callback_space(handle, space);
    
    return GLOBUS_SUCCESS;
}
/* globus_io_tcp_posix_convert_listener() */

/**
 * Asynchronous wait until a client connection is pending.
 *
 * This function will issue a callback when the Globus I/O handle
 * has a connection pending. Calls to this function or globus_io_tcp_listen()
 * must be made before each call to globus_io_tcp_accept()
 * or globus_io_tcp_register_accept().
 *
 * @param handle The listener handle which will be monitored.
 * @param callback The function to be called when a connection is
 * pending.
 * @param callback_arg A user-supplied parameter to this function.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle or callback was equal to GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle already has a close pending, so this function cannot be
 * procesed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle was not initialized.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The handle was not a TCP listener handle.
 *
 * @see globus_io_tcp_listen() globus_io_tcp_register_accept(),
 * @see globus_io_tcp_accept()
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_register_listen(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback,
    void *				callback_arg)
{
    return globus_io_register_listen(handle, callback, callback_arg);
}
/* globus_io_tcp_register_listen() */

/**
 * Block until a client connection is pending.
 *
 * This function will block until a client connection is pending on
 * the listener handle. Once this function returns, the user
 * application can call globus_io_tcp_register_accept() or 
 * globus_io_tcp_accept() to create a newly connected handle.
 *
 * Calls to this function or globus_io_tcp_register_listen() must be
 * made before each call to globus_io_tcp_accept() or
 * globus_io_tcp_register_accept().
 *
 * @param handle The listener handle which will be monitored.
 * @param callback_arg A user-supplied parameter to this function.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_CLOSE_ALREADY_REGISTERED
 * The handle already has a close pending, so this function cannot be
 * procesed.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle was not initialized.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The handle was not a TCP listener handle.
 *
 * @see globus_io_tcp_listen() globus_io_tcp_register_accept(),
 * @see globus_io_tcp_accept()
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_listen(
    globus_io_handle_t *		handle)
{
    return globus_io_listen(handle);
}
/* globus_io_tcp_listen() */


/**
 * Get the IP address associated with a connected TCP socket.
 *
 * This function will return, in the passed parameters, the IP address
 * of the socket associated with this handle. The handle must be
 * already connected, or an error will be returned.
 *
 * @param handle
 *        The TCP connection handle.
 * @param host
 *        The host value must be a pointer to a location of memory
 *        large enought to hold four integers. The first four integers
 *	  pointed to by host will be replaced with the integer values
 *        of the address in network byte order.
 * @param port
 *        The port number of the connection will be returned in the
 *        value pointed to by port.
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, host, or port was equal to GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The handle was not a connected TCP handle.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * A system call failed while processing this command.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_get_local_address(
    globus_io_handle_t *		handle,
    int *				host,
    unsigned short *			port)
{
    struct sockaddr_in			my_addr;
    globus_netlen_t			len = sizeof(struct sockaddr_in);
    static char *
	myname="globus_io_tcp_get_address";
    globus_object_t *			err = GLOBUS_NULL;

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "handle",
	        1,
	        myname));
    }
    else if(host == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "host",
	        2,
	        myname));
    }
    else if(port == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "port",
	        3,
	        myname));
    }
    globus_i_io_mutex_lock();
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED &&
        handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED");

	goto error_exit;
    }
#ifndef TARGET_ARCH_WIN32
    if(getsockname(handle->fd,
		   (struct sockaddr *) & my_addr,
		   &len) < 0)
    {
		int save_errno;
#else
    if(getsockname( (SOCKET)handle->io_handle,
		   (struct sockaddr *) & my_addr,
		   &len) == SOCKET_ERROR )
    {
		int save_errno;
		globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32*/

        save_errno = errno;

        err = globus_io_error_construct_system_failure(
                  GLOBUS_IO_MODULE,
	          GLOBUS_NULL,
	          handle,
		  save_errno);

	goto error_exit;    
    }

    host[0] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[0]);
    host[1] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[1]);
    host[2] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[2]);
    host[3] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[3]);
    *port = (unsigned short) ntohs(my_addr.sin_port);

    globus_i_io_mutex_unlock();
    return GLOBUS_SUCCESS;

error_exit:
    globus_i_io_mutex_unlock();
    return globus_error_put(err);
}
/* globus_io_tcp_get_local_address() */

/**
 * Get the IP address associated with the peer of a connected TCP socket.
 *
 * This function will return, in the passed parameters, the IP address
 * of the peer of the socket associated with this handle. The handle must be
 * already connected, or an error will be returned.
 *
 * @param handle
 *        The TCP connection handle.
 * @param host
 *        The host value must be a pointer to a location of memory
 *        large enought to hold four integers. The first four integers
 *	  pointed to by host will be replaced with the integer values
 *        of the address in network byte order.
 * @param port
 *        The port number of the connection will be returned in the
 *        value pointed to by port.
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle, host, or port was equal to GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The handle was not a connected TCP handle.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * A system call failed while processing this command.
 * @ingroup tcp
 */
globus_result_t
globus_io_tcp_get_remote_address(
    globus_io_handle_t *		handle,
    int *				host,
    unsigned short *			port)
{
    struct sockaddr_in			my_addr;
    globus_netlen_t			len = sizeof(struct sockaddr_in);
    static char *
	myname="globus_io_tcp_get_remote_address";
    globus_object_t *			err = GLOBUS_NULL;

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "handle",
	        1,
	        myname));
    }
    else if(host == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "host",
	        2,
	        myname));
    }
    else if(port == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "port",
	        3,
	        myname));
    }
    globus_i_io_mutex_lock();
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED");

	goto error_exit;
    }
#ifndef TARGET_ARCH_WIN32
    if(getpeername(handle->fd,
		   (struct sockaddr *) & my_addr,
		   &len) < 0)
    {
	int save_errno;
#else
    if(getpeername( (SOCKET)handle->io_handle,
		   (struct sockaddr *) & my_addr,
		   &len) == SOCKET_ERROR )
    {
		int save_errno;
		globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32 */

        save_errno = errno;

        err = globus_io_error_construct_system_failure(
                  GLOBUS_IO_MODULE,
	          GLOBUS_NULL,
	          handle,
		  save_errno);

	goto error_exit;    
    }

    host[0] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[0]);
    host[1] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[1]);
    host[2] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[2]);
    host[3] = (int) (((unsigned char * ) &my_addr.sin_addr.s_addr)[3]);
    *port = (unsigned short) ntohs(my_addr.sin_port);

    globus_i_io_mutex_unlock();
    return GLOBUS_SUCCESS;

error_exit:
    globus_i_io_mutex_unlock();
    return globus_error_put(err);
}
/* globus_io_tcp_get_remote_address() */

/*
 * Module Specific Functions
 */
/*
 * Function:	globus_l_io_tcp_create_socket()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
static
globus_result_t
globus_l_io_tcp_create_socket(
    globus_io_handle_t *		handle)
{
    globus_result_t			rc;
    int					save_errno;
    globus_object_t *			err;
    static char *			myname="globus_i_io_tcp_create_socket";
    
    globus_i_io_debug_printf(3,
			     (stderr, "%s(): entering\n",
			      myname));

    globus_assert(handle != GLOBUS_NULL);
    
    handle->context = GSS_C_NO_CONTEXT;

#ifndef TARGET_ARCH_WIN32
    if((handle->fd = socket(AF_INET,
			    SOCK_STREAM,
			    0)) < 0)
    {
#else
    if( (SOCKET)( handle->io_handle = (HANDLE)socket( AF_INET,
	 SOCK_STREAM, 0 ) ) == INVALID_SOCKET )
    {
		globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32 */
	save_errno = errno;

	err = globus_io_error_construct_system_failure(
	            GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    handle,
		    save_errno);
	
	goto error_exit;
    }

    rc = globus_l_io_setup_tcp_socket(handle);
    if(rc != GLOBUS_SUCCESS)
    {
	err = globus_error_get(rc);
	goto error_exit;
    }
    
#ifdef TARGET_ARCH_WIN32
	/* initialize the WinIoOperation structs */
	globus_i_io_windows_init_io_operations( handle );
	/* associate the socket with the completion port */
	if ( CreateIoCompletionPort( handle->io_handle,
		completionPort, (ULONG_PTR)handle, 0 ) == NULL )
		{
		err = globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				globus_i_io_windows_get_last_error() );
	
		goto error_exit;
	}
#endif
    return GLOBUS_SUCCESS;
    
  error_exit:
#ifndef TARGET_ARCH_WIN32
    if(handle->fd >= 0)
    {
	globus_libc_close(handle->fd);
    }
#else
    if( (SOCKET)handle->io_handle != INVALID_SOCKET )
		globus_i_io_windows_close( handle );
#endif /* TARGET_ARCH_WIN32 */

    return globus_error_put(err);
}
/* globus_l_io_tcp_create_socket() */


/*
 * Function:	globus_l_io_tcp_handle_destroy()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */ 
static
void
globus_l_io_tcp_handle_destroy(
    globus_io_handle_t *		handle)
{
}
/* globus_l_io_tcp_handle_destroy() */

/*
 * Function:	globus_l_io_setup_tcp_socket()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */ 
static
globus_result_t
globus_l_io_setup_tcp_socket(
    globus_io_handle_t *		handle)
{
    globus_result_t			rc;
    int					one = 1;
    int					save_errno;
    globus_object_t *			err;
    
    rc = globus_i_io_setup_securesocket(handle);

    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    else
    {
	if(handle->tcp_attr.nodelay)
	{
#ifndef TARGET_ARCH_WIN32
	    if(setsockopt(handle->fd,
			  IPPROTO_TCP,
			  TCP_NODELAY,
			  (char *) &one,
			  sizeof(one)) < 0)
	    {
#else
			if(setsockopt( (SOCKET)handle->io_handle,
				IPPROTO_TCP,
				TCP_NODELAY,
				(char *) &one,
				sizeof(one)) == SOCKET_ERROR )
			{
				globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32 */
		save_errno = errno;
		goto error_exit;
	    }
	}

#       ifdef HAVE_TCP_FASTACK
	{
	    /* If using a socket one-way only, there are potential
	     * problems on IRIX 6.5; occasionally an ACK to a probing
	     * packet will not left unanswered or dropped, resulting
	     * in a reset of the TCP window and a 5-second timeout.
	     *
	     * While investigating the nature of the bug, SGI have
	     * provided a workaround; Setting the IRIX-specific
	     * TCP_FASTACK will result in a much shorter timeout
	     * instead of a 5-second timeout. We can live with that
	     * for the time being.
	     */
	
	    int     fastack_arg;
	    char *  fastack_str = globus_libc_getenv("GLOBUS_IO_TCP_FASTACK");
	    
	    if (fastack_str)
	    {
		fastack_arg = atoi(fastack_str);
		if (fastack_arg < 0) fastack_arg = 0;
		
#ifndef TARGET_ARCH_WIN32
		if(setsockopt(handle->fd,
			      IPPROTO_TCP,
			      TCP_FASTACK,
			      &fastack_arg,
			      sizeof(fastack_arg)) < 0)
		{
#else
				if(setsockopt(handle->io_handle,
						IPPROTO_TCP,
						TCP_FASTACK,
						&fastack_arg,
						sizeof(fastack_arg)) == SOCKET_ERROR )
				{
					globus_i_io_winsock_get_last_error();
#endif /* TARGET_ARCH_WIN32 */
		    save_errno = errno;               
		    goto error_exit;
		}
	    }
	}
#       endif /* HAVE_TCP_FASTACK */
    }
    return GLOBUS_SUCCESS;
    
  error_exit:
    err = globus_io_error_construct_system_failure(
	GLOBUS_IO_MODULE,
	GLOBUS_NULL,
	handle,
	save_errno);    

    return globus_error_put(err);
}
/* globus_l_io_setup_tcp_socket() */

static
globus_object_t *
globus_l_io_tcp_bind_socket(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr,
    unsigned short *			port)
{
    unsigned short  			myport;
    unsigned short  			end_port;
    globus_bool_t                       found_port = GLOBUS_FALSE;
    globus_bool_t                       bind_error = GLOBUS_FALSE;
    struct sockaddr_in			my_addr;
    int					save_errno;
    globus_i_io_tcpattr_instance_t *    instance;
    globus_netlen_t			len = sizeof(my_addr);

    instance = (globus_i_io_tcpattr_instance_t *) &handle->tcp_attr;

    myport = *port;
    handle->type = GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER;
    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    
    memset(&my_addr, '\0', len);

    if(myport == 0)
    {
        if(globus_i_io_tcp_used_port_table != GLOBUS_NULL &&
	   instance->restrict_port)
        {
	    myport = globus_i_io_tcp_used_port_min;
	    end_port = globus_i_io_tcp_used_port_max;
        }
    }
    else
    {
       end_port = myport;
    }

    do
    {
	found_port = GLOBUS_FALSE;
        if(!strcmp(instance->interface_addr, "000.000.000.000"))
        {
            my_addr.sin_addr.s_addr = INADDR_ANY;
        }
        else
        {
	    my_addr.sin_addr.s_addr = inet_addr(&instance->interface_addr[0]);
	}
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(myport);

#ifndef TARGET_ARCH_WIN32
        if(bind(handle->fd,
	    (struct sockaddr *)&my_addr,
	    len) >= 0)
        {
            found_port = GLOBUS_TRUE;
        }
        else
        {
#else
		if( bind( (SOCKET)handle->io_handle, 
		 (struct sockaddr *)&my_addr, len ) == 0 )
        {
            found_port = GLOBUS_TRUE;
        }
        else
        {
			globus_i_io_winsock_get_last_error();
#endif
            (myport)++;

	    if(myport > end_port)
	    {
                bind_error = GLOBUS_TRUE;
	    }
	}
    } while(!found_port && !bind_error);

    if(bind_error)
    {
  	    save_errno = errno;

	    return globus_io_error_construct_system_failure(
	             GLOBUS_IO_MODULE,
		     GLOBUS_NULL,
		     handle,
		     save_errno);
    }
    return GLOBUS_SUCCESS;
}


/* globus_io_get_credential and globus_io_get_credential routines below were */
/* added for backward compatibility With XIO  - 2/26/04 rcg */

/* globus_io_tcp_get_credential() */
globus_result_t
globus_io_tcp_get_credential(
    globus_io_handle_t *    handle,
    gss_cred_id_t *         cred)
{
   globus_object_t *        err;
   static char *            myname="globus_io_tcp_get_credential";

    if(handle == GLOBUS_NULL)
    {
    return globus_error_put(
        globus_io_error_construct_null_parameter(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        "handle",
        1,
        myname));
    }
    if(cred == GLOBUS_NULL)
    {
    return globus_error_put(
        globus_io_error_construct_null_parameter(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        "cred",
        2,
        myname));
    }
    globus_i_io_mutex_lock();
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED)
    {
    err = globus_io_error_construct_invalid_type(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        "handle",
        1,
        myname,
        "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED");

    goto error_exit;
    }

    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CONNECTED:
    break;
      default:
    err = globus_io_error_construct_not_initialized(
       GLOBUS_IO_MODULE,
       GLOBUS_NULL,
       "handle",
       1,
       myname);
    goto error_exit;
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        *cred = GSS_C_NO_CREDENTIAL;
    }
    else
    {
        *cred = handle->delegated_credential;
    }

    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_tcp_get_credential() */


/* globus_io_tcp_set_credential() */
globus_result_t
globus_io_tcp_set_credential(
    globus_io_handle_t *    handle,
    gss_cred_id_t           cred)
{
   globus_object_t *        err;
   static char *            myname="globus_io_tcp_set_credential";

    if(handle == GLOBUS_NULL)
    {
    return globus_error_put(
        globus_io_error_construct_null_parameter(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        "handle",
        1,
        myname));
    }
    if(cred == GLOBUS_NULL)
    {
    return globus_error_put(
        globus_io_error_construct_null_parameter(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        "cred",
        2,
        myname));
    }
    globus_i_io_mutex_lock();
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED)
    {
    err = globus_io_error_construct_invalid_type(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        "handle",
        1,
        myname,
        "GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED");

    goto error_exit;
    }

    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_CONNECTED:
    break;
      default:
    err = globus_io_error_construct_not_initialized(
       GLOBUS_IO_MODULE,
       GLOBUS_NULL,
       "handle",
       1,
       myname);
    goto error_exit;
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        handle->delegated_credential = GSS_C_NO_CREDENTIAL;
    }
    else
    {
        handle->delegated_credential = cred;
    }

    globus_i_io_mutex_unlock();

    return GLOBUS_SUCCESS;

  error_exit:
    globus_i_io_mutex_unlock();

    return globus_error_put(err);
}
/* globus_io_tcp_set_credential() */
