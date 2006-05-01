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

/* This File Doesn't Build Under Windows */
#ifndef WIN32

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_io_udp.c Globus I/O toolset for UDP/IP sockets.
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */

/**
 * RCS Identification for this source file.
static char *rcsid = "$Header$";
 */
#endif

/**
 * @defgroup udp UDP Sockets
 *
 * UDP Sockets
 *
 * The API functions in this section provide services for creating
 * UDP sockets, and sending and receiving UDP messages.
 */


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
#   include "globus_l_io.h"
#   include <assert.h>
#else
#   include "globus_io.h"
#endif

/* one of the things I don't like about UNIX */
#if defined(EACCES) && !defined(EACCESS)
#   define EACCESS EACCES
#endif

/* overloads globus_i_io_monitor_t */
typedef struct globus_i_io_udp_monitor_s
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_object_t *                   err;
    globus_bool_t                       use_err;
    globus_bool_t                       done;
    globus_size_t                       nbytes;

    char *                              host;
    unsigned short                      port;
    char **                             out_host;
    unsigned short *                    out_port;
    globus_size_t *                     out_nbytes;
} globus_i_io_udp_monitor_t;


typedef struct globus_l_io_udp_info_s
{
    globus_io_handle_t *                handle;
    globus_byte_t *                     buf;
    globus_size_t                       nbytes;
    globus_io_udp_recvfrom_callback_t   recv_callback;
    globus_io_udp_recvfromv_callback_t  recv_callbackv;
    globus_io_udp_sendto_callback_t     send_cb;
    globus_io_udp_sendvto_callback_t    sendv_cb;
    struct iovec *                      iovec;
    int                                 iovec_count;
    int                                 flags;
    void *                              user_callback_arg;
    struct sockaddr_in                  addr;
} globus_l_io_udp_info_t;

static
globus_result_t
globus_l_io_udp_create_socket(
    globus_io_handle_t *		handle);

static
globus_result_t
globus_l_io_setup_udp_socket(
    globus_io_handle_t *                 handle,
    globus_i_io_udpattr_instance_t *     udp_attr);

static
void globus_l_io_udp_recvfrom_callback(
     void *                           arg,
     globus_io_handle_t *             handle,
     globus_result_t                  result);

static void
globus_l_io_udp_recvfrom_monitor_callback(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes_recvd,
    const char *                        host,
    unsigned short                      port);

/*
 * Module Specific Prototypes
 */

/*
 * API Functions
 */
#ifndef SO_REUSEPORT
#   define SO_REUSEPORT SO_REUSEADDR
#endif

#define MAX_SOCKET_SEND_BUFFER          9000
#define MAX_SOCKET_RECEIVE_BUFFER       18032


/*************************************************************************
 *                      internal functions
 *                      ------------------
 ************************************************************************/
static void
globus_l_io_udp_sendto_callback(
     void *                             arg,
     globus_io_handle_t *               handle,
     globus_result_t                    result)
{
    globus_l_io_udp_info_t *            send_info;
    globus_size_t                       nbytes;
    struct msghdr                       msg;

    send_info = (globus_l_io_udp_info_t *) arg;
    globus_assert(send_info != GLOBUS_NULL);

    send_info = (globus_l_io_udp_info_t *) arg;

    if(result == GLOBUS_SUCCESS)
    {
        if(send_info->buf != NULL)
        {
            nbytes = sendto(
                handle->fd,
                send_info->buf,
                send_info->nbytes,
                send_info->flags,
	            (struct sockaddr*)&send_info->addr,
	            sizeof(send_info->addr));
        }
        else if(send_info->iovec != NULL)
		{
            memset(&msg, '\0', sizeof(msg));
            msg.msg_name = (void *) &send_info->addr;
            msg.msg_namelen = sizeof(send_info->addr);
            msg.msg_iov = send_info->iovec;
            msg.msg_iovlen = send_info->iovec_count;
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
            msg.msg_flags = 0; /* out param */
                                                                                
            nbytes = sendmsg(
                handle->fd,
                &msg,
                send_info->flags);
        }	
        else
		{
            globus_assert(0);
        }	

        if(nbytes < 0)
        {
            result =  globus_error_put(
			     globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
			            errno));
        }
    }

    if(send_info->send_cb != NULL)
    {
        send_info->send_cb(
            send_info->user_callback_arg,
    		handle,
			result,
			send_info->buf,
            nbytes);
    }
    else if(send_info->sendv_cb != NULL)
    {
        send_info->sendv_cb(
            send_info->user_callback_arg,
    		handle,
			result,
            send_info->iovec,
            send_info->iovec_count);
    }

    globus_free(send_info);
}

static void
globus_l_io_udp_recvfrom_callback(
     void *                           arg,
     globus_io_handle_t *             handle,
     globus_result_t                  result)
{
    globus_l_io_udp_info_t *        recvfrom_arg;
    int                             bytes_received;
    struct sockaddr_in              from_addr;
    GLOBUS_SOCK_SIZE_T              from_len;
    char *                          from_host;
    unsigned short                  from_port;
    struct msghdr                   msg;

    recvfrom_arg = (globus_l_io_udp_info_t *) arg;
    globus_assert(recvfrom_arg != GLOBUS_NULL);

    if(result == GLOBUS_SUCCESS)
    {
        if(recvfrom_arg->buf != NULL)
        {
            from_len = sizeof(from_addr);

            bytes_received = recvfrom( 
                handle->fd,
                (char *)recvfrom_arg->buf,
                recvfrom_arg->nbytes,
                recvfrom_arg->flags,
                (struct sockaddr *)&from_addr,
                &from_len);
        }
        else if(recvfrom_arg->iovec != NULL)
		{
            msg.msg_name = (void *) &from_addr;
            msg.msg_namelen = sizeof(from_addr);
            msg.msg_iov = recvfrom_arg->iovec;
            msg.msg_iovlen = recvfrom_arg->iovec_count;
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
            msg.msg_flags = 0; /* out param */

            bytes_received = recvmsg(
                handle->fd,
                &msg,
                recvfrom_arg->flags);
        }	
        else
		{
            globus_assert(0);
        }	

        if(bytes_received < 0)
        {
            result =  globus_error_put(
			     globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
			            errno));
        }
        else
        {
           from_port = (unsigned short) ntohs(from_addr.sin_port);
           from_host = 
                globus_libc_strdup((char *)inet_ntoa(from_addr.sin_addr));
        }
    }

    /* get source host anf port */
    recvfrom_arg = (globus_l_io_udp_info_t *) arg;
    if(recvfrom_arg->recv_callback)
    {
        recvfrom_arg->recv_callback(recvfrom_arg->user_callback_arg,
    		           handle,
			           result,
			           recvfrom_arg->buf,
                       bytes_received,
			           from_host,
			           from_port);
    }
    else if(recvfrom_arg->recv_callbackv)
    {
        recvfrom_arg->recv_callbackv(
            recvfrom_arg->user_callback_arg,
            handle,
            result,
            recvfrom_arg->iovec,
            recvfrom_arg->iovec_count,
            bytes_received,
            from_host,
            from_port);
    }

    globus_free(recvfrom_arg); 
}

static globus_result_t
globus_l_io_udp_set_socket_size(
    globus_io_handle_t *                        handle)
{
    int size;
    int sock_size;
    GLOBUS_SOCK_SIZE_T sock_opt_len = sizeof(GLOBUS_SOCK_SIZE_T);
    int save_error;

    size = MAX_SOCKET_SEND_BUFFER;
    if(setsockopt(handle->fd, 
		  SOL_SOCKET, 
		  SO_SNDBUF, 
		  (char *) &size, 
		  sizeof(int)) < 0)
    {
          return globus_error_put(globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
    }

    if (getsockopt(handle->fd, 
		   SOL_SOCKET, 
		   SO_SNDBUF, 
		   (char *) &sock_size,
                   &sock_opt_len) < 0)
    {
        save_error = errno;
        sock_size = -1;
    }

    size = MAX_SOCKET_RECEIVE_BUFFER;

    if(setsockopt(handle->fd, 
	       SOL_SOCKET, 
	       SO_RCVBUF, 
	       (char *) &size, 
	       sizeof(int)) < 0)
    {
          return globus_error_put(globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));

    }

    if (getsockopt(handle->fd, 
		   SOL_SOCKET, 
		   SO_RCVBUF, 
		   (char *) &sock_size,
		    &sock_opt_len) < 0 ) 
    {
        return globus_error_put(globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
    }

    globus_i_io_setup_nonblocking(handle);

    return GLOBUS_SUCCESS;
}


void
globus_l_io_udp_recvfrom_monitor_callback(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes_recvd,
    const char *                        host,
    unsigned short                      port)
{
    globus_i_io_udp_monitor_t *         monitor;

    monitor = (globus_i_io_udp_monitor_t *) arg;

    *(monitor->out_port) = port;
    *(monitor->out_host) = (char *)host;
    *(monitor->out_nbytes) = nbytes_recvd;

    globus_i_io_monitor_callback(arg,
				 handle,
				 result);
}

void
globus_l_io_udp_recvfromv_monitor_callback(
    void *                                  arg,
    globus_io_handle_t *                    handle,
    globus_result_t                         result,
    struct iovec *                          iov,
    int                                     iovc,
    globus_size_t                           nbytes_recvd,
    const char *                            host,
    unsigned short                          port)
{
    globus_i_io_udp_monitor_t *             monitor;

    monitor = (globus_i_io_udp_monitor_t *) arg;

    *(monitor->out_port) = port;
    *(monitor->out_host) = (char *)host;
    *(monitor->out_nbytes) = nbytes_recvd;

    globus_i_io_monitor_callback(arg,
				 handle,
				 result);
}

void
globus_l_io_udp_sendto_monitor_callback(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes)
{
    globus_i_io_udp_monitor_t *         monitor;

    monitor = (globus_i_io_udp_monitor_t *) arg;

    *(monitor->out_nbytes) = nbytes;

    globus_i_io_monitor_callback(arg,
				 handle,
				 result);
}

void
globus_l_io_udp_sendvto_monitor_callback(
    void *                                  arg,
    globus_io_handle_t *                    handle,
    globus_result_t                         result,
    struct iovec *                          iov,
    int                                     iovc)
{
    globus_i_io_udp_monitor_t *             monitor;

    monitor = (globus_i_io_udp_monitor_t *) arg;

    globus_i_io_monitor_callback(arg,
				 handle,
				 result);
}

/*
 * Function:	globus_l_io_udp_create_socket()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
static
globus_result_t
globus_l_io_udp_create_socket(
    globus_io_handle_t *		handle)
{
    static char *                       myname="globus_i_io_udp_create_socket";
    int					save_errno;
    globus_object_t *			err;

    globus_i_io_debug_printf(3,
			     (stderr, "%s(): entering\n",
  			     myname));

    globus_assert(handle != GLOBUS_NULL);
    
    handle->context = GSS_C_NO_CONTEXT;

    /*
     * Create datagram socket
     */
    if((handle->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
	save_errno = errno;

	err = globus_io_error_construct_system_failure(
	            GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    handle,
		    save_errno);
	
	goto error_exit;
    }
    
    return GLOBUS_SUCCESS;
  
  error_exit:
    if(handle->fd >= 0)
    {
	globus_libc_close(handle->fd);
    }
    return globus_error_put(err);
}
/* globus_l_io_udp_create_socket() */

/*
 * Function:    globus_l_io_setup_udp_socket()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
static
globus_result_t
globus_l_io_setup_udp_socket(
    globus_io_handle_t *                 handle,
    globus_i_io_udpattr_instance_t *    udp_attr)
{
    globus_result_t                     rc;
    struct ip_mreq                      imr;

    rc = globus_i_io_setup_securesocket(handle);
    
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    if(udp_attr->mc_enabled)
    {
	if(udp_attr->reuse)
	{
	    int                         so_reuse = 1;

            if (setsockopt(handle->fd, 
			   SOL_SOCKET, 
			   SO_REUSEPORT,
			   (char *) &so_reuse, 
			   sizeof(so_reuse)) == -1)
            {
                return globus_error_put(
			     globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
	    }
	}

        if (setsockopt(handle->fd, 
		       IPPROTO_IP, 
		       IP_MULTICAST_TTL,
		       &(udp_attr->mc_ttl), 
		       sizeof(udp_attr->mc_ttl)) < 0)
        {
            return globus_error_put(
		     globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
        } 

        if (setsockopt(handle->fd, 
 	           IPPROTO_IP, 
	           IP_MULTICAST_LOOP,
	           &(udp_attr->mc_loop), 
	           sizeof(udp_attr->mc_loop)) == -1)
        {
            return globus_error_put(
	              globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
        }

        imr.imr_multiaddr.s_addr = inet_addr(udp_attr->address);
        if (((int) imr.imr_multiaddr.s_addr) == -1)
        {
            return globus_error_put(
	              globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
	}

        imr.imr_interface.s_addr = (unsigned long)udp_attr->interface_addr;
	if(setsockopt(handle->fd, 
		      IPPROTO_IP, 
		      IP_ADD_MEMBERSHIP,
                      (char *) &imr, 
		      sizeof(struct ip_mreq)) == -1)
        {
            return globus_error_put(
		     globus_io_error_construct_system_failure(
					    GLOBUS_IO_MODULE,
					    GLOBUS_NULL,
					    handle,
				            errno));
        }
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_io_setup_udp_socket() */

/*************************************************************************
 *                          user functions
 *                          --------------
 ************************************************************************/

/**
 *  Set an attr on a bound udp handle
 *
 *  This function is not thread safe.
 *
 *  @param handle
 *         The bound udp handle the user wishes to alter.
 *  @param attr
 *         The attribute structure containing the value changes.
 *
 *  @ingroup udp
 */
globus_result_t
globus_io_udp_set_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr)
{
    globus_i_io_udpattr_instance_t *    udp_attr;
    static char *			myname="globus_io_udp_set_attr";
    
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
    if(globus_object_get_type(attr->attr) != GLOBUS_IO_OBJECT_TYPE_UDPATTR)
    {
	return globus_error_put(
	    globus_io_error_construct_invalid_type(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		2,
		myname,
		"GLOBUS_IO_OBJECT_TYPE_UDPATTR"));
    }
    
    /* set local socket options */
    udp_attr = (globus_i_io_udpattr_instance_t *)
			     globus_object_get_local_instance_data(attr->attr);

    globus_l_io_setup_udp_socket(handle, udp_attr);
    
    return GLOBUS_SUCCESS;
}
/* globus_io_udp_set_attr() */

/**
 * @name UDP Attributes
 */
/* @{ */
/**
 * Initialize a UDP attribute structure.
 *
 * @param attr Attribute to initialize.
 *
 * <b>Default UDP Attributes:</b>
 * @code
 * restrict_port: TRUE
 * reuseaddr: FALSE
 * keepalive: FALSE
 * linger: FALSE
 * OOB-inline: FALSE
 * sndbuf: system default
 * rcvbuf: system default
 * multicast_loop: FALSE
 * multicast_ttl: 1
 * multicast_enabled: FALSE
 * address: NULL
 * interface: INADDR_ANY
 * @endcode
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The attr was GLOBUS_NULL.
 *
 * @see globus_io_udpattr_destroy()
 * @ingroup udp
 */
globus_result_t
globus_io_udpattr_init(
    globus_io_attr_t *			attr)
{
    static char *			myname="globus_io_udpattr_init";

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
    
    attr->attr = globus_i_io_udpattr_construct();

    /*
     *  NETLOGGER
     */
    attr->nl_handle = GLOBUS_NULL;
    
    return GLOBUS_SUCCESS;
}
/* globus_udpattr_init() */

/**
 * Destroy a previously allocated UDP attribute structure.
 *
 * All memory allocated upon creation of the attribute structure is
 * freed. The attribute is no longer usable in any Globus I/O UDP
 * handle creation functions.
 *
 * @param attr The attribute structure to destroy.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The attr parameter was equal to GLOBUS_NULL.
 *
 * @see globus_io_udpattr_init()
 * @ingroup udp
 */
globus_result_t
globus_io_udpattr_destroy(
    globus_io_attr_t *			attr)
{
    static char *			myname="globus_io_udpattr_destroy";

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
/* globus_io_udpattr_destroy() */
/* @} */

/*
 * Module Specific Functions
 */

/**
 *  Initialize a globus io udp handle and bind it to the provided local port.
 *  If the port is NULL or 0 a port number will be assigned by the system.
 *
 *  @param port
 *         The local port to which the handle will be bound.  If NULL is 
 *         passed or *port is 0 the system will assign a port.  Otherwise
 *         the system will attempt to use the provided port.
 *
 *  @param attr
 *         An attribute structure used to alter the default values of the 
 *         handle.
 *
 *  @param handle
 *         I handle structure to be intialized.
 *
 *  @ingroup udp
 */
globus_result_t
globus_io_udp_bind(
    unsigned short *                  port,
    globus_io_attr_t *                attr,
    globus_io_handle_t *              handle)
{
    struct sockaddr_in                  my_addr;
    static char *                       myname = "globus_io_udp_bind";
    unsigned short                      myport = 0;
    globus_result_t                     rc;
    globus_i_io_udpattr_instance_t *    udp_attr;
    globus_bool_t                       found_port = GLOBUS_FALSE;
    globus_bool_t                       bind_error = GLOBUS_FALSE;
    GLOBUS_SOCK_SIZE_T                  len;
    unsigned short                      end_port;
    globus_io_attr_t                    tmp_attr;

    /* 
     *  Test parameters for errors
     */
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

    rc = globus_i_io_initialize_handle(handle,
				       GLOBUS_IO_HANDLE_TYPE_UDP_UNCONNECTED);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    rc = globus_i_io_copy_udpattr_to_handle(attr, 
					    handle);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    /* create the udp socket and set options */
    rc = globus_l_io_udp_create_socket(handle);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    /* if user isn't interested in port leave as 0 */
    if(port != GLOBUS_NULL)
    {
        myport = *port;
    }

    /* 
     * if port is zero figure out a port number
     *  TODO : this
     */
    if(attr == NULL)
    {
        globus_io_udpattr_init(&tmp_attr);
        udp_attr = (globus_i_io_udpattr_instance_t *)
			globus_object_get_local_instance_data(tmp_attr.attr);
        globus_io_udpattr_destroy(&tmp_attr);
    }
    else
    {
        udp_attr = (globus_i_io_udpattr_instance_t *)
            globus_object_get_local_instance_data(attr->attr);
    }

    rc = globus_l_io_setup_udp_socket(handle, udp_attr);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    if(myport == 0)
    {
	if(globus_i_io_tcp_used_port_table != GLOBUS_NULL && 
	   udp_attr->restrict_port)
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
        bzero((char*) &my_addr, sizeof(my_addr));
        my_addr.sin_family = AF_INET;
        my_addr.sin_addr.s_addr = htonl((unsigned long)udp_attr->interface_addr);
        my_addr.sin_port = htons(myport);

        if(bind(handle->fd,
            (struct sockaddr *)&my_addr,
            sizeof(my_addr)) >= 0)
	{
            found_port = GLOBUS_TRUE;
	}
        else
	{
            myport++;

            if(myport > end_port)
	    {
                bind_error = GLOBUS_TRUE;
	    }
	}
    } while(!found_port && !bind_error);

    if(bind_error)
    {
        return globus_error_put(
		    globus_io_error_construct_system_failure(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    handle,
	            errno));
    }
    len = sizeof(my_addr);
    if( (getsockname(handle->fd, (struct sockaddr *)&my_addr, &len)) < 0)
    {
        /* error stuff */	    
    }

    if(port != GLOBUS_NULL)
    {
        *port = (unsigned short) ntohs(my_addr.sin_port);
    }

    globus_l_io_udp_set_socket_size(handle); 

    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;

    globus_i_io_debug_printf(3,
			    (stderr, "%s(): exiting\n", myname));
    return rc;
}
/* globus_io_udp_bind() */

/* 'connect' a udp socket so regular globus io read/write/send can be used
 * Note:  all data received with recvfrom will be from this host
 * while (i believe) sendto can still be used to send to other hosts.
 * pass NULL to 'unconnect'
 */
globus_result_t
globus_io_udp_connect(
    globus_io_handle_t *                handle,
    char *                              host,
    unsigned short                      port)
{
    struct sockaddr_in                  addr;
    struct hostent *                    hp;
    int                                 hp_errnop;
    char                                hp_tsdbuffer[500];
    struct hostent                      he;
    int                                 rc;
    static char *                       myname="globus_io_udp_connect";

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
    
    memset(&addr, 0, sizeof(addr));
    if(host)
    {
        hp = globus_libc_gethostbyname_r(
                host,
                &he,
                hp_tsdbuffer,
                500,
                &hp_errnop);
        if(hp == GLOBUS_NULL)
        {
            return globus_error_put(
                globus_io_error_construct_system_failure(
    	            GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle,
                    errno));
        }
        
        addr.sin_family = hp->h_addrtype;
        memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
        addr.sin_port = htons(port);
    }
    else
    {
        addr.sin_family = AF_UNSPEC;
    }
    
    do
    {
        rc = connect(handle->fd, (struct sockaddr *) &addr, sizeof(addr));
    } while(rc < 0 && errno == EINTR);
    
    if(rc < 0)
    {
        return globus_error_put(
            globus_io_error_construct_system_failure(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                errno));
    }
    
    if(host)
    {
        handle->type = GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED;
    }
    else
    {
        handle->type = GLOBUS_IO_HANDLE_TYPE_UDP_UNCONNECTED;
    }
    
    return GLOBUS_SUCCESS;
}

/**
 *  Send a udp message to a remote socket using an iovec as input.
 *
 *  This function is used to send udp messages from the localhost to the
 *  remote host designated by the 'host' parameter.
 * 
 *  @param handle
 *         The handle used to send the message.
 *
 *  @param iov
 *         The message to be sent
 *
 *  @param iovc
 *         The number of entries in the iovec
 *
 *  @param flags
 *         MSG_OOB, MSG_DONTROUTE, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_CONFIRM
 *
 *  @param host
 *         The host to which the message will be sent.  Will be more 
 *         efficient if in the IP format.
 *
 *  @param port
 *         The remote port to which the message will be sent.
 *
 *  @param bytes_sent
 *         An out parameter.  Will contain the number of bytes sent when
 *         the function returns successfully.
 *  @ingroup udp
 */
globus_result_t
globus_io_udp_sendvto(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    int                                 iovc,
    int                                 flags,
    char *                              host,
    unsigned short                      port,
    globus_size_t *                     bytes_sent)
{
    globus_result_t                     result;
    globus_i_io_udp_monitor_t *         monitor;
    static char *                       myname="globus_io_udp_sendvto";

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
    if(iov == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iov",
                2,
                myname));
    }
    if(iovc < 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iovc",
                3,
                myname));
    }
    if(host == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "host",
                5,
                myname));
    }

    monitor = (globus_i_io_udp_monitor_t *) 
                   globus_malloc(sizeof(globus_i_io_udp_monitor_t));

    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->cond, GLOBUS_NULL);
    monitor->done = GLOBUS_FALSE;
    monitor->err = GLOBUS_NULL;
    monitor->use_err = GLOBUS_FALSE;
    monitor->port = port;
    monitor->host = host;
    monitor->out_nbytes = bytes_sent;
    
    handle->blocking_read = GLOBUS_TRUE;
    
    result = globus_io_udp_register_sendvto(
                handle,
                iov,
                iovc,
                flags,
                host,
                port,
                globus_l_io_udp_sendvto_monitor_callback,
                (void *)monitor);

    if(result != GLOBUS_SUCCESS)
    {
        monitor->done = GLOBUS_TRUE;
        monitor->err = globus_error_get(result);
        monitor->use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor->mutex);
    {
        while(!monitor->done)
        {
            globus_cond_wait(&monitor->cond, &monitor->mutex);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);
    if(monitor->use_err)
    {
        result = globus_error_put(monitor->err);
    }

    globus_free(monitor); 

    return result;

    return GLOBUS_SUCCESS;
}
/* globus_io_udp_sendto() */

/**
 *  Send a udp message to a remote socket.
 *
 *  This function is used to send udp messages from the localhost to the
 *  remote host designated by the 'host' parameter.
 * 
 *  @param handle
 *         The handle used to send the message.
 *
 *  @param buf
 *         The message to be sent
 *
 *  @param flags
 *         MSG_OOB, MSG_DONTROUTE, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_CONFIRM
 *
 *  @param host
 *         The host to which the message will be sent.  Will be more 
 *         efficient if in the IP format.
 *
 *  @param port
 *         The remote port to which the message will be sent.
 *
 *  @param bytes_sent
 *         An out parameter.  Will contain the number of bytes sent when
 *         the function returns successfully.
 *  @ingroup udp
 */
globus_result_t
globus_io_udp_sendto(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    int                                 flags,
    globus_size_t                       nbytes,
    char *                              host,
    unsigned short                      port,
    globus_size_t *                     nbytes_sent)
{
    globus_i_io_udp_monitor_t *         monitor;
    globus_result_t                     result;
    static char *                       myname="globus_io_udp_sendto";

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
    if(buf == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "buf",
                1,
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
    if(nbytes <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "nbytes",
                1,
                myname));
    }

    monitor = (globus_i_io_udp_monitor_t *) 
                   globus_malloc(sizeof(globus_i_io_udp_monitor_t));

    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->cond, GLOBUS_NULL);
    monitor->done = GLOBUS_FALSE;
    monitor->err = GLOBUS_NULL;
    monitor->use_err = GLOBUS_FALSE;
    monitor->port = port;
    monitor->host = host;
    monitor->out_nbytes = nbytes_sent;
    
    handle->blocking_read = GLOBUS_TRUE;
    
    result = globus_io_udp_register_sendto(
                handle,
                buf,
                flags,
                nbytes,
                host,
                port,
                globus_l_io_udp_sendto_monitor_callback,
                (void *)monitor);

    if(result != GLOBUS_SUCCESS)
    {
        monitor->done = GLOBUS_TRUE;
        monitor->err = globus_error_get(result);
        monitor->use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor->mutex);
    {
        while(!monitor->done)
        {
            globus_cond_wait(&monitor->cond, &monitor->mutex);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);
    if(monitor->use_err)
    {
        result = globus_error_put(monitor->err);
    }

    globus_free(monitor); 

    return result;
}

globus_result_t
globus_io_udp_register_sendto(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    int                                 flags,
    globus_size_t                       nbytes,
    char *                              host,
    unsigned short                      port,
    globus_io_udp_sendto_callback_t     send_cb,
    void *                              user_arg)
{
    globus_l_io_udp_info_t *            sendto_arg;
    globus_result_t                     result;
    struct hostent                      he;
    int                                 hp_errnop;
    char                                hp_tsdbuffer[500];
    globus_object_t *			        err;
    struct hostent *                    hp;
    static char *                       myname="globus_io_udp_register_sendto";

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
    if(buf == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "buf",
                1,
                myname));
    }
    if(nbytes <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "nbytes",
                1,
                myname));
    }

    hp = globus_libc_gethostbyname_r(
            host,
            &he,
            hp_tsdbuffer,
            500,
            &hp_errnop);
    if(hp == GLOBUS_NULL)
    {
        err = globus_io_error_construct_system_failure(
	            GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                errno);
       return globus_error_put(err);
    }

    sendto_arg = (globus_l_io_udp_info_t *)
              globus_malloc(sizeof(globus_l_io_udp_info_t));
    sendto_arg->buf = buf;
    sendto_arg->nbytes = nbytes;
    sendto_arg->iovec = NULL;
    sendto_arg->iovec_count = 0;
    sendto_arg->handle = handle;
    sendto_arg->flags = flags;
    sendto_arg->sendv_cb = NULL;
    sendto_arg->send_cb = send_cb;
    sendto_arg->user_callback_arg = user_arg;

    memset(&sendto_arg->addr, '\0', sizeof(sendto_arg->addr));
    sendto_arg->addr.sin_family = hp->h_addrtype;
    memcpy(&sendto_arg->addr.sin_addr, hp->h_addr, hp->h_length);
    sendto_arg->addr.sin_port = htons(port);

    result = globus_io_register_select(
                  handle,
                  GLOBUS_NULL,
                  GLOBUS_NULL,
                  globus_l_io_udp_sendto_callback,
                  (void *)sendto_arg,
                  GLOBUS_NULL,
                  GLOBUS_NULL);

    return result;
}
/* globus_io_udp_register_sendto() */

globus_result_t
globus_io_udp_register_sendvto(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    int                                 iovc,
    int                                 flags,
    char *                              host,
    unsigned short                      port,
    globus_io_udp_sendvto_callback_t    sendv_cb,
    void *                              user_arg)
{
    globus_l_io_udp_info_t *            sendto_arg;
    globus_result_t                     result;
    struct hostent                      he;
    int                                 hp_errnop;
    char                                hp_tsdbuffer[500];
    globus_object_t *			        err;
    struct hostent *                    hp;
    static char *                       myname="globus_io_udp_register_sendto";

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
    if(iov == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iov",
                1,
                myname));
    }
    if(iovc <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iovc",
                1,
                myname));
    }

    hp = globus_libc_gethostbyname_r(
            host,
            &he,
            hp_tsdbuffer,
            500,
            &hp_errnop);
    if(hp == GLOBUS_NULL)
    {
        err = globus_io_error_construct_system_failure(
	            GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                errno);
       return globus_error_put(err);
    }

    sendto_arg = (globus_l_io_udp_info_t *)
              globus_malloc(sizeof(globus_l_io_udp_info_t));
    sendto_arg->buf = NULL;
    sendto_arg->nbytes = 0;
    sendto_arg->iovec = iov;
    sendto_arg->iovec_count = iovc;
    sendto_arg->handle = handle;
    sendto_arg->flags = flags;
    sendto_arg->sendv_cb = sendv_cb;
    sendto_arg->send_cb = NULL;
    sendto_arg->user_callback_arg = user_arg;

    memset(&sendto_arg->addr, '\0', sizeof(sendto_arg->addr));
    sendto_arg->addr.sin_family = hp->h_addrtype;
    memcpy(&sendto_arg->addr.sin_addr, hp->h_addr, hp->h_length);
    sendto_arg->addr.sin_port = htons(port);

    result = globus_io_register_select(
                  handle,
                  GLOBUS_NULL,
                  GLOBUS_NULL,
                  globus_l_io_udp_sendto_callback,
                  (void *)sendto_arg,
                  GLOBUS_NULL,
                  GLOBUS_NULL);

    return result;
}
/* globus_io_udp_register_sendvto() */

/**
 *  Receive a udp message from a remote socket
 *
 *  This function is used to receive a message from a remote host.
 * 
 *  @param handle
 *         The handle used to send the message.
 *
 *  @param iovec
 *         The iovec that will contain the users buffers.
 *
 *  @param iovec_count
 *         The number of entries in the iovec.
 *
 *  @param flags
 *         MSG_OOB, MSG_PEEK, MSG_WAITALL, MSG_NOSIGNAL, MSG_TRUNC, 
 *         MSG_ERRQUEUE
 *
 *  @param recvfrom_callback
 *         The function to be called when the data is in the users buffer.
 *
 *  @param callback_arg
 *         A user pointer that will be threaded through to the callback.
 *
 *  @ingroup udp
 */
globus_result_t
globus_io_udp_register_recvfromv(
    globus_io_handle_t *                handle,
    struct iovec *                      iovec,
    int                                 iovec_count,
    int                                 flags,
    globus_io_udp_recvfromv_callback_t  recvfromv_callback,
    void *                              callback_arg)
{
    globus_l_io_udp_info_t *            recvfrom_arg;
    globus_result_t                     result;
    static char *                       myname="globus_io_udp_register_recvfromv";

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
    if(iovec == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iovec",
                1,
                myname));
    }
    if(iovec_count <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iovec_count",
                1,
                myname));
    }

    /* memory will be freed when callback is finished */

    recvfrom_arg = (globus_l_io_udp_info_t *)
		      globus_malloc(sizeof(globus_l_io_udp_info_t));
    recvfrom_arg->buf = NULL;
    recvfrom_arg->iovec = iovec;
    recvfrom_arg->iovec_count = iovec_count;
    recvfrom_arg->handle = handle;
    recvfrom_arg->flags = flags;
    recvfrom_arg->recv_callback = NULL;
    recvfrom_arg->recv_callbackv = recvfromv_callback;
    recvfrom_arg->user_callback_arg = callback_arg;
   
    result = globus_io_register_select(
			      handle,
			      globus_l_io_udp_recvfrom_callback,
		          (void *)recvfrom_arg,
			      GLOBUS_NULL,
			      GLOBUS_NULL,
			      GLOBUS_NULL,
			      GLOBUS_NULL);

    return result;
}

globus_result_t
globus_io_udp_recvfromv(
    globus_io_handle_t *                handle,
    struct iovec *                      iovec,
    int                                 iovec_count,
    int                                 flags,
    char **                             host,
    unsigned short *                    port,
    globus_size_t *                     nbytes_received)
{
    globus_i_io_udp_monitor_t *         monitor;
    globus_result_t                     result;
    static char *                       myname="globus_io_udp_recvfromv";

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
    if(iovec == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iovec",
                1,
                myname));
    }
    if(iovec_count <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "iovec_count",
                1,
                myname));
    }

    monitor = (globus_i_io_udp_monitor_t *) 
                   globus_malloc(sizeof(globus_i_io_udp_monitor_t));

    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->cond, GLOBUS_NULL);
    monitor->done = GLOBUS_FALSE;
    monitor->err = GLOBUS_NULL;
    monitor->use_err = GLOBUS_FALSE;
    monitor->out_port = port;
    monitor->out_host = host;
    monitor->out_nbytes = nbytes_received;
    
    handle->blocking_read = GLOBUS_TRUE;
    
    result = globus_io_udp_register_recvfromv(
				    handle,
				    iovec,
                    iovec_count,
				    flags,
                    globus_l_io_udp_recvfromv_monitor_callback, 
				    (void *)monitor);

    if(result != GLOBUS_SUCCESS)
    {
        monitor->done = GLOBUS_TRUE;
        monitor->err = globus_error_get(result);
        monitor->use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor->mutex);
    {
        while(!monitor->done)
        {
            globus_cond_wait(&monitor->cond, &monitor->mutex);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);
    if(monitor->use_err)
    {
        result = globus_error_put(monitor->err);
    }

    globus_free(monitor); 

    return result;

}

/**
 *  Receive a udp message from a remote socket
 *
 *  This function is used to receive a message from a remote host.
 * 
 *  @param handle
 *         The handle used to send the message.
 *
 *  @param buf
 *         The buffer into which the message will be read.
 *
 *  @param nbytes
 *         the length of the buffer.
 *
 *  @param flags
 *         MSG_OOB, MSG_DONTROUTE, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_CONFIRM
 *
 *  @param recvfrom_callback
 *         The function to be called when the data is in the users buffer.
 *
 *  @param callback_arg
 *         A user pointer that will be threaded through to the callback.
 *
 *  @ingroup udp
 */
globus_result_t
globus_io_udp_register_recvfrom(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_io_udp_recvfrom_callback_t   recvfrom_callback,
    void *                              callback_arg)
{
    globus_l_io_udp_info_t *            recvfrom_arg;
    globus_result_t                     result;
    static char *                       myname="globus_io_udp_register_recvfrom";

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
    if(buf == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "buf",
                1,
                myname));
    }
    if(nbytes <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "nbytes",
                1,
                myname));
    }

    /* memory will be freed when callback is finished */
    recvfrom_arg = (globus_l_io_udp_info_t *)
		      globus_malloc(sizeof(globus_l_io_udp_info_t));
    recvfrom_arg->buf = buf;
    recvfrom_arg->iovec = NULL;
    recvfrom_arg->iovec_count = -1;
    recvfrom_arg->nbytes = nbytes;
    recvfrom_arg->handle = handle;
    recvfrom_arg->flags = flags;
    recvfrom_arg->recv_callback = recvfrom_callback;
    recvfrom_arg->recv_callbackv = NULL;
    recvfrom_arg->user_callback_arg = callback_arg;
   
    result = globus_io_register_select(
			      handle,
			      globus_l_io_udp_recvfrom_callback,
		              (void *)recvfrom_arg,
			      GLOBUS_NULL,
			      GLOBUS_NULL,
			      GLOBUS_NULL,
			      GLOBUS_NULL);

    return result;
}
/* globus_io_udp_register_recvfrom() */


/*
 * Function:	globus_io_udp_recvfrom()
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_io_udp_recvfrom(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    int                                 flags,
    globus_size_t                       nbytes,
    char **                             host,
    unsigned short *                    port,
    globus_size_t *                     nbytes_received)
{
    globus_i_io_udp_monitor_t *         monitor;
    globus_result_t                     result;
    static char *                       myname="globus_io_udp_recvfrom";

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
    if(buf == GLOBUS_NULL)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "buf",
                1,
                myname));
    }
    if(nbytes <= 0)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "nbytes",
                1,
                myname));
    }

    monitor = (globus_i_io_udp_monitor_t *) 
                   globus_malloc(sizeof(globus_i_io_udp_monitor_t));

    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->cond, GLOBUS_NULL);
    monitor->done = GLOBUS_FALSE;
    monitor->err = GLOBUS_NULL;
    monitor->use_err = GLOBUS_FALSE;
    monitor->out_port = port;
    monitor->out_host = host;
    monitor->out_nbytes = nbytes_received;
    
    handle->blocking_read = GLOBUS_TRUE;
    
    result = globus_io_udp_register_recvfrom(
				    handle,
				    buf,
                                    nbytes,
				    flags,
                    globus_l_io_udp_recvfrom_monitor_callback,
				    (void *)monitor);

    if(result != GLOBUS_SUCCESS)
    {
        monitor->done = GLOBUS_TRUE;
        monitor->err = globus_error_get(result);
        monitor->use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor->mutex);
    {
        while(!monitor->done)
        {
            globus_cond_wait(&monitor->cond, &monitor->mutex);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);
    if(monitor->use_err)
    {
        result = globus_error_put(monitor->err);
    }

    globus_free(monitor); 

    return result;
}
/* globus_io_udp_recvfrom() */

#endif /* WIN32 */
