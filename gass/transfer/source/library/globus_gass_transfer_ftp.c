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

/******************************************************************************
globus_gass_transfer_ftp.c

Description:
    This module implements the ftp and https URL schemes for the GASS transfer
    library

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#include "globus_ftp_client.h"
#include "globus_i_gass_transfer.h"
#include "globus_l_gass_transfer_ftp.h"

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#ifndef TARGET_ARCH_WIN32
#include <strings.h>
#endif
#include "version.h"

#if defined(DEBUG_GASS_TRANSFER)
#define debug_printf(a) printf a
#undef globus_l_gass_transfer_ftp_lock()
#undef globus_l_gass_transfer_ftp_unlock()
static int globus_l_gass_lock_line=0;
static int globus_l_gass_lock_tmp=0;

#define globus_l_gass_transfer_ftp_lock() \
        printf(_GTSL("Thread [%d] acquiring mutex at %s:%d\n"), \
               (int) globus_thread_self(), \
	       __FILE__, \
	       __LINE__), \
	fflush(stdout), \
	globus_l_gass_lock_tmp = \
		globus_mutex_lock(&globus_l_gass_transfer_ftp_mutex), \
	globus_l_gass_lock_line=__LINE__, \
	globus_l_gass_lock_tmp
#define globus_l_gass_transfer_ftp_unlock() \
        printf(_GTSL("Thread [%d] releasing mutex at %s:%d\n"), \
               (int) globus_thread_self(), \
	       __FILE__, \
	       __LINE__), \
	fflush(stdout), \
	globus_l_gass_lock_line = 0 \
	globus_mutex_unlock(&globus_l_gass_transfer_ftp_mutex) \
#else
#define debug_printf(a)
#endif

static volatile int globus_l_gass_transfer_ftp_open_connections;
#if !defined(GLOBUS_GASS_TRANSFER_FTP_PARSER_TEST)
int
globus_l_gass_transfer_ftp_activate(void)
{
    globus_l_gass_transfer_ftp_open_connections = 0;
 
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);

    globus_mutex_init(&globus_l_gass_transfer_ftp_mutex,
		      GLOBUS_NULL);
    globus_cond_init(&globus_l_gass_transfer_ftp_cond,
		     GLOBUS_NULL);

    
    return GLOBUS_SUCCESS;
}

int
globus_l_gass_transfer_ftp_deactivate(void)
{
  
    globus_l_gass_transfer_ftp_lock();

    while(globus_l_gass_transfer_ftp_open_connections > 0)
    {
	globus_l_gass_transfer_ftp_wait();
    }
    globus_l_gass_transfer_ftp_unlock();
  
    globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
 
    globus_mutex_destroy(&globus_l_gass_transfer_ftp_mutex);
    globus_cond_destroy(&globus_l_gass_transfer_ftp_cond);
    /* FIX - don't think subject_name is needed 
    globus_free(globus_l_gass_transfer_ftp_subject_name);
    */
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return GLOBUS_SUCCESS;
}
globus_module_descriptor_t globus_i_gass_transfer_ftp_module =
{
    "globus_i_gass_transfer_ftp",
    globus_l_gass_transfer_ftp_activate,
    globus_l_gass_transfer_ftp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/* Protocol Descriptor, which is registered with the GASS system */
globus_gass_transfer_proto_descriptor_t
globus_i_gass_transfer_ftp_descriptor =
{
    "ftp",

    /* client-side support */
    globus_l_gass_transfer_ftp_new_requestattr,
    globus_l_gass_transfer_ftp_new_request,

    /* server-side support */
    GLOBUS_NULL,
    GLOBUS_NULL
};

globus_gass_transfer_proto_descriptor_t
globus_i_gass_transfer_gsiftp_descriptor =
{
    "gsiftp",

    /* client-side support */
    globus_l_gass_transfer_ftp_new_requestattr,
    globus_l_gass_transfer_ftp_new_request,

    /* server-side support */
    GLOBUS_NULL,
    GLOBUS_NULL
};

/*
 * Function: globus_l_gass_transfer_ftp_send()
 * 
 * Description: Send a byte array to an FTP server
 * 
 * Parameters: 
 * 
 * Returns: 
 */
static
void
globus_l_gass_transfer_ftp_send(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				buffer,
    globus_size_t				buffer_length,
    globus_bool_t				last_data)
{
    globus_result_t				result;
    globus_gass_transfer_ftp_request_proto_t *		new_proto;
    globus_reltime_t                                    delay_time;

    globus_l_gass_transfer_ftp_lock();
    new_proto = (globus_gass_transfer_ftp_request_proto_t *) proto;
    new_proto->last_data = last_data;

    /* We can only process a send if the proto is in the "idle" state */
    globus_assert(new_proto->state == GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE);

    /* state change to "pending" */
    new_proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_PENDING;

    /* Update the buffers to point to those supplied by the user */
    new_proto->user_buffer = buffer;
    new_proto->user_buflen = buffer_length;

    /* If a a failure occurred, callback with the failure bit set,
     * and close the handle
     */
    if(new_proto->failure_occurred)
    {
	goto fail_exit;
    }

    /* Register the send of the data */
    result = globus_ftp_client_register_write(
	&new_proto->handle,
	new_proto->user_buffer,
	new_proto->user_buflen,
	new_proto->user_offset,
	new_proto->last_data,
	globus_l_gass_transfer_ftp_write_callback,
	(void *) new_proto);

    if(result == GLOBUS_SUCCESS)
    {
	/*
	 * Registration succeeded. Callback to GASS occurs when ftp_client
	 * completes the write.
	 */
	new_proto->user_offset += new_proto->user_buflen;
	globus_l_gass_transfer_ftp_unlock();
	return;
    }
    else /* there was an error trying to register a write, need to close up */
      globus_l_gass_transfer_ftp_register_close(new_proto);

  fail_exit:
    /* Registration failed, closing up the handle and signaling failure to GASS */
    /* will be handled in the globus_l_gass_transfer_ftp_put_done_callback() */
    
    globus_l_gass_transfer_ftp_unlock();
}
/* globus_l_gass_transfer_ftp_send() */


/*
 * Function: globus_l_gass_transfer_ftp_receive()
 * 
 * Description: Schedule the next block of data from the ftp server
 *              to end up in the provided byte array
 * 
 * Parameters: 
 * 
 * Returns: 
 */
static
void
globus_l_gass_transfer_ftp_receive(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				buffer,
    globus_size_t				buffer_length,
    globus_size_t				wait_for_length)
{
    globus_result_t                                     result;
    globus_gass_transfer_ftp_request_proto_t *		new_proto;
    globus_reltime_t                                    delay_time;

    globus_l_gass_transfer_ftp_lock();
    new_proto = (globus_gass_transfer_ftp_request_proto_t *) proto;

    /* We can only process a receive if the proto is in the "idle" state */
    globus_assert(new_proto->state == GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE);

    /* state change to "pending" */
    new_proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_PENDING;

    /* Update the buffers to point to those supplied by the user */
    new_proto->user_buffer = buffer;
    new_proto->user_buflen = buffer_length;
    new_proto->user_offset = 0;

    result = globus_ftp_client_register_read(
	    &new_proto->handle,
	    new_proto->user_buffer,
	    new_proto->user_buflen,
	    globus_l_gass_transfer_ftp_read_callback,
	    (void *) new_proto);

    if(result != GLOBUS_SUCCESS)
    {
	/* FIX - there was an error, do something about it */
      globus_l_gass_transfer_ftp_register_close(new_proto);
    }

    globus_l_gass_transfer_ftp_unlock();
}
/* globus_l_gass_transfer_ftp_receive() */

/*
 * Function: globus_l_gass_transfer_ftp_fail()
 * 
 * Description: Cause the given request to fail for client-caused reasons
 * 
 * Parameters: 
 * 
 * Returns: 
 */
static
void
globus_l_gass_transfer_ftp_fail(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_ftp_request_proto_t *	new_proto;
    globus_bool_t				signalled;

    new_proto = (globus_gass_transfer_ftp_request_proto_t *) proto;

    globus_l_gass_transfer_ftp_lock();

    signalled = GLOBUS_FALSE;
    while(!signalled)
    {
	switch(new_proto->state)
	{
	  case GLOBUS_GASS_TRANSFER_FTP_STATE_PENDING:
	    new_proto->failure_occurred = GLOBUS_TRUE;
	    while(new_proto->state ==
		  GLOBUS_GASS_TRANSFER_FTP_STATE_PENDING)
	    {
	      globus_l_gass_transfer_ftp_wait();
	    }
	    break;
	    
	    /*
          case GLOBUS_GASS_TRANSFER_FTP_STATE_CONNECTING:
	    */
          case GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE:
	    /* We will transition to the closing state, signalling the failure,
	     * and registering the close (which will transition us to the 
	     * done state).
	     */
	    signalled = GLOBUS_TRUE;
	    new_proto->failure_occurred = GLOBUS_TRUE;

	    globus_l_gass_transfer_ftp_register_close(new_proto);
	    break;

          case GLOBUS_GASS_TRANSFER_FTP_STATE_CLOSING:
          case GLOBUS_GASS_TRANSFER_FTP_STATE_DONE:
	    /*  the rest of these states don't exist */
	    /*
          case GLOBUS_GASS_TRANSFER_FTP_STATE_REQUESTING:
          case GLOBUS_GASS_TRANSFER_FTP_STATE_RESPONDING:
          case GLOBUS_GASS_TRANSFER_FTP_STATE_REFERRED:
          case GLOBUS_GASS_TRANSFER_FTP_STATE_DENIED:
	    */
	    signalled = GLOBUS_TRUE;
	    new_proto->failure_occurred = GLOBUS_TRUE;
	    break;
        }
    }
    globus_l_gass_transfer_ftp_unlock();
}
/* globus_l_gass_transfer_ftp_fail() */

static
void
globus_l_gass_transfer_ftp_write_callback(
    void *                                      callback_arg,
    globus_ftp_client_handle_t *                handle, 
    globus_object_t *                           error,
    globus_byte_t *                             bytes,
    globus_size_t                               nbytes,
    globus_off_t                                offset,
    globus_bool_t		                eof)
{
    globus_gass_transfer_ftp_request_proto_t *		proto;

    proto = (globus_gass_transfer_ftp_request_proto_t *) callback_arg;

    globus_l_gass_transfer_ftp_lock();

    if(error ||
       proto->failure_occurred)
    {
	proto->last_data = GLOBUS_TRUE;
	proto->failure_occurred = GLOBUS_TRUE;
    }

    if(eof)
	proto->last_data = GLOBUS_TRUE;

    {
	globus_gass_transfer_request_t request;
	globus_byte_t * buf;
	globus_bool_t fail;
	globus_bool_t last_data;
	    
	proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE;

	request = proto->request;
	buf = proto->user_buffer;
	fail = proto->failure_occurred;
	last_data = proto->last_data;
	

	globus_l_gass_transfer_ftp_signal();
	globus_l_gass_transfer_ftp_unlock();
	if(!last_data) 
	    globus_gass_transfer_proto_send_complete(request,
						     buf,
						     nbytes,
						     fail,
						     last_data);
    }
    return;
}
/* globus_l_gass_transfer_ftp_write_callback() */



/*
 * Function: globus_l_gass_transfer_ftp_read_callack()
 * 
 * Description: Callback when the read of from the connection to the active
 *              buffer has completed or failed.
 * 
 * Parameters: 
 * 
 * Returns: 
 */
static
void
globus_l_gass_transfer_ftp_read_callback(
    void *                          callback_arg,
    globus_ftp_client_handle_t *    handle,
    globus_object_t *               error,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_off_t                    offset,
    globus_bool_t		    eof)
{
    globus_gass_transfer_ftp_request_proto_t *		proto;

    proto = (globus_gass_transfer_ftp_request_proto_t *) callback_arg;
 
    globus_l_gass_transfer_ftp_lock();

    proto->user_offset = nbytes;
    if(eof)
    {
	proto->eof_read = GLOBUS_TRUE;
    }

    if(error)
    {
	proto->recv_state = GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_ERROR;
	proto->failure_occurred = GLOBUS_TRUE;
    }
    else if(eof)
	proto->recv_state = GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_EOF;

    /* Register the socket for closing if we're done reading from it */
    /*  FIX - ftp doesn't require a close, but leave this code here for the time being  */
    /*  if there was an error, the ftp_get_done_callback will take care of calling close 
     */
    /*
    if(proto->recv_state == GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_EOF ||
       proto->recv_state == GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_ERROR)
    {
	if(proto->state != GLOBUS_GASS_TRANSFER_FTP_STATE_CLOSING)
	    { 
		globus_l_gass_transfer_ftp_register_close(proto);
	    }
    }
    */   
    
    {
	globus_gass_transfer_request_t		request;
	globus_bool_t				last_data = GLOBUS_FALSE;
	globus_bool_t				failure ;
	globus_byte_t *				buf;
	globus_size_t				l_offset;
	
	/*
	 * Received the required minimum of data from connection, an
	 * error, or the end-of file, signal this to GASS
	 */
	if(proto->recv_state == GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_EOF ||
	   proto->recv_state == GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_ERROR)
	    last_data = GLOBUS_TRUE;
	
	if(proto->state == GLOBUS_GASS_TRANSFER_FTP_STATE_PENDING)
	{
	    proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE;
	}
	

	failure = proto->failure_occurred;
	buf = proto->user_buffer;
	l_offset = proto->user_offset;
	request = proto->request;

	globus_l_gass_transfer_ftp_signal();
	globus_l_gass_transfer_ftp_unlock();
	
	if(!last_data) 
	    globus_gass_transfer_proto_receive_complete(request,
							buf,
							l_offset,
							failure,
							last_data);
    }
    
    return;
}
/* globus_l_gass_transfer_ftp_read_callback() */


#ifdef TEMP_DEF
/*
 * Function: globus_l_gass_transfer_ftp_close_callback()
 *
 * Description: Called upon completion of close()ing the file handle,
 *              Will free the proto instance if the client has called
 *              the "done" function
 *
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_gass_transfer_ftp_close_callback(
    void *					callback_arg,
    globus_io_handle_t *			handle,
    globus_result_t				result)
{
    globus_gass_transfer_ftp_request_proto_t *		proto;


    proto = (globus_gass_transfer_ftp_request_proto_t *) callback_arg;

    globus_l_gass_transfer_ftp_lock();
    globus_l_gass_transfer_ftp_close(proto);
    globus_l_gass_transfer_ftp_unlock();
}
/* globus_l_gass_transfer_ftp_close_callback() */

#endif

/*
 * Function: globus_l_gass_transfer_ftp_close()
 *
 * Description: must be called with the mutex locked
 *
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_gass_transfer_ftp_close(
    globus_gass_transfer_ftp_request_proto_t *		proto)
{
 
    proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_DONE;

    if(proto->destroy_called)
    {
	globus_l_gass_transfer_ftp_proto_destroy(proto);
    }
  
    globus_l_gass_transfer_ftp_open_connections--; 
    globus_l_gass_transfer_ftp_signal();
}
/* globus_l_gass_transfer_ftp_close() */

/*
 * Function: globus_l_gass_transfer_ftp_register_close()
 *
 * Description: must be called with the mutex locked
 *
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_gass_transfer_ftp_register_close(
    globus_gass_transfer_ftp_request_proto_t *		proto)
{
    globus_result_t result = GLOBUS_SUCCESS;

    proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_CLOSING;

    /*  globus_l_gass_transfer_ftp_closing++; */
/*printf("ftp_register_close: closing= %d\n", globus_l_gass_transfer_ftp_closing); */
    
/*   FIX - not sure if this is right, should only abort when fail is called by the user -  actually, just call abort in the fail function
     actually, i changed my mind, in the case where send or receive_bytes returns something other than SUCCESS, we want to
     abort as well.
    if(proto->failure_occurred)
*/
    result = globus_ftp_client_abort(&proto->handle);
		      
    if(result != GLOBUS_SUCCESS)
    {
      /*
      globus_libc_fprintf(stderr, "in _ftp_register_close(), _ftp_client_abort() returned something other than GLOBUS_SUCCESS");
      */
      /*  not sure if this should get called here 
	globus_l_gass_transfer_ftp_close(proto);
      */
    }
}
/* globus_l_gass_transfer_ftp_register_close() */



/*
 * Function: globus_l_gass_transfer_ftp_listener_proto_destroy()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_gass_transfer_ftp_listener_proto_destroy(
    globus_gass_transfer_ftp_listener_proto_t *
					proto)
{
#if 0
    globus_free(proto);
#endif
}
/* globus_l_gass_transfer_ftp_listener_proto_destroy() */

/*
 * Function: globus_l_gass_transfer_ftp_destroy()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_gass_transfer_ftp_destroy(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_ftp_request_proto_t *		new_proto;

    new_proto = (globus_gass_transfer_ftp_request_proto_t *) proto;

    globus_l_gass_transfer_ftp_lock();
    if(new_proto->state == GLOBUS_GASS_TRANSFER_FTP_STATE_CLOSING)
    {
	new_proto->destroy_called=GLOBUS_TRUE;
    }
    else if(new_proto->state == GLOBUS_GASS_TRANSFER_FTP_STATE_DONE)
    {
	globus_l_gass_transfer_ftp_proto_destroy(new_proto);
    }
    globus_l_gass_transfer_ftp_unlock();
}
/* globus_l_gass_transfer_ftp_destroy() */


static
void
globus_l_gass_transfer_ftp_proto_destroy(
    globus_gass_transfer_ftp_request_proto_t *		proto)
{
    
    if(proto->reason != GLOBUS_NULL)
    {
	globus_free(proto->reason);
    }
    if(proto->client_side)
    {
	globus_url_destroy(&proto->url);
    }

    globus_ftp_client_handle_destroy(&proto->handle);
    globus_free(proto);
}
/* globus_l_gass_transfer_ftp_proto_destroy() */


/*
 * Function: globus_l_gass_transfer_ftp_new_request(()
 *
 * Description: Create a new request's "proto" structure
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_gass_transfer_ftp_new_request(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_requestattr_t *	attr)
{
    int						rc=GLOBUS_SUCCESS;
    globus_gass_transfer_file_mode_t		file_mode=GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY;
    globus_ftp_client_operationattr_t		ftp_attr;
    globus_ftp_control_tcpbuffer_t              tcp_buffer;
    globus_result_t				result;
    globus_gass_transfer_ftp_request_proto_t *	proto;
    int						sndbuf;
    int						rcvbuf;
    int						nodelay;
    globus_reltime_t                            delay_time;

    switch(globus_gass_transfer_request_get_type(request))
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET:
      case GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT:
      case GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND:
	break;
      default:
	goto error_exit;
    }

    /* Allocate proto instance */
    proto = (globus_gass_transfer_ftp_request_proto_t *) 
	globus_malloc(sizeof(globus_gass_transfer_ftp_request_proto_t));

    if(proto == GLOBUS_NULL)
    {
	goto error_exit;
    }

    result = globus_ftp_client_handle_init(&proto->handle, GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
	goto proto_error;
    }
    result = globus_ftp_client_operationattr_init(&ftp_attr);
    
    if(result != GLOBUS_SUCCESS)
    {
	goto handle_error;
    }
    
#if 1 /* NOT skipping attributes stuff for now */
    
    if(*attr != GLOBUS_NULL)
    {
	/* Check attributes we care about */
      /*	globus_gass_transfer_requestattr_get_proxy_url(attr,
		&proxy);
      */
	rc = globus_gass_transfer_requestattr_get_socket_sndbuf(
	    attr,
	    &sndbuf);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto attr_error;
	}
	/*
	else
	{
	    if(sndbuf != 0)
	    {
		globus_io_attr_set_socket_sndbuf(&tcp_attr,
						 sndbuf);
	    }
	}
	*/
	
	rc = globus_gass_transfer_requestattr_get_socket_rcvbuf(
	    attr,
	    &rcvbuf);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto attr_error;
	}
	/*
	else
	{
	    if(rcvbuf != 0)
	    {
		globus_io_attr_set_socket_rcvbuf(&tcp_attr,
						 rcvbuf);
	    }
	}
	*/
	/*
	rc = globus_gass_transfer_requestattr_get_socket_nodelay(
	    attr,
	    &nodelay);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto tcpattr_error;
	}
	else
	{
	    globus_io_attr_set_tcp_nodelay(&tcp_attr,
					   nodelay);
	}
	*/
	
	/* File mode is important on Windows */
	rc = globus_gass_transfer_requestattr_get_file_mode(attr,
							    &file_mode);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto attr_error;
	}
	if(file_mode == GLOBUS_GASS_TRANSFER_FILE_MODE_TEXT)
	{
	  globus_ftp_client_operationattr_set_type(&ftp_attr,
					           GLOBUS_FTP_CONTROL_TYPE_ASCII);
	}    
	/*
	rc = globus_gass_transfer_requestattr_get_block_size(attr,
							     &proto->block_size);
	if(rc != GLOBUS_SUCCESS)
	{
	    goto tcpattr_error;
	}
	*/
    }
#endif /* NOT skipping attribute stuff for now */
    
    proto->url_string = globus_gass_transfer_request_get_url(request);

    rc = globus_url_parse(proto->url_string,
			  &proto->url);
    if(rc != GLOBUS_SUCCESS)
    {
	goto attr_error;
    }
    if(proto->url.url_path == GLOBUS_NULL)
    {
	proto->url.url_path = globus_libc_strdup("/");
    }
    if(strcmp(proto->url.scheme, "ftp") != 0 &&
       strcmp(proto->url.scheme, "gsiftp") != 0)
    {
	goto url_error;
    }

#if 1 /* NOT skipping attribute stuff for now */
    {
      globus_gass_transfer_authorization_t	mode;
      char *					subject=NULL;
      globus_result_t				result;
      
    /* If gsiftp, set security subject attribute of TCP handle */
      if(strcmp(proto->url.scheme, "gsiftp")== 0)
      {
	 
	if(*attr != GLOBUS_NULL)
	{
	  rc = globus_gass_transfer_secure_requestattr_get_authorization(
									 attr,
									 &mode,
									 &subject);
	  if(rc != GLOBUS_SUCCESS)
	  {
	    goto url_error;
	  }
	}

      }

      if( proto->url.user     ||
	  proto->url.password ||
	  subject )
      {
	globus_ftp_client_operationattr_set_authorization(
						          &ftp_attr,
							  GSS_C_NO_CREDENTIAL,
						          proto->url.user,
						          proto->url.password,
						          NULL,
						          subject);
      }
    }
#endif /* NOT skipping attribute stuff for now */
    
    if(proto == GLOBUS_NULL)
    {
	goto url_error;
    }

    /* Initialize the proto instance */
    proto->send_buffer	= globus_l_gass_transfer_ftp_send;
    proto->recv_buffer	= globus_l_gass_transfer_ftp_receive;
    proto->fail		= globus_l_gass_transfer_ftp_fail;
    proto->deny		= GLOBUS_NULL;
    proto->refer	= GLOBUS_NULL;
    proto->authorize	= GLOBUS_NULL;
    proto->destroy	= globus_l_gass_transfer_ftp_destroy;
    proto->text_mode	= (file_mode == GLOBUS_GASS_TRANSFER_FILE_MODE_TEXT);
    /*   proto->line_mode	= GLOBUS_L_LINE_MODE_UNKNOWN; */
    proto->state	= GLOBUS_GASS_TRANSFER_FTP_STATE_CONNECTING;
    proto->request	= request;
    proto->type		= globus_gass_transfer_request_get_type(request);
    proto->code		= 0;
    proto->reason	= 0;
    proto->parse_error	= GLOBUS_FALSE;
    proto->destroy_called = GLOBUS_FALSE;
    proto->headers	= GLOBUS_NULL;
    proto->response_buffer = GLOBUS_NULL;
    proto->length	= 0;
    proto->handled	= 0;
    proto->chunked	= GLOBUS_FALSE;
    proto->chunk_left	= 0;
    proto->failure_occurred = GLOBUS_FALSE;
    proto->oneshot_registered = GLOBUS_FALSE;
    proto->oneshot_active = GLOBUS_FALSE;
    proto->eof_read	= GLOBUS_FALSE;
    proto->client_side	= GLOBUS_TRUE;
    proto->connected_subject	= GLOBUS_NULL;
/*    proto->proxy_connect = proxy ? GLOBUS_TRUE : GLOBUS_FALSE; */
    proto->got_response = GLOBUS_FALSE;
    proto->waiting_for_response = GLOBUS_FALSE;

    proto->user_offset = 0;

    /* Open the handle */

    switch(proto->type)
    {	
    case GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT:
      if(sndbuf !=0)
      {
	tcp_buffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
	tcp_buffer.fixed.size = sndbuf;
	globus_ftp_client_operationattr_set_tcp_buffer(&ftp_attr,
					               &tcp_buffer);
      }
      
      result = globus_ftp_client_put(
	    &proto->handle,
	    proto->url_string,
	    &ftp_attr,
            GLOBUS_NULL,
	    globus_l_gass_transfer_ftp_put_done_callback,
	    (void *) proto);
	break;
	
    case GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND:
	/* FIX  - appropriate error until ftp_client supports APPEND mode */
	result = globus_error_put(GLOBUS_ERROR_NO_INFO);
	break;
	
    case GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET:
      if(rcvbuf !=0)
      {
	tcp_buffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
	tcp_buffer.fixed.size = rcvbuf;
	globus_ftp_client_operationattr_set_tcp_buffer(&ftp_attr,
					               &tcp_buffer);
      }
      
	result = globus_ftp_client_get(
	    &proto->handle,
	    proto->url_string,
	    &ftp_attr,
            GLOBUS_NULL,
	    globus_l_gass_transfer_ftp_get_done_callback,
	    (void *) proto);
	break;

    }
    

    if(result != GLOBUS_SUCCESS)
    {
	/* FIX - handle errors properly */
	goto url_error;
    }
    /* Success! */
    proto->state = GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE;
    globus_l_gass_transfer_ftp_open_connections++;
    globus_gass_transfer_proto_request_ready(
	proto->request,
	(globus_gass_transfer_request_proto_t *) proto);
    
    globus_ftp_client_operationattr_destroy(&ftp_attr);
    return ;

  url_error:
    globus_url_destroy(&proto->url);

  attr_error:
    globus_ftp_client_operationattr_destroy(&ftp_attr);
  handle_error:
    globus_ftp_client_handle_destroy(&proto->handle);
  proto_error:
    globus_free(proto);
  error_exit:
  
    GlobusTimeReltimeSet(delay_time, 0, 0);
    globus_callback_register_oneshot(
        GLOBUS_NULL,
	&delay_time,
	globus_l_gass_transfer_ftp_callback_denied,
	(void *) request);
}
/* globus_l_gass_transfer_ftp_new_request() */

/*
 * Function: globus_l_gass_transfer_ftp_new_requestattr()
 *
 * Description: Create a new request attribute structure,
 *              appropriate for the "ftp" url scheme
 *
 * Parameters:
 *
 * Returns:
 */
static
globus_object_t *
globus_l_gass_transfer_ftp_new_requestattr(
    char *                                      url_scheme)
{
    globus_object_t *				obj;

    if(strcmp(url_scheme, "gsiftp") == 0)
    {
	obj = globus_object_construct(GLOBUS_GASS_OBJECT_TYPE_SECURE_REQUESTATTR);

	return
	    globus_gass_transfer_secure_requestattr_initialize(
		obj,
		GLOBUS_NULL,
		0,
		GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY,
		GLOBUS_FALSE,
		0,
		0,
		GLOBUS_FALSE,
		GLOBUS_GASS_TRANSFER_AUTHORIZE_HOST,
		GLOBUS_NULL);
    }
    else if(strcmp(url_scheme, "ftp") == 0)
    {
	obj = globus_object_construct(GLOBUS_GASS_OBJECT_TYPE_SOCKET_REQUESTATTR);

	return
	    globus_gass_transfer_socket_requestattr_initialize(
		obj,
		GLOBUS_NULL,
		0,
		GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY,
		GLOBUS_FALSE,
		0,
		0,
		GLOBUS_FALSE);
    }
    else
    {
	return GLOBUS_NULL;
    }
}
/* globus_l_gass_transfer_ftp_new_requestattr() */


void
globus_l_gass_transfer_ftp_get_done_callback(
    void *                                     callback_arg,
    globus_ftp_client_handle_t *               handle,
    globus_object_t *	                       error)
{
    globus_gass_transfer_ftp_request_proto_t * proto;
    globus_bool_t                              failure = GLOBUS_FALSE;

   
    if(error)
	failure = GLOBUS_TRUE;
    
    proto = (globus_gass_transfer_ftp_request_proto_t *) callback_arg;

    if(!failure)
      globus_gass_transfer_proto_receive_complete(proto->request,
						  proto->user_buffer,
						  proto->user_offset,
						  failure,
						  GLOBUS_TRUE);
    globus_l_gass_transfer_ftp_close(proto);
    
} /*globus_l_gass_transfer_ftp_get_done_callback() */

void
globus_l_gass_transfer_ftp_put_done_callback(
    void *                                     callback_arg,
    globus_ftp_client_handle_t *               handle,
    globus_object_t *	                       error)
{
    globus_gass_transfer_ftp_request_proto_t * proto;
    globus_bool_t                              failure = GLOBUS_FALSE;

    if(error)
	failure = GLOBUS_TRUE;
   
    proto = (globus_gass_transfer_ftp_request_proto_t *) callback_arg;
    
    if(!failure)
    {
      globus_gass_transfer_proto_send_complete(proto->request,
					       proto->user_buffer,
					       proto->user_offset,
					       failure,
					       GLOBUS_TRUE);
    }
  
    globus_l_gass_transfer_ftp_close(proto);
    
} /* globus_l_gass_transfer_ftp_put_done_callback() */

static
void
globus_l_gass_transfer_ftp_callback_denied(
    void *					arg)
{
    globus_gass_transfer_request_t		request;

    request = (globus_gass_transfer_request_t) arg;
    
    globus_gass_transfer_proto_request_denied(
	request,
	GLOBUS_L_DEFAULT_FAILURE_CODE,
	globus_libc_strdup(GLOBUS_L_DEFAULT_FAILURE_REASON));
}

#endif /* !parser only */
