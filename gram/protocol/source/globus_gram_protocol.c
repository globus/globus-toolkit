/* 
   globus_i_gram_http.c 

   convenience wrappers around globus_io to implement "http"-alike protocol.
   it's all based on callbacks.

   Server side:
   ------------
   globus_gram_http_allow_attach()
        creates and register a listen handle. The handle is recored in a
	table of listeners along with its port number.

	The function must forward information A:
	    userfunc  : callback to trigger after successfully receiving
	                a HTTP message, of type globus_gram_http_callback_t
	    userarg   : callback arg
	    userptr   : user_pointer of the handle that appears in callback

   globus_gram_http_callback_disallow()
        locates listener with help of the port number (from URL argument)
	and closes it.

   Client side:
   ------------ 
   globus_gram_http_post_and_get()
         attaches to URL, frames the user message, sends it, awaits
	 reply and unframes the reply.

	The function must forward information B:
	    monitor       : a monitor to signal done and error codes
	    reply_message : pointer to pointer to buf with parsed reply in
	    reply_size    : pointer to size_t, updated to reply size

   Typedefs:
   ---------
   globus_gram_http_read_t
       contains information A and B plus structure to maintain read status

   globus_gram_http_callback_t
        void (callback_t*)(userarg, io_handle, message, msgsize, int rc);

        This function must ensure that message buffer is freed and that
	io_handle is closed after it has been used.

   Callbacks
   ---------
        close_callback:
	    frees TCP attr and handle.
	    if TCP Listener, frees user pointer (array with information A)

        close_callback_after_write:
	    always frees sendbuf and issues a close on the handle.

        listen_callback:                                       [SERVER ONLY]
	    gets information A as a void** in the listen handle's user
	    pointer.

	    always reregisters for new listen calls.

	    does nothing more if error.

	    allocates a new gram_read_t, copies information A into it and
	    forwards it to other callbacks as an argument from now on.
	    allocates a new handle and registers an accept() with it.

        accept_callback:                                       [SERVER ONLY]
	    if error, frees read_t and closes handle.

	    allocates a message buffer to recv a HTTP message, issues
	    initial read.

        read_callback:
	    if error, frees recv buffer, closes handle. if read_t contains
	    a monitor, signals monitor "done with error". frees read_t.

	    if got_header is false, scans for CRLF CRLF in message, if
	    not found, re-registers for more data.
	    if found, sets got_header in the read_t, finds content_length,
	    and reregisters to read the body.
	    if got_header is true, then calls the user's callback, and
	    then frees the read_t.

        post_callback:                                         [CLIENT ONLY]
	    gets as argument an allocated read_t with userfunc ==
	    get_callback and userarg == the read_t itself.

	    if error, frees sendbuf, if read_t contains a monitor,
	    signals monitor "done with error". closes handle.

	    if write was successful, uses send buffer to recv an HTTP
	    message (replicate functionality of accept_callback)


    Defined globus_gram_http_callback_t's :
    ---------------------------------------
	client_callback:                                       [SERVER ONLY]
	    takes as an argument the GRAM client callback argument,
	    and as user pointer the GRAM client callback function.

	    always closes handle.

	    if error, translates to GRAM error and calls the GRAM client
	    callback with status=FAILED and failure_code = GRAM error.

	    if not error, translates the incoming message arguments
	    {URL, job_status, failure_code} and forwards to GRAM client
	    callback.

	get_callback:                                          [CLIENT ONLY]
	    takes as the read_t as argument.

	    always closes handle.

	    if error, translates to GRAM error and signals monitor "done
	    with error".

	    uses read_t monitor to store parsed message at the right spot.
	    signals monitor "done with success".
	    
*/

#include "globus_i_gram_http.h"       /* function decl.   */
#include "globus_i_gram_version.h"    /* GRAM version     */
#include "globus_gram_client.h"       /* GRAM error codes */

#include <globus_io.h>
#include <stdlib.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

static
char *
globus_l_gram_http_lookup_reason(int code);

static
int
globus_l_gram_http_parse_request(
    globus_byte_t *			buf,
    globus_size_t *			payload_length);

static
int
globus_l_gram_http_parse_reply(
    globus_byte_t *			buf,
    globus_size_t *			payload_length);

/* GRAM Protocol Strings */
#define CRLF		"\015\012"
#define CR		"\015"

#define GLOBUS_GRAM_HTTP_REQUEST_LINE \
			"POST %s HTTP/1.1" CRLF

#define GLOBUS_GRAM_HTTP_HOST_LINE \
			"Host: %s" CRLF

#define GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE \
			"Gram-Protocol-Version: %d" CRLF

#define GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE \
			"Content-Type: application/x-globus-gram" CRLF

#define GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE \
			"Content-Length: %d" CRLF

#define GLOBUS_GRAM_HTTP_REPLY_LINE \
			"HTTP/1.1 %3d %s" CRLF

#define GLOBUS_GRAM_HTTP_PARSE_REPLY_LINE \
			"HTTP/1.1 %3d %[^" CRLF "]" CRLF
#define GLOBUS_GRAM_HTTP_CONNECTION_LINE \
			"Connection: Close" CRLF

#define GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE \
		        "protocol-version: %d" CRLF	

#define GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE \
		        "job-state-mask: %d" CRLF	

#define GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE \
		        "callback-url: %s" CRLF	

#define GLOBUS_GRAM_HTTP_PACK_STATUS_LINE \
		        "status: %d" CRLF	

#define GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE \
		        "failure-code: %d" CRLF	

#define GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE \
		        "job-manager-url: %s" CRLF	

#define GLOBUS_GRAM_HTTP_PACK_CLIENT_REQUEST_LINE \
		        "%s" CRLF	

typedef enum
{
    GLOBUS_GRAM_HTTP_REQUEST,
    GLOBUS_GRAM_HTTP_REPLY
} globus_gram_http_read_type_t;

#define my_malloc(t,n) (t *) globus_libc_malloc(n * sizeof(t))
#define my_free(ptr)   globus_free(ptr)


#if 0
#define verbose(q) q
#else
#define verbose(q) { }
#endif

#define notice globus_libc_printf


typedef struct
{
    globus_bool_t                  got_header;
    globus_byte_t *                buf;
    globus_size_t		   bufsize;
    globus_gram_http_read_type_t   read_type;
    globus_size_t                  n_read;
    globus_gram_http_callback_t    callback_func;
    void *                         callback_arg;
    void *                         user_pointer;
    globus_byte_t **               reply_buf;
    globus_size_t *                reply_size;
    globus_gram_http_monitor_t *   monitor;
} globus_gram_http_read_t;


#define monitor_signal_done(monitor,errcode) \
    { \
	if (monitor) \
	{ \
	    globus_mutex_lock(&(monitor)->mutex); \
	    if (!(monitor)->done) \
	    {  \
		verbose(notice("SIGNAL, errcode =%d\n", errcode)); \
		(monitor)->done = GLOBUS_TRUE; \
		(monitor)->errorcode = errcode; \
		globus_cond_signal(&(monitor)->cond); \
	    } \
	    globus_mutex_unlock(&(monitor)->mutex); \
	}  \
    }

#define initialize_monitor(monitor) \
    { \
	globus_mutex_lock(&monitor->mutex); \
	monitor->done = GLOBUS_FALSE; \
	globus_mutex_unlock(&monitor->mutex); \
    }


/* for some reason, this couldn't be defined as a macro. ? */
void 
globus_gram_http_initialize_read_t( globus_gram_http_read_t **    read_t,
				    void *                        func,
				    void *                        arg,
				    void *                        userptr,
				    globus_gram_http_monitor_t *  monitor,
				    globus_byte_t **              buf, 
				    globus_size_t *               bufsize) 
{ 
    *read_t = my_malloc(globus_gram_http_read_t,1);
    
    (*read_t)->got_header     = GLOBUS_FALSE; 
    (*read_t)->buf            = GLOBUS_NULL; 
    (*read_t)->bufsize        = 0;
    (*read_t)->n_read         = 0; 
    (*read_t)->callback_func  = (globus_gram_http_callback_t) func; 
    (*read_t)->callback_arg   = arg; 
    (*read_t)->user_pointer   = userptr; 
    (*read_t)->monitor        = monitor; 
    (*read_t)->reply_buf      = buf;
    (*read_t)->reply_size     = bufsize;
}


#define start_http_read(res,status,handle,rtype) \
{ \
    if (!status->buf) \
	status->buf = my_malloc(globus_byte_t, GLOBUS_GRAM_HTTP_BUFSIZE); \
	status->bufsize = GLOBUS_GRAM_HTTP_BUFSIZE; \
	status->read_type = rtype; \
    {  \
	res = globus_io_register_read( handle, \
				       status->buf, \
				       1, \
				       1, \
				       globus_l_gram_http_read_callback, \
				       (void *) status); \
    } \
    if (res != GLOBUS_SUCCESS) \
    { \
	my_free(status->buf); \
        res = globus_io_register_close( handle, \
		     		        globus_gram_http_close_callback, \
				        GLOBUS_NULL ); \
        monitor_signal_done(status->monitor, \
			    GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED); \
	my_free(status); \
    } \
}


/********************      internal list over active listeners ************/
typedef struct
{
    unsigned short        port;
    globus_io_handle_t *  handle;
} globus_i_gram_http_listener_t;

static globus_list_t *  globus_i_gram_http_listeners = GLOBUS_NULL;



/***** forward declarations of internal functions ***/

void
globus_l_gram_http_accept_callback( void *                read_t,
                                    globus_io_handle_t *  handle,
                                    globus_result_t       result );

void
globus_l_gram_http_post_callback( void * arg,
				  globus_io_handle_t * handle,
				  globus_result_t result,
				  globus_byte_t * buf,
				  globus_size_t nbytes);

void
globus_l_gram_http_read_callback( void * arg,
				  globus_io_handle_t * handle,
				  globus_result_t result,
				  globus_byte_t * buf,
				  globus_size_t nbytes);

void
globus_l_gram_http_parse_callback( void * arg,
				   globus_io_handle_t * handle,
				   globus_result_t result,
				   globus_byte_t * buf,
				   globus_size_t nbytes);

void
globus_l_gram_http_get_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_byte_t *       buf,
				 globus_size_t         nbytes,
				 int                   errorcode );



/************************** activation / deactivation ********************/

/*
 * NOTE: These functions are called from the the gram_client module
 * activation/deactivation.
 */

int
globus_gram_http_activate()
{
    globus_i_gram_http_listeners = GLOBUS_NULL;
    return GLOBUS_SUCCESS;
}

int
globus_gram_http_deactivate()
{
    globus_i_gram_http_listener_t *  listener;

    /*
     * flush any outstanding tasks
     */
    globus_poll_nonblocking();
    
    /*
     * close open listeners
     */
    while (!globus_list_empty(globus_i_gram_http_listeners))
    {
	listener = globus_list_remove(&globus_i_gram_http_listeners,
				      globus_i_gram_http_listeners);

	/* 
	 * listener was dynamically allocated. it points to a handle
	 * which is also dynamic and that has a dynamic user-pointer
	 * array, but the close callback routine will take care of
	 * those: we only have to free the listener struct.
	 */
	globus_io_register_close(listener->handle,
				 globus_gram_http_close_callback,
				 GLOBUS_NULL);

	my_free(listener);
    }

    globus_i_gram_http_listeners = GLOBUS_NULL;
    return GLOBUS_SUCCESS;
}

/************************  callback functions  *****************************/

void
globus_gram_http_close_callback( void *                ignored,
				 globus_io_handle_t *  handle,
				 globus_result_t       result)
{
    void *                        user_ptr;

    verbose(notice("close_callback : handle %d is done\n", handle->fd));

    if (globus_io_get_handle_type(handle) ==
	GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER )
    {
	verbose(notice("close_callback : handle %d was listener\n",
		       handle->fd));
	globus_io_handle_get_user_pointer( handle,
					   &user_ptr );
	my_free(user_ptr);
    }


    my_free(handle);
}


void
globus_gram_http_close_after_write( void * arg,
				    globus_io_handle_t * handle,
				    globus_result_t result,
				    globus_byte_t * buf,
				    globus_size_t nbytes)
{
    verbose(notice("close_after_write : res=%ld, buf=%p, handle=%d\n",
		   (long) result, buf, handle->fd));

    my_free(buf);
    globus_io_register_close(handle,
			     globus_gram_http_close_callback,
			     arg);
}


void
globus_l_gram_http_listen_callback( void *                ignored,
				    globus_io_handle_t *  listener_handle,
				    globus_result_t       result )
{
    globus_io_handle_t *          handle;
    globus_gram_http_read_t *     status;
    void **                       p;
    
    /* TODO: Globus result_t needs to be printed out specially; it's
       implemented as a void * --Steve A
*/
    verbose(notice("listen_callback : got connection on listener %d, res=%ld\n",
		   listener_handle->fd, (long) result));
    
    if (result == GLOBUS_SUCCESS)
    {
	globus_io_handle_get_user_pointer( listener_handle,
					   (void **) &p );

	globus_gram_http_initialize_read_t(
	    &status,
	    p[0],             /* userfunc   */
	    p[1],             /* userarg    */
	    p[2],             /* userptr    */
	    GLOBUS_NULL,      /* monitor    */
	    GLOBUS_NULL,      /* replybuf   */
	    GLOBUS_NULL );    /* replysize  */
	
	handle = my_malloc(globus_io_handle_t,1);

	result = globus_io_tcp_register_accept(
	             listener_handle,
		     GLOBUS_NULL,
		     handle,
		     globus_l_gram_http_accept_callback,
		     (void *) status);

	verbose(notice("listen_callback : result=%ld, handle=%d\n",
		       (long) result,
		       handle->fd));
    }

    /* reregister */
    result = globus_io_tcp_register_listen( listener_handle,
					    globus_l_gram_http_listen_callback,
					    GLOBUS_NULL );
}



void
globus_gram_http_client_callback( void *                 arg,
				  globus_io_handle_t *   handle,
				  globus_byte_t *        buf,
				  globus_size_t          nbytes,
				  int                    errorcode)
{
    globus_gram_client_callback_func_t *   userfunc;
    globus_byte_t *                        reply;
    globus_size_t                          replysize;
    char *                                 url;
    int                                    job_status;
    int                                    failure_code;
    int                                    version;
    int                                    rc;

    verbose(notice("client_callback : listener %d is done\n", handle->fd));

    rc = errorcode;

    if (rc != GLOBUS_SUCCESS || nbytes <= 0)
    {
	job_status   = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
	failure_code = rc;
    }
    else
    {
	rc = globus_gram_http_unpack_status_update_message(
	    buf,
	    nbytes,
	    &url,
	    &job_status,
	    &failure_code );
    }

    my_free(buf);

    rc = globus_gram_http_frame_reply( 200,
				       GLOBUS_NULL,
				       0,
				       &reply,
				       &replysize );
    
    globus_io_register_write( handle,
			      reply,
			      replysize,
			      globus_gram_http_close_after_write,
			      GLOBUS_NULL );

    globus_io_handle_get_user_pointer( handle,
				       (void *) userfunc );
    
    (*userfunc)(arg, url, job_status, failure_code);

    my_free(url);
}	      

 
void
globus_l_gram_http_read_callback( void *                 read_t,
				  globus_io_handle_t *   handle,
				  globus_result_t        result,
				  globus_byte_t *        buf,
				  globus_size_t          nbytes)
{
    globus_gram_http_read_t *    status = (globus_gram_http_read_t *) read_t;
    globus_result_t              res    = result;
    globus_size_t                chunk  = 1;
    char *			 p;
    globus_size_t		 payload_length;
    int				 rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;

    verbose(notice("read_callback : handle=%d nbytes=%d total=%d rc=%d\n",
		   handle->fd, nbytes, status->n_read, result));

    /* Error doing read */
    if (res != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }
    /* Reading the header information */
    else if (! status->got_header)
    {
	if (status->n_read==0 && (((char)*buf == '0') || ((char)*buf == 'D')))
	{
	    globus_libc_fprintf(
		stderr,
		"WARNING, read first character %c : delegation packet?\n",
		(char)*buf );
	    goto register_read_again;
	}

	status->n_read += nbytes;
	status->buf[status->n_read] = '\0';

	if (GLOBUS_NULL !=
	    (p = strstr((const char *)status->buf, CRLF CRLF)))
	{
	    status->got_header = GLOBUS_TRUE;
		
	    if(status->read_type == GLOBUS_GRAM_HTTP_REQUEST)
	    {
		rc = globus_l_gram_http_parse_request(
		    status->buf,
		    &payload_length);
	    }
	    else
	    {
		rc = globus_l_gram_http_parse_reply(
		    status->buf,
		    &payload_length);
	    }
	    if(rc != GLOBUS_SUCCESS)
	    {
		verbose(notice("read_callback : parse error\n"));
		goto error_exit;
	    }

	    status->n_read = 0;
	    chunk = payload_length;
	}

	if(status->bufsize < status->n_read + chunk)
	{
	    p = (char *) globus_libc_realloc((void *) status->buf,
				    status->n_read + chunk + 1);
	    if(p == GLOBUS_NULL)
	    {
		goto error_exit;
	    }
	    status->buf = (globus_byte_t *) p;
	    status->bufsize = status->n_read + chunk + 1;
	}

    register_read_again:
	res = globus_io_register_read( handle,
				       status->buf + status->n_read,
				       chunk,
				       chunk,
				       globus_l_gram_http_read_callback,
				       read_t );
	if(res != GLOBUS_SUCCESS)
	{
	    verbose(notice("read_callback : re-register error\n"));
	    goto error_exit;
	}
	return;
    }
    /* Just read the body */
    else
    {
	status->n_read += nbytes;
	status->buf[status->n_read] = '\0';

	verbose(notice("read_callback : calling callback function\n"));

	globus_io_handle_set_user_pointer( handle,
					   status->user_pointer );

	(status->callback_func)( status->callback_arg,
				 handle,
				 status->buf,
				 status->n_read,
				 GLOBUS_SUCCESS);
	my_free(status);
	return;
    }

error_exit:
    my_free(status->buf);
    globus_io_register_close( handle,
			      globus_gram_http_close_callback,
			      GLOBUS_NULL);
    
    monitor_signal_done( status->monitor,
			 rc);
    
    my_free(status);
    return;
}


void
globus_l_gram_http_accept_callback( void *                read_t,
                                    globus_io_handle_t *  handle,
                                    globus_result_t       result )
{
    globus_gram_http_read_t *  status;
    globus_result_t            res;

    verbose(notice("accept_callback : handle = %d, res = %ld\n",
		   handle->fd,
		   (long) result ));

    status = (globus_gram_http_read_t *) read_t;

    res = result;
    start_http_read(res,status,handle,GLOBUS_GRAM_HTTP_REQUEST);
}


void
globus_l_gram_http_post_callback( void *                read_t,
				  globus_io_handle_t *  handle,
				  globus_result_t       result,
				  globus_byte_t *       buf,
				  globus_size_t         nbytes)
{
    globus_gram_http_read_t *   status;
    globus_result_t             res;

    verbose(notice("http_post_callback : done writing %ld on %d\n",
		   (long) nbytes, handle->fd));

    status = (globus_gram_http_read_t *) read_t;

    res = result;
    status->buf = buf;

    start_http_read(res,status,handle,GLOBUS_GRAM_HTTP_REPLY);
}


void
globus_l_gram_http_get_callback( void *                read_t,
				 globus_io_handle_t *  handle,
				 globus_byte_t *       buf,
				 globus_size_t         nbytes,
				 int                   errorcode )
{
    globus_gram_http_read_t *  status;
    int                        rc;
    globus_result_t            res;

    verbose(notice("http_get_callback : handle %d , rc = %d\n",
		   handle->fd, errorcode));

    status = (globus_gram_http_read_t *) read_t;

    res = globus_io_register_close( handle,
				    globus_gram_http_close_callback,
				    GLOBUS_NULL );

    if ((errorcode == GLOBUS_SUCCESS) &&
	(res == GLOBUS_SUCCESS) )
    {
	if (status->reply_buf)
	    (*status->reply_buf) = buf;
	else
	    my_free(buf);
	
	if (status->reply_size)
	    *status->reply_size = nbytes;
    }
    else
    {
	my_free(buf);
    }

    if (errorcode != GLOBUS_SUCCESS)
	rc = errorcode;
    else if (res != GLOBUS_SUCCESS)
    	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    else
	rc = GLOBUS_SUCCESS;

    monitor_signal_done(status->monitor, rc);
}


/************************ "HTTP" post/get functions ************************/
int
globus_gram_http_post_and_get( char *                         url,
			       char *                         header_url,
			       globus_io_attr_t *             attr,
			       globus_byte_t *                request_message,
			       globus_size_t                  request_size,
			       globus_byte_t **               reply_message,
			       globus_size_t *                reply_size,
			       globus_gram_http_monitor_t *   monitor)
{
    int                             rc;
    globus_gram_http_read_t *       status;
    globus_io_handle_t *            handle;
    globus_byte_t *                 sendbuf;
    globus_size_t                   sendbufsize;
    globus_result_t                 res;
    globus_url_t		    parsed_url;
    globus_size_t                   i;


    rc = globus_url_parse(url, &parsed_url);

    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }

    if (monitor)
	initialize_monitor(monitor);

    globus_gram_http_initialize_read_t(
	&status,
	(void *)globus_l_gram_http_get_callback,    /* userfunc after get */
	GLOBUS_NULL,                                /* userarg            */
	GLOBUS_NULL,                                /* userptr            */
	monitor,                                    /* monitor            */
	reply_message,                              /* replybuf           */
	reply_size );                               /* replysize          */

    status->callback_arg = (void *) status;

    handle  = my_malloc(globus_io_handle_t,1);

    if ((rc = globus_gram_http_attach(url, handle, attr))
	|| (rc = globus_gram_http_frame_request( header_url,
						 parsed_url.host,
						 request_message,
						 request_size,
						 &sendbuf,
						 &sendbufsize)))
    {
	my_free(handle);
	my_free(status);
	globus_url_destroy(&parsed_url);
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;	
    }

    globus_url_destroy(&parsed_url);
    verbose(notice("http_post : writing size=%d on %d\n",
		   sendbufsize, handle->fd));
    for(i = 0; i < sendbufsize; i++)
    {
	verbose(notice("%c", sendbuf[i]));
    }
    verbose(notice("---\n"));

    res = globus_io_register_write( handle,
				    sendbuf,
				    sendbufsize,
				    globus_l_gram_http_post_callback,
				    status );
    if (res != GLOBUS_SUCCESS)
    {
	my_free(sendbuf);
	my_free(handle);
	my_free(status);
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }
    return GLOBUS_SUCCESS;
}




/************************* help function *********************************/

int
globus_gram_http_setup_attr(globus_io_attr_t *  attr)
{
    globus_result_t                        res;
    globus_io_secure_authorization_data_t  auth_data;

    /* acquire mutex */
    if ( (res = globus_io_tcpattr_init(attr))
	 || (res = globus_io_secure_authorization_data_initialize(
	                &auth_data))
	 || (res = globus_io_attr_set_secure_authentication_mode(
	                attr,
			GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI,
			GSS_C_NO_CREDENTIAL))
	 || (res = globus_io_attr_set_secure_authorization_mode(
	                attr,
			GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
			&auth_data))
	 || (res = globus_io_attr_set_secure_channel_mode(
	                attr,
			GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP)) )
    {
	globus_object_t *  err = globus_error_get(res);
	globus_object_free(err);
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED;
    }

    /* release mutex */
    return GLOBUS_SUCCESS;
}    



/**************************** create listener ****************************/

int
globus_gram_http_allow_attach( unsigned short *             port,
			       char **                      host,
			       void *                       user_ptr,
			       globus_gram_http_callback_t  user_callback,
			       void *                       user_arg )
{
    int                                    rc;
    char                                   hostnamebuf[256];
    globus_result_t                        res;
    globus_io_handle_t *                   handle;
    globus_io_attr_t                       attr;
    globus_i_gram_http_listener_t *        new_listener;
    void **                                buf;

    rc = globus_gram_http_setup_attr( &attr );
    if (rc != GLOBUS_SUCCESS)
    {
	/* release mutex */
	return rc;
    }

    handle = my_malloc(globus_io_handle_t,1);

    globus_libc_gethostname(hostnamebuf, 256);
    *host = globus_libc_strdup(hostnamebuf);
    *port = 0;

    if ( (res = globus_io_tcp_create_listener( port,
					       -1,       /* default backlog */
					       &attr,
					       handle))
	 || (res = globus_io_tcp_set_attr(handle, &attr)) )
    {
	globus_object_t *  err = globus_error_get(res);
	globus_object_free(err);
	globus_io_tcpattr_destroy(&attr);
	my_free(handle);
	/* TODO: return proper error */
	return rc;
    }

    buf = my_malloc(void *, 3);

    buf[0] = (void *) user_callback;
    buf[1] = user_arg;
    buf[2] = user_ptr;

    globus_io_handle_set_user_pointer(handle, (void *) buf);

    res = globus_io_tcp_register_listen( handle,
					 globus_l_gram_http_listen_callback,
					 GLOBUS_NULL );
    if (res != GLOBUS_SUCCESS)
    {
	globus_object_t *  err = globus_error_get(res);
	globus_object_free(err);
	globus_io_tcpattr_destroy(&attr);
	my_free(handle);
	/* TODO: return proper error */
	return rc;
    }
    else
    {
	new_listener = my_malloc(globus_i_gram_http_listener_t,1);
	new_listener->port   = *port;
	new_listener->handle = handle;
	globus_list_insert(&globus_i_gram_http_listeners, new_listener);
    }

    globus_io_tcpattr_destroy(&attr);

    return GLOBUS_SUCCESS;
}



/******************** locates listener at URL and closes it ************/

int
globus_gram_http_callback_disallow(char *   httpsurl)
{
    int                              rc;
    globus_list_t  *                 list;
    globus_i_gram_http_listener_t *  listener;
    globus_io_handle_t *             handle;
    globus_url_t                     url;
    unsigned short                   port;

    /*
     * get port number from url
     */
    rc = globus_url_parse(httpsurl, &url);
    if (rc == GLOBUS_SUCCESS)
	port = url.port;
    globus_url_destroy(&url);
    if (rc != GLOBUS_SUCCESS)
	return GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;

    /*
     * find listener with help of port and close it
     */
    handle = GLOBUS_NULL;
    list = globus_i_gram_http_listeners;
    while (!handle && !globus_list_empty(list))
    {
	listener = globus_list_first(list);

	if (listener->port == port)
	    handle = listener->handle;
	else
	    list = globus_list_rest(list);
    }
    
    if (!handle)
	return GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;

    globus_list_remove(&globus_i_gram_http_listeners, list);
    my_free(listener);

    verbose(notice("callback_disallow : closing handle = %d\n", handle->fd ));

    globus_io_register_close( handle,
			      globus_gram_http_close_callback,
			      GLOBUS_NULL );
    
    return GLOBUS_SUCCESS;
}



/**************************** "HTTP" callbacks ************************/


void
globus_l_gram_http_connection_closed( void *                arg,
				      globus_io_handle_t *  handle,
				      globus_result_t       result)
{
    globus_gram_http_monitor_t *  monitor; 
    
    verbose(notice("connection_closed : handle %d is done\n", handle->fd));

    globus_io_handle_get_user_pointer( handle,
				       (void **) &monitor );
    
    if (result != GLOBUS_SUCCESS)
    {
	monitor_signal_done(monitor, GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }
    else
    {
	monitor_signal_done(monitor, GLOBUS_SUCCESS);
    }

    my_free(handle);
}


/********************* attaches to a URL, returns globus_io handle ******/

int
globus_gram_http_attach( char *                job_contact,
			 globus_io_handle_t *  handle,
			 globus_io_attr_t *    user_attr )
{
    int                  rc;
    globus_result_t      res;
    globus_io_attr_t     default_attr;
    globus_io_attr_t *   attr;
    globus_url_t         url;

    /* dissect the job_contact URL */
    rc = globus_url_parse(job_contact, &url);
    if (rc != GLOBUS_SUCCESS)
    {
	globus_url_destroy(&url);
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
    }

    if (user_attr)
	attr = user_attr;
    else
    {
	rc = globus_gram_http_setup_attr( &default_attr );
	if (rc != GLOBUS_SUCCESS)
	{
	    globus_url_destroy(&url);
	    return rc;
	}
	attr = &default_attr;
    }

    res = globus_io_tcp_connect( url.host,
				 url.port,
				 attr,
				 handle );

    verbose(notice("connect: res=%ld, got new handle %d\n",
		   (long) res,
		   handle->fd));
    
    if (res != GLOBUS_SUCCESS)
    {   
        globus_object_t *       err  = globus_error_get(res);

        if (globus_object_type_match(
	        GLOBUS_IO_ERROR_TYPE_SECURITY_FAILED,
		globus_object_type_get_parent_type(
		    globus_object_get_type(err))))
        {   
	    rc = GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION;
        }
        else
        {
	    rc = GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED;
        }
	globus_object_free(err);
    }

    if (!user_attr)
	globus_io_tcpattr_destroy(attr);
    
    globus_url_destroy(&url);

    return rc;
}



/************************** HTTP "framing" routines *******************/

/*
 * Function:	globus_gram_http_frame_request()
 *
 */
int
globus_gram_http_frame_request(char *             uri,
			       char *             hostname,
			       globus_byte_t *    msg,
			       globus_size_t	  msgsize,
			       globus_byte_t **   framedmsg,
			       globus_size_t *	  framedsize)
{
    char *					buf;
    globus_size_t				digits = 0;
    globus_size_t				tmp;
    globus_size_t				framedlen;

    /*
     * HTTP request message framing:
     *    POST <uri> HTTP/1.1<CR><LF>
     *    Host: <hostname><CR><LF>
     *    Gram-Protocol-Version: <GLOBUS_GRAM_PROTOCOL_VERSION><CR><LF>
     *    Content-Type: application/x-globus-gram<CR><LF>
     *    Content-Length: <msgsize><CR><LF>
     *    <CR><LF>
     *    <msg>
     */
    tmp = msgsize;

    do
    {
	tmp /= 10;
	digits++;
    }
    while(tmp > 0);

    tmp = GLOBUS_GRAM_PROTOCOL_VERSION;
    
    do
    {
	tmp /= 10;
	digits++;
    }
    while(tmp > 0);

    framedlen  = strlen(GLOBUS_GRAM_HTTP_REQUEST_LINE);
    framedlen += strlen((char *) uri);
    framedlen += strlen(GLOBUS_GRAM_HTTP_HOST_LINE);
    framedlen += strlen((char *)hostname);
    framedlen += strlen(GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE);
    framedlen += strlen(GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE);
    framedlen += strlen(GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE);
    framedlen += digits;
    framedlen += 2;
    framedlen += msgsize;

    buf = (char *) my_malloc(globus_byte_t, framedlen + 1 /*null terminator*/);

    tmp  = 0;
    tmp += globus_libc_sprintf(buf + tmp,
			      GLOBUS_GRAM_HTTP_REQUEST_LINE,
			      uri);
    tmp += globus_libc_sprintf(buf + tmp,
			      GLOBUS_GRAM_HTTP_HOST_LINE,
			      hostname);
    tmp += globus_libc_sprintf(buf + tmp,
			       GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE,
			       GLOBUS_GRAM_PROTOCOL_VERSION);
    tmp += globus_libc_sprintf(buf + tmp,
			       GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE);
    tmp += globus_libc_sprintf(buf + tmp,
			       GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE,
			       msgsize);
    tmp += globus_libc_sprintf(buf + tmp,
			       CRLF);
    memcpy(buf + tmp,
	   msg,
	   msgsize);
			
    *framedmsg = (globus_byte_t *) buf;
    *framedsize = tmp + msgsize;

    return GLOBUS_SUCCESS;
}



/*
 * Function:	globus_gram_http_frame_reply()
 *
 */
int
globus_gram_http_frame_reply(int		code,
			     globus_byte_t *    msg,
			     globus_size_t      msgsize,
			     globus_byte_t **   framedmsg,
			     globus_size_t *    framedsize)
{
    char *					buf;
    char *					reason;
    globus_size_t				digits = 0;
    globus_size_t				tmp;
    globus_size_t				framedlen;

    /*
     * HTTP reply message framing:
     *    HTTP/1.1 <3 digit code> Reason String<CR><LF>
     *    Gram-Protocol-Version: <GLOBUS_GRAM_PROTOCOL_VERSION><CR><LF>
     *    Connection: close<CR><LF>
     *    <CR><LF>
     *
     * or
     *    HTTP/1.1 <3 digit code> Reason String<CR><LF>
     *    Gram-Protocol-Version: <GLOBUS_GRAM_PROTOCOL_VERSION><CR><LF>
     *    Content-Type: application/x-globus-gram<CR><LF>
     *    Content-Length: <msgsize><CR><LF>
     *    <CR><LF>
     *    msg
     */

    reason = globus_l_gram_http_lookup_reason(code);
    
    if(msgsize == 0)
    {
	tmp = GLOBUS_GRAM_PROTOCOL_VERSION;
	do
	{
	    tmp /= 10;
	    digits++;
	}
	while(tmp > 0);

	framedlen = 0;
	framedlen += strlen(GLOBUS_GRAM_HTTP_REPLY_LINE);
	framedlen += strlen(reason);
	framedlen += strlen(GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE);
	framedlen += digits;
	framedlen += strlen(GLOBUS_GRAM_HTTP_CONNECTION_LINE);

	buf = (char *) globus_malloc(framedlen + 1 /* null terminator */);

	tmp = 0;
	tmp += globus_libc_sprintf(buf + tmp,
				   GLOBUS_GRAM_HTTP_REPLY_LINE,
				   code,
				   reason);
	tmp += globus_libc_sprintf(buf + tmp,
				   GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE,
				   GLOBUS_GRAM_PROTOCOL_VERSION);
	tmp += globus_libc_sprintf(buf + tmp,
				   GLOBUS_GRAM_HTTP_CONNECTION_LINE);
	tmp += globus_libc_sprintf(buf + tmp,
				   CRLF);
    }
    else
    {
	tmp = msgsize;

	do
	{
	    tmp /= 10;
	    digits++;
	}
	while(tmp > 0);

	tmp = GLOBUS_GRAM_PROTOCOL_VERSION;
	do
	{
	    tmp /= 10;
	    digits++;
	}
	while(tmp > 0);

	framedlen = 0;
	framedlen += strlen(GLOBUS_GRAM_HTTP_REPLY_LINE);
	framedlen += strlen(reason);
	framedlen += strlen(GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE);
	framedlen += strlen(GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE);
	framedlen += strlen(GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE);
	framedlen += digits;
	framedlen += 2;
	framedlen += msgsize;

	buf = (char *) globus_malloc(framedlen);
	tmp = 0;
	tmp += globus_libc_sprintf(buf + tmp,
				   GLOBUS_GRAM_HTTP_REPLY_LINE,
				   code,
				   reason);
	tmp += globus_libc_sprintf(buf + tmp,
				   GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE,
				   GLOBUS_GRAM_PROTOCOL_VERSION);
	tmp += globus_libc_sprintf(buf + tmp,
		       GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE);
	tmp += globus_libc_sprintf(buf + tmp,
		       GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE,
		       msgsize);
	tmp += globus_libc_sprintf(buf + tmp,
		       CRLF);

	if (msgsize > 0)   /* this allows msg = NULL */
	{
	    memcpy(buf + tmp,
		   msg,
		   msgsize);
	}
    }


    *framedmsg = (globus_byte_t *) buf;
    *framedsize = tmp + msgsize;

    return GLOBUS_SUCCESS;
}


/************************ "HTTP" pack/unpack functions *********************/

static
globus_size_t
globus_l_gram_http_quote_string(
    const char *        in,
    globus_byte_t *     bufp )   /* assumes bufp has sufficient memory */
{
    char *  out = (char *) bufp;

    *out++='"';			/* Start the quoted string */
    while (*in)
    {
	if (*in == '"' || *in == '\\')   /* need escaping */
	    *out++ = '\\';
	*out++ = *in++;
    }
    *out++ = '"';		/* End the quoted string. */
    *out   = '\0';

    return (globus_size_t)(out - (char *)bufp);
}


/*
 * 
 * TODO: Add unquoting for the % HEX HEX mechanism.
 *
 */
static
int
globus_l_gram_http_unquote_string(
    const globus_byte_t *  inbuf, 
    globus_size_t          insize,
    char *                 out )  /* assumes enough mem alloc'd */
{
    globus_bool_t  in_quote = GLOBUS_FALSE;
    globus_bool_t  done     = GLOBUS_FALSE;
    char *         in       = (char *) inbuf;

    if (*in == '"')
    {
	in_quote = GLOBUS_TRUE;
	++in;
    }
    while (!done && ((globus_size_t)(in - (char *)inbuf) < insize))
    {
	if (!*in)
	{
	    done = GLOBUS_TRUE;
	    continue;
	}
	if (in_quote)
	{
	    if (*in == '"')  /* done */
	    {
		++in;
		in_quote = GLOBUS_FALSE;
		done = GLOBUS_TRUE;
		continue;
	    } 
	    else if (*in == '\\')   /* escaped characeter, do next instead */
		*out++ = *(++in);
	    else 
		*out++ = *in;
	} 
	else   /* no quote */
	{
	    if (*in == '\r')	/* end of the line. */ 
	    {
	        if (*(++in) != '\n')
		{
		    /* Malformed line */
		    return GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
		}
	    }
	    /* TODO: Recognize % HEX HEX here. */
	    *out++ = *in;
	}
	++in;
    }   /* while */

    if (in_quote)
	return GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;

    *out  = '\0';
    return GLOBUS_SUCCESS;
}


int
globus_gram_http_pack_job_request(
    const int               job_state_mask,
    const char *            callback_url,
    const char *            rsl,
    globus_byte_t **        query,
    globus_size_t *         querysize )
{
    int          rc;
    int          len;

    *query = my_malloc( globus_byte_t,
			strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE) +
			((callback_url) ? strlen(callback_url) : 2)
			+ 2*strlen(rsl) + 16);

    len = globus_libc_sprintf((char *) *query, 
			      GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			      GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE
			      GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE
			      "rsl: ",
			      GLOBUS_GRAM_PROTOCOL_VERSION,
			      job_state_mask,
			      (callback_url) ? callback_url : "\"\"" );
    
    len += globus_l_gram_http_quote_string( rsl,
					    (*query)+len );

    globus_libc_sprintf((char *)(*query)+len,
			"%s", 
			CRLF);
    *querysize = (globus_size_t)(len+3);

    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unpack_job_request(
    globus_byte_t *         query,
    globus_size_t           querysize,
    int  *                  job_state_mask,
    char **                 callback_url,
    char **                 description )
{
    int              protocol_version;
    int              rc;
    globus_size_t    rsl_count;
    char *           q = (char *) query;
    char *           p;

    p = strstr(q, CRLF"rsl: ");
    if (!p)
	return GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;	

    p+=strlen(CRLF"rsl: ");
    rsl_count = querysize - (globus_size_t)(p-q);

    *callback_url = my_malloc(char,(p-q));
    *description  = my_malloc(char,rsl_count);

    globus_libc_lock();
    rc = sscanf( q,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE
		 GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE,
		 &protocol_version,
		 job_state_mask,
		 *callback_url );
    globus_libc_unlock();
    if (rc != 3)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
	goto globus_gram_http_unpack_job_request_done;
    }
    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
	goto globus_gram_http_unpack_job_request_done;
    }	
    if (strcmp(*callback_url, "\"\"")==0)
    {
	my_free(*callback_url);
	*callback_url = GLOBUS_NULL;
    }

    rc = globus_l_gram_http_unquote_string(
	          (globus_byte_t*) p,
		  rsl_count-3,        /* CR LF + null */
		  *description );

globus_gram_http_unpack_job_request_done:
    if (rc != GLOBUS_SUCCESS)
    {
	my_free(*callback_url);
	my_free(*description);
	*callback_url = GLOBUS_NULL;
	*description = GLOBUS_NULL;
    }
    return rc;
}


int
globus_gram_http_pack_job_request_reply(
    int                      status,
    char *                   job_contact,    /* may be null */
    globus_byte_t **         reply,
    globus_size_t *          replysize )
{
    *reply = my_malloc(globus_byte_t,
		       strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
		       strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
		       strlen(GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE) +
		       ((job_contact) ? strlen(job_contact) + 3 : 3));
    
    if (job_contact)
	globus_libc_sprintf( (char *) *reply,
			     GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			     GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
			     GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE,
			     GLOBUS_GRAM_PROTOCOL_VERSION, 
			     status,
			     job_contact );
    else
	globus_libc_sprintf( (char *) *reply,
			     GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			     GLOBUS_GRAM_HTTP_PACK_STATUS_LINE,
			     GLOBUS_GRAM_PROTOCOL_VERSION,
			     status );
		 
    *replysize = (globus_size_t)(strlen((char *) *reply) + 1);
    return GLOBUS_SUCCESS;
}



int
globus_gram_http_unpack_job_request_reply(
    globus_byte_t *          reply,
    globus_size_t            replysize,
    int *                    status,
    char **                  job_contact )
{
    int      rc;
    int      protocol_version;
    char *   p;

    p = strstr((char *)reply, CRLF"job-manager-url:");
    if (p)
    {
	*job_contact = my_malloc(
	    char,
	    replysize - strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE));
	
	p+=2;  /* crlf */
    }

    globus_libc_lock();
    rc = sscanf( (char *) reply,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE,
		 &protocol_version,
		 status );
    globus_libc_unlock();
    if (rc != 2 )
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
	goto globus_gram_http_unpack_job_request_done;
    }
    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
	goto globus_gram_http_unpack_job_request_done;
    }	
    rc = GLOBUS_SUCCESS;
    if (p)
    {
	globus_libc_lock();
	rc = sscanf( p,
		     GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE,
		     *job_contact );
	globus_libc_unlock();
	if (rc != 1)
	    rc = GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
	else
	    rc = GLOBUS_SUCCESS;
    }

globus_gram_http_unpack_job_request_done:

    if (rc != GLOBUS_SUCCESS)
    {
	my_free(*job_contact);
	*job_contact = NULL;
    }

    return rc;
} 


int
globus_gram_http_pack_status_request(
    char *              status_request,
    globus_byte_t **    query,
    globus_size_t *     querysize )
{
    globus_size_t     len;

    *query = my_malloc(globus_byte_t,
		       strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
		       strlen(GLOBUS_GRAM_HTTP_PACK_CLIENT_REQUEST_LINE) +
		       2*strlen(status_request));

    len = globus_libc_sprintf( (char *) *query,	
			       GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE,
			       GLOBUS_GRAM_PROTOCOL_VERSION );

    len += globus_l_gram_http_quote_string( status_request,
					    (*query) + len );

    globus_libc_sprintf( (char *)(*query)+len, CRLF);	
    
    *querysize = (globus_size_t)(strlen((char*)*query) + 1);

    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unpack_status_request(
    globus_byte_t *    query,
    globus_size_t      querysize,
    char **            status_request )
{
    int             rc;
    int             protocol_version;
    char *          p;
    globus_size_t   msgsize;

    p = strstr((char *) query, CRLF);
    if (!p)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
	goto error_exit;
    }

    p+=2;
    msgsize = querysize - (globus_size_t)(p-(char *)query);
    *status_request = my_malloc(char, msgsize);
    rc = GLOBUS_SUCCESS;

    globus_libc_lock();
    rc = sscanf( (char *) query,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE,
		 &protocol_version );
    globus_libc_unlock();
    if (rc != 1)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
	goto error_exit;
    }
    else if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
	goto error_exit;
    }	

    rc = globus_l_gram_http_unquote_string(
	          (globus_byte_t*) p,
		  msgsize,
		  *status_request );

error_exit:
    if (rc != GLOBUS_SUCCESS)
    {
	my_free(*status_request);
	*status_request = GLOBUS_NULL;
    }

    return rc;
}


int
globus_gram_http_pack_status_reply(
    int                 job_status,
    int                 failure_code,
    globus_byte_t **    reply,
    globus_size_t *     replysize )
{
    *reply = my_malloc( globus_byte_t,
			strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE)
			+ 4 );

    globus_libc_sprintf( (char *)*reply,
			 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
			 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
			 GLOBUS_GRAM_PROTOCOL_VERSION,
			 job_status,
			 failure_code );
    
    *replysize = (globus_size_t)(strlen((char *)*reply) + 1);

    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unpack_status_reply(
    globus_byte_t *    reply,
    globus_size_t      replysize,
    int *              job_status,
    int *              failure_code )
{
    int     protocol_version;
    int     rc;
    
    globus_libc_unlock();
    rc = sscanf( (char *) reply,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
		 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
		 &protocol_version,
		 job_status,
		 failure_code );
    globus_libc_unlock();
    if (rc != 3)
    {
	return GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
    }
    else if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	return GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }		

    return GLOBUS_SUCCESS;
}



int
globus_gram_http_pack_status_update_message(   
    char *                   job_contact,
    int                      status,            
    int                      failure_code,
    globus_byte_t **         reply,
    globus_size_t *          replysize )
{
    *reply = my_malloc( 
	globus_byte_t,
	strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
	strlen(GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE) +
	strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
	strlen(GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE) +
	strlen(job_contact) + 5 );

    globus_libc_sprintf( (char *) *reply,
			 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			 GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE
			 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
			 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
			 GLOBUS_GRAM_PROTOCOL_VERSION,
			 job_contact,
			 status,
			 failure_code );
	     
    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unpack_status_update_message(
    globus_byte_t *          reply,
    globus_size_t            replysize,
    char **                  job_contact,
    int *                    status,
    int *                    failure_code )
{
    int   protocol_version;
    int   rc;

    *job_contact = my_malloc(char, replysize);

    globus_libc_lock();
    rc = sscanf( (char *) *reply,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE
		 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
		 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
		 &protocol_version,
		 *job_contact,
		 status,
		 failure_code );
    globus_libc_unlock();
    if (rc != 4)
    {
        return GLOBUS_GRAM_CLIENT_ERROR_HTTP_UNPACK_FAILED;
    }
    else if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        return GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }

    return GLOBUS_SUCCESS;
}



static
char *
globus_l_gram_http_lookup_reason(code)
{
    char * reason = GLOBUS_NULL;
    
    /* These are culled from RFC 2616 */
    switch(code)
    {
    case 100: reason="Continue"; break;
    case 101: reason="Switching Protocols"; break;
    case 200: reason="OK"; break;
    case 201: reason="Created"; break;
    case 202: reason="Accepted"; break;
    case 203: reason="Non-Authoritative Information"; break;
    case 204: reason="No Content"; break;
    case 205: reason="Reset Content"; break;
    case 206: reason="Partial Content"; break;
    case 300: reason="Multiple Choices"; break;
    case 301: reason="Moved Permanently"; break;
    case 302: reason="Found"; break;
    case 303: reason="See Other"; break;
    case 304: reason="Not Modified"; break;
    case 305: reason="Use Proxy"; break;
    case 307: reason="Temporary Redirect"; break;
    case 400: reason="Bad Request"; break;
    case 401: reason="Unauthorized"; break;
    case 402: reason="Payment Required"; break;
    case 403: reason="Forbidden"; break;
    case 404: reason="Not Found"; break;
    case 405: reason="Method Not Allowed"; break;
    case 406: reason="Not Acceptable"; break;
    case 407: reason="Proxy Authentication Required"; break;
    case 408: reason="Request Time-out"; break;
    case 409: reason="Conflict"; break;
    case 410: reason="Gone"; break;
    case 411: reason="Length Required"; break;
    case 412: reason="Precondition Failed"; break;
    case 413: reason="Request Entity Too Large"; break;
    case 414: reason="Request-URI Too Large"; break;
    case 415: reason="Unsupported Media Type"; break;
    case 416: reason="Requested range not satisfiable"; break;
    case 417: reason="Expectation Failed"; break;
    case 500: reason="Internal Server Error"; break;
    case 501: reason="Not Implemented"; break;
    case 502: reason="Bad Gateway"; break;
    case 503: reason="Service Unavailable"; break;
    case 504: reason="Gateway Time-out"; break;
    case 505: reason="HTTP Version not supported"; break;
    default:
	if(code < 100 ||
	   code >= 600)
	{
	    reason="Internal Server Error";
	}
	else if(code < 200)
	{
	    reason="Continue";
	}
	else if(code < 300)
	{
	    reason="OK";
	}
	else if(code < 400)
	{
	    reason="Multiple Choices";
	}
	else if(code < 500)
	{
	    reason="Bad Request";
	}
	else if(code < 600)
	{
	    reason="Internal Server Error";
	}
    }
    return reason;
}

static
int
globus_l_gram_http_parse_request(
    globus_byte_t *			buf,
    globus_size_t *			payload_length)
{
    int rc;
    char *uri;
    char *host;
    int protocol_version;

    uri = (char *) globus_malloc(strlen((char *) buf));
    host = (char *) globus_malloc(strlen((char *) buf));
    
    globus_libc_lock();
    rc = sscanf( (char *) buf,
		 GLOBUS_GRAM_HTTP_REQUEST_LINE
		 GLOBUS_GRAM_HTTP_HOST_LINE
		 GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE
		 GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE
		 CRLF,
		 uri,
		 host,
		 &protocol_version,
		 payload_length);
    globus_libc_unlock();
    if(rc != 4)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	*payload_length = 0;
    }
    else if(protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else
    {
	rc = GLOBUS_SUCCESS;
    }

    globus_free(uri);
    globus_free(host);

    return rc;
}


static
int
globus_l_gram_http_parse_reply(
    globus_byte_t *			buf,
    globus_size_t *			payload_length)
{
    int rc;
    int protocol_version;
    int code;
    int offset;
    char * reason;

    reason = (char *) globus_malloc(strlen((char *)buf));

    *payload_length = 0;
    
    globus_libc_lock();
    rc = sscanf( (char *) buf,
		 GLOBUS_GRAM_HTTP_PARSE_REPLY_LINE
		 GLOBUS_GRAM_HTTP_PROTOCOL_VERSION_LINE "%n",
		 &code,
		 reason,
		 &protocol_version,
		 &offset);
    globus_libc_unlock();
		       
    if(rc < 3)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }
    else if(protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }
    else if(code == 200)
    {
	globus_libc_lock();
	rc = sscanf( (char *)buf + offset,
		     GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE
		     GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE,
		     payload_length);
	globus_libc_unlock();
	if(rc != 1)
	{
	    rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	    *payload_length = 0;
	}
	else
	{
	    rc = GLOBUS_SUCCESS;
	}
    }
    else
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }

    globus_free(reason);
    
    return rc;
}



