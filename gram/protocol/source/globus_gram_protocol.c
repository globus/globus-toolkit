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
   globus_gram_http_post()
         attaches to URL, frames the user message and sends it.
	 
   globus_gram_http_post_and_get()
         attaches to URL, frames the user message, sends it, awaits
	 reply and unframes the reply.

	The function must forward information B:
	    monitor       : a monitor to signal done and error codes
	    reply_message : pointer to buf to store parsed reply in
	    reply_size    : pointer to size_t, updated to message size

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

	    scans for "\n\n" in message, if not, re-registers for more data.
	    if found, sets got_header in the read_t, finds content_length,
	    and reads the rest of the message accordingly.

	parse_callback:
	    always frees recv buffer, uses read_t to modify user_pointer
	    on handle, and invokes the callback_t.

	    always frees read_t after the callback_t returns.

	    if error, translates to gram client error code and forwards
	    to userfunc with message == NULL

	    if not error, parses the recv buffer, forwards message and
	    parsing error code to userfunc.

        post_callback:                                         [CLIENT ONLY]
	    gets as argument an allocated read_t with userfunc ==
	    get_callback and userarg == the read_t itself.

	    if error, frees sendbuf, if read_t contains a monitor,
	    signals monitor "done with error". closes handle.

	    if write was successful, uses send buffer to recv an HTTP
	    message (replicate functionality of accept_callback)

        post_done_callback:                                    [CLIENT ONLY]
	    always signals monitor from read_t "done with success"
	    or "done with error".

	    always frees sendbuf, closes handle, and frees read_t.


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

#ifdef HAVE_STRING_H
#include <string.h>
#endif


#define my_malloc(t,n) globus_gram_http_malloc(t,n)
#define my_free(ptr)   globus_gram_http_free(ptr)


#if (GLOBUS_GRAM_HTTP_TRACE_MALLOC)

static globus_list_t * malloc_table = GLOBUS_NULL;

void *
globus_gram_http_real_malloc(globus_size_t asize, char * file, int line )
{
    void *  p = globus_libc_malloc(asize);
    globus_libc_printf("%s:%d : malloc size %ld, ptr = %x\n", 
		       strrchr(file,'/'), line, asize, p );
    globus_list_insert( &malloc_table,
			p );
    return p;
}

void
globus_gram_http_real_free(void * ptr, char * file, int line)
{
    globus_list_t *  list;
    globus_bool_t    done = GLOBUS_FALSE;

    globus_libc_printf("%s:%d : free ptr = %x\n", 
		       strrchr(file,'/'), line, ptr );

    list = malloc_table;
    while (!done && !globus_list_empty(list))
    {
	if (globus_list_first(list) == ptr)
	{
	    globus_free(globus_list_remove(&malloc_table,
					   list));
	    done = GLOBUS_TRUE;
	}
	else
	    list = globus_list_rest(list);
    }

    globus_assert(done == GLOBUS_TRUE);
}

static void
report_leaks()
{
    while(!globus_list_empty(malloc_table))
    {
	globus_libc_printf("failed to free buffer %x\n",
			   globus_list_first(malloc_table));
	globus_free(globus_list_remove(&malloc_table,
				       malloc_table ));
    }
}

#else

#define report_leaks() { }

#endif


#if 1
#define verbose(q) q
#else
#define verbose(q) { }
#endif

#define notice globus_libc_printf


typedef struct
{
    globus_bool_t                  got_header;
    globus_byte_t *                buf;
    globus_size_t                  n_read;
    globus_size_t                  n_total;
    globus_gram_http_callback_t    callback_func;
    void *                         callback_arg;
    void *                         user_pointer;
    globus_byte_t *                reply_buf;
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
				    globus_byte_t *               buf, 
				    globus_size_t *               bufsize) 
{ 
    *read_t = my_malloc(globus_gram_http_read_t,1);
    
    (*read_t)->got_header     = GLOBUS_FALSE; 
    (*read_t)->buf            = GLOBUS_NULL; 
    (*read_t)->n_read         = 0; 
    (*read_t)->n_total        = 0; 
    (*read_t)->callback_func  = (globus_gram_http_callback_t) func; 
    (*read_t)->callback_arg   = arg; 
    (*read_t)->user_pointer   = userptr; 
    (*read_t)->monitor        = monitor; 
    (*read_t)->reply_buf      = buf; 
    (*read_t)->reply_size     = bufsize;
}


#define start_http_read(res,status,handle) \
{ \
    if (!status->buf) \
	status->buf = my_malloc(globus_byte_t, GLOBUS_GRAM_HTTP_BUFSIZE); \
    {  \
	res = globus_io_register_read( handle, \
				       status->buf, \
				       2, \
				       2, \
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
globus_l_gram_http_post_done_callback( void * arg,
				       globus_io_handle_t * handle,
				       globus_result_t result,
				       globus_byte_t * buf,
				       globus_size_t nbytes );

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

    report_leaks();

    globus_i_gram_http_listeners = GLOBUS_NULL;
    return GLOBUS_SUCCESS;
}

/************************  callback functions  *****************************/

void
globus_gram_http_close_callback( void *                ignored,
				 globus_io_handle_t *  handle,
				 globus_result_t       result)
{
    globus_io_attr_t              attr;
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

    globus_io_tcp_get_attr(handle, &attr);
    globus_io_tcpattr_destroy(&attr);

    my_free(handle);
}


void
globus_gram_http_close_after_write( void * arg,
				    globus_io_handle_t * handle,
				    globus_result_t result,
				    globus_byte_t * buf,
				    globus_size_t nbytes)
{
    verbose(notice("close_after_write : res=%ld, buf=%x, handle=%d\n",
		   result, buf, handle->fd));

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
    
    verbose(notice("listen_callback : got connection on listener %d, res=%d\n",
		   listener_handle->fd, result));
    
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

	verbose(notice("listen_callback : accept=%d, handle=%d\n",
		       result,
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
    char                                   url[1000];
    int                                    job_status;
    int                                    failure_code;
    int                                    version;
    int                                    rc;

    verbose(notice("client_callback : listener %d is done\n", handle->fd));

    rc = errorcode;

    if (rc != GLOBUS_SUCCESS || nbytes <= 0)
    {
	job_status   = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
	failure_code = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }
    else if (4 != sscanf((char *) buf,
			 "%d %s %d %d",
			 &version,
			 url,
			 &job_status,
			 &failure_code))
    {
	job_status   = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
	failure_code = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }
    else if (version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	job_status   = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
	failure_code = GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH;
    }

    my_free(buf);
    
    globus_io_handle_get_user_pointer( handle,
				       (void *) userfunc );
    
    (*userfunc)(arg, url, job_status, failure_code);

    globus_io_register_close( handle,
			      globus_gram_http_close_callback,
			      GLOBUS_NULL );
}	      
 
 
void
globus_l_gram_http_parse_callback( void *                 read_t,
				   globus_io_handle_t *   handle,
				   globus_result_t        result,
				   globus_byte_t *        buf,
				   globus_size_t          nbytes)
{
    globus_gram_http_read_t *  status = (globus_gram_http_read_t *) read_t;
    globus_result_t            res    = result;
    int                        rc;
    globus_byte_t *            newbuf;
    globus_size_t              bufsize;

    verbose(notice("parse_callback : done read %ld on %d, res=%d total=%d\n",
		   nbytes, handle->fd, res, status->n_total));

    if (res != GLOBUS_SUCCESS)
    {
	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	newbuf = GLOBUS_NULL;
	bufsize = 0;
    }
    else
    {
	status->buf[status->n_total] = '\0';

	verbose(notice("parse_callback : http message =\n%s----\n", 
		       status->buf));

	rc = globus_gram_http_unframe( status->buf,
				       status->n_total,
				       &newbuf,
				       &bufsize );

	newbuf[bufsize] = 0;

	verbose(notice("parse_callback : unframe rc=%d, size=%d, msg =\n%s----\n",
		       rc, bufsize, (char *) newbuf ));


    }

    my_free(status->buf);

    globus_io_handle_set_user_pointer( handle,
				       status->user_pointer );

    (status->callback_func)( status->callback_arg,
			     handle,
			     newbuf,
			     bufsize,
			     rc );
    
    my_free(status);
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
    globus_size_t                chunk  = 2;
    globus_io_read_callback_t    func   = globus_l_gram_http_read_callback;
    globus_size_t                len;
    char *                       p;

    if (res == GLOBUS_SUCCESS)
    {
	status->n_read += nbytes;
	status->buf[status->n_read] = '\0';

	if (strstr((const char *)status->buf,"\n\n"))
	{
	    status->got_header = GLOBUS_TRUE;

	    sscanf((const char *)status->buf,"#HTTP %d\n\n", &len);

	    p = strchr((const char *)status->buf,'\n');
	    ++p;
	    ++p;

	    status->n_total = (globus_size_t)(p - (char *)(status->buf))+len;

	    chunk = status->n_total - status->n_read;
	    func  = globus_l_gram_http_parse_callback;
	}

	verbose(notice("read_callback : handle = %d, chunk=%ld read=%d total=%d\n",
		       handle->fd, chunk, status->n_read, status->n_total));

	res = globus_io_register_read( handle,
				       status->buf + status->n_read,
				       chunk,
				       chunk,
				       func,
				       read_t );
    }    
    
    if (res != GLOBUS_SUCCESS)
    {	
	my_free(status->buf);
	globus_io_register_close( handle,
				  globus_gram_http_close_callback,
				  GLOBUS_NULL);
	
	monitor_signal_done( status->monitor,
			     GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);

	my_free(status);
	return;
    }
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
		   result ));

    status = (globus_gram_http_read_t *) read_t;

    res = result;
    start_http_read(res,status,handle);
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
		   nbytes, handle->fd));

    status = (globus_gram_http_read_t *) read_t;

    res = result;
    status->buf = buf;

    start_http_read(res,status,handle);
}



void
globus_l_gram_http_post_done_callback( void *                read_t,
				       globus_io_handle_t *  handle,
				       globus_result_t       result,
				       globus_byte_t *       buf,
				       globus_size_t         nbytes)
{
    globus_gram_http_read_t *   status;
    globus_result_t             res;
    int                         rc;

    verbose(notice("post_done_callback : done writing %ld on %d\n",
		   nbytes, handle->fd));

    status = (globus_gram_http_read_t *) read_t;

    my_free(buf);

    res = globus_io_register_close( handle,
				    globus_gram_http_close_callback,
				    GLOBUS_NULL );

    if (res != GLOBUS_NULL || result != GLOBUS_NULL)
	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    
    monitor_signal_done( status->monitor, rc );

    my_free(status);
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
	(res == GLOBUS_SUCCESS)  )
    {
	bcopy(buf, status->reply_buf, nbytes);
	*status->reply_size = nbytes;
    }

    my_free(buf);

    if (errorcode != GLOBUS_SUCCESS)
	rc = errorcode;
    else if (res != GLOBUS_SUCCESS)
    	rc = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    else
	rc = GLOBUS_SUCCESS;

    monitor_signal_done(status->monitor, rc);
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
			GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP)) )
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

    /* acquire mutex */

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
	/* release mutex */
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
	/* release mutex */
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

    /* release mutex */
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
    globus_io_attr_t              attr;
    globus_gram_http_monitor_t *  monitor; 
    
    verbose(notice("connection_closed : handle %d is done\n", handle->fd));

    /* acquire mutex */
    globus_io_tcp_get_attr(handle, &attr);
    globus_io_tcpattr_destroy(&attr);

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

    verbose(notice("connect: res=%ld, got new handle %d\n", res, handle->fd));
    
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

    /* release mutex */
    return rc;
}



/************************** HTTP "framing" routines *******************/

int
globus_gram_http_frame(globus_byte_t *    msg,
		       globus_size_t      msgsize,
		       globus_byte_t **   framedmsg,
		       globus_size_t *    framedsize)
{
    char *  p;
    char *  buf;

    buf = (char *) my_malloc(globus_byte_t,GLOBUS_GRAM_HTTP_BUFSIZE);

    globus_libc_sprintf(buf, "#HTTP %d\n\n", msgsize);

    p = strchr(buf, '\n');
    ++p;
    ++p;

    bcopy(msg, p, msgsize);
    
    p[msgsize] = '\0';

    *framedsize = (globus_size_t)(p - buf) + msgsize;
    *framedmsg = (globus_byte_t *) buf;

    return GLOBUS_SUCCESS;
}


int
globus_gram_http_frame_error(int                 errorcode,
			     globus_byte_t **    msg,
			     globus_size_t *     msgsize)
{
    char *  buf;
    
    buf = (char *) my_malloc(globus_byte_t,GLOBUS_GRAM_HTTP_BUFSIZE);

    globus_libc_sprintf(buf, "HTTP 0\n\n");
    *msgsize = strlen(buf);
    *msg = (globus_byte_t *) buf;

    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unframe(globus_byte_t *    httpmsg,
			 globus_size_t      httpsize,
			 globus_byte_t **   message,
			 globus_size_t *    msgsize )
{
    char *  buf;
    char *  p;

    buf = (char *) my_malloc(globus_byte_t,GLOBUS_GRAM_HTTP_BUFSIZE);

    sscanf((char*) httpmsg, "#HTTP %d\n\n", msgsize);
    p = strchr((char *)httpmsg, '\n');
    ++p;
    ++p;

    bcopy(p, buf, *msgsize);

    buf[*msgsize] = '\0';
    *message = (globus_byte_t *) buf;

    return GLOBUS_SUCCESS;
}


/************************ "HTTP" post/get functions ************************/

int
globus_l_gram_http_post( char *                          url,
			 globus_io_attr_t *              attr,
			 globus_byte_t *                 message,
			 globus_size_t                   msgsize,
			 globus_gram_http_read_t *       status,
			 globus_io_write_callback_t      callback )
{
    globus_io_handle_t *            handle;
    globus_byte_t *                 sendbuf;
    globus_size_t                   sendbufsize;
    globus_result_t                 res;
    int                             rc;

    handle  = my_malloc(globus_io_handle_t,1);

    if ((rc = globus_gram_http_attach(url, handle, attr))
	|| (rc = globus_gram_http_frame( message,
					 msgsize,
					 &sendbuf,
					 &sendbufsize)))
    {
	my_free(handle);
	my_free(status);
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;	
    }

    verbose(notice("http_post : writing size=%d on %d\n%s----\n",
		   sendbufsize, handle->fd, (char *) sendbuf));
    
    res = globus_io_register_write( handle,
				    sendbuf,
				    sendbufsize,
				    callback,
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


int
globus_gram_http_post( char *                         url,
		       globus_io_attr_t *             attr,
		       globus_byte_t *                message,
		       globus_size_t                  msgsize,
		       globus_gram_http_monitor_t *   monitor )
{
    globus_gram_http_read_t *       status;

    if (monitor)
	initialize_monitor(monitor);
    globus_gram_http_initialize_read_t(
	&status,
	GLOBUS_NULL,              /* userfunc   */
	GLOBUS_NULL,              /* userarg    */
	GLOBUS_NULL,              /* userptr    */
	monitor,                  /* monitor    */
	GLOBUS_NULL,              /* replybuf   */
	GLOBUS_NULL );            /* replysize  */

    return globus_l_gram_http_post( url,
				    attr,
				    message,
				    msgsize,
				    status,
				    globus_l_gram_http_post_done_callback);
}


int
globus_gram_http_post_and_get( char *                         url,
			       globus_io_attr_t *             attr,
			       globus_byte_t *                message,
			       globus_size_t *                msgsize,
			       globus_gram_http_monitor_t *   monitor )
{
    globus_gram_http_read_t *       status;

    if (monitor)
	initialize_monitor(monitor);
    globus_gram_http_initialize_read_t(
	&status,
	(void *)globus_l_gram_http_get_callback,    /* userfunc   */
	GLOBUS_NULL,                                /* userarg    */
	GLOBUS_NULL,                                /* userptr    */
	monitor,                                    /* monitor    */
	message,                                    /* replybuf   */
	msgsize );                                  /* replysize  */

    status->callback_arg = (void *) status;

    return globus_l_gram_http_post( url,
				    attr,
				    message,
				    *msgsize,
				    status,
				    globus_l_gram_http_post_callback );

}

