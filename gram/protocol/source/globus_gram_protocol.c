/* 
   gram_goes_http.c 

   convenience wrappers around globus_io.
*/

#include "globus_i_gram_http.h"       /* function decl.   */
#include "globus_i_gram_version.h"    /* GRAM version     */
#include "globus_gram_client.h"       /* GRAM error codes */

#include <globus_io.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#define my_malloc(type,count) (type *) globus_libc_malloc(count*sizeof(type))

#define notice globus_libc_printf
#if 1
#define verbose(q) q
#else
#define verbose(q) { }
#endif


#define GLOBUS_GRAM_HTTP_FREE_BUF        1
#define GLOBUS_GRAM_HTTP_FREE_HANDLE     2
#define GLOBUS_GRAM_HTTP_SIGNAL_MONITOR  4

#define monitor_signal_done(monitor,errcode) \
           { \
	       globus_mutex_lock(&monitor->mutex); \
               if (monitor->destruct_options & \
                   GLOBUS_GRAM_HTTP_SIGNAL_MONITOR) \
	       { \
		 monitor->done = GLOBUS_TRUE; \
	         monitor->errorcode = errcode; \
                 monitor->destruct_options -= GLOBUS_GRAM_HTTP_SIGNAL_MONITOR;\
	         globus_cond_signal(&monitor->cond); \
	       } \
	       globus_mutex_unlock(&monitor->mutex); \
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
globus_gram_http_close_listener_callback( void *                arg,
					  globus_io_handle_t *  handle,
					  globus_result_t       result);


void
globus_gram_http_close_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_result_t       result);

void
globus_gram_http_post_callback( void * arg,
				globus_io_handle_t * handle,
				globus_result_t result,
				globus_byte_t * buf,
				globus_size_t nbytes);

void
globus_gram_http_get_callback( void * arg,
			       globus_io_handle_t * handle,
			       globus_result_t result,
			       globus_byte_t * buf,
			       globus_size_t nbytes);



/************************** activation / deactivation ********************/

/*
 * NOTE: These functions are called from the the gram_client module
 * activation/deactivation.
 */

int
globus_gram_http_activate()
{
    /* initialize a bunch of mutexes */
}

int
globus_gram_http_deactivate()
{
    globus_i_gram_http_listener_t *  listener;
    
    /* close open listeners */

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
				 globus_gram_http_close_listener_callback,
				 GLOBUS_NULL);

	globus_libc_free(listener);
    }

    globus_i_gram_http_listeners = GLOBUS_NULL;

    /* kill a bunch of mutexes */
}


/*********************     callback functions *****************************/

void
globus_gram_http_close_listener_callback( void *                arg,
					  globus_io_handle_t *  handle,
					  globus_result_t       result)
{
    globus_io_attr_t              attr;
    void *                        usr_ptrs;

    verbose(notice("close_callback : listener %d is done\n", handle->fd));

    /* acquire mutex */
    globus_io_tcp_get_attr(handle, &attr);
    globus_io_tcpattr_destroy(&attr);
    globus_io_handle_get_user_pointer( handle,
				       &usr_ptrs );
    globus_libc_free(usr_ptrs);
    /* release mutex */

    globus_libc_free(handle);
}


void
globus_gram_http_client_callback( void * arg,
				  globus_io_handle_t * handle,
				  globus_result_t result,
				  globus_byte_t * buf,
				  globus_size_t nbytes)
{
    globus_gram_client_callback_func_t *   userfunc;
    char                                   message[GLOBUS_GRAM_HTTP_BUFSIZE];
    char                                   url[1000];
    globus_size_t                          msgsize;
    int                                    job_status;
    int                                    failure_code;
    int                                    version;
    int                                    rc;

    verbose(notice("client_callback : listener %d is done\n", handle->fd));

    /* acquire mutex */

    globus_io_handle_get_user_pointer( handle,
				       (void **) userfunc );

    rc = globus_gram_http_unframe( buf,
				   nbytes,
				   (globus_byte_t *) message,
				   &msgsize);

    if (rc != GLOBUS_SUCCESS || msgsize <= 0)
    {
	job_status   = GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED;
	failure_code = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }
    else if (3 != sscanf(message,
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

    (*userfunc)(arg, url, job_status, failure_code);

    /* release mutex */
}	      


void
globus_gram_http_accept_callback( void *                arg,
				  globus_io_handle_t *  handle,
				  globus_result_t       result )
{
    globus_byte_t *            message;
    globus_io_handle_t *       listener_handle;
    void *                     user_ptr;
    globus_io_read_callback_t  user_func;
    void *                     user_arg;
    void *                     my_user_ptr;
    void **                    argv;

    verbose(notice("accept_callback : handle = %d, res = %ld\n",
		   handle->fd,
		   result ));

    /* acquire mutex */

    listener_handle = (globus_io_handle_t *) arg;
	
    if (result == GLOBUS_SUCCESS)
    {
	globus_io_handle_get_user_pointer(listener_handle,
					  &my_user_ptr);

	argv = (void **) my_user_ptr;
	user_ptr  = argv[0];  /* user_ptr */
	user_func = (globus_io_read_callback_t) argv[1];  /* user_callback */
	user_arg  = argv[2];  /* user_callback_arg  */

	globus_io_handle_set_user_pointer(handle,
					  user_ptr );

	message = my_malloc(globus_byte_t,GLOBUS_GRAM_HTTP_BUFSIZE);
	
	result = globus_io_register_read( handle,
					  message,
					  GLOBUS_GRAM_HTTP_BUFSIZE,
					  GLOBUS_GRAM_HTTP_BUFSIZE,
					  user_func,
					  user_arg  );
    }

    /* release mutex */
}


void
globus_gram_http_listen_callback( void *                ignored,
				  globus_io_handle_t *  listener_handle,
				  globus_result_t       result )
{
    globus_io_handle_t *  handle;

    verbose(notice("listen_callback : got connection on listener %d\n",
		   handle->fd));

    if (result == GLOBUS_SUCCESS)
    {
	/* acquire mutex */
	handle = my_malloc(globus_io_handle_t,1);

	result = globus_io_tcp_register_accept(
	             listener_handle,
		     GLOBUS_NULL,
		     handle,
		     globus_gram_http_accept_callback,
		     (void *) listener_handle);
	/* release mutex */
    }

    /* reregister */
    result = globus_io_tcp_register_listen( listener_handle,
					    globus_gram_http_listen_callback,
					    GLOBUS_NULL );
}


/************************* help function *********************************/

int
globus_l_gram_http_setup_attr( globus_io_attr_t *  attr)
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
globus_gram_http_allow_attach( unsigned short *           port,
			       char **                    host,
			       void *                     user_ptr,
			       globus_io_read_callback_t  user_callback,
			       void *                     user_arg )
{
    int                                    rc;
    char                                   hostnamebuf[256];
    globus_result_t                        res;
    globus_io_handle_t *                   handle;
    globus_io_attr_t                       attr;
    globus_io_secure_authorization_data_t  auth_data;
    globus_i_gram_http_listener_t *        new_listener;
    void **                                buf;

    /* acquire mutex */

    rc = globus_l_gram_http_setup_attr( &attr );
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
	globus_libc_free(handle);
	/* release mutex */
	return rc;
    }

    buf = my_malloc(void *, 3);

    buf[0] = user_ptr;
    buf[1] = (void *) user_callback;
    buf[2] = user_arg;

    globus_io_handle_set_user_pointer(handle, (void *) buf);

    res = globus_io_tcp_register_listen( handle,
					 globus_gram_http_listen_callback,
					 GLOBUS_NULL );
    if (res != GLOBUS_SUCCESS)
    {
	globus_object_t *  err = globus_error_get(res);
	globus_object_free(err);
	globus_io_tcpattr_destroy(&attr);
	globus_libc_free(handle);
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

    /* acquire mutex */

    handle = GLOBUS_NULL;

    /* get port number from url */
    rc = globus_url_parse(httpsurl, &url);
    if (rc == GLOBUS_SUCCESS)
	port = url.port;
    globus_url_destroy(&url);
    if (rc != GLOBUS_SUCCESS)
    {
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
    }

    /* find listener with help of port and close it */
    list = globus_i_gram_http_listeners;
    while (!handle && !globus_list_empty(list))
    {
	listener = globus_list_first(list);
	if (listener->port = port)
	{
	    handle = listener->handle;
	    globus_free(globus_list_remove(&globus_i_gram_http_listeners,
					   list));
	}
	else
	    list = globus_list_rest(list);
    }

    if (!handle)
    {
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
    }

    globus_io_register_close( handle,
			      globus_gram_http_close_listener_callback,
			      GLOBUS_NULL );
    
    /* release mutex */
    return GLOBUS_SUCCESS;
}



/**************************** "HTTP" callbacks ************************/


void
globus_gram_http_close_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_result_t       result)
{
    globus_io_attr_t              attr;
    globus_gram_http_monitor_t *  monitor; 
    
    verbose(notice("close_callback : handle %d is done\n", handle->fd));

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

    globus_mutex_lock(&monitor->mutex);    
    if (monitor->destruct_options & GLOBUS_GRAM_HTTP_FREE_HANDLE)
    {
	globus_libc_free(handle);
    }
    globus_mutex_unlock(&monitor->mutex);
}



void
globus_gram_http_close_after_read_or_write( void * arg,
					    globus_io_handle_t * handle,
					    globus_result_t result,
					    globus_byte_t * buf,
					    globus_size_t nbytes)
{
    globus_gram_http_monitor_t *  monitor; 

    verbose(notice("close_after_read_or_write : buf=%x,  handle=%d\n",
		   buf, handle->fd));

    /* acquire mutex */

    globus_io_handle_get_user_pointer( handle,
				       (void **) &monitor );

    if (result != GLOBUS_SUCCESS)
    {
	monitor_signal_done(monitor,GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    globus_mutex_lock(&monitor->mutex);
    if (monitor->destruct_options & GLOBUS_GRAM_HTTP_FREE_BUF)
	globus_libc_free(buf);
    globus_mutex_unlock(&monitor->mutex);

    /* release mutex */

    globus_io_register_close(handle,
			     globus_gram_http_close_callback,
			     arg);
}


void
globus_gram_http_post_callback( void * messagebuf,
				globus_io_handle_t * handle,
				globus_result_t result,
				globus_byte_t * buf,
				globus_size_t nbytes)
{
    globus_gram_http_monitor_t *   monitor;
    globus_result_t                res;

    verbose(notice("http_post_callback : done writing %x on %d\n",
		   sendbuf,
		   handle->fd));

    /* acquire mutex */

    globus_io_handle_get_user_pointer( handle,
				       (void **) &monitor );

    if (result != GLOBUS_SUCCESS)
    {
	monitor_signal_done(monitor, GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    res = globus_io_register_read( handle,
				   buf,
				   GLOBUS_GRAM_HTTP_BUFSIZE,
				   GLOBUS_GRAM_HTTP_BUFSIZE,
				   globus_gram_http_get_callback,
				   messagebuf);

    if (res != GLOBUS_SUCCESS)
    {
	monitor_signal_done(monitor, GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }

    /* release mutex */

}


void
globus_gram_http_get_callback( void * arg,
			       globus_io_handle_t * handle,
			       globus_result_t result,
			       globus_byte_t * buf,
			       globus_size_t nbytes)
{
    globus_gram_http_monitor_t *   monitor;
    void **                        p;
    int                            rc;

    verbose(notice("http_get_callback : done read %x on %d\n",
		   sendbuf,
		   handle->fd));

    /* acquire mutex */

    globus_io_handle_get_user_pointer( handle,
				       (void **) &monitor );

    if (result != GLOBUS_SUCCESS)
    {
	monitor_signal_done(monitor, GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED);
    }
    else
    {
	p = (void **) arg;

	rc = globus_gram_http_unframe( buf,
				       nbytes,
				       (globus_byte_t *) p[0],
				       (globus_size_t *) p[1] );

	if (!rc)
	    monitor_signal_done(monitor, rc);
    }

    globus_mutex_lock(&monitor->mutex);
    if (monitor->destruct_options & GLOBUS_GRAM_HTTP_FREE_BUF)
	globus_libc_free(buf);
    globus_mutex_unlock(&monitor->mutex);

    /* release mutex */

    verbose(notice("http_post_and_get : handle %d done, closing\n",
		   handle->fd));
	
    globus_io_register_close(handle,
			     globus_gram_http_close_callback,
			     GLOBUS_NULL);
}


/********************* attaches to a URL, returns globus_io handle ******/

int
globus_gram_http_attach( char *               job_contact,
			 globus_io_handle_t * handle)
{
    int                  rc;
    globus_result_t      res;
    globus_io_attr_t     attr;
    globus_url_t         url;

    /* acquire mutex */

    /* dissect the job_contact URL */
    rc = globus_url_parse(job_contact, &url);
    if (rc != GLOBUS_SUCCESS)
    {
	globus_url_destroy(&url);
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT;
    }

    rc = globus_l_gram_http_setup_attr( &attr );
    if (rc != GLOBUS_SUCCESS)
    {
	globus_url_destroy(&url);
	/* release mutex */
	return rc;
    }

    res = globus_io_tcp_connect( url.host,
				 url.port,
				 &attr,
				 handle );
    
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

    globus_io_tcpattr_destroy(&attr);
    globus_url_destroy(&url);

    /* release mutex */
    return rc;
}



/************************** HTTP "framing" routines *******************/

int
globus_gram_http_frame(globus_byte_t *    msg,
		       globus_size_t      msgsize,
		       globus_byte_t *    framedmsg,
		       globus_size_t *    framedsize)
{
    globus_libc_sprintf((char *) framedmsg,
			"#HTTP <version and some other info>\n" 
			"#content-type: text/ascii\n" 
			"#content-length: %d\n\n", 
			msgsize);

    *framedsize = strlen((char *)framedmsg) + msgsize;

    strncpy((char *)(framedmsg) + strlen((char *)framedmsg), 
	    (char *) msg, 
	    msgsize);

    return GLOBUS_SUCCESS;
}


int
globus_gram_http_frame_error(globus_byte_t *    msg)
{
    globus_libc_sprintf((char *)msg, 
			"#HTTP ERROR <version and some other info>\n" 
			"#content-type: text/ascii\n" 
			"#content-length: 0\n\n" );
    
    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unframe(globus_byte_t *    httpmsg,
			 globus_size_t      httpsize,
			 globus_byte_t *    message,
			 globus_size_t *    msgsize )
{
    globus_bool_t     found;
    char *            p;
    char *            end;
    int               s;
    int               err;

    /* acquire mutex */

    found         = GLOBUS_FALSE;
    p             = (char *) httpmsg; 
    end           = p + httpsize;
    s             = 0;
    err           = GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    p[httpsize-1] = '\0';  /* ensure strchr() won't run out of bounds... */
    *msgsize      = 0;

    while (!found && (p < end))
    { 
	if (0 == strncmp(p,"#HTTP ERROR", strlen("#HTTP ERROR")))
	{
	    verbose(notice("ouch, HTTP error\n"));
	    /* release mutex */
	    return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
	}
	found = (1 == sscanf(p,"#content-length: %d", &s));
	verbose(notice("buf %x : found: %d\np:\n%s\n", httpmsg, found,p));
	p = strchr(p,'\n');
	if (!p) 
	    p = end;
	else 
	    ++p; 
    }

    if (found)
    {
	err = GLOBUS_SUCCESS;
	s = GLOBUS_MIN( s, GLOBUS_GRAM_HTTP_BUFSIZE-1);
	*msgsize = s;
	strncpy((char *)message, ++p /* another '\n' */ , s);
	message[s] = '\0';
    }

    /* release mutex */
    return err;
}


/************************ "HTTP" post/get functions ************************/

int
globus_l_gram_http_post( char *                         url,
			 globus_byte_t *                message,
			 globus_size_t                  msgsize,
			 globus_gram_http_monitor_t *   monitor,
			 globus_io_write_callback_t     callback,
			 void *                         callback_arg)
{
    int                             rc;
    globus_result_t                 res;
    globus_io_handle_t *            handle;
    globus_byte_t *                 sendbuf;
    globus_size_t                   sendbufsize;
    int                             version;

    /* acquire mutex */

    handle  = my_malloc(globus_io_handle_t,1);
    sendbuf = my_malloc(globus_byte_t, GLOBUS_GRAM_HTTP_BUFSIZE);

    if ( (rc = globus_gram_http_frame( message,
				       msgsize,
				       sendbuf,
				       &sendbufsize))
	 || (rc = globus_gram_http_attach(url, handle)) )
    {
	globus_libc_free(sendbuf);
	/* release mutex */
	return rc;
    }

    globus_mutex_lock(&monitor->mutex);
    monitor->destruct_options = 0;
    monitor->destruct_options |= GLOBUS_GRAM_HTTP_FREE_BUF;
    monitor->destruct_options |= GLOBUS_GRAM_HTTP_FREE_HANDLE;
    monitor->destruct_options |= GLOBUS_GRAM_HTTP_SIGNAL_MONITOR;
    globus_mutex_unlock(&monitor->mutex);

    globus_io_handle_set_user_pointer( handle,
				       (void *) monitor );

    verbose(notice("http_post : writing on %d\n%s----\n",
		   handle->fd,
		   (char *) sendbuf));

    res = globus_io_register_write( handle,
				    sendbuf,
				    sendbufsize,
				    callback,
				    callback_arg );

    /* release mutex */
    return GLOBUS_SUCCESS;
}


int
globus_gram_http_post( char *                         url,
		       globus_byte_t *                message,
		       globus_size_t                  msgsize,
		       globus_gram_http_monitor_t *   monitor)
{
    return globus_l_gram_http_post( url,
				    message,
				    msgsize,
				    monitor,
				    globus_gram_http_close_after_read_or_write,
				    GLOBUS_NULL );
}



int
globus_gram_http_post_and_get( char *                         url,
			       globus_byte_t *                message,
			       globus_size_t *                msgsize,
			       globus_gram_http_monitor_t *   monitor)
{
    void **    p;

    /* acquire mutex */

    p = my_malloc(void*, 2);

    p[0] = (void *) message;
    p[1] = (void *) msgsize;

    /* release mutex */

    return globus_l_gram_http_post( url,
				    message,
				    *msgsize,
				    monitor,
				    globus_gram_http_post_callback,
				    (void *) p );
}


