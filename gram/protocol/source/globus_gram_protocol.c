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

#define my_malloc(type) (type *) globus_libc_malloc(sizeof(type))

#define notice globus_libc_printf
#if 0
#define verbose(q) q
#else
#define verbose(q) { }
#endif

/********************      internal list over active listeners ************/
typedef struct
{
    unsigned short        port;
    globus_io_handle_t *  handle;
} globus_i_gram_http_listener_t;

static globus_list_t *  globus_i_gram_http_listeners = GLOBUS_NULL;

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
				 globus_gram_http_close_callback,
				 GLOBUS_NULL);

	globus_libc_free(listener);
    }

    globus_i_gram_http_listeners = GLOBUS_NULL;

    /* kill a bunch of mutexes */
}


/*********************     callback functions *****************************/

void
globus_gram_http_close_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_result_t       result)
{
    globus_io_attr_t   attr;
    void *             usr_ptrs;
    
    verbose(notice("close_callback : handle %d is done\n", handle->fd));

    /* acquire mutex */
    globus_io_tcp_get_attr(handle, &attr);
    globus_io_tcpattr_destroy(&attr);
    if (globus_io_get_handle_type(handle) ==
	GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER )
    {
	globus_io_handle_get_user_pointer( handle,
					   &usr_ptrs );
	globus_libc_free(usr_ptrs);
    }
    /* release mutex */
    globus_libc_free(handle);
}


void
globus_gram_http_close_after_read_or_write( void * arg,
					    globus_io_handle_t * handle,
					    globus_result_t result,
					    globus_byte_t * buf,
					    globus_size_t nbytes)
{
    verbose(notice("close_after_read_or_write : handle=%d\n", handle->fd));

    globus_io_register_close(handle,
			     globus_gram_http_close_callback,
			     arg);
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

	message = (globus_byte_t *)
	             globus_libc_malloc(GLOBUS_GRAM_HTTP_BUFSIZE);
	
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

    if (result == GLOBUS_SUCCESS)
    {
	/* acquire mutex */
	handle = my_malloc(globus_io_handle_t);

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
globus_gram_http_setup_attr( globus_io_attr_t *  attr)
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

    rc = globus_gram_http_setup_attr( &attr );
    if (rc != GLOBUS_SUCCESS)
    {
	/* release mutex */
	return rc;
    }

    handle = my_malloc(globus_io_handle_t);

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

    buf = (void **) globus_libc_malloc(3 * sizeof(void *));

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
	new_listener = my_malloc(globus_i_gram_http_listener_t);
	new_listener->port   = *port;
	new_listener->handle = handle;
	globus_list_insert(&globus_i_gram_http_listeners, new_listener);
    }

    globus_io_tcpattr_destroy(&attr);

    /* release mutex */
    return GLOBUS_SUCCESS;
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

    rc = globus_gram_http_setup_attr( &attr );
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



/******************** locates listener at URL and closes it ************/

int
globus_gram_http_disallow_attach(char *   httpsurl)
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
			      globus_gram_http_close_callback,
			      GLOBUS_NULL );
    
    /* release mutex */
    return GLOBUS_SUCCESS;
}


/************************** HTTP "framing" routines *******************/

int
globus_gram_http_frame(globus_byte_t *    msg,
		       globus_size_t      msgsize,
		       globus_byte_t *    result)
{
    globus_libc_sprintf((char *)result, 
			"#HTTP <version and some other info>\n" 
			"#content-type: text/ascii\n" 
			"#content-length: %d\n", 
			msgsize); 

    strncpy((char *)(result) + strlen((char *)result), 
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
			"#content-length: 0\n" );
    
    return GLOBUS_SUCCESS;
}


int
globus_gram_http_unframe(globus_byte_t *    httpmsg,
			 globus_size_t      httpsize,
			 globus_byte_t *    message,
			 globus_size_t *    msgsize)
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
    *msgsize      = 0;
    p[httpsize-1] = '\0';  /* ensure strchr() won't run out of bounds... */

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
	*msgsize = (globus_size_t) s;
	strncpy((char *)message, p, s);
	message[s] = '\0';
    }

    /* release mutex */
    return err;
}


/************************ "HTTP" post/get functions ************************/


int
globus_gram_http_post( char *           url,
		       globus_byte_t *  message,
		       globus_size_t    msgsize )
{
    int                             rc;
    globus_result_t                 res;
    globus_io_handle_t *            handle;
    globus_byte_t                   sendbuf[GLOBUS_GRAM_HTTP_BUFSIZE];
    globus_size_t                   bytes_processed;
    int                             version;

    /* acquire mutex */

    handle = my_malloc(globus_io_handle_t);

    if ( (rc = globus_gram_http_attach(url, handle))
	 || (rc = globus_gram_http_frame( message,
					  msgsize,
					  sendbuf )) )
    {
	/* release mutex */
	return rc;
    }

    verbose(notice("http_post : writing on %d\n%s----\n",
		   handle->fd,
		   (char *) sendbuf));

    res = globus_io_register_write( handle,
				    sendbuf,
				    GLOBUS_GRAM_HTTP_BUFSIZE,
				    globus_gram_http_close_after_read_or_write,
				    GLOBUS_NULL );
}


int
globus_gram_http_post_and_get( char *           url,
			       globus_byte_t *  message,
			       globus_size_t *  msgsize)
{
    int                             rc;
    globus_result_t                 res;
    globus_io_handle_t *            handle;
    globus_byte_t                   sendbuf[GLOBUS_GRAM_HTTP_BUFSIZE];
    globus_size_t                   bytes_processed;
    int                             version;

    /* acquire mutex */

    handle = my_malloc(globus_io_handle_t);

    if ( (rc = globus_gram_http_attach(url, handle))
	 || (rc = globus_gram_http_frame( message,
					  *msgsize,
					  sendbuf )) )
    {
	/* release mutex */
	return rc;
    }

    verbose(notice("http_post_and_get : writing on %d\n%s----\n",
		   handle->fd,
		   (char *) sendbuf));

    res = globus_io_write( handle,
			   sendbuf,
			   GLOBUS_GRAM_HTTP_BUFSIZE,
			   &bytes_processed );

    if ((res != GLOBUS_SUCCESS) ||
	(bytes_processed != GLOBUS_GRAM_HTTP_BUFSIZE)) 
    {
	verbose(notice("http_post_and_get : error on %d, closing\n",
		       handle->fd));

	globus_io_register_close( handle,
				  globus_gram_http_close_callback,
				  GLOBUS_NULL );
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }

    verbose(notice("http_post_and_get : reading %x on %d\n",
		   sendbuf,
		   handle->fd));

    res = globus_io_read( handle,
			  sendbuf,
			  GLOBUS_GRAM_HTTP_BUFSIZE,
			  GLOBUS_GRAM_HTTP_BUFSIZE,
			  &bytes_processed );

    if ((res != GLOBUS_SUCCESS) ||
	(bytes_processed != GLOBUS_GRAM_HTTP_BUFSIZE))
    {
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }

    verbose(notice("http_post_and_get : handle %d done, closing\n",
		   handle->fd));

    globus_io_register_close(handle,
			     globus_gram_http_close_callback,
			     GLOBUS_NULL);

    rc = globus_gram_http_unframe( sendbuf,
				   bytes_processed,
				   message,
				   msgsize);
    /* release mutex */
    verbose(notice("http_post_and_get : returning  %d\n", rc));
    return rc;
}


/*
 * This is a wrapper around the post_and_get function.  It adds GRAM
 * version checking.
 */

int
globus_gram_http_query_response(char *           https_url,
				globus_byte_t *  query,
				globus_byte_t *  response)
{
    int                             rc;
    globus_byte_t                   message[GLOBUS_GRAM_HTTP_BUFSIZE];
    globus_size_t                   msgsize;
    int                             version;
    char *                          p;

    /* OLLE: query and response are assumed to be strings.

       The protocol:
       establish secure connection to job_contact, post a string
       {GLOBUS_GRAM_PROTOCOL_VERSION,query}
       then block on reply from the job manager containing
       {GLOBUS_GRAM_PROTOCOL_VERSION,status}
       */

    /* acquire mutex */

    globus_libc_sprintf( (char *) message,
			 "%d\n%s\n",
			 GLOBUS_GRAM_PROTOCOL_VERSION,
			 (char *) query );

    msgsize = (globus_size_t) strlen((char *) message);

    rc = globus_gram_http_post_and_get(https_url,
				       message,
				       &msgsize );
    if (rc != GLOBUS_SUCCESS )
    {
	verbose(notice("query_response : got rc = %d\n", rc));
	/* release mutex */
	return rc;
    }

    if ( (1!=sscanf((char *) message, "%d\n", &version))
	 || (version != GLOBUS_GRAM_PROTOCOL_VERSION) )
    {
	/* release mutex */
	return GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED;
    }

    p = strchr((char *)(message),'\n');
    ++p;

    strcpy((char *)response, p);

    /* release mutex */
    return GLOBUS_SUCCESS;
}

