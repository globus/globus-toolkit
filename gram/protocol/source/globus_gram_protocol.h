
#if !defined(_GLOBUS_I_GRAM_HTTP_H)
    #define _GLOBUS_I_GRAM_HTTP_H

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN

#include <globus_io.h>

#define GRAM_GOES_HTTP 1
#define GLOBUS_GRAM_HTTP_BUFSIZE     1024

#define GLOBUS_GRAM_HTTP_QUERY_JOB_STATUS      1
#define GLOBUS_GRAM_HTTP_QUERY_JOB_CANCEL      2
#define GLOBUS_GRAM_HTTP_QUERY_JOB_REGISTER    3
#define GLOBUS_GRAM_HTTP_QUERY_JOB_UNREGISTER  4
#define GLOBUS_GRAM_HTTP_QUERY_JOB_START_TIME  5


typedef struct
{
    globus_mutex_t           mutex;
    globus_cond_t            cond;
    volatile globus_bool_t   done;
    volatile int             errorcode;
    volatile void *          buf;
} globus_gram_http_monitor_t;


/*
 * part of GRAM_CLIENT activation
 */
int
globus_gram_http_activate();

/*
 * part of GRAM_CLIENT deactivation 
 */
int
globus_gram_http_deactivate();


/*
 * creates a default set of TCP attributes (authentication with self, SSL
 * wrappers around messages)
 */
int
globus_gram_http_setup_attr( globus_io_attr_t *    attr );


/*
 * attaches to URL, returns io handle. If attr==NULL, the default set
 * will be used (see globus_gram_http_setup_attr)
 */
int
globus_gram_http_attach( char *                https_url,
			 globus_io_handle_t *  handle,
			 globus_io_attr_t *    attr );


/* 
 * sets up and registers a listener. returns port and host. user_ptr
 * must contain the read callback to be used. 
 */
int
globus_gram_http_allow_attach( unsigned short *           port,
			       char **                    host,
			       void *                     user_ptr,
			       globus_io_read_callback_t  user_callback,
			       void *                     user_callback_arg);


/*
 * kills the listener at the specified URL.
 */
int
globus_gram_http_callback_disallow( char *  url );


/*
 * two callbacks that frees the handle struct after close
 */
void
globus_gram_http_close_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_result_t       result);

void
globus_gram_http_close_after_read_or_write( void * arg,
					    globus_io_handle_t * handle,
					    globus_result_t result,
					    globus_byte_t * buf,
					    globus_size_t nbytes);

/*
 * callback to bridge between globus_io_read_callback_t and
 * globus_gram_client_callback_func_t
 */

void
globus_gram_http_client_callback( void * arg,
				  globus_io_handle_t * handle,
				  globus_result_t result,
				  globus_byte_t * buf,
				  globus_size_t nbytes);


int
globus_gram_http_post( char *                         url,
		       globus_byte_t *                message,
		       globus_size_t                  msgsize,
		       globus_gram_http_monitor_t *   monitor);

int
globus_gram_http_post_and_get( char *                         url,
			       globus_byte_t *                message,
			       globus_size_t *                msgsize,
			       globus_gram_http_monitor_t *   monitor);


/* frame message with HTTP headers */
int
globus_gram_http_frame(globus_byte_t *    msg,
		       globus_size_t      msgsize,
		       globus_byte_t *    httpmsg,
		       globus_size_t *    httpsize);

/* create HTTP error message */
int
globus_gram_http_frame_error(globus_byte_t * msg);


/* unframe HTTP message */
int
globus_gram_http_unframe(globus_byte_t *    httpmsg,
			 globus_size_t      httpsize,
			 globus_byte_t *    message,
			 globus_size_t *    msgsize);

EXTERN_C_END

#endif

