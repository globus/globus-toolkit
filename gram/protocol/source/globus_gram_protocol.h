
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
 * attaches to URL, returns io handle 
 */
int
globus_gram_http_attach( char *                https_url,
			 globus_io_handle_t *  handle);


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
globus_gram_http_disallow_attach( char *  url );


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
 * user-supplied function that takes care of the client query and
 * generates a response.
 */
extern void
globus_gram_http_query_callback( void * arg,
				 globus_io_handle_t * handle,
				 globus_result_t result,
				 globus_byte_t * buf,
				 globus_size_t nbytes);

/*
 * sends a message "query", waits for an reply "response". This is
 * a version-checking wrapper around globus_gram_http_post_and_get()
 */
int
globus_gram_http_query_response(char *           https_url,
				globus_byte_t *  query,
				globus_byte_t *  response);

/* posts a message of maxsize GLOBUS_GRAM_HTTP_BUFSIZE, reuses buffer
   for response */
int
globus_gram_http_post_and_get( char *            url,
			       globus_byte_t *   message,
			       globus_size_t *   msgsize);


/* frame message with HTTP headers */
int
globus_gram_http_frame(globus_byte_t *    msg,
		       globus_size_t      msgsize,
		       globus_byte_t *    result);

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

