
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
#define GLOBUS_GRAM_HTTP_BUFSIZE     64000

typedef struct
{
    globus_mutex_t             mutex;
    globus_cond_t              cond;
    volatile globus_bool_t     done;
    volatile int               errorcode;
} globus_gram_http_monitor_t;

typedef void (*globus_gram_http_callback_t)( void  *               arg,
					     globus_io_handle_t *  handle,
					     globus_byte_t *       message,
					     globus_size_t         msgsize,
					     int                   errorcode);

#define GLOBUS_GRAM_HTTP_MODULE (&globus_i_gram_http_module)

extern globus_module_descriptor_t	globus_i_gram_http_module;

extern gss_cred_id_t globus_i_gram_http_credential;

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
globus_gram_http_allow_attach( unsigned short *             port,
			       char **                      host,
			       void *                       user_ptr,
			       globus_gram_http_callback_t  user_callback,
			       void *                       user_callback_arg);

/*
 * kills the listener at the specified URL.
 */
int
globus_gram_http_callback_disallow( char *  url );


/*
 * callback that frees the handle after close
 */
void
globus_gram_http_close_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_result_t       result);

/*
 * callback that frees the handle and sendbuf after write
 */
void
globus_gram_http_close_after_write( void *                arg,
				    globus_io_handle_t *  handle,
				    globus_result_t       result,
				    globus_byte_t *       buf,
				    globus_size_t         nbytes);

/*
 * callback to bridge between globus_io_read_callback_t and
 * globus_gram_client_callback_func_t
 */

void
globus_gram_http_client_callback( void *                arg,
				  globus_io_handle_t *  handle,
				  globus_byte_t *       buf,
				  globus_size_t         nbytes,
				  int                   errorcode );

int
globus_gram_http_post_and_get( char *                         url,
			       char *                         header_url,
			       globus_io_attr_t *             attr,
			       globus_byte_t *                request_message,
			       globus_size_t                  request_size,
			       globus_byte_t **               reply_message,
			       globus_size_t *                reply_size,
			       globus_gram_http_monitor_t *   monitor);


/* Frame a request message with HTTP headers */
int
globus_gram_http_frame_request(char *             uri,
			       char *             hostname,
			       globus_byte_t *    msg,
			       globus_size_t	  msgsize,
			       globus_byte_t **   framedmsg,
			       globus_size_t *	  framedsize);

/* Frame a reply message with HTTP headers */
int
globus_gram_http_frame_reply(int		   code,
			     globus_byte_t *    msg,
			     globus_size_t      msgsize,
			     globus_byte_t **   framedmsg,
			     globus_size_t *    framedsize);

/************************ "HTTP" pack/unpack functions *********************/

int
globus_gram_http_pack_job_request(
    const int               job_state_mask,
    const char *            callback_url,
    const char *            rsl,
    globus_byte_t **        query,
    globus_size_t *         querysize );


int
globus_gram_http_unpack_job_request(
    globus_byte_t *         query,
    globus_size_t           querysize,
    int  *                  job_state_mask,
    char **                 callback_url,
    char **                 description );


int
globus_gram_http_pack_job_request_reply(
    int                      status,
    char *                   job_contact,    /* may be null */
    globus_byte_t **         reply,
    globus_size_t *          replysize );


int
globus_gram_http_unpack_job_request_reply(
    globus_byte_t *          reply,
    globus_size_t            replysize,
    int *                    status,
    char **                  job_contact );


int
globus_gram_http_pack_status_request(
    char *              status_request,
    globus_byte_t **    query,
    globus_size_t *     querysize );


int
globus_gram_http_unpack_status_request(
    globus_byte_t *    query,
    globus_size_t      querysize,
    char **            status_requst );


int
globus_gram_http_pack_status_reply(
    int                 job_status,
    int                 failure_code,
    globus_byte_t **    reply,
    globus_size_t *     replysize );


int
globus_gram_http_unpack_status_reply(
    globus_byte_t *    reply,
    globus_size_t      replysize,
    int *              job_status,
    int *              failure_code );


int
globus_gram_http_pack_status_update_message(   
    char *                   job_contact,
    int                      status,            
    int                      failure_code,
    globus_byte_t **         reply,
    globus_size_t *          replysize );


int
globus_gram_http_unpack_status_update_message(
    globus_byte_t *          reply,
    globus_size_t            replysize,
    char **                  job_contact,
    int *                    status,
    int *                    failure_code );



EXTERN_C_END

#endif

