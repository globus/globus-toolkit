
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


#define GLOBUS_GRAM_HTTP_TRACE_MALLOC 0


#if !(GLOBUS_GRAM_HTTP_TRACE_MALLOC)

#define globus_gram_http_malloc(type,count) \
    (type *) globus_libc_malloc(count*sizeof(type))
    
#define globus_gram_http_free(ptr) \
    if (ptr) globus_libc_free(ptr)

#else
    
#define globus_gram_http_malloc(type,n) \
    (type *) globus_gram_http_real_malloc(n*sizeof(type), __FILE__, __LINE__)
    
#define globus_gram_http_free(ptr) if (ptr) \
    globus_gram_http_real_free(ptr,__FILE__,__LINE__)

void*
globus_gram_http_real_malloc(globus_size_t asize, char * file, int line);

void
globus_gram_http_real_free(void * ptr, char * file, int line);

#endif

#define GRAM_GOES_HTTP 1
#define GLOBUS_GRAM_HTTP_BUFSIZE     64000

#define GLOBUS_GRAM_HTTP_QUERY_JOB_STATUS      1
#define GLOBUS_GRAM_HTTP_QUERY_JOB_CANCEL      2
#define GLOBUS_GRAM_HTTP_QUERY_JOB_REGISTER    3
#define GLOBUS_GRAM_HTTP_QUERY_JOB_UNREGISTER  4
#define GLOBUS_GRAM_HTTP_QUERY_JOB_START_TIME  5


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
globus_gram_http_post( char *                         url,
		       globus_io_attr_t *             attr,
		       globus_byte_t *                message,
		       globus_size_t                  msgsize,
		       globus_gram_http_monitor_t *   monitor);

int
globus_gram_http_post_and_get( char *                         url,
			       globus_io_attr_t *             attr,
			       globus_byte_t *                message,
			       globus_size_t *                msgsize,
			       globus_gram_http_monitor_t *   monitor);


/* I don't use these --frame functions right now.  --Steve A, 7/20/99 */
/* frame message with HTTP headers */
int
globus_gram_http_frame(globus_byte_t *    msg,
		       globus_size_t      msgsize,
		       globus_byte_t **   httpmsg,        /* gets allocated */
		       globus_size_t *    httpsize);

/* create HTTP error message */
int
globus_gram_http_frame_error(int                errortype,
                             globus_byte_t **   httpmsg,  /* gets allocated */
			     globus_size_t *    httpsize);


/* unframe HTTP message */
int
globus_gram_http_unframe(globus_byte_t *    httpmsg,
			 globus_size_t      httpsize,
			 globus_byte_t **   message,      /* gets allocated */
			 globus_size_t *    msgsize);

/* These functions pack and unpack GRAM requests into HTTP format
   They come in two forms right now, depending upon how they handle
   the memory for the HTTP request itself: the _fb forms accept a
   "fixed size buffer" as an IN/OUT argument, the _malloc forms
   allocate enough memory for their needs, memory which must be freed.  
   The _fb _pack_ forms would theoretically have the size of the
   allocated buffer passed to them as in the globus_size_t argument;
   they get it back chopped down to the actual amount of the buffer
   that was used.    In practice, though, the buffers are always of
   size GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE

   If the _fb_ forms wind up with the address of a pointer to the
   buffer passed to them, don't worry about it; that will be returned
   unscathed, and is being done for easier transition to the _malloc
   forms.  

   Also, the returned buffers, in practice, are null-terminated, so we
   don't even need to worry about the buffer_size returns. 

   TODO: We will soon standardize on the _malloc forms, but the _fb
   forms work with other existing code.  Obviously, as an interim
   step, the _fb versions should be written as wrappers around the
   malloc forms.  Obviously the malloc forms are more desirable, since
   we don't want to exceed buffer sizes.


   --Steve A  7/20/99
. */

int
globus_i_gram_pack_http_job_request_fb(
    globus_byte_t *query,	/* OUT */
    globus_size_t *query_size, /* OUT */
    int job_state_mask /* integer (IN) */,
    const char *callback_url /* user's state listener URL (IN) */,
    const char *description /* user's RSL (IN) */);

int
globus_i_gram_unpack_http_job_request_fb(
    globus_byte_t *query,
    globus_size_t *query_size,
    int *job_state_mask,
    char *client_contact_str,
    char *rsl_spec,
    globus_size_t *rsl_spec_size);

int
globus_i_gram_pack_http_job_request_result_fb(
    globus_byte_t *reply	/* OUT */,
    globus_size_t *reply_size	/* OUT */,
    int result_code		/* IN */,
    const char *graml_job_contact /* IN */);


/* pass in result_contactp as a pointer to a null character pointer.
   This will be malloced. */
int
globus_i_gram_unpack_http_job_request_result_fb(
    globus_byte_t *query,
    globus_size_t *query_size,
    int *result_status, /* GLOBUS_SUCCESS or a failure */
    char **result_contactp /* NULL if not SUCCESS */);

int
globus_i_gram_http_pack_status_message_fb(
    globus_byte_t *message	/* OUT */,
    globus_size_t *message_size /* OUT */,
    const char *graml_job_contact /* IN */,
    int status			/* IN */,
    int failure_code /* IN */);

#define globus_gram_http_version(x) (\
	/* TODO --steve A */ puts("Must replace this with" \
	" a test against the return code from *_unpack_*"), \
	GLOBUS_GRAM_PROTOCOL_VERSION)

EXTERN_C_END

#endif

