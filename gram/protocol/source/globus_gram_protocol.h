#if !defined(GLOBUS_GRAM_PROTOCOL_H)
#define GLOBUS_GRAM_PROTOCOL_H

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif


#include "globus_io.h"
#include "globus_gram_protocol_constants.h"

EXTERN_C_BEGIN

enum { GLOBUS_GRAM_PROTOCOL_VERSION = 2 };
enum { GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE = 64000 };
enum { GLOBUS_GRAM_PROTOCOL_PARAM_SIZE = 1024 };

typedef struct
{
    globus_mutex_t             mutex;
    globus_cond_t              cond;
    volatile globus_bool_t     done;
    volatile int               errorcode;
} globus_gram_protocol_monitor_t;

typedef void (*globus_gram_protocol_callback_t)( void  *               arg,
					     globus_io_handle_t *  handle,
					     globus_byte_t *       message,
					     globus_size_t         msgsize,
					     int                   errorcode);

#define GLOBUS_GRAM_PROTOCOL_MODULE (&globus_i_gram_protocol_module)

extern globus_module_descriptor_t	globus_i_gram_protocol_module;

extern gss_cred_id_t globus_i_gram_protocol_credential;

/*
 * creates a default set of TCP attributes (authentication with self, SSL
 * wrappers around messages)
 */
int
globus_gram_protocol_setup_attr( globus_io_attr_t *    attr );


/*
 * attaches to URL, returns io handle. If attr==NULL, the default set
 * will be used (see globus_gram_protocol_setup_attr)
 */
int
globus_gram_protocol_attach( char *                https_url,
			 globus_io_handle_t *  handle,
			 globus_io_attr_t *    attr );


/* 
 * sets up and registers a listener. returns port and host. user_ptr
 * must contain the read callback to be used. 
 */
int
globus_gram_protocol_allow_attach( unsigned short *             port,
			       char **                      host,
			       void *                       user_ptr,
			       globus_gram_protocol_callback_t  user_callback,
			       void *                       user_callback_arg);

/*
 * kills the listener at the specified URL.
 */
int
globus_gram_protocol_callback_disallow( char *  url );


/*
 * callback that frees the handle after close
 */
void
globus_gram_protocol_close_callback( void *                arg,
				 globus_io_handle_t *  handle,
				 globus_result_t       result);

/*
 * callback that frees the handle and sendbuf after write
 */
void
globus_gram_protocol_close_after_write( void *                arg,
				    globus_io_handle_t *  handle,
				    globus_result_t       result,
				    globus_byte_t *       buf,
				    globus_size_t         nbytes);


int
globus_gram_protocol_post_and_get( char *                         url,
			       char *                         header_url,
			       globus_io_attr_t *             attr,
			       globus_byte_t *                request_message,
			       globus_size_t                  request_size,
			       globus_byte_t **               reply_message,
			       globus_size_t *                reply_size,
			       globus_gram_protocol_monitor_t *   monitor);


/* Frame a request message with HTTP headers */
int
globus_gram_protocol_frame_request(char *             uri,
			       char *             hostname,
			       globus_byte_t *    msg,
			       globus_size_t	  msgsize,
			       globus_byte_t **   framedmsg,
			       globus_size_t *	  framedsize);

/* Frame a reply message with HTTP headers */
int
globus_gram_protocol_frame_reply(int		   code,
			     globus_byte_t *    msg,
			     globus_size_t      msgsize,
			     globus_byte_t **   framedmsg,
			     globus_size_t *    framedsize);

/************************ "HTTP" pack/unpack functions *********************/

int
globus_gram_protocol_pack_job_request(
    const int               job_state_mask,
    const char *            callback_url,
    const char *            rsl,
    globus_byte_t **        query,
    globus_size_t *         querysize );


int
globus_gram_protocol_unpack_job_request(
    globus_byte_t *         query,
    globus_size_t           querysize,
    int  *                  job_state_mask,
    char **                 callback_url,
    char **                 description );


int
globus_gram_protocol_pack_job_request_reply(
    int                      status,
    char *                   job_contact,    /* may be null */
    globus_byte_t **         reply,
    globus_size_t *          replysize );


int
globus_gram_protocol_unpack_job_request_reply(
    globus_byte_t *          reply,
    globus_size_t            replysize,
    int *                    status,
    char **                  job_contact );


int
globus_gram_protocol_pack_status_request(
    char *              status_request,
    globus_byte_t **    query,
    globus_size_t *     querysize );


int
globus_gram_protocol_unpack_status_request(
    globus_byte_t *    query,
    globus_size_t      querysize,
    char **            status_requst );


int
globus_gram_protocol_pack_status_reply(
    int                 job_status,
    int                 failure_code,
    int                 job_failure_code,
    globus_byte_t **    reply,
    globus_size_t *     replysize );


int
globus_gram_protocol_unpack_status_reply(
    globus_byte_t *    reply,
    globus_size_t      replysize,
    int *              job_status,
    int *              failure_code,
    int *              job_failure_code);


int
globus_gram_protocol_pack_status_update_message(   
    char *                   job_contact,
    int                      status,            
    int                      failure_code,
    globus_byte_t **         reply,
    globus_size_t *          replysize );


int
globus_gram_protocol_unpack_status_update_message(
    globus_byte_t *          reply,
    globus_size_t            replysize,
    char **                  job_contact,
    int *                    status,
    int *                    failure_code );

/*
 * RSL Parameters
 */
#define GLOBUS_GRAM_PROTOCOL_EXECUTABLE_PARAM               "executable"
#define GLOBUS_GRAM_PROTOCOL_ARGUMENTS_PARAM                "arguments"
#define GLOBUS_GRAM_PROTOCOL_ENVIRONMENT_PARAM              "environment"
#define GLOBUS_GRAM_PROTOCOL_DIR_PARAM                      "directory"
#define GLOBUS_GRAM_PROTOCOL_COUNT_PARAM                    "count"
#define GLOBUS_GRAM_PROTOCOL_STDIN_PARAM                    "stdin"
#define GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM                   "stdout"
#define GLOBUS_GRAM_PROTOCOL_STDERR_PARAM                   "stderr"
#define GLOBUS_GRAM_PROTOCOL_MAX_WALL_TIME_PARAM            "maxwalltime"
#define GLOBUS_GRAM_PROTOCOL_MAX_CPU_TIME_PARAM             "maxcputime"
#define GLOBUS_GRAM_PROTOCOL_MAX_TIME_PARAM                 "maxtime"
#define GLOBUS_GRAM_PROTOCOL_PARADYN_PARAM                  "paradyn"
#define GLOBUS_GRAM_PROTOCOL_JOB_TYPE_PARAM                 "jobtype"
#define GLOBUS_GRAM_PROTOCOL_MYJOB_PARAM                    "grammyjob"
#define GLOBUS_GRAM_PROTOCOL_QUEUE_PARAM                    "queue"
#define GLOBUS_GRAM_PROTOCOL_PROJECT_PARAM                  "project"
#define GLOBUS_GRAM_PROTOCOL_HOST_COUNT_PARAM               "hostcount"
#define GLOBUS_GRAM_PROTOCOL_DRY_RUN_PARAM                  "dryrun"
#define GLOBUS_GRAM_PROTOCOL_MIN_MEMORY_PARAM               "minmemory"
#define GLOBUS_GRAM_PROTOCOL_MAX_MEMORY_PARAM               "maxmemory"
#define GLOBUS_GRAM_PROTOCOL_START_TIME_PARAM               "starttime"
#define GLOBUS_GRAM_PROTOCOL_RESERVATION_HANDLE_PARAM       "reservationhandle"
#define GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM          "stdoutposition"
#define GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM          "stderrposition"
#define GLOBUS_GRAM_PROTOCOL_SAVE_STATE_PARAM               "savestate"
#define GLOBUS_GRAM_PROTOCOL_RESTART_PARAM                  "restart"
#define GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM         "twophase"
#define GLOBUS_GRAM_PROTOCOL_REMOTE_IO_URL_PARAM            "remoteiourl"

#define GLOBUS_GRAM_PROTOCOL_DEFAULT_STDIN                  "/dev/null"
#define GLOBUS_GRAM_PROTOCOL_DEFAULT_STDOUT                 "/dev/null"
#define GLOBUS_GRAM_PROTOCOL_DEFAULT_STDERR                 "/dev/null"
#define GLOBUS_GRAM_PROTOCOL_DEFAULT_MYJOB                  "collective"
#define GLOBUS_GRAM_PROTOCOL_DEFAULT_JOBTYPE                "multiple"
#define GLOBUS_GRAM_PROTOCOL_DEFAULT_DRYRUN                 "no"
#define GLOBUS_GRAM_PROTOCOL_DEFAULT_START_TIME             "none"

EXTERN_C_END

#endif

