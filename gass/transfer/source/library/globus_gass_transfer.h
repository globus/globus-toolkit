/******************************************************************************
globus_gass_transfer.h
 
Description:
    This header defines the GASS transfer library interface
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_H
#define GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#define GLOBUS_GASS_TRANSFER 1

#include "globus_common.h"
#include "globus_handle_table.h"
#include "globus_gass_common.h"
#include "globus_io.h"

EXTERN_C_BEGIN

typedef globus_handle_t globus_gass_transfer_request_t;
typedef globus_handle_t globus_gass_transfer_listener_t;

typedef globus_object_t * globus_gass_transfer_requestattr_t;
typedef globus_object_t * globus_gass_transfer_listenerattr_t;

/* Module Specific Types */
typedef enum
{
    GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID,
    GLOBUS_GASS_TRANSFER_REQUEST_TYPE_GET,
    GLOBUS_GASS_TRANSFER_REQUEST_TYPE_PUT,
    GLOBUS_GASS_TRANSFER_REQUEST_TYPE_APPEND
} globus_gass_transfer_request_type_t;

/* globus_gass_transfer_request_status will return only the
 * "visible" subset:
 *     GLOBUS_GASS_TRANSFER_REQUEST_INVALID
 *     GLOBUS_GASS_TRANSFER_REQUEST_STARTING
 *     GLOBUS_GASS_TRANSFER_REQUEST_PENDING (PENDING, ACTING, ACTING_TO_PENDING)
 *     GLOBUS_GASS_TRANSFER_REQUEST_FAILED  (FAILED, USER_FAIL, ACTING_TO_FAIL)
 *     GLOBUS_GASS_TRANSFER_REQUEST_REFERRED
 *     GLOBUS_GASS_TRANSFER_REQUEST_DENIED
 *     GLOBUS_GASS_TRANSFER_REQUEST_DONE
 */
typedef enum
{
    GLOBUS_GASS_TRANSFER_REQUEST_INVALID,  /* handle no longer valid */
    GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING, /* for listener-created requests,
					       the state before starting,
					       after the user has called
					       register_accept, but before the
					       callback is done */
    GLOBUS_GASS_TRANSFER_REQUEST_STARTING, /* not ready/referred/denied yet */
    GLOBUS_GASS_TRANSFER_REQUEST_PENDING,  /* proto called ready, no op passed
					      to request */
    GLOBUS_GASS_TRANSFER_REQUEST_ACTING,   /* op passed to request */
    GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING, /* calling back to user */
    GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING, /* op passed to request, and
						    user called fail */
    GLOBUS_GASS_TRANSFER_REQUEST_FAILING,   /* user called fail, or op
					       completed, user callback
					       started */
    GLOBUS_GASS_TRANSFER_REQUEST_FAILED,    /* user called fail,
					      last user callback complete */
    GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL, /* user called fail before
					       ready/referred/denied */
    GLOBUS_GASS_TRANSFER_REQUEST_REFERRED,  /* proto called referred */
    GLOBUS_GASS_TRANSFER_REQUEST_DENIED,    /* proto called denied */
    GLOBUS_GASS_TRANSFER_REQUEST_FINISHING, /* op completed successfully,
					       with last data, user callback
					       started*/
    GLOBUS_GASS_TRANSFER_REQUEST_DONE,      /* last data callback completed */
    GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1, /* user called fail before
					          new_listener_request */
    GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2, /* user called fail before
					         authorize/refer/deny */
    GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3, /* user called fail before
					         request_ready */
    GLOBUS_GASS_TRANSFER_REQUEST_STARTING2, /* server not authorized/denied/failed */
    GLOBUS_GASS_TRANSFER_REQUEST_STARTING3  /* server not authorized/denied/failed */
} globus_gass_transfer_request_status_t;

typedef enum
{
    GLOBUS_GASS_TRANSFER_LISTENER_INVALID,     /* handle no longer valid */
    GLOBUS_GASS_TRANSFER_LISTENER_STARTING,    /* new listener called */
    GLOBUS_GASS_TRANSFER_LISTENER_LISTENING,   /* register listen/
						  proto->register listen */
    GLOBUS_GASS_TRANSFER_LISTENER_READY,       /* proto calls listener_ready */
    GLOBUS_GASS_TRANSFER_LISTENER_ACCEPTING,   /* register_accept() */
    GLOBUS_GASS_TRANSFER_LISTENER_CLOSING1,    /* close_listener before
						  listener_ready called */
    GLOBUS_GASS_TRANSFER_LISTENER_CLOSING2,    /* close listener before
						  new_request */
    GLOBUS_GASS_TRANSFER_LISTENER_CLOSED       /* listener is closed */
} globus_gass_transfer_listener_status_t;

typedef void
(* globus_gass_transfer_callback_t)(
    void *					arg,
    globus_gass_transfer_request_t 		request);

/* Request Attribute Object Types */
typedef enum
{
    GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY,
    GLOBUS_GASS_TRANSFER_FILE_MODE_TEXT
} globus_gass_transfer_file_mode_t;


typedef enum
{
    GLOBUS_GASS_TRANSFER_AUTHORIZE_SELF,
    GLOBUS_GASS_TRANSFER_AUTHORIZE_HOST,
    GLOBUS_GASS_TRANSFER_AUTHORIZE_SUBJECT,
    GLOBUS_GASS_TRANSFER_AUTHORIZE_CALLBACK
} globus_gass_transfer_authorization_t;

extern const globus_object_type_t
GLOBUS_GASS_OBJECT_TYPE_REQUESTATTR_DEFINITION;

#define GLOBUS_GASS_OBJECT_TYPE_REQUESTATTR \
	(&GLOBUS_GASS_OBJECT_TYPE_REQUESTATTR_DEFINITION)

globus_object_t *
globus_gass_transfer_requestattr_initialize(
    globus_object_t *				obj,
    char *					proxy_url,
    globus_size_t				block_size,
    globus_gass_transfer_file_mode_t		file_mode,
    globus_bool_t				connection_reuse);

extern const globus_object_type_t
GLOBUS_GASS_OBJECT_TYPE_SOCKET_REQUESTATTR_DEFINITION;

#define GLOBUS_GASS_OBJECT_TYPE_SOCKET_REQUESTATTR \
	(&GLOBUS_GASS_OBJECT_TYPE_SOCKET_REQUESTATTR_DEFINITION)

globus_object_t *
globus_gass_transfer_socket_requestattr_initialize(
    globus_object_t *				obj,
    char *					proxy_url,
    globus_size_t				block_size,
    globus_gass_transfer_file_mode_t		file_mode,
    globus_bool_t				connection_reuse,
    int						sndbuf,
    int						rcvbuf,
    globus_bool_t				nodelay);

extern const globus_object_type_t
GLOBUS_GASS_OBJECT_TYPE_SECURE_REQUESTATTR_DEFINITION;

#define GLOBUS_GASS_OBJECT_TYPE_SECURE_REQUESTATTR \
	(&GLOBUS_GASS_OBJECT_TYPE_SECURE_REQUESTATTR_DEFINITION)

globus_object_t *
globus_gass_transfer_secure_requestattr_initialize(
    globus_object_t *				obj,
    char *					proxy_url,
    globus_size_t				block_size,
    globus_gass_transfer_file_mode_t		file_mode,
    globus_bool_t				connection_reuse,
    int						sndbuf,
    int						rcvbuf,
    globus_bool_t				nodelay,
    globus_gass_transfer_authorization_t	authorization,
    char *					subject);

/* Listener Attribute Object Types */
extern const globus_object_type_t
GLOBUS_GASS_OBJECT_TYPE_LISTENERATTR_DEFINITION;

#define GLOBUS_GASS_OBJECT_TYPE_LISTENERATTR \
	(&GLOBUS_GASS_OBJECT_TYPE_LISTENERATTR_DEFINITION)

globus_object_t *
globus_gass_transfer_listenerattr_initialize(
    globus_object_t *				obj,
    int						backlog,
    unsigned short				port);

typedef struct
{
    char **					url;
    globus_size_t				count;
} globus_gass_transfer_referral_t;

/* Client Interface */
int
globus_gass_transfer_register_get(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg);

int
globus_gass_transfer_get(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url);

int
globus_gass_transfer_register_put(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg);

int
globus_gass_transfer_put(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length);

int
globus_gass_transfer_register_append(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg);

int
globus_gass_transfer_append(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    char *					url,
    globus_size_t				length);

/* Server Interface */
typedef void
(* globus_gass_transfer_close_callback_t)(
    void *					callback_arg,
    globus_gass_transfer_listener_t		listener);

typedef void
(* globus_gass_transfer_listen_callback_t)(
    void *					callback_arg,
    globus_gass_transfer_listener_t 		listener);

int
globus_gass_transfer_create_listener(
    globus_gass_transfer_listener_t *		listener,
    globus_gass_transfer_listenerattr_t *	attr,
    char *					scheme);

int
globus_gass_transfer_close_listener(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_close_callback_t 	callback,
    void *					user_arg);

int
globus_gass_transfer_register_listen(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_listen_callback_t	callback,
    void *					user_arg);

int
globus_gass_transfer_register_accept(
    globus_gass_transfer_request_t *		request,
    globus_gass_transfer_requestattr_t *	attr,
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg);

int
globus_gass_transfer_refer(
    globus_gass_transfer_request_t		request,
    char **					urls,
    globus_size_t				num_urls);

int
globus_gass_transfer_authorize(
    globus_gass_transfer_request_t		request,
    globus_size_t				total_length);

int
globus_gass_transfer_deny(
    globus_gass_transfer_request_t		request,
    int						reason,
    char *					message);

char *
globus_gass_transfer_listener_get_base_url(
    globus_gass_transfer_listener_t		listener);

void *
globus_gass_transfer_listener_get_user_pointer(
    globus_gass_transfer_listener_t		listener);

int
globus_gass_transfer_listener_set_user_pointer(
    globus_gass_transfer_listener_t		listener,
    void *					user_pointer);

/* Send and Receive Functionality (common to client and server) */
typedef void
(* globus_gass_transfer_bytes_callback_t)(
    void *					arg,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				length,
    globus_bool_t				last_data);

int
globus_gass_transfer_send_bytes(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				send_length,
    globus_bool_t				last_data,
    globus_gass_transfer_bytes_callback_t	callback,
    void *					user_arg);

int
globus_gass_transfer_receive_bytes(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				max_length,
    globus_size_t				wait_for_length,
    globus_gass_transfer_bytes_callback_t	callback,
    void *					user_arg);

int
globus_gass_transfer_fail(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_callback_t		callback,
    void *					user_arg);

/* Request Accessors */
globus_gass_transfer_request_type_t
globus_gass_transfer_request_get_type(
    globus_gass_transfer_request_t		request);

globus_gass_transfer_request_status_t
globus_gass_transfer_request_get_status(
    globus_gass_transfer_request_t		request);

char *
globus_gass_transfer_request_get_subject(
    globus_gass_transfer_request_t		request);

int
globus_gass_transfer_request_set_subject(
    globus_gass_transfer_request_t		request,
    char *					subject);

int
globus_gass_transfer_request_get_referral(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_referral_t *		referral);

char *
globus_gass_transfer_request_get_url(
    globus_gass_transfer_request_t		request);

int
globus_gass_transfer_request_set_url(
    globus_gass_transfer_request_t		request,
    char *					url);

globus_size_t
globus_gass_transfer_request_get_length(
    globus_gass_transfer_request_t		request);

int
globus_gass_transfer_request_get_denial_reason(
    globus_gass_transfer_request_t		request);

char *
globus_gass_transfer_request_get_denial_message(
    globus_gass_transfer_request_t		request);

void *
globus_gass_transfer_request_get_user_pointer(
    globus_gass_transfer_request_t		request);

int
globus_gass_transfer_request_set_user_pointer(
    globus_gass_transfer_request_t		request,
    void *					user_pointer);

int
globus_gass_transfer_request_destroy(
    globus_gass_transfer_request_t		request);

/* should only be called by protocol modules */
int
globus_gass_transfer_request_set_type(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_type_t		type);

/* Referral Accessors */
globus_size_t
globus_gass_transfer_referral_get_count(
    globus_gass_transfer_referral_t *		referral);

char *
globus_gass_transfer_referral_get_url(
    globus_gass_transfer_referral_t *		referral,
    globus_size_t				index);

int
globus_gass_transfer_referral_destroy(
    globus_gass_transfer_referral_t *		referral);

/* Attribute Functions */
int
globus_gass_transfer_requestattr_init(
    globus_gass_transfer_requestattr_t *	attr,
    char *					url_scheme);

int
globus_gass_transfer_requestattr_destroy(
    globus_gass_transfer_requestattr_t *	attr);

int
globus_gass_transfer_listenerattr_init(
    globus_gass_transfer_listenerattr_t *	attr,
    char *					url_scheme);

int
globus_gass_transfer_listenerattr_destroy(
    globus_gass_transfer_listenerattr_t *	attr);

/* Base Attribute Accessors */
int
globus_gass_transfer_requestattr_set_proxy_url(
    globus_gass_transfer_requestattr_t *	attr,
    char *					proxy_url);

int
globus_gass_transfer_requestattr_get_proxy_url(
    globus_gass_transfer_requestattr_t *	attr,
    char **					proxy_url);

int
globus_gass_transfer_requestattr_set_block_size(
    globus_gass_transfer_requestattr_t *	attr,
    globus_size_t				block_size);

int
globus_gass_transfer_requestattr_get_block_size(
    globus_gass_transfer_requestattr_t *	attr,
    globus_size_t *				block_size);

int
globus_gass_transfer_requestattr_set_file_mode(
    globus_gass_transfer_requestattr_t *	attr,
    globus_gass_transfer_file_mode_t		file_mode);

int
globus_gass_transfer_requestattr_get_file_mode(
    globus_gass_transfer_requestattr_t *	attr,
    globus_gass_transfer_file_mode_t *		file_mode);

int
globus_gass_transfer_requestattr_set_connection_reuse(
    globus_gass_transfer_requestattr_t *	attr,
    globus_bool_t				connection_reuse);

int
globus_gass_transfer_requestattr_get_connection_reuse(
    globus_gass_transfer_requestattr_t *	attr,
    globus_bool_t *				connection_reuse);

/* Socket Attribute Accessors */
int
globus_gass_transfer_requestattr_set_socket_sndbuf(
    globus_gass_transfer_requestattr_t *	attr,
    int						sndbuf);

int
globus_gass_transfer_requestattr_get_socket_sndbuf(
    globus_gass_transfer_requestattr_t *	attr,
    int *					sndbuf);

int
globus_gass_transfer_requestattr_set_socket_rcvbuf(
    globus_gass_transfer_requestattr_t *	attr,
    int						rcvbuf);

int
globus_gass_transfer_requestattr_get_socket_rcvbuf(
    globus_gass_transfer_requestattr_t *	attr,
    int *					rcvbuf);

int
globus_gass_transfer_requestattr_set_socket_nodelay(
    globus_gass_transfer_requestattr_t *	attr,
    globus_bool_t				nodelay);

int
globus_gass_transfer_requestattr_get_socket_nodelay(
    globus_gass_transfer_requestattr_t *	attr,
    globus_bool_t *				nodelay);

/* Security attribute accessors */
int
globus_gass_transfer_secure_requestattr_set_authorization(
    globus_gass_transfer_requestattr_t *	attr,
    globus_gass_transfer_authorization_t	mode,
    char *					subject);

int
globus_gass_transfer_secure_requestattr_get_authorization(
    globus_gass_transfer_requestattr_t *	attr,
    globus_gass_transfer_authorization_t *	mode,
    char **					subject);

/* Base Listener Attributes */
int
globus_gass_transfer_listenerattr_set_backlog(
    globus_gass_transfer_listenerattr_t *	attr,
    int						backlog);

int
globus_gass_transfer_listenerattr_get_backlog(
    globus_gass_transfer_listenerattr_t *	attr,
    int	*					backlog);

int
globus_gass_transfer_listenerattr_set_port(
    globus_gass_transfer_listenerattr_t *	attr,
    unsigned short				port);

int
globus_gass_transfer_listenerattr_get_port(
    globus_gass_transfer_listenerattr_t *	attr,
    unsigned short *				port);

/* Module descriptor */
extern globus_module_descriptor_t		globus_i_gass_transfer_module;
#define GLOBUS_GASS_TRANSFER_MODULE		(&globus_i_gass_transfer_module)

EXTERN_C_END

#endif /* GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_H */
