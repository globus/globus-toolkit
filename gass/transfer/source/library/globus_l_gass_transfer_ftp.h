/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************************
globus_l_gass_transfer_ftp.h
 
Description:
    This header defines the prototypes for the local functions in the
    ftp protocol module source file
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_GASS_INCLUDE_GLOBUS_L_GASS_TRANSFER_FTP_H
#define GLOBUS_GASS_INCLUDE_GLOBUS_L_GASS_TRANSFER_FTP_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/******************************************************************************
			  Module Specific Constants
******************************************************************************/

static globus_mutex_t globus_l_gass_transfer_ftp_mutex;
static globus_cond_t globus_l_gass_transfer_ftp_cond;

#define globus_l_gass_transfer_ftp_lock() \
	globus_mutex_lock(&globus_l_gass_transfer_ftp_mutex)/*,*/ \
	/*printf("locked mutex at %s: %d\n", __FILE__, __LINE__)*/
#define globus_l_gass_transfer_ftp_unlock() \
	/*printf("unlocking mutex at %s: %d\n", __FILE__, __LINE__), */\
	globus_mutex_unlock(&globus_l_gass_transfer_ftp_mutex)
#define globus_l_gass_transfer_ftp_wait() \
	globus_cond_wait(&globus_l_gass_transfer_ftp_cond, \
			 &globus_l_gass_transfer_ftp_mutex)
#define globus_l_gass_transfer_ftp_signal() \
	globus_cond_signal(&globus_l_gass_transfer_ftp_cond)
				
#define GLOBUS_L_DEFAULT_FAILURE_CODE	400
#define GLOBUS_L_DEFAULT_FAILURE_REASON	"Bad Request"

/* The "client failure" (4xx) response codes defined in RFC 2068 end at 415 */
#define GLOBUS_L_PROTOCOL_FAILURE_CODE	416
#define GLOBUS_L_PROTOCOL_FAILURE_REASON "Protocol Error"

#define GLOBUS_L_MALLOC_FAILURE_CODE	417
#define GLOBUS_L_MALLOC_FAILURE_REASON  "Malloc Error"

/******************************************************************************
			  Module specific Types
******************************************************************************/
typedef enum
{
    /* Client-only states */
    GLOBUS_GASS_TRANSFER_FTP_STATE_CONNECTING,
    GLOBUS_GASS_TRANSFER_FTP_STATE_REQUESTING,
    GLOBUS_GASS_TRANSFER_FTP_STATE_CLOSING,
    GLOBUS_GASS_TRANSFER_FTP_STATE_REFERRED,
    GLOBUS_GASS_TRANSFER_FTP_STATE_DENIED,
    GLOBUS_GASS_TRANSFER_FTP_STATE_RESPONDING,
    /* Common states */
    GLOBUS_GASS_TRANSFER_FTP_STATE_IDLE,
    GLOBUS_GASS_TRANSFER_FTP_STATE_DONE,
    GLOBUS_GASS_TRANSFER_FTP_STATE_PENDING
} globus_gass_transfer_ftp_state_t;

/* These mirror the GASS listener states exactly */
typedef enum
{
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_STARTING,
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_LISTENING,
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_READY,
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_ACCEPTING,
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_CLOSING1,
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_CLOSING2,
    GLOBUS_GASS_TRANSFER_FTP_LISTENER_CLOSED
} globus_gass_transfer_listener_state_t;
typedef enum
{
    GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_UNTIL_EOF,
    GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_EOF,
    GLOBUS_GASS_TRANSFER_FTP_RECV_STATE_ERROR
} globus_l_gass_transfer_ftp_recv_state_t;

typedef struct 
{
    /* Standard "proto" elements */
    globus_gass_transfer_proto_listener_t  	close_listener;
    globus_gass_transfer_proto_listener_t	listen;
    globus_gass_transfer_proto_accept_t	 	accept;
    globus_gass_transfer_proto_listener_t	destroy;

    /* Begin internal ftp-specific proto state */
    globus_gass_transfer_listener_t		listener;
    globus_ftp_client_handle_t			handle;
    globus_url_scheme_t				url_scheme;

    globus_gass_transfer_listener_state_t	state;
    globus_bool_t				destroy_called;

    struct globus_gass_transfer_ftp_request_proto_s *	request;
} globus_gass_transfer_ftp_listener_proto_t;

typedef struct globus_gass_transfer_ftp_request_proto_s 
{
    /* Standard "proto" elements */
    globus_gass_transfer_proto_send_t		send_buffer;
    globus_gass_transfer_proto_receive_t	recv_buffer;

    globus_gass_transfer_proto_func_t		fail;

    globus_gass_transfer_proto_func_t		deny;
    globus_gass_transfer_proto_func_t		refer;
    globus_gass_transfer_proto_func_t		authorize;

    globus_gass_transfer_proto_func_t		destroy;

    /* Begin internal ftp-specific proto state */
    globus_ftp_client_handle_t			handle;
    /* last data for sending, and EOF on receiving */

    volatile globus_bool_t			oneshot_registered;
    volatile globus_bool_t			oneshot_active;

    volatile globus_gass_transfer_ftp_state_t	state;

    globus_gass_transfer_request_t		request;

    globus_bool_t				failure_occurred;
    globus_bool_t				destroy_called;

    /* Flags from the request attributes */
    globus_url_t				proxy_url;
    globus_bool_t				text_mode;
    globus_size_t				block_size;

    /* Type and name of the requested resource */
    globus_url_t				url;
    char *					url_string;
    globus_gass_transfer_request_type_t		type;

    /*
     * For the "send" case, a 4 item iovec array, containing
     * the chunk header, body, and trailing CRLF, and a 0-length
     * chunk + crlf
     */
    struct iovec				iov[4];
    /* Length and transfer encoding */
    globus_size_t				length;
    globus_size_t				handled;
    globus_bool_t				chunked;
    /* sending-side: are we handling the last data block? */
    globus_bool_t				last_data;
    /* sending-side, number of writes that have been issued, used to compute the offset */
    /*  globus_size_t                               num_writes_sent; */

    globus_bool_t				client_side;
    /* Amount of data from the current chunk still needs to
       be given to the user */
    globus_size_t				chunk_left;
    globus_l_gass_transfer_ftp_recv_state_t	recv_state;
    globus_bool_t				eof_read;

    /* Used to parse/store responses from the FTP server */
    globus_byte_t * 				response_buffer;	
    globus_size_t				response_buflen;
    globus_size_t				response_offset;
    globus_size_t				parsed_offset;
    int						code;
    char *					reason;
    globus_bool_t				parse_error;

    /* Major/minor version of the FTP protocol we are using */
    int						major;
    int						minor;
    /* FTP headers we've received */
    globus_list_t *				headers;

    /* Line mode of this particular file we are reading */

    /*
    globus_gass_transfer_ftp_line_mode_t	line_mode;
    */
    /*
     * The buffer which was handed to the protocol module
     * from GASS
     */
    globus_byte_t *				user_buffer;
    globus_size_t				user_buflen;
    globus_size_t				user_offset;
    globus_size_t				user_waitlen;

    globus_gass_transfer_authorization_t	authorization_mode;
    char *					authorized_subject;
    char *					connected_subject;

    /* For handling requests from client */
    char *					uri;
    char *					method;
    globus_bool_t				proxy_connect;
    globus_bool_t				got_response;
    globus_bool_t				waiting_for_response;
} globus_gass_transfer_ftp_request_proto_t;

/******************************************************************************
			  Module specific Prototypes
******************************************************************************/
#if !defined(GLOBUS_GASS_TRANSFER_FTP_PARSER_TEST)
static
void
globus_l_gass_transfer_ftp_send(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				buffer,
    globus_size_t				buffer_length,
    globus_bool_t				last_data);

static
void
globus_l_gass_transfer_ftp_receive(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				buffer,
    globus_size_t				buffer_length,
    globus_size_t				wait_for_length);

static
void
globus_l_gass_transfer_ftp_writev_callback(
    void *					callback_arg,
    globus_io_handle_t *			handle,
    globus_result_t 				result,
    struct iovec *				iov,
    globus_size_t				iovcnt,
    globus_size_t				nbytes);


static
void
globus_l_gass_transfer_ftp_write_callback(
    void *                                      callback_arg,
    globus_ftp_client_handle_t *                handle, 
    globus_object_t *                           error,
    globus_byte_t *                             bytes,
    globus_size_t                               nbytes,
    globus_off_t                                offset,
    globus_bool_t		                eof);

#ifdef TEMP_DEF

static
void
globus_l_gass_transfer_ftp_write_response(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);

#endif

static
void
globus_l_gass_transfer_ftp_proto_destroy(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
void
globus_l_gass_transfer_ftp_read_callback(
    void *                          callback_arg,
    globus_ftp_client_handle_t *    handle,
    globus_object_t *               error,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_off_t                    offset,
    globus_bool_t		    eof);

void
globus_l_gass_transfer_ftp_get_done_callback(
    void *                                     callback_arg,
    globus_ftp_client_handle_t *               handle,
    globus_object_t *	                       error);

void
globus_l_gass_transfer_ftp_put_done_callback(
    void *                                     callback_arg,
    globus_ftp_client_handle_t *               handle,
    globus_object_t *	                       error);

#ifdef TEMP_DEF
static
void
globus_l_gass_transfer_ftp_read_buffered_callback(
    void *					callback_arg,
    globus_io_handle_t *			handle,
    globus_result_t				result,
    globus_byte_t *				buf,
    globus_size_t				nbytes);

static
globus_bool_t
globus_l_gass_transfer_ftp_callback_read_buffered_callback(
    globus_abstime_t *                          time_stop,
    void *					arg);

static
globus_bool_t
globus_l_gass_transfer_ftp_callback_ready_callback(
    globus_abstime_t *                          time_stop,
    void *					arg);
#endif

static
void
globus_l_gass_transfer_ftp_fail(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request);

static
void
globus_l_gass_transfer_ftp_close_callback(
    void *					callback_arg,
    globus_io_handle_t *			handle,
    globus_result_t				result);

#ifdef TEMP_DEF
static
void
globus_l_gass_transfer_ftp_accept_callback(
    void *					callback_arg,
    globus_io_handle_t *			handle,
    globus_result_t				result);

#endif

static
void
globus_l_gass_transfer_ftp_destroy(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request);

static
void
globus_l_gass_transfer_ftp_new_request(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_requestattr_t *	attr);

static
globus_object_t *
globus_l_gass_transfer_ftp_new_requestattr(
    char *                              	url_scheme);

#ifdef TEMP_DEF
static
globus_object_t *
globus_l_gass_transfer_ftp_new_listenerattr(
    char *					url_scheme);

static
void
globus_l_gass_transfer_ftp_close_listener(
    globus_gass_transfer_listener_proto_t *	proto,
    globus_gass_transfer_listener_t		listener);

static
void
globus_l_gass_transfer_ftp_listen(
    globus_gass_transfer_listener_proto_t *	proto,
    globus_gass_transfer_listener_t		listener);

static
void
globus_l_gass_transfer_ftp_accept(
    globus_gass_transfer_listener_proto_t *	proto,
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_requestattr_t *	attr);

static
globus_bool_t
globus_l_gass_transfer_ftp_authorization_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    char *				identity,
    gss_ctx_id_t *			context_handle);

static
void
globus_l_gass_transfer_ftp_listener_destroy(
    globus_gass_transfer_listener_proto_t *	proto,
    globus_gass_transfer_listener_t		listener);

static
int
globus_l_gass_transfer_ftp_new_listener(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_listenerattr_t *	attr,
    char *					scheme,
    char **					base_url,
    globus_gass_transfer_listener_proto_t **	proto);

static
void
globus_l_gass_transfer_ftp_connect_callback(
    void *					arg, 
    globus_io_handle_t *			handle, 
    globus_result_t				result);

static
void
globus_l_gass_transfer_ftp_command_callback(
    void *					arg, 
    globus_io_handle_t *			handle, 
    globus_result_t				result,
    globus_byte_t *				buf,
    globus_size_t				nbytes);

static
void
globus_l_gass_transfer_ftp_response_callback(
    void *					arg,
    globus_io_handle_t *			handle,
    globus_result_t				result,
    globus_byte_t *				buf,
    globus_size_t				nbytes);

static
void
globus_l_gass_transfer_ftp_listener_proto_destroy(
    globus_gass_transfer_ftp_listener_proto_t *
						proto);
static
globus_bool_t
globus_l_gass_transfer_ftp_callback_listen_callback(
    globus_abstime_t *                          time_stop,
    void *					arg);

static
void
globus_l_gass_transfer_ftp_listen_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);
#endif

static
globus_bool_t
globus_l_gass_transfer_ftp_find_crlf(
    globus_byte_t *				bytes,
    globus_size_t				len,
    globus_size_t *				crlf_offset);

static
globus_bool_t
globus_l_gass_transfer_ftp_parse_headers(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
globus_bool_t
globus_l_gass_transfer_ftp_parse_one_header(
    globus_gass_transfer_ftp_request_proto_t *		proto,
    globus_bool_t *				last_header);

static
globus_bool_t
globus_l_gass_transfer_ftp_parse_status_line(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
globus_bool_t
islws(
    char 					byte);

static
globus_bool_t
ischar(
    char 					byte);

static
globus_bool_t
istspecial(
    char 					byte);

static
globus_bool_t
globus_l_gass_transfer_ftp_callback_send_callback(
    globus_abstime_t *                          time_stop,
    void *					arg);
#endif

static
void
globus_l_gass_transfer_ftp_request_callback(
    void *					arg,
    globus_io_handle_t *			handle,
    globus_result_t				result,
    globus_byte_t *				buf,
    globus_size_t				nbytes);

static
globus_result_t
globus_l_gass_transfer_ftp_register_read(
    globus_gass_transfer_ftp_request_proto_t *		proto);

#ifdef TEMP_DEF
static
char *
globus_l_gass_transfer_ftp_construct_request(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
globus_bool_t
globus_l_gass_transfer_ftp_handle_chunk(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
globus_bool_t
globus_l_gass_transfer_ftp_parse_response(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
globus_bool_t
globus_l_gass_transfer_ftp_parse_request(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
globus_bool_t
globus_l_gass_transfer_ftp_parse_request_line(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
void
globus_l_gass_transfer_ftp_extract_referral(
    globus_gass_transfer_ftp_request_proto_t *		proto,
    char ***						referral,
    globus_size_t *					referral_count);
#endif

static
void
globus_l_gass_transfer_ftp_callback_denied(
    void *					arg);

static
void
globus_l_gass_transfer_ftp_close(
    globus_gass_transfer_ftp_request_proto_t *		proto);

static
void
globus_l_gass_transfer_ftp_register_close(
    globus_gass_transfer_ftp_request_proto_t *		proto);

#ifdef TEMP_DEF
static
void
globus_l_gass_transfer_ftp_listener_close(
    globus_gass_transfer_ftp_listener_proto_t * proto);
#endif

EXTERN_C_END

#endif /* GLOBUS_GASS_INCLUDE_GLOBUS_L_GASS_TRANSFER_FTP_H */
