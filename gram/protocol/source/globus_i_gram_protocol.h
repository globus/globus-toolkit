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

#ifndef DOXYGEN

#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_io.h"

EXTERN_C_BEGIN

/* Strings used in protocol framing, packing, unframing, and unpacking */

#define CRLF             "\015\012"
#define GLOBUS_GRAM_HTTP_REQUEST_LINE \
                        "POST %s HTTP/1.1" CRLF

#define GLOBUS_GRAM_HTTP_HOST_LINE \
                        "Host: %s" CRLF

#define GLOBUS_GRAM_HTTP_CONTENT_TYPE_LINE \
                        "Content-Type: application/x-globus-gram" CRLF

#define GLOBUS_GRAM_HTTP_CONTENT_LENGTH_LINE \
                        "Content-Length: %ld" CRLF

#define GLOBUS_GRAM_HTTP_REPLY_LINE \
                        "HTTP/1.1 %3d %s" CRLF
#define GLOBUS_GRAM_HTTP_PARSE_REPLY_LINE \
                        "HTTP/1.1 %3d %[^" CRLF "]" CRLF
#define GLOBUS_GRAM_HTTP_CONNECTION_LINE \
                        "Connection: Close" CRLF

#define GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE \
                        "protocol-version: %d" CRLF

#define GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE \
                        "job-state-mask: %d" CRLF

#define GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE \
                        "callback-url: %s" CRLF

#define GLOBUS_GRAM_HTTP_PACK_STATUS_LINE \
                        "status: %d" CRLF

#define GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE \
                        "failure-code: %d" CRLF

#define GLOBUS_GRAM_HTTP_PACK_JOB_FAILURE_CODE_LINE \
                        "job-failure-code: %d" CRLF

#define GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE \
                        "job-manager-url: %s" CRLF

#define GLOBUS_GRAM_HTTP_PACK_CLIENT_REQUEST_LINE \
                        "%s" CRLF

typedef enum
{
    GLOBUS_GRAM_PROTOCOL_REQUEST,
    GLOBUS_GRAM_PROTOCOL_REPLY
}
globus_gram_protocol_read_type_t;

typedef struct
{
    unsigned short			port;
    globus_bool_t			allow_attach;
    globus_io_handle_t *		handle;
    globus_gram_protocol_callback_t	callback;
    void *				callback_arg;
    volatile int			connection_count;
    globus_cond_t			cond;
}
globus_i_gram_protocol_listener_t;

typedef struct
{
    globus_bool_t			got_header;
    globus_byte_t *			buf;
    globus_size_t			bufsize;
    globus_gram_protocol_read_type_t	read_type;
    globus_size_t			payload_length;
    globus_size_t			n_read;
    globus_gram_protocol_callback_t	callback;
    void *				callback_arg;
    globus_byte_t *			replybuf;
    globus_size_t			replybufsize;

    globus_io_handle_t *		io_handle;
    globus_gram_protocol_handle_t	handle;
    globus_i_gram_protocol_listener_t *	listener;
    int					rc;
    char *				uri;

    /* added for delegation support */
    globus_bool_t			keep_open;
    globus_size_t			token_length;
    globus_gram_protocol_delegation_callback_t
					delegation_callback;
    OM_uint32				delegation_major_status;
    OM_uint32				delegation_minor_status;
    void *				delegation_arg;
    gss_cred_id_t			delegation_cred;
    gss_OID_set				delegation_restriction_oids;
    gss_buffer_set_t			delegation_restriction_buffers;
    OM_uint32				delegation_req_flags;
    OM_uint32				delegation_time_req;
    gss_buffer_desc			delegation_input_token;
    gss_buffer_desc			delegation_output_token;

    /* added for gram authz callout support */
    
    gss_ctx_id_t                        context;
}
globus_i_gram_protocol_connection_t;

int
globus_i_gram_protocol_callback_disallow(
    globus_i_gram_protocol_listener_t *	listener);

extern globus_mutex_t			globus_i_gram_protocol_mutex;
extern globus_cond_t			globus_i_gram_protocol_cond;

extern globus_list_t *			globus_i_gram_protocol_listeners;
extern globus_list_t *			globus_i_gram_protocol_connections;
extern globus_list_t *			globus_i_gram_protocol_old_creds;
extern globus_bool_t 			globus_i_gram_protocol_shutdown_called;
extern globus_io_attr_t			globus_i_gram_protocol_default_attr;
extern int				globus_i_gram_protocol_num_connects;
extern globus_gram_protocol_handle_t	globus_i_gram_protocol_handle;

EXTERN_C_END

#endif /* DOXYGEN */
