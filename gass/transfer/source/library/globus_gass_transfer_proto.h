/******************************************************************************
globus_gass_transfer_proto.h
 
Description:
    This header defines the GASS protocol module library interface
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_GASS_INCLUDE_GLOBUS_GASS_PROTO_H
#define GLOBUS_GASS_INCLUDE_GLOBUS_GASS_PROTO_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_common.h"
#include "globus_gass_transfer.h"

EXTERN_C_BEGIN

/* Module-specific types */
typedef struct globus_gass_transfer_request_proto_s
globus_gass_transfer_request_proto_t;

typedef struct globus_gass_transfer_listener_proto_s
globus_gass_transfer_listener_proto_t;

typedef void
(* globus_gass_transfer_proto_send_t)(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				buffer,
    globus_size_t				buffer_length,
    globus_bool_t				last_data);

typedef void
(* globus_gass_transfer_proto_receive_t)(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request,
    globus_byte_t *				buffer,
    globus_size_t				buffer_length,
    globus_size_t				wait_for_length);

typedef void
(* globus_gass_transfer_proto_func_t)(
    globus_gass_transfer_request_proto_t *	proto,
    globus_gass_transfer_request_t		request);

typedef void
(* globus_gass_transfer_proto_new_request_t)(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_requestattr_t *	attr);

typedef int
(* globus_gass_transfer_proto_create_listener_t)(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_listenerattr_t *	attr,
    char *					scheme,
    char **					base_url,
    globus_gass_transfer_listener_proto_t **	proto);

typedef void
(* globus_gass_transfer_proto_listener_t)(
    globus_gass_transfer_listener_proto_t *	proto,
    globus_gass_transfer_listener_t		listener);

typedef globus_object_t *
(* globus_gass_transfer_proto_new_attr_t)(
    char *					url_scheme);

typedef void
(* globus_gass_transfer_proto_accept_t)(
    globus_gass_transfer_listener_proto_t *	proto,
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_requestattr_t *	attr);

struct globus_gass_transfer_request_proto_s
{
    globus_gass_transfer_proto_send_t		send_buffer;
    globus_gass_transfer_proto_receive_t	recv_buffer;


    globus_gass_transfer_proto_func_t		fail;

    globus_gass_transfer_proto_func_t		deny;
    globus_gass_transfer_proto_func_t		refer;
    globus_gass_transfer_proto_func_t		authorize;

    globus_gass_transfer_proto_func_t		destroy;
};

struct globus_gass_transfer_listener_proto_s
{
    globus_gass_transfer_proto_listener_t  	close_listener;
    globus_gass_transfer_proto_listener_t	listen;
    globus_gass_transfer_proto_accept_t	 	accept;
    globus_gass_transfer_proto_listener_t	destroy;
};

typedef struct
{
    char *					 url_scheme;

    globus_gass_transfer_proto_new_attr_t	 new_requestattr;

    /* client-side support */
    globus_gass_transfer_proto_new_request_t	 new_request;

    /* server-side support */
    globus_gass_transfer_proto_new_attr_t	 new_listenerattr;
    globus_gass_transfer_proto_create_listener_t new_listener;
} globus_gass_transfer_proto_descriptor_t;

globus_result_t
globus_gass_transfer_proto_register_protocol(
    globus_gass_transfer_proto_descriptor_t *	proto_desc);

void
globus_gass_transfer_proto_request_ready(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_proto_t *	proto);

void
globus_gass_transfer_proto_request_denied(
    globus_gass_transfer_request_t		request,
    int						reason,
    char *					message);

void
globus_gass_transfer_proto_request_referred(
    globus_gass_transfer_request_t		request,
    char **					url,
    globus_size_t				num_urls);

void
globus_gass_transfer_proto_new_listener_request(
    globus_gass_transfer_listener_t		listener,
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_proto_t *	proto);

void
globus_gass_transfer_proto_send_complete(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				nbytes,
    globus_bool_t				failed,
    globus_bool_t				last_data);

void
globus_gass_transfer_proto_receive_complete(
    globus_gass_transfer_request_t		request,
    globus_byte_t *				bytes,
    globus_size_t				nbytes,
    globus_bool_t				failed,
    globus_bool_t				last_data);

void
globus_gass_transfer_proto_listener_ready(
    globus_gass_transfer_listener_t		listener);


/* Protocol Implementation Helper Functions */
/* implemented in globus_gass_transfer_text.c */
void
globus_gass_transfer_crlf_to_lf(
    globus_byte_t *				src,
    globus_size_t 				src_len,
    globus_byte_t **				dst,
    globus_size_t * 				dst_len);

void
globus_gass_transfer_lf_to_crlf(
    globus_byte_t *				src,
    globus_size_t 				src_len,
    globus_byte_t **				dst,
    globus_size_t * 				dst_len);

EXTERN_C_END

#endif /* GLOBUS_GASS_INCLUDE_GLOBUS_GASS_PROTO_H */
