#ifndef GSI_SOCKET_PRIV_H
#define GSI_SOCKET_PRIV_H 1
/*
 * gsi_socket_priv.h
 *
 * See gsi_socket.h for documentation.
 */

struct _gsi_socket 
{
    int				sock;
    int				allow_anonymous; /* Boolean */
    /* All these variables together indicate the last error we saw */
    char			*error_string;
    int				error_number;
    gss_ctx_id_t		gss_context;
    OM_uint32			major_status;
    OM_uint32			minor_status;
    char			*peer_name;
    int             limited_proxy; /* 1 if peer used a limited proxy */
    int             max_token_len;
    char            *certreq;   /* path to a PEM encoded cert req */
};

#define DEFAULT_SERVICE_NAME		"host"

#endif /* GSI_SOCKET_PRIV_H */
