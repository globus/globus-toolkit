#if !defined GLOBUS_XIO_DRIVER_SMTP_H
#define GLOBUS_XIO_DRIVER_SMTP_H 1

#include "globus_common.h"
#include "globus_error_gssapi.h"

typedef enum  globus_i_xio_gssapi_ftp_state_s
{
    /* starting state for both client and server */
    GSSAPI_FTP_STATE_NONE,
    /* server auhenticating states */
    GSSAPI_FTP_STATE_SERVER_READING_AUTH,
    GSSAPI_FTP_STATE_SERVER_GSSAPI_READ,
    GSSAPI_FTP_STATE_SERVER_READING_ADAT,
    GSSAPI_FTP_STATE_SERVER_ADAT_REPLY,
    GSSAPI_FTP_STATE_SERVER_QUITING,
                                                                                
    /* client authenticating states */
    GSSAPI_FTP_STATE_CLIENT_READING_220,
    GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH,
    GSSAPI_FTP_STATE_CLIENT_ADAT_INIT,
    GSSAPI_FTP_STATE_CLIENT_SENDING_ADAT,
                                                                                
    /* open state is final state xio takes care of closing */
    GSSAPI_FTP_STATE_OPEN
} globus_i_xio_gssapi_ftp_state_t;
                                                                                
typedef enum
{
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_START_STATE,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_ENCRYPT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUPER_MODE
} globus_xio_gssapi_attr_type_t;


#define GlobusXIOGssapiFTPOutstandingOp()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,                           \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Operation is outstanding"))

#define GlobusXIOGssapiFTPEncodingError()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,                           \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Error encoding."))

#define GlobusXIOGssapiFTPAllocError()                                      \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,                              \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Operation is outstanding"))

#define GlobusXIOGssapiFTPGSIAuthFailure(maj, min)                          \
    globus_error_put(                                                       \
        globus_error_wrap_gssapi_error(                                     \
            GLOBUS_XIO_MODULE,                                              \
            (maj),                                                          \
            (min),                                                          \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,                               \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Authentication Error"))

#define GlobusXIOGssapiFTPAuthenticationFailure(str)                        \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,                              \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Authentication Error: %s",                                     \
            str))



enum
{
    GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH
};

#endif
