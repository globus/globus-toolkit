#if !defined GLOBUS_XIO_DRIVER_SMTP_H
#define GLOBUS_XIO_DRIVER_SMTP_H 1

#include "globus_common.h"

typedef enum  globus_i_xio_gssapi_ftp_state_s
{
    /* starting state for both client and server */
    GSSAPI_FTP_STATE_NONE,
    /* server auhenticating states */
    GSSAPI_FTP_STATE_SERVER_READING_AUTH,
    GSSAPI_FTP_STATE_SERVER_GSSAPI_READ,
    GSSAPI_FTP_STATE_SERVER_READING_ADAT,
    GSSAPI_FTP_STATE_SERVER_ADAT_REPLY,
                                                                                
    /* client authenticating states */
    GSSAPI_FTP_STATE_CLIENT_READING_220,
    GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH,
    GSSAPI_FTP_STATE_CLIENT_ADAT_INIT,
    GSSAPI_FTP_STATE_CLIENT_SENDING_ADAT,
                                                                                
    /* open state is final state xio takes care of closing */
    GSSAPI_FTP_STATE_OPEN,
} globus_i_xio_gssapi_ftp_state_t;
                                                                                
typedef enum
{
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_START_STATE,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_ENCRYPT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUPER_MODE,
} globus_xio_gssapi_attr_type_t;


#define GlobusXIOGssapiFTPOutstandingOp()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,                           \
            "[%s:%d] Operation is outstanding",                             \
            _xio_name, __LINE__))

#define GlobusXIOGssapiFTPEncodingError()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,                           \
            "[%s:%d] Error encoding.",                                      \
            _xio_name, __LINE__))

#define GlobusXIOGssapiFTPAllocError()                                      \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,                              \
            "[%s:%d] Operation is outstanding",                             \
            _xio_name, __LINE__))

#define GlobusXIOGssapiFTPGSIAuthFailure(res, maj, min)                     \
do                                                                          \
{                                                                           \
    char *                                  _err_str;                       \
                                                                            \
    globus_gss_assist_display_status_str(&_err_str,                         \
                             GLOBUS_NULL,                                   \
                             maj,                                           \
                             min,                                           \
                             0);                                            \
                                                                            \
    res = globus_error_put(                                                 \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,                               \
            "[%s:%d] Authentication Error: %s.",                            \
            _xio_name, __LINE__, _err_str));                                \
    globus_free(_err_str);                                                  \
}                                                                           \
while(0)

#define GlobusXIOGssapiFTPAuthenticationFailure(str)                        \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,                              \
            "[%s:%d] Authentication Error: %s",                             \
            _xio_name, __LINE__))



enum
{
    GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,
};

#endif
