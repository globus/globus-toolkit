#if !defined GLOBUS_XIO_DRIVER_SMTP_H
#define GLOBUS_XIO_DRIVER_SMTP_H 1

#include "globus_common.h"

typedef enum
{
    GLOBUS_XIO_SMTP_CMD_SET_ADDRESS
} globus_xio_smtp_attr_cmd_t;

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

#define GlobusXIOGssapiFTPAuthenticationFailure(str)                        \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,                               \
            "[%s:%d] Authentication. %s",                                   \
            _xio_name, __LINE__, str))

enum
{
    GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,
};

#endif
