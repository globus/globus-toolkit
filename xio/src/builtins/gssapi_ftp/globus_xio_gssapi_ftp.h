#if !defined GLOBUS_XIO_DRIVER_GSSAPI_FTP_H
#define GLOBUS_XIO_DRIVER_GSSAPI_FTP_H 1

#include "globus_common.h"
#include "globus_error_gssapi.h"

typedef enum
{
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_START_STATE,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_ENCRYPT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_ALLOW_CLEAR,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_FORCE_SERVER
} globus_xio_gssapi_attr_type_t;

typedef enum globus_xio_gssapi_handle_cntl_type_e
{
    GLOBUS_XIO_DRIVER_GSSAPI_FTP_GET_AUTH,
} globus_xio_gssapi_handle_cntl_type_t;


#define GlobusXIOGssapiBadParameter()                                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GSSAPI_FTP_BAD_PARAMETER,                            \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Bad Parameter"))

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

#define GlobusXIOGssapiFTPAuthenticationFailure(str)                         \
     globus_error_put(                                                       \
         globus_error_construct_error(                                       \
             GLOBUS_XIO_MODULE,                                              \
             GLOBUS_NULL,                                                    \
             GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,                               \
             __FILE__,                                                       \
             _xio_name,                                                      \
             __LINE__,                                                       \
             "Authentication Error: %s",                                     \
             str))

#define GlobusXIOGssapiFTPQuit()                                             \
     globus_error_put(                                                       \
         globus_error_construct_error(                                       \
             GLOBUS_XIO_MODULE,                                              \
             GLOBUS_NULL,                                                    \
             GLOBUS_XIO_GSSAPI_FTP_ERROR_QUIT,                               \
             __FILE__,                                                       \
             _xio_name,                                                      \
             __LINE__,                                                       \
             "Pre mature Quit, close connection"))

enum
{
    GLOBUS_XIO_GSSAPI_FTP_BAD_PARAMETER,
    GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_QUIT
};

enum
{
    GLOBUS_XIO_GSSAPI_FTP_SECURE,
    GLOBUS_XIO_GSSAPI_FTP_CLEAR,
    GLOBUS_XIO_GSSAPI_FTP_NONE
};

#endif
