#if !defined GLOBUS_XIO_DRIVER_SMTP_H
#define GLOBUS_XIO_DRIVER_SMTP_H 1

#include "globus_common.h"

typedef enum
{
    GLOBUS_XIO_SMTP_CMD_SET_ADDRESS
} globus_xio_smtp_attr_cmd_t;

#define GlobusXIOGssapiFTPOutstandingOp globus_error_put(GLOBUS_ERROR_NO_INFO)
#define GlobusXIOGssapiFTPEncodingError globus_error_put(GLOBUS_ERROR_NO_INFO)
#define GlobusXIOGssapiFTPAllocError globus_error_put(GLOBUS_ERROR_NO_INFO)
#define GlobusXIOGssapiFTPAuthenticationFailure globus_error_put(GLOBUS_ERROR_NO_INFO)

#endif
