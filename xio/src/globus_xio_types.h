#if !defined(GLOBUS_XIO_TYPES_H)
#define GLOBUS_XIO_TYPES_H 1

#include "globus_common.h"

EXTERN_C_BEGIN


/*************************************************************************
 *    define types
 ************************************************************************/
typedef struct globus_i_xio_handle_s *          globus_xio_handle_t;
typedef struct globus_i_xio_context_entry_s *   globus_xio_driver_handle_t;
typedef struct globus_i_xio_op_s *              globus_xio_operation_t;
typedef struct globus_i_xio_driver_s *          globus_xio_driver_t;
typedef struct globus_i_xio_attr_s *            globus_xio_attr_t;
typedef struct globus_i_xio_stack_s *           globus_xio_stack_t;
typedef struct globus_i_xio_server_s *          globus_xio_server_t;
typedef struct globus_i_xio_server_s *          globus_xio_driver_server_t;
typedef struct globus_i_xio_op_s *              globus_xio_data_descriptor_t;


typedef struct iovec                            globus_xio_iovec_t;


/**
 *  @ingroup GLOBUS_XIO_API
 *  Operation types
 *  ---------------
 *
 *  An enumeration of operation types.  Used in the timeout callback
 *  to indicate what operation typed timedout.
 */
typedef enum globus_i_xio_op_type_e
{
    GLOBUS_XIO_OPERATION_TYPE_NONE,
    GLOBUS_XIO_OPERATION_TYPE_FINISHED,
    GLOBUS_XIO_OPERATION_TYPE_OPEN,
    GLOBUS_XIO_OPERATION_TYPE_CLOSE,
    GLOBUS_XIO_OPERATION_TYPE_READ,
    GLOBUS_XIO_OPERATION_TYPE_WRITE,
    GLOBUS_XIO_OPERATION_TYPE_ACCEPT,
    GLOBUS_XIO_OPERATION_TYPE_DRIVER,
    GLOBUS_XIO_OPERATION_TYPE_DD,
    GLOBUS_XIO_OPERATION_TYPE_SERVER_INIT
} globus_xio_operation_type_t;

typedef enum globus_i_xio_signal_type_e
{
    GLOBUS_XIO_SIGNAL_TYPE_NONE
} globus_xio_signal_type_t;

typedef enum
{
    GLOBUS_XIO_ERROR_CANCELED,
    GLOBUS_XIO_ERROR_EOF,
    GLOBUS_XIO_ERROR_COMMAND,
    GLOBUS_XIO_ERROR_CONTACT_STRING,
    GLOBUS_XIO_ERROR_PARAMETER,
    GLOBUS_XIO_ERROR_MEMORY,
    GLOBUS_XIO_ERROR_SYSTEM_ERROR,
    GLOBUS_XIO_ERROR_SYSTEM_RESOURCE,
    GLOBUS_XIO_ERROR_STACK,
    GLOBUS_XIO_ERROR_DRIVER,
    GLOBUS_XIO_ERROR_PASS,
    GLOBUS_XIO_ERROR_ALREADY_REGISTERED,
    GLOBUS_XIO_ERROR_STATE,
    GLOBUS_XIO_ERROR_WRAPPED,
    GLOBUS_XIO_ERROR_NOT_REGISTERED,
    GLOBUS_XIO_ERROR_NOT_ACTIVATED,
    GLOBUS_XIO_ERROR_UNLOADED,
    GLOBUS_XIO_ERROR_TIMEOUT
} globus_xio_error_type_t;


/* ALL is all but ACCEPT */
typedef enum
{
    GLOBUS_XIO_ATTR_SET_TIMEOUT_ALL,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_OPEN,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_CLOSE,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_READ,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_WRITE,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_ACCEPT,
    GLOBUS_XIO_ATTR_SET_SPACE,
    GLOBUS_XIO_ATTR_CLOSE_NO_CANCEL
} globus_xio_attr_cmd_t;

typedef enum
{
    GLOBUS_XIO_DD_SET_OFFSET,
    GLOBUS_XIO_DD_GET_OFFSET
} globus_xio_dd_cmd_t;

typedef enum
{
    GLOBUS_XIO_CANCEL_OPEN = 0x01,
    GLOBUS_XIO_CANCEL_CLOSE = 0x02,
    GLOBUS_XIO_CANCEL_READ = 0x04,
    GLOBUS_XIO_CANCEL_WRITE = 0x08
} globus_xio_cancel_t;

typedef enum
{
    GLOBUS_XIO_DEBUG_ERROR = 1,
    GLOBUS_XIO_DEBUG_WARNING = 2,
    GLOBUS_XIO_DEBUG_TRACE = 4,
    GLOBUS_XIO_DEBUG_INTERNAL_TRACE = 8,
    GLOBUS_XIO_DEBUG_INFO = 16,
    GLOBUS_XIO_DEBUG_STATE = 32,
    GLOBUS_XIO_DEBUG_INFO_VERBOSE = 64
} globus_xio_debug_levels_t;

typedef struct
{
    char *                              unparsed;
    char *                              resource;
    char *                              host;
    char *                              port;
    char *                              scheme;
    char *                              user;
    char *                              pass;
    char *                              subject;
} globus_xio_contact_t;

EXTERN_C_END

#endif

