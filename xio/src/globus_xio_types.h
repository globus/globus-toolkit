#if !defined(GLOBUS_XIO_TYPES_H)
#define GLOBUS_XIO_TYPES_H 1

#include "globus_common.h"
#include <sys/uio.h>


/*************************************************************************
 *    define types
 ************************************************************************/
struct globus_i_xio_handle_s;
struct globus_i_xio_context_s;
struct globus_i_xio_target_s;
struct globus_i_xio_op_s;
struct globus_i_xio_driver_s;
struct globus_i_xio_attr_s;
struct globus_i_xio_stack_s;
struct globus_i_xio_server_s;
struct globus_i_xio_dd_s;

typedef struct globus_i_xio_handle_s *          globus_xio_handle_t;
typedef struct globus_i_xio_context_entry_s *   globus_xio_context_t;
typedef struct globus_i_xio_target_s *          globus_xio_target_t;
typedef struct globus_i_xio_op_s *              globus_xio_operation_t;
typedef struct globus_i_xio_driver_s *          globus_xio_driver_t;
typedef struct globus_i_xio_attr_s *            globus_xio_attr_t;
typedef struct globus_i_xio_stack_s *           globus_xio_stack_t;
typedef struct globus_i_xio_server_s *          globus_xio_server_t;
typedef struct globus_i_xio_dd_s *              globus_xio_data_descriptor_t;

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
    GLOBUS_XIO_OPERATION_TYPE_FINISHED,
    GLOBUS_XIO_OPERATION_TYPE_OPEN,
    GLOBUS_XIO_OPERATION_TYPE_CLOSE,
    GLOBUS_XIO_OPERATION_TYPE_READ,
    GLOBUS_XIO_OPERATION_TYPE_WRITE,
    GLOBUS_XIO_OPERATION_TYPE_ACCEPT,
} globus_xio_operation_type_t;

typedef enum globus_i_xio_signal_type_e
{
    GLOBUS_XIO_SIGNAL_TYPE_NONE,
} globus_xio_signal_type_t;

typedef enum
{
    GLOBUS_XIO_ERROR_BAD_PARAMETER_ERROR = 1024,
    GLOBUS_XIO_ERROR_MEMORY_ALLOC,
    GLOBUS_XIO_ERROR_DRIVER_NOT_FOUND,
    GLOBUS_XIO_ERROR_INVALID_STACK,
    GLOBUS_XIO_OPERATION_CANCELED,
    GLOBUS_XIO_ERROR_HANDLE_BAD_STATE,
} globus_xio_error_t;

#endif
