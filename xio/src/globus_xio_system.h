#ifndef GLOBUS_XIO_SYSTEM_INCLUDE
#define GLOBUS_XIO_SYSTEM_INCLUDE

#include "globus_common.h"
#include "globus_xio_types.h"

EXTERN_C_BEGIN

#define GLOBUS_XIO_SYSTEM_MODULE (&globus_i_xio_system_module)

extern globus_module_descriptor_t       globus_i_xio_system_module;

#define GLOBUS_XIO_SYSTEM_INVALID_HANDLE  -1
typedef int globus_xio_system_handle_t;   /* for posix, same as fd */

typedef enum
{
    /** Open file with create  */
    GLOBUS_XIO_SYSTEM_CREAT     = O_CREAT,
    /** Exclusive open */
    GLOBUS_XIO_SYSTEM_EXCL      = O_EXCL,
    /** Read-only open */
    GLOBUS_XIO_SYSTEM_RDONLY    = O_RDONLY,
    /** Write-only open */
    GLOBUS_XIO_SYSTEM_WRONLY    = O_WRONLY,
    /** Read-write open */
    GLOBUS_XIO_SYSTEM_RDWR      = O_RDWR,
    /** Open and truncate */
    GLOBUS_XIO_SYSTEM_TRUNC     = O_TRUNC,
    /** Open for append */
    GLOBUS_XIO_SYSTEM_APPEND    = O_APPEND
} globus_xio_system_open_flag_t;

typedef enum
{
    GLOBUS_XIO_SYSTEM_ERROR_SYSTEM_ERROR = 1024,
    GLOBUS_XIO_SYSTEM_ERROR_TOO_MANY_FDS,
    GLOBUS_XIO_SYSTEM_ERROR_ALREADY_REGISTERED,
    GLOBUS_XIO_SYSTEM_ERROR_OPERATION_CANCELED,
    GLOBUS_XIO_SYSTEM_ERROR_NOT_REGISTERED,
    GLOBUS_XIO_SYSTEM_ERROR_MEMORY_ALLOC

} globus_xio_system_error_type_t;

typedef void
(*globus_xio_system_callback_t)(
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_xio_system_data_callback_t)(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_connect(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          handle,
    const globus_sockaddr_t *           addr,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_accept(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          listener_handle,
    globus_xio_system_handle_t *        out_handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

/* if using from, probably want waitforbytes to be 1 */
globus_result_t
globus_xio_system_register_read_ex(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 out_from,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_write_ex(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_close(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_try_read(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes);

globus_result_t
globus_xio_system_try_read_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     nbytes);

globus_result_t
globus_xio_system_try_write(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes);

globus_result_t
globus_xio_system_try_write_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_size_t *                     nbytes);

EXTERN_C_END

#endif
