#ifndef GLOBUS_XIO_SYSTEM_INCLUDE
#define GLOBUS_XIO_SYSTEM_INCLUDE

#include "globus_common.h"

EXTERN_C_BEGIN

#define GLOBUS_XIO_SYSTEM_MODULE (&globus_i_xio_system_module)

extern globus_module_descriptor_t       globus_i_xio_system_module;

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
} globus_xio_system_flag_t;

typedef enum
{
    GLOBUS_XIO_SYSTEM_ERROR_SYSTEM_ERROR = 1024,
    GLOBUS_XIO_SYSTEM_ERROR_TOO_MANY_FDS,
    GLOBUS_XIO_SYSTEM_ERROR_ALREADY_REGISTERED,
    GLOBUS_XIO_SYSTEM_ERROR_OPERATION_CANCELED,
    GLOBUS_XIO_SYSTEM_ERROR_NOT_REGISTERED,
    GLOBUS_XIO_SYSTEM_ERROR_MEMORY_ALLOC

} globus_xio_system_error_type_t;

typedef int globus_xio_system_handle_t;   /* for posix, same as fd */

typedef void
(*globus_xio_system_callback_t)(
    globus_xio_system_handle_t          handle,
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_xio_system_data_callback_t)(
    globus_xio_system_handle_t          handle,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

globus_result_t
globus_xio_system_open(
    const char *                        pathname,
    int                                 flags,
    int                                 mode,
    globus_xio_system_handle_t *        out_handle);

globus_result_t
globus_xio_system_register_open(
    const char *                        pathname,
    int                                 flags,
    int                                 mode,
    globus_xio_system_handle_t *        out_handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_connect(
    globus_xio_system_handle_t          handle,
    const globus_sockaddr_t *           addr);

/* new_handle in callback will be the same as handle */
globus_result_t
globus_xio_system_register_connect(
    globus_xio_system_handle_t          handle,
    const globus_sockaddr_t *           addr,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_accept(
    globus_xio_system_handle_t          listener_handle,
    globus_xio_system_handle_t *        out_handle);

globus_result_t
globus_xio_system_register_accept(
    globus_xio_system_handle_t          listener_handle,
    globus_xio_system_handle_t *        out_handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

/* nread == -1 on eof (nbytes in callback) */
globus_result_t
globus_xio_system_read(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nread);

globus_result_t
globus_xio_system_read_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    const globus_sockaddr_t *           from,
    globus_size_t *                     nread);

globus_result_t
globus_xio_system_register_read(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_read_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    const globus_sockaddr_t *           from,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_write(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nwritten);

globus_result_t
globus_xio_system_write_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_size_t *                     nwritten);

globus_result_t
globus_xio_system_register_write(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_register_write_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_close(
    globus_xio_system_handle_t          handle);

globus_result_t
globus_xio_system_register_close(
    globus_xio_system_handle_t          handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_cancel_open(
    globus_xio_system_handle_t          handle);

globus_result_t
globus_xio_system_cancel_connect(
    globus_xio_system_handle_t          handle);

globus_result_t
globus_xio_system_cancel_accept(
    globus_xio_system_handle_t          listener_handle);

globus_result_t
globus_xio_system_cancel_read(
    globus_xio_system_handle_t          handle);

globus_result_t
globus_xio_system_cancel_write(
    globus_xio_system_handle_t          handle);

EXTERN_C_END

#endif
