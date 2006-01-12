#if !defined(GLOBUS_XIO_WRAPBLOCK_H)
#define GLOBUS_XIO_WRAPBLOCK_H 1

#include "globus_xio.h"

EXTERN_C_BEGIN

typedef globus_result_t
(*globus_xio_wrapblock_open_func_t)(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    void **                             driver_handle);

typedef globus_result_t
(*globus_xio_wrapblock_write_func_t)(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_size_t *                     nbytes);

typedef globus_result_t
(*globus_xio_wrapblock_read_func_t)(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_size_t *                     nbytes);

typedef globus_result_t
(*globus_xio_wrapblock_close_func_t)(
    void *                              driver_specific_handle,
    void *                              attr);

typedef globus_result_t
(*globus_xio_wrapblock_accept_func_t)(
    void *                              driver_server,
    void **                             out_link);


globus_result_t
globus_xio_wrapblock_init(
    globus_xio_driver_t                 driver,
    globus_xio_wrapblock_open_func_t    open,
    globus_xio_wrapblock_close_func_t   close,
    globus_xio_wrapblock_read_func_t    read,
    globus_xio_wrapblock_write_func_t   write,
    globus_xio_wrapblock_accept_func_t  accept);

EXTERN_C_END

#endif
