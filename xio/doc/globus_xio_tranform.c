#include "globus_xio_driver.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 *  handle structure
 */
struct globus_l_xio_ascii_handle_s
{
    int                                         last_r;
};

globus_result_t
globus_xio_driver_ascii(
    globus_xio_driver_t *                       out_driver)
{
    *out_driver = &globus_xio_driver_ascii_info;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_ascii_open(
    void **                                     driver_handle,
    void *                                      driver_handle_attr,
    void *                                      target,
    globus_xio_driver_operation_t               op);
{
    struct globus_l_xio_ascii_handle_s *        ascii_handle;
    globus_result_t                             res;

    ascii_handle = (struct globus_l_xio_ascii_handle_s *)
            globus_malloc(sizeof(struct globus_l_xio_ascii_handle_s));
    ascii_handle->last_r = 0;

    *driver_handle = ascii_handle;

    res = globus_xio_driver_open(NULL, op, NULL, NULL);

    return res;
}

globus_result_t
globus_xio_driver_ascii_close(
    void *                                      driver_handle,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_ascii_handle_s *        ascii_handle;
    globus_result_t                             res;

    ascii_handle = (struct globus_l_xio_ascii_handle_s *) driver_handle;

    res = globus_xio_driver_close(op, NULL, NULL);

    if(res == GLOBUS_SUCCESS)
    {
        globus_free(ascii_handle);
    }

    return res;
}

globus_result_t
globus_xio_driver_ascii_write(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_ascii_handle_s *        ascii_handle;
    globus_result_t                             res;
    int                                         ctr;

    ascii_handle = (struct globus_l_xio_ascii_handle_s *) driver_handle;

    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        tmp_ptr = memchr(iovec[ctr].buffer, '\n', iovec[ctr].len);
        while(tmp_ptr != NULL)
        {
            ndx = tmp_ptr - iovec[ctr].buffer;
            iovec[ctr].buffer = realloc(iovec[ctr].buffer, iovec[ctr].len + 1);
            memmove(&iovec[ctr].buffer[ndx], 
                iovec[ctr].buffer[ndx + 1], len - ndx - 1);
            iovec[ctr].buffer[ndx] = '\r';
            tmp_ptr = iovec[ctr].buffer[ndx+2];

            tmp_ptr = memchr(tmp_ptr, '\n', iovec[ctr].len - ndx - 2);
        }
    }

    res = globus_xio_driver_write(op, iovec, iovec_count, NULL, NULL);

    return res;
}

static globus_xio_driver_t globus_xio_driver_ascii_info = 
{
    /*
     *  main io interface functions
     */
    globus_xio_driver_ascii_open,
    globus_xio_driver_ascii_close,
    NULL,
    globus_xio_driver_ascii_write,     
    NULL,
    1,

    NULL,
    NULL,

    /*
     *  No server functions.
     */
    NULL,
    NULL,
    NULL,
    NULL,
    0,

    /*
     *  driver attr functions.  All or none may be NULL
     */
    NULL,
    NULL,
    NULL,
    NULL,
    0,
    
    /*
     *  No need for data descriptors.
     */
    NULL,
    NULL,
    NULL,
    NULL,
    0,
};
