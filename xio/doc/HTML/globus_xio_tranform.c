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

static
globus_result_t
globus_xio_driver_ascii(
    globus_xio_driver_t *                       out_driver)
{
    *out_driver = &globus_xio_driver_ascii_info;

    return GLOBUS_SUCCESS;
}

static
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

static
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

static
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
        /* find the first '\n' if there is one */
        tmp_ptr = memchr(iovec[ctr].buffer, '\n', iovec[ctr].len);
        while(tmp_ptr != NULL)
        {
            /* calculate the index of the '\n' for lateruse */
            ndx = tmp_ptr - iovec[ctr].buffer;

            /* reallooc the size of the buffer to include '\r'*/
            iovec[ctr].buffer = realloc(iovec[ctr].buffer, iovec[ctr].len + 1);
            /* move everything ove tomakeroom for the '\r' */
            memmove(&iovec[ctr].buffer[ndx], 
                iovec[ctr].buffer[ndx + 1], len - ndx - 1);

            /* add in the '\r' */
            iovec[ctr].buffer[ndx] = '\r';

            /* set the next start point after the new "\r\n" */
            tmp_ptr = iovec[ctr].buffer[ndx+2];

            /* increase the buffer length */
            iovec[ctr].len++;

            /* find the next '\n' */
            tmp_ptr = memchr(tmp_ptr, '\n', iovec[ctr].len - ndx - 2);
        }
    }

    /* pass the write request down the stack */
    res = globus_xio_driver_write(op, iovec, iovec_count, NULL, NULL);

    return res;
}

static
void *
l_find_crlf(
    globus_byte_t *                             buffer,
    int                                         length)
{
    tmp_s = memchr(buffer, '\r', length);
    if(tmp_s == NULL)
    {
        return NULL;
    }

}

static
globus_result_t
globus_xio_driver_ascii_read(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    globus_result_t                             res;

    /* we do nothing until data is returned so simplly pass the request */

    res = globus_xio_driver_read(
              op,
              iovec,
              iovec_count,
              GlobusXIODriverOperationMinimumRead(op),
              ascii_read_callback,
              driver_handle);

    return res;
}

static
void
ascii_read_callback(
    globus_xio_operation_t                      op,
    globus_result_t                             result,
    globus_size_t                               nbytes,
    void *                                      user_arg,
    
    globus_xio_iovec_t *                        iovec,
    int                                         iovec_count)
{
    struct globus_l_xio_ascii_handle_s *        ascii_handle;
    globus_result_t                             res;
    int                                         ctr;

    ascii_handle = (struct globus_l_xio_ascii_handle_s *) driver_handle;

    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        if(ascii_handle->last_r)
        {
            ascii_handle->last_r = 0;
            /* if previous buffer ended in '\r' and this one does not 
               start in \nthe add the \r into the stream */
            if(iovec[ctr].buffer[0] != '\n')
            {
                iovec[ctr].len++;
                tmp_s = malloc(iovec[ctr].len);
                tmp_s[0] = '\r';
                memcpy(&iovec[ctr].buffer[1], 
                                        iovec[ctr].len);
            }
        }
        start = iovec[ctr].buffer;
        tmp_ptr = memchr(start, '\r', iovec[ctr].len);
        while(tmp_ptr != NULL)
        {
            /* calculate the index of the '\r' */
            ndx = tmp_ptr - start;
            /* if last thing in the stack deal with it on next pass */
            if(ndx == iovec[ctr].len)
            {
                ascii_handle->last_r = 1;
                iovec[ctr].len--;
            }
            /* if it is"\r\n" */
            else if(tmp_ptr[ndx + 1] == '\n')
            {
                /* move the mery over the '\r' anddecrement the length */
                memmove(&tmp_ptr[ndx + 1], tmp_ptr[ndx], len - ndx - 1);
                iovec[ctr].len--;
                ascii_handle->last_r = 1;
                start = tmp_ptr[ndx];
            }

            /* oove past the one that wasjust found and research */
            start++;
            tmp_ptr = memchr(start, '\r', iovec[ctr].len);
        }
    }
}

static globus_xio_driver_t globus_xio_driver_ascii_info = 
{
    /*
     *  main io interface functions
     */
    globus_xio_driver_ascii_open,
    globus_xio_driver_ascii_close,
    globus_xio_driver_ascii_read,
    globus_xio_driver_ascii_write,     
    NULL,

    NULL,
    NULL,

    /*
     *  No server functions.
     */
    NULL,
    NULL,
    NULL,
    NULL,

    /*
     *  driver attr functions.  All or none may be NULL
     */
    NULL,
    NULL,
    NULL,
    NULL,
    
    /*
     *  No need for data descriptors.
     */
    NULL,
    NULL,
    NULL,
    NULL,
};
