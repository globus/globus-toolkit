#include "globus_xio_driver.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 *  possible commands for att cntl
 */
enum
{
    GLOBUS_XIO_FILE_SET_MODE = 1,
    GLOBUS_XIO_FILE_GET_MODE,
    GLOBUS_XIO_FILE_SET_FLAGS,
    GLOBUS_XIO_FILE_GET_FALGS,
    GLOBUS_XIO_FILE_GET_EOF,
    GLOBUS_XIO_FILE_MAX_CMD = GLOBUS_XIO_FILE_GET_EOF,
}

/*
 *  attribute structure 
 */
struct globus_l_xio_file_attr_s
{
    int                                         mode;
    int                                         flags;
}

/*
 *  target structure
 */
struct globus_l_xio_file_target_s
{
    char                                        cs[256];
}

/*
 *  handle structure
 */
struct globus_l_xio_file_handle_s
{
    int                                         fd;
};

globus_result_t
globus_xio_driver_file(
    globus_xio_driver_t *                       out_driver)
{
    *out_driver = &globus_xio_driver_file_info;

    return GLOBUS_SUCCESS;
}

/*
 *  initialize a driver attribute 
 */
globus_result_t
globus_xio_driver_file_attr_init(
    void **                                     out_attr)
{
    struct globus_l_xio_file_attr_s *           file_attr;

    /*
     *  create a file attr structure and intialize its values
     */
    file_attr = (struct globus_l_xio_file_attr_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_attr_s));

    file_attr->flags = O_CREAT;
    file_attr->mode = S_IRWXU;

    /* set the out parameter to the driver attr */
    *out_attr = file_attr;

    return GLOBUS_SUCCESS;
}

/*
 *  modify the attribute structure
 */
globus_result_t
globus_xio_driver_file_attr_cntl(
    void *                                      attr,
    int                                         cmd,
    va_list                                     ap)
{
    struct globus_l_xio_file_attr_s *           file_attr;
    int *                                       out_i;

    file_attr = (struct globus_l_xio_file_attr_s *)attr;
    switch(cmd)
    {
        case GLOBUS_XIO_FILE_SET_MODE:
            file_attr->mode = va_arg(ap, int);
            break;

        case GLOBUS_XIO_FILE_GET_MODE:
            out_i = va_arg(ap, int *);
            *out_i = file_attr->mode;
            break;

        case GLOBUS_XIO_FILE_SET_FLAGS:
            file_attr->flags = va_arg(ap, int);
            break;

        case GLOBUS_XIO_FILE_GET_FLAGS:
            out_i = va_arg(ap, int *);
            *out_i = file_attr->flags;
            break;

        default:
            return FILE_DRIVER_ERROR_COMMAND_NOT_FOUND;
            break;
    }

    return GLOBUS_SUCCESS;
}

/*
 *  copy an attribute structure
 */
globus_result_t
globus_xio_driver_file_attr_copy(
    void **                                     dst,
    void *                                      src)
{
    struct globus_l_xio_file_attr_s *           file_attr;

    file_attr = (struct globus_l_xio_file_attr_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_attr_s));

    memcpy(file_attr, src, sizeof(struct globus_l_xio_file_attr_s));

    *dst = file_attr;

    return GLOBUS_SUCCESS;
}

/*
 *  destroy an attr structure
 */
globus_result_t
globus_xio_driver_file_attr_destroy(
    void *                                      attr)
{
    globus_free(attr);

    return GLOBUS_SUCCESS;
}

/*
 *  initialize target structure
 *
 *  all we need to do is hang onto the contact string here
 */
globus_result_t
globus_xio_driver_file_target_init(
    void **                                     out_target,
    void *                                      target_attr,
    const char *                                contact_string,
    globus_xio_driver_stack_t                   stack)
{
    struct globus_l_xio_file_target_s *         target;

    /* create the target structure and copy the contact string into it */
    target = (struct globus_l_xio_file_target_s *)
                globus_malloc(sizeof(struct globus_l_xio_file_target_s));
    sprintf(target->cs, "%s", contact_string);

    return GLOBUS_SUCCESS;
}

/*
 *  destroy the target structure
 */
globus_result_t
globus_xio_driver_file_target_destroy(
    void *                                      target)
{
    globus_free(target);

    return GLOBUS_SUCCESS;
}

/*
 *  request info from the handle
 */
globus_result_t
globus_xio_driver_file_handle_cntl(
    void *                                      driver_handle,
    int                                         cmd,
    va_list                                     ap)
{
    int *                                       out_i;

    switch(cmd)
    {
        case GLOBUS_XIO_FILE_GET_EOF:
            out_i = va_arg(ap, int *);
            *out_i = file_handle->eof;
            break;

        default:
            return FILE_DRIVER_ERROR_COMMAND_NOT_FOUND;
            break;
    }

    return GLOBUS_SUCCESS;
}

/*
 *  open a file
 */
globus_result_t
globus_xio_driver_file_open(
    void **                                     driver_handle,
    void *                                      driver_handle_attr,
    void *                                      target,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op);
{
    struct globus_l_xio_file_target_s *         file_target;
    struct globus_l_xio_file_handle_s *         file_handle;
    int                                         fd;

    file_target = (struct globus_l_xio_file_target_s *) target;

    /*
     * open the file referenced by the contact string given in target 
     * init.
     */
    fd = open(file_target->cs, file_attr->flags, file_attr->mode);
    if(fd < 0)
    {
        return GLOBUS_FAILURE;
    }

    file_handle = (struct globus_l_xio_file_handle_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_handle_s));
    file_handle->fd = fd;

    /* set the driver_handle return parameter to our handle */
    *driver_handle = file_handle;

    /* tell globus_xio that we have finished the open request */
    globus_xio_driver_finished_open(context, op);

    return GLOBUS_SUCCESS;
}

/*
 *  close a file
 */
globus_result_t
globus_xio_driver_file_close(
    void *                                      driver_handle,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;
    /* preform the posix close operation */
    close(file_handle->fd);
    globus_free(file_handle);

    /* tell globus_xio that we have finished the close operation */
    globus_xio_driver_finished_close(op);
    /* tell globus_xio that we are finished with the context */
    globus_xio_driver_context_close(op);
    
    return GLOBUS_SUCCESS;
}

/*
 *  read from a file
 */
globus_result_t
globus_xio_driver_file_read(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;
    ssize_t                                     nbytes;
    int                                         ctr;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    /* preform all read requests in the iovec */
    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        nbytes = read(file_handle->fd, 
                      iovec[ctr].iov_base, 
                      iovec[ctr].iov_len);

        /* check the return codes */
        if(nbytes < 0)
        {
            res = globus_error_put(
                    globus_error_construct_errno_error(
                        GLOBUS_XIO_MODULE,
                        NULL,
                        errno));
            return res;
        }
        else if(nbytes == 0)
        {
            /* set nbytes in iovec to be EOF (represented by -1) */
            iovec[ctr].nbytes = -1;
            return GLOBUS_SUCCESS;
        }
        else
        {
            /* set the number of bytes writen in the iovec */
            iovec[ctr].nbytes = nbytes;
        }
    }

    /* tell globus_xio that we have finished the read operation */
    globus_xio_driver_finished_read(op);

    return GLOBUS_SUCCESS;
}

/*
 *  write to a file
 */
globus_result_t
globus_xio_driver_file_write(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;
    ssize_t                                     nbytes;
    int                                         ctr;
    globus_result_t                             res;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    /* preform all write requests in the iovec */
    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        nbytes = fwrite(file_handle->fd,
                        iovec[ctr].iov_base, 
                        iovec[ctr].iov_len);
        /* check the return codes */
        if(nbytes < 0)
        {
            res = globus_error_put(
                    globus_error_construct_errno_error(
                        GLOBUS_XIO_MODULE,
                        NULL,
                        errno));
            return res;
        }
        else
        {
            /* set the number of bytes writen in the iovec */
            iovec[ctr].nbytes = nbytes;
        }
    }

    /* tell globus io that the write request is complete */
    globus_xio_driver_finished_write(op);

    return GLOBUS_SUCCESS;
}

static globus_xio_driver_t globus_xio_driver_file_info = 
{
    /*
     *  main io interface functions
     */
    globus_xio_driver_file_open,
    globus_xio_driver_file_close,
    globus_xio_driver_file_read,
    globus_xio_driver_file_write,     
    globus_xio_driver_file_handle_cntl,
    1,

    globus_xio_driver_file_target_init,
    globus_xio_driver_file_target_destory,

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
    globus_xio_driver_file_attr_init,
    globus_xio_driver_file_attr_copy,
    globus_xio_driver_file_attr_cntl,
    globus_xio_driver_file_attr_destroy,
    GLOBUS_XIO_FILE_MAX_CMD,
    
    /*
     *  No need for data descriptors.
     */
    NULL,
    NULL,
    NULL,
    NULL,
    0,
};
