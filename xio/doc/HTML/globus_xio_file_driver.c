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
    GLOBUS_XIO_FILE_GET_FLAGS,
    GLOBUS_XIO_FILE_MAX_CMD = GLOBUS_XIO_FILE_GET_FLAGS,
};

/*
 *  attribute structure
 */
struct globus_l_xio_file_attr_s
{
    int                                         mode;
    int                                         flags;
};

/*
 *  target structure
 */
struct globus_l_xio_file_target_s
{
    char                                        pathname[256];
};

/*
 *  handle structure
 */
struct globus_l_xio_file_handle_s
{
    int                                         fd;
};

static
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
static
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
static
globus_result_t
globus_xio_driver_file_attr_cntl(
    void *                                      attr,
    int                                         cmd,
    va_list                                     ap)
{
    struct globus_l_xio_file_attr_s *           file_attr;
    int *                                       out_i;

    file_attr = (struct globus_l_xio_file_attr_s *) attr;
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
static
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
static
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
static
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
    strncpy(target->pathname, contact_string, sizeof(target->pathname) - 1);
    target->pathname[sizeof(target->pathname) - 1] = '\0';

    return GLOBUS_SUCCESS;
}

/*
 *  destroy the target structure
 */
static
globus_result_t
globus_xio_driver_file_target_destroy(
    void *                                      target)
{
    globus_free(target);

    return GLOBUS_SUCCESS;
}

/*
 *  open a file
 */
static
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
    struct globus_l_xio_file_attr_s *           file_attr;

    file_target = (struct globus_l_xio_file_target_s *) target;
    file_attr = (struct globus_l_xio_file_attr_s *) driver_handle_attr;
    
    /*
     * open the file referenced by the contact string given in target
     * init.
     */
    fd = open(
        file_target->pathname, 
        (file_attr ? file_attr->flags : O_CREAT), 
        (file_attr ? file_attr->mode : S_IRWXU));
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
    globus_xio_driver_finished_open(context, op, GLOBUS_SUCCESS);

    return GLOBUS_SUCCESS;
}

/*
 *  close a file
 */
static
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
    globus_xio_driver_finished_close(op, GLOBUS_SUCCESS);
    /* tell globus_xio that we are finished with the context */
    globus_xio_driver_context_close(context);

    return GLOBUS_SUCCESS;
}

/*
 *  read from a file
 */
static
globus_result_t
globus_xio_driver_file_read(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;
    globus_size_t                               total_nbytes = 0;
    globus_ssize_t                              nbytes;
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    /* perform all read requests in the iovec */
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
            break;
        }
        else if(nbytes == 0)
        {
            break;
        }
        
        total_nbytes += nbytes;
    }
    
    if(total_nbytes == 0 && res == GLOBUS_SUCCESS)
    {
        res = globus_xio_construct_eof();
    }

    /* tell globus_xio that we have finished the read operation */
    globus_xio_driver_finished_read(op, res, total_nbytes);

    return GLOBUS_SUCCESS;
}

/*
 *  write to a file
 */
static
globus_result_t
globus_xio_driver_file_write(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;
    globus_size_t                               total_nbytes = 0;
    globus_ssize_t                              nbytes;
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    /* preform all write requests in the iovec */
    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        nbytes = write(file_handle->fd,
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
            break;
        }
        
        total_nbytes += nbytes;
    }

    /* tell globus io that the write request is complete */
    globus_xio_driver_finished_write(op, res, total_nbytes);

    return GLOBUS_SUCCESS;
}

static globus_xio_driver_t globus_xio_driver_file_info =
{
    /*
     *  main io interface functions
     */
    globus_xio_driver_file_open,                      /* open_func           */
    globus_xio_driver_file_close,                     /* close_func          */
    globus_xio_driver_file_read,                      /* read_func           */
    globus_xio_driver_file_write,                     /* write_func          */
    NULL,                                             /* handle_cntl_func    */

    globus_xio_driver_file_target_init,               /* target_init_func    */
    globus_xio_driver_file_target_destory,            /* target_destroy_finc */

    /*
     *  No server functions.
     */
    NULL,                                             /* server_init_func    */
    NULL,                                             /* server_accept_func  */
    NULL,                                             /* server_destroy_func */
    NULL,                                             /* server_cntl_func    */

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_xio_driver_file_attr_init,                 /* attr_init_func      */
    globus_xio_driver_file_attr_copy,                 /* attr_copy_func      */
    globus_xio_driver_file_attr_cntl,                 /* attr_cntl_func      */
    globus_xio_driver_file_attr_destroy,              /* attr_destroy_func   */

    /*
     *  No need for data descriptors.
     */
    NULL,                                             /* dd_init             */
    NULL,                                             /* dd_copy             */
    NULL,                                             /* dd_destroy          */
    NULL                                              /* dd_cntl             */
};
