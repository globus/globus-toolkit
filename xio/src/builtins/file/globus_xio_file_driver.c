#include "globus_xio_driver.h"
#include "globus_xio_file_driver.h"

static
int
globus_l_xio_file_activate();

static
int
globus_l_xio_file_deactivate();

#include "version.h"

globus_module_descriptor_t              globus_i_xio_file_module =
{
    "globus_xio_file",
    globus_l_xio_file_activate,
    globus_l_xio_file_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 *  attribute structure
 */
typedef struct
{
    int                                 mode;
    int                                 flags;
    int                                 type;
    globus_xio_system_handle_t          handle;
} globus_l_attr_t;

/* default attr */
static const globus_l_attr_t            globus_l_xio_file_attr_default =
{
    GLOBUS_XIO_FILE_IRUSR | GLOBUS_XIO_FILE_IWUSR,  /* mode     */
    GLOBUS_XIO_FILE_CREAT | GLOBUS_XIO_FILE_RDWR,   /* flags    */
    GLOBUS_XIO_FILE_TYPE_BINARY,                    /* type     */
    GLOBUS_XIO_FILE_INVALID_HANDLE                  /* handle   */
};

/*
 *  target structure
 */
typedef struct
{
    char *                              pathname;
    globus_xio_system_handle_t          handle;
} globus_l_target_t;

/* default target */
static const globus_l_target_t          globus_l_xio_file_target_default =
{
    GLOBUS_NULL,                                    /* pathname */
    GLOBUS_XIO_FILE_INVALID_HANDLE                  /* handle   */
};

/*
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
} globus_l_handle_t;

/* default handle */
static const globus_l_handle_t          globus_l_xio_file_handle_default =
{
    GLOBUS_XIO_FILE_INVALID_HANDLE                  /* handle    */
};

static
int
globus_l_xio_system_activate(void)
{
    return globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
}

static
int
globus_l_xio_system_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);
}

/*
 *  initialize a driver attribute
 */
static
globus_result_t
globus_l_xio_file_attr_init(
    void **                             out_attr)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    
    /*
     *  create a file attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_file_attr_init", "attr");
        goto error_attr;
    }
    
    memcpy(attr, &globus_l_xio_file_attr_default, sizeof(globus_l_attr_t));
    *out_attr = attr;

    return GLOBUS_SUCCESS;

error_attr:
    return result;
}

/*
 *  modify the attribute structure
 */
static
globus_result_t
globus_l_xio_file_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_attr_t *                   attr;
    int *                               out_int;
    globus_xio_system_handle_t *        out_handle;

    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd)
    {
      case GLOBUS_XIO_FILE_SET_MODE:
        attr->mode = va_arg(ap, int);
        break;

      case GLOBUS_XIO_FILE_GET_MODE:
        out_int = va_arg(ap, int *);
        *out_int = attr->mode;
        break;

      case GLOBUS_XIO_FILE_SET_FLAGS:
        attr->flags = va_arg(ap, int);
        break;

      case GLOBUS_XIO_FILE_GET_FLAGS:
        out_int = va_arg(ap, int *);
        *out_int = attr->flags;
        break;
    
      case GLOBUS_XIO_FILE_SET_TYPE:
        attr->type = va_arg(ap, int);
        break;
        
      case GLOBUS_XIO_FILE_GET_TYPE:
        out_int = va_arg(ap, int *);
        *out_int = attr->type;
        break;
        
      case GLOBUS_XIO_FILE_SET_HANDLE:
        attr->handle = va_arg(ap, int);
        break;
        
      case GLOBUS_XIO_FILE_GET_HANDLE:
        out_handle = va_arg(ap, out_handle *);
        *out_handle = attr->handle;
        break;

      default:
        return GLOBUS_XIO_ERROR_CONSTRUCT_INVALID_COMMAND(
            "globus_l_xio_file_attr_cntl", cmd);
        break;
    }

    return GLOBUS_SUCCESS;
}

/*
 *  copy an attribute structure
 */
static
globus_result_t
globus_l_xio_file_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;

    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_file_attr_copy", "attr");
        goto error_attr;
    }
    
    memcpy(attr, src, sizeof(globus_l_attr_t));
    *dst = attr;

    return GLOBUS_SUCCESS;

error_attr:
    return result;
}

/*
 *  destroy an attr structure
 */
static
globus_result_t
globus_l_xio_file_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);

    return GLOBUS_SUCCESS;
}

/*
 *  initialize target structure
 */
static
globus_result_t
globus_l_xio_file_target_init(
    void **                             out_target,
    void *                              driver_attr,
    const char *                        contact_string)
{
    globus_l_target_t *                 target;
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    
    attr = (globus_l_attr_t *) driver_attr;
    
    /* create the target structure and copy the contact string into it */
    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
    if(!target)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_file_target_init", "target");
        goto error_target;
    }
    
    memcpy(
        target,
        &globus_l_xio_file_target_default,
        sizeof(globus_l_target_t));
    
    if(!attr || attr->handle == GLOBUS_XIO_FILE_INVALID_HANDLE)
    {
        target->pathname = globus_libc_strdup(contact_string);
        if(!target->pathname)
        {
            result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
                "globus_l_xio_file_target_init", "pathname");
            goto error_pathname;
        }
    }
    else
    {
        target->handle = attr->handle;
    }
    
    *out_target = target;

    return GLOBUS_SUCCESS;

error_pathname:
    globus_free(target);
    
error_target:
    return result;
}

/*
 *  destroy the target structure
 */
static
globus_result_t
globus_l_xio_file_target_destroy(
    void *                              driver_target)
{
    globus_l_target_t *                 target;
    
    target = (globus_l_target_t *) driver_target;
    
    if(target->pathname)
    {
        globus_free(target->pathname);
    }
    globus_free(target);

    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_file_system_open_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_operation_t       op;
    globus_xio_driver_context_t         context;
    globus_l_handle_t *                 handle;
    
    op = (globus_xio_driver_operation_t) user_arg;
    
    context = GlobusXIOOperationGetContext(op);
    handle = GlobusXIOOperationGetDriverHandle(op);
    
    globus_xio_driver_finished_open(context, op, result);
    if(result != GLOBUS_SUCCESS)
    {
        globus_free(handle);
    }
}

/*
 *  open a file
 */
static
globus_result_t
globus_l_xio_file_open(
    void **                             out_handle,
    void *                              driver_attr,
    void *                              driver_target,
    globus_xio_driver_context_t         context,
    globus_xio_driver_operation_t       op)
{
    globus_l_target_t *                 target;
    globus_l_handle_t *                 handle;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    
    target = (globus_l_target_t *) target;
    attr = (globus_l_attr_t *) 
        driver_attr ? driver_attr : &globus_l_xio_file_attr_default;
    
    handle = (globus_l_handle_t *) globus_malloc(sizeof(globus_l_handle_t));
    if(!handle)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_file_open", "handle");
        goto error_handle;
    }
    memcpy(
        handle, &globus_l_xio_file_handle_default, sizeof(globus_l_handle_t));
    *out_handle = handle;
    
    if(target->handle == GLOBUS_XIO_FILE_INVALID_HANDLE)
    {
        int                             flags;
        
        flags = attr->flags;
#ifdef TARGET_ARCH_CYGWIN
        if(attr->type == GLOBUS_XIO_FILE_TYPE_TEXT)
        {
            flags |= O_TEXT;
        }
        else
        {
            flags |= O_BINARY;
        }
#endif
        result = globus_xio_system_register_open(
            op,
            target->pathname,
            flags,
            attr->mode,
            &handle->handle,
            globus_l_xio_file_system_open_cb,
            op);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_register;
        }
    }
    else
    {
        handle->handle = target->handle;
    }

    return GLOBUS_SUCCESS;
    
error_register:
    globus_free(handle);  

error_handle:
    return result;
}

static
void
globus_l_xio_file_system_close_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_operation_t       op;
    globus_xio_driver_context_t         context;
    globus_l_handle_t *                 handle;
    
    op = (globus_xio_driver_operation_t) user_arg;
    
    context = GlobusXIOOperationGetContext(op);
    handle = GlobusXIOOperationGetDriverHandle(op);
    
    globus_xio_driver_finished_close(op, result);
    globus_xio_driver_context_close(context);
    globus_free(handle);
}

/*
 *  close a file
 */
static
globus_result_t
globus_l_xio_file_close(
    void *                              driver_handle,
    globus_xio_driver_context_t         context,
    globus_xio_driver_operation_t       op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;

    handle = (globus_l_handle_t *) driver_handle;
        
    result = globus_xio_system_register_close(
        op,
        handle->handle,
        globus_l_xio_file_system_close_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }

    return GLOBUS_SUCCESS;
    
error_register:
    globus_xio_driver_context_close(context);
    globus_free(handle);
    
    return result;
}

static
void
globus_l_xio_file_system_read_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_operation_t       op;
    
    op = (globus_xio_driver_operation_t) user_arg;
    globus_xio_driver_finished_read(op, result, nbytes);
}

/*
 *  read from a file
 */
static
globus_result_t
globus_l_xio_file_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_driver_operation_t       op)
{
    globus_l_handle_t *                 handle;

    handle = (globus_l_handle_t *) driver_handle;

    return globus_xio_system_register_read(
        op,
        handle->handle,
        iovec,
        iovec_count,
        GlobusXIOOperationMinimumRead(op),
        globus_l_xio_file_system_read_cb,
        op);
}

static
void
globus_l_xio_file_system_write_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_operation_t       op;
    
    op = (globus_xio_driver_operation_t) user_arg;
    globus_xio_driver_finished_write(op, result, nbytes);
}

/*
 *  write to a file
 */
static
globus_result_t
globus_l_xio_file_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_driver_operation_t       op)
{
    globus_l_handle_t *                 handle;

    handle = (globus_l_handle_t *) driver_handle;

    return globus_xio_system_register_write(
        op,
        handle->handle,
        iovec,
        iovec_count,
        globus_l_xio_file_system_write_cb,
        op);
}

static
globus_result_t
globus_l_xio_file_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_off_t                        offset;
    int                                 whence;

    handle = (globus_l_handle_t *) driver_handle;
    switch(cmd)
    {
      case GLOBUS_XIO_FILE_SEEK:
        offset = va_arg(ap, globus_off_t);
        whence = va_arg(ap, int);
        offset = lseek(handle->handle, offset, whence);
        if(offset < 0)
        {
            return GLOBUS_XIO_ERROR_CONSTRUCT_ERRNO(
                "globus_l_xio_file_cntl", errno);
        }
        break;

      default:
        return GLOBUS_XIO_ERROR_CONSTRUCT_INVALID_COMMAND(
            "globus_l_xio_file_cntl", cmd);
        break;
    }

    return GLOBUS_SUCCESS;
}

static globus_xio_driver_t globus_l_xio_file_info =
{
    /*
     *  main io interface functions
     */
    globus_l_xio_file_open,                      /* open_func           */
    globus_l_xio_file_close,                     /* close_func          */
    globus_l_xio_file_read,                      /* read_func           */
    globus_l_xio_file_write,                     /* write_func          */
    globus_l_xio_file_cntl,                      /* handle_cntl_func    */

    globus_l_xio_file_target_init,               /* target_init_func    */
    globus_l_xio_file_target_destory,            /* target_destroy_finc */

    /*
     *  No server functions.
     */
    NULL,                                        /* server_init_func    */
    NULL,                                        /* server_accept_func  */
    NULL,                                        /* server_destroy_func */
    NULL,                                        /* server_cntl_func    */

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_l_xio_file_attr_init,                 /* attr_init_func      */
    globus_l_xio_file_attr_copy,                 /* attr_copy_func      */
    globus_l_xio_file_attr_cntl,                 /* attr_cntl_func      */
    globus_l_xio_file_attr_destroy,              /* attr_destroy_func   */

    /*
     *  No need for data descriptors.
     */
    NULL,                                        /* dd_init             */
    NULL,                                        /* dd_copy             */
    NULL,                                        /* dd_destroy          */
    NULL                                         /* dd_cntl             */
};
