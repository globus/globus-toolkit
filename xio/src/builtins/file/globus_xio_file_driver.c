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
    globus_xio_system_handle_t          handle;
} globus_l_attr_t;

/* default attr */
static const globus_l_attr_t            globus_l_xio_file_attr_default =
{
    GLOBUS_XIO_FILE_IRUSR       |       /* mode     */
        GLOBUS_XIO_FILE_IWUSR,  
    GLOBUS_XIO_FILE_CREAT       |       /* flags    */
        GLOBUS_XIO_FILE_RDWR    | 
        GLOBUS_XIO_FILE_BINARY,   
    GLOBUS_XIO_FILE_INVALID_HANDLE      /* handle   */             
};

/*
 *  target structure
 */
typedef struct
{
    char *                              pathname;
    globus_xio_system_handle_t          handle;
} globus_l_target_t;

/*
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
} globus_l_handle_t;

static
int
globus_l_xio_file_activate(void)
{
    GlobusXIOName(globus_l_xio_file_activate);
    
    return globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
}

static
int
globus_l_xio_file_deactivate(void)
{
    GlobusXIOName(globus_l_xio_file_deactivate);
    
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
    GlobusXIOName(globus_l_xio_file_attr_init);
    
    /*
     *  create a file attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
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
    GlobusXIOName(globus_l_xio_file_attr_cntl);

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
    
      case GLOBUS_XIO_FILE_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_handle_t);
        break;
        
      case GLOBUS_XIO_FILE_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = attr->handle;
        break;

      default:
        return GlobusXIOErrorInvalidCommand(cmd);
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
    GlobusXIOName(globus_l_xio_file_attr_copy);

    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
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
    GlobusXIOName(globus_l_xio_file_attr_destroy);
    
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
    GlobusXIOName(globus_l_xio_file_target_init);
    
    attr = (globus_l_attr_t *) driver_attr;
    
    /* create the target structure and copy the contact string into it */
    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
    if(!target)
    {
        result = GlobusXIOErrorMemory("target");
        goto error_target;
    }
    
    target->pathname = GLOBUS_NULL;
    target->handle = GLOBUS_XIO_FILE_INVALID_HANDLE;
    
    if(!attr || attr->handle == GLOBUS_XIO_FILE_INVALID_HANDLE)
    {
        target->pathname = globus_libc_strdup(contact_string);
        if(!target->pathname)
        {
            result = GlobusXIOErrorMemory("pathname");
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
    GlobusXIOName(globus_l_xio_file_target_destroy);
    
    target = (globus_l_target_t *) driver_target;
    
    if(target->pathname)
    {
        globus_free(target->pathname);
    }
    globus_free(target);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_file_handle_init(
    globus_l_handle_t **                handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_handle_init);
    
    *handle = (globus_l_handle_t *) globus_malloc(sizeof(globus_l_handle_t));
    if(!*handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    
    return GLOBUS_SUCCESS;

error_handle:
    return result;    
}

static
void
globus_l_xio_file_handle_destroy(
    globus_l_handle_t *                 handle)
{
    GlobusXIOName(globus_l_xio_file_handle_destroy);
    
    globus_free(handle);
}

typedef struct
{
    globus_xio_operation_t              op;
    globus_l_handle_t *                 handle;
} globus_l_open_info_t;

static
void
globus_l_xio_file_system_open_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_open_info_t *              open_info;
    GlobusXIOName(globus_l_xio_file_system_open_cb);
    
    open_info = (globus_l_open_info_t *) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_file_handle_destroy(open_info->handle);
        open_info->handle = GLOBUS_NULL;
    }
    
    GlobusXIODriverFinishedOpen(
        GlobusXIOOperationGetContext(open_info->op),
        open_info->handle,
        open_info->op,
        result);
    
    globus_free(open_info);
}

/*
 *  open a file
 */
static
globus_result_t
globus_l_xio_file_open(
    void *                              driver_attr,
    void *                              driver_target,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    const globus_l_target_t *           target;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    globus_l_open_info_t *              open_info;
    GlobusXIOName(globus_l_xio_file_open);
    
    target = (globus_l_target_t *) driver_target;
    attr = (globus_l_attr_t *) 
        driver_attr ? driver_attr : &globus_l_xio_file_attr_default;
    
    result = globus_l_xio_file_handle_init(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_file_handle_init", result);
        goto error_handle;
    }
    
    if(target->handle == GLOBUS_XIO_FILE_INVALID_HANDLE)
    {
        open_info = (globus_l_open_info_t *)
            globus_malloc(sizeof(globus_l_open_info_t));
        if(!open_info)
        {
            result = GlobusXIOErrorMemory("open_info");
            goto error_info;
        }
        
        open_info->op = op;
        open_info->handle = handle;
        
        result = globus_xio_system_register_open(
            op,
            target->pathname,
            attr->flags,
            attr->mode,
            &handle->handle,
            globus_l_xio_file_system_open_cb,
            open_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_xio_system_register_open", result);
            goto error_register;
        }
    }
    else
    {
        handle->handle = target->handle;
        GlobusXIODriverFinishedOpen(context, handle, op, GLOBUS_SUCCESS);
    }

    return GLOBUS_SUCCESS;
    
error_register:
    globus_free(open_info);
    
error_info:
    globus_l_xio_file_handle_destroy(handle);

error_handle:
    return result;
}

static
void
globus_l_xio_file_system_close_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_file_system_close_cb);
    
    op = (globus_xio_operation_t) user_arg;
    
    context = GlobusXIOOperationGetContext(op);
    handle = GlobusXIOOperationGetDriverHandle(op);
    
    GlobusXIODriverFinishedClose(op, result);
    globus_xio_driver_context_close(context);
    globus_l_xio_file_handle_destroy(handle);
}

/*
 *  close a file
 */
static
globus_result_t
globus_l_xio_file_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_close);

    handle = (globus_l_handle_t *) driver_handle;
        
    result = globus_xio_system_register_close(
        op,
        handle->handle,
        globus_l_xio_file_system_close_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_register_close", result);
        goto error_register;
    }

    return GLOBUS_SUCCESS;
    
error_register:
    globus_xio_driver_context_close(context);
    globus_l_xio_file_handle_destroy(handle);
    
    return result;
}

static
void
globus_l_xio_file_system_read_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_file_system_read_cb);
    
    op = (globus_xio_operation_t) user_arg;
    GlobusXIODriverFinishedRead(op, result, nbytes);
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
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_file_read);

    handle = (globus_l_handle_t *) driver_handle;
    
    if(GlobusXIOOperationGetWaitFor(op) == 0)
    {
        globus_size_t                       nbytes;
        globus_result_t                     result;
        
        result = globus_xio_system_try_read(
            handle->handle, iovec, iovec_count, &nbytes);
        GlobusXIODriverFinishedRead(op, result, nbytes);
        /* dont want to return error here mainly because error could be eof, 
         * which is against our convention to return an eof error on async
         * calls.  Other than that, the choice is arbitrary
         */
        return GLOBUS_SUCCESS;
    }
    else
    {
        return globus_xio_system_register_read(
            op,
            handle->handle,
            iovec,
            iovec_count,
            GlobusXIOOperationGetWaitFor(op),
            globus_l_xio_file_system_read_cb,
            op);
    }
}

static
void
globus_l_xio_file_system_write_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_file_system_write_cb);
    
    op = (globus_xio_operation_t) user_arg;
    GlobusXIODriverFinishedWrite(op, result, nbytes);
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
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_file_write);

    handle = (globus_l_handle_t *) driver_handle;
    
    if(GlobusXIOOperationGetWaitFor(op) == 0)
    {
        globus_size_t                       nbytes;
        globus_result_t                     result;
        
        result = globus_xio_system_try_write(
            handle->handle, iovec, iovec_count, &nbytes);
        GlobusXIODriverFinishedWrite(op, result, nbytes);
        /* Since I am finishing the request in the callstack,
         * the choice to pass the result in the finish instead of below
         * is arbitrary.
         */
        return GLOBUS_SUCCESS;
    }
    else
    {
        return globus_xio_system_register_write(
            op,
            handle->handle,
            iovec,
            iovec_count,
            GlobusXIOOperationGetWaitFor(op),
            globus_l_xio_file_system_write_cb,
            op);
    }
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
    GlobusXIOName(globus_l_xio_file_cntl);

    handle = (globus_l_handle_t *) driver_handle;
    switch(cmd)
    {
      case GLOBUS_XIO_FILE_SEEK:
        offset = va_arg(ap, globus_off_t);
        whence = va_arg(ap, int);
        offset = lseek(handle->handle, offset, whence);
        if(offset < 0)
        {
            return GlobusXIOErrorSystemError("lseek", errno);
        }
        break;

      default:
        return GlobusXIOErrorInvalidCommand(cmd);
        break;
    }

    return GLOBUS_SUCCESS;
}

static struct globus_i_xio_driver_s     globus_l_xio_file_info =
{
    /*
     *  main io interface functions
     */
    GLOBUS_NULL,                        /* transform_open_func */
    globus_l_xio_file_open,             /* transport_open_func */
    globus_l_xio_file_close,            /* close_func          */
    globus_l_xio_file_read,             /* read_func           */
    globus_l_xio_file_write,            /* write_func          */
    globus_l_xio_file_cntl,             /* handle_cntl_func    */

    globus_l_xio_file_target_init,      /* target_init_func    */
    GLOBUS_NULL,                        /* target_cntl_func    */
    globus_l_xio_file_target_destroy,   /* target_destroy_finc */

    /*
     *  No server functions.
     */
    GLOBUS_NULL,                        /* server_init_func    */
    GLOBUS_NULL,                        /* server_accept_func  */
    GLOBUS_NULL,                        /* server_destroy_func */
    GLOBUS_NULL,                        /* server_cntl_func    */

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_l_xio_file_attr_init,        /* attr_init_func      */
    globus_l_xio_file_attr_copy,        /* attr_copy_func      */
    globus_l_xio_file_attr_cntl,        /* attr_cntl_func      */
    globus_l_xio_file_attr_destroy      /* attr_destroy_func   */
};
