#include "globus_xio_driver.h"
#include "globus_xio_file_driver.h"
#include "version.h"
#include <stdio.h>

GlobusDebugDefine(GLOBUS_XIO_FILE);

#define GlobusXIOFileDebugPrintf(level, message)                            \
    GlobusDebugPrintf(GLOBUS_XIO_FILE, level, message)

#define GlobusXIOFileDebugEnter()                                           \
    GlobusXIOFileDebugPrintf(                                               \
        GLOBUS_L_XIO_FILE_DEBUG_TRACE,                                      \
        (_XIOSL("[%s] Entering\n"), _xio_name))
        
#define GlobusXIOFileDebugExit()                                            \
    GlobusXIOFileDebugPrintf(                                               \
        GLOBUS_L_XIO_FILE_DEBUG_TRACE,                                      \
        (_XIOSL("[%s] Exiting\n"), _xio_name))

#define GlobusXIOFileDebugExitWithError()                                   \
    GlobusXIOFileDebugPrintf(                                               \
        GLOBUS_L_XIO_FILE_DEBUG_TRACE,                                      \
        (_XIOSL("[%s] Exiting with error\n"), _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_FILE_DEBUG_TRACE       = 1,
    GLOBUS_L_XIO_FILE_DEBUG_INFO        = 2
};

static
int
globus_l_xio_file_activate(void);

static
int
globus_l_xio_file_deactivate(void);

GlobusXIODefineModule(file) =
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
    globus_off_t                        trunc_offset;
    globus_xio_system_handle_t          handle;
} globus_l_attr_t;

/* default attr */
static const globus_l_attr_t            globus_l_xio_file_attr_default =
{
    GLOBUS_XIO_FILE_IRUSR       |       /* mode     */
        GLOBUS_XIO_FILE_IWUSR   |
        GLOBUS_XIO_FILE_IRGRP   |
        GLOBUS_XIO_FILE_IROTH,
    GLOBUS_XIO_FILE_CREAT       |       /* flags    */
        GLOBUS_XIO_FILE_RDWR    | 
        GLOBUS_XIO_FILE_BINARY,
    0,                                  /* trunc_offset */
    GLOBUS_XIO_FILE_INVALID_HANDLE      /* handle   */             
};

/*
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
    globus_bool_t                       converted;
} globus_l_handle_t;

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
    
    GlobusXIOFileDebugEnter();
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
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOFileDebugExitWithError();
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
    globus_off_t *                      out_offset;
    GlobusXIOName(globus_l_xio_file_attr_cntl);
    
    GlobusXIOFileDebugEnter();
    
    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd)
    {
      /* int                            mode */
      case GLOBUS_XIO_FILE_SET_MODE:
        attr->mode = va_arg(ap, int);
        break;
        
      /* int *                          mode_out */
      case GLOBUS_XIO_FILE_GET_MODE:
        out_int = va_arg(ap, int *);
        *out_int = attr->mode;
        break;

      /* int                            mode */
      case GLOBUS_XIO_FILE_SET_FLAGS:
        attr->flags = va_arg(ap, int);
        break;

      /* int *                          mode_out */
      case GLOBUS_XIO_FILE_GET_FLAGS:
        out_int = va_arg(ap, int *);
        *out_int = attr->flags;
        break;
      
      /* globus_off_t                     offset */
      case GLOBUS_XIO_FILE_SET_TRUNC_OFFSET:
        attr->trunc_offset = va_arg(ap, globus_off_t);
        break;
        
      /* globus_off_t *                   offset_out */
      case GLOBUS_XIO_FILE_GET_TRUNC_OFFSET:
        out_offset = va_arg(ap, globus_off_t *);
        *out_offset = attr->trunc_offset;
        break;
    
      /* globus_xio_system_handle_t     handle */
      case GLOBUS_XIO_FILE_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_handle_t);
        break;
        
      /* globus_xio_system_handle_t *   handle */
      case GLOBUS_XIO_FILE_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = attr->handle;
        break;

      default:
        GlobusXIOFileDebugExitWithError();
        return GlobusXIOErrorInvalidCommand(cmd);
        break;
    }
    
    GlobusXIOFileDebugExit();
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
    
    GlobusXIOFileDebugEnter();
    
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, src, sizeof(globus_l_attr_t));
    *dst = attr;
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOFileDebugExitWithError();
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
    
    GlobusXIOFileDebugEnter();
    
    globus_free(driver_attr);
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_file_handle_init(
    globus_l_handle_t **                handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_handle_init);
    
    GlobusXIOFileDebugEnter();
    
    *handle = (globus_l_handle_t *) globus_malloc(sizeof(globus_l_handle_t));
    if(!*handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    (*handle)->converted = GLOBUS_FALSE;
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_handle:
    GlobusXIOFileDebugExitWithError();
    return result;    
}

static
void
globus_l_xio_file_handle_destroy(
    globus_l_handle_t *                 handle)
{
    GlobusXIOName(globus_l_xio_file_handle_destroy);
    
    GlobusXIOFileDebugEnter();
    
    globus_free(handle);
    
    GlobusXIOFileDebugExit();
}

typedef struct
{
    globus_xio_operation_t              op;
    globus_l_handle_t *                 handle;
    globus_off_t                        trunc_offset;
} globus_l_open_info_t;

/*
 *  open a file
 */
static
globus_result_t
globus_l_xio_file_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    globus_xio_system_handle_t          converted_handle;
    GlobusXIOName(globus_l_xio_file_open);
    
    GlobusXIOFileDebugEnter();
    
    attr = (globus_l_attr_t *) 
        driver_attr ? driver_attr : &globus_l_xio_file_attr_default;
    
    result = globus_l_xio_file_handle_init(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_file_handle_init", result);
        goto error_handle;
    }
    
    converted_handle = attr->handle;
    if(converted_handle == GLOBUS_XIO_FILE_INVALID_HANDLE && 
        !contact_info->resource && contact_info->scheme)
    {
        /* if scheme is one of the following, we'll convert the handle */
        if(strcmp(contact_info->scheme, "stdin") == 0)
        {
            converted_handle = fileno(stdin);
        }
        else if(strcmp(contact_info->scheme, "stdout") == 0)
        {
            converted_handle = fileno(stdout);
        }
        else if(strcmp(contact_info->scheme, "stderr") == 0)
        {
            converted_handle = fileno(stderr);
        }
    }
    
    if(converted_handle == GLOBUS_XIO_FILE_INVALID_HANDLE)
    {
        int                             flags;
        globus_off_t                    trunc_offset = 0;
        
        if(!contact_info->resource)
        {
            result = GlobusXIOErrorContactString("missing path");
            goto error_pathname;
        }
        
        flags = attr->flags;
        if((attr->flags & GLOBUS_XIO_FILE_TRUNC) && attr->trunc_offset > 0)
        {
            flags = flags & ~GLOBUS_XIO_FILE_TRUNC;
            trunc_offset = attr->trunc_offset;
        }
        
        do
        {
            handle->handle = open(
                contact_info->resource, flags | O_NONBLOCK, attr->mode);
        } while(handle->handle < 0 && errno == EINTR);

        if(handle->handle < 0)
        {
            result = GlobusXIOErrorSystemError("open", errno);
            goto error_open;
        }
        
        /* all handles created by me are closed on exec */
        fcntl(handle->handle, F_SETFD, FD_CLOEXEC);
        if(trunc_offset > 0)
        {
            int                         rc;
            
            rc = ftruncate(handle->handle, trunc_offset);
            if(rc < 0)
            {
                result = GlobusXIOErrorSystemError("ftruncate", errno);
                
                do
                {
                    rc = close(handle->handle);
                } while(rc < 0 && errno == EINTR);
                
                goto error_truncate;
            }
        }
    }
    else
    {
        handle->handle = converted_handle;
        handle->converted = GLOBUS_TRUE;
        
        if(attr->flags & GLOBUS_XIO_FILE_TRUNC)
        {
            int                         rc;
            
            rc = ftruncate(handle->handle, attr->trunc_offset);
            if(rc < 0)
            {
                result = GlobusXIOErrorSystemError("ftruncate", errno);
                goto error_truncate;
            }
        }
    }
    
    globus_xio_driver_finished_open(handle, op, GLOBUS_SUCCESS);
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_open:
error_truncate:
error_pathname:
    globus_l_xio_file_handle_destroy(handle);

error_handle:
    GlobusXIOFileDebugExitWithError();
    return result;
}

static
void
globus_l_xio_file_system_close_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_file_system_close_cb);
    
    GlobusXIOFileDebugEnter();
    
    op = (globus_xio_operation_t) user_arg;
    
    handle = (globus_l_handle_t *)
        globus_xio_operation_get_driver_specific(op);
    
    globus_xio_driver_finished_close(op, result);
    globus_l_xio_file_handle_destroy(handle);
    
    GlobusXIOFileDebugExit();
}

/*
 *  close a file
 */
static
globus_result_t
globus_l_xio_file_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_close);

    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    if(handle->converted)
    {
        globus_xio_driver_finished_close(op, GLOBUS_SUCCESS);
        globus_l_xio_file_handle_destroy(handle);
    }
    else
    {
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
    }
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;
    
error_register:
    globus_l_xio_file_handle_destroy(handle);
    
    GlobusXIOFileDebugExitWithError();
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
    
    GlobusXIOFileDebugEnter();
    
    op = (globus_xio_operation_t) user_arg;
    globus_xio_driver_finished_read(op, result, nbytes);
    
    GlobusXIOFileDebugExit();
}

/*
 *  read from a file
 */
static
globus_result_t
globus_l_xio_file_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_file_read);

    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    /* if buflen and waitfor are both 0, we behave like register select */
    if(globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0))
    {
        globus_size_t                   nbytes;
        globus_result_t                 result;
        
        result = globus_xio_system_try_read(
            handle->handle, iovec, iovec_count, &nbytes);
        globus_xio_driver_finished_read(op, result, nbytes);
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
            globus_xio_operation_get_wait_for(op),
            globus_l_xio_file_system_read_cb,
            op);
    }
    
    GlobusXIOFileDebugExit();
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
    
    GlobusXIOFileDebugEnter();
    
    op = (globus_xio_operation_t) user_arg;
    globus_xio_driver_finished_write(op, result, nbytes);
    
    GlobusXIOFileDebugExit();
}

/*
 *  write to a file
 */
static
globus_result_t
globus_l_xio_file_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_file_write);
    
    GlobusXIOFileDebugEnter();
    
    GlobusXIOFileDebugPrintf(
        GLOBUS_L_XIO_FILE_DEBUG_INFO,
        (_XIOSL("[%s] count=%d, 1st buflen=%d\n"),
            _xio_name, iovec_count, (int) iovec[0].iov_len));
            
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    /* if buflen and waitfor are both 0, we behave like register select */
    if(globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0))
    {
        globus_size_t                   nbytes;
        globus_result_t                 result;
        
        result = globus_xio_system_try_write(
            handle->handle, iovec, iovec_count, &nbytes);
        globus_xio_driver_finished_write(op, result, nbytes);
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
            globus_xio_operation_get_wait_for(op),
            globus_l_xio_file_system_write_cb,
            op);
    }
    
    GlobusXIOFileDebugExit();
}

static
globus_result_t
globus_l_xio_file_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_xio_system_handle_t *        out_handle;
    globus_off_t *                      offset;
    int                                 whence;
    GlobusXIOName(globus_l_xio_file_cntl);
    
    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    switch(cmd)
    {
      /* globus_off_t *                 in_out_offset */
      /* globus_xio_file_whence_t       whence */
      case GLOBUS_XIO_FILE_SEEK:
        offset = va_arg(ap, globus_off_t *);
        whence = va_arg(ap, int);
        *offset = lseek(handle->handle, *offset, whence);
        if(*offset < 0)
        {
            return GlobusXIOErrorSystemError("lseek", errno);
        }
        break;
      
      /* globus_xio_system_handle_t *   handle */
      case GLOBUS_XIO_FILE_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = handle->handle;
        break;

      default:
        return GlobusXIOErrorInvalidCommand(cmd);
        break;
    }
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_file_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_init);
    
    GlobusXIOFileDebugEnter();
    
    /* I dont support any driver options, so I'll ignore the ap */
    
    result = globus_xio_driver_init(&driver, "file", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_file_handle_init", result);
        goto error_init;
    }

    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_file_open,
        globus_l_xio_file_close,
        globus_l_xio_file_read,
        globus_l_xio_file_write,
        globus_l_xio_file_cntl);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_file_attr_init,
        globus_l_xio_file_attr_copy,
        globus_l_xio_file_attr_cntl,
        globus_l_xio_file_attr_destroy);
    
    *out_driver = driver;
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIOFileDebugExitWithError();
    return result;
}

static
void
globus_l_xio_file_destroy(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_file_destroy);
    
    GlobusXIOFileDebugEnter();
    
    globus_xio_driver_destroy(driver);
    
    GlobusXIOFileDebugExit();
}

GlobusXIODefineDriver(
    file,
    globus_l_xio_file_init,
    globus_l_xio_file_destroy);

static
int
globus_l_xio_file_activate(void)
{
    int                                 rc;
    
    GlobusXIOName(globus_l_xio_file_activate);
    
    GlobusDebugInit(GLOBUS_XIO_FILE, TRACE INFO);
    
    GlobusXIOFileDebugEnter();
    
    rc = globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto error_activate;
    }
    
    GlobusXIORegisterDriver(file);
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_activate:
    GlobusXIOFileDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_FILE);
    return rc;
}

static
int
globus_l_xio_file_deactivate(void)
{
    GlobusXIOName(globus_l_xio_file_deactivate);
    
    GlobusXIOFileDebugEnter();
    
    GlobusXIOUnRegisterDriver(file);
    globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);
    
    GlobusXIOFileDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_FILE);
    
    return GLOBUS_SUCCESS;
}
