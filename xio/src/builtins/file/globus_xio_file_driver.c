/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

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

#define GlobusIXIOFileCloseFd(fd)                                           \
    do                                                                      \
    {                                                                       \
        int                             _rc;                                \
        globus_xio_system_file_t        _fd;                                \
                                                                            \
        _fd = (fd);                                                         \
        do                                                                  \
        {                                                                   \
            _rc = close(_fd);                                               \
        } while(_rc < 0 && errno == EINTR);                                 \
                                                                            \
        (fd) = GLOBUS_XIO_SYSTEM_INVALID_FILE;                              \
    } while(0)

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
    globus_xio_system_file_t            fd;
    globus_bool_t                       use_blocking_io;
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
    GLOBUS_XIO_FILE_INVALID_HANDLE,     /* handle   */
    GLOBUS_FALSE                        /* use_blocking_io */
};

/*
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          system;
    globus_xio_system_file_t            fd;
    globus_bool_t                       converted;
    globus_bool_t                       use_blocking_io;
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
    globus_xio_system_file_t          * out_fd;
    globus_off_t *                      out_offset;
    globus_bool_t *                     out_bool;
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
      
      /* globus_off_t                   offset */
      case GLOBUS_XIO_FILE_SET_TRUNC_OFFSET:
        attr->trunc_offset = va_arg(ap, globus_off_t);
        break;
        
      /* globus_off_t *                 offset_out */
      case GLOBUS_XIO_FILE_GET_TRUNC_OFFSET:
        out_offset = va_arg(ap, globus_off_t *);
        *out_offset = attr->trunc_offset;
        break;
    
      /* globus_xio_system_file_t          fd */
      case GLOBUS_XIO_FILE_SET_HANDLE:
        attr->fd = va_arg(ap, globus_xio_system_file_t);
        break;
        
      /* globus_xio_system_file_t *        fd */
      case GLOBUS_XIO_FILE_GET_HANDLE:
        out_fd = va_arg(ap, globus_xio_system_file_t *);
        *out_fd = attr->fd;
        break;
      
      /* globus_bool_t                  use_blocking_io */
      case GLOBUS_XIO_FILE_SET_BLOCKING_IO:
        attr->use_blocking_io = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                use_blocking_io */
      case GLOBUS_XIO_FILE_GET_BLOCKING_IO:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->use_blocking_io;
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
    
    *handle = (globus_l_handle_t *)
        globus_calloc(1, sizeof(globus_l_handle_t));
    if(!*handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    
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
    globus_xio_system_file_t            converted_fd;
    globus_bool_t                       converted_std = GLOBUS_FALSE;
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
    
    handle->use_blocking_io = attr->use_blocking_io;
    converted_fd = attr->fd;
    if(converted_fd == GLOBUS_XIO_FILE_INVALID_HANDLE && 
        !contact_info->resource && contact_info->scheme)
    {
        /* if scheme is one of the following, we'll convert the handle */
        if(strcmp(contact_info->scheme, "stdin") == 0)
        {
            converted_fd = fileno(stdin);
            converted_std = GLOBUS_TRUE;
        }
        else if(strcmp(contact_info->scheme, "stdout") == 0)
        {
            converted_fd = fileno(stdout);
            converted_std = GLOBUS_TRUE;
        }
        else if(strcmp(contact_info->scheme, "stderr") == 0)
        {
            converted_fd = fileno(stderr);
            converted_std = GLOBUS_TRUE;
        }
    }
    
    if(converted_fd == GLOBUS_XIO_FILE_INVALID_HANDLE)
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
            handle->fd = open(
                contact_info->resource, flags | O_NONBLOCK, attr->mode);
        } while(handle->fd == GLOBUS_XIO_FILE_INVALID_HANDLE &&
            errno == EINTR);

        if(handle->fd == GLOBUS_XIO_FILE_INVALID_HANDLE)
        {
            result = GlobusXIOErrorSystemError("open", errno);
            goto error_open;
        }
        
        /* all handles created by me are closed on exec */
        fcntl(handle->fd, F_SETFD, FD_CLOEXEC);
        if(trunc_offset > 0)
        {
            int                         rc;
            
            rc = ftruncate(handle->fd, trunc_offset);
            if(rc < 0)
            {
                result = GlobusXIOErrorSystemError("ftruncate", errno);
                goto error_truncate;
            }
        }
    }
    else
    {
        handle->fd = converted_fd;
        handle->converted = GLOBUS_TRUE;
        
        if(!converted_std && attr->flags & GLOBUS_XIO_FILE_TRUNC)
        {
            int                         rc;
            
            rc = ftruncate(handle->fd, attr->trunc_offset);
            if(rc < 0)
            {
                result = GlobusXIOErrorSystemError("ftruncate", errno);
                goto error_truncate;
            }
        }
    }
    
    result = globus_xio_system_handle_init_file(&handle->system, handle->fd);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_handle_init_file", result);
        goto error_init;
    }
    
    globus_xio_driver_finished_open(handle, op, GLOBUS_SUCCESS);
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_init:
error_truncate:
    if(!handle->converted)
    {
        GlobusIXIOFileCloseFd(handle->fd);
    }
error_open:
    if(handle->converted)
    {
        result = GlobusXIOErrorWrapFailedWithMessage(result,
            "Unable to convert file handle %ld", (long) handle->fd);
    }
    else
    {
        result = GlobusXIOErrorWrapFailedWithMessage(result,
            "Unable to open file %s", contact_info->resource);
    }
error_pathname:
    globus_l_xio_file_handle_destroy(handle);

error_handle:
    GlobusXIOFileDebugExitWithError();
    return result;
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
    GlobusXIOName(globus_l_xio_file_close);

    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    globus_xio_system_handle_destroy(handle->system);
    
    if(!handle->converted)
    {
        GlobusIXIOFileCloseFd(handle->fd);
    }
    
    globus_xio_driver_finished_close(op, GLOBUS_SUCCESS);
    globus_l_xio_file_handle_destroy(handle);
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;
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
    globus_size_t                       nbytes;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_read);

    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    /* if buflen and waitfor are both 0, we behave like register select */
    if((globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0)) ||
        (handle->use_blocking_io &&
        globus_xio_driver_operation_is_blocking(op)))
    {
        result = globus_xio_system_read(
            handle->system,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            &nbytes);
            
        globus_xio_driver_finished_read(op, result, nbytes);
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = globus_xio_system_register_read(
            op,
            handle->system,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            globus_l_xio_file_system_read_cb,
            op);
    }
    
    GlobusXIOFileDebugExit();
    return result;
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
    globus_size_t                       nbytes;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_file_write);
    
    GlobusXIOFileDebugEnter();
    
    GlobusXIOFileDebugPrintf(
        GLOBUS_L_XIO_FILE_DEBUG_INFO,
        (_XIOSL("[%s] count=%d, 1st buflen=%d\n"),
            _xio_name, iovec_count, (int) iovec[0].iov_len));
            
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    /* if buflen and waitfor are both 0, we behave like register select */
    if((globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0)) ||
        (handle->use_blocking_io &&
        globus_xio_driver_operation_is_blocking(op)))
    {
        result = globus_xio_system_write(
            handle->system,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            &nbytes);
            
        globus_xio_driver_finished_write(op, result, nbytes);
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = globus_xio_system_register_write(
            op,
            handle->system,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            globus_l_xio_file_system_write_cb,
            op);
    }
    
    GlobusXIOFileDebugExit();
    return result;
}

static
globus_result_t
globus_l_xio_file_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_handle_t *                 handle;
    globus_xio_system_file_t *          out_fd;
    globus_off_t *                      offset;
    globus_off_t                        in_offset;
    int                                 whence;
    globus_bool_t *                     out_bool;
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
        *offset = lseek(handle->fd, *offset, whence);
        if(*offset < 0)
        {
            result = GlobusXIOErrorSystemError("lseek", errno);
        }
        break;
      
      /* globus_off_t                   offset */
      case GLOBUS_XIO_SEEK:
        in_offset = va_arg(ap, globus_off_t);
        in_offset = lseek(handle->fd, in_offset, SEEK_SET);
        if(in_offset < 0)
        {
            result = GlobusXIOErrorSystemError("lseek", errno);
        }
        break;
        
      /* globus_xio_system_file_t *     handle */
      case GLOBUS_XIO_FILE_GET_HANDLE:
        out_fd = va_arg(ap, globus_xio_system_file_t *);
        *out_fd = handle->fd;
        break;
      
      /* globus_bool_t                  use_blocking_io */
      case GLOBUS_XIO_FILE_SET_BLOCKING_IO:
        handle->use_blocking_io = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                use_blocking_io */
      case GLOBUS_XIO_FILE_GET_BLOCKING_IO:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = handle->use_blocking_io;
        break;
        
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        break;
    }
    
    GlobusXIOFileDebugExit();
    return result;
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
