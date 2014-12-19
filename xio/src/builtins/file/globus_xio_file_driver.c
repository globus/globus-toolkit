/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
    globus_xio_system_file_handle_t     system;
    globus_xio_system_file_t            fd;
    globus_bool_t                       converted;
    globus_bool_t                       use_blocking_io;
    globus_mutex_t                      lock; /* only used to protect below */
    globus_off_t                        file_position;
} globus_l_handle_t;

#define GlobusXIOFileGetFilePosition(handle)                                \
    globus_l_xio_file_update_position(handle, 0, SEEK_CUR)

static
globus_off_t
globus_l_xio_file_update_position(
    globus_l_handle_t *                 handle,
    globus_off_t                        offset,
    int                                 whence)
{
    globus_mutex_lock(&handle->lock);
    {
        if(whence == SEEK_SET)
        {
            handle->file_position = offset;
        }
        else if(whence == SEEK_CUR)
        {
            handle->file_position += offset;
        }
        else if(whence == SEEK_END)
        {
            globus_off_t                size;
            
            size = globus_xio_system_file_get_size(handle->fd);
            if(size != -1)
            {
                handle->file_position = size;
            }
            
            handle->file_position += offset;
        }
        
        offset = handle->file_position;
    }
    globus_mutex_unlock(&handle->lock);
    
    return offset;
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

static
globus_result_t
globus_l_xio_file_string_cntl_mode(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    globus_result_t                     result;
    unsigned int                        mode = 0;
    int                                 sc;
    GlobusXIOName(globus_l_xio_file_string_cntl_mode);

    sc = sscanf(val, "%o", &mode);
    if(sc != 1 || mode > INT_MAX)
    {
        result = GlobusXIOErrorParse(val);
        goto error;
    }

    result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, (int) mode);

    return result;

error:

    return result;
}

static
globus_result_t
globus_l_xio_file_string_cntl_flags(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    globus_result_t                     result;
    int                                 flags = 0;

    if(strcmp(val, "r") == 0)
    {
        flags = GLOBUS_XIO_FILE_RDONLY;
    }
    else if(strcmp(val, "r+") == 0)
    {
        flags = GLOBUS_XIO_FILE_RDWR;
    }
    else if(strcmp(val, "w") == 0)
    {
        flags = GLOBUS_XIO_FILE_WRONLY |
            GLOBUS_XIO_FILE_CREAT | GLOBUS_XIO_FILE_TRUNC;
    }
    else if(strcmp(val, "w+") == 0)
    {
        flags = GLOBUS_XIO_FILE_RDWR | GLOBUS_XIO_FILE_CREAT;
    }
    else if(strcmp(val, "a") == 0)
    {
        flags = GLOBUS_XIO_FILE_CREAT |
            GLOBUS_XIO_FILE_WRONLY | GLOBUS_XIO_FILE_APPEND;
    }
    else if(strcmp(val, "a+") == 0)
    {
        flags = GLOBUS_XIO_FILE_CREAT
            | GLOBUS_XIO_FILE_RDWR | GLOBUS_XIO_FILE_APPEND;
    }
    result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, flags);

    return result;
}

static
globus_result_t
globus_l_xio_file_flags_to_string(
    int                                 flags,
    const char                        **flag_string)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    if (flags ==
        (GLOBUS_XIO_FILE_CREAT
            | GLOBUS_XIO_FILE_RDWR | GLOBUS_XIO_FILE_APPEND))
    {
        *flag_string = "a+";
    }
    else if (flags == 
        (GLOBUS_XIO_FILE_CREAT |
            GLOBUS_XIO_FILE_WRONLY | GLOBUS_XIO_FILE_APPEND))
    {
        *flag_string = "a";
    }
    else if (flags == 
        (GLOBUS_XIO_FILE_RDWR | GLOBUS_XIO_FILE_CREAT))
    {
        *flag_string = "w+";
    }
    else if (flags == 
        (GLOBUS_XIO_FILE_WRONLY |
            GLOBUS_XIO_FILE_CREAT | GLOBUS_XIO_FILE_TRUNC))
    {
        *flag_string = "w";
    }
    else if (flags == GLOBUS_XIO_FILE_RDWR)
    {
        *flag_string = "r+";
    }
    else if (flags == GLOBUS_XIO_FILE_RDONLY)
    {
        *flag_string = "r";
    }
    else
    {
        result = GLOBUS_FAILURE;
    }

    return result;
}


static globus_xio_string_cntl_table_t file_l_string_opts_table[] =
{
    {"flags", GLOBUS_XIO_FILE_SET_FLAGS,
        globus_l_xio_file_string_cntl_flags},
    {"mode", GLOBUS_XIO_FILE_SET_MODE,
        globus_l_xio_file_string_cntl_mode},
    {"blocking", GLOBUS_XIO_FILE_SET_BLOCKING_IO,
        globus_xio_string_cntl_bool},
    {NULL, 0, NULL}
};

/*
 nk*  modify the attribute structure
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
    char                              **out_string;
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
        
      case GLOBUS_XIO_GET_STRING_OPTIONS:
        {
            const char *opts_format = "flags=%s;mode=%03o;blocking=%s"; 
            const char *flags_string, *blocking_string;
            globus_result_t result = GLOBUS_SUCCESS;

            out_string = va_arg(ap, char **);
            result = globus_l_xio_file_flags_to_string(attr->flags,
                    &flags_string);
            if (result)
            {
                GlobusXIOFileDebugExitWithError();
                return result;
            }
            blocking_string = attr->use_blocking_io ? "true" : "false";
            *out_string = malloc(strlen(opts_format)
                    + strlen(flags_string)
                    + 4
                    + strlen(blocking_string));
            if (!*out_string)
            {
                result = GlobusXIOErrorMemory("attr");
                GlobusXIOFileDebugExitWithError();
                return result;
            }
            sprintf(*out_string, opts_format,
                    flags_string, attr->mode, blocking_string);
        }
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
    
    free(driver_attr);
    
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
    
    globus_mutex_init(&(*handle)->lock, NULL);
    
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
    
    globus_mutex_destroy(&handle->lock);
    free(handle);
    
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
        converted_fd = globus_xio_system_convert_stdio(contact_info->scheme);
        if(converted_fd != GLOBUS_XIO_FILE_INVALID_HANDLE)
        {
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

#ifdef O_LARGEFILE
        flags |= O_LARGEFILE;
#endif

        result = globus_xio_system_file_open(
            &handle->fd, contact_info->resource, flags, attr->mode);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_open;
        }

        if(trunc_offset > 0)
        {
            result = globus_xio_system_file_truncate(
                handle->fd, trunc_offset);
            if(result != GLOBUS_SUCCESS)
            {
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
            result = globus_xio_system_file_truncate(
                handle->fd, attr->trunc_offset);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_truncate;
            }
        }
        
        handle->file_position =
            globus_xio_system_file_get_position(handle->fd);
    }
    
    result = globus_xio_system_file_init(&handle->system, handle->fd);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_file_init", result);
        goto error_init;
    }
    
    globus_xio_driver_finished_open(handle, op, GLOBUS_SUCCESS);
    
    GlobusXIOFileDebugExit();
    return GLOBUS_SUCCESS;

error_init:
error_truncate:
    if(!handle->converted)
    {
        globus_xio_system_file_close(handle->fd);
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
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_file_close);

    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    globus_xio_system_file_destroy(handle->system);
    
    if(!handle->converted)
    {
        res = globus_xio_system_file_close(handle->fd);
    }
    
    globus_xio_driver_finished_close(op, res);
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
    
    globus_l_xio_file_update_position(
        (globus_l_handle_t *) globus_xio_operation_get_driver_specific(op),
        nbytes,
        SEEK_CUR);
        
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
    globus_off_t                        offset;
    GlobusXIOName(globus_l_xio_file_read);

    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    result = globus_xio_driver_data_descriptor_cntl(
        op, NULL, GLOBUS_XIO_DD_GET_OFFSET, &offset);
    if(result != GLOBUS_SUCCESS || offset == -1)
    {
        offset = GlobusXIOFileGetFilePosition(handle);
    }
    else
    {
        globus_l_xio_file_update_position(handle, offset, SEEK_SET);
    }
    
    GlobusXIOFileDebugPrintf(
        GLOBUS_L_XIO_FILE_DEBUG_INFO,
        ("[%s] count=%d, 1st buflen=%d offset=%" GLOBUS_OFF_T_FORMAT "\n",
            _xio_name, iovec_count, (int) iovec[0].iov_len, offset));
            
    /* if buflen and waitfor are both 0, we behave like register select */
    if((globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0)) ||
        (handle->use_blocking_io &&
        globus_xio_driver_operation_is_blocking(op)))
    {
        result = globus_xio_system_file_read(
            handle->system,
            offset,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            &nbytes);
        
        globus_l_xio_file_update_position(handle, nbytes, SEEK_CUR);
        globus_xio_driver_finished_read(op, result, nbytes);
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = globus_xio_system_file_register_read(
            op,
            handle->system,
            offset,
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
    
    globus_l_xio_file_update_position(
        (globus_l_handle_t *) globus_xio_operation_get_driver_specific(op),
        nbytes,
        SEEK_CUR);
        
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
    globus_off_t                        offset;
    GlobusXIOName(globus_l_xio_file_write);
    
    GlobusXIOFileDebugEnter();
    
    handle = (globus_l_handle_t *) driver_specific_handle;
    
    result = globus_xio_driver_data_descriptor_cntl(
        op, NULL, GLOBUS_XIO_DD_GET_OFFSET, &offset);
    if(result != GLOBUS_SUCCESS || offset == -1)
    {
        offset = GlobusXIOFileGetFilePosition(handle);
    }
    else
    {
        globus_l_xio_file_update_position(handle, offset, SEEK_SET);
    }
    
    GlobusXIOFileDebugPrintf(
        GLOBUS_L_XIO_FILE_DEBUG_INFO,
        ("[%s] count=%d, 1st buflen=%d offset=%" GLOBUS_OFF_T_FORMAT "\n",
            _xio_name, iovec_count, (int) iovec[0].iov_len, offset));
            
    /* if buflen and waitfor are both 0, we behave like register select */
    if((globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0)) ||
        (handle->use_blocking_io &&
        globus_xio_driver_operation_is_blocking(op)))
    {
        result = globus_xio_system_file_write(
            handle->system,
            offset,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            &nbytes);
        
        globus_l_xio_file_update_position(handle, nbytes, SEEK_CUR);
        globus_xio_driver_finished_write(op, result, nbytes);
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = globus_xio_system_file_register_write(
            op,
            handle->system,
            offset,
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
        *offset = globus_l_xio_file_update_position(handle, *offset, whence);
        break;
      
      /* globus_off_t                   offset */
      case GLOBUS_XIO_SEEK:
        in_offset = va_arg(ap, globus_off_t);
        globus_l_xio_file_update_position(handle, in_offset, SEEK_SET);
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
    
    /* I don't support any driver options, so I'll ignore the ap */
    
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

    globus_xio_driver_string_cntl_set_table(
        driver,
        file_l_string_opts_table);
    
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
