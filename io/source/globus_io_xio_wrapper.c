
#include "globus_io.h"
#include <arpa/inet.h>
#include <gssapi.h>
#include <globus_error_gssapi.h>

#ifdef __GNUC__
#define GlobusIOName(func) static const char * _io_name __attribute__((__unused__)) = #func
#else
#define GlobusIOName(func) static const char * _io_name = #func
#endif

#define GlobusLIOCheckHandle(handle, _type)                                 \
    do                                                                      \
    {                                                                       \
        if(!(handle) || !*(handle))                                         \
        {                                                                   \
            return globus_error_put(                                        \
                globus_io_error_construct_null_parameter(                   \
                    GLOBUS_IO_MODULE,                                       \
                    GLOBUS_NULL,                                            \
                    #handle,                                                \
                    1,                                                      \
                    (char *) _io_name));                                    \
        }                                                                   \
                                                                            \
        if((_type) && !((*(handle))->type & (_type)))                       \
        {                                                                   \
            return globus_error_put(                                        \
                globus_io_error_construct_bad_pointer(                      \
                    GLOBUS_IO_MODULE,                                       \
                    GLOBUS_NULL,                                            \
                    #handle,                                                \
                    1,                                                      \
                    (char *) _io_name));                                    \
        }                                                                   \
    } while(0)

#define GlobusLIOCheckAttr(attr, types, need_gsi)                           \
    do                                                                      \
    {                                                                       \
        globus_result_t                 _result;                            \
                                                                            \
        _result = globus_l_io_attr_check(                                   \
            (attr),                                                         \
            (types),                                                        \
            (need_gsi),                                                     \
            _io_name);                                                      \
        if(_result != GLOBUS_SUCCESS)                                       \
        {                                                                   \
            return _result;                                                 \
        }                                                                   \
    } while(0)

#define GlobusLIOCheckNullParam(arg)                                        \
    if(!(arg))                                                              \
        return globus_error_put(                                            \
            globus_io_error_construct_null_parameter(                       \
                GLOBUS_IO_MODULE,                                           \
                GLOBUS_NULL,                                                \
                #arg,                                                       \
                1,                                                          \
                (char *) _io_name))

#define GlobusLIOMalloc(pointer, type)                                      \
    ((pointer = (type *) globus_malloc(sizeof(type)))                       \
        ? (GLOBUS_SUCCESS)                                                  \
        : (globus_error_put(                                                \
            globus_io_error_construct_system_failure(                       \
                GLOBUS_IO_MODULE,                                           \
                GLOBUS_NULL,                                                \
                GLOBUS_NULL,                                                \
                errno))))

#define GlobusLIOMallocSize(__pointer, __size)                              \
    ((__pointer = globus_malloc(__size))                                    \
        ? (GLOBUS_SUCCESS)                                                  \
        : (globus_error_put(                                                \
            globus_io_error_construct_system_failure(                       \
                GLOBUS_IO_MODULE,                                           \
                GLOBUS_NULL,                                                \
                GLOBUS_NULL,                                                \
                errno))))


#define GlobusLIOErrorWrapGSSFailed(failed_func, major_status, minor_status) \
    globus_error_put(                                                        \
        globus_error_wrap_gssapi_error(                                      \
            GLOBUS_IO_MODULE,                                                \
            major_status,                                                    \
            minor_status,                                                    \
            2,                                                               \
            "[%s:%d] %s failed.",                                            \
            _io_name, __LINE__, (failed_func)))


typedef enum
{
    GLOBUS_I_IO_FILE_ATTR = 1,
    GLOBUS_I_IO_TCP_ATTR  = 2
} globus_l_io_attr_type_t;

typedef enum
{
    GLOBUS_I_IO_FILE_HANDLE = 1,
    GLOBUS_I_IO_TCP_HANDLE  = 2
} globus_l_io_handle_type_t;

typedef struct globus_l_io_secure_authorization_data_s
{
    gss_name_t                                  identity;
    globus_io_secure_authorization_callback_t   callback;
    void *				        callback_arg;
} globus_l_io_secure_authorization_data_t; 

typedef struct globus_l_io_attr_s
{
    globus_l_io_attr_type_t                     type;
    globus_xio_attr_t                           attr;
    int                                         file_flags;
    globus_io_secure_authentication_mode_t      authentication_mode;
    globus_io_secure_authorization_mode_t       authorization_mode;
    globus_io_secure_channel_mode_t             channel_mode;
    globus_l_io_secure_authorization_data_t     authz_data;
} globus_l_io_attr_t;

typedef struct globus_l_io_handle_s
{
    globus_l_io_handle_type_t                   type;
    globus_io_handle_t *                        io_handle;
    globus_xio_handle_t                         xio_handle;
    /* used only for listener */
    globus_xio_server_t                         xio_server;
    globus_xio_target_t                         xio_target;
    globus_xio_attr_t                           xio_attr;
    globus_io_secure_authorization_mode_t       authorization_mode;
    globus_io_secure_authorization_data_t       authz_data;
} globus_l_io_handle_t;

typedef struct
{
    globus_bool_t                       done;
    globus_result_t                     result;
    globus_mutex_t                      lock;
    globus_cond_t                       cond;
    void *                              arg;
} globus_l_io_monitor_t;

typedef struct
{
    globus_l_io_handle_t *              handle;
    globus_io_handle_t *                u_handle;
    union
    {
        globus_io_callback_t            non_io;
        globus_io_read_callback_t       read_write;
        globus_io_writev_callback_t     writev;
    } cb;
    void *                              user_arg;
} globus_l_io_bounce_t;



static globus_mutex_t                   globus_l_io_driver_lock;
static globus_xio_driver_t              globus_l_io_file_driver;
static globus_xio_driver_t              globus_l_io_tcp_driver;
static globus_xio_driver_t              globus_l_io_gsi_driver;

static
int
globus_l_io_activate(void);

static
int
globus_l_io_deactivate(void);

#include "version.h"

globus_module_descriptor_t              globus_l_io_module =
{
    "globus_io",
    globus_l_io_activate,
    globus_l_io_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
int
globus_l_io_activate(void)
{
    if(globus_module_activate(GLOBUS_XIO_MODULE) != GLOBUS_SUCCESS)
    {
        goto error_activate;
    }
    
    if(globus_xio_driver_load(
        "file", &globus_l_io_file_driver) != GLOBUS_SUCCESS)
    {
        goto error_load_file;
    }
    
    if(globus_xio_driver_load(
        "tcp", &globus_l_io_tcp_driver) != GLOBUS_SUCCESS)
    {
        goto error_load_tcp;
    }

    if(globus_xio_driver_load(
        "gsi", &globus_l_io_gsi_driver) != GLOBUS_SUCCESS)
    {
        goto error_load_gsi;
    }
    
    globus_mutex_init(&globus_l_io_driver_lock, GLOBUS_NULL);
    
    return GLOBUS_SUCCESS;

error_load_gsi:
    globus_xio_driver_unload(globus_l_io_tcp_driver);

 error_load_tcp:
    globus_xio_driver_unload(globus_l_io_file_driver);
 
error_load_file:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    
error_activate:
    return GLOBUS_FAILURE;
}

static
int
globus_l_io_deactivate(void)
{
    globus_xio_driver_unload(globus_l_io_file_driver);
    globus_xio_driver_unload(globus_l_io_tcp_driver);
    globus_xio_driver_unload(globus_l_io_gsi_driver);
    globus_mutex_destroy(&globus_l_io_driver_lock);
    
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}

static
globus_result_t
globus_l_io_attr_check(
    globus_io_attr_t *                  attr,
    int                                 types,
    globus_bool_t                       need_gsi,
    const char *                        func_name)
{
    globus_l_io_attr_t *                iattr;
    
    if(!attr)
    {
        return globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                (char *) func_name));
    }
    
    iattr = (globus_l_io_attr_t *) *attr;
    
    if(!iattr || !(iattr->type & types))
    {
        return globus_error_put(
            globus_io_error_construct_bad_pointer(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                1,
                (char *) func_name));
    }
    
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_io_iattr_copy(
    globus_io_attr_t *                  dest,
    globus_io_attr_t *                  source)
{
    globus_l_io_attr_t *                source_iattr;
    globus_l_io_attr_t *                dest_iattr;
    globus_result_t                     result;
    GlobusIOName(globus_io_fileattr_init);
    
    source_iattr = (globus_l_io_attr_t *) *source;
    
    result = GlobusLIOMalloc(dest_iattr, globus_l_io_attr_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    dest_iattr->type = source_iattr->type;
    dest_iattr->file_flags = source_iattr->file_flags;
    result = globus_xio_attr_copy(&dest_iattr->attr, source_iattr->attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_copy;
    }
    
    *dest = dest_iattr;
    return GLOBUS_SUCCESS;

error_copy:
    globus_free(dest_iattr);
    
error_alloc:
    *dest = GLOBUS_NULL;
    return result;
}

static
void
globus_l_io_bounce_io_cb(
    globus_xio_handle_t                 xio_handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_l_io_bounce_io_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        if(globus_xio_error_is_eof(result))
        {
            result = globus_error_put(
                globus_io_error_construct_eof(
                    GLOBUS_IO_MODULE,
                    globus_error_get(result),
                    bounce_info->handle->io_handle));
        }
        else if(globus_xio_error_is_canceled(result))
        {
            result = globus_error_put(
                globus_io_error_construct_io_cancelled(
                    GLOBUS_IO_MODULE,
                    globus_error_get(result),
                    bounce_info->handle->io_handle));
        }
    }
    
    bounce_info->cb.read_write(
        bounce_info->user_arg,
        bounce_info->handle->io_handle,
        result,
        buffer,
        nbytes);
    
    globus_free(bounce_info);
}

static
void
globus_l_io_bounce_iovec_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_l_io_bounce_iovec_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        if(globus_xio_error_is_eof(result))
        {
            result = globus_error_put(
                globus_io_error_construct_eof(
                    GLOBUS_IO_MODULE,
                    globus_error_get(result),
                    bounce_info->handle->io_handle));
        }
        else if(globus_xio_error_is_canceled(result))
        {
            result = globus_error_put(
                globus_io_error_construct_io_cancelled(
                    GLOBUS_IO_MODULE,
                    globus_error_get(result),
                    bounce_info->handle->io_handle));
        }
    }
    
    bounce_info->cb.writev(
        bounce_info->user_arg,
        bounce_info->handle->io_handle,
        result,
        iovec,
        count,
        nbytes);
    
    globus_free(bounce_info);
}

static
void
globus_l_io_bounce_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_l_io_handle_t *              ihandle;
    GlobusIOName(globus_l_io_bounce_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    ihandle = bounce_info->handle;
    
    if(result != GLOBUS_SUCCESS)
    {
        ihandle->xio_handle = GLOBUS_NULL;
        *ihandle->io_handle = GLOBUS_NULL;
    }
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        ihandle->io_handle,
        result);
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_free(ihandle);
    }
    globus_free(bounce_info);
}


static
void
globus_l_io_bounce_authz_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_l_io_handle_t *              ihandle;
    gss_name_t                          authorized_identity;
    gss_name_t                          peer_identity;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_desc                     peer_name_buffer;
    int                                 equal;
    gss_ctx_id_t                        context;

    GlobusIOName(globus_l_io_bounce_authz_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;

    ihandle = bounce_info->handle;
    
    if(result == GLOBUS_SUCCESS)
    { 
        switch(bounce_info->handle->authorization_mode)
        { 
          case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
            result = globus_xio_handle_cntl(
                ihandle->xio_handle,
                globus_l_io_gsi_driver,
                GLOBUS_XIO_GSI_GET_LOCAL_NAME,
                &authorized_identity);
            if(result != GLOBUS_SUCCESS)
            {
                goto done;
            }
            result = globus_xio_handle_cntl(
                ihandle->xio_handle,
                globus_l_io_gsi_driver,
                GLOBUS_XIO_GSI_GET_PEER_NAME,
                &peer_identity);
            if(result != GLOBUS_SUCCESS)
            {
                goto done;
            }
            major_status = gss_compare_name(&minor_status,
                                            authorized_identity,
                                            peer_identity,
                                            &equal);
            if(GSS_ERROR(major_status))
            {
                result = GlobusLIOErrorWrapGSSFailed("gss_compare_name",
                                                     major_status,
                                                     minor_status);
                goto done;
            }

            if(!equal)
            {
                result = globus_error_put(
                    globus_io_error_construct_authorization_failed(
                        GLOBUS_IO_MODULE,
                        GLOBUS_NULL,
                        ihandle->io_handle,
                        0,
                        0,
                        0));
            }
            
            break;                            
          case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
            authorized_identity = ihandle->authz_data->identity;
            result = globus_xio_handle_cntl(
                ihandle->xio_handle,
                globus_l_io_gsi_driver,
                GLOBUS_XIO_GSI_GET_PEER_NAME,
                &peer_identity);
            if(result != GLOBUS_SUCCESS)
            {
                goto done;
            }
            major_status = gss_compare_name(&minor_status,
                                            authorized_identity,
                                            peer_identity,
                                            &equal);
            if(GSS_ERROR(major_status))
            {
                result = GlobusLIOErrorWrapGSSFailed("gss_compare_name",
                                                     major_status,
                                                     minor_status);
                goto done;
            }

            if(!equal)
            {
                result = globus_error_put(
                    globus_io_error_construct_authorization_failed(
                        GLOBUS_IO_MODULE,
                        GLOBUS_NULL,
                        ihandle->io_handle,
                        0,
                        0,
                        0));                
            }
            
            break;            
          case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
            {
                char *                  cs;
                char *                  s;
                char                    name_buf[4101];
                gss_buffer_desc         name_buffer;
                /* copy the io crap */
                
                result = globus_xio_target_cntl(
                    ihandle->xio_target,
                    globus_l_io_tcp_driver,
                    GLOBUS_XIO_TCP_GET_REMOTE_CONTACT,
                    &cs);
                if(result != GLOBUS_SUCCESS)
                {
                    goto done;
                }
                
                /* nop off port number */
                s = strrchr(cs, ':');
                if(s)
                {
                    *s = 0;
                }
                
                snprintf(name_buf, sizeof(name_buf), "host@%s", cs);
                name_buf[sizeof(name_buf) - 1] = 0;
                globus_free(cs);
                
                name_buffer.value = name_buf;
                name_buffer.length = strlen(name_buf);
                
                major_status = gss_import_name(&minor_status,
                                               &name_buffer,
                                               GSS_C_NT_HOSTBASED_SERVICE,
                                               &authorized_identity);
                if(GSS_ERROR(major_status))
                {
                    result = GlobusLIOErrorWrapGSSFailed("gss_import_name",
                                                         major_status,
                                                         minor_status);
                    goto done;
                }
            }
            result = globus_xio_handle_cntl(
                ihandle->xio_handle,
                globus_l_io_gsi_driver,
                GLOBUS_XIO_GSI_GET_PEER_NAME,
                &peer_identity);
            if(result != GLOBUS_SUCCESS)
            {
                goto done;
            }
            major_status = gss_compare_name(&minor_status,
                                            authorized_identity,
                                            peer_identity,
                                            &equal);
            if(GSS_ERROR(major_status))
            {
                result = GlobusLIOErrorWrapGSSFailed("gss_compare_name",
                                                     major_status,
                                                     minor_status);
                gss_release_name(&minor_status,
                                 authorized_identity);
                goto done;
            }

            gss_release_name(&minor_status,
                             authorized_identity);
            
            if(!equal)
            {
                result = globus_error_put(
                    globus_io_error_construct_authorization_failed(
                        GLOBUS_IO_MODULE,
                        GLOBUS_NULL,
                        ihandle->io_handle,
                        0,
                        0,
                        0));   
            }
            break;                  
          case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
            result = globus_xio_handle_cntl(
                ihandle->xio_handle,
                globus_l_io_gsi_driver,
                GLOBUS_XIO_GSI_GET_PEER_NAME,
                &peer_identity);

            if(result != GLOBUS_SUCCESS)
            {
                goto done;
            }
            
            result = globus_xio_handle_cntl(
                ihandle->xio_handle,
                globus_l_io_gsi_driver,
                GLOBUS_XIO_GSI_GET_CONTEXT,
                &context);

            if(result != GLOBUS_SUCCESS)
            {
                goto done;
            }

            major_status = gss_display_name(&minor_status,
                                            peer_identity,
                                            &peer_name_buffer,
                                            NULL);

            if(GSS_ERROR(major_status))
            {
                result = GlobusLIOErrorWrapGSSFailed("gss_display_name",
                                                     major_status,
                                                     minor_status);
                goto done;
            }
            
            if(!ihandle->authz_data->callback(
               ihandle->authz_data->callback_arg,
               ihandle->io_handle,
               GLOBUS_SUCCESS,
               peer_name_buffer.value,
               context))
            {
                result = globus_error_put(
                    globus_io_error_construct_authorization_failed(
                        GLOBUS_IO_MODULE,
                        GLOBUS_NULL,
                        ihandle->io_handle,
                        0,
                        0,
                        0));   
            }

            free(peer_name_buffer.value);
            
            break;
          case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
          default:
            break;
        }
    }
    else
    {
        ihandle->xio_handle = GLOBUS_NULL;
    }
    
 done:
    
    if(result != GLOBUS_SUCCESS)
    {
        if(ihandle->xio_handle)
        {
            globus_xio_close(ihandle->xio_handle, GLOBUS_NULL);
            ihandle->xio_handle = GLOBUS_NULL;
        }
        
        *ihandle->io_handle = GLOBUS_NULL;
    }
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        ihandle->io_handle,
        result);
    
    if(result != GLOBUS_SUCCESS)
    {
        if(ihandle->authz_data)
        {
            globus_free(ihandle->authz_data);
        }
        globus_free(ihandle);
    }
    
    globus_free(bounce_info);
}


static
void
globus_l_io_bounce_listen_cb(
    globus_xio_server_t                 server,
    globus_xio_target_t                 target,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_l_io_bounce_listen_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    bounce_info->handle->xio_target = target;
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        bounce_info->handle->io_handle,
        result);

    globus_free(bounce_info);
}

static
void
globus_l_io_blocking_xio_data_cb(
    globus_xio_handle_t                 xio_handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_io_monitor_t *             monitor;
    GlobusIOName(globus_l_io_blocking_xio_data_cb);
    
    monitor = (globus_l_io_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        *((globus_size_t *) monitor->arg) = nbytes;
        monitor->done = GLOBUS_TRUE;
        monitor->result = result;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->lock);
}

static
void
globus_l_io_blocking_xio_iovec_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_io_monitor_t *             monitor;
    GlobusIOName(globus_l_io_blocking_xio_iovec_cb);
    
    monitor = (globus_l_io_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        *((globus_size_t *) monitor->arg) = nbytes;
        monitor->done = GLOBUS_TRUE;
        monitor->result = result;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->lock);
}

static
void
globus_l_io_blocking_xio_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_io_monitor_t *             monitor;
    GlobusIOName(globus_l_io_blocking_xio_cb);
    
    monitor = (globus_l_io_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        monitor->done = GLOBUS_TRUE;
        monitor->result = result;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->lock);
}

static
void
globus_l_io_blocking_cb(
    void *                              user_arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result)
{
    globus_l_io_monitor_t *             monitor;
    GlobusIOName(globus_l_io_blocking_cb);
    
    monitor = (globus_l_io_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        monitor->done = GLOBUS_TRUE;
        monitor->result = result;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->lock);
}

/* file attrs */

globus_result_t
globus_io_fileattr_init(
    globus_io_attr_t *                  attr)
{
    globus_l_io_attr_t *                iattr;
    globus_result_t                     result;
    GlobusIOName(globus_io_fileattr_init);
    
    GlobusLIOCheckNullParam(attr);
    
    result = GlobusLIOMalloc(iattr, globus_l_io_attr_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    iattr->type = GLOBUS_I_IO_FILE_ATTR;
    
    result = globus_xio_attr_init(&iattr->attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    iattr->file_flags = GLOBUS_IO_FILE_TYPE_BINARY;
    *attr = iattr;
    
    return GLOBUS_SUCCESS;

error_attr:
    globus_free(iattr);
    
error_alloc:
    *attr = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_fileattr_destroy(
    globus_io_attr_t *                  attr)
{
    globus_l_io_attr_t *                iattr;
    GlobusIOName(globus_io_fileattr_destroy);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_FILE_ATTR, GLOBUS_FALSE);
    
    iattr = (globus_l_io_attr_t *) *attr;
    
    globus_xio_attr_destroy(iattr->attr);
    globus_free(iattr);
    *attr = GLOBUS_NULL;
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_set_file_type(
    globus_io_attr_t *                  attr,
    globus_io_file_type_t               file_type)
{
    GlobusIOName(globus_io_attr_set_file_type);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_FILE_ATTR, GLOBUS_FALSE);
    
    (*attr)->file_flags = file_type;
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_get_file_type(
    globus_io_attr_t *                  attr,
    globus_io_file_type_t *             file_type)
{
    GlobusIOName(globus_io_attr_get_file_type);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_FILE_ATTR, GLOBUS_FALSE);
    
    *file_type = (*attr)->file_flags;
    
    return GLOBUS_SUCCESS;
}

/* tcp attrs */

globus_result_t
globus_io_tcpattr_init(
    globus_io_attr_t *                  attr)
{
    globus_l_io_attr_t *                iattr;
    globus_result_t                     result;
    GlobusIOName(globus_io_tcpattr_init);
    
    GlobusLIOCheckNullParam(attr);
    
    result = GlobusLIOMalloc(iattr, globus_l_io_attr_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    iattr->type = GLOBUS_I_IO_TCP_ATTR;
    iattr->file_flags = 0;
    iattr->authentication_mode = GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE;
    iattr->authorization_mode = GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE;
    iattr->channel_mode = GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR;
    memset(&iattr->authz_data, 0, sizeof(globus_l_io_secure_authorization_data_t));
    result = globus_xio_attr_init(&iattr->attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    *attr = iattr;
    
    return GLOBUS_SUCCESS;

error_attr:
    globus_free(iattr);
    
error_alloc:
    *attr = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_tcpattr_destroy(
    globus_io_attr_t *                  attr)
{
    globus_l_io_attr_t *                iattr;
    GlobusIOName(globus_io_tcpattr_destroy);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    iattr = (globus_l_io_attr_t *) *attr;
    
    globus_xio_attr_destroy(iattr->attr);
    globus_free(iattr);
    *attr = GLOBUS_NULL;
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_set_tcp_restrict_port(
    globus_io_attr_t *                  attr,
    globus_bool_t                       restrict_port)
{
    GlobusIOName(globus_io_attr_set_tcp_restrict_port);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_RESTRICT_PORT, 
        restrict_port);
}

globus_result_t
globus_io_attr_get_tcp_restrict_port(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     restrict_port)
{
    GlobusIOName(globus_io_attr_get_tcp_restrict_port);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_RESTRICT_PORT, 
        restrict_port);
}

globus_result_t
globus_io_attr_set_tcp_nodelay(
    globus_io_attr_t *                  attr,
    globus_bool_t                       nodelay)
{
    GlobusIOName(globus_io_attr_set_tcp_nodelay);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_NODELAY, 
        nodelay);
}

globus_result_t
globus_io_attr_get_tcp_nodelay(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     nodelay)
{
    GlobusIOName(globus_io_attr_get_tcp_nodelay);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_NODELAY, 
        nodelay);
}

globus_result_t
globus_io_attr_set_tcp_interface(
    globus_io_attr_t *                  attr,
    const char *                        interface_addr)
{
    GlobusIOName(globus_io_attr_set_tcp_interface);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_INTERFACE, 
        interface_addr);
}

globus_result_t
globus_io_attr_get_tcp_interface(
    globus_io_attr_t *                  attr,
    char **                             interface_addr)
{
    GlobusIOName(globus_io_attr_get_tcp_interface);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_INTERFACE, 
        interface_addr);
}

/* socket attrs */
globus_result_t
globus_io_attr_set_socket_reuseaddr(
    globus_io_attr_t *                  attr,
    globus_bool_t                       reuseaddr)
{
    GlobusIOName(globus_io_attr_set_socket_reuseaddr);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_REUSEADDR,
        reuseaddr);
}

globus_result_t
globus_io_attr_get_socket_reuseaddr(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     reuseaddr)
{
    GlobusIOName(globus_io_attr_get_socket_reuseaddr);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);

    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_REUSEADDR,
        reuseaddr);
}

globus_result_t
globus_io_attr_set_socket_keepalive(
    globus_io_attr_t *                  attr,
    globus_bool_t                       keepalive)
{
    GlobusIOName(globus_io_attr_set_socket_keepalive);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_KEEPALIVE, 
        keepalive);
}

globus_result_t
globus_io_attr_get_socket_keepalive(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     keepalive)
{
    GlobusIOName(globus_io_attr_get_socket_keepalive);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_KEEPALIVE, 
        keepalive);
}

globus_result_t
globus_io_attr_set_socket_linger(
    globus_io_attr_t *                  attr,
    globus_bool_t                       linger,
    int                                 linger_time)
{
    GlobusIOName(globus_io_attr_set_socket_linger);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);

    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_LINGER,
        linger,
        linger_time);
}

globus_result_t
globus_io_attr_get_socket_linger(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     linger,
    int *                               linger_time)
{
    GlobusIOName(globus_io_attr_get_socket_linger);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_LINGER,
        linger,
        linger_time);
}

globus_result_t
globus_io_attr_set_socket_oobinline(
    globus_io_attr_t *                  attr,
    globus_bool_t                       oobinline)
{
    GlobusIOName(globus_io_attr_set_socket_oobinline);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_OOBINLINE,
        oobinline);
}

globus_result_t
globus_io_attr_get_socket_oobinline(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     oobinline)
{
    GlobusIOName(globus_io_attr_get_socket_oobinline);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_OOBINLINE, 
        oobinline);
}

globus_result_t
globus_io_attr_set_socket_sndbuf(
    globus_io_attr_t *                  attr,
    int                                 sndbuf)
{
    GlobusIOName(globus_io_attr_set_socket_sndbuf);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_SNDBUF,
        sndbuf);
}

globus_result_t
globus_io_attr_get_socket_sndbuf(
    globus_io_attr_t *                  attr,
    int *                               sndbuf)
{
    GlobusIOName(globus_io_attr_get_socket_sndbuf);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_SNDBUF,
        sndbuf);
}

globus_result_t
globus_io_attr_set_socket_rcvbuf(
    globus_io_attr_t *                  attr,
    int                                 rcvbuf)
{
    GlobusIOName(globus_io_attr_set_socket_rcvbuf);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_SET_RCVBUF,
        rcvbuf);
}

globus_result_t
globus_io_attr_get_socket_rcvbuf(
    globus_io_attr_t *                  attr,
    int *                               rcvbuf)
{
    GlobusIOName(globus_io_attr_get_socket_rcvbuf);
    
    GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    
    return globus_xio_attr_cntl(
        (*attr)->attr, 
        globus_l_io_tcp_driver, 
        GLOBUS_XIO_TCP_GET_RCVBUF,
        rcvbuf);
}

/* file operations */
static
globus_result_t
globus_l_io_file_open(
    globus_io_handle_t *                handle,
    globus_l_io_attr_t *                iattr,
    const char *                        path)
{
    globus_result_t                     result;
    globus_l_io_handle_t *              ihandle;
    globus_xio_stack_t                  stack;
    globus_xio_target_t                 target;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_l_io_file_open);
    
    result = GlobusLIOMalloc(ihandle, globus_l_io_handle_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    result = globus_xio_stack_init(&stack, GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }
    
    result = globus_xio_stack_push_driver(
        stack, globus_l_io_file_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }

    result = globus_xio_target_init(&target, GLOBUS_NULL, path, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_target;
    }
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_open(
        &ihandle->xio_handle,
        iattr->attr,
        target,
        globus_l_io_blocking_xio_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_open;
    }
    
    ihandle->type = GLOBUS_I_IO_FILE_HANDLE;
    ihandle->io_handle = handle;
    ihandle->authz_data = GLOBUS_NULL;
    *handle = ihandle;
    
    /* XXX globus_xio_target_destroy(target); */
    globus_xio_stack_destroy(stack);
    
    return GLOBUS_SUCCESS;

error_open:
    /* XXX globus_xio_target_destroy(target); */
    
error_target:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
    globus_free(ihandle);

error_alloc:
    return result;
}

globus_result_t
globus_io_file_open(
    const char *                        path,
    int                                 flags,
    int                                 mode,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_io_attr_t                    myattr;
    globus_l_io_attr_t *                iattr;
    GlobusIOName(globus_io_file_open);
    
    GlobusLIOCheckNullParam(handle);
    GlobusLIOCheckNullParam(path);
    
    if(attr)
    {
        GlobusLIOCheckAttr(attr, GLOBUS_I_IO_FILE_ATTR, GLOBUS_FALSE);
        result = globus_l_io_iattr_copy(&myattr, attr);
    }
    else
    {
        result = globus_io_fileattr_init(&myattr);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    iattr = (globus_l_io_attr_t *) myattr;
    
    result = globus_xio_attr_cntl(
        iattr->attr,
        globus_l_io_file_driver,
        GLOBUS_XIO_FILE_SET_MODE,
        mode);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    result = globus_xio_attr_cntl(
        iattr->attr,
        globus_l_io_file_driver,
        GLOBUS_XIO_FILE_SET_FLAGS,
        flags | iattr->file_flags);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    result = globus_l_io_file_open(handle, iattr, path);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
        
    globus_io_fileattr_destroy(&myattr);

    return GLOBUS_SUCCESS;

error_open:
error_cntl:
    globus_io_fileattr_destroy(&myattr);
    
error_attr:
    *handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_file_seek(
    globus_io_handle_t *                handle,
    globus_off_t                        offset,
    globus_io_whence_t                  whence)
{
    GlobusIOName(globus_io_file_seek);
    
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_FILE_HANDLE);
    
    return globus_xio_handle_cntl(
        (*handle)->xio_handle,
        globus_l_io_file_driver,
        GLOBUS_XIO_FILE_SEEK,
        &offset,
        whence);
}

globus_result_t
globus_io_file_posix_convert(
    int                                 fd,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_handle_t *              ihandle;
    globus_xio_attr_t                   myattr;
    globus_xio_stack_t                  stack;
    globus_xio_target_t                 target;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_file_posix_convert);
    
    GlobusLIOCheckNullParam(handle);
    
    result = GlobusLIOMalloc(ihandle, globus_l_io_handle_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    result = globus_xio_attr_init(&myattr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    result = globus_xio_attr_cntl(
        myattr,
        globus_l_io_file_driver,
        GLOBUS_XIO_FILE_SET_HANDLE,
        fd);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    result = globus_xio_stack_init(&stack, GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }
    
    result = globus_xio_stack_push_driver(
        stack, globus_l_io_file_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }
    
    result = globus_xio_target_init(&target, myattr, "", stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_target;
    }
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_open(
        &ihandle->xio_handle,
        GLOBUS_NULL,
        target,
        globus_l_io_blocking_xio_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_open;
    }
    
    ihandle->type = GLOBUS_I_IO_FILE_HANDLE;
    ihandle->io_handle = handle;
    ihandle->authz_data = GLOBUS_NULL;
    *handle = ihandle;
    
    /* XXX globus_xio_target_destroy(target); */
    globus_xio_stack_destroy(stack);
    globus_xio_attr_destroy(myattr);
    
    return GLOBUS_SUCCESS;

error_open:
    /* XXX globus_xio_target_destroy(target); */

error_target:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
error_cntl:
    globus_xio_attr_destroy(myattr);
    
error_attr:
    globus_free(ihandle);

error_alloc:
    *handle = GLOBUS_NULL;
    return result;
}

/* tcp operations */

globus_result_t
globus_io_tcp_register_connect(
    const char *                        host,
    unsigned short                      port,
    globus_io_attr_t *                  attr,
    globus_io_callback_t                callback,
    void *                              callback_arg,
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_handle_t *              ihandle;
    globus_xio_stack_t                  stack;
    globus_xio_target_t                 target;
    char                                buf[MAXHOSTNAMELEN + 10];
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_io_tcp_register_connect);
    
    GlobusLIOCheckNullParam(handle);
    GlobusLIOCheckNullParam(callback);
    GlobusLIOCheckNullParam(host);
    
    if(attr)
    {
        GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    }
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_bounce;
    }
    
    result = GlobusLIOMalloc(ihandle, globus_l_io_handle_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_handle;
    }

    memset(ihandle, 0, sizeof(globus_l_io_handle_t));
    
    result = globus_xio_stack_init(&stack, GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }
    
    result = globus_xio_stack_push_driver(
        stack, globus_l_io_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }

    result = globus_io_attr_get_secure_authorization_mode(
        attr,
        &ihandle->authorization_mode,
        &ihandle->authz_data);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }
    
    if((*attr)->authentication_mode !=
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        result =  globus_xio_stack_push_driver(
            stack, globus_l_io_gsi_driver);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_authz;
        }
    }
    else
    {
        /* force authorization mode to none */
        ihandle->authorization_mode = GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE;
    }

    snprintf(buf, sizeof(buf), "%s:%hd", host, port);
    result = globus_xio_target_init(&target, GLOBUS_NULL, buf, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_target;
    }

    ihandle->type = GLOBUS_I_IO_TCP_HANDLE;
    ihandle->io_handle = handle;
    bounce_info->handle = ihandle;
    bounce_info->cb.non_io = callback;
    bounce_info->user_arg = callback_arg;
    *handle = ihandle;
    
    result = globus_xio_register_open(
        &ihandle->xio_handle,
        attr ? (*attr)->attr : GLOBUS_NULL,
        target,
        globus_l_io_bounce_authz_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    
    /* XXX globus_xio_target_destroy(target); */
    globus_xio_stack_destroy(stack);
    
    return GLOBUS_SUCCESS;

error_open:
    /* XXX globus_xio_target_destroy(target); */
error_target:
error_authz:
    if(ihandle->authz_data->identity != GSS_C_NO_NAME)
    {
        OM_uint32                       minor_status;

        gss_release_name(&minor_status,
                         ihandle->authz_data->identity);
    }
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
    globus_free(ihandle);
    
error_handle:
    globus_free(bounce_info);
error_bounce:
    *handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_tcp_connect(
    const char *                        host,
    unsigned short                      port,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_tcp_connect);
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_io_tcp_register_connect(
        host,
        port,
        attr,
        globus_l_io_blocking_cb,
        &monitor,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    globus_free(*handle);
    *handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_tcp_create_listener(
    unsigned short *                    port,
    int                                 backlog,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_io_attr_t                    myattr;
    globus_l_io_attr_t *                iattr;
    globus_l_io_handle_t *              ihandle;
    globus_xio_stack_t                  stack;
    GlobusIOName(globus_io_tcp_create_listener);
    
    GlobusLIOCheckNullParam(handle);
    GlobusLIOCheckNullParam(port);
    
    if(attr)
    {
        GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
        result = globus_l_io_iattr_copy(&myattr, attr);
    }
    else
    {
        result = globus_io_tcpattr_init(&myattr);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    iattr = (globus_l_io_attr_t *) myattr;
    
    result = globus_xio_attr_cntl(
        iattr->attr,
        globus_l_io_tcp_driver,
        GLOBUS_XIO_TCP_SET_PORT,
        *port);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    result = globus_xio_attr_cntl(
        iattr->attr,
        globus_l_io_tcp_driver,
        GLOBUS_XIO_TCP_SET_BACKLOG,
        backlog);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    result = GlobusLIOMalloc(ihandle, globus_l_io_handle_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    result = globus_xio_stack_init(&stack, GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }
    
    result = globus_xio_stack_push_driver(
        stack, globus_l_io_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }

    if((*attr)->authentication_mode !=
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE)
    {
        result =  globus_xio_stack_push_driver(
            stack, globus_l_io_gsi_driver);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_push;
        }
    }
    
    result = globus_xio_server_create(
        &ihandle->xio_server, iattr->attr, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server;
    }
    
    ihandle->type = GLOBUS_I_IO_TCP_HANDLE;
    ihandle->xio_handle = GLOBUS_NULL;
    ihandle->xio_target = GLOBUS_NULL;
    ihandle->xio_attr = iattr->attr;
    ihandle->authz_data = GLOBUS_NULL;
    globus_free(iattr);
    ihandle->io_handle = handle;
    *handle = ihandle;
    
    if(!*port)
    {
        char *                          contact_string;
        char *                          s;
        
        result = globus_xio_server_cntl(
            ihandle->xio_server,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_CONTACT,
            &contact_string);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_server_cntl;
        }
        
        s = strrchr(contact_string, ':');
        globus_assert(s);
        *port = atoi(s + 1);
        
        globus_free(contact_string);
    }
    
    globus_xio_stack_destroy(stack);
    
    return GLOBUS_SUCCESS;

error_server_cntl:
    globus_xio_server_close(ihandle->xio_server);
    
error_server:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
    globus_free(ihandle);
    
error_alloc:
error_cntl:
    globus_io_tcpattr_destroy(&myattr);
    
error_attr:
    *handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_tcp_register_listen(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback,
    void *                              callback_arg)
{
    globus_result_t                     result;
    globus_l_io_handle_t *              ihandle;
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_io_tcp_register_listen);
    
    GlobusLIOCheckNullParam(callback);
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    ihandle = *handle;
    if(ihandle->xio_target)
    {
        /* user called listen before accepting previous connection */
        result = globus_error_put(
            globus_io_error_construct_registration_error(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                ihandle->io_handle));
        
        goto error_registered;
    }
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_bounce;
    }
    
    bounce_info->handle = ihandle;
    bounce_info->cb.non_io = callback;
    bounce_info->user_arg = callback_arg;
    
    result = globus_xio_server_register_accept(
        ihandle->xio_server,
        ihandle->xio_attr,
        globus_l_io_bounce_listen_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_bounce:
error_registered:
    free(*handle);
    *handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_tcp_listen(
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_tcp_listen);
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_io_tcp_register_listen(
        handle, globus_l_io_blocking_cb, &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    return result;
}

/** XXX regardless, listener attr will be applied...
 * this attr will also be applied, except that it can't change whether or not
 * gsi is used
 */
globus_result_t
globus_io_tcp_register_accept(
    globus_io_handle_t *                listener_handle,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                new_handle,
    globus_io_callback_t                callback,
    void *                              callback_arg)
{
    globus_result_t                     result;
    globus_l_io_handle_t *              ihandle;
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_io_tcp_register_accept);
    
    GlobusLIOCheckNullParam(new_handle);
    GlobusLIOCheckNullParam(callback);
    GlobusLIOCheckHandle(listener_handle, GLOBUS_I_IO_TCP_HANDLE);
    
    if(!(*listener_handle)->xio_target)
    {
        result = globus_error_put(
            globus_io_error_construct_not_initialized(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "listener_handle",
                1,
                (char *) _io_name));
                
        goto error_target;
    }
    
    if(attr)
    {
        GlobusLIOCheckAttr(attr, GLOBUS_I_IO_TCP_ATTR, GLOBUS_FALSE);
    }
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_bounce;
    }
    
    result = GlobusLIOMalloc(ihandle, globus_l_io_handle_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_handle;
    }
    
    ihandle->type = GLOBUS_I_IO_TCP_HANDLE;
    ihandle->io_handle = new_handle;
    ihandle->xio_server = GLOBUS_NULL;
    ihandle->xio_target = GLOBUS_NULL;
    ihandle->xio_attr = GLOBUS_NULL;
    ihandle->authz_data = GLOBUS_NULL;
    bounce_info->handle = ihandle;
    bounce_info->cb.non_io = callback;
    bounce_info->user_arg = callback_arg;
    *new_handle = ihandle;
    
    result = globus_xio_register_open(
        &ihandle->xio_handle,
        attr ? (*attr)->attr : GLOBUS_NULL,
        (*listener_handle)->xio_target,
        globus_l_io_bounce_cb,
        bounce_info);
    (*listener_handle)->xio_target = GLOBUS_NULL;
    if(result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    
    return GLOBUS_SUCCESS;

error_open:
    globus_free(ihandle);
error_handle:
    globus_free(bounce_info);
error_bounce:
error_target:
    *new_handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_tcp_accept(
    globus_io_handle_t *                listener_handle,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_tcp_accept);
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_io_tcp_register_accept(
        listener_handle,
        attr,
        handle,
        globus_l_io_blocking_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    return result;
}

globus_result_t
globus_io_tcp_get_local_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port)
{
    globus_result_t                     result;
    char *                              cs;
    GlobusIOName(globus_io_tcp_get_local_address);
    
    GlobusLIOCheckNullParam(host);
    GlobusLIOCheckNullParam(port);
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    if((*handle)->xio_handle)
    {
        result = globus_xio_handle_cntl(
            (*handle)->xio_handle,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
            &cs);
    }
    else
    {
        result = globus_xio_server_cntl(
            (*handle)->xio_server,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
            &cs);
    }
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    if(*cs == '[')
    {
        /* interface doesnt support ipv6 addresses */
        result = globus_error_put(
            globus_io_error_construct_internal_error(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            (char *) _io_name));
            
        goto error_ipv6;
    }
    
    sscanf(cs, "%d.%d.%d.%d:%hu", &host[0], &host[1], &host[2], &host[3], port);
    globus_free(cs);
    
    return GLOBUS_SUCCESS;

error_ipv6:
    globus_free(cs);
    
error_cntl:
    return result;
}

globus_result_t
globus_io_tcp_get_remote_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port)
{
    globus_result_t                     result;
    char *                              cs;
    GlobusIOName(globus_io_tcp_get_local_address);
    
    GlobusLIOCheckNullParam(host);
    GlobusLIOCheckNullParam(port);
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    if((*handle)->xio_handle)
    {
        result = globus_xio_handle_cntl(
            (*handle)->xio_handle,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,
            &cs);
    }
    else
    {
        result = globus_xio_server_cntl(
            (*handle)->xio_server,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,
            &cs);
    }
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    if(*cs == '[')
    {
        /* interface doesnt support ipv6 addresses */
        result = globus_error_put(
            globus_io_error_construct_internal_error(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            (char *) _io_name));
            
        goto error_ipv6;
    }
    
    sscanf(cs, "%d.%d.%d.%d:%hu", &host[0], &host[1], &host[2], &host[3], port);
    globus_free(cs);
    
    return GLOBUS_SUCCESS;

error_ipv6:
    globus_free(cs);
    
error_cntl:
    return result;
}

/* read operations */

globus_result_t
globus_io_register_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t                       wait_for_nbytes,
    globus_io_read_callback_t           callback,
    void *                              callback_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_result_t                     result;
    GlobusIOName(globus_io_register_read);
    
    GlobusLIOCheckNullParam(callback);
    GlobusLIOCheckHandle(handle, 0);
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    bounce_info->handle = *handle;
    bounce_info->cb.read_write = callback;
    bounce_info->user_arg = callback_arg;
    
    result = globus_xio_register_read(
        (*handle)->xio_handle,
        buf,
        max_nbytes,
        wait_for_nbytes,
        GLOBUS_NULL,
        globus_l_io_bounce_io_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

globus_result_t
globus_io_try_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_read)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_try_read);
    
    GlobusLIOCheckNullParam(nbytes_read);
    *nbytes_read = 0;
    GlobusLIOCheckHandle(handle, 0);
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = nbytes_read;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_read(
        (*handle)->xio_handle,
        buf,
        max_nbytes,
        0,
        GLOBUS_NULL,
        globus_l_io_blocking_xio_data_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }
    
    return result;
}

globus_result_t
globus_io_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t                       wait_for_nbytes,
    globus_size_t *                     nbytes_read)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_read);
    
    GlobusLIOCheckNullParam(nbytes_read);
    *nbytes_read = 0;
    GlobusLIOCheckHandle(handle, 0);
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = nbytes_read;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_read(
        (*handle)->xio_handle,
        buf,
        max_nbytes,
        wait_for_nbytes,
        GLOBUS_NULL,
        globus_l_io_blocking_xio_data_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_eof(result))
    {
        result = globus_error_put(
            globus_io_error_construct_eof(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }
    else if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }
    
    return result;
}

/* write operations */

globus_result_t
globus_io_register_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    globus_io_write_callback_t          write_callback,
    void *                              callback_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_result_t                     result;
    GlobusIOName(globus_io_register_write);
    
    GlobusLIOCheckNullParam(write_callback);
    GlobusLIOCheckHandle(handle, 0);
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    bounce_info->handle = *handle;
    bounce_info->cb.read_write = write_callback;
    bounce_info->user_arg = callback_arg;
    
    result = globus_xio_register_write(
        (*handle)->xio_handle,
        buf,
        nbytes,
        nbytes,
        GLOBUS_NULL,
        globus_l_io_bounce_io_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

globus_result_t
globus_io_register_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_io_write_callback_t          write_callback,
    void *                              callback_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_result_t                     result;
    globus_xio_data_descriptor_t        dd;
    GlobusIOName(globus_io_register_send);
    
    GlobusLIOCheckNullParam(write_callback);
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    if(flags)
    {
        result = globus_xio_data_descriptor_init(&dd, (*handle)->xio_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_dd;
        }
        
        result = globus_xio_data_descriptor_cntl(
            dd,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_SET_SEND_FLAGS,
            flags);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_dd_cntl;
        }
    }
    else
    {
        dd = GLOBUS_NULL;
    }
    
    bounce_info->handle = *handle;
    bounce_info->cb.read_write = write_callback;
    bounce_info->user_arg = callback_arg;
    
    result = globus_xio_register_write(
        (*handle)->xio_handle,
        buf,
        nbytes,
        nbytes,
        dd,
        globus_l_io_bounce_io_cb,
        bounce_info);
    dd = GLOBUS_NULL;
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
error_dd_cntl:
    if(dd)
    {
        globus_xio_data_descriptor_destroy(dd);
    }
    
error_dd:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

globus_result_t
globus_io_register_writev(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_io_writev_callback_t         writev_callback,
    void *                              callback_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_result_t                     result;
    int                                 i;
    globus_size_t                       nbytes;
    GlobusIOName(globus_io_register_writev);
    
    GlobusLIOCheckNullParam(writev_callback);
    GlobusLIOCheckNullParam(iov);
    GlobusLIOCheckHandle(handle, 0);
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    bounce_info->handle = *handle;
    bounce_info->cb.writev = writev_callback;
    bounce_info->user_arg = callback_arg;
    
    nbytes = 0;
    for(i = 0; i < iovcnt; i++)
    {
        nbytes += iov[i].iov_len;
    }
    
    result = globus_xio_register_writev(
        (*handle)->xio_handle,
        iov,
        iovcnt,
        nbytes,
        GLOBUS_NULL,
        globus_l_io_bounce_iovec_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

globus_result_t
globus_io_try_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_written)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_try_write);
    
    GlobusLIOCheckNullParam(nbytes_written);
    *nbytes_written = 0;
    GlobusLIOCheckHandle(handle, 0);
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = nbytes_written;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_write(
        (*handle)->xio_handle,
        buf,
        max_nbytes,
        0,
        GLOBUS_NULL,
        globus_l_io_blocking_xio_data_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }
    
    return result;
}

globus_result_t
globus_io_try_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_size_t *                     nbytes_sent)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    globus_xio_data_descriptor_t        dd;
    GlobusIOName(globus_io_try_send);
    
    GlobusLIOCheckNullParam(nbytes_sent);
    *nbytes_sent = 0;
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    if(flags)
    {
        result = globus_xio_data_descriptor_init(&dd, (*handle)->xio_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_dd;
        }
        
        result = globus_xio_data_descriptor_cntl(
            dd,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_SET_SEND_FLAGS,
            flags);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_dd_cntl;
        }
    }
    else
    {
        dd = GLOBUS_NULL;
    }
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = nbytes_sent;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_write(
        (*handle)->xio_handle,
        buf,
        nbytes,
        0,
        dd,
        globus_l_io_blocking_xio_data_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }

error_dd_cntl:
    if(dd)
    {
        globus_xio_data_descriptor_destroy(dd);
    }
    
error_dd:
    return result;
}

globus_result_t
globus_io_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    globus_size_t *                     nbytes_written)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_write);
    
    GlobusLIOCheckNullParam(nbytes_written);
    *nbytes_written = 0;
    GlobusLIOCheckHandle(handle, 0);
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = nbytes_written;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_write(
        (*handle)->xio_handle,
        buf,
        nbytes,
        nbytes,
        GLOBUS_NULL,
        globus_l_io_blocking_xio_data_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }
    
    return result;
}

globus_result_t
globus_io_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_size_t *                     nbytes_sent)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    globus_xio_data_descriptor_t        dd;
    GlobusIOName(globus_io_send);
    
    GlobusLIOCheckNullParam(nbytes_sent);
    *nbytes_sent = 0;
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    if(flags)
    {
        result = globus_xio_data_descriptor_init(&dd, (*handle)->xio_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_dd;
        }
        
        result = globus_xio_data_descriptor_cntl(
            dd,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_SET_SEND_FLAGS,
            flags);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_dd_cntl;
        }
    }
    else
    {
        dd = GLOBUS_NULL;
    }
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = nbytes_sent;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_write(
        (*handle)->xio_handle,
        buf,
        nbytes,
        nbytes,
        dd,
        globus_l_io_blocking_xio_data_cb,
        &monitor);
    dd = GLOBUS_NULL;
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }

error_dd_cntl:
    if(dd)
    {
        globus_xio_data_descriptor_destroy(dd);
    }
    
error_dd:
    return result;
}

globus_result_t
globus_io_writev(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_size_t *                     bytes_written)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    int                                 i;
    globus_size_t                       nbytes;
    GlobusIOName(globus_io_writev);
    
    GlobusLIOCheckNullParam(bytes_written);
    *bytes_written = 0;
    GlobusLIOCheckNullParam(iov);
    GlobusLIOCheckHandle(handle, 0);
    
    monitor.done = GLOBUS_FALSE;
    monitor.arg = bytes_written;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);

    nbytes = 0;
    for(i = 0; i < iovcnt; i++)
    {
        nbytes += iov[i].iov_len;
    }
    
    result = globus_xio_register_writev(
        (*handle)->xio_handle,
        iov,
        iovcnt,
        nbytes,
        GLOBUS_NULL,
        globus_l_io_blocking_xio_iovec_cb,
        &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    if(globus_xio_error_is_canceled(result))
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                globus_error_get(result),
                (*handle)->io_handle));
    }
    
    return result;
}

/* miscelaneous */

static
void
globus_l_io_bounce_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_l_io_bounce_close_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    if(bounce_info->u_handle)
    {
        *bounce_info->u_handle = GLOBUS_NULL;
        if(bounce_info->handle->authz_data)
        {
            globus_free(bounce_info->handle->authz_data);
        }
        globus_free(bounce_info->handle);
    }
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        bounce_info->u_handle,
        result);
    
    globus_free(bounce_info);
}

static
void
globus_l_io_server_close_cb(
    globus_xio_server_t                 xio_server,
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_l_io_server_close_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    if(bounce_info->u_handle)
    {
        *bounce_info->u_handle = GLOBUS_NULL;
        globus_free(bounce_info->handle);
    }
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        bounce_info->u_handle,
        GLOBUS_SUCCESS);
    
    globus_free(bounce_info);
}

globus_result_t
globus_io_register_close(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback,
    void *                              callback_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    globus_l_io_handle_t *              ihandle;
    globus_result_t                     result;
    GlobusIOName(globus_io_register_close);
    
    GlobusLIOCheckNullParam(callback);
    GlobusLIOCheckHandle(handle, 0);
    ihandle = *handle;
    
    result = GlobusLIOMalloc(bounce_info, globus_l_io_bounce_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    bounce_info->handle = ihandle;
    bounce_info->u_handle = handle;
    bounce_info->cb.non_io = callback;
    bounce_info->user_arg = callback_arg;
    
    if(ihandle->xio_handle)
    {
        result = globus_xio_register_close(
            ihandle->xio_handle,
            GLOBUS_NULL,
            globus_l_io_bounce_close_cb,
            bounce_info);
        ihandle->xio_handle = GLOBUS_NULL;
    }
    else if(ihandle->xio_server)
    {
        if(ihandle->xio_attr)
        {
            globus_xio_attr_destroy(ihandle->xio_attr);
            ihandle->xio_attr = GLOBUS_NULL;
        }
        
        if(ihandle->xio_target)
        {
            globus_xio_target_destroy(ihandle->xio_target);
            ihandle->xio_target = GLOBUS_NULL;
        }
        
        result = globus_xio_server_register_close(
            ihandle->xio_server,
            globus_l_io_server_close_cb,
            bounce_info);
        ihandle->xio_server = GLOBUS_NULL;
    }
    else
    {
        result = globus_error_put(
            globus_io_error_construct_not_initialized(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                (char *) _io_name));
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    globus_free(ihandle);
    *handle = GLOBUS_NULL;
    return result;
}

globus_result_t
globus_io_close(
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_close);
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_io_register_close(
        handle, globus_l_io_blocking_cb, &monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.result = result;
    }
    
    globus_mutex_lock(&monitor.lock);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.lock);
        }
    }
    globus_mutex_unlock(&monitor.lock);
    
    globus_mutex_destroy(&monitor.lock);
    globus_cond_destroy(&monitor.cond);
    
    if(monitor.result != GLOBUS_SUCCESS)
    {
        result = monitor.result;
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;
    
error_register:
    return result;
}

globus_bool_t
globus_io_eof(
    globus_object_t *                   eof)
{
    GlobusIOName(globus_io_eof);
    
    if(eof && globus_object_get_type(eof) == GLOBUS_IO_ERROR_TYPE_EOF)
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}

/* XXXXX */
globus_result_t
globus_io_tcp_posix_convert(
    int                                 socket,
    globus_io_attr_t *                  attributes,
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_tcp_posix_convert);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_posix_convert_listener(
    int                                 socket,
    globus_io_attr_t *                  attributes,
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_tcp_posix_convert_listener);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_register_cancel(
    globus_io_handle_t *                handle,
    globus_bool_t                       perform_callbacks,
    globus_io_callback_t                cancel_callback,
    void *                              cancel_arg)
{
    GlobusIOName(globus_io_register_cancel);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_cancel(
    globus_io_handle_t *                handle,
    globus_bool_t                       perform_callbacks)
{
    GlobusIOName(globus_io_cancel);
    
    return GLOBUS_SUCCESS;
}

globus_io_handle_type_t
globus_io_get_handle_type(
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_get_handle_type);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_handle_get_user_pointer(
    globus_io_handle_t *                handle,
    void **                             user_pointer)
{
    GlobusIOName(globus_io_handle_get_user_pointer);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_handle_set_user_pointer(
    globus_io_handle_t *                handle,
    void *                              user_pointer)
{
    GlobusIOName(globus_io_handle_set_user_pointer);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_get_attr(
    globus_io_handle_t *                handle,
    globus_io_attr_t *                  attr)
{
    GlobusIOName(globus_io_tcp_get_attr);
    
    return GLOBUS_SUCCESS;
}

/*** this needs to apply everything set on the attrs ***/
globus_result_t
globus_io_tcp_set_attr(
    globus_io_handle_t *                handle,
    globus_io_attr_t *                  attr)
{
    GlobusIOName(globus_io_tcp_set_attr);
    
    return GLOBUS_SUCCESS;
}

/* XXXXX */

globus_result_t
globus_io_tcp_get_security_context(
    globus_io_handle_t *                handle,
    gss_ctx_id_t *                      context)
{
    GlobusIOName(globus_io_tcp_get_security_context);

    return globus_xio_handle_cntl(
        (*handle)->xio_handle,
        globus_l_io_gsi_driver,
        GLOBUS_XIO_GSI_GET_CONTEXT,
        context);
}

globus_result_t
globus_io_tcp_get_delegated_credential(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     cred)
{
    GlobusIOName(globus_io_tcp_get_delegated_credential);
    return globus_xio_handle_cntl(
        (*handle)->xio_handle,
        globus_l_io_gsi_driver,
        GLOBUS_XIO_GSI_GET_DELEGATED_CRED,
        cred);
}

globus_result_t
globus_io_register_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t     callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_register_init_delegation);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req)
{
    GlobusIOName(globus_io_init_delegation);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_register_accept_delegation(
    globus_io_handle_t *                handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t     callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_register_accept_delegation);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_accept_delegation(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     delegated_cred,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec)
{
    GlobusIOName(globus_io_accept_delegation);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_set_secure_authentication_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authentication_mode_t
                                        mode,
    gss_cred_id_t                       credential)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusIOName(globus_io_attr_set_secure_authentication_mode);
    (*attr)->authentication_mode = mode;

    switch(mode)
    {
      case GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI:
      case GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL:
        if(credential != GSS_C_NO_CREDENTIAL)
        { 
            result = globus_xio_attr_cntl(
                (*attr)->attr, 
                globus_l_io_gsi_driver, 
                GLOBUS_XIO_GSI_SET_CREDENTIAL, 
                credential);
        }
        break;
      case GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS:
        result = globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_ANON);
        break;
    }
    
    return result;
}

globus_result_t
globus_io_attr_get_secure_authentication_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authentication_mode_t *
                                        mode,
    gss_cred_id_t *                     credential)
{
    GlobusIOName(globus_io_attr_get_secure_authentication_mode);
    *mode = (*attr)->authentication_mode;
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_io_attr_set_secure_authorization_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authorization_mode_t
                                        mode,
    globus_io_secure_authorization_data_t *
                                        data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    GlobusIOName(globus_io_attr_set_secure_authorization_mode);
    (*attr)->authorization_mode = mode;

    switch((*attr)->authorization_mode)
    {
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
        if((*attr)->authz_data.identity != GSS_C_NO_NAME)
        {
            gss_release_name(&minor_status,
                             (*attr)->authz_data.identity);
            (*attr)->authz_data.identity = GSS_C_NO_NAME;
        }
        break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
        if((*attr)->authz_data.identity != GSS_C_NO_NAME)
        {
            gss_release_name(&minor_status,
                             (*attr)->authz_data.identity);
        }        

        major_status = gss_duplicate_name(&minor_status,
                                          (*data)->identity,
                                          &(*attr)->authz_data.identity);

        if(GSS_ERROR(major_status))
        {
            result = GlobusLIOErrorWrapGSSFailed("gss_duplicate_name",
                                                 major_status,
                                                 minor_status);
        }
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
	(*attr)->authz_data.callback = (*data)->callback;
	(*attr)->authz_data.callback_arg = (*data)->callback_arg;
	break;
    }

    return result;
}

globus_result_t
globus_io_attr_get_secure_authorization_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authorization_mode_t *
                                        mode,
    globus_io_secure_authorization_data_t *
                                        data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    GlobusIOName(globus_io_attr_get_secure_authorization_mode);

    result = GlobusLIOMalloc(*data, globus_l_io_secure_authorization_data_t);

    if(result != GLOBUS_SUCCESS)
    {
        goto done;
    }
    
    *mode = (*attr)->authorization_mode;

    switch((*attr)->authorization_mode)
    {
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
        major_status = gss_duplicate_name(&minor_status,
                                          (*attr)->authz_data.identity,
                                          &(*data)->identity);
        if(GSS_ERROR(major_status))
        {
            result = GlobusLIOErrorWrapGSSFailed("gss_duplicate_name",
                                                 major_status,
                                                 minor_status);
        }
	break;
      case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
	(*data)->callback = (*attr)->authz_data.callback;
	(*data)->callback_arg = (*attr)->authz_data.callback_arg;
	break;
    }

 done:
    
    return result;
}

globus_result_t
globus_io_attr_set_secure_extension_oids(
    globus_io_attr_t *                  attr,
    gss_OID_set                         extension_oids)
{
    GlobusIOName(globus_io_attr_set_secure_extension_oids);
    return GLOBUS_SUCCESS;    
}

globus_result_t
globus_io_attr_get_secure_extension_oids(
    globus_io_attr_t *                  attr,
    gss_OID_set *                       extension_oids)
{
    GlobusIOName(globus_io_attr_get_secure_extension_oids);
    return GLOBUS_SUCCESS;    
}

globus_result_t
globus_io_secure_authorization_data_initialize(
    globus_io_secure_authorization_data_t * data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusIOName(globus_io_secure_authorization_data_initialize);

    result = GlobusLIOMalloc(*data, globus_l_io_secure_authorization_data_t);

    if(result == GLOBUS_SUCCESS)
    {
        memset(*data, 0, sizeof(globus_l_io_secure_authorization_data_t));
    }
    
    return result;
}

globus_result_t
globus_io_secure_authorization_data_destroy(
    globus_io_secure_authorization_data_t *
                                        data)
{
    GlobusIOName(globus_io_secure_authorization_data_destroy);

    if((*data)->identity != GSS_C_NO_NAME)
    {
        OM_uint32                       minor_status;

        gss_release_name(&minor_status,
                         (*data)->identity);
    }

    globus_free(*data);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_secure_authorization_data_set_identity(
    globus_io_secure_authorization_data_t *
                                        data,
    char *                              identity)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_desc                     name_buffer;
    gss_OID                             name_type = GSS_C_NO_OID;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusIOName(globus_io_secure_authorization_data_set_identity);


    if(!strncmp("GSI-NO-TARGET", identity, 13))
    {
        (*data)->identity = GSS_C_NO_NAME;
    }
    else
    {
        name_buffer.value = identity;
        name_buffer.length = strlen(identity);
          
        /* 
         * A  GSS_C_NT_HOSTBASED_SERVICE is of the form service@FQDN
         * At least the Globus gssapi, and the Kerberos gssapi 
         * use the same form. We will check for 
         * two special forms here: host@FQDN and ftp@FQDN
         */

        if (strchr(identity,'@') && 
            !strstr(identity,"CN="))
        { 
            name_type = GSS_C_NT_HOSTBASED_SERVICE;
        }
        else if(!strncmp("<anonymous>",identity, 11))
        {
            name_type = GSS_C_NT_ANONYMOUS;
        }
        
        major_status = gss_import_name(&minor_status,
                                       &name_buffer,
                                       name_type,
                                       &(*data)->identity);
        if(GSS_ERROR(major_status))
        {
            result = GlobusLIOErrorWrapGSSFailed("gss_import_name",
                                                 major_status,
                                                 minor_status);
        }
    }
    
    return result;
}

globus_result_t
globus_io_secure_authorization_data_get_identity(
    globus_io_secure_authorization_data_t *
                                        data,
    char **                             identity)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusIOName(globus_io_secure_authorization_data_get_identity);

    if((*data)->identity != GSS_C_NO_NAME)
    { 
        OM_uint32                       major_status;
        OM_uint32                       minor_status;
        gss_buffer_desc                 name_buffer;
        
        major_status = gss_display_name(&minor_status,
                                        (*data)->identity,
                                        &name_buffer,
                                        NULL);
        if(GSS_ERROR(major_status))
        {
            result = GlobusLIOErrorWrapGSSFailed("gss_export_name",
                                                 major_status,
                                                 minor_status);
            goto done;
        }

        /* could probably just realloc the buffer contents */
        
        result = GlobusLIOMallocSize(*identity, name_buffer.length + 1);

        if(result != GLOBUS_SUCCESS)
        {
            gss_release_buffer(&minor_status,
                               &name_buffer);
            goto done;
        }

        memcpy(*identity, name_buffer.value, name_buffer.length);

        (*identity)[name_buffer.length] = '\0';

        gss_release_buffer(&minor_status,
                           &name_buffer);
    }
    else
    {
        *identity = NULL;
    }

 done:
    
    return result;
}

globus_result_t
globus_io_secure_authorization_data_set_callback(
    globus_io_secure_authorization_data_t *
                                        data,
    globus_io_secure_authorization_callback_t
                                        callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_secure_authorization_data_set_callback);

    (*data)->callback = callback;
    (*data)->callback_arg = callback_arg;
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_secure_authorization_data_get_callback(
    globus_io_secure_authorization_data_t *
                                        data,
    globus_io_secure_authorization_callback_t *
                                        callback,
    void **                             callback_arg)
{
    GlobusIOName(globus_io_secure_authorization_data_get_callback);

    *callback = (*data)->callback;
    *callback_arg = (*data)->callback_arg;
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_set_secure_channel_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_channel_mode_t     mode)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusIOName(globus_io_attr_set_secure_channel_mode);
    (*attr)->channel_mode = mode;
    switch(mode)
    {
      case GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR:
        result = globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_PROTECTION_LEVEL,
            GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE);
        break;
      case GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP:
        result = globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_WRAP_MODE,
            GLOBUS_TRUE);
        break;
      case GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP:
        result = globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_SSL_COMPATIBLE);
        break;
    }
    return result;
}

globus_result_t
globus_io_attr_get_secure_channel_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_channel_mode_t *   mode)
{
    GlobusIOName(globus_io_attr_get_secure_channel_mode);
    *mode = (*attr)->channel_mode;
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_set_secure_protection_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_protection_mode_t  mode)
{
    GlobusIOName(globus_io_attr_set_secure_protection_mode);
    
    return globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_PROTECTION_LEVEL,
            mode);
}

globus_result_t
globus_io_attr_get_secure_protection_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_protection_mode_t *mode)
{
    GlobusIOName(globus_io_attr_get_secure_protection_mode);
    return globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_GET_PROTECTION_LEVEL,
            mode);
}

globus_result_t
globus_io_attr_set_secure_delegation_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_delegation_mode_t  mode)
{
    GlobusIOName(globus_io_attr_set_secure_delegation_mode);
    return globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_DELEGATION_MODE,
            mode);
}


globus_result_t
globus_io_attr_get_secure_delegation_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_delegation_mode_t *
                                        mode)
{
    GlobusIOName(globus_io_attr_set_secure_delegation_mode);
    return globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_GET_DELEGATION_MODE,
            mode);
}

globus_result_t
globus_io_attr_set_secure_proxy_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_proxy_mode_t       mode)
{
    GlobusIOName(globus_io_attr_set_secure_proxy_mode);
    return globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_SET_PROXY_MODE,
            mode);
}

globus_result_t
globus_io_attr_get_secure_proxy_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_proxy_mode_t *     mode)
{
    GlobusIOName(globus_io_attr_get_secure_proxy_mode);
    return globus_xio_attr_cntl(
            (*attr)->attr, 
            globus_l_io_gsi_driver, 
            GLOBUS_XIO_GSI_GET_PROXY_MODE,
            mode);
}


/* netlogger functions */

globus_result_t
globus_io_attr_netlogger_set_handle(
    globus_io_attr_t *                  attr,
    globus_netlogger_handle_t *         nl_handle)
{
    GlobusIOName(globus_io_attr_netlogger_set_handle);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_attr_netlogger_copy_handle(
    globus_netlogger_handle_t *              src,
    globus_netlogger_handle_t *              dst)
{
    GlobusIOName(globus_io_attr_netlogger_copy_handle);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_write(
    globus_netlogger_handle_t *       nl_handle,
    const char *                      event,
    const char *                      id,
    const char *                      level,
    const char *                      tag)
{
    GlobusIOName(globus_netlogger_write);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_handle_init(
    globus_netlogger_handle_t *       gnl_handle,
    const char *                      hostname,
    const char *                      progname,
    const char *                      pid)
{
    GlobusIOName(globus_netlogger_handle_init);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_handle_destroy(
    globus_netlogger_handle_t *       nl_handle)
{
    GlobusIOName(globus_netlogger_handle_destroy);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_get_nlhandle(
    globus_netlogger_handle_t *       nl_handle,
    void **                           handle)
{
    GlobusIOName(globus_netlogger_get_nlhandle);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_netlogger_set_desc(
    globus_netlogger_handle_t *       nl_handle,
    char *                            desc)
{
    GlobusIOName(globus_netlogger_set_desc);
    return GLOBUS_SUCCESS;
}
