
#include "globus_io.h"
#include <arpa/inet.h>

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

typedef struct globus_l_io_attr_s
{
    globus_l_io_attr_type_t             type;
    globus_xio_attr_t                   attr;
    
    int                                 file_flags;
} globus_l_io_attr_t;

typedef struct globus_l_io_handle_s
{
    globus_l_io_handle_type_t           type;
    globus_io_handle_t *                io_handle;
    globus_xio_handle_t                 xio_handle;
    /* used only for listener */
    globus_xio_server_t                 xio_server;
    globus_xio_target_t                 xio_target;
    globus_xio_attr_t                   xio_attr;
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
    
    globus_mutex_init(&globus_l_io_driver_lock, GLOBUS_NULL);
    
    return GLOBUS_SUCCESS;

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
    GlobusIOName(globus_l_io_bounce_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        bounce_info->handle->io_handle,
        result);
    
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
    
    /** XXX I should do this here, but I have to ref count first... handle
     * could be destroyed in this callback
     *
    if(bounce_info->handle->xio_target)
    {
        user didnt 'accept' this target
        globus_xio_target_destroy(bounce_info->handle->xio_target);
        bounce_info->handle->xio_target = GLOBUS_NULL;
    }
     */
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
    *attr = GLOBUS_NULL;
    
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
    *attr = GLOBUS_NULL;
    
    result = GlobusLIOMalloc(iattr, globus_l_io_attr_t);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_alloc;
    }
    
    iattr->type = GLOBUS_I_IO_TCP_ATTR;
    iattr->file_flags = 0;
    
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
    
    snprintf(buf, sizeof(buf), "%s:%hd", host, port);
    result = globus_xio_target_init(&target, GLOBUS_NULL, buf, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_target;
    }
    
    ihandle->type = GLOBUS_I_IO_TCP_HANDLE;
    ihandle->io_handle = handle;
    ihandle->xio_server = GLOBUS_NULL;
    ihandle->xio_target = GLOBUS_NULL;
    ihandle->xio_attr = GLOBUS_NULL;
    bounce_info->handle = ihandle;
    bounce_info->cb.non_io = callback;
    bounce_info->user_arg = callback_arg;
    *handle = ihandle;
    
    result = globus_xio_register_open(
        &ihandle->xio_handle,
        attr ? (*attr)->attr : GLOBUS_NULL,
        target,
        globus_l_io_bounce_cb,
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
    
    result = globus_xio_server_init(&ihandle->xio_server, iattr->attr, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server;
    }
    
    ihandle->type = GLOBUS_I_IO_TCP_HANDLE;
    ihandle->xio_handle = GLOBUS_NULL;
    ihandle->xio_target = GLOBUS_NULL;
    ihandle->xio_attr = iattr->attr;
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
            GLOBUS_XIO_TCP_GET_CONTACT,
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
    globus_xio_server_destroy(ihandle->xio_server);
    
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
    uint32_t                            addr;
    globus_result_t                     result;
    GlobusIOName(globus_io_tcp_get_local_address);
    
    GlobusLIOCheckNullParam(host);
    GlobusLIOCheckNullParam(port);
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    if((*handle)->xio_handle)
    {
        globus_sockaddr_t               sock_addr;
        
        result = globus_xio_handle_cntl(
            (*handle)->xio_handle,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_ADDRESS,
            &sock_addr);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_cntl;
        }
        
        if(((struct sockaddr *) &sock_addr)->sa_family != PF_INET)
        {
            /* interface doesnt support ipv6 addresses */
            result = globus_error_put(
                globus_io_error_construct_internal_error(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                (char *) _io_name));
                
            goto error_ipv6;
        }
        
        addr = ((struct sockaddr_in *) &sock_addr)->sin_addr.s_addr;
        *port = ntohs(((struct sockaddr_in *) &sock_addr)->sin_port);
    }
    else
    {
        struct in_addr                  inaddr;
        char *                          contact_string;
        char *                          s;
        
        result = globus_xio_server_cntl(
            (*handle)->xio_server,
            globus_l_io_tcp_driver,
            GLOBUS_XIO_TCP_GET_NUMERIC_CONTACT,
            &contact_string);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_server_cntl;
        }
        
        if(*contact_string == '[')
        {
            /* interface doesnt support ipv6 addresses */
            globus_free(contact_string);
            result = globus_error_put(
                globus_io_error_construct_internal_error(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                (char *) _io_name));
                
            goto error_ipv6;
        }
        
        s = strrchr(contact_string, ':');
        globus_assert(s);
        *port = atoi(s + 1);
        *s = 0;
        inet_aton(contact_string, &inaddr);
        addr = inaddr.s_addr;
        
        globus_free(contact_string);
    }
    
    host[0] = ((unsigned char *) &addr)[0];
    host[1] = ((unsigned char *) &addr)[1];
    host[2] = ((unsigned char *) &addr)[2];
    host[3] = ((unsigned char *) &addr)[3];
    
    return GLOBUS_SUCCESS;

error_ipv6:
error_server_cntl:
error_cntl:
    return result;
}

globus_result_t
globus_io_tcp_get_remote_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port)
{
    uint32_t                            addr;
    globus_sockaddr_t                   sock_addr;
    globus_result_t                     result;
    GlobusIOName(globus_io_tcp_get_remote_address);
    
    GlobusLIOCheckNullParam(host);
    GlobusLIOCheckNullParam(port);
    GlobusLIOCheckHandle(handle, GLOBUS_I_IO_TCP_HANDLE);
    
    result = globus_xio_handle_cntl(
        (*handle)->xio_handle,
        globus_l_io_tcp_driver,
        GLOBUS_XIO_TCP_GET_REMOTE_ADDRESS,
        &sock_addr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    if(((struct sockaddr *) &sock_addr)->sa_family != PF_INET)
    {
        /* interface doesnt support ipv6 addresses */
        result = globus_error_put(
            globus_io_error_construct_internal_error(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            (char *) _io_name));
            
        goto error_ipv6;
    }
    
    *port = ntohs(((struct sockaddr_in *) &sock_addr)->sin_port);
    addr = ((struct sockaddr_in *) &sock_addr)->sin_addr.s_addr;
        
    host[0] = ((unsigned char *) &addr)[0];
    host[1] = ((unsigned char *) &addr)[1];
    host[2] = ((unsigned char *) &addr)[2];
    host[3] = ((unsigned char *) &addr)[3];
    
    return GLOBUS_SUCCESS;

error_ipv6:
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
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        bounce_info->handle->io_handle,
        result);
    
    globus_free(bounce_info->handle);
    globus_free(bounce_info);
}

static
void
globus_l_io_oneshot_close_cb(
    void *                              user_arg)
{
    globus_l_io_bounce_t *              bounce_info;
    GlobusIOName(globus_l_io_oneshot_close_cb);
    
    bounce_info = (globus_l_io_bounce_t *) user_arg;
    
    bounce_info->cb.non_io(
        bounce_info->user_arg,
        bounce_info->handle->io_handle,
        GLOBUS_SUCCESS);
    
    globus_free(bounce_info->handle);
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
    bounce_info->cb.non_io = callback;
    bounce_info->user_arg = callback_arg;
    
    if(ihandle->xio_handle)
    {
        result = globus_xio_register_close(
            ihandle->xio_handle,
            GLOBUS_NULL,
            globus_l_io_bounce_close_cb,
            bounce_info);
    }
    else
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
        
        if(ihandle->xio_server)
        {
            globus_xio_server_destroy(ihandle->xio_server);
            ihandle->xio_server = GLOBUS_NULL;
        }
        
        result = globus_callback_register_oneshot(
            GLOBUS_NULL,
            GLOBUS_NULL,
            globus_l_io_oneshot_close_cb,
            bounce_info);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
        
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    globus_free(*handle);
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
    
    *handle = GLOBUS_NULL;
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

#if 0

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

#endif
