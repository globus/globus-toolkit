
#ifdef __GNUC__
#define GlobusIOName(func) static const char * _io_name __attribute__((__unused__)) = #func
#else
#define GlobusIOName(func) static const char * _io_name = #func
#endif

#define GlobusLIOCheckHandle(handle, type)                                  \
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
                    _io_name));                                             \
        }                                                                   \
                                                                            \
        if(type && (*(handle))->type != type)                               \
        {                                                                   \
            return globus_error_put(                                        \
                globus_io_error_construct_bad_pointer(                      \
                    GLOBUS_IO_MODULE,                                       \
                    GLOBUS_NULL,                                            \
                    #handle,                                                \
                    1,                                                      \
                    _io_name));                                             \
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
                _io_name))

#define GlobusLIOMalloc(pointer, type)                                      \
    ((pointer = (type *) globus_malloc(sizeof(type)))                       \
        ? (GLOBUS_SUCCESS)                                                  \
        : (globus_error_put(                                                \
            globus_io_error_construct_system_failure(                       \
                GLOBUS_IO_MODULE,                                           \
                GLOBUS_NULL,                                                \
                GLOBUS_NULL,                                                \
                errno))))

#define GlobusLIODriverRef(_driver)                                         \
    do                                                                      \
    {                                                                       \
        globus_mutex_lock(&globus_l_io_driver_lock);                        \
        {                                                                   \
            if(globus_l_io_##_driver##_driver.driver)                       \
            {                                                               \
                globus_l_io_##_driver##_driver.ref_count++;                 \
            }                                                               \
            else                                                            \
            {                                                               \
                globus_xio_driver_load(                                     \
                    #_driver, &globus_l_io_##_driver##_driver.driver);      \
                globus_l_io_##_driver##_driver.ref_count = 1;               \
            }                                                               \
        }                                                                   \
        globus_mutex_unlock(&globus_l_io_driver_lock);                      \
    } while(0)                                                              
                                                                            
#define GlobusLIODriverFree(_driver)                                        \
    do                                                                      \
    {                                                                       \
        globus_mutex_lock(&globus_l_io_driver_lock);                        \
        {                                                                   \
            globus_l_io_##_driver##_driver.ref_count--;                     \
            if(globus_l_io_##_driver##_driver.ref_count == 0)               \
            {                                                               \
                globus_xio_driver_unload(                                   \
                    globus_l_io_##_driver##_driver.driver);                 \
                globus_l_io_##_driver##_driver.driver = GLOBUS_NULL;        \
            }                                                               \
        }                                                                   \
        globus_mutex_unlock(&globus_l_io_driver_lock);                      \
    } while(0)
    
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
} globus_l_io_handle_t;

typedef struct
{
    globus_xio_driver_t                 driver;
    int                                 ref_count;
} globus_l_io_driver_t;

typedef struct
{
    globus_bool_t                       done;
    globus_result_t                     result;
    globus_mutex_t                      lock;
    globus_cond_t                       cond;
    void *                              arg;
} globus_l_io_monitor_t;

static globus_mutex_t                   globus_l_io_driver_lock;
static globus_l_io_driver_t             globus_l_io_file_driver;
static globus_l_io_driver_t             globus_l_io_tcp_driver;

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
    globus_l_io_file_driver.driver = GLOBUS_NULL;
    globus_l_io_file_driver.ref_count = 0;
    globus_l_io_tcp_driver.driver = GLOBUS_NULL;
    globus_l_io_tcp_driver.ref_count = 0;
    
    globus_mutex_init(&globus_l_io_driver_lock, GLOBUS_NULL);
    
    return globus_module_activate(GLOBUS_XIO_MODULE);
}

static
int
globus_l_io_deactivate(void)
{
    if(globus_l_io_file_driver.driver)
    {
        globus_xio_driver_unload(globus_l_io_file_driver.driver);
    }
    
    if(globus_l_io_tcp_driver.driver)
    {
        globus_xio_driver_unload(globus_l_io_tcp_driver.driver);
    }
    
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
                func_name));
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
                func_name));
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
    
    if(source_iattr->type == GLOBUS_I_IO_FILE_ATTR)
    {
        GlobusLIODriverRef(file);
    }
    else if(source_iattr->type == GLOBUS_I_IO_TCP_ATTR)
    {
        GlobusLIODriverRef(tcp);
    }

    return GLOBUS_SUCCESS;

error_copy:
    globus_free(dest_iattr);
    
error_alloc:
    return result;
}

static
void
globus_l_io_blocking_io_cb(
    globus_xio_handle_t                 xio_handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_io_monitor_t *             monitor;
    
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
globus_l_io_blocking_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_io_monitor_t *             monitor;
    
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
    
    GlobusLIODriverRef(file);
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
    GlobusLIODriverFree(file);
    
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
    
    result = globus_xio_attr_init(&iattr->attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    GlobusLIODriverRef(tcp);
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
    GlobusLIODriverFree(tcp);

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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
        globus_l_io_tcp_driver.driver, 
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
    
    GlobusLIODriverRef(file);
    result = globus_xio_stack_push_driver(
        stack, globus_l_io_file_driver.driver);
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
        goto error_open;
    }
    
    ihandle->type = GLOBUS_I_IO_FILE_HANDLE;
    ihandle->io_handle = handle;
    *handle = ihandle;
    
    globus_xio_target_destroy(target);
    globus_xio_stack_destroy(stack);
    
    return GLOBUS_SUCCESS;

error_open:
    globus_xio_target_destroy(target);
    
error_target:
error_push:
    globus_xio_stack_destroy(stack);
    GlobusLIODriverFree(file);
    
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
        globus_l_io_file_driver.driver,
        GLOBUS_XIO_FILE_SET_MODE,
        mode);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }
    
    result = globus_xio_attr_cntl(
        iattr->attr,
        globus_l_io_file_driver.driver,
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
    
    ihandle = (globus_l_io_handle_t *) handle;
    
    return globus_xio_handle_cntl(
        (*handle)->xio_handle,
        globus_l_io_file_driver.driver,
        GLOBUS_XIO_FILE_SEEK,
        offset,
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
    
    GlobusLIODriverRef(file);
    result = globus_xio_attr_cntl(
        myattr,
        globus_l_io_file_driver.driver,
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
        stack, globus_l_io_file_driver.driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }
    
    result = globus_xio_target_init(&target, myattr, GLOBUS_NULL, stack);
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
        goto error_open;
    }
    
    ihandle->type = GLOBUS_I_IO_FILE_HANDLE;
    ihandle->io_handle = handle;
    *handle = ihandle;
    
    globus_xio_target_destroy(target);
    globus_xio_stack_destroy(stack);
    globus_xio_attr_destroy(myattr);
    
    return GLOBUS_SUCCESS;

error_open:
    globus_xio_target_destroy(target);

error_target:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
error_cntl:
    globus_xio_attr_destroy(myattr);
    GlobusLIODriverFree(file);
    
error_attr:
    globus_free(ihandle);

error_alloc:
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
    GlobusIOName(globus_io_tcp_register_connect);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_connect(
    const char *                        host,
    unsigned short                      port,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_tcp_connect);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_create_listener(
    unsigned short *                    port,
    int                                 backlog,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_tcp_create_listener);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_register_listen(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_tcp_register_listen);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_listen(
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_tcp_listen);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_register_accept(
    globus_io_handle_t *                listener_handle,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                new_handle,
    globus_io_callback_t                callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_tcp_register_accept);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_accept(
    globus_io_handle_t *                listener_handle,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle)
{
    GlobusIOName(globus_io_tcp_accept);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_get_local_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port)
{
    GlobusIOName(globus_io_tcp_get_local_address);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_tcp_get_remote_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port)
{
    GlobusIOName(globus_io_tcp_get_remote_address);
    
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
    GlobusIOName(globus_io_register_read);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_try_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_read)
{
    GlobusIOName(globus_io_try_read);
    
    return GLOBUS_SUCCESS;
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
        globus_l_io_blocking_io_cb,
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
        result = globus_io_error_construct_eof(
            GLOBUS_IO_MODULE,
            globus_error_get(result),
            (*handle)->io_handle);
    }
    else if(globus_xio_error_is_canceled(result))
    {
        result = globus_io_error_construct_io_cancelled(
            GLOBUS_IO_MODULE,
            globus_error_get(result),
            (*handle)->io_handle);
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
    GlobusIOName(globus_io_register_write);
    
    return GLOBUS_SUCCESS;
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
    GlobusIOName(globus_io_register_send);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_register_writev(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_io_writev_callback_t         writev_callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_register_writev);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_try_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_written)
{
    GlobusIOName(globus_io_try_write);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_try_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_size_t *                     nbytes_sent)
{
    GlobusIOName(globus_io_try_send);
    
    return GLOBUS_SUCCESS;
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
        globus_l_io_blocking_io_cb,
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
        result = globus_io_error_construct_io_cancelled(
            GLOBUS_IO_MODULE,
            globus_error_get(result),
            (*handle)->io_handle);
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
    GlobusIOName(globus_io_send);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_writev(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_size_t *                     bytes_written)
{
    GlobusIOName(globus_io_writev);
    
    return GLOBUS_SUCCESS;
}

/* miscelaneous */

globus_result_t
globus_io_register_close(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback,
    void *                              callback_arg)
{
    GlobusIOName(globus_io_register_close);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_io_close(
    globus_io_handle_t *                handle)
{
    globus_result_t                     result;
    globus_l_io_monitor_t               monitor;
    GlobusIOName(globus_io_close);
    
    GlobusLIOCheckHandle(handle, 0);
    
    monitor.done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.lock, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    
    result = globus_xio_register_close(
        (*handle)->xio_handle,
        GLOBUS_NULL,
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

globus_bool_t
globus_io_eof(
    globus_object_t *                   eof)
{
    GlobusIOName(globus_io_eof);
    
    return GLOBUS_SUCCESS;
}
