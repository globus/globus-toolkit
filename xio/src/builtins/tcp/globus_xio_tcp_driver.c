#include "globus_xio_driver.h"
#include "globus_xio_tcp_driver.h"

#define GlobusIXIOTcpCloseFd(fd)                                            \
    do                                                                      \
    {                                                                       \
        int                             _rc;                                \
        int                             _fd;                                \
                                                                            \
        _fd = (fd);                                                         \
        do                                                                  \
        {                                                                   \
            _rc = close(_fd);                                               \
        } while(_rc < 0 && errno == EINTR);                                 \
                                                                            \
        (fd) = -1;                                                          \
    } while(0)

static
int
globus_l_xio_tcp_activate();

static
int
globus_l_xio_tcp_deactivate();

#include "version.h"

globus_module_descriptor_t              globus_i_xio_tcp_module =
{
    "globus_xio_tcp",
    globus_l_xio_tcp_activate,
    globus_l_xio_tcp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 *  attribute structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
} globus_l_attr_t;

/* default attr */
static const globus_l_attr_t            globus_l_xio_tcp_attr_default =
{
    GLOBUS_XIO_TCP_INVALID_HANDLE      /* handle   */             
};

/*
 *  target structure
 */
typedef struct
{
    char *                              contact_string;
    globus_xio_system_handle_t          handle;
} globus_l_target_t;

/*
 *  server structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
} globus_l_server_t;

/*
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
    globus_l_attr_t *                   attr;
} globus_l_handle_t;

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
globus_l_xio_tcp_attr_init(
    void **                             out_attr)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    
    /*
     *  create a tcp attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_tcp_attr_init", "attr");
        goto error_attr;
    }
    
    memcpy(attr, &globus_l_xio_tcp_attr_default, sizeof(globus_l_attr_t));
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
globus_l_xio_tcp_attr_cntl(
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
      case GLOBUS_XIO_TCP_SET_MODE:
        attr->mode = va_arg(ap, int);
        break;

      case GLOBUS_XIO_TCP_GET_MODE:
        out_int = va_arg(ap, int *);
        *out_int = attr->mode;
        break;

      case GLOBUS_XIO_TCP_SET_FLAGS:
        attr->flags = va_arg(ap, int);
        break;

      case GLOBUS_XIO_TCP_GET_FLAGS:
        out_int = va_arg(ap, int *);
        *out_int = attr->flags;
        break;
    
      case GLOBUS_XIO_TCP_SET_HANDLE:
        attr->handle = va_arg(ap, int);
        break;
        
      case GLOBUS_XIO_TCP_GET_HANDLE:
        out_handle = va_arg(ap, out_handle *);
        *out_handle = attr->handle;
        break;

      default:
        return GLOBUS_XIO_ERROR_CONSTRUCT_INVALID_COMMAND(
            "globus_l_xio_tcp_attr_cntl", cmd);
        break;
    }

    return GLOBUS_SUCCESS;
}

/*
 *  copy an attribute structure
 */
static
globus_result_t
globus_l_xio_tcp_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;

    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_tcp_attr_copy", "attr");
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
globus_l_xio_tcp_attr_destroy(
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
globus_l_xio_tcp_target_init(
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
            "globus_l_xio_tcp_target_init", "target");
        goto error_target;
    }
    
    memcpy(
        target,
        &globus_l_xio_tcp_target_default,
        sizeof(globus_l_target_t));
    
    if(!attr || attr->handle == GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        target->contact_string = globus_libc_strdup(contact_string);
        if(!target->contact_string)
        {
            result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
                "globus_l_xio_tcp_target_init", "contact_string");
            goto error_contact_string;
        }
    }
    else
    {
        target->handle = attr->handle;
    }
    
    *out_target = target;

    return GLOBUS_SUCCESS;

error_contact_string:
    globus_free(target);
    
error_target:
    return result;
}

/*
 *  destroy the target structure
 */
static
globus_result_t
globus_l_xio_tcp_target_destroy(
    void *                              driver_target)
{
    globus_l_target_t *                 target;
    
    target = (globus_l_target_t *) driver_target;
    
    if(target->contact_string)
    {
        globus_free(target->contact_string);
    }
    globus_free(target);

    return GLOBUS_SUCCESS;
}

/*
 * server interface funcs
 */
static
globus_result_t
globus_l_xio_tcp_server_init(
    void **                                     out_server,
    void *                                      server_attr)
{
    
}

static
globus_result_t
globus_l_xio_tcp_server_accept(
    void **                                     out_target,
    void *                                      target_attr,
    void *                                      server,
    globus_xio_driver_operation_t               op)
{
    
}

static
globus_result_t
globus_l_xio_tcp_server_cntl(
    void *                                      server,
    int                                         cmd,
    va_list                                     ap)
{
    
    
}

static
globus_result_t
globus_l_xio_tcp_server_destroy(
    void *                                      server)
{
    
}

static
globus_result_t
globus_l_xio_tcp_apply_socket_attrs(
    const globus_l_attr_t *             attr,
    int                                 fd)
{
    
}

static
globus_result_t
globus_l_xio_tcp_handle_init(
    globus_l_handle_t **                handle,
    globus_l_attr_t *                   attr)
{
    globus_result_t                     result;
    
    *handle = (globus_l_handle_t *) globus_malloc(sizeof(globus_l_handle_t));
    if(!*handle)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_tcp_handle_init", "handle");
        goto error_handle;
    }
    
    result = globus_l_xio_tcp_attr_copy(&(*handle)->attr, attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
    return GLOBUS_SUCCESS;

error_attr:
    globus_free(handle);
    
error_handle:
    return result;    
}

static
void
globus_l_xio_tcp_handle_destroy(
    globus_l_handle_t *                 handle)
{
    globus_l_xio_tcp_attr_destroy(handle->attr);
    globus_free(handle);
}

typedef struct
{
    globus_xio_driver_operation_t       op;
    globus_l_handle_t *                 handle;
    globus_addrinfo_t *                 save_addrinfo;
    globus_addrinfo_t *                 next_addrinfo;
} globus_l_xio_connect_info_t;

static
globus_result_t
globus_l_xio_tcp_connect_next(
    globus_l_xio_connect_info_t *       connect_info)
{
    globus_addrinfo_t *                 addrinfo;
    int                                 fd;
    globus_result_t                     result;
    int                                 save_errno;
    
    result = GLOBUS_SUCCESS;
    save_errno = 0;
    for(addrinfo = connect_info->next_addrinfo;
        addrinfo;
        addrinfo = addrinfo->ai_next)
    {
#ifdef BUILD_DEBUG
        /* just making sure my assumptions about addr size are correct */
        {
            int                             len;
    
            GlobusLibcSizeofSockaddr(*addrinfo->ai_addr, len);
            globus_assert(
                addrinfo->ai_addrlen == len && "Size assumption incorrect!");
        }
#endif

        if(GlobusLibcProtocolFamilyIsIP(addrinfo->ai_family))
        {
            fd = socket(
                addrinfo->ai_family,
                addrinfo->ai_socktype,
                addrinfo->ai_protocol);
            if(fd < 0)
            {
                save_errno = errno;
                continue;
            }
            
            result = globus_l_xio_tcp_apply_socket_attrs(
                connect_info->handle->attr, fd);
            if(result != GLOBUS_SUCCESS)
            {
                GlobusIXIOTcpCloseFd(fd);
                continue;
            }
            
            /* XXX do local bind stuff here */
            
            connect_info->handle->handle = fd;
            connect_info->next_addrinfo = addrinfo->ai_next;
    
            result = globus_xio_system_register_connect(
                op,
                fd, 
                addrinfo->ai_addr, 
                globus_l_xio_tcp_system_connect_cb,
                connect_info);
            if(result != GLOBUS_SUCCESS)
            {
                continue;
            }

            break;
        }
    }
    
    if(!addrinfo)
    {
        if(result == GLOBUS_SUCCESS)
        {
            if(save_errno == 0)
            {
                result = GLOBUS_XIO_TCP_CONSTRUCT_NO_ADDRS(
                    "globus_l_xio_tcp_connect_next");
            }
            else
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_ERRNO(
                    "globus_l_xio_tcp_connect_next", errno);
            }
        }
        
        goto error_no_addrinfo;
    }

    return GLOBUS_SUCCESS;
    
error_no_addrinfo:
    return result;
}

static
void
globus_l_xio_tcp_system_connect_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_connect_info_t *       addrinfo;
    
    connect_info = (globus_l_xio_connect_info_t *) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_result_t                 res;
        
        res = globus_l_xio_tcp_connect_next(connect_info);
        if(res == GLOBUS_SUCCESS)
        {
            goto error_tryagain;
        }
    }
    
    globus_xio_driver_finished_open(
        GlobusXIOOperationGetContext(connect_info->op),
        connect_info->op,
        result);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_tcp_handle_destroy(connect_info->handle);
    }
    globus_libc_freeaddrinfo(connect_info->save_addrinfo);
    globus_free(connect_info);
    
    return;
    
error_tryagain:    
    return;
}

static
globus_result_t
globus_l_xio_tcp_connect(
    globus_xio_driver_operation_t       op,
    globus_l_handle_t *                 handle,
    const globus_l_target_t *           target)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    globus_l_xio_connect_info_t *       connect_info;
    
    /* XXX need to decompose contact string into host/port */
    
    /* setup hints for types of connectable sockets we want */
    memset(&addrinfo_hints, 0, sizeof(globus_addrinfo_t));
    addrinfo_hints.ai_flags = 0;
    addrinfo_hints.ai_family = PF_UNSPEC;
    addrinfo_hints.ai_socktype = SOCK_STREAM;
    addrinfo_hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(host, port, &addrinfo_hints, &addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_getaddrinfo;
    }
    
    connect_info = (globus_l_xio_connect_info_t *)
        globus_malloc(sizeof(globus_l_xio_connect_info_t));
    if(!connect_info)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_tcp_connect", "connect_info");
        goto error_info;
    }
    
    connect_info->op = op;
    connect_info->handle = handle;
    connect_info->save_addrinfo = addrinfo;
    connect_info->next_addrinfo = addrinfo;
    
    result = globus_l_xio_tcp_connect_next(connect_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_connect_next;
    }
    
    return GLOBUS_SUCCESS;

error_connect_next:
    globus_free(connect_info);
    
error_info:
    globus_libc_freeaddrinfo(save_addrinfo);

error_getaddrinfo:
    return result;
}

/*
 *  open a tcp
 */
static
globus_result_t
globus_l_xio_tcp_open(
    void **                             out_handle,
    void *                              driver_attr,
    void *                              driver_target,
    globus_xio_driver_context_t         context,
    globus_xio_driver_operation_t       op)
{
    globus_l_handle_t *                 handle;
    const globus_l_target_t *           target;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    
    target = (globus_l_target_t *) driver_target;
    attr = (globus_l_attr_t *) 
        driver_attr ? driver_attr : &globus_l_xio_tcp_attr_default;
    
    result = globus_l_xio_tcp_handle_init(&handle, attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_handle;
    }
    *out_handle = handle;
    
    if(target->handle == GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        result = globus_l_xio_tcp_connect(op, handle, target);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_connect;
        }
    }
    else
    {
        handle->handle = target->handle;
        globus_xio_driver_finished_open(context, op, GLOBUS_SUCCESS);
    }

    return GLOBUS_SUCCESS;
    
error_connect:
    globus_l_xio_tcp_handle_destroy(handle);  

error_handle:
    return result;
}

static
void
globus_l_xio_tcp_system_close_cb(
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
 *  close a tcp
 */
static
globus_result_t
globus_l_xio_tcp_close(
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
        globus_l_xio_tcp_system_close_cb,
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
globus_l_xio_tcp_system_read_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_operation_t       op;
    
    op = (globus_xio_driver_operation_t) user_arg;
    globus_xio_driver_finished_read(op, result, nbytes);
}

/*
 *  read from a tcp
 */
static
globus_result_t
globus_l_xio_tcp_read(
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
        globus_l_xio_tcp_system_read_cb,
        op);
}

static
void
globus_l_xio_tcp_system_write_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_operation_t       op;
    
    op = (globus_xio_driver_operation_t) user_arg;
    globus_xio_driver_finished_write(op, result, nbytes);
}

/*
 *  write to a tcp
 */
static
globus_result_t
globus_l_xio_tcp_write(
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
        globus_l_xio_tcp_system_write_cb,
        op);
}

static
globus_result_t
globus_l_xio_tcp_cntl(
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
      case GLOBUS_XIO_TCP_SEEK:
        offset = va_arg(ap, globus_off_t);
        whence = va_arg(ap, int);
        offset = lseek(handle->handle, offset, whence);
        if(offset < 0)
        {
            return GLOBUS_XIO_ERROR_CONSTRUCT_ERRNO(
                "globus_l_xio_tcp_cntl", errno);
        }
        break;

      default:
        return GLOBUS_XIO_ERROR_CONSTRUCT_INVALID_COMMAND(
            "globus_l_xio_tcp_cntl", cmd);
        break;
    }

    return GLOBUS_SUCCESS;
}

static globus_xio_driver_t globus_l_xio_tcp_info =
{
    /*
     *  main io interface functions
     */
    globus_l_xio_tcp_open,                      /* open_func           */
    globus_l_xio_tcp_close,                     /* close_func          */
    globus_l_xio_tcp_read,                      /* read_func           */
    globus_l_xio_tcp_write,                     /* write_func          */
    globus_l_xio_tcp_cntl,                      /* handle_cntl_func    */

    globus_l_xio_tcp_target_init,               /* target_init_func    */
    globus_l_xio_tcp_target_destory,            /* target_destroy_finc */

    globus_l_xio_tcp_server_init,               /* server_init_func    */
    globus_l_xio_tcp_server_accept,             /* server_accept_func  */
    globus_l_xio_tcp_server_destroy,            /* server_destroy_func */
    globus_l_xio_tcp_server_cntl,               /* server_cntl_func    */

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_l_xio_tcp_attr_init,                 /* attr_init_func      */
    globus_l_xio_tcp_attr_copy,                 /* attr_copy_func      */
    globus_l_xio_tcp_attr_cntl,                 /* attr_cntl_func      */
    globus_l_xio_tcp_attr_destroy,              /* attr_destroy_func   */

    /*
     *  No need for data descriptors.
     */
    NULL,                                        /* dd_init             */
    NULL,                                        /* dd_copy             */
    NULL,                                        /* dd_destroy          */
    NULL                                         /* dd_cntl             */
};
