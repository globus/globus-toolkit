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
    char *                              bind_address;
    char *                              listener_serv;
    int                                 listener_port;
    int                                 listener_backlog;
    globus_bool_t                       restrict_port;
    /* XXX i need to separate these for listeners and connectors, otherwise
     * port range env will apply to both
     */
    int                                 min_port;
    int                                 max_port;
} globus_l_attr_t;

/* default attr */
static globus_l_attr_t                  globus_l_xio_tcp_attr_default =
{
    GLOBUS_XIO_TCP_INVALID_HANDLE,      /* handle   */ 
    GLOBUS_NULL,                        /* bind_address */
    GLOBUS_NULL,                        /* listener_serv */
    0,                                  /* listener_port */
    -1,                                 /* listener_backlog (SOMAXCONN) */
    GLOBUS_TRUE,                        /* restrict_port */
    0,                                  /* min_port */
    0                                   /* max_port */
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
    globus_xio_system_handle_t          listener_handle;
} globus_l_server_t;

/*
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
    /* XXX so far only need this for connect info, maybe just put it there */
    globus_l_attr_t *                   attr;
} globus_l_handle_t;

static
int
globus_l_xio_tcp_activate(void)
{
    return globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
}

static
int
globus_l_xio_tcp_deactivate(void)
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
    globus_xio_system_handle_t *        out_handle;
    char **                             out_string;
    int *                               out_int;
    globus_bool_t *                     out_bool;
    globus_result_t                     result;

    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd)
    {
      case GLOBUS_XIO_TCP_SET_SERVICE:
        attr->listener_serv = va_arg(ap, char *);
        if(attr->listener_serv)
        {
            attr->listener_serv = globus_libc_strdup(attr->listener_serv);
            if(!attr->listener_serv)
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
                    "globus_l_xio_tcp_attr_cntl", "listener_serv");
                goto error_memory;
            }
        }
        break;
      
      case GLOBUS_XIO_TCP_GET_SERVICE:
        out_string = va_arg(ap, char **);
        if(attr->listener_serv)
        {
            *out_string = globus_libc_strdup(attr->listener_serv);
            if(!*out_string)
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
                    "globus_l_xio_tcp_attr_cntl", "listener_serv_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;
        }
        break;
      
      case GLOBUS_XIO_TCP_SET_PORT:
        attr->listener_port = va_arg(ap, int);
        break;
      
      case GLOBUS_XIO_TCP_GET_PORT:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_port;
        break;
      
      case GLOBUS_XIO_TCP_SET_BACKLOG:
        attr->listener_backlog = va_arg(ap, int);
        break;
      
      case GLOBUS_XIO_TCP_GET_BACKLOG:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_backlog;
        break;
      
      case GLOBUS_XIO_TCP_SET_INTERFACE:
        attr->bind_address = va_arg(ap, char *);
        if(attr->bind_address)
        {
            attr->bind_address = globus_libc_strdup(attr->bind_address);
            if(!attr->bind_address)
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
                    "globus_l_xio_tcp_attr_cntl", "bind_address");
                goto error_memory;
            }
        }
        break;
      
      case GLOBUS_XIO_TCP_GET_INTERFACE:
        out_string = va_arg(ap, char **);
        if(attr->bind_address)
        {
            *out_string = globus_libc_strdup(attr->bind_address);
            if(!*out_string)
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
                    "globus_l_xio_tcp_attr_cntl", "bind_address_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;
        }
        break;
      
      case GLOBUS_XIO_TCP_SET_RESTRICT_PORT:
        attr->restrict_port = va_arg(ap, globus_bool_t);
        break;
        
      case GLOBUS_XIO_TCP_GET_RESTRICT_PORT:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->restrict_port;
        break;
        
      case GLOBUS_XIO_TCP_SET_RESTRICT_RANGE:
        attr->min_port = va_arg(ap, int);
        attr->max_port = va_arg(ap, int);
        break;
        
      case GLOBUS_XIO_TCP_SET_RESTRICT_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->max_port;
        break;
      
      case GLOBUS_XIO_TCP_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_handle_t);
        break;
        
      case GLOBUS_XIO_TCP_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = attr->handle;
        break;

      default:
        result = GLOBUS_XIO_ERROR_CONSTRUCT_INVALID_COMMAND(
            "globus_l_xio_tcp_attr_cntl", cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_memory:
error_invalid:
    return result;
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
    
    target->handle = GLOBUS_XIO_TCP_INVALID_HANDLE;
    target->contact_string = GLOBUS_NULL;
    
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

static
globus_result_t
globus_l_xio_tcp_bind(
    int                                 fd,
    const struct sockaddr *             addr,
    int                                 addr_len,
    const globus_l_attr_t *             attr)
{
    int                                 port;
    int                                 max_port;
    globus_bool_t                       done;
    globus_sockaddr_t                   myaddr;
    globus_result_t                     result;
    
    GlobusLibcSockaddrGetPort(*addr, port);
    
    if(port == 0 && attr->restrict_port)
    {
        port = attr->min_port;
        max_port = attr->max_port;
    }
    else
    {
        max_port = port;
    }
    
    done = GLOBUS_FALSE;
    do
    {
        GlobusLibcSockaddrCopy(myaddr, *addr, addr_len);
        GlobusLibcSockaddrSetPort(myaddr, port);
        
        if(bind(fd, (struct sockaddr *) &myaddr, sizeof(myaddr)) < 0)
        {
            if(++port > max_port)
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_ERRNO(
                    "globus_l_xio_tcp_bind", errno);
                goto error_bind;
            }
        }
        else
        {
            done = GLOBUS_TRUE;
        }
    } while(!done);

    return GLOBUS_SUCCESS;
    
error_bind:
    return result;
}

static
globus_result_t
globus_l_xio_tcp_create_listener(
    globus_l_handle_t *                 handle,
    globus_l_attr_t *                   attr)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 save_addrinfo
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    char                                portbuf[10];
    char *                              port;
    int                                 fd;
    
    if(attr->listener_serv)
    {
        port = attr->listener_serv;
    }
    else
    {
        snprintf(portbuf, sizeof(portbuf), "%d", attr->listener_port);
        port = portbuf;
    }
    
    /* setup hints for types of connectable sockets we want */
    memset(&addrinfo_hints, 0, sizeof(globus_addrinfo_t));
    addrinfo_hints.ai_flags = AI_PASSIVE;
    addrinfo_hints.ai_family = PF_UNSPEC;
    addrinfo_hints.ai_socktype = SOCK_STREAM;
    addrinfo_hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(
        attr->bind_address, port, &addrinfo_hints, &save_addrinfo);
    if(result != GLOBUS_SUCCESS && 
        attr->listener_serv && attr->listener_port > 0)
    {
        /* it's possible the service name doesnt exist, since they also
         * specified a numeric port, lets try that one
         */
        snprintf(portbuf, sizeof(portbuf), "%d", attr->listener_port);
        result = globus_libc_getaddrinfo(
            attr->bind_address, portbuf, &addrinfo_hints, &save_addrinfo);
    }

    if(result != GLOBUS_SUCCESS)
    {
        goto error_getaddrinfo;
    }
    
    /* bind to the first one possible --
     * its not possible to bind multiple interfaces (except on some openbsd)
     * so, if the system doesnt map its inet interfaces to inet6, we
     * may have a problem
     */
    for(addrinfo = save_addrinfo; addrinfo; addrinfo = addrinfo->ai_next)
    {
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
            
            result = globus_l_xio_tcp_apply_socket_attrs(attr, fd);
            if(result != GLOBUS_SUCCESS)
            {
                GlobusIXIOTcpCloseFd(fd);
                continue;
            }
            
            result = globus_l_xio_tcp_bind(
                fd, addrinfo->ai_addr, addrinfo->ai_addrlen, attr);
            if(result != GLOBUS_SUCCESS)
            {
                GlobusIXIOTcpCloseFd(fd);
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
                    "globus_l_xio_tcp_create_listener");
            }
            else
            {
                result = GLOBUS_XIO_ERROR_CONSTRUCT_ERRNO(
                    "globus_l_xio_tcp_create_listener", errno);
            }
        }
        
        goto error_no_addrinfo;
    }
    
    if(listen(
        fd, 
        (attr->listener_backlog < 0 ? SOMAXCONN : attr->listener_backlog)) < 0)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_ERRNO(
            "globus_l_xio_tcp_create_listener", errno);
        goto error_listen;
    }
    
    handle->listener_handle = fd;
    globus_libc_freeaddrinfo(save_addrinfo);

    return GLOBUS_SUCCESS;

error_listen:
    GlobusIXIOTcpCloseFd(fd);
    
error_no_addrinfo:
    globus_libc_freeaddrinfo(save_addrinfo);

error_getaddrinfo:
    return result;
}

/*
 * server interface funcs
 */
static
globus_result_t
globus_l_xio_tcp_server_init(
    void **                             out_server,
    void *                              server_attr)
{
    globus_l_server_t *                 server;
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    
    attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_tcp_attr_default);
    
    server = (globus_l_server_t *) globus_malloc(sizeof(globus_l_server_t));
    if(!server)
    {
        result = GLOBUS_XIO_ERROR_CONSTRUCT_MEMORY(
            "globus_l_xio_tcp_server_init", "server");
        goto error_server;
    }
    *out_server = server;
    
    if(attr->handle == GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        result = globus_l_xio_tcp_create_listener(handle, attr);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_listener;
        }
    }
    else
    {
        /* use specified handle */ 
        server->listener_handle = attr->handle;
    }
    
    return GLOBUS_SUCCESS;

error_listener:
    globus_free(server);
    
error_server:
    return result;
}

static
globus_result_t
globus_l_xio_tcp_server_accept(
    void *                              driver_server,
    void *                              target_attr,
    void **                             out_target,
    globus_xio_driver_operation_t       op)
{
    
}

static
globus_result_t
globus_l_xio_tcp_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_server_t *                 server;
    
    server = (globus_l_server_t *)
    
}

static
globus_result_t
globus_l_xio_tcp_server_destroy(
    void *                              driver_server)
{
            _fd = (fd);                                                         \
        do                                                                  \
        {                                                                   \
            _rc = close(_fd);                                               \
        } while(_rc < 0 && errno == EINTR);                                 \

}

static
globus_result_t
globus_l_xio_tcp_apply_socket_attrs(
    const globus_l_attr_t *             attr,
    int                                 fd)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_tcp_handle_init(
    globus_l_handle_t **                handle,
    const globus_l_attr_t *             attr)
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
globus_l_xio_tcp_bind_local(
    int                                 fd,
    globus_l_attr_t *                   attr)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 save_addrinfo
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    char *                              port = "0";
    
    memset(&addrinfo_hints, 0, sizeof(globus_addrinfo_t));
    addrinfo_hints.ai_flags = AI_PASSIVE;
    addrinfo_hints.ai_family = PF_UNSPEC;
    addrinfo_hints.ai_socktype = SOCK_STREAM;
    addrinfo_hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(
        attr->bind_address, port, &addrinfo_hints, &save_addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_getaddrinfo;
    }
    
    /* bind to the first one possible --
     * its not possible to bind multiple interfaces (except on some openbsd)
     * so, if the system doesnt map its inet interfaces to inet6, we
     * may have a problem
     */
    for(addrinfo = save_addrinfo; addrinfo; addrinfo = addrinfo->ai_next)
    {
        if(GlobusLibcProtocolFamilyIsIP(addrinfo->ai_family))
        {
            result = globus_l_xio_tcp_bind(
                fd, addrinfo->ai_addr, addrinfo->ai_addrlen, attr);
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
            result = GLOBUS_XIO_TCP_CONSTRUCT_NO_ADDRS(
                "globus_l_xio_tcp_bind_local");
        }
        
        goto error_no_addrinfo;
    }
    
    globus_libc_freeaddrinfo(save_addrinfo);
    
    return GLOBUS_SUCCESS;

error_no_addrinfo:
    globus_libc_freeaddrinfo(save_addrinfo);
    
error_getaddrinfo:
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
        globus_object_t *               err;
        
        err = globus_error_get(result);
        
        if(!globus_xio_canceled(err))
        {
            res = globus_l_xio_tcp_connect_next(connect_info);
            if(res == GLOBUS_SUCCESS)
            {
                globus_object_free(err);
                goto error_tryagain;
            }
        }
        
        result = globus_error_put(err);
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
globus_l_xio_tcp_connect_next(
    globus_l_xio_connect_info_t *       connect_info)
{
    globus_addrinfo_t *                 addrinfo;
    int                                 fd;
    globus_result_t                     result;
    int                                 save_errno;
    globus_sockaddr_t                   myaddr;
    globus_l_attr_t *                   attr;
    
    attr = connect_info->handle->attr;
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
            
            /* if specifying interface or outgoing port ranges, need to bind */
            if(attr->bind_address || (attr->restrict_port && attr->max_port))
            {
                result = globus_l_xio_tcp_bind_local(fd, attr);
                if(result != GLOBUS_SUCCESS)
                {
                    GlobusIXIOTcpCloseFd(fd);
                    continue;
                }
            }
            
            connect_info->handle->handle = fd;
            connect_info->next_addrinfo = addrinfo->ai_next;
            GlobusLibcSockaddrCopy(
                myaddr, *addrinfo->ai_addr, addrinfo->ai_addrlen);
                
            result = globus_xio_system_register_connect(
                op,
                fd, 
                &myaddr,
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
        (driver_attr ? driver_attr : &globus_l_xio_tcp_attr_default);
    
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
    globus_l_xio_tcp_handle_destroy(handle);
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
    globus_l_xio_tcp_handle_destroy(handle);
    
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
