#include "globus_xio_driver.h"
#include "globus_xio_tcp_driver.h"
#include <netinet/tcp.h>
#include "version.h"


static
int
globus_l_xio_tcp_activate(void);


static
int
globus_l_xio_tcp_deactivate(void);

static globus_module_descriptor_t       globus_i_xio_tcp_module =
{
    "globus_xio_tcp",
    globus_l_xio_tcp_activate,
    globus_l_xio_tcp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

#define GlobusXIOTcpErrorNoAddrs()                                          \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            &globus_i_xio_tcp_module,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_TCP_ERROR_NO_ADDRS,                                  \
            "[%s:%d] No addrs for INET family",                             \
            _xio_name, __LINE__))


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

/*
 *  attribute structure
 */
typedef struct
{
    /* target/server attrs */
    globus_xio_system_handle_t          handle;
    
    /* server attrs */
    char *                              listener_serv;
    int                                 listener_port;
    int                                 listener_backlog;
    int                                 listener_min_port;
    int                                 listener_max_port;
    
    /* handle/server attrs */
    char *                              bind_address;
    globus_bool_t                       restrict_port;
    globus_bool_t                       resuseaddr;
    
    /* handle attrs */
    globus_bool_t                       keepalive;
    globus_bool_t                       linger;
    int                                 linger_time;
    globus_bool_t                       oobinline;
    int                                 sndbuf;
    int                                 rcvbuf;
    globus_bool_t                       nodelay;
    int                                 connector_min_port;
    int                                 connector_max_port;
    
    /* data descriptor */
    int                                 send_flags;
} globus_l_attr_t;

/* default attr */
static globus_l_attr_t                  globus_l_xio_tcp_attr_default =
{
    GLOBUS_XIO_TCP_INVALID_HANDLE,      /* handle   */ 
    
    GLOBUS_NULL,                        /* listener_serv */
    0,                                  /* listener_port */
    -1,                                 /* listener_backlog (SOMAXCONN) */
    0,                                  /* listener_min_port */
    0,                                  /* listener_max_port */
    
    GLOBUS_NULL,                        /* bind_address */
    GLOBUS_TRUE,                        /* restrict_port */
    GLOBUS_FALSE,                       /* reuseaddr */
    
    GLOBUS_FALSE,                       /* keepalive */  
    GLOBUS_FALSE,                       /* linger */     
    0,                                  /* linger_time */
    GLOBUS_FALSE,                       /* oobinline */  
    0,                                  /* sndbuf (system default) */     
    0,                                  /* rcvbuf (system default) */     
    GLOBUS_FALSE,                       /* nodelay */    
    0,                                  /* connector_min_port */
    0,                                  /* connector_max_port */
    
    0                                   /* send_flags */
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
} globus_l_handle_t;

static
globus_bool_t
globus_l_xio_tcp_get_env_pair(
    const char *                        env_name,
    int *                               min,
    int *                               max)
{
    char *                              min_max;
    GlobusXIOName(globus_l_xio_tcp_get_env_pair);

    min_max = globus_module_getenv(env_name);

    if(min_max && sscanf(min_max, " %d , %d", min, max) == 2)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

static
int
globus_l_xio_tcp_activate(void)
{
    int                                 min;
    int                                 max;
    GlobusXIOName(globus_l_xio_tcp_activate);
    
    if(globus_l_xio_tcp_get_env_pair(
        "GLOBUS_XIO_TCP_LISTEN_RANGE", &min, &max) && min <= max)
    {
        globus_l_xio_tcp_attr_default.listener_min_port = min;
        globus_l_xio_tcp_attr_default.listener_max_port = max;
    }
    
    if(globus_l_xio_tcp_get_env_pair(
        "GLOBUS_XIO_TCP_CONNECT_RANGE", &min, &max) && min <= max)
    {
        globus_l_xio_tcp_attr_default.connector_min_port = min;
        globus_l_xio_tcp_attr_default.connector_max_port = max;
    }
    
    return globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
}

static
int
globus_l_xio_tcp_deactivate(void)
{
    GlobusXIOName(globus_l_xio_tcp_deactivate);
    
    globus_l_xio_tcp_attr_default.listener_min_port = 0;
    globus_l_xio_tcp_attr_default.listener_max_port = 0;
    globus_l_xio_tcp_attr_default.connector_min_port = 0;
    globus_l_xio_tcp_attr_default.connector_max_port = 0;
        
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
    GlobusXIOName(globus_l_xio_tcp_attr_init);
    
    /*
     *  create a tcp attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
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
    GlobusXIOName(globus_l_xio_tcp_attr_cntl);

    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd)
    {
      /**
       *  target/server attrs
       */
      /* globus_xio_system_handle_t     handle */
      case GLOBUS_XIO_TCP_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_handle_t);
        break;
      
      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_TCP_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = attr->handle;
        break;
       
      /**
       *  server attrs
       */
      /* char *                         service_name */
      case GLOBUS_XIO_TCP_SET_SERVICE:
        attr->listener_serv = va_arg(ap, char *);
        if(attr->listener_serv)
        {
            attr->listener_serv = globus_libc_strdup(attr->listener_serv);
            if(!attr->listener_serv)
            {
                result = GlobusXIOErrorMemory("listener_serv");
                goto error_memory;
            }
        }
        break;
      
      /* char **                        service_name_out */
      case GLOBUS_XIO_TCP_GET_SERVICE:
        out_string = va_arg(ap, char **);
        if(attr->listener_serv)
        {
            *out_string = globus_libc_strdup(attr->listener_serv);
            if(!*out_string)
            {
                result = GlobusXIOErrorMemory("listener_serv_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;
        }
        break;
      
      /* int                            listener_port */
      case GLOBUS_XIO_TCP_SET_PORT:
        attr->listener_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_port_out */
      case GLOBUS_XIO_TCP_GET_PORT:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_port;
        break;
      
      /* int                            listener_backlog */
      case GLOBUS_XIO_TCP_SET_BACKLOG:
        attr->listener_backlog = va_arg(ap, int);
        break;
      
      /* int *                          listener_backlog_out */
      case GLOBUS_XIO_TCP_GET_BACKLOG:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_backlog;
        break;
      
      /* int                            listener_min_port */
      /* int                            listener_max_port */
      case GLOBUS_XIO_TCP_SET_LISTEN_RANGE:
        attr->listener_min_port = va_arg(ap, int);
        attr->listener_max_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_min_port_out */
      /* int *                          listener_max_port_out */
      case GLOBUS_XIO_TCP_GET_LISTEN_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_max_port;
        break;
        
      /**
       *  handle/server attrs
       */
      /* char *                         interface */
      case GLOBUS_XIO_TCP_SET_INTERFACE:
        attr->bind_address = va_arg(ap, char *);
        if(attr->bind_address)
        {
            attr->bind_address = globus_libc_strdup(attr->bind_address);
            if(!attr->bind_address)
            {
                result = GlobusXIOErrorMemory("bind_address");
                goto error_memory;
            }
        }
        break;
      
      /* char **                        interface_out */
      case GLOBUS_XIO_TCP_GET_INTERFACE:
        out_string = va_arg(ap, char **);
        if(attr->bind_address)
        {
            *out_string = globus_libc_strdup(attr->bind_address);
            if(!*out_string)
            {
                result = GlobusXIOErrorMemory("bind_address_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;
        }
        break;
      
      /* globus_bool_t                  restrict_port */
      case GLOBUS_XIO_TCP_SET_RESTRICT_PORT:
        attr->restrict_port = va_arg(ap, globus_bool_t);
        break;
      
      /* globus_bool_t *                restrict_port_out */
      case GLOBUS_XIO_TCP_GET_RESTRICT_PORT:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->restrict_port;
        break;
      
      /* globus_bool_t                  resuseaddr */
      case GLOBUS_XIO_TCP_SET_REUSEADDR:
        attr->resuseaddr = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                resuseaddr_out */
      case GLOBUS_XIO_TCP_GET_REUSEADDR:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->resuseaddr;
        break;
        
      /**
       *  handle attrs
       */
      /* globus_bool_t                  keepalive */
      case GLOBUS_XIO_TCP_SET_KEEPALIVE:
        attr->keepalive = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                keepalive_out */
      case GLOBUS_XIO_TCP_GET_KEEPALIVE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->keepalive;
        break;
        
      /* globus_bool_t                  linger */
      /* int                            linger_time */
      case GLOBUS_XIO_TCP_SET_LINGER:
        attr->linger = va_arg(ap, globus_bool_t);
        attr->linger_time = va_arg(ap, int);
        break;
        
      /* globus_bool_t *                linger_out */
      /* int *                          linger_time_out */
      case GLOBUS_XIO_TCP_GET_LINGER:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->linger;
        out_int = va_arg(ap, int *);
        *out_int = attr->linger_time;
        break;
        
      /* globus_bool_t                  oobinline */
      case GLOBUS_XIO_TCP_SET_OOBINLINE:
        attr->oobinline = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                oobinline_out */
      case GLOBUS_XIO_TCP_GET_OOBINLINE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->oobinline;
        break;
        
      /* int                            sndbuf */
      case GLOBUS_XIO_TCP_SET_SNDBUF:
        attr->sndbuf = va_arg(ap, int);
        break;
        
      /* int *                          sndbuf_out */
      case GLOBUS_XIO_TCP_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->sndbuf;
        break;
        
      /* int                            rcvbuf */
      case GLOBUS_XIO_TCP_SET_RCVBUF:
        attr->rcvbuf = va_arg(ap, int);
        break;
        
      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_TCP_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->rcvbuf;
        break;
        
      /* globus_bool_t                  nodelay */
      case GLOBUS_XIO_TCP_SET_NODELAY:
        attr->nodelay = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                nodelay_out */
      case GLOBUS_XIO_TCP_GET_NODELAY:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->nodelay;
        break;
        
      /* int                            connector_min_port */
      /* int                            connector_max_port */
      case GLOBUS_XIO_TCP_SET_CONNECT_RANGE:
        attr->connector_min_port = va_arg(ap, int);
        attr->connector_max_port = va_arg(ap, int);
        break;
      
      /* int *                          connector_min_port_out */
      /* int *                          connector_max_port_out */
      case GLOBUS_XIO_TCP_GET_CONNECT_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->connector_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->connector_max_port;
        break;
      
      /**
       * data descriptors
       */
      /* int                            send_flags */
      case GLOBUS_XIO_TCP_SET_SEND_FLAGS:
        attr->send_flags = va_arg(ap, int);
        break;
        
      /* int *                          send_flags_out */
      case GLOBUS_XIO_TCP_GET_SEND_FLAGS:
        out_int = va_arg(ap, int *);
        *out_int = attr->send_flags;
        break;
        
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
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
    GlobusXIOName(globus_l_xio_tcp_attr_copy);

    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, src, sizeof(globus_l_attr_t));
    if(attr->bind_address)
    {
        attr->bind_address = globus_libc_strdup(attr->bind_address);
        if(!attr->bind_address)
        {
            result = GlobusXIOErrorMemory("bind_address");
            goto error_bind_address;
        }
    }
    if(attr->listener_serv)
    {
        attr->listener_serv = globus_libc_strdup(attr->listener_serv);
        if(!attr->listener_serv)
        {
            result = GlobusXIOErrorMemory("listener_serv");
            goto error_listener_serv;
        }
    }
    *dst = attr;

    return GLOBUS_SUCCESS;

error_listener_serv:
    if(attr->bind_address)
    {
        globus_free(attr->bind_address);
    }
    
error_bind_address:
    globus_free(attr);
    
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
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_tcp_attr_destroy);
    
    attr = (globus_l_attr_t *) driver_attr;
    if(attr->bind_address)
    {
        globus_free(attr->bind_address);
    }
    if(attr->listener_serv)
    {
        globus_free(attr->listener_serv);
    }
    
    globus_free(driver_attr);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_tcp_apply_bind_attrs(
    const globus_l_attr_t *             attr,
    int                                 fd)
{
    globus_result_t                     result;
    int                                 int_one = 1;
    GlobusXIOName(globus_l_xio_tcp_apply_bind_attrs);
    
    if(attr->resuseaddr &&
       setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &int_one, sizeof(int_one)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }
    
    return GLOBUS_SUCCESS;

error_sockopt:
    return result;
}

static
globus_result_t
globus_l_xio_tcp_apply_handle_attrs(
    const globus_l_attr_t *             attr,
    int                                 fd,
    globus_bool_t                       do_bind_attrs)
{
    globus_result_t                     result;
    int                                 int_one = 1;
    GlobusXIOName(globus_l_xio_tcp_apply_handle_attrs);
    
    if(do_bind_attrs)
    {
        result = globus_l_xio_tcp_apply_bind_attrs(attr, fd);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_tcp_apply_bind_attrs", result);
            goto error_bind_attrs;
        }
    }
    
    if(attr->keepalive &&
       setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &int_one, sizeof(int_one)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }
    
    if(attr->linger)
    {
        struct linger           linger;
        
        linger.l_onoff = 1;
        linger.l_linger = attr->linger_time;
        
        if(setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
    }
    
    if(attr->oobinline &&
       setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &int_one, sizeof(int_one)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }

#ifdef TCP_RFC1323
    if(attr->sndbuf ||attr->rcvbuf)
    {
        /* On AIX, RFC 1323 extensions can be set system-wide,
         * using the 'no' network options command. But we can also set them
         * per-socket, so let's try just in case. 
         */
        if(setsockopt(
            fd, IPPROTO_TCP, TCP_RFC1323, &int_one, sizeof(int_one)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
    }
#endif

    if(attr->sndbuf &&
        setsockopt(
           fd, SOL_SOCKET, SO_SNDBUF, &attr->sndbuf, sizeof(attr->sndbuf)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }
    
    if(attr->rcvbuf &&
        setsockopt(
           fd, SOL_SOCKET, SO_RCVBUF, &attr->rcvbuf, sizeof(attr->rcvbuf)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }
    
    if(attr->nodelay &&
       setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int_one)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }

    return GLOBUS_SUCCESS;

error_sockopt:
error_bind_attrs:
    return result;
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
    GlobusXIOName(globus_l_xio_tcp_target_init);
    
    attr = (globus_l_attr_t *) driver_attr;
    
    /* create the target structure and copy the contact string into it */
    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
    if(!target)
    {
        result = GlobusXIOErrorMemory("target");
        goto error_target;
    }
    
    target->handle = GLOBUS_XIO_TCP_INVALID_HANDLE;
    target->contact_string = GLOBUS_NULL;
    
    if(!attr || attr->handle == GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        target->contact_string = globus_libc_strdup(contact_string);
        if(!target->contact_string)
        {
            result = GlobusXIOErrorMemory("contact_string");
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

static
globus_result_t
globus_l_xio_tcp_target_cntl(
    void *                              driver_target,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_target_t *                 target;
    globus_result_t                     result;
    globus_sockaddr_t *                 out_sock;
    globus_size_t                       sock_len = sizeof(globus_sockaddr_t);
    GlobusXIOName(globus_l_xio_tcp_target_cntl);

    target = (globus_l_target_t *) driver_target;
    switch(cmd)
    {
      /* globus_sockaddr_t *            sock_name_out */
      case GLOBUS_XIO_TCP_GET_LOCAL_ADDRESS:
        out_sock = va_arg(ap, globus_sockaddr_t *);
        if(getsockname(
            target->handle, (struct sockaddr *) out_sock, &sock_len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockname", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_sockaddr_t *            peer_name_out */
      case GLOBUS_XIO_TCP_GET_REMOTE_ADDRESS:
        out_sock = va_arg(ap, globus_sockaddr_t *);
        if(getpeername(
            target->handle, (struct sockaddr *) out_sock, &sock_len) < 0)
        {
            result = GlobusXIOErrorSystemError("getpeername", errno);
            goto error_sockopt;
        }
        break;
        
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_invalid:
error_sockopt:
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
    GlobusXIOName(globus_l_xio_tcp_target_destroy);
    
    target = (globus_l_target_t *) driver_target;
    
    if(target->contact_string)
    {
        globus_free(target->contact_string);
    }
    if(target->handle != GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        GlobusIXIOTcpCloseFd(target->handle);
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
    int                                 min_port,
    int                                 max_port)
{
    int                                 port;
    globus_bool_t                       done;
    globus_sockaddr_t                   myaddr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_tcp_bind);
    
    GlobusLibcSockaddrGetPort(*addr, port);
    
    if(port == 0)
    {
        port = min_port;
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
                result = GlobusXIOErrorSystemError("bind", errno);
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
    globus_l_server_t *                 server,
    globus_l_attr_t *                   attr)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 save_addrinfo;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    char                                portbuf[10];
    char *                              port;
    int                                 fd;
    int                                 save_errno;
    GlobusXIOName(globus_l_xio_tcp_create_listener);
    
    save_errno = 0;
    
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
    addrinfo_hints.ai_flags = GLOBUS_AI_PASSIVE;
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
        result = GlobusXIOErrorWrapFailed("globus_libc_getaddrinfo", result);
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
            
            result = globus_l_xio_tcp_apply_bind_attrs(attr, fd);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_l_xio_tcp_apply_bind_attrs", result);
                GlobusIXIOTcpCloseFd(fd);
                continue;
            }
            
            result = globus_l_xio_tcp_bind(
                fd,
                addrinfo->ai_addr,
                addrinfo->ai_addrlen,
                attr->restrict_port ? attr->listener_min_port : 0,
                attr->restrict_port ? attr->listener_max_port : 0);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_l_xio_tcp_bind", result);
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
                result = GlobusXIOTcpErrorNoAddrs();
            }
            else
            {
                result = GlobusXIOErrorSystemError("socket", save_errno);
            }
        }
        
        goto error_no_addrinfo;
    }
    
    if(listen(
        fd, 
        (attr->listener_backlog < 0 ? SOMAXCONN : attr->listener_backlog)) < 0)
    {
        result = GlobusXIOErrorSystemError("listen", errno);
        goto error_listen;
    }
    
    server->listener_handle = fd;
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
    void *                              driver_attr)
{
    globus_l_server_t *                 server;
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_tcp_server_init);
    
    attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_tcp_attr_default);
    
    server = (globus_l_server_t *) globus_malloc(sizeof(globus_l_server_t));
    if(!server)
    {
        result = GlobusXIOErrorMemory("server");
        goto error_server;
    }
    *out_server = server;
    
    if(attr->handle == GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        result = globus_l_xio_tcp_create_listener(server, attr);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_tcp_create_listener", result);
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

typedef struct
{
    globus_xio_operation_t              op;
    globus_l_target_t *                 target;
} globus_l_accept_info_t;

static
void
globus_l_xio_tcp_system_accept_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_accept_info_t *            accept_info;
    GlobusXIOName(globus_l_xio_tcp_system_accept_cb);
    
    accept_info = (globus_l_accept_info_t *) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_free(accept_info->target);
        accept_info->target = GLOBUS_NULL;
    }
    
    GlobusXIODriverFinishedAccept(
        accept_info->op, accept_info->target, result);
    
    globus_free(accept_info);
}

static
globus_result_t
globus_l_xio_tcp_server_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_server_t *                 server;
    globus_l_attr_t *                   attr;
    globus_l_target_t *                 target;
    globus_result_t                     result;
    globus_l_accept_info_t *            accept_info;
    GlobusXIOName(globus_l_xio_tcp_server_accept);

    server = (globus_l_server_t *) driver_server;
    attr = (globus_l_attr_t *) driver_attr;
    
     /* create the target structure */
    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
    if(!target)
    {
        result = GlobusXIOErrorMemory("target");
        goto error_target;
    }
    
    target->handle = GLOBUS_XIO_TCP_INVALID_HANDLE;
    target->contact_string = GLOBUS_NULL;
    
    if(attr && attr->handle != GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        target->handle = attr->handle;
        GlobusXIODriverFinishedAccept(op, target, GLOBUS_SUCCESS);
    }
    else
    {
        accept_info = (globus_l_accept_info_t *)
            globus_malloc(sizeof(globus_l_accept_info_t));
        if(!accept_info)
        {
            result = GlobusXIOErrorMemory("accept_info");
            goto error_info;
        }
        
        accept_info->op = op;
        accept_info->target = target;
        
        result = globus_xio_system_register_accept(
            op,
            server->listener_handle,
            &target->handle,
            globus_l_xio_tcp_system_accept_cb,
            accept_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_xio_system_register_accept", result);
            goto error_register;
        }
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(accept_info);
    
error_info:
    globus_free(target);
    
error_target:
    return result;
}

static
globus_result_t
globus_l_xio_tcp_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_server_t *                 server;
    globus_sockaddr_t                   sock_name;
    globus_size_t                       sock_len;
    globus_result_t                     result;
    char                                host[GLOBUS_NI_MAXHOST];
    char                                port[10];
    int                                 ni_flags;
    char **                             out_string;
    char *                              cs;
    GlobusXIOName(globus_l_xio_tcp_server_cntl);
    
    server = (globus_l_server_t *) driver_server;
    sock_len = sizeof(sock_name);
    ni_flags = GLOBUS_NI_NUMERICSERV;
    
    switch(cmd)
    {
      /* char **                        contact_string_out */
      case GLOBUS_XIO_TCP_GET_NUMERIC_CONTACT:
        ni_flags |= GLOBUS_NI_NUMERICHOST;
        /* fall through */
      
      /* char **                        contact_string_out */
      case GLOBUS_XIO_TCP_GET_CONTACT:
        if(getsockname(
            server->listener_handle,
            (struct sockaddr *) &sock_name,
            &sock_len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockname", errno);
            goto error_sockopt;
        }
        
        /* XXX should probably be makeing use of globus_libc_hostname here */
        result = globus_libc_getnameinfo(
            &sock_name, host, sizeof(host), port, sizeof(port), ni_flags);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_libc_getnameinfo", result);
            goto error_nameinfo;
        }
        
        cs = globus_malloc(strlen(host) + strlen(port) + 2);
        if(!cs)
        {
            result = GlobusXIOErrorMemory("contact_string");
            goto error_memory;
        }
        
        sprintf(cs, "%s:%s", host, port);
        out_string = va_arg(ap, char **);
        *out_string = cs;
        break;
    
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_invalid:
error_memory:
error_nameinfo:
error_sockopt:
    return result;
}

static
globus_result_t
globus_l_xio_tcp_server_destroy(
    void *                              driver_server)
{
    globus_result_t                     result;
    globus_l_server_t *                 server;
    int                                 rc;
    GlobusXIOName(globus_l_xio_tcp_server_destroy);
    
    server = (globus_l_server_t *) driver_server;
    
    do                                                                  
    {                                                                   
        rc = close(server->listener_handle);                             
    } while(rc < 0 && errno == EINTR);       
    
    if(rc < 0)
    {
        result = GlobusXIOErrorSystemError("close", errno);
        goto error_close;
    }                          
    
    globus_free(server);
    return GLOBUS_SUCCESS;
    
error_close:
    globus_free(server);
    return result;
}

static
globus_result_t
globus_l_xio_tcp_handle_init(
    globus_l_handle_t **                handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_tcp_handle_init);
    
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
globus_l_xio_tcp_handle_destroy(
    globus_l_handle_t *                 handle)
{
    GlobusXIOName(globus_l_xio_tcp_handle_destroy);
    
    globus_free(handle);
}

static
globus_result_t
globus_l_xio_tcp_bind_local(
    int                                 fd,
    globus_l_attr_t *                   attr)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 save_addrinfo;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    char *                              port = "0";
    GlobusXIOName(globus_l_xio_tcp_bind_local);
    
    memset(&addrinfo_hints, 0, sizeof(globus_addrinfo_t));
    addrinfo_hints.ai_flags = AI_PASSIVE;
    addrinfo_hints.ai_family = PF_UNSPEC;
    addrinfo_hints.ai_socktype = SOCK_STREAM;
    addrinfo_hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(
        attr->bind_address, port, &addrinfo_hints, &save_addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed("globus_libc_getaddrinfo", result);
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
                fd,
                addrinfo->ai_addr,
                addrinfo->ai_addrlen,
                attr->restrict_port ? attr->connector_min_port : 0,
                attr->restrict_port ? attr->connector_max_port : 0);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_l_xio_tcp_bind", result);
                continue;
            }
            
            break;
        }
    }
    
    if(!addrinfo)
    {
        if(result == GLOBUS_SUCCESS)
        {
            result = GlobusXIOTcpErrorNoAddrs();
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

typedef struct
{
    globus_xio_operation_t              op;
    globus_l_handle_t *                 handle;
    globus_l_attr_t *                   attr;
    globus_addrinfo_t *                 save_addrinfo;
    globus_addrinfo_t *                 next_addrinfo;
} globus_l_connect_info_t;

static
globus_result_t
globus_l_xio_tcp_connect_next(
    globus_l_connect_info_t *           connect_info);
    
static
void
globus_l_xio_tcp_system_connect_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_connect_info_t *           connect_info;
    GlobusXIOName(globus_l_xio_tcp_system_connect_cb);
    
    connect_info = (globus_l_connect_info_t *) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_result_t                 res;
        globus_object_t *               err;
        
        err = globus_error_get(result);
        
        if(!globus_xio_error_is_canceled(err))
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
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_tcp_handle_destroy(connect_info->handle);
        connect_info->handle = GLOBUS_NULL;
    }
    
    GlobusXIODriverFinishedOpen(
        GlobusXIOOperationGetContext(connect_info->op),
        connect_info->handle,
        connect_info->op,
        result);
    
    globus_libc_freeaddrinfo(connect_info->save_addrinfo);
    globus_l_xio_tcp_attr_destroy(connect_info->attr);
    globus_free(connect_info);
    
    return;
    
error_tryagain:    
    return;
}

static
globus_result_t
globus_l_xio_tcp_connect_next(
    globus_l_connect_info_t *           connect_info)
{
    globus_addrinfo_t *                 addrinfo;
    int                                 fd;
    globus_result_t                     result;
    int                                 save_errno;
    globus_sockaddr_t                   myaddr;
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_tcp_connect_next);
    
    attr = connect_info->attr;
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
    
            GlobusLibcSockaddrLen(*addrinfo->ai_addr, len);
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
            
            result = globus_l_xio_tcp_apply_handle_attrs(attr, fd, GLOBUS_TRUE);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_l_xio_tcp_apply_handle_attrs", result);
                GlobusIXIOTcpCloseFd(fd);
                continue;
            }
            
            /* if specifying interface or outgoing port ranges, need to bind */
            if(attr->bind_address || 
                (attr->restrict_port && attr->connector_max_port > 0))
            {
                result = globus_l_xio_tcp_bind_local(fd, attr);
                if(result != GLOBUS_SUCCESS)
                {
                    result = GlobusXIOErrorWrapFailed(
                        "globus_l_xio_tcp_bind_local", result);
                    GlobusIXIOTcpCloseFd(fd);
                    continue;
                }
            }
            
            connect_info->handle->handle = fd;
            connect_info->next_addrinfo = addrinfo->ai_next;
            GlobusLibcSockaddrCopy(
                myaddr, *addrinfo->ai_addr, addrinfo->ai_addrlen);
                
            result = globus_xio_system_register_connect(
                connect_info->op,
                fd, 
                &myaddr,
                globus_l_xio_tcp_system_connect_cb,
                connect_info);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_xio_system_register_connect", result);
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
                result = GlobusXIOTcpErrorNoAddrs();
            }
            else
            {
                result = GlobusXIOErrorSystemError("socket", save_errno);
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
    globus_xio_operation_t              op,
    globus_l_handle_t *                 handle,
    const globus_l_attr_t *             attr,
    const char *                        contact_string)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    globus_l_connect_info_t *           connect_info;
    char *                              host;
    char *                              port;
    GlobusXIOName(globus_l_xio_tcp_connect);
    
    host = globus_libc_strdup(contact_string);
    if(!host)
    {
        result = GlobusXIOErrorMemory("cs_copy");
        goto error_cs_copy;
    }
    
    port = strrchr(host, ':');
    if(!port)
    {
        result = GlobusXIOErrorContactString("missing ':'");
        goto error_bad_contact;
    }
    
    *port = 0;
    port++;
    
    /* setup hints for types of connectable sockets we want */
    memset(&addrinfo_hints, 0, sizeof(globus_addrinfo_t));
    addrinfo_hints.ai_flags = 0;
    addrinfo_hints.ai_family = PF_UNSPEC;
    addrinfo_hints.ai_socktype = SOCK_STREAM;
    addrinfo_hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(host, port, &addrinfo_hints, &addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_libc_getaddrinfo", result);
        goto error_getaddrinfo;
    }
    
    connect_info = (globus_l_connect_info_t *)
        globus_malloc(sizeof(globus_l_connect_info_t));
    if(!connect_info)
    {
        result = GlobusXIOErrorMemory("connect_info");
        goto error_info;
    }
    
    result = globus_l_xio_tcp_attr_copy(
        (void **) &connect_info->attr, (void *) attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_tcp_attr_copy", result);
        goto error_attr;
    }
    
    connect_info->op = op;
    connect_info->handle = handle;
    connect_info->save_addrinfo = addrinfo;
    connect_info->next_addrinfo = addrinfo;
    
    result = globus_l_xio_tcp_connect_next(connect_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_tcp_connect_next", result);
        goto error_connect_next;
    }
    
    free(host);
    
    return GLOBUS_SUCCESS;

error_connect_next:
    globus_l_xio_tcp_attr_destroy(connect_info->attr);
    
error_attr:
    globus_free(connect_info);
    
error_info:
    globus_libc_freeaddrinfo(addrinfo);

error_getaddrinfo:
error_bad_contact:
    globus_free(host);

error_cs_copy:
    return result;
}

/*
 *  open a tcp
 */
static
globus_result_t
globus_l_xio_tcp_open(
    void *                              driver_attr,
    void *                              driver_target,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_l_target_t *                 target;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_tcp_open);
    
    target = (globus_l_target_t *) driver_target;
    attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_tcp_attr_default);
    
    result = globus_l_xio_tcp_handle_init(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_tcp_handle_init", result);
        goto error_handle;
    }
    
    if(target->handle == GLOBUS_XIO_TCP_INVALID_HANDLE)
    {
        result = globus_l_xio_tcp_connect(
            op, handle, attr, target->contact_string);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_tcp_connect", result);
            goto error_connect;
        }
    }
    else
    {
        handle->handle = target->handle;
        /* so handle isnt closed when target is destroyed */
        target->handle = GLOBUS_XIO_TCP_INVALID_HANDLE;
        result = globus_l_xio_tcp_apply_handle_attrs(
            attr, handle->handle, GLOBUS_FALSE);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_tcp_apply_handle_attrs", result);
            goto error_attrs;
        }
        
        GlobusXIODriverFinishedOpen(context, handle, op, GLOBUS_SUCCESS);
    }

    return GLOBUS_SUCCESS;

error_attrs:   
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
    globus_xio_operation_t              op;
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_tcp_system_close_cb);
    
    op = (globus_xio_operation_t) user_arg;
    
    context = GlobusXIOOperationGetContext(op);
    handle = GlobusXIOOperationGetDriverHandle(op);
    
    GlobusXIODriverFinishedClose(op, result);
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
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_tcp_close);

    handle = (globus_l_handle_t *) driver_handle;
        
    result = globus_xio_system_register_close(
        op,
        handle->handle,
        globus_l_xio_tcp_system_close_cb,
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
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_tcp_system_read_cb);
    
    op = (globus_xio_operation_t) user_arg;
    GlobusXIODriverFinishedRead(op, result, nbytes);
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
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_tcp_read);

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
            globus_l_xio_tcp_system_read_cb,
            op);
    }
}

static
void
globus_l_xio_tcp_system_write_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_tcp_system_write_cb);
    
    op = (globus_xio_operation_t) user_arg;
    GlobusXIODriverFinishedWrite(op, result, nbytes);
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
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_tcp_write);

    handle = (globus_l_handle_t *) driver_handle;
    attr = (globus_l_attr_t *) GlobusXIOOperationGetDataDescriptor(op);
    
    if(GlobusXIOOperationGetWaitFor(op) == 0)
    {
        globus_size_t                       nbytes;
        globus_result_t                     result;
        
        if(attr && attr->send_flags)
        {
            result = globus_xio_system_try_write_ex(
                handle->handle,
                iovec,
                iovec_count,
                attr->send_flags,
                GLOBUS_NULL,
                &nbytes);
        }
        else
        {
            result = globus_xio_system_try_write(
                handle->handle, iovec, iovec_count, &nbytes);
        }
        GlobusXIODriverFinishedWrite(op, result, nbytes);
        /* Since I am finishing the request in the callstack,
         * the choice to pass the result in the finish instead of below
         * is arbitrary.
         */
        return GLOBUS_SUCCESS;
    }
    else
    {
        if(attr && attr->send_flags)
        {
            return globus_xio_system_register_write_ex(
                op,
                handle->handle,
                iovec,
                iovec_count,
                GlobusXIOOperationGetWaitFor(op),
                attr->send_flags,
                GLOBUS_NULL,
                globus_l_xio_tcp_system_write_cb,
                op);
        }
        else
        {
            return globus_xio_system_register_write(
                op,
                handle->handle,
                iovec,
                iovec_count,
                GlobusXIOOperationGetWaitFor(op),
                globus_l_xio_tcp_system_write_cb,
                op);
        }
    }
}

static
globus_result_t
globus_l_xio_tcp_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    int *                               out_int;
    globus_bool_t                       in_bool;
    globus_bool_t *                     out_bool;
    int                                 in_int;
    globus_sockaddr_t *                 out_sock;
    int                                 fd;
    globus_size_t                       len;
    GlobusXIOName(globus_l_xio_tcp_cntl);

    handle = (globus_l_handle_t *) driver_handle;
    fd = handle->handle;
    switch(cmd)
    {
      /* globus_bool_t                  keepalive */
      case GLOBUS_XIO_TCP_SET_KEEPALIVE:
        in_bool = va_arg(ap, globus_bool_t);
        if(setsockopt(
            fd, SOL_SOCKET, SO_KEEPALIVE, &in_bool, sizeof(in_bool)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_bool_t *                keepalive_out */
      case GLOBUS_XIO_TCP_GET_KEEPALIVE:
        out_bool = va_arg(ap, globus_bool_t *);
        len = sizeof(globus_bool_t);
        if(getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, out_bool, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_bool_t                  linger */
      /* int                            linger_time */
      case GLOBUS_XIO_TCP_SET_LINGER:
        {
            struct linger           linger;
        
            linger.l_onoff = va_arg(ap, globus_bool_t);;
            linger.l_linger = va_arg(ap, int);
            
            if(setsockopt(
                fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0)
            {
                result = GlobusXIOErrorSystemError("setsockopt", errno);
                goto error_sockopt;
            }
        }
        break;
        
      /* globus_bool_t *                linger_out */
      /* int *                          linger_time_out */
      case GLOBUS_XIO_TCP_GET_LINGER:
        {
            struct linger           linger;
            
            len = sizeof(linger);
            if(getsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, &len) < 0)
            {
                result = GlobusXIOErrorSystemError("getsockopt", errno);
                goto error_sockopt;
            }
            
            out_bool = va_arg(ap, globus_bool_t *);
            out_int = va_arg(ap, int *);
            *out_bool = linger.l_onoff;
            *out_int = linger.l_linger;
        }
        break;
        
      /* globus_bool_t                  oobinline */
      case GLOBUS_XIO_TCP_SET_OOBINLINE:
        in_bool = va_arg(ap, globus_bool_t);
        if(setsockopt(
            fd, SOL_SOCKET, SO_OOBINLINE, &in_bool, sizeof(in_bool)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_bool_t *                oobinline_out */
      case GLOBUS_XIO_TCP_GET_OOBINLINE:
        out_bool = va_arg(ap, globus_bool_t *);
        len = sizeof(globus_bool_t);
        if(getsockopt(
            fd, SOL_SOCKET, SO_OOBINLINE, out_bool, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int                            sndbuf */
      case GLOBUS_XIO_TCP_SET_SNDBUF:
        in_int = va_arg(ap, int);
        if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &in_int, sizeof(in_int)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int *                          sndbuf_out */
      case GLOBUS_XIO_TCP_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        len = sizeof(int);
        if(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, out_int, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int                            rcvbuf */
      case GLOBUS_XIO_TCP_SET_RCVBUF:
        in_int = va_arg(ap, int);
        if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &in_int, sizeof(in_int)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_TCP_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        len = sizeof(int);
        if(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, out_int, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_bool_t                  nodelay */
      case GLOBUS_XIO_TCP_SET_NODELAY:
        in_bool = va_arg(ap, globus_bool_t);
        if(setsockopt(
            fd, IPPROTO_TCP, TCP_NODELAY, &in_bool, sizeof(in_bool)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_bool_t *                nodelay_out */
      case GLOBUS_XIO_TCP_GET_NODELAY:
        out_bool = va_arg(ap, globus_bool_t *);
        len = sizeof(globus_bool_t);
        if(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, out_bool, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
      
      /* globus_sockaddr_t *            sock_name_out */
      case GLOBUS_XIO_TCP_GET_LOCAL_ADDRESS:
        out_sock = va_arg(ap, globus_sockaddr_t *);
        len = sizeof(globus_sockaddr_t);
        if(getsockname(
            handle->handle, (struct sockaddr *) out_sock, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockname", errno);
            goto error_sockopt;
        }
        break;
        
      /* globus_sockaddr_t *            peer_name_out */
      case GLOBUS_XIO_TCP_GET_REMOTE_ADDRESS:
        out_sock = va_arg(ap, globus_sockaddr_t *);
        len = sizeof(globus_sockaddr_t);
        if(getpeername(
            handle->handle, (struct sockaddr *) out_sock, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getpeername", errno);
            goto error_sockopt;
        }
        break;
        
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_invalid:
error_sockopt:
    return result;
}

static
globus_result_t
globus_l_xio_tcp_init(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_tcp_init);
    
    /* I dont support any driver options, so I'll ignore the ap */
    
    result = globus_xio_driver_init(&driver, "tcp", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_tcp_handle_init", result);
        goto error_init;
    }

    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_tcp_open,
        globus_l_xio_tcp_close,
        globus_l_xio_tcp_read,
        globus_l_xio_tcp_write,
        globus_l_xio_tcp_cntl);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_tcp_target_init,
        globus_l_xio_tcp_target_cntl,
        globus_l_xio_tcp_target_destroy);
    
    globus_xio_driver_set_server(
        driver,
        globus_l_xio_tcp_server_init,
        globus_l_xio_tcp_server_accept,
        globus_l_xio_tcp_server_destroy,
        globus_l_xio_tcp_server_cntl,
        globus_l_xio_tcp_target_destroy);
        
    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_tcp_attr_init,
        globus_l_xio_tcp_attr_copy,
        globus_l_xio_tcp_attr_cntl,
        globus_l_xio_tcp_attr_destroy);
    
    *out_driver = driver;

    return GLOBUS_SUCCESS;

error_init:
    return result;
}

static
void
globus_l_xio_tcp_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    tcp,
    &globus_i_xio_tcp_module,
    globus_l_xio_tcp_init,
    globus_l_xio_tcp_destroy);
