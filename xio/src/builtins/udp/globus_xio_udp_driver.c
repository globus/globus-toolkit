#include "globus_i_xio.h"
#include "globus_xio_driver.h"
#include "globus_xio_udp_driver.h"
#include "version.h"
#include <netinet/udp.h>

static
int
globus_l_xio_udp_activate(void);


static
int
globus_l_xio_udp_deactivate(void);

static globus_module_descriptor_t       globus_i_xio_udp_module =
{
    "globus_xio_udp",
    globus_l_xio_udp_activate,
    globus_l_xio_udp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

#define GlobusXIOUdpErrorNoAddrs()                                          \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            &globus_i_xio_udp_module,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDP_ERROR_NO_ADDRS,                                  \
            "[%s:%d] No addrs for INET family",                             \
            _xio_name, __LINE__))


#define GlobusIXIOUdpCloseFd(fd)                                            \
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
    /* target attrs */
    globus_xio_system_handle_t          handle;
    
    /* handle attrs */
    char *                              listener_serv;
    int                                 listener_port;
    int                                 listener_min_port;
    int                                 listener_max_port;
    char *                              bind_address;
    globus_bool_t                       restrict_port;
    globus_bool_t                       resuseaddr;
    int                                 sndbuf;
    int                                 rcvbuf;
    
    /* dd attrs */
    globus_bool_t                       use_addr;
    globus_sockaddr_t                   addr;
} globus_l_attr_t;

/* default attr */
static globus_l_attr_t                  globus_l_xio_udp_attr_default =
{
    GLOBUS_XIO_UDP_INVALID_HANDLE,      /* handle   */ 
    
    GLOBUS_NULL,                        /* listener_serv */
    0,                                  /* listener_port */
    0,                                  /* listener_min_port */
    0,                                  /* listener_max_port */
    GLOBUS_NULL,                        /* bind_address */
    GLOBUS_TRUE,                        /* restrict_port */
    GLOBUS_FALSE,                       /* reuseaddr */
    0,                                  /* sndbuf (system default) */     
    0,                                  /* rcvbuf (system default) */
    
    GLOBUS_FALSE,                       /* use_addr */
    {0}                                 /* addr */
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
 *  handle structure
 */
typedef struct
{
    globus_xio_system_handle_t          handle;
} globus_l_handle_t;

static
globus_bool_t
globus_l_xio_udp_get_env_pair(
    const char *                        env_name,
    int *                               min,
    int *                               max)
{
    char *                              min_max;
    GlobusXIOName(globus_l_xio_udp_get_env_pair);

    min_max = globus_module_getenv(env_name);

    if(min_max && sscanf(min_max, " %d , %d", min, max) == 2)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

static
int
globus_l_xio_udp_activate(void)
{
    int                                 min;
    int                                 max;
    GlobusXIOName(globus_l_xio_udp_activate);
    
    if(globus_l_xio_udp_get_env_pair(
        "GLOBUS_XIO_UDP_LISTEN_RANGE", &min, &max) && min <= max)
    {
        globus_l_xio_udp_attr_default.listener_min_port = min;
        globus_l_xio_udp_attr_default.listener_max_port = max;
    }
    
    return globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
}

static
int
globus_l_xio_udp_deactivate(void)
{
    GlobusXIOName(globus_l_xio_udp_deactivate);
    
    globus_l_xio_udp_attr_default.listener_min_port = 0;
    globus_l_xio_udp_attr_default.listener_max_port = 0;
        
    return globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);
}

/*
 *  initialize a driver attribute
 */
static
globus_result_t
globus_l_xio_udp_attr_init(
    void **                             out_attr)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_attr_init);
    
    /*
     *  create a udp attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, &globus_l_xio_udp_attr_default, sizeof(globus_l_attr_t));
    *out_attr = attr;

    return GLOBUS_SUCCESS;

error_attr:
    return result;
}

static
globus_result_t
globus_l_xio_udp_get_addrinfo(
    const char *                        contact_string,
    globus_addrinfo_t **                addrinfo)
{
    globus_result_t                     result;
    globus_addrinfo_t                   addrinfo_hints;
    char *                              host;
    char *                              port;
    GlobusXIOName(globus_l_xio_udp_get_addrinfo);
    
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
    addrinfo_hints.ai_socktype = SOCK_DGRAM;
    addrinfo_hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(
        host, port, &addrinfo_hints, addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_libc_getaddrinfo", result);
        goto error_getaddrinfo;
    }
    
    globus_free(host);
    
    return GLOBUS_SUCCESS;

error_getaddrinfo:
error_bad_contact:
    globus_free(host);

error_cs_copy:
    return result;
}

/*
 *  modify the attribute structure
 */
static
globus_result_t
globus_l_xio_udp_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_attr_t *                   attr;
    globus_xio_system_handle_t *        out_handle;
    char **                             out_string;
    int *                               out_int;
    globus_bool_t *                     out_bool;
    char *                              in_string;
    globus_result_t                     result;
    int                                 flags;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t *                 save_addrinfo;
    GlobusXIOName(globus_l_xio_udp_attr_cntl);

    attr = (globus_l_attr_t *) driver_attr;
    flags = 0;
    switch(cmd)
    {
      /**
       *  target attrs
       */
      /* globus_xio_system_handle_t     handle */
      case GLOBUS_XIO_UDP_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_handle_t);
        break;
      
      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_UDP_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = attr->handle;
        break;
       
      /**
       *  handle attrs
       */
      /* char *                         service_name */
      case GLOBUS_XIO_UDP_SET_SERVICE:
        if(attr->listener_serv)
        {
            globus_free(attr->listener_serv);
        }
        
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
      case GLOBUS_XIO_UDP_GET_SERVICE:
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
      case GLOBUS_XIO_UDP_SET_PORT:
        attr->listener_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_port_out */
      case GLOBUS_XIO_UDP_GET_PORT:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_port;
        break;
      
      /* int                            listener_min_port */
      /* int                            listener_max_port */
      case GLOBUS_XIO_UDP_SET_LISTEN_RANGE:
        attr->listener_min_port = va_arg(ap, int);
        attr->listener_max_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_min_port_out */
      /* int *                          listener_max_port_out */
      case GLOBUS_XIO_UDP_GET_LISTEN_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_max_port;
        break;
        
      /* char *                         interface */
      case GLOBUS_XIO_UDP_SET_INTERFACE:
        if(attr->bind_address)
        {
            globus_free(attr->bind_address);
        }
        
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
      case GLOBUS_XIO_UDP_GET_INTERFACE:
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
      case GLOBUS_XIO_UDP_SET_RESTRICT_PORT:
        attr->restrict_port = va_arg(ap, globus_bool_t);
        break;
      
      /* globus_bool_t *                restrict_port_out */
      case GLOBUS_XIO_UDP_GET_RESTRICT_PORT:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->restrict_port;
        break;
      
      /* globus_bool_t                  resuseaddr */
      case GLOBUS_XIO_UDP_SET_REUSEADDR:
        attr->resuseaddr = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                resuseaddr_out */
      case GLOBUS_XIO_UDP_GET_REUSEADDR:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->resuseaddr;
        break;
        
      /* int                            sndbuf */
      case GLOBUS_XIO_UDP_SET_SNDBUF:
        attr->sndbuf = va_arg(ap, int);
        break;
        
      /* int *                          sndbuf_out */
      case GLOBUS_XIO_UDP_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->sndbuf;
        break;
        
      /* int                            rcvbuf */
      case GLOBUS_XIO_UDP_SET_RCVBUF:
        attr->rcvbuf = va_arg(ap, int);
        break;
        
      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_UDP_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->rcvbuf;
        break;
        
      /**
       * dd attrs
       */
      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT:
        flags |= GLOBUS_LIBC_ADDR_NUMERIC;
        /* fall through */
      
      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDP_GET_CONTACT:
        
        out_string = va_arg(ap, char **);
        result = globus_libc_addr_to_contact_string(
            &attr->addr,
            flags,
            out_string);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_libc_addr_to_contact_string", result);
            goto error_contact;
        }
        break;
      
      /* char *                         contact_string */
      case GLOBUS_XIO_UDP_SET_CONTACT:
        in_string = va_arg(ap, char *);
    
        result = globus_l_xio_udp_get_addrinfo(in_string, &save_addrinfo);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_udp_get_addrinfo", result);
            goto error_getaddrinfo;
        }
    
        for(addrinfo = save_addrinfo;
            addrinfo && !GlobusLibcProtocolFamilyIsIP(addrinfo->ai_family);
            addrinfo = addrinfo->ai_next)
        {
        }
    
        if(addrinfo)
        {
            GlobusLibcSockaddrCopy(
                attr->addr, *addrinfo->ai_addr, addrinfo->ai_addrlen);
            attr->use_addr = GLOBUS_TRUE;
        }
        else
        {
            result = GlobusXIOUdpErrorNoAddrs();
            goto error_no_addrinfo;
        }
    
        globus_libc_freeaddrinfo(save_addrinfo);
        break;

      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_no_addrinfo:
    globus_libc_freeaddrinfo(save_addrinfo);

error_getaddrinfo:
error_memory:
error_contact:
error_invalid:
    return result;
}

/*
 *  copy an attribute structure
 */
static
globus_result_t
globus_l_xio_udp_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_attr_copy);

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
globus_l_xio_udp_attr_destroy(
    void *                              driver_attr)
{
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_udp_attr_destroy);
    
    attr = (globus_l_attr_t *) driver_attr;
    if(attr->bind_address)
    {
        globus_free(attr->bind_address);
    }
    if(attr->listener_serv)
    {
        globus_free(attr->listener_serv);
    }
    
    globus_free(attr);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udp_apply_handle_attrs(
    const globus_l_attr_t *             attr,
    int                                 fd)
{
    globus_result_t                     result;
    int                                 int_one = 1;
    GlobusXIOName(globus_l_xio_udp_apply_handle_attrs);
    
    /* all handles created by me are closed on exec */
    if(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        result = GlobusXIOErrorSystemError("fcntl", errno);
        goto error_sockopt;
    }
        
    if(attr->resuseaddr &&
       setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &int_one, sizeof(int_one)) < 0)
    {
        result = GlobusXIOErrorSystemError("setsockopt", errno);
        goto error_sockopt;
    }
    
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
    
    return GLOBUS_SUCCESS;

error_sockopt:
    return result;
}

/*
 *  initialize target structure
 */
static
globus_result_t
globus_l_xio_udp_target_init(
    void **                             out_target,
    void *                              driver_attr,
    const char *                        contact_string)
{
    globus_l_target_t *                 target;
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_target_init);
    
    attr = (globus_l_attr_t *) driver_attr;
    
    /* create the target structure and copy the contact string into it */
    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
    if(!target)
    {
        result = GlobusXIOErrorMemory("target");
        goto error_target;
    }
    
    target->handle = GLOBUS_XIO_UDP_INVALID_HANDLE;
    target->contact_string = GLOBUS_NULL;
    
    if(!attr || attr->handle == GLOBUS_XIO_UDP_INVALID_HANDLE)
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
globus_l_xio_udp_target_cntl(
    void *                              driver_target,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_target_t *                 target;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_target_cntl);

    target = (globus_l_target_t *) driver_target;
    switch(cmd)
    {
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_invalid:
    return result;
}

/*
 *  destroy the target structure
 */
static
globus_result_t
globus_l_xio_udp_target_destroy(
    void *                              driver_target)
{
    globus_l_target_t *                 target;
    GlobusXIOName(globus_l_xio_udp_target_destroy);
    
    target = (globus_l_target_t *) driver_target;
    
    if(target->contact_string)
    {
        globus_free(target->contact_string);
    }
    if(target->handle != GLOBUS_XIO_UDP_INVALID_HANDLE)
    {
        GlobusIXIOUdpCloseFd(target->handle);
    }
    
    globus_free(target);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udp_bind(
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
    GlobusXIOName(globus_l_xio_udp_bind);
    
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
globus_l_xio_udp_create_listener(
    globus_l_handle_t *                 handle,
    const globus_l_attr_t *             attr)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 save_addrinfo;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    char                                portbuf[10];
    char *                              port;
    int                                 fd;
    int                                 save_errno;
    GlobusXIOName(globus_l_xio_udp_create_listener);
    
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
    addrinfo_hints.ai_socktype = SOCK_DGRAM;
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
            
            result = globus_l_xio_udp_apply_handle_attrs(attr, fd);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_l_xio_udp_apply_handle_attrs", result);
                GlobusIXIOUdpCloseFd(fd);
                continue;
            }
            
            result = globus_l_xio_udp_bind(
                fd,
                addrinfo->ai_addr,
                addrinfo->ai_addrlen,
                attr->restrict_port ? attr->listener_min_port : 0,
                attr->restrict_port ? attr->listener_max_port : 0);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOErrorWrapFailed(
                    "globus_l_xio_udp_bind", result);
                GlobusIXIOUdpCloseFd(fd);
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
                result = GlobusXIOUdpErrorNoAddrs();
            }
            else
            {
                result = GlobusXIOErrorSystemError("socket", save_errno);
            }
        }
        
        goto error_no_addrinfo;
    }
    
    handle->handle = fd;
    globus_libc_freeaddrinfo(save_addrinfo);

    return GLOBUS_SUCCESS;

error_no_addrinfo:
    globus_libc_freeaddrinfo(save_addrinfo);

error_getaddrinfo:
    return result;
}

static
globus_result_t
globus_l_xio_udp_handle_init(
    globus_l_handle_t **                handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_handle_init);
    
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
globus_l_xio_udp_handle_destroy(
    globus_l_handle_t *                 handle)
{
    GlobusXIOName(globus_l_xio_udp_handle_destroy);
    
    globus_free(handle);
}

static
globus_result_t
globus_l_xio_udp_connect(
    globus_l_handle_t *                 handle,
    const globus_l_attr_t *             attr,
    const char *                        contact_string)
{
    globus_result_t                     result;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t *                 save_addrinfo;
    int                                 rc;
    GlobusXIOName(globus_l_xio_udp_connect);
    
    result = globus_l_xio_udp_get_addrinfo(contact_string, &save_addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_udp_get_addrinfo", result);
        goto error_getaddrinfo;
    }
    
    for(addrinfo = save_addrinfo; addrinfo; addrinfo = addrinfo->ai_next)
    {
        if(GlobusLibcProtocolFamilyIsIP(addrinfo->ai_family))
        {
            do
            {
                rc = connect(
                    handle->handle, addrinfo->ai_addr, addrinfo->ai_addrlen);
            } while(rc < 0 && errno == EINTR);
                
            if(rc < 0)
            {
                result = GlobusXIOErrorSystemError("connect", errno);
                continue;
            }
            
            break;
        }
    }
    
    if(!addrinfo)
    {
        if(result == GLOBUS_SUCCESS)
        {
            result = GlobusXIOUdpErrorNoAddrs();
        }
        
        goto error_no_addrinfo;
    }
    
    globus_libc_freeaddrinfo(save_addrinfo);
    
    return GLOBUS_SUCCESS;

error_no_addrinfo:
    globus_libc_freeaddrinfo(save_addrinfo);

error_getaddrinfo:
    GlobusIXIOUdpCloseFd(handle->handle);
    
    return result;
}

/*
 *  open a udp
 */
static
globus_result_t
globus_l_xio_udp_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_l_target_t *                 target;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_open);
    
    target = (globus_l_target_t *) driver_target;
    attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_udp_attr_default);
    
    result = globus_l_xio_udp_handle_init(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_udp_handle_init", result);
        goto error_handle;
    }
    
    if(target->handle == GLOBUS_XIO_UDP_INVALID_HANDLE)
    {
        /* setup the local side */
        result = globus_l_xio_udp_create_listener(handle, attr);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_udp_create_listener", result);
            goto error_listen;
        }
    }
    else
    {
        handle->handle = target->handle;
        /* so handle isnt closed when target is destroyed */
        target->handle = GLOBUS_XIO_UDP_INVALID_HANDLE;
        result = globus_l_xio_udp_apply_handle_attrs(attr, handle->handle);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_udp_apply_handle_attrs", result);
            goto error_attrs;
        }
    }
    
    /* if a peer has been chosen, bind them */
    /* XXX need to check into ipv4/6 mismatches between local and remote */
    if(*target->contact_string)
    {
        result = globus_l_xio_udp_connect(
            handle, attr, target->contact_string);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_udp_connect", result);
            goto error_connect;
        }
    }
    
    GlobusXIODriverFinishedOpen(context, handle, op, GLOBUS_SUCCESS);
    
    return GLOBUS_SUCCESS;

error_connect:
error_listen:
error_attrs:   
    globus_l_xio_udp_handle_destroy(handle);  

error_handle:
    return result;
}

static
void
globus_l_xio_udp_system_close_cb(
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_udp_system_close_cb);
    
    op = (globus_xio_operation_t) user_arg;
    
    context = GlobusXIOOperationGetContext(op);
    handle = GlobusXIOOperationGetDriverHandle(op);
    
    GlobusXIODriverFinishedClose(op, result);
    globus_xio_driver_context_close(context);
    globus_l_xio_udp_handle_destroy(handle);
}

/*
 *  close a udp
 */
static
globus_result_t
globus_l_xio_udp_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_close);

    handle = (globus_l_handle_t *) driver_handle;
        
    result = globus_xio_system_register_close(
        op,
        handle->handle,
        globus_l_xio_udp_system_close_cb,
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
    globus_l_xio_udp_handle_destroy(handle);
    
    return result;
}

static
void
globus_l_xio_udp_system_read_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_udp_system_read_cb);
    
    op = (globus_xio_operation_t) user_arg;
    if(result != GLOBUS_SUCCESS && globus_xio_error_is_eof(result))
    {
        /* eof not possible, zero byte packets allowed */
        result = GLOBUS_SUCCESS;
    }
    GlobusXIODriverFinishedRead(op, result, nbytes);
}

/*
 *  read from a udp
 */
static
globus_result_t
globus_l_xio_udp_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_l_attr_t *                   attr;
    globus_sockaddr_t *                 addr;
    GlobusXIOName(globus_l_xio_udp_read);

    handle = (globus_l_handle_t *) driver_handle;
    attr = (globus_l_attr_t *) GlobusXIOOperationGetDataDescriptor(op);
    
    /* XXXX temporary */
    if(!attr)
    {
        globus_l_xio_udp_attr_init(&attr);
        GlobusXIOOperationSetDataDescriptor(op, attr);
    }

    if(attr)
    {
        addr = &attr->addr;
        attr->use_addr = GLOBUS_TRUE;
    }
    else
    {
        addr = GLOBUS_NULL;
    }
    
    if(GlobusXIOOperationGetWaitFor(op) == 0)
    {
        globus_size_t                   nbytes;
        globus_result_t                 result;
        
        result = globus_xio_system_try_read_ex(
            handle->handle,
            iovec,
            iovec_count,
            0,
            addr,
            &nbytes);
        if(result != GLOBUS_SUCCESS && globus_xio_error_is_eof(result))
        {
            /* eof not possible, zero byte packets allowed */
            result = GLOBUS_SUCCESS;
        }
        
        GlobusXIODriverFinishedRead(op, result, nbytes);
        /* dont want to return error here mainly because error could be eof, 
         * which is against our convention to return an eof error on async
         * calls.  Other than that, the choice is arbitrary
         */
        return GLOBUS_SUCCESS;
    }
    else
    {
        return globus_xio_system_register_read_ex(
            op,
            handle->handle,
            iovec,
            iovec_count,
            GlobusXIOOperationGetWaitFor(op),
            0,
            addr,
            globus_l_xio_udp_system_read_cb,
            op);
    }
}

static
void
globus_l_xio_udp_system_write_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_udp_system_write_cb);
    
    op = (globus_xio_operation_t) user_arg;
    GlobusXIODriverFinishedWrite(op, result, nbytes);
}

/*
 *  write to a udp
 */
static
globus_result_t
globus_l_xio_udp_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_l_attr_t *                   attr;
    globus_sockaddr_t *                 addr;
    GlobusXIOName(globus_l_xio_udp_write);

    handle = (globus_l_handle_t *) driver_handle;
    attr = (globus_l_attr_t *) GlobusXIOOperationGetDataDescriptor(op);
    
    addr = GLOBUS_NULL;
    if(attr && attr->use_addr)
    {
        addr = &attr->addr;
    }

    if(GlobusXIOOperationGetWaitFor(op) == 0)
    {
        globus_size_t                   nbytes;
        globus_result_t                 result;
        
        result = globus_xio_system_try_write_ex(
            handle->handle, iovec, iovec_count, 0, addr, &nbytes);
            
        GlobusXIODriverFinishedWrite(op, result, nbytes);
        /* Since I am finishing the request in the callstack,
         * the choice to pass the result in the finish instead of below
         * is arbitrary.
         */
        return GLOBUS_SUCCESS;
    }
    else
    {
        return globus_xio_system_register_write_ex(
            op,
            handle->handle,
            iovec,
            iovec_count,
            GlobusXIOOperationGetWaitFor(op),
            0,
            addr,
            globus_l_xio_udp_system_write_cb,
            op);
    }
}

static
globus_result_t
globus_l_xio_udp_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    int *                               out_int;
    int                                 in_int;
    globus_sockaddr_t                   sock_name;
    int                                 fd;
    globus_size_t                       len;
    int                                 flags;
    char **                             out_string;
    GlobusXIOName(globus_l_xio_udp_cntl);

    handle = (globus_l_handle_t *) driver_handle;
    fd = handle->handle;
    flags = GLOBUS_LIBC_ADDR_LOCAL;
    
    switch(cmd)
    {
      /* int                            sndbuf */
      case GLOBUS_XIO_UDP_SET_SNDBUF:
        in_int = va_arg(ap, int);
        if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &in_int, sizeof(in_int)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int *                          sndbuf_out */
      case GLOBUS_XIO_UDP_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        len = sizeof(int);
        if(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, out_int, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int                            rcvbuf */
      case GLOBUS_XIO_UDP_SET_RCVBUF:
        in_int = va_arg(ap, int);
        if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &in_int, sizeof(in_int)) < 0)
        {
            result = GlobusXIOErrorSystemError("setsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_UDP_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        len = sizeof(int);
        if(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, out_int, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockopt", errno);
            goto error_sockopt;
        }
        break;
        
      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT:
        flags |= GLOBUS_LIBC_ADDR_NUMERIC;
        /* fall through */
      
      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDP_GET_CONTACT:
        len = sizeof(globus_sockaddr_t);
        if(getsockname(fd, (struct sockaddr *) &sock_name, &len) < 0)
        {
            result = GlobusXIOErrorSystemError("getsockname", errno);
            goto error_sockopt;
        }
        
        out_string = va_arg(ap, char **);
        result = globus_libc_addr_to_contact_string(
            &sock_name,
            flags,
            out_string);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_libc_addr_to_contact_string", result);
            goto error_contact;
        }
        break;

      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    return GLOBUS_SUCCESS;

error_contact:
error_invalid:
error_sockopt:
    return result;
}

static
globus_result_t
globus_l_xio_udp_init(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_init);
    
    /* I dont support any driver options, so I'll ignore the ap */
    
    result = globus_xio_driver_init(&driver, "udp", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_udp_handle_init", result);
        goto error_init;
    }

    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_udp_open,
        globus_l_xio_udp_close,
        globus_l_xio_udp_read,
        globus_l_xio_udp_write,
        globus_l_xio_udp_cntl);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_udp_target_init,
        globus_l_xio_udp_target_cntl,
        globus_l_xio_udp_target_destroy);
    
    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_udp_attr_init,
        globus_l_xio_udp_attr_copy,
        globus_l_xio_udp_attr_cntl,
        globus_l_xio_udp_attr_destroy);
    
    *out_driver = driver;

    return GLOBUS_SUCCESS;

error_init:
    return result;
}

static
void
globus_l_xio_udp_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    udp,
    &globus_i_xio_udp_module,
    globus_l_xio_udp_init,
    globus_l_xio_udp_destroy);
