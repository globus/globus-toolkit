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
#include "globus_xio_wrapblock.h"
#include "globus_xio_udt_ref.h"
#include "version.h"
#include <arpa/inet.h>

#include "udt.h"

#define XIO_UDT_BOOL_UNDEF  (GLOBUS_FALSE - 10)

#define GlobusXIOUdtError(_r) globus_error_put(GlobusXIOUdtErrorObj(_r))

#define GlobusXIOUdtErrorObj(_reason)                                       \
    globus_error_construct_error(                                           \
        GLOBUS_XIO_MODULE,                                                  \
        GLOBUS_NULL,                                                        \
        1,                                                                  \
        __FILE__,                                                           \
        _xio_name,                                                          \
        __LINE__,                                                           \
        _XIOSL(_reason))                                

GlobusDebugDefine(GLOBUS_XIO_UDT_REF);
GlobusXIODeclareDriver(udt_ref);

#define GlobusXIOUDTRefDebugPrintf(level, message)                           \
    GlobusDebugPrintf(GLOBUS_XIO_UDT_REF, level, message)

#define GlobusXIOUDTRefDebugEnter()                                          \
    GlobusXIOUDTRefDebugPrintf(                                              \
        GLOBUS_L_XIO_UDT_REF_DEBUG_TRACE,                                     \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOUDTRefDebugExit()                                           \
    GlobusXIOUDTRefDebugPrintf(                                              \
        GLOBUS_L_XIO_UDT_REF_DEBUG_TRACE,                                     \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOUDTRefDebugExitWithError()                                  \
    GlobusXIOUDTRefDebugPrintf(                                              \
        GLOBUS_L_XIO_UDT_REF_DEBUG_TRACE,                                     \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_udt_ref_error_levels
{
    GLOBUS_L_XIO_UDT_REF_DEBUG_TRACE                = 1,
    GLOBUS_L_XIO_UDT_REF_DEBUG_INTERNAL_TRACE       = 2
};

typedef struct xio_l_udt_ref_server_handle_s
{
    globus_sockaddr_t                   addr;
    int                                 listener;
    int                                 port;
} xio_l_udt_ref_server_handle_t;

typedef struct xio_l_udt_ref_handle_s
{
    int                                 port;
    globus_sockaddr_t                   addr;
    int                                 sock;
} xio_l_udt_ref_handle_t;

typedef struct xio_l_udt_ref_attr_s
{
    int                                 mss;
    globus_bool_t                       sndsyn;
    globus_bool_t                       rcvsyn;
    int                                 fc;
    int                                 sndbuf;
    int                                 rcvbuf;
    int                                 udp_sndbuf;
    int                                 udp_rcvbuf;
    globus_bool_t                       rendezvous;
    int                                 sndtimeo;
    int                                 rcvtimeo;
    globus_bool_t                       reuseaddr;
    int                                 port;
    int                                 fd;
} xio_l_udt_ref_attr_t;

static
int
globus_l_xio_udt_ref_activate(void);

static
int
globus_l_xio_udt_ref_deactivate(void);

static
void
globus_l_xio_udt_attr_to_socket(
    xio_l_udt_ref_attr_t *              attr,
    int                                 sock);

GlobusXIODefineModule(udt_ref) =
{
    "globus_xio_udt_ref",
    globus_l_xio_udt_ref_activate,
    globus_l_xio_udt_ref_deactivate,
    NULL,
    NULL,
    &local_version
};


static  xio_l_udt_ref_attr_t            globus_l_xio_udt_ref_attr_default;

static
int
globus_l_xio_udt_ref_activate(void)
{
    int rc;
    GlobusXIOName(globus_l_xio_udt_ref_activate);

    GlobusDebugInit(GLOBUS_XIO_UDT_REF, TRACE);
    GlobusXIOUDTRefDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    GlobusXIORegisterDriver(udt_ref);
    GlobusXIOUDTRefDebugExit();

    globus_l_xio_udt_ref_attr_default.fd = -1;
    globus_l_xio_udt_ref_attr_default.mss = -1;
    globus_l_xio_udt_ref_attr_default.sndsyn = XIO_UDT_BOOL_UNDEF;
    globus_l_xio_udt_ref_attr_default.rcvsyn = XIO_UDT_BOOL_UNDEF;
    globus_l_xio_udt_ref_attr_default.fc = -1;
    globus_l_xio_udt_ref_attr_default.sndbuf = -1;
    globus_l_xio_udt_ref_attr_default.rcvbuf = -1;
    globus_l_xio_udt_ref_attr_default.udp_sndbuf = -1; 
    globus_l_xio_udt_ref_attr_default.udp_rcvbuf = -1;
    globus_l_xio_udt_ref_attr_default.rendezvous = XIO_UDT_BOOL_UNDEF;
    globus_l_xio_udt_ref_attr_default.sndtimeo = -1;
    globus_l_xio_udt_ref_attr_default.rcvtimeo = -1;
    globus_l_xio_udt_ref_attr_default.reuseaddr = XIO_UDT_BOOL_UNDEF;
    globus_l_xio_udt_ref_attr_default.port = 0;

    return GLOBUS_SUCCESS;

error_xio_system_activate:
    GlobusXIOUDTRefDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT_REF);
    return rc;
}


static
int
globus_l_xio_udt_ref_deactivate(void)
{   
    int rc;
    GlobusXIOName(globus_l_xio_udt_ref_deactivate);
    
    GlobusXIOUDTRefDebugEnter();
    GlobusXIOUnRegisterDriver(udt_ref);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    GlobusXIOUDTRefDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_UDT_REF);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusXIOUDTRefDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT_REF);
    return rc;
}

static
globus_result_t
globus_l_xio_udt_ref_attr_copy(
    void **                             dst,
    void *                              src)
{
    xio_l_udt_ref_attr_t *              src_attr;
    xio_l_udt_ref_attr_t *              dst_attr;

    src_attr = (xio_l_udt_ref_attr_t *) src;
    dst_attr = (xio_l_udt_ref_attr_t *) globus_calloc(1,
        sizeof(xio_l_udt_ref_attr_t));

    /* this should be fine for now */
    memcpy(dst_attr, src_attr, sizeof(xio_l_udt_ref_attr_t));

    *dst = dst_attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_attr_init(
    void **                             out_attr)
{
    xio_l_udt_ref_attr_t *              attr;

    globus_l_xio_udt_ref_attr_copy(
        (void **)&attr, (void *)&globus_l_xio_udt_ref_attr_default);

    *out_attr = attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_attr_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    xio_l_udt_ref_attr_t *              attr;

    attr = (xio_l_udt_ref_attr_t *) driver_specific_handle;

    switch(cmd)
    {
        case GLOBUS_XIO_UDT_MSS:
            attr->mss = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_SNDSYN:
            attr->sndsyn = va_arg(ap, globus_bool_t);
            break;

        case GLOBUS_XIO_UDT_RCVSYN:
            attr->rcvsyn = va_arg(ap, globus_bool_t);
            break;

        case GLOBUS_XIO_UDT_FC:
            attr->fc = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_SNDBUF:
            attr->sndbuf = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_RCVBUF:
            attr->rcvbuf = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_UDP_SNDBUF:
            attr->udp_sndbuf = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_UDP_RCVBUF:
            attr->udp_rcvbuf = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_LINGER:
            break;

        case GLOBUS_XIO_UDT_RENDEZVOUS:
            attr->rendezvous = va_arg(ap, globus_bool_t);
            break;

        case GLOBUS_XIO_UDT_SNDTIMEO:
            attr->sndtimeo = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_RCVTIMEO:
            attr->rcvtimeo = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_REUSEADDR:
            attr->reuseaddr = va_arg(ap, globus_bool_t);
            break;

        case GLOBUS_XIO_UDT_SET_LOCAL_PORT:
            attr->port = va_arg(ap, int);
            break;

        case GLOBUS_XIO_UDT_SET_FD:
            attr->fd = va_arg(ap, int);
            break;

        default:
            break;
    }

    return GLOBUS_SUCCESS;
}


static globus_xio_string_cntl_table_t  udt_ref_l_string_opts_table[] =
{
    {"mss", GLOBUS_XIO_UDT_MSS, globus_xio_string_cntl_int},
    {"sndsyn", GLOBUS_XIO_UDT_SNDSYN, globus_xio_string_cntl_bool},
    {"rcvsyn", GLOBUS_XIO_UDT_RCVSYN, globus_xio_string_cntl_bool},
    {"fc", GLOBUS_XIO_UDT_FC, globus_xio_string_cntl_int},
    {"sndbuf", GLOBUS_XIO_UDT_UDP_SNDBUF, globus_xio_string_cntl_int},
    {"rcvbuf", GLOBUS_XIO_UDT_UDP_RCVBUF, globus_xio_string_cntl_int},
    {"linger", GLOBUS_XIO_UDT_LINGER, globus_xio_string_cntl_int},
    {"rendezvous", GLOBUS_XIO_UDT_RENDEZVOUS, globus_xio_string_cntl_bool},
    {"sndtimeo", GLOBUS_XIO_UDT_SNDTIMEO, globus_xio_string_cntl_int},
    {"rcvtimeo", GLOBUS_XIO_UDT_RCVTIMEO, globus_xio_string_cntl_int},
    {"reuseaddr", GLOBUS_XIO_UDT_REUSEADDR, globus_xio_string_cntl_bool},
    {"port", GLOBUS_XIO_UDT_SET_LOCAL_PORT, globus_xio_string_cntl_int},
    {NULL, 0, NULL}
};


static
globus_result_t
globus_l_xio_udt_ref_attr_destroy(
    void *                              driver_attr)
{
    /* this is fine for now (no pointers in it) */
    if(driver_attr)
    {
        globus_free(driver_attr);
    }

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_udt_ref_bind(
    int                                 fd,
    struct sockaddr *                   addr,
    int                                 addr_len,
    int                                 min_port,
    int                                 max_port)
{
    int                                 port = 0;
    int                                 rc;
    globus_bool_t                       done;
    globus_sockaddr_t                   myaddr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udp_bind);

    if(min_port == -1)
    {
        port = 0;
        max_port = -1;
    }
    else
    {
        port = min_port;
    }

    done = GLOBUS_FALSE;
    do
    {
        GlobusLibcSockaddrCopy(myaddr, *addr, addr_len);
        GlobusLibcSockaddrSetPort(myaddr, port);

        rc = UDT::bind(
            fd,
            (struct sockaddr *) &myaddr,
            (unsigned int)GlobusLibcSockaddrLen(&myaddr));
        if(rc < 0)
        {
            if(++port > max_port)
            {
                result = GlobusXIOUdtError(
                    UDT::getlasterror().getErrorMessage());
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
globus_l_xio_udt_ref_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    int                                 min = 0;
    int                                 max = 0;
    char *                              tmp_cs;
    int                                 len;
    globus_xio_contact_t                my_contact_info;
    globus_result_t                     result;
    struct sockaddr_in                  my_addr;
    xio_l_udt_ref_server_handle_t *     server_handle;
    xio_l_udt_ref_attr_t *              attr;
    GlobusXIOName(globus_l_xio_udt_ref_server_init);

    attr = (xio_l_udt_ref_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_udt_ref_attr_default);

    server_handle = (xio_l_udt_ref_server_handle_t *)
        globus_calloc(1, sizeof(xio_l_udt_ref_server_handle_t));

    server_handle->listener = UDT::socket(AF_INET, SOCK_STREAM, 0);
    if(server_handle->listener < 0)
    {
        result = GlobusXIOUdtError("UDT::socket failed");
        goto error_socket;
    }

    server_handle->port = attr->port;
    globus_l_xio_udt_attr_to_socket(attr, server_handle->listener);

    my_addr.sin_family = AF_INET;
    if(contact_info->port != NULL)
    {
        min = atoi(contact_info->port);
        max = atoi(contact_info->port);
    }
    else
    {
        if(!globus_xio_get_env_pair("GLOBUS_UDP_PORT_RANGE", &min, &max))
        {
            min = -1;
            max = -1;
        }
    }
    my_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(my_addr.sin_zero), '\0', 8);

    result = globus_l_xio_udt_ref_bind(
        server_handle->listener, 
        (struct sockaddr *)&my_addr, sizeof(my_addr), min, max);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_bind;
    }

    if(UDT::listen(server_handle->listener, 10) < 0)
    {
        result = GlobusXIOUdtError("UDT::listen failed");
        goto error_listen;
    }
    len = sizeof(server_handle->addr);
    UDT::getsockname(server_handle->listener, (sockaddr *)&my_addr, &len);
    memcpy(&server_handle->addr, &my_addr, sizeof(my_addr));
    globus_libc_addr_to_contact_string(&server_handle->addr, 0, &tmp_cs);
    globus_xio_contact_parse(&my_contact_info, tmp_cs);

    globus_xio_driver_pass_server_init(op, &my_contact_info, server_handle);
    globus_xio_contact_destroy(&my_contact_info);
    globus_free(tmp_cs);

    return GLOBUS_SUCCESS;
error_listen:
error_bind:
    UDT::close(server_handle->listener);
error_socket:
    globus_free(server_handle);
    return result;
}

static
globus_result_t
globus_l_xio_udt_ref_server_destroy(
    void *                              driver_server)
{
    xio_l_udt_ref_server_handle_t *     server_handle;

    server_handle = (xio_l_udt_ref_server_handle_t *) driver_server;
    UDT::close(server_handle->listener);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_link_destroy(
    void *                              driver_link)
{
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_udt_attr_to_socket(
    xio_l_udt_ref_attr_t *              attr,
    int                                 sock)
{
    int                                 rc;

    if(attr->mss != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_MSS,
            &attr->mss,
            sizeof(attr->mss));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->sndsyn != XIO_UDT_BOOL_UNDEF)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_SNDSYN,
            &attr->sndsyn,
            sizeof(attr->sndsyn));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->rcvsyn != XIO_UDT_BOOL_UNDEF)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_RCVSYN,
            &attr->rcvsyn,
            sizeof(attr->rcvsyn));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->fc != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_FC,
            &attr->fc,
            sizeof(attr->fc));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->sndbuf != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_SNDBUF,
            &attr->sndbuf,
            sizeof(attr->sndbuf));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->rcvbuf != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_RCVBUF,
            &attr->rcvbuf,
            sizeof(attr->rcvbuf));
        if(rc != 0)
        {
           goto error;
        }
    }
    if(attr->udp_sndbuf != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDP_SNDBUF,
            &attr->udp_sndbuf,
            sizeof(attr->udp_sndbuf));
        if(rc != 0)
        {
           goto error;
        }
    }
    if(attr->udp_rcvbuf != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDP_RCVBUF,
            &attr->udp_rcvbuf,
            sizeof(attr->udp_rcvbuf));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->rendezvous != XIO_UDT_BOOL_UNDEF)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_RENDEZVOUS,
            &attr->rendezvous,
            sizeof(attr->rendezvous));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->sndtimeo != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_SNDTIMEO,
            &attr->sndtimeo,
            sizeof(attr->sndtimeo));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->rcvtimeo != -1)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_RCVTIMEO,
            &attr->rcvtimeo,
            sizeof(attr->rcvtimeo));
        if(rc != 0)
        {
            goto error;
        }
    }
    if(attr->reuseaddr != XIO_UDT_BOOL_UNDEF)
    {
        rc = UDT::setsockopt(sock, 0,
            UDT_REUSEADDR,
            &attr->reuseaddr,
            sizeof(attr->reuseaddr));
        if(rc != 0)
        {
            goto error;
        }
    }

    return;

error:

    return;
}

static
globus_result_t
globus_l_xio_udt_ref_accept(
    void *                              driver_server,
    void **                             out_link)
{
    globus_result_t                     result;
    int                                 addr_len = sizeof(struct sockaddr_in);
    xio_l_udt_ref_handle_t *            handle;
    xio_l_udt_ref_server_handle_t *     server;
    GlobusXIOName(globus_l_xio_udt_ref_accept);

    server = (xio_l_udt_ref_server_handle_t *) driver_server;

    handle = (xio_l_udt_ref_handle_t *)
        globus_calloc(1, sizeof(xio_l_udt_ref_handle_t));

    handle->sock = UDT::accept(
        server->listener, (sockaddr *)&handle->addr, &addr_len);
    if(handle->sock < 0)
    {
        result = GlobusXIOUdtError("UDT::accept failed");
        goto error_accept;
    }
    *out_link = handle;

    return GLOBUS_SUCCESS;
error_accept:
    globus_free(handle);
    return result;
}



static
globus_result_t
globus_l_xio_udt_ref_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    void **                             driver_handle)
{
    xio_l_udt_ref_attr_t *              attr;
    int                                 min;
    int                                 max;
    struct sockaddr_in                  my_addr;
    globus_addrinfo_t *                 addrinfo;
    globus_addrinfo_t                   addrinfo_hints;
    globus_result_t                     result;
    xio_l_udt_ref_handle_t *            handle;
    GlobusXIOName(globus_l_xio_udt_ref_open);

    attr = (xio_l_udt_ref_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_udt_ref_attr_default);

    if(driver_link == NULL)
    {
        handle = (xio_l_udt_ref_handle_t *)
            globus_calloc(1, sizeof(xio_l_udt_ref_handle_t));

        memset(&addrinfo_hints, 0, sizeof(globus_addrinfo_t));
        addrinfo_hints.ai_flags = 0;
        addrinfo_hints.ai_family = PF_INET;
        addrinfo_hints.ai_socktype = SOCK_DGRAM;
        addrinfo_hints.ai_protocol = 0;
        result = globus_libc_getaddrinfo(
            contact_info->host, contact_info->port, &addrinfo_hints, &addrinfo);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOUdtError("getaddrinfo failed");
            goto error_getaddr;
        }
        if(addrinfo == NULL)
        {
            result = GlobusXIOUdtError("no address found for contact");
            goto error_getaddr;
        }

        handle->sock = UDT::socket(AF_INET, SOCK_STREAM, 0);
        if(handle->sock <= 0)
        {
            result = GlobusXIOUdtError("UDT::socket failed");
            goto error_socket;
        }

        globus_l_xio_udt_attr_to_socket(attr, handle->sock);
        handle->port = attr->port;

        my_addr.sin_family = AF_INET;
        my_addr.sin_addr.s_addr = INADDR_ANY;
        memset(&(my_addr.sin_zero), '\0', 8);

        if(handle->port == 0)
        {
            if(!globus_xio_get_env_pair("GLOBUS_UDP_PORT_RANGE", &min, &max))
            {
                min = -1;
                max = -1;
            }
        }
        else
        {
            min = handle->port;
            max = handle->port;
        }

        if(attr->fd == -1)
        {
            result = globus_l_xio_udt_ref_bind(
                handle->sock,
                (struct sockaddr *)&my_addr,
                sizeof(my_addr),
                min, max);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_socket;
            }
        }
        else
        {
            /* UDT::setFD(handle->sock, attr->fd); */
        }
        if(UDT::connect(
            handle->sock, addrinfo->ai_addr, addrinfo->ai_addrlen))
        {
            result = GlobusXIOUdtError("UDT::connect failed");
            goto error_connect;
        }
        *driver_handle = handle;
    }
    else
    {
        *driver_handle = driver_link;
    }

    return GLOBUS_SUCCESS;
error_connect:
    UDT::close(handle->sock);
error_socket:
error_getaddr:
    globus_free(handle);

    return result;
}

static
globus_result_t
globus_l_xio_udt_ref_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    xio_l_udt_ref_handle_t *            handle;
    int                                 rc;
    GlobusXIOName(globus_l_xio_udt_ref_read);

    handle = (xio_l_udt_ref_handle_t *) driver_specific_handle;

    rc = (globus_size_t) UDT::recv(
        handle->sock, (char *)iovec[0].iov_base, iovec[0].iov_len, 0);
    if(rc == UDT::ERROR)
    {
        if(UDT::getlasterror().getErrorCode() == 2001) /* this seems to mean EOF */
        {
            result = GlobusXIOErrorEOF();
        }
        else
        {
            result = GlobusXIOUdtError(UDT::getlasterror().getErrorMessage());
        }
        goto error;
    }
    *nbytes = (globus_size_t) rc;

    return GLOBUS_SUCCESS;
error:
    *nbytes = 0;
    return result;
}

static
globus_result_t
globus_l_xio_udt_ref_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    xio_l_udt_ref_handle_t *            handle;
    GlobusXIOName(globus_l_xio_udt_ref_write);

    handle = (xio_l_udt_ref_handle_t *) driver_specific_handle;

    *nbytes = (globus_size_t) UDT::send(
        handle->sock, (char*)iovec[0].iov_base, iovec[0].iov_len, 0);
    if(*nbytes < 0)
    {
        result = GlobusXIOUdtError("UDT::send failed");
        goto error;
    }

    return GLOBUS_SUCCESS;
error:
    return result;
}

static
globus_result_t
globus_l_xio_udt_ref_close(
    void *                              driver_specific_handle,
    void *                              attr)
{
    xio_l_udt_ref_handle_t *            handle;
    GlobusXIOName(globus_l_xio_udt_ref_close);

    handle = (xio_l_udt_ref_handle_t *) driver_specific_handle;

    UDT::close(handle->sock);
    globus_free(handle);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_ref_init);

    GlobusXIOUDTRefDebugEnter();
    result = globus_xio_driver_init(&driver, "udt_ref", NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_driver_init", result);
        goto error_init;
    }
    globus_xio_driver_set_transport(
        driver,
        NULL,
        NULL,
        NULL,
        NULL,
        globus_l_xio_udt_ref_cntl);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_udt_ref_server_init,
        NULL,
        globus_l_xio_udt_ref_server_destroy,
        globus_l_xio_udt_ref_server_cntl,
        globus_l_xio_udt_ref_link_cntl,
        globus_l_xio_udt_ref_link_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_udt_ref_attr_init,
        globus_l_xio_udt_ref_attr_copy,
        globus_l_xio_udt_ref_attr_cntl,
        globus_l_xio_udt_ref_attr_destroy);
    globus_xio_wrapblock_init(
        driver,
        globus_l_xio_udt_ref_open,
        globus_l_xio_udt_ref_close,
        globus_l_xio_udt_ref_read,
        globus_l_xio_udt_ref_write,
        globus_l_xio_udt_ref_accept);
    *out_driver = driver;
    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIOUDTRefDebugExitWithError();
    return result;
}


static
void
globus_l_xio_udt_ref_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


GlobusXIODefineDriver(
    udt_ref,
    globus_l_xio_udt_ref_init,
    globus_l_xio_udt_ref_destroy);
