/*
 * Copyright 1999-2014 University of Chicago
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
#include "globus_xio_wrapblock.h"
#include "globus_xio_udt_ref.h"
#include "version.h"

#ifndef _WIN32
    #include <arpa/inet.h>
#endif /* _WIN32 */

#ifdef HAVE_UDT_H
#include <udt.h>
#elif HAVE_UDT_UDT_H
#include <udt/udt.h>
#endif

#ifdef UDT_HAS_BIND2
#define G_UDT_BIND UDT::bind2
#else
#define G_UDT_BIND UDT::bind
#endif

extern "C"
{
#include "ice.h"
}

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

GlobusDebugDefine(GLOBUS_XIO_UDT);
GlobusXIODeclareDriver(udt);

#define GlobusXIOUDTRefDebugPrintf(level, message)                           \
    GlobusDebugPrintf(GLOBUS_XIO_UDT, level, message)

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
    globus_bool_t                       cancel_accept;
    globus_mutex_t                      lock;
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
    int                                 ice_controlling;
    globus_bool_t                       ice;
    struct icedata                      ice_data;
    globus_sockaddr_t                   ice_local_addr;
    globus_socklen_t                    ice_local_addr_len;
    globus_sockaddr_t                   ice_remote_addr;
    globus_socklen_t                    ice_remote_addr_len;
} xio_l_udt_ref_attr_t;

typedef struct globus_l_xio_udt_bounce_s
{
    globus_xio_operation_t              op;
    xio_l_udt_ref_server_handle_t *     server;
} globus_l_xio_udt_bounce_t;

extern "C" {
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

GlobusXIODefineModule(udt) =
{
    "globus_xio_udt",
    globus_l_xio_udt_ref_activate,
    globus_l_xio_udt_ref_deactivate,
    NULL,
    NULL,
    &local_version
};
}


static  xio_l_udt_ref_attr_t            globus_l_xio_udt_ref_attr_default;

static
int
globus_l_xio_udt_ref_activate(void)
{
    int rc;
    GlobusXIOName(globus_l_xio_udt_ref_activate);

    GlobusDebugInit(GLOBUS_XIO_UDT, TRACE);
    GlobusXIOUDTRefDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    GlobusXIORegisterDriver(udt);
    
    memset(&globus_l_xio_udt_ref_attr_default, 0, sizeof(xio_l_udt_ref_attr_t));
    
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

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;

error_xio_system_activate:
    GlobusXIOUDTRefDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return rc;
}


static
int
globus_l_xio_udt_ref_deactivate(void)
{   
    int rc;
    GlobusXIOName(globus_l_xio_udt_ref_deactivate);
    
    GlobusXIOUDTRefDebugEnter();
    GlobusXIOUnRegisterDriver(udt);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    GlobusXIOUDTRefDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusXIOUDTRefDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
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
    GlobusXIOName(globus_l_xio_udt_ref_attr_copy);
    GlobusXIOUDTRefDebugEnter();

    src_attr = (xio_l_udt_ref_attr_t *) src;
    dst_attr = (xio_l_udt_ref_attr_t *) globus_calloc(1,
        sizeof(xio_l_udt_ref_attr_t));

    /* this should be fine for now */
    memcpy(dst_attr, src_attr, sizeof(xio_l_udt_ref_attr_t));

    *dst = dst_attr;

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_attr_init(
    void **                             out_attr)
{
    xio_l_udt_ref_attr_t *              attr;
    GlobusXIOName(globus_l_xio_udt_ref_attr_init);
    GlobusXIOUDTRefDebugEnter();

    globus_l_xio_udt_ref_attr_copy(
        (void **)&attr, (void *)&globus_l_xio_udt_ref_attr_default);

    *out_attr = attr;

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}
/* stun.stunprotocol.org */
#define DEFAULTSTUNSERVER "107.23.150.92"
#define DEFAULTSTUNPORT 3478


static
globus_result_t
globus_l_xio_udt_ref_attr_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    xio_l_udt_ref_attr_t *              attr;
    char **                             out_string;
    globus_result_t                     result;
    int                                 rc;

    GlobusXIOName(globus_l_xio_udt_ref_attr_cntl);
    GlobusXIOUDTRefDebugEnter();
    
    attr = (xio_l_udt_ref_attr_t *) driver_specific_handle;

    switch(cmd)
    {
        case GLOBUS_XIO_UDT_GET_LOCAL_CANDIDATES:
          {
            char *                      stunserver;
            char *                      stunhost;
            unsigned int                stunport;
            
            attr->ice_controlling = va_arg(ap, int);
            stunserver = va_arg(ap, char *);
            out_string = va_arg(ap, char **);
            
            ice_lib_init();
            
            if(stunserver)
            {
                char *                  ptr;
                
                stunhost = strdup(stunserver);
                ptr = strchr(stunhost, ':');
                if(ptr)
                {
                    *ptr = 0;
                    ptr++;
                    stunport = atoi(ptr);
                }
                else
                {
                    stunport = DEFAULTSTUNPORT;
                }
            }
            else
            {
                stunhost = strdup(DEFAULTSTUNSERVER);
                stunport = DEFAULTSTUNPORT;
            }
                    
            rc = ice_init(
                &attr->ice_data, 
                (const char *) stunhost,
                stunport,
                attr->ice_controlling);
            if(rc != ICE_SUCCESS)
            {
                result = GlobusXIOUdtError("ICE init failed.");
                goto error;
            }
            globus_free(stunhost);
            
            *out_string = (char *) globus_calloc(1, LOCAL_DATA_SIZE);
            
            rc = ice_get_local_data(
                &attr->ice_data,
                *out_string,
                LOCAL_DATA_SIZE);
            if(rc != ICE_SUCCESS)
            {
                globus_free(*out_string);
                *out_string = NULL;
                
                result = GlobusXIOUdtError("ICE failed getting local data.");
                goto error;
            }
          }
            break;

        case GLOBUS_XIO_UDT_SET_REMOTE_CANDIDATES:
            {
                char *                  ice_args;
                char **                 ice_argv;
                int                     ice_argc;
                int                     status;
                socklen_t               local_addrlen;
                socklen_t               remote_addrlen;
                                       
                ice_args = va_arg(ap, char *);
                
                ice_argv = ice_parse_args(ice_args, &ice_argc);
    
                status = ice_negotiate(&attr->ice_data, ice_argc, ice_argv);
                if(status != ICE_SUCCESS)
                {
                    /* possibly due to first-time-on-network delays, 
                     * crude retry */
                    status = ice_negotiate(&attr->ice_data, ice_argc, ice_argv);
                }
                if(status != ICE_SUCCESS)
                {
                    result = GlobusXIOUdtError("ICE negotiation failed.");
                    goto error;
                }
    
                local_addrlen = sizeof(attr->ice_local_addr);
                remote_addrlen = sizeof(attr->ice_remote_addr);
                status = ice_get_negotiated_addrs(&attr->ice_data,
                    (struct sockaddr *)&attr->ice_local_addr, &local_addrlen,
                    (struct sockaddr *)&attr->ice_remote_addr, &remote_addrlen);
                if(status != ICE_SUCCESS)
                {
                    result = GlobusXIOUdtError("ICE failed getting negotiated addrs.");
                    goto error;
                }
                attr->ice = GLOBUS_TRUE;
            }
            break;
            
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

        case GLOBUS_XIO_GET_STRING_OPTIONS:
            {
                out_string = va_arg(ap, char **);
                size_t string_opts_len = 1;
                if (attr->mss != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "mss=%d;", attr->mss);
                }
                if (attr->sndsyn != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "sndsyn=%s;", attr->sndsyn ? "true" : "false");
                }
                if (attr->rcvsyn != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "rcvsyn=%s;", attr->rcvsyn ? "true" : "false");
                }
                if (attr->fc != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "fc=%d;", attr->fc);
                }
                if (attr->sndbuf != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "sndbuf=%d;", attr->sndbuf);
                }
                if (attr->rcvbuf != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "rcvbuf=%d;", attr->rcvbuf);
                }
                if (attr->rendezvous != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "rendezvous=%s;",
                                attr->rendezvous ? "true" : "false");
                }
                if (attr->sndtimeo != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "sndtimeo=%d;", attr->sndtimeo);
                }
                if (attr->rcvtimeo != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "rcvtimeo=%d;", attr->rcvtimeo);
                }
                if (attr->reuseaddr != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "reuseaddr=%s;",
                                attr->reuseaddr ? "true" : "false");
                }
                if (attr->port != -1)
                {
                    string_opts_len += snprintf(
                        NULL, 0, "port=%d;", attr->port);
                }

                *out_string = reinterpret_cast<char *>(malloc(string_opts_len));
                string_opts_len = 0;

                if (attr->mss != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "mss=%d;", attr->mss);
                }
                if (attr->sndsyn != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "sndsyn=%s;", attr->sndsyn ? "true" : "false");
                }
                if (attr->rcvsyn != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "rcvsyn=%s;", attr->rcvsyn ? "true" : "false");
                }
                if (attr->fc != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "fc=%d;", attr->fc);
                }
                if (attr->sndbuf != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "sndbuf=%d;", attr->sndbuf);
                }
                if (attr->rcvbuf != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "rcvbuf=%d;", attr->rcvbuf);
                }
                if (attr->rendezvous != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "rendezvous=%s;",
                                attr->rendezvous ? "true" : "false");
                }
                if (attr->sndtimeo != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "sndtimeo=%d;", attr->sndtimeo);
                }
                if (attr->rcvtimeo != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "rcvtimeo=%d;", attr->rcvtimeo);
                }
                if (attr->reuseaddr != XIO_UDT_BOOL_UNDEF)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "reuseaddr=%s;",
                                attr->reuseaddr ? "true" : "false");
                }
                if (attr->port != -1)
                {
                    string_opts_len += sprintf(
                        (*out_string) + string_opts_len,
                        "port=%d;", attr->port);
                }
            }
            break;
        default:
            break;
    }

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOUDTRefDebugExitWithError();
    return result;

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
    GlobusXIOName(globus_l_xio_udt_ref_attr_destroy);
    GlobusXIOUDTRefDebugEnter();
    /* this is fine for now (no pointers in it) */
    if(driver_attr)
    {
        globus_free(driver_attr);
    }

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_udt_ref_cntl);
    GlobusXIOUDTRefDebugEnter();

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_udt_ref_bind(
    int                                 fd,
    struct sockaddr *                   addr,
    int                                 addr_len,
    int                                 min_port,
    int                                 max_port,
    xio_l_udt_ref_attr_t *              attr)
{
    int                                 port = 0;
    int                                 rc;
    globus_bool_t                       done;
    globus_sockaddr_t                   myaddr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_ref_bind);
    GlobusXIOUDTRefDebugEnter();

    if(min_port == -1)
    {
        port = 0;
        max_port = -1;
    }
    else
    {
        port = min_port;
    }

    if(attr->ice)
    {
        int                             ice_sock;
        
        attr->ice = 0;
        rc = ice_get_negotiated_sock(&attr->ice_data, &ice_sock);
        if(rc < 0)
        {
            result = GlobusXIOUdtError("Could not get negotiated socket.");
            goto error_bind;
        }
        
        ice_destroy(&attr->ice_data);

        rc = G_UDT_BIND(fd, ice_sock);
        if(rc < 0)
        {
            result = GlobusXIOUdtError(
                UDT::getlasterror().getErrorMessage());
            goto error_bind;
        }
        GlobusLibcSockaddrCopy(*addr, attr->ice_local_addr, addr_len);
    }
    else
    {
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
    }

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;

error_bind:
    GlobusXIOUDTRefDebugExitWithError();
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
    GlobusXIOUDTRefDebugEnter();

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
        (struct sockaddr *)&my_addr, sizeof(my_addr), min, max, attr);
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

    globus_mutex_init(&server_handle->lock, GLOBUS_NULL);

    globus_xio_driver_pass_server_init(op, &my_contact_info, server_handle);
    globus_xio_contact_destroy(&my_contact_info);
    globus_free(tmp_cs);

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
error_listen:
error_bind:
    UDT::close(server_handle->listener);
error_socket:
    globus_free(server_handle);
    GlobusXIOUDTRefDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_xio_udt_ref_server_destroy(
    void *                              driver_server)
{
    xio_l_udt_ref_server_handle_t *     server_handle;
    GlobusXIOName(globus_l_xio_udt_ref_server_destroy);
    GlobusXIOUDTRefDebugEnter();

    server_handle = (xio_l_udt_ref_server_handle_t *) driver_server;
    UDT::close(server_handle->listener);
    globus_mutex_destroy(&server_handle->lock);
    globus_free(server_handle);
    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_udt_ref_server_cntl);
    GlobusXIOUDTRefDebugEnter();

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_udt_ref_link_cntl);
    GlobusXIOUDTRefDebugEnter();

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_udt_ref_link_destroy(
    void *                              driver_link)
{
    GlobusXIOName(globus_l_xio_udt_ref_link_destroy);
    GlobusXIOUDTRefDebugEnter();

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_udt_attr_to_socket(
    xio_l_udt_ref_attr_t *              attr,
    int                                 sock)
{
    int                                 rc;
    GlobusXIOName(globus_l_xio_udt_attr_to_socket);
    GlobusXIOUDTRefDebugEnter();

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

    /* XXX force this to be false so THAT IT WILL WORK! */
    attr->reuseaddr = 0;
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

    GlobusXIOUDTRefDebugExit();
    return;

error:

    GlobusXIOUDTRefDebugExitWithError();
    return;
}


static
void
globus_l_xio_udt_accept_cancel(
    globus_xio_operation_t              op,
    void *                              user_arg,
    globus_xio_error_type_t             reason)
{
    xio_l_udt_ref_server_handle_t *     server;
    
    server = (xio_l_udt_ref_server_handle_t *) user_arg;
    if(server)
    {
        globus_mutex_lock(&server->lock);
        server->cancel_accept = GLOBUS_TRUE;
        globus_mutex_unlock(&server->lock);
    }
}
  

static
void
globus_l_xio_udt_accept_kickout(
    void *                              user_arg)
{
    globus_result_t                     result;
    int                                 addr_len = sizeof(struct sockaddr_in);
    xio_l_udt_ref_handle_t *            handle;
    xio_l_udt_ref_server_handle_t *     server;
    UDT::UDSET                          readfds;
    struct timeval                      tv;
    int                                 rc;
    globus_bool_t                       waiting = GLOBUS_TRUE;
    globus_l_xio_udt_bounce_t *         bounce;
    globus_bool_t                       cancel;
    GlobusXIOName(globus_l_xio_udt_accept_kickout);
    GlobusXIOUDTRefDebugEnter();
    
    bounce = (globus_l_xio_udt_bounce_t *) user_arg;
    server = bounce->server;

    handle = (xio_l_udt_ref_handle_t *)
        globus_calloc(1, sizeof(xio_l_udt_ref_handle_t));

    globus_thread_blocking_will_block();

    if(globus_xio_operation_enable_cancel(bounce->op, 
        globus_l_xio_udt_accept_cancel, server))
    {
        result = GlobusXIOUdtError("UDT::accept canceled");
        goto error_accept;
    }
        
    UD_ZERO(&readfds);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    
    while(waiting)
    {
        UD_SET(server->listener, &readfds);
        rc = UDT::select(1, &readfds, NULL, NULL, &tv);
        if(rc < 0)
        {
            result = GlobusXIOUdtError("UDT::select failed");
            goto error_accept;
        }
        globus_mutex_lock(&server->lock);
        cancel = server->cancel_accept;
        globus_mutex_unlock(&server->lock);
        if(cancel)
        {
            result = GlobusXIOUdtError("UDT::accept canceled");
            goto error_accept;
        }
        
        if(rc > 0)
        {
            waiting = GLOBUS_FALSE;
        }
    }

    handle->sock = UDT::accept(
        server->listener, (sockaddr *)&handle->addr, &addr_len);
    if(handle->sock < 0)
    {
        result = GlobusXIOUdtError("UDT::accept failed");
        goto error_accept;
    }
    
    globus_xio_driver_finished_accept(bounce->op, handle, GLOBUS_SUCCESS);

    globus_free(bounce);
    return;
    
error_accept:
    globus_xio_driver_finished_accept(bounce->op, NULL, result);
    globus_free(handle);
    globus_free(bounce);
    GlobusXIOUDTRefDebugExitWithError();
    return;    
}
    
    
static
globus_result_t
globus_l_xio_udt_ref_accept(
    void *                              driver_server,
    globus_xio_operation_t              op)
{
    xio_l_udt_ref_server_handle_t *     server;
    globus_l_xio_udt_bounce_t *         bounce;
    GlobusXIOName(globus_l_xio_udt_ref_accept);
    GlobusXIOUDTRefDebugEnter();

    server = (xio_l_udt_ref_server_handle_t *) driver_server;

    bounce = (globus_l_xio_udt_bounce_t *)
        globus_calloc(1, sizeof(globus_l_xio_udt_bounce_t));
    bounce->op = op;
    bounce->server = server;

    globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_xio_udt_accept_kickout,
        bounce);    

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
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
    struct sockaddr *                   addr;
    size_t                              addrlen;

    GlobusXIOName(globus_l_xio_udt_ref_open);
    GlobusXIOUDTRefDebugEnter();

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
        
        if(!attr->ice)
        {
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
            addr = addrinfo->ai_addr;
            addrlen = addrinfo->ai_addrlen;
        }
        else
        {
            addr = (struct sockaddr *) &attr->ice_remote_addr;
            addrlen = GlobusLibcSockaddrLen(&attr->ice_remote_addr);
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
                min, max, attr);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_socket;
            }
        }
        else
        {
            /* UDT::setFD(handle->sock, attr->fd); */
        }
        if(UDT::connect(handle->sock, addr, addrlen))
        {
            result = GlobusXIOUdtError(UDT::getlasterror().getErrorMessage());
            goto error_connect;
        }
        *driver_handle = handle;
    }
    else
    {
        *driver_handle = driver_link;
    }

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
error_connect:
    UDT::close(handle->sock);
error_socket:
error_getaddr:
    globus_free(handle);

    GlobusXIOUDTRefDebugExitWithError();
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
    GlobusXIOUDTRefDebugEnter();

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

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
error:
    *nbytes = 0;
    GlobusXIOUDTRefDebugExitWithError();
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
    GlobusXIOUDTRefDebugEnter();

    handle = (xio_l_udt_ref_handle_t *) driver_specific_handle;

    *nbytes = (globus_size_t) UDT::send(
        handle->sock, (char*)iovec[0].iov_base, iovec[0].iov_len, 0);
    if(*nbytes < 0)
    {
        result = GlobusXIOUdtError("UDT::send failed");
        goto error;
    }

    GlobusXIOUDTRefDebugExit();
    return GLOBUS_SUCCESS;
error:
    GlobusXIOUDTRefDebugExitWithError();
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
    GlobusXIOUDTRefDebugEnter();

    handle = (xio_l_udt_ref_handle_t *) driver_specific_handle;

    UDT::close(handle->sock);
    globus_free(handle);

    GlobusXIOUDTRefDebugExit();
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

    result = globus_xio_driver_init(&driver, "udt", NULL);
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
        globus_l_xio_udt_ref_accept,
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
        NULL);
    globus_xio_driver_string_cntl_set_table(
        driver,
        udt_ref_l_string_opts_table);

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
    GlobusXIOName(globus_l_xio_udt_ref_destroy);
    GlobusXIOUDTRefDebugEnter();

    globus_xio_driver_destroy(driver);

    GlobusXIOUDTRefDebugExit();
    return;    
}


GlobusXIODefineDriver(
    udt,
    globus_l_xio_udt_ref_init,
    globus_l_xio_udt_ref_destroy);
