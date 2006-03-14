#include "globus_xio_driver.h"
#include "globus_xio_wrapblock.h"
#include "globus_xio_quanta_rbudp.h"
#include "globus_xio_tcp_driver.h"
#include "version.h"

#include "QUANTA/QUANTAnet_rbudpReceiver_c.hxx"
#include "QUANTA/QUANTAnet_rbudpSender_c.hxx"

#define QUANTA_RBUDP_IPSIZE             256

#define GlobusXIORbudpError(_r) globus_error_put(GlobusXIORbudpErrorObj(_r))

#define GlobusXIORbudpErrorObj(_reason)                                     \
    globus_error_construct_error(                                           \
        GLOBUS_XIO_MODULE,                                                  \
        GLOBUS_NULL,                                                        \
        1,                                                                  \
        __FILE__,                                                           \
        _xio_name,                                                          \
        __LINE__,                                                           \
        _XIOSL(_reason))                                

GlobusDebugDefine(GLOBUS_XIO_QUANTA_RBUDP);
GlobusXIODeclareDriver(quanta_rbudp);

#define GlobusXIORBUDPRefDebugPrintf(level, message)                        \
    GlobusDebugPrintf(GLOBUS_XIO_QUANTA_RBUDP, level, message)

#define GlobusXIORBUDPRefDebugEnter()                                       \
    GlobusXIORBUDPRefDebugPrintf(                                           \
        GLOBUS_L_XIO_QUANTA_RBUDP_DEBUG_TRACE,                              \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIORBUDPRefDebugExit()                                        \
    GlobusXIORBUDPRefDebugPrintf(                                           \
        GLOBUS_L_XIO_QUANTA_RBUDP_DEBUG_TRACE,                              \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIORBUDPRefDebugExitWithError()                               \
    GlobusXIORBUDPRefDebugPrintf(                                           \
        GLOBUS_L_XIO_QUANTA_RBUDP_DEBUG_TRACE,                              \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_quanta_rbudp_error_levels
{
    GLOBUS_L_XIO_QUANTA_RBUDP_DEBUG_TRACE                = 1,
    GLOBUS_L_XIO_QUANTA_RBUDP_DEBUG_INTERNAL_TRACE       = 2
};

typedef struct globus_l_xio_quanta_rbudp_handle_s
{
    int                                 flags;
    char *                              remote_ip;
    int                                 my_port;
    int                                 remote_port;
    int32_t                             port_buf;
    globus_xio_operation_t              op;
    QUANTAnet_rbudpSender_c *           sender;
    QUANTAnet_rbudpReceiver_c *         receiver;
    int                                 send_rate;
    globus_xio_handle_t                 tcp_handle;
} globus_l_xio_quanta_rbudp_handle_t;

typedef struct globus_l_xio_quanta_rbudp_server_s
{
    char *                              cs;
    globus_xio_operation_t              op;
    globus_xio_server_t                 tcp_server;
} globus_l_xio_quanta_rbudp_server_t;

typedef struct globus_l_xio_quanta_rbudp_attr_s
{
    int                                 flags;
    int                                 send_rate;
    int                                 my_port;
} globus_l_xio_quanta_rbudp_attr_t;

globus_l_xio_quanta_rbudp_attr_t        globus_l_xio_quanta_rbudp_default_attr;

static
int
globus_l_xio_quanta_rbudp_activate(void);

static
int
globus_l_xio_quanta_rbudp_deactivate(void);

static globus_xio_driver_t              globus_l_xio_quanta_rbudp_driver;
static globus_xio_stack_t               globus_l_xio_quanta_rbudp_stack;

GlobusXIODefineModule(quanta_rbudp) =
{
    "globus_xio_quanta_rbudp",
    globus_l_xio_quanta_rbudp_activate,
    globus_l_xio_quanta_rbudp_deactivate,
    NULL,
    NULL,
    &local_version
};


static
int
globus_l_xio_quanta_rbudp_activate(void)
{
    globus_result_t                     result;
    char *                              env_str;
    int                                 rc;
    int                                 sc;
    int                                 sr;
    GlobusXIOName(globus_l_xio_quanta_rbudp_activate);

    GlobusDebugInit(GLOBUS_XIO_QUANTA_RBUDP, TRACE);
    GlobusXIORBUDPRefDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    GlobusXIORegisterDriver(quanta_rbudp);

    result = globus_xio_driver_load("tcp", &globus_l_xio_quanta_rbudp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        rc = -1;
        goto error_xio_deactivate;
    }
    globus_xio_stack_init(&globus_l_xio_quanta_rbudp_stack, NULL);
    result = globus_xio_stack_push_driver(
        globus_l_xio_quanta_rbudp_stack, globus_l_xio_quanta_rbudp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        rc = -1;
        goto error_xio_deactivate;
    }

    globus_l_xio_quanta_rbudp_default_attr.flags = O_WRONLY;
    globus_l_xio_quanta_rbudp_default_attr.send_rate = 600000;
    env_str = globus_libc_getenv("GLOBUS_XIO_QUANTA_RBUDP_SEND_RATE");
    if(env_str != NULL)
    {
        sc = sscanf(env_str, "%d", &sr);
        if(sc == 1)
        {
            globus_l_xio_quanta_rbudp_default_attr.send_rate = sr;
        }
    }
    globus_l_xio_quanta_rbudp_default_attr.my_port = 50500;
    env_str = globus_libc_getenv("GLOBUS_XIO_QUANTA_RBUDP_PORT");
    if(env_str != NULL)
    {
        sc = sscanf(env_str, "%d", &sr);
        if(sc == 1)
        {
            globus_l_xio_quanta_rbudp_default_attr.my_port = sr;
        }
    }

    GlobusXIORBUDPRefDebugExit();
    return GLOBUS_SUCCESS;
error_xio_deactivate:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
error_xio_system_activate:
    GlobusXIORBUDPRefDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_QUANTA_RBUDP);
    return rc;
}

static
int
globus_l_xio_quanta_rbudp_deactivate(void)
{   
    int rc;
    GlobusXIOName(globus_l_xio_quanta_rbudp_deactivate);
    
    GlobusXIORBUDPRefDebugEnter();
    GlobusXIOUnRegisterDriver(quanta_rbudp);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    GlobusXIORBUDPRefDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_QUANTA_RBUDP);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusXIORBUDPRefDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_QUANTA_RBUDP);
    return rc;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_init(
    void **                             out_attr)
{
    globus_l_xio_quanta_rbudp_attr_t *  attr;
    attr = (globus_l_xio_quanta_rbudp_attr_t *)
        globus_calloc(1, sizeof(globus_l_xio_quanta_rbudp_handle_t));
    *out_attr = attr;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_copy(
    void **                             dst,
    void *                              src)
{
    *dst = globus_calloc(1, sizeof(globus_l_xio_quanta_rbudp_handle_t));
    memcpy(*dst, src, sizeof(globus_l_xio_quanta_rbudp_handle_t));
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_quanta_rbudp_attr_t *  attr;

    attr = (globus_l_xio_quanta_rbudp_attr_t *) driver_specific_handle;

    switch(cmd)
    {
        case XIO_QUANTA_RBUDP_RDONLY:
        case XIO_QUANTA_RBUDP_WRONLY:
            attr->flags = cmd;
            break;

        default:
            break;
    }

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_link_destroy(
    void *                              driver_link)
{
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_quanta_rbudp_open_init(
    globus_l_xio_quanta_rbudp_handle_t *    handle)
{
    char *                              tmp_str;
    globus_xio_system_socket_t          system_handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_quanta_rbudp_open_init);

    GlobusXIORBUDPRefDebugEnter();
    globus_thread_blocking_will_block();

    result = globus_xio_handle_cntl(
        handle->tcp_handle,
        globus_l_xio_quanta_rbudp_driver,
        GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,
        &handle->remote_ip);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    tmp_str = strchr(handle->remote_ip, ':');
    if(tmp_str == NULL)
    {
        result = GlobusXIORbudpError("no : in contact string");
        goto error;
    }
    *tmp_str = '\0';

    result = globus_xio_handle_cntl(
        handle->tcp_handle,
        globus_l_xio_quanta_rbudp_driver,
        GLOBUS_XIO_TCP_GET_HANDLE,
        &system_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    if(handle->flags | XIO_QUANTA_RBUDP_RDONLY)
    {
        handle->receiver = 
            new QUANTAnet_rbudpReceiver_c(system_handle, handle->remote_port);
        handle->receiver->init(handle->remote_ip);
    }
    else
    {
        handle->sender =
            new QUANTAnet_rbudpSender_c(system_handle, handle->remote_port);
        handle->sender->init(handle->remote_ip);
    }

    globus_xio_driver_finished_open(handle, handle->op, GLOBUS_SUCCESS);
    GlobusXIORBUDPRefDebugExit();
    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
globus_result_t
globus_l_xio_quanta_rbudp_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    globus_xio_contact_t                my_contact_info;
    globus_result_t                     result;
    globus_l_xio_quanta_rbudp_server_t * server_handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_server_init);

    GlobusXIORBUDPRefDebugEnter();
    server_handle = (globus_l_xio_quanta_rbudp_server_t *)
        globus_calloc(1, sizeof(globus_l_xio_quanta_rbudp_server_t));

    result = globus_xio_server_create(
        &server_handle->tcp_server,
        NULL,
        globus_l_xio_quanta_rbudp_stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_xio_server_get_contact_string(
        server_handle->tcp_server,
        &server_handle->cs);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_close;
    }
    result = globus_xio_contact_parse(&my_contact_info, server_handle->cs);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_close;
    }
    result = globus_xio_driver_pass_server_init(
        op, &my_contact_info, server_handle);
    globus_xio_contact_destroy(&my_contact_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_close;
    }
    GlobusXIORBUDPRefDebugExit();
    return GLOBUS_SUCCESS;
error_close:
    globus_xio_server_close(server_handle->tcp_server);
error:
    GlobusXIORBUDPRefDebugExitWithError();
    return result;
}

static
void
globus_l_xio_quanta_rbudp_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 accepted_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    globus_l_xio_quanta_rbudp_server_t *    server_handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_accept_cb);

    GlobusXIORBUDPRefDebugEnter();
    server_handle = (globus_l_xio_quanta_rbudp_server_t *)user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    handle = (globus_l_xio_quanta_rbudp_handle_t *)
        globus_calloc(1, sizeof(globus_l_xio_quanta_rbudp_handle_t));
    handle->tcp_handle = accepted_handle;

    globus_xio_driver_finished_accept(
        server_handle->op, handle, GLOBUS_SUCCESS);
    GlobusXIORBUDPRefDebugExit();
    return;

error:
    globus_xio_driver_finished_accept(server_handle->op, NULL, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
globus_result_t
globus_l_xio_quanta_rbudp_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     result;
    globus_l_xio_quanta_rbudp_server_t * server_handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_accept);

    GlobusXIORBUDPRefDebugEnter();
    server_handle = (globus_l_xio_quanta_rbudp_server_t *)driver_server;
    server_handle->op = accept_op;

    result = globus_xio_server_register_accept(
        server_handle->tcp_server,
        globus_l_xio_quanta_rbudp_accept_cb,
        server_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusXIORBUDPRefDebugExit();
    return GLOBUS_SUCCESS;
error:
    GlobusXIORBUDPRefDebugExitWithError();
    return result;
}

static
void
globus_l_xio_quanta_rbudp_client_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_client_read_cb);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    handle->remote_port = (int) htonl(handle->port_buf);
    /* we can now open */
    globus_l_xio_quanta_rbudp_open_init(handle);

    GlobusXIORBUDPRefDebugExit();
    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
void
globus_l_xio_quanta_rbudp_client_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_client_write_cb);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    /* now post read for the server port */
    result = globus_xio_register_read(
        handle->tcp_handle,
        (globus_byte_t *)&handle->port_buf,
        sizeof(handle->port_buf),
        sizeof(handle->port_buf),
        NULL,
        globus_l_xio_quanta_rbudp_client_read_cb,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    GlobusXIORBUDPRefDebugExit();
    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
void
globus_l_xio_quanta_rbudp_client_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_client_open_cb);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    /* now exchange contact info */
    handle->port_buf = htonl(handle->my_port);
    result = globus_xio_register_write(
        handle->tcp_handle,
        (globus_byte_t *)&handle->port_buf,
        sizeof(handle->port_buf),
        sizeof(handle->port_buf),
        NULL,
        globus_l_xio_quanta_rbudp_client_write_cb,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    GlobusXIORBUDPRefDebugExit();
    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
void
globus_l_xio_quanta_rbudp_server_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_server_write_cb);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    GlobusXIORBUDPRefDebugExit();
    globus_l_xio_quanta_rbudp_open_init(handle);

    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
void
globus_l_xio_quanta_rbudp_server_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_server_read_cb);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    handle->remote_port = ntohl(handle->port_buf);
    handle->port_buf = htonl(handle->my_port);
    result = globus_xio_register_write(
        handle->tcp_handle,
        (globus_byte_t *)&handle->port_buf,
        sizeof(handle->port_buf),
        sizeof(handle->port_buf),
        NULL,
        globus_l_xio_quanta_rbudp_server_write_cb,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusXIORBUDPRefDebugExit();
    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
void
globus_l_xio_quanta_rbudp_server_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_server_open_cb);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_register_read(
        handle->tcp_handle,
        (globus_byte_t *)&handle->port_buf,
        sizeof(handle->port_buf),
        sizeof(handle->port_buf),
        NULL,
        globus_l_xio_quanta_rbudp_server_read_cb,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    GlobusXIORBUDPRefDebugExit();
    return;
error:
    globus_xio_driver_finished_open(handle, handle->op, result);
    GlobusXIORBUDPRefDebugExitWithError();
}

static
globus_result_t
globus_l_xio_quanta_rbudp_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    globus_result_t                     result;
    globus_l_xio_quanta_rbudp_attr_t *      attr;
    GlobusXIOName(globus_l_xio_quanta_rbudp_open);

    GlobusXIORBUDPRefDebugEnter();
    attr = (globus_l_xio_quanta_rbudp_attr_t *) driver_attr;
    if(attr == NULL)
    {
        attr = &globus_l_xio_quanta_rbudp_default_attr;
    }

    if(driver_link != NULL)
    {
        handle = (globus_l_xio_quanta_rbudp_handle_t *) driver_link;

        handle->op = op;
        handle->send_rate = attr->send_rate;
        handle->flags = attr->flags;
        handle->my_port = attr->my_port;
        result = globus_xio_register_open(
                handle->tcp_handle,
                NULL,
                NULL,
                globus_l_xio_quanta_rbudp_server_open_cb,
                handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        handle = (globus_l_xio_quanta_rbudp_handle_t *)
            globus_calloc(1, sizeof(globus_l_xio_quanta_rbudp_handle_t));

        result = globus_xio_handle_create(
            &handle->tcp_handle, globus_l_xio_quanta_rbudp_stack);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        handle->op = op;
        handle->send_rate = attr->send_rate;
        handle->flags = attr->flags;
        handle->my_port = attr->my_port;
        result = globus_xio_register_open(
                handle->tcp_handle,
                contact_info->unparsed,
                NULL,
                globus_l_xio_quanta_rbudp_client_open_cb,
                handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    GlobusXIORBUDPRefDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIORBUDPRefDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_size_t *                     nbytes)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_write);

    GlobusXIORBUDPRefDebugEnter();

    handle = (globus_l_xio_quanta_rbudp_handle_t *) driver_specific_handle;
    handle->receiver->receive(iovec[0].iov_base, iovec[0].iov_len, 1452);
    *nbytes = iovec[0].iov_len;
    GlobusXIORBUDPRefDebugExit();

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_size_t *                     nbytes)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;
    GlobusXIOName(globus_l_xio_quanta_rbudp_write);

    GlobusXIORBUDPRefDebugEnter();
    handle = (globus_l_xio_quanta_rbudp_handle_t *) driver_specific_handle;
    handle->sender->send(
        iovec[0].iov_base, iovec[0].iov_len, handle->send_rate, 1452);
    *nbytes = iovec[0].iov_len;
    GlobusXIORBUDPRefDebugExit();

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_close(
    void *                              driver_specific_handle,
    void *                              attr)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;

    handle = (globus_l_xio_quanta_rbudp_handle_t *) driver_specific_handle;

    globus_xio_close(handle->tcp_handle, NULL);
    handle->sender->close();
    handle->receiver->close();
    globus_free(handle);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_quanta_rbudp_init);

    GlobusXIORBUDPRefDebugEnter();
    result = globus_xio_driver_init(&driver, "quanta_rbudp", NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_driver_init", result);
        goto error_init;
    }
    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_quanta_rbudp_open,
        NULL,
        NULL,
        NULL,
        globus_l_xio_quanta_rbudp_cntl);
   globus_xio_driver_set_server(
        driver,
        globus_l_xio_quanta_rbudp_server_init,
        globus_l_xio_quanta_rbudp_accept,
        NULL,
        NULL,
        NULL,
        NULL);
    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_quanta_rbudp_attr_init,
        globus_l_xio_quanta_rbudp_attr_copy,
        globus_l_xio_quanta_rbudp_attr_cntl,
        globus_l_xio_quanta_rbudp_attr_destroy);
    globus_xio_wrapblock_init(
        driver,
        NULL,
        globus_l_xio_quanta_rbudp_close,
        globus_l_xio_quanta_rbudp_read,
        globus_l_xio_quanta_rbudp_write,
        NULL);
    *out_driver = driver;
    GlobusXIORBUDPRefDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIORBUDPRefDebugExitWithError();
    return result;
}

static
void
globus_l_xio_quanta_rbudp_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    quanta_rbudp,
    globus_l_xio_quanta_rbudp_init,
    globus_l_xio_quanta_rbudp_destroy);
