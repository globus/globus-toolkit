#include "globus_xio_driver.h"
#include "globus_xio_wrapblock.h"
#include "version.h"

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
    QUANTAnet_rbudpSender_c *           sender;
    QUANTAnet_rbudpReceiver_c *         receiver;
    int                                 send_rate;
} globus_l_xio_quanta_rbudp_handle_t;

static
int
globus_l_xio_quanta_rbudp_activate(void);

static
int
globus_l_xio_quanta_rbudp_deactivate(void);

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
    int rc;
    GlobusXIOName(globus_l_xio_quanta_rbudp_activate);

    GlobusDebugInit(GLOBUS_XIO_QUANTA_RBUDP, TRACE);
    GlobusXIORBUDPRefDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    GlobusXIORegisterDriver(quanta_rbudp);
    GlobusXIORBUDPRefDebugExit();
    return GLOBUS_SUCCESS;

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
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_copy(
    void **                             dst,
    void *                              src)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_attr_destroy(
    void *                              driver_attr)
{
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
globus_l_xio_quanta_rbudp_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
}

static
globus_result_t
globus_l_xio_quanta_rbudp_server_destroy(
    void *                              driver_server)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_quanta_rbudp_server_cntl(
    void *                              driver_server,
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
globus_result_t
globus_l_xio_quanta_rbudp_accept(
    void *                              driver_server,
    void **                             out_link)
{
    return GLOBUS_SUCCESS;
}



static
globus_result_t
globus_l_xio_quanta_rbudp_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    void **                             driver_handle)
{
    globus_l_xio_quanta_rbudp_handle_t *    handle;

    handle = (globus_l_xio_quanta_rbudp_handle_t *)
        globus_calloc(1, sizeof(globus_l_xio_quanta_rbudp_handle_t));

    handle->sender = new QUANTAnet_rbudpSender_c(38000);
    mysender->init(contact_info->host);
    handle->receiver = new QUANTAnet_rbudpReceiver_c(38001);
    receiver->init(contact_info->host);

    return GLOBUS_SUCCESS;
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

    handle = (globus_l_xio_quanta_rbudp_handle_t *) driver_specific_handle;
    handle->receiver->receive(iovec[0].iov_base, iovec[0].iov_len, 1496);
    *nbytes = iovec[0].iov_len;

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

    handle = (globus_l_xio_quanta_rbudp_handle_t *) driver_specific_handle;
    handle->sender->send(
        iovec[0].iov_base, iovec[0].iov_len, handle->send_rate, 1496);
    *nbytes = iovec[0].iov_len;

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
        NULL,
        NULL,
        NULL,
        NULL,
        globus_l_xio_quanta_rbudp_cntl);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_quanta_rbudp_server_init,
        NULL,
        globus_l_xio_quanta_rbudp_server_destroy,
        globus_l_xio_quanta_rbudp_server_cntl,
        globus_l_xio_quanta_rbudp_link_cntl,
        globus_l_xio_quanta_rbudp_link_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_quanta_rbudp_attr_init,
        globus_l_xio_quanta_rbudp_attr_copy,
        globus_l_xio_quanta_rbudp_attr_cntl,
        globus_l_xio_quanta_rbudp_attr_destroy);
    globus_xio_wrapblock_init(
        driver,
        globus_l_xio_quanta_rbudp_open,
        globus_l_xio_quanta_rbudp_close,
        globus_l_xio_quanta_rbudp_read,
        globus_l_xio_quanta_rbudp_write,
        globus_l_xio_quanta_rbudp_accept);
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
