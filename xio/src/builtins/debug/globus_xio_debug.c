#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_debug.h"

#define GLOBUS_XIO_DEBUG_DRIVER_MODULE &globus_i_xio_test_module

#define XIOTestCreateOpWraper(ow, _in_dh, _in_op, res, nb)              \
{                                                                       \
    ow = (globus_l_xio_test_op_wrapper_t *)                             \
            globus_malloc(sizeof(globus_l_xio_test_op_wrapper_t));      \
    ow->dh = _in_dh;                                                    \
    ow->op = (_in_op);                                                  \
    ow->res = res;                                                      \
    ow->nbytes = nb;                                                    \
}

static int
globus_l_xio_debug_activate();

static int
globus_l_xio_debug_deactivate();

#include "version.h"

static globus_module_descriptor_t  globus_i_xio_debug_module =
{
    "globus_xio_debug",
    globus_l_xio_debug_activate,
    globus_l_xio_debug_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static void
debug_driver_log(
    char *                              fmt,
    ...)
{
    va_list                                     ap;

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, fmt);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    fprintf(stderr, "DEBUG DRIVER: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");

    va_end(ap);
}

static globus_result_t
globus_l_xio_debug_server_init(
    void **                             out_server,
    void *                              driver_attr)
{
    debug_driver_log("server init");
    return GLOBUS_SUCCESS;
}

void
globus_l_xio_debug_accept_cb(
    globus_i_xio_op_t *                 op,
    globus_result_t                     result,
    void *                              user_arg)
{
    debug_driver_log("finished accept");
    GlobusXIODriverFinishedAccept(op, NULL, result);
}

static globus_result_t
globus_l_xio_debug_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;

    debug_driver_log("finished accept");

    GlobusXIODriverPassAccept(res, accept_op,      \
        globus_l_xio_debug_accept_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_debug_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    debug_driver_log("server cntl");

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_debug_server_destroy(
    void *                              driver_server)
{
    debug_driver_log("server destroy");

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_debug_target_destroy(
    void *                              driver_target)
{
    debug_driver_log("target destroy");

    return GLOBUS_SUCCESS;
}



/*
 *  open
 */
void
globus_l_xio_debug_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_context_t                context;

    debug_driver_log("finished open");

    context = GlobusXIOOperationGetContext(op);

    GlobusXIODriverFinishedOpen(context, NULL, op, result);
}   

static
globus_result_t
globus_l_xio_debug_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_xio_context_t                context;
  
    debug_driver_log("open");

    GlobusXIODriverPassOpen(res, context, op, \
        globus_l_xio_debug_open_cb, NULL);

    return res;
}

/*
 *  close
 */
void
globus_l_xio_debug_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    debug_driver_log("finished close");

    GlobusXIODriverFinishedClose(op, result);
}   

static
globus_result_t
globus_l_xio_debug_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;

    debug_driver_log("close");

    GlobusXIODriverPassClose(res, op,   \
        globus_l_xio_debug_close_cb, NULL);

    return res;
}

/*
 *  read
 */
void
globus_l_xio_debug_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    debug_driver_log("finished read");

    GlobusXIODriverFinishedRead(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_debug_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    debug_driver_log("read");

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassRead(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_debug_read_cb, NULL);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_debug_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    debug_driver_log("finished write");

    GlobusXIODriverFinishedWrite(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_debug_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    debug_driver_log("write");

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_debug_write_cb, NULL);

    return res;
}

static
globus_result_t
globus_l_xio_debug_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    debug_driver_log("handle cntl");

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_debug_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "debug", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_debug_open,
        globus_l_xio_debug_close,
        globus_l_xio_debug_read,
        globus_l_xio_debug_write,
        globus_l_xio_debug_cntl);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_debug_server_init,
        globus_l_xio_debug_accept,
        globus_l_xio_debug_server_destroy,
        globus_l_xio_debug_server_cntl,
        globus_l_xio_debug_target_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_debug_unload(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_debug_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    return rc;
}

static
int
globus_l_xio_debug_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    debug,
    &globus_i_xio_debug_module,
    globus_l_xio_debug_load,
    globus_l_xio_debug_unload);
