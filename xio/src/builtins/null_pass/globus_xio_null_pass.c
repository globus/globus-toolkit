#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_null_pass.h"

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
globus_l_xio_null_pass_activate();

static int
globus_l_xio_null_pass_deactivate();

#include "version.h"

static globus_module_descriptor_t  globus_i_xio_null_pass_module =
{
    "globus_xio_null_pass",
    globus_l_xio_null_pass_activate,
    globus_l_xio_null_pass_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static globus_result_t
globus_l_xio_null_pass_server_init(
    void **                             out_server,
    void *                              driver_attr)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_null_pass_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;

    GlobusXIODriverPassAccept(res, accept_op, NULL, NULL);

    return res;
}

static globus_result_t
globus_l_xio_null_pass_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_null_pass_server_destroy(
    void *                              driver_server)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_null_pass_target_destroy(
    void *                              driver_target)
{
    return GLOBUS_SUCCESS;
}



/*
 *  open
 */
static
globus_result_t
globus_l_xio_null_pass_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_xio_context_t                context;
  
    GlobusXIODriverPassOpen(res, context, op, NULL, NULL);

    return res;
}

/*
 *  close
 */
static
globus_result_t
globus_l_xio_null_pass_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;

    GlobusXIODriverPassClose(res, op, NULL, NULL);

    return res;
}

/*
 *  read
 */
static
globus_result_t
globus_l_xio_null_pass_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassRead(res, op, iovec, iovec_count, wait_for, NULL, NULL);

    return res;
}

/*
 *  write
 */
static
globus_result_t
globus_l_xio_null_pass_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, wait_for, NULL, NULL);

    return res;
}

static
globus_result_t
globus_l_xio_null_pass_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_null_pass_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "null_pass", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_null_pass_open,
        globus_l_xio_null_pass_close,
        globus_l_xio_null_pass_read,
        globus_l_xio_null_pass_write,
        globus_l_xio_null_pass_cntl);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_null_pass_server_init,
        globus_l_xio_null_pass_accept,
        globus_l_xio_null_pass_server_destroy,
        globus_l_xio_null_pass_server_cntl,
        globus_l_xio_null_pass_target_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_null_pass_unload(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_null_pass_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    return rc;
}

static
int
globus_l_xio_null_pass_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    null_pass,
    &globus_i_xio_null_pass_module,
    globus_l_xio_null_pass_load,
    globus_l_xio_null_pass_unload);
