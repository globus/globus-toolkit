#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_error_string.h"
#include "globus_xio_http.h"
#include "version.h"
 
typedef enum
{
    HTTP_S_HEADER,
    HTTP_S_ARGS,
    HTTP_R_BODY
} l_http_state_t;

#define _SERVER "test_server_string"
#define _TARGET "test_target_string"
#define _HANDLE "test_handle_string"

typedef struct l_http_info_s
{
    char remote_address[256];
} l_http_info_t;
    
/*
 *  used as attr and handle
 */

globus_result_t
globus_l_xio_http_target_destroy(
    void *                                  driver_target)
{
    return GLOBUS_SUCCESS;
}


static char *                               globus_l_remote_address = NULL;

l_http_info_t *
l_http_create_new_info()
{
    l_http_info_t *                         info;

    info = (l_http_info_t *) globus_malloc(sizeof(l_http_info_t));
    sprintf(info->remote_address, "%s", globus_l_remote_address);

    return info;
}


static globus_result_t
globus_l_xio_http_attr_init(
    void **                             out_attr)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_attr_copy(
    void **                             dst,
    void *                              src)
{
    l_http_info_t *                     src_info;
    l_http_info_t *                     dst_info;

    src_info = (l_http_info_t *) src;
    dst_info = l_http_create_new_info();
    memcpy(dst_info, src_info, sizeof(l_http_info_t));

    *dst = dst_info;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);

    return GLOBUS_SUCCESS;
}


/*
 *  open
 */
void
globus_l_xio_http_open_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_xio_context_t                    context;

    context = GlobusXIOOperationGetContext(op);

    GlobusXIODriverFinishedOpen(context, strdup(_HANDLE), op, result);
}   

static
globus_result_t
globus_l_xio_http_open(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_xio_context_t                    context;
    l_http_info_t *                         info;

    if(driver_attr == NULL)
    {
        return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }

    globus_l_xio_http_attr_copy(&info, driver_attr);

    GlobusXIODriverPassOpen(res, context, op, globus_l_xio_http_open_cb, info);

    return res;
}

/*
 *  close
 */
void
globus_l_xio_http_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    globus_xio_context_t                context;

    context = GlobusXIOOperationGetContext(op);
    GlobusXIODriverFinishedClose(op, result);
    globus_xio_driver_context_close(context);
}   

/*
 *  simply pass the close on down
 */
static globus_result_t
globus_l_xio_http_close(
    void *                                  driver_handle,
    void *                                  attr,
    globus_xio_context_t                    context,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;

    GlobusXIODriverPassClose(res, op, globus_l_xio_http_close_cb, NULL);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_http_write_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    GlobusXIODriverFinishedWrite(op, result, nbytes);
}

/*
 *  writes are easy, just pass everything along
 */
static
globus_result_t
globus_l_xio_http_write(
    void *                                  driver_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_size_t                           wait_for;
    l_http_info_t *                         info;

    info = (l_http_info_t *) driver_handle;

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_http_write_cb, NULL);

    return res;
}

/*
 *  read
 */
void
globus_l_xio_http_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    GlobusXIODriverFinishedRead(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_http_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    char *                              tst_str;

    tst_str = (char *) driver_handle;
    if(strcmp(tst_str, _HANDLE) != 0)
    {
        globus_assert(!"Handle string doesn't match");
    }

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassRead(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_http_read_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_http_target_init(
    void **                             out_target,
    void *                              driver_attr,
    const char *                        contact_string)
{
    //We don't do client work yet.  Only server
    *out_target = (void *)strdup(_TARGET);

    return GLOBUS_FALSE;
}

static globus_result_t
globus_l_xio_http_server_init(
    void **                             out_server,
    void *                              driver_attr)
{
    *out_server = (void *)strdup(_SERVER);

    return GLOBUS_SUCCESS;
}


/*
 *   accepting
 *
 *   Meary pass the accept, set target state to server.  The open will
 *   take care of the protocol exchange.
 */
static void
globus_l_xio_http_accept_cb(
    globus_i_xio_op_t *                     op,
    globus_result_t                         result,
    void *                                  user_arg)
{

    GlobusXIODriverFinishedAccept(op, strdup(_TARGET), GLOBUS_SUCCESS);
    return;

  err:

    GlobusXIODriverFinishedAccept(op, NULL, result);
    return;
}


static globus_result_t
globus_l_xio_http_accept(
    void *                                  driver_server,
    void *                                  driver_attr,
    globus_xio_operation_t                  accept_op)
{
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_http_accept);

    GlobusXIODriverPassAccept(res, accept_op, 
        globus_l_xio_http_accept_cb, NULL);

    return res;
}


static globus_result_t
globus_l_xio_http_load(
    globus_xio_driver_t *                   out_driver,
    va_list                                 ap)
{
    globus_xio_driver_t                     driver;
    globus_result_t                         res;

    res = globus_xio_driver_init(&driver, "http", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_http_open,
        globus_l_xio_http_close,
        globus_l_xio_http_read,
        globus_l_xio_http_write,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_http_attr_init,
        globus_l_xio_http_attr_copy,
        globus_l_xio_http_attr_cntl,
        globus_l_xio_http_attr_destroy);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_http_target_init,
        NULL,
        globus_l_xio_http_target_destroy);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_http_server_init,
        globus_l_xio_http_accept,
        NULL,
        NULL,
        globus_l_xio_http_target_destroy);
    *out_driver = driver;

    return GLOBUS_SUCCESS;
}



static void
globus_l_xio_http_unload(
    globus_xio_driver_t                     driver)
{
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_http_activate(void)
{
    int                                     rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    return rc;
}

static
int
globus_l_xio_http_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

static globus_module_descriptor_t  globus_i_xio_http_module =
{
    "globus_xio_http", //module name
    globus_l_xio_http_activate, //activate
    globus_l_xio_http_deactivate, //deactivate
    GLOBUS_NULL, //at exit
    GLOBUS_NULL, //get pointer
    &local_version //version
};

GlobusXIODefineDriver(
    http,
    &globus_i_xio_http_module,
    globus_l_xio_http_load,
    globus_l_xio_http_unload);
