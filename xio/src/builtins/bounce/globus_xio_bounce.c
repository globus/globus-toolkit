#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_bounce.h"

#define MAX_COUNT 2

enum
{
    GLOBUS_XIO_BOUNCE_DEBUG = 1,
} bounce_debug_type_t;

#define GlobusXIOBounceDebugEnter()                                         \
    GlobusDebugPrintf(GLOBUS_XIO_BOUNCE,                                    \
        GLOBUS_XIO_BOUNCE_DEBUG,                                            \
        ("[%s] Entering\n", _xio_name))
                                                                                
#define GlobusXIODebugBounceExit()                                          \
    GlobusDebugPrintf(GLOBUS_XIO_BOUNCE,                                    \
        GLOBUS_XIO_BOUNCE_DEBUG,                                             \
        ("[%s] Exiting\n", _xio_name))

GlobusDebugDefine(GLOBUS_XIO_BOUNCE);

static int
globus_l_xio_bounce_activate();

static int
globus_l_xio_bounce_deactivate();

#include "version.h"

globus_module_descriptor_t  globus_i_xio_bounce_module =
{
    "globus_xio_bounce",
    globus_l_xio_bounce_activate,
    globus_l_xio_bounce_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef enum  test_next_op_e
{
    TEST_OPEN,
    TEST_CLOSE,
    TEST_READ,
    TEST_WRITE,
    TEST_FINISH,
} test_next_op_t;

typedef struct bounce_info_s
{
    int                                 bounce_count;
    int                                 max_count;
    test_next_op_t                      next_op;
    test_next_op_t                      start_op;
    globus_size_t                       nbytes;
    globus_xio_operation_t              op;
    globus_xio_context_t                context;
    globus_result_t                     res;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    globus_size_t                       wait_for;
    globus_xio_iovec_t                  tmp_iovec;
} bounce_info_t;

void
bounce_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

void
bounce_data_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);


static void
test_bounce_finish_op(
    bounce_info_t *                     info,
    globus_xio_operation_t              op)
{
    GlobusXIOName(test_bounce_finish_op);

    GlobusXIOBounceDebugEnter();

    globus_xio_context_t                context;
    switch(info->start_op)
    {
        case TEST_READ:
            GlobusXIODriverFinishedRead(op, info->res, info->nbytes);
            break;

        case TEST_WRITE:
            GlobusXIODriverFinishedWrite(op, info->res, info->nbytes);
            break;
    
        case TEST_OPEN:
            GlobusXIODriverFinishedOpen(info->context, 
                NULL, op, info->res);
            break;

        case TEST_CLOSE:
            context = GlobusXIOOperationGetContext(op);
            GlobusXIODriverFinishedClose(op, info->res);
            globus_xio_driver_context_close(context);
            break;

        default:
            globus_assert(0);
            break;
    }

     GlobusDebugPrintf(GLOBUS_XIO_BOUNCE,
        GLOBUS_XIO_BOUNCE_DEBUG,
        ("[%s:%d]  freeing info @ 0x%x\n", _xio_name, __LINE__, info));

    globus_free(info);

    GlobusXIODebugBounceExit();
}

static globus_result_t
test_bounce_next_op(
    bounce_info_t *                     info,
    globus_xio_operation_t              op)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(test_bounce_next_op);

    GlobusXIOBounceDebugEnter();
    info->bounce_count++;

    switch(info->next_op)
    {
        case TEST_OPEN:
            info->next_op = TEST_READ;
            GlobusXIODriverPassOpen(res, &info->context, op,
                bounce_cb, (void*)info);
            break;

        case TEST_READ:
            if(info->bounce_count == info->max_count)
            {
                info->bounce_count = 0;
                if(info->start_op == TEST_CLOSE)
                {
                    info->next_op = TEST_CLOSE;
                }
                else if(info->start_op == TEST_READ)
                {
                    info->next_op = TEST_WRITE;
                }
                else
                {
                    info->next_op = TEST_FINISH;
                }
            }
            GlobusXIODriverPassRead(res, op, info->iovec, info->iovec_count,
                info->wait_for, bounce_data_cb, (void *)info);

            break;

        case TEST_WRITE:
            if(info->bounce_count == info->max_count)
            {
                info->bounce_count = 0;
                if(info->start_op == TEST_CLOSE)
                {
                    info->next_op = TEST_CLOSE;
                }
                else if(info->start_op == TEST_WRITE)
                {
                    info->next_op = TEST_READ;
                }
                else
                {
                    info->next_op = TEST_FINISH;
                }
            }

            GlobusXIODriverPassWrite(res, op, info->iovec, info->iovec_count,
                info->wait_for, bounce_data_cb, (void *)info);
            break;

        case TEST_CLOSE:
            info->next_op = TEST_FINISH;
            GlobusXIODriverPassClose(res, op,
                bounce_cb, (void*)info);
            break;

        case TEST_FINISH:
            test_bounce_finish_op(info, op);
            res = GLOBUS_SUCCESS;
            break;
    }

    GlobusXIODebugBounceExit();
    return res;
}

void
bounce_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    bounce_info_t *                         info;
    globus_result_t                         res;
    GlobusXIOName(bounce_cb);

    GlobusXIOBounceDebugEnter();
    info = (bounce_info_t *) user_arg;
    info->res = result;
    info->wait_for = 1024;
    info->iovec = &info->tmp_iovec;
    info->iovec->iov_base = (globus_byte_t *) 0x100;
    info->iovec->iov_len = 1024;
    info->iovec_count = 1;

    if(result != GLOBUS_SUCCESS)
    {
        info->next_op = TEST_FINISH;
    }

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        info->res = res;
        test_bounce_finish_op(info, op);
    }
    GlobusXIODebugBounceExit();
}

void
bounce_data_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    bounce_info_t *                         info;
    globus_result_t                         res;
    GlobusXIOName(bounce_data_cb);

    GlobusXIOBounceDebugEnter();
    info = (bounce_info_t *) user_arg;
    info->res = result;
    info->nbytes = nbytes;

    if(result != GLOBUS_SUCCESS)
    {
        info->next_op = TEST_FINISH;
    }

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        info->res = res;
        test_bounce_finish_op(info, op);
    }
    GlobusXIODebugBounceExit();
}

static
globus_result_t
globus_l_xio_bounce_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    bounce_info_t *                     info;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_bounce_open);

    GlobusXIOBounceDebugEnter();
    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    info->next_op = TEST_READ;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_OPEN;

    GlobusXIODriverPassOpen(res, &info->context, op, 
                bounce_cb, (void*)info);

    GlobusXIODebugBounceExit();

    return res;
}

static
globus_result_t
globus_l_xio_bounce_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    bounce_info_t *                     info;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_bounce_close);

    GlobusXIOBounceDebugEnter();

    GlobusDebugPrintf(GLOBUS_XIO_BOUNCE,
        GLOBUS_XIO_BOUNCE_DEBUG,
        ("[%s:%d] close op @ 0x%x\n", _xio_name, __LINE__, op));

    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    info->next_op = TEST_READ;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_CLOSE;
    info->wait_for = 1024;
    info->iovec = &info->tmp_iovec;
    info->iovec->iov_base = (globus_byte_t *)0x100;
    info->iovec->iov_len = 1024;
    info->iovec_count = 1;

    res = test_bounce_next_op(info, op);

    GlobusXIODebugBounceExit();
    return res;
}

static
globus_result_t
globus_l_xio_bounce_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    bounce_info_t *                     info;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_size_t                       wait_for;
    GlobusXIOName(globus_l_xio_bounce_read);

    GlobusXIOBounceDebugEnter();
    wait_for = GlobusXIOOperationGetWaitFor(op);

    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    info->next_op = TEST_READ;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_READ;
    info->wait_for = wait_for;
    info->iovec = (globus_xio_iovec_t *) iovec;
    info->iovec_count = iovec_count;
    info->nbytes = 0;
    res = test_bounce_next_op(info, op);

    GlobusXIODebugBounceExit();
    return res;
}

static
globus_result_t
globus_l_xio_bounce_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    bounce_info_t *                     info;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_size_t                       wait_for;
    GlobusXIOName(globus_l_xio_bounce_write);

    GlobusXIOBounceDebugEnter();
    wait_for = GlobusXIOOperationGetWaitFor(op);

    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    info->next_op = TEST_WRITE;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_WRITE;
    info->wait_for = wait_for;
    info->iovec = (globus_xio_iovec_t *)iovec;
    info->iovec_count = iovec_count;
    info->nbytes = 0;
    res = test_bounce_next_op(info, op);

    GlobusXIODebugBounceExit();
    return res;
}

static
globus_result_t
globus_l_xio_bounce_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_bounce_cntl);

    GlobusXIOBounceDebugEnter();
    GlobusXIODebugBounceExit();
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_bounce_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_bounce_load);

    GlobusXIOBounceDebugEnter();
    res = globus_xio_driver_init(&driver, "bounce", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_bounce_open,
        globus_l_xio_bounce_close,
        globus_l_xio_bounce_read,
        globus_l_xio_bounce_write,
        globus_l_xio_bounce_cntl);

    *out_driver = driver;

    GlobusXIODebugBounceExit();
    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_bounce_unload(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_bounce_unload);

    GlobusXIOBounceDebugEnter();
    globus_xio_driver_destroy(driver);
    GlobusXIODebugBounceExit();
}


static
int
globus_l_xio_bounce_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    GlobusDebugInit(GLOBUS_XIO_BOUNCE,
        GLOBUS_XIO_BOUNCE_DEBUG);

    return rc;
}

static
int
globus_l_xio_bounce_deactivate(void)
{
    GlobusDebugDestroy(GLOBUS_XIO_BOUNCE);

    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    bounce,
    &globus_i_xio_bounce_module,
    globus_l_xio_bounce_load,
    globus_l_xio_bounce_unload);
