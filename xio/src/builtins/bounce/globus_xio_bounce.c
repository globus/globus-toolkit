#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_bounce.h"

#define MAX_COUNT 2

static int
globus_l_xio_bounce_activate();

static int
globus_l_xio_bounce_deactivate();

#include "version.h"

GlobusXIODefineModule(bounce) =
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
    TEST_NONE,
    TEST_OPEN,
    TEST_CLOSE,
    TEST_READ,
    TEST_WRITE,
    TEST_FINISH
} test_next_op_t;

typedef struct bounce_handle_s
{
    globus_mutex_t                      mutex;
    globus_bool_t                       closed_iface;
    globus_bool_t                       closed_cb;
    globus_bool_t                       open_cb;
} bounce_handle_t;

typedef struct bounce_info_s
{
    int                                 bounce_count;
    int                                 max_count;
    test_next_op_t                      next_op;
    test_next_op_t                      start_op;
    globus_size_t                       nbytes;
    globus_result_t                     res;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    globus_size_t                       wait_for;
    globus_xio_iovec_t                  tmp_iovec;
    bounce_handle_t *                   handle;
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
close_bounce_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static void
open_bounce_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static void
bounce_handle_destroy(
    bounce_handle_t *                   handle)
{
    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
}

static void
test_bounce_finish_op(
    bounce_info_t *                     info,
    globus_xio_operation_t              op)
{
    GlobusXIOName(test_bounce_finish_op);

    GlobusXIODebugInternalEnter();

    switch(info->start_op)
    {
        case TEST_READ:
            globus_xio_driver_finished_read(op, info->res, info->nbytes);
            break;

        case TEST_WRITE:
            globus_xio_driver_finished_write(op, info->res, info->nbytes);
            break;
    
        case TEST_OPEN:
            if(info->res != GLOBUS_SUCCESS)
            {
                bounce_handle_destroy(info->handle);
                info->handle = NULL;
            }
            globus_xio_driver_finished_open(
                info->handle, op, info->res);
            break;

        case TEST_CLOSE:
            globus_xio_driver_finished_close(op, info->res);
            bounce_handle_destroy(info->handle);
            break;

        default:
            globus_assert(0);
            break;
    }

    globus_free(info);

    GlobusXIODebugInternalExit();
}

static globus_result_t
test_bounce_next_op(
    bounce_info_t *                     info,
    globus_xio_operation_t              op)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(test_bounce_next_op);

    GlobusXIODebugInternalEnter();
    info->bounce_count++;

    switch(info->next_op)
    {
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
            res = globus_xio_driver_pass_read(
                op, info->iovec, info->iovec_count,
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

            res = globus_xio_driver_pass_write(
                op, info->iovec, info->iovec_count,
                info->wait_for, bounce_data_cb, (void *)info);
            break;

        case TEST_CLOSE:
            info->next_op = TEST_FINISH;
            res = globus_xio_driver_pass_close(op, close_bounce_cb,
                (void*)info);
            break;

        case TEST_FINISH:
            test_bounce_finish_op(info, op);
            res = GLOBUS_SUCCESS;
            break;

        default:
            globus_assert(0);
            break;
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  err:
    GlobusXIODebugInternalExitWithError();
    return res;
}

void
bounce_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    bounce_info_t *                     info;
    globus_result_t                     res;
    GlobusXIOName(bounce_cb);

    GlobusXIODebugInternalEnter();
    info = (bounce_info_t *) user_arg;
    info->res = result;
    info->wait_for = 1024;
    info->iovec = &info->tmp_iovec;
    info->iovec->iov_base = (globus_byte_t *) 0x100;
    info->iovec->iov_len = 1024;
    info->iovec_count = 1;

    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_STATE,
            ("[%s] : result != Success\n", _xio_name));
        info->next_op = TEST_FINISH;
    }

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        info->res = res;
        test_bounce_finish_op(info, op);
    }
    GlobusXIODebugInternalExit();
}

void
bounce_data_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    bounce_info_t *                     info;
    globus_result_t                     res;
    GlobusXIOName(bounce_data_cb);

    GlobusXIODebugInternalEnter();
    info = (bounce_info_t *) user_arg;
    info->res = result;
    info->nbytes = nbytes;

    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_STATE,
            ("[%s] : result != Success\n", _xio_name));
        info->next_op = TEST_FINISH;
    }

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        info->res = res;
        test_bounce_finish_op(info, op);
    }
    GlobusXIODebugInternalExit();
}

static void
close_bounce_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    bounce_info_t *                     info;

    info = (bounce_info_t *) user_arg;
    /* verify close callback isn't called twice */
    globus_assert(info->handle->closed_cb == GLOBUS_FALSE);
    info->handle->closed_cb = GLOBUS_TRUE;

    bounce_cb(op, result, user_arg);
}

static void
open_bounce_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    bounce_info_t *                     info;

    info = (bounce_info_t *) user_arg;
    /* verify open callback isn't called twice */
    globus_assert(info->handle->open_cb == GLOBUS_FALSE);
    info->handle->open_cb = GLOBUS_TRUE;

    bounce_cb(op, result, user_arg);
}

globus_result_t
globus_l_xio_bounce_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    bounce_info_t *                     info;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_bounce_open);

    GlobusXIODebugInternalEnter();
    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    memset(info, '\0', sizeof(bounce_info_t));
    info->next_op = TEST_READ;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_OPEN;
    info->handle = (bounce_handle_t *) globus_malloc(sizeof(bounce_handle_t));  
    globus_mutex_init(&info->handle->mutex, NULL);
    info->handle->closed_iface = GLOBUS_FALSE;
    info->handle->closed_cb = GLOBUS_FALSE;
    info->handle->open_cb = GLOBUS_FALSE;

    res = globus_xio_driver_pass_open(
        op, contact_info, open_bounce_cb, (void*)info);
    if(res != GLOBUS_SUCCESS)
    {
        bounce_handle_destroy(info->handle);
        globus_free(info);
        goto err;
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  err:
    GlobusXIODebugInternalExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_bounce_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    bounce_info_t *                     info;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_bounce_close);

    GlobusXIODebugInternalEnter();

    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    memset(info, '\0', sizeof(bounce_info_t));
    info->next_op = TEST_READ;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_CLOSE;
    info->wait_for = 1024;
    info->iovec = &info->tmp_iovec;
    info->iovec->iov_base = (globus_byte_t *)0x100;
    info->iovec->iov_len = 1024;
    info->iovec_count = 1;

    info->handle = driver_handle;

    /* verify close isn't called twice */
    globus_assert(info->handle->closed_iface == GLOBUS_FALSE);

    info->handle->closed_iface = GLOBUS_TRUE;

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        bounce_handle_destroy(info->handle);
        goto err;
    }
    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;    

  err:

    GlobusXIODebugInternalExitWithError();
    return res;
}

static globus_result_t
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

    GlobusXIODebugInternalEnter();
    wait_for = globus_xio_operation_get_wait_for(op);

    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    memset(info, '\0', sizeof(bounce_info_t));
    info->next_op = TEST_READ;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_READ;
    info->wait_for = wait_for;
    info->iovec = (globus_xio_iovec_t *) iovec;
    info->iovec_count = iovec_count;
    info->nbytes = 0;

    info->handle = driver_handle;

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;
  err:

    GlobusXIODebugInternalExitWithError();
    return res;
}

static globus_result_t
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

    GlobusXIODebugInternalEnter();
    wait_for = globus_xio_operation_get_wait_for(op);

    info = (bounce_info_t *)
                globus_malloc(sizeof(bounce_info_t));
    memset(info, '\0', sizeof(bounce_info_t));
    info->next_op = TEST_WRITE;
    info->bounce_count = 0;
    info->max_count = MAX_COUNT;
    info->start_op = TEST_WRITE;
    info->wait_for = wait_for;
    info->iovec = (globus_xio_iovec_t *)iovec;
    info->iovec_count = iovec_count;
    info->nbytes = 0;

    info->handle = driver_handle;

    res = test_bounce_next_op(info, op);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugInternalExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugInternalExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_bounce_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_bounce_cntl);

    GlobusXIODebugInternalEnter();
    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_bounce_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_bounce_init);

    GlobusXIODebugInternalEnter();
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
        globus_l_xio_bounce_cntl,
        NULL);

    *out_driver = driver;

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_bounce_destroy(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_bounce_destroy);

    GlobusXIODebugInternalEnter();
    globus_xio_driver_destroy(driver);
    GlobusXIODebugInternalExit();
}

GlobusXIODefineDriver(
    bounce,
    globus_l_xio_bounce_init,
    globus_l_xio_bounce_destroy);

static int
globus_l_xio_bounce_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(bounce);
    }
    
    return rc;
}

static int
globus_l_xio_bounce_deactivate(void)
{
    GlobusXIOUnRegisterDriver(bounce);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
