#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_test_transport.h"

#define GLOBUS_XIO_TEST_TRANSPORT_DRIVER_MODULE &globus_i_xio_test_module

#define MAX_DELAY 100000

#define XIOTestCreateOpWraper(ow, _in_dh, _in_op, res, nb)              \
{                                                                       \
    ow = (globus_l_xio_test_op_wrapper_t *)                             \
            globus_malloc(sizeof(globus_l_xio_test_op_wrapper_t));      \
    ow->dh = _in_dh;                                                    \
    ow->op = (_in_op);                                                  \
    ow->res = res;                                                      \
    ow->nbytes = nb;                                                    \
}

static globus_mutex_t                   globus_l_mutex;
static globus_cond_t                    globus_l_cond;
static globus_callback_space_t          globus_l_space;

static int
globus_l_xio_test_activate();

static int
globus_l_xio_test_deactivate();

static
void
globus_l_xio_operation_kickout(
    void *                              user_arg);

/* 
 *  handle and attr are the same structure here
 */
typedef struct globus_l_xio_test_handle_s
{
    globus_xio_test_failure_t           failure;
    globus_xio_context_t                context;
    globus_bool_t                       inline_finish;
    globus_size_t                       read_nbytes;
    globus_size_t                       chunk_size;
    globus_size_t                       bytes_read;
    globus_reltime_t                    delay;

    int                                 random;
} globus_l_xio_test_handle_t;

typedef struct globus_l_xio_test_op_wrapper_s
{
    globus_xio_operation_type_t         type;
    globus_xio_operation_t              op;
    globus_l_xio_test_handle_t *        dh;
    globus_result_t                     res;
    globus_size_t                       nbytes;
    globus_callback_handle_t            callback_handle;
} globus_l_xio_test_op_wrapper_t;


static globus_l_xio_test_handle_t       globus_l_default_attr;

#include "version.h"

globus_module_descriptor_t       globus_i_xio_test_module =
{
    "globus_xio_test",
    globus_l_xio_test_activate,
    globus_l_xio_test_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


static void
cancel_cb(
    globus_xio_operation_t                      op,
    void *                                      user_arg)
{
    globus_l_xio_test_op_wrapper_t *    ow;
    globus_bool_t                       active;
    globus_result_t                     res;
    GlobusXIOName(cancel_cb);

    GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE, ("test driver cancel callback\n"));
    ow = (globus_l_xio_test_op_wrapper_t *) user_arg;

    ow->res = GlobusXIOErrorTimedout();

    res = globus_callback_unregister(
            ow->callback_handle,
            NULL,
            NULL,
            &active);
    globus_assert(res == GLOBUS_SUCCESS);
    if(!active)
    {
        /* if we could stop it, register it for right now */
        globus_callback_space_register_oneshot(
            NULL,
            NULL,
            globus_l_xio_operation_kickout,
            (void *) ow,
            GLOBUS_CALLBACK_GLOBAL_SPACE);
    }
}

static void
test_inline_blocker(
    globus_reltime_t *                          delay)
{
    globus_abstime_t                            timeout;
    globus_reltime_t                            zero;
    int                                         sec;
    int                                         usec;

    GlobusTimeReltimeSet(zero, 0, 0);
    if(globus_reltime_cmp(delay, &zero) != 0)
    {
    GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE, ("nonzero delay\n"));
        GlobusTimeAbstimeGetCurrent(timeout);
        GlobusTimeAbstimeInc(timeout, *delay);
        GlobusTimeReltimeGet(*delay, sec, usec);
        sleep(sec);
        globus_libc_usleep(usec);
    }
}

/*
 *  initialize a driver attribute
 */
static
globus_result_t
globus_l_xio_test_attr_init(
    void **                             out_attr)
{
    globus_l_xio_test_handle_t *        attr;

    attr = (globus_l_xio_test_handle_t *)
                globus_malloc(sizeof(globus_l_xio_test_handle_t));
    memset(attr, '\0', sizeof(globus_l_xio_test_handle_t));
    attr->inline_finish = GLOBUS_FALSE;
    attr->failure = 0;  /* default is no failures */
    GlobusTimeReltimeSet(attr->delay, 0, 0);
    attr->read_nbytes = -1; /* default is no EOF (close only) */
    attr->chunk_size = -1; /* default: entire chunk requested */

    *out_attr = attr;

    return GLOBUS_SUCCESS;
}

static void
test_get_delay_time(
    globus_l_xio_test_handle_t *        dh,
    globus_reltime_t *                  out_delay)
{
    int                                 usec = 0;
    GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE, ("start random delay\n"));
    if(dh->random)
    {
        usec = rand() % MAX_DELAY;
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE, ("-> %d\n", MAX_DELAY));
        GlobusTimeReltimeSet(*out_delay, 0, usec);
    }
}

/*
 *  modify the attribute structure
 */
static
globus_result_t
globus_l_xio_test_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_test_handle_t *        attr;
    int                                 usecs;

    attr = (globus_l_xio_test_handle_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_TEST_SET_INLINE:
            attr->inline_finish = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TEST_SET_FAILURES:
            attr->failure = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TEST_SET_USECS:
            usecs = va_arg(ap, int);
            GlobusTimeReltimeSet(attr->delay, 0, usecs);
            break;

        case GLOBUS_XIO_TEST_READ_EOF_BYTES:
            attr->read_nbytes = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TEST_CHUNK_SIZE:
            attr->chunk_size = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TEST_RANDOM:
            attr->random = GLOBUS_TRUE;
            usecs = va_arg(ap, int);
            srand(usecs);
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE, ("turning on random, seed=%d\n", usecs));
            break;

    }

    return GLOBUS_SUCCESS;
}

/*
 *  copy an attribute structure
 */
static
globus_result_t
globus_l_xio_test_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_xio_test_handle_t *        attr;

    attr = (globus_l_xio_test_handle_t *)
                globus_malloc(sizeof(globus_l_xio_test_handle_t));
    memcpy(attr, src, sizeof(globus_l_xio_test_handle_t));

    *dst = attr;

    return GLOBUS_SUCCESS;
}

/*
 *  destroy an attr structure
 */
static
globus_result_t
globus_l_xio_test_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);

    return GLOBUS_SUCCESS;
}

/*
 *  initialize target structure
 */
static
globus_result_t
globus_l_xio_test_target_init(
    void **                             out_target,
    void *                              driver_attr,
    const char *                        contact_string)
{
    return GLOBUS_SUCCESS;
}

/*
 *  destroy the target structure
 */
static
globus_result_t
globus_l_xio_test_target_destroy(
    void *                              driver_target)
{
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_operation_kickout(
    void *                              user_arg)
{
    globus_l_xio_test_op_wrapper_t *    ow;

    ow = (globus_l_xio_test_op_wrapper_t *) user_arg;

    GlobusXIODriverDisableCancel(ow->op);

    GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE, ("finishing with=%d\n", ow->res));
    switch(ow->type)
    {
        case GLOBUS_XIO_OPERATION_TYPE_OPEN:
            GlobusXIODriverFinishedOpen(ow->dh->context, ow->dh, ow->op, \
                ow->res);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_CLOSE:
            GlobusXIODriverFinishedClose(ow->op, ow->res);
            globus_xio_driver_context_close(ow->dh->context);
            globus_l_xio_test_attr_destroy(ow->dh);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_READ:
            GlobusXIODriverFinishedRead(ow->op, ow->res, ow->nbytes);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_WRITE:
            GlobusXIODriverFinishedWrite(ow->op, ow->res, ow->nbytes);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_ACCEPT:
            GlobusXIODriverFinishedAccept(ow->op, NULL, ow->res);
            break;

        default:
            globus_assert(0);
    }    
    globus_free(ow);
}

/**********************************
 *  server stuff
 *********************************/

static globus_result_t
globus_l_xio_test_server_init(
    void **                             out_server,
    void *                              driver_attr)
{
    globus_l_xio_test_handle_t *        server;

    if(driver_attr == NULL)
    {
        driver_attr = &globus_l_default_attr;
    }

    /* copy the attr to a handle */
    globus_l_xio_test_attr_copy((void **)&server, driver_attr);

    *out_server = server;
    
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_test_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              accept_op)
{
    globus_reltime_t                    end_time;
    globus_l_xio_test_handle_t *        server;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_test_accept);


    server = (globus_l_xio_test_handle_t *) driver_server;

    if(server->failure == GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT)
    {
        return GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT);
    }
    else if(server->failure == GLOBUS_XIO_TEST_FAIL_FINISH_ACCEPT)
    {
        res = GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_FINISH_ACCEPT);
    }

    if(server->inline_finish)
    {
        GlobusXIODriverFinishedAccept(accept_op, NULL, res);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;
        globus_reltime_t *                  delay;
        globus_bool_t                       canceled;

        XIOTestCreateOpWraper(ow, server, accept_op, res, 0);
        ow->type = GLOBUS_XIO_OPERATION_TYPE_ACCEPT;

        delay = &server->delay;
        GlobusXIODriverEnableCancel(accept_op, canceled, cancel_cb, ow);
        if(canceled)
        {
            delay = NULL;
            ow->res = GlobusXIOErrorCanceled();
        }
        else if(server->random)
        {
            test_get_delay_time(server, &end_time);
            delay = &end_time;
        }

        globus_callback_space_register_oneshot(
            &ow->callback_handle,
            delay,
            globus_l_xio_operation_kickout,
            (void *) ow,
            GLOBUS_CALLBACK_GLOBAL_SPACE);
    }

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_test_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_test_server_destroy(
    void *                              driver_server)
{
    globus_free(driver_server);
    return GLOBUS_SUCCESS;
}



/*
 *  open a file
 */
static
globus_result_t
globus_l_xio_test_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_xio_test_handle_t *        attr;
    globus_l_xio_test_handle_t *        dh;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_reltime_t *                  delay;
    globus_reltime_t                    end_time;
    GlobusXIOName(globus_l_xio_test_open);

    attr = (globus_l_xio_test_handle_t *) driver_attr;

    if(attr == NULL)
    {
        attr = &globus_l_default_attr;
    }

    /* copy the attr to a handle */
    globus_l_xio_test_attr_copy((void **)&dh, attr);
    dh->context = context;

    if(dh->failure == GLOBUS_XIO_TEST_FAIL_PASS_OPEN)
    {
        return GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_PASS_OPEN);
    }
    else if(dh->failure == GLOBUS_XIO_TEST_FAIL_FINISH_OPEN)
    {
        res = GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_FINISH_OPEN);
    }

    if(dh->inline_finish)
    {
        test_inline_blocker(&dh->delay);
        GlobusXIODriverFinishedOpen(context, dh, op, res);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;
        globus_bool_t                       canceled;

        XIOTestCreateOpWraper(ow, dh, op, res, 0);
        ow->type = GLOBUS_XIO_OPERATION_TYPE_OPEN;

        delay = &dh->delay;
        GlobusXIODriverEnableCancel(op, canceled, cancel_cb, ow);
        if(canceled)
        {
            delay = NULL;
        }
        else if(dh->random)
        {
            test_get_delay_time(dh, &end_time);
            delay = &end_time;
        }

        globus_callback_space_register_oneshot(
            &ow->callback_handle,
            delay,
            globus_l_xio_operation_kickout,
            (void *) ow,
            GLOBUS_CALLBACK_GLOBAL_SPACE);
    }

    return GLOBUS_SUCCESS;
}

/*
 *  close a file
 */
static
globus_result_t
globus_l_xio_test_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_l_xio_test_handle_t *        dh;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_test_close);

    dh = (globus_l_xio_test_handle_t *) driver_handle;

    if(dh->failure == GLOBUS_XIO_TEST_FAIL_PASS_CLOSE)
    {
        return GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_PASS_CLOSE);
    }
    else if(dh->failure == GLOBUS_XIO_TEST_FAIL_FINISH_CLOSE)
    {
        res = GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_FINISH_CLOSE);
    }

    if(dh->inline_finish)
    {
        test_inline_blocker(&dh->delay);
        GlobusXIODriverFinishedClose(op, res);
        globus_xio_driver_context_close(dh->context);
        globus_l_xio_test_attr_destroy(dh);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;
        globus_reltime_t *                  delay;
        globus_bool_t                       canceled;
        globus_reltime_t                    end_time;

        XIOTestCreateOpWraper(ow, dh, op, res, 0);
        ow->type = GLOBUS_XIO_OPERATION_TYPE_CLOSE;

        delay = &dh->delay;
        GlobusXIODriverEnableCancel(op, canceled, cancel_cb, ow);
        if(canceled)
        {
            delay = NULL;
        }
        else if(dh->random)
        {
            test_get_delay_time(dh, &end_time);
            delay = &end_time;
        }

        globus_callback_space_register_oneshot(
            &ow->callback_handle,
            delay,
            globus_l_xio_operation_kickout,
            (void *)ow,
            GLOBUS_CALLBACK_GLOBAL_SPACE);
    }

    return GLOBUS_SUCCESS;
}

/*
 *  read from a file
 */
static
globus_result_t
globus_l_xio_test_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_xio_test_handle_t *        dh;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_size_t                       nbytes;
    int                                 ctr;
    globus_size_t                       tb;
    GlobusXIOName(globus_l_xio_test_read);

    dh = (globus_l_xio_test_handle_t *) driver_handle;

    if(dh->failure == GLOBUS_XIO_TEST_FAIL_PASS_READ)
    {
        return GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_PASS_READ);
    }
    else if(dh->failure == GLOBUS_XIO_TEST_FAIL_FINISH_READ)
    {
        res = GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_FINISH_READ);
    }

    nbytes = dh->chunk_size;
    if(dh->chunk_size == -1)
    {
        nbytes = GlobusXIOOperationGetWaitFor(op);
    }

    tb = 0;
    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        tb += iovec[ctr].iov_len;
    }
    if(nbytes > tb)
    {
        nbytes = tb;
    }

    dh->bytes_read += nbytes;
    if(dh->read_nbytes != -1 && dh->bytes_read >= dh->read_nbytes)
    {
        res = GlobusXIOErrorEOF();
    }

    if(dh->inline_finish)
    {
        test_inline_blocker(&dh->delay);
        GlobusXIODriverFinishedRead(op, res, nbytes);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;
        globus_reltime_t *                  delay;
        globus_bool_t                       canceled;
        globus_reltime_t                    end_time;

        XIOTestCreateOpWraper(ow, dh, op, res, nbytes);
        ow->type = GLOBUS_XIO_OPERATION_TYPE_READ;

        delay = &dh->delay;
        GlobusXIODriverEnableCancel(op, canceled, cancel_cb, ow);
        if(canceled)
        {
            delay = NULL;
        }
        else if(dh->random)
        {
            test_get_delay_time(dh, &end_time);
            delay = &end_time;
        }
        globus_callback_space_register_oneshot(
            &ow->callback_handle,
            delay,
            globus_l_xio_operation_kickout,
            (void *)ow,
            GLOBUS_CALLBACK_GLOBAL_SPACE);
    }

    return GLOBUS_SUCCESS;
}

/*
 *  write to a file
 */
static
globus_result_t
globus_l_xio_test_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_xio_test_handle_t *        dh;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_size_t                       nbytes;
    int                                 ctr;
    globus_size_t                       tb;
    GlobusXIOName(globus_l_xio_test_write);
    
    dh = (globus_l_xio_test_handle_t *) driver_handle;
    
    if(dh->failure == GLOBUS_XIO_TEST_FAIL_PASS_WRITE)
    {
        return GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_PASS_WRITE);
    }
    else if(dh->failure == GLOBUS_XIO_TEST_FAIL_FINISH_WRITE)
    {
        res = GlobusXIOErrorTestError(GLOBUS_XIO_TEST_FAIL_FINISH_WRITE);
    }

    nbytes = dh->chunk_size;
    if(dh->chunk_size == -1)
    {
        nbytes = GlobusXIOOperationGetWaitFor(op);
    }

    tb = 0;
    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        tb += iovec[ctr].iov_len;
    }
    if(nbytes > tb)
    {
        nbytes = tb;
    }


    if(dh->inline_finish)
    {
        test_inline_blocker(&dh->delay);
        GlobusXIODriverFinishedWrite(op, res, nbytes);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;
        globus_reltime_t *                  delay;
        globus_bool_t                       canceled;
        globus_reltime_t                    end_time;

        XIOTestCreateOpWraper(ow, dh, op, res, nbytes);
        ow->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;

        delay = &dh->delay;
        GlobusXIODriverEnableCancel(op, canceled, cancel_cb, ow);
        if(canceled)
        {
            delay = NULL;
        }
        else if(dh->random)
        {
            test_get_delay_time(dh, &end_time);
            delay = &end_time;
        }
        globus_callback_space_register_oneshot(
            &ow->callback_handle,
            delay,
            globus_l_xio_operation_kickout,
            (void *)ow,
            GLOBUS_CALLBACK_GLOBAL_SPACE);
    }

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_test_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_test_transport_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "test", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_test_open,
        globus_l_xio_test_close,
        globus_l_xio_test_read,
        globus_l_xio_test_write,
        globus_l_xio_test_cntl);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_test_target_init,
        NULL,
        globus_l_xio_test_target_destroy);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_test_server_init,
        globus_l_xio_test_accept,
        globus_l_xio_test_server_destroy,
        globus_l_xio_test_server_cntl,
        globus_l_xio_test_target_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_test_attr_init,
        globus_l_xio_test_attr_copy,
        globus_l_xio_test_attr_cntl,
        globus_l_xio_test_attr_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_test_transport_unload(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}



static
int
globus_l_xio_test_activate(void)
{
    int                                 rc;
    globus_l_xio_test_handle_t *        attr;
    globus_condattr_t                   cond_attr;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    globus_callback_space_init(&globus_l_space, NULL);
    globus_condattr_init(&cond_attr);
    globus_condattr_setspace(&cond_attr, globus_l_space);
    globus_cond_init(&globus_l_cond, &cond_attr);
    globus_mutex_init(&globus_l_mutex, NULL);

    attr = &globus_l_default_attr;

    memset(attr, '\0', sizeof(globus_l_xio_test_handle_t));
    attr->inline_finish = GLOBUS_FALSE;
    attr->failure = 0;  /* default is no failures */
    GlobusTimeReltimeSet(attr->delay, 0, 0);
    attr->read_nbytes = -1; /* default is no EOF (close only) */
    attr->chunk_size = -1; /* default: entire chunk requested */

    return GLOBUS_SUCCESS;
}

static
int
globus_l_xio_test_deactivate(void)
{
    globus_callback_space_destroy(&globus_l_space);
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    test,
    &globus_i_xio_test_module,
    globus_l_xio_test_transport_load,
    globus_l_xio_test_transport_unload);
