#include "globus_xio_driver.h"
#include "globus_common.h"

#define XIOTestCreateOpWraper(ow, dh, op, res, nb)                      \
{                                                                       \
    ow = (globus_l_xio_test_op_wrapper_t *)                             \
            globus_malloc(sizeof(globus_l_xio_test_op_wrapper_t));      \
    ow->dh = dh;                                                        \
    ow->op = op;                                                        \
    ow->res = res;                                                      \
    ow->nbytes = nb;                                                    \
}

enum
{
    GLOBUS_XIO_TEST_SET_INLINE,
    GLOBUS_XIO_TEST_SET_FAILURES,
    GLOBUS_XIO_TEST_SET_USECS,
    GLOBUS_XIO_TEST_READ_EOF_BYTES,
    GLOBUS_XIO_TEST_CHUNK_SIZE,
};

typedef enum globus_xio_test_failure_e
{
    GLOBUS_XIO_TEST_FAIL_PASS_OPEN = 0x01,
    GLOBUS_XIO_TEST_FAIL_FINISH_OPEN = 0x02,
    GLOBUS_XIO_TEST_FAIL_PASS_CLOSE = 0x04,
    GLOBUS_XIO_TEST_FAIL_FINISH_CLOSE = 0x08,
    GLOBUS_XIO_TEST_FAIL_PASS_READ = 0x10,
    GLOBUS_XIO_TEST_FAIL_FINISH_READ = 0x20,
    GLOBUS_XIO_TEST_FAIL_PASS_WRITE = 0x40,
    GLOBUS_XIO_TEST_FAIL_FINISH_WRITE = 0x80,
} globus_xio_test_failure_t;

static int
globus_l_xio_test_activate();

static int
globus_l_xio_test_deactivate();

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
} globus_l_xio_test_handle_t;

typedef struct globus_l_xio_test_op_wrapper_s
{
    globus_xio_operation_t              op;
    globus_l_xio_test_handle_t *        dh;
    globus_result_t                     res;
    globus_size_t                       nbytes;
} globus_l_xio_test_op_wrapper_t;


static globus_l_xio_test_handle_t       globus_l_default_attr;

#include "version.h"

globus_module_descriptor_t              globus_i_xio_test_module =
{
    "globus_xio_test",
    globus_l_xio_test_activate,
    globus_l_xio_test_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

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

static
int
globus_l_xio_test_activate(void)
{
    int                                 rc;
    globus_l_xio_test_handle_t *        attr;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    attr = &globus_l_default_attr;

    memset(attr, '\0', sizeof(globus_l_xio_test_handle_t));
    attr->inline_finish = GLOBUS_FALSE;
    attr->failure = 0;  /* default is no failures */
    GlobusTimeReltimeSet(attr->delay, 0, 0);
    attr->read_nbytes = -1; /* default is no EOF (close only) */
    attr->chunk_size = -1; /* default: entire chunk requested */

    return rc;
}

static
int
globus_l_xio_test_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
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

void
globus_l_xio_operation_kickout(
    void *                              user_arg)
{
    globus_l_xio_test_op_wrapper_t *    ow;
    globus_size_t                       nbytes;

    ow = (globus_l_xio_test_op_wrapper_t *) user_arg;

    /* this is kindof cheating */
    switch(ow->op->type)
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

        default:
            globus_assert(0);
    }    

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
    globus_result_t                     res;

    attr = (globus_l_xio_test_handle_t *) driver_attr;

    if(attr == NULL)
    {
        attr = &globus_l_default_attr;
    }

    /* copy the attr to a handle */
    globus_l_xio_test_attr_copy((void **)&dh, attr);
    dh->context = context;

    if(dh->failure | GLOBUS_XIO_TEST_FAIL_PASS_OPEN)
    {
        return GlobusXIOErrorLazy();
    }
    else if(dh->failure | GLOBUS_XIO_TEST_FAIL_FINISH_OPEN)
    {
        res = GlobusXIOErrorLazy();
    }

    if(dh->inline_finish)
    {
        GlobusXIODriverFinishedOpen(context, dh, op, res);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;

        XIOTestCreateOpWraper(ow, dh, op, res, 0);

        globus_callback_space_register_oneshot(
            NULL,
            &dh->delay,
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

    dh = (globus_l_xio_test_handle_t *) driver_handle;

    if(dh->failure | GLOBUS_XIO_TEST_FAIL_PASS_CLOSE)
    {
        return GlobusXIOErrorLazy();
    }
    else if(dh->failure | GLOBUS_XIO_TEST_FAIL_FINISH_CLOSE)
    {
        res = GlobusXIOErrorLazy();
    }

    if(dh->inline_finish)
    {
        GlobusXIODriverFinishedClose(op, res);
        globus_l_xio_test_attr_destroy(dh);
        globus_xio_driver_context_close(dh->context);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;

        XIOTestCreateOpWraper(ow, dh, op, res, 0);
        globus_callback_space_register_oneshot(
            NULL,
            &dh->delay,
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

    dh = (globus_l_xio_test_handle_t *) driver_handle;

    if(dh->failure | GLOBUS_XIO_TEST_FAIL_PASS_READ)
    {
        return GlobusXIOErrorLazy();
    }
    else if(dh->failure | GLOBUS_XIO_TEST_FAIL_FINISH_READ)
    {
        res = GlobusXIOErrorLazy();
    }

    nbytes = dh->chunk_size;
    if(dh->chunk_size == -1)
    {
        GlobusXIOOperationWaitFor(op, nbytes);
    }

    dh->bytes_read += nbytes;
    if(dh->read_nbytes != -1 && dh->bytes_read >= dh->read_nbytes)
    {
        res = GlobusXIOErrorReadEOF();
    }

    if(dh->inline_finish)
    {
        GlobusXIODriverFinishedRead(op, res, nbytes);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;

        XIOTestCreateOpWraper(ow, dh, op, res, nbytes);
        globus_callback_space_register_oneshot(
            NULL,
            &dh->delay,
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
    
    dh = (globus_l_xio_test_handle_t *) driver_handle;
    
    if(dh->failure | GLOBUS_XIO_TEST_FAIL_PASS_WRITE)
    {
        return GlobusXIOErrorLazy();
    }
    else if(dh->failure | GLOBUS_XIO_TEST_FAIL_FINISH_WRITE)
    {
        res = GlobusXIOErrorLazy();
    }

    nbytes = dh->chunk_size;
    if(dh->chunk_size == -1)
    {
        GlobusXIOOperationWaitFor(op, nbytes);
    }

    if(dh->inline_finish)
    {
        GlobusXIODriverFinishedWrite(op, res, nbytes);
    }
    else
    {
        globus_l_xio_test_op_wrapper_t *    ow;

        XIOTestCreateOpWraper(ow, dh, op, res, nbytes);
        globus_callback_space_register_oneshot(
            NULL,
            &dh->delay,
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

static struct globus_i_xio_driver_s globus_l_xio_test_info =
{
    /*
     *  main io interface functions
     */
    NULL,
    globus_l_xio_test_open,                      /* open_func           */
    globus_l_xio_test_close,                     /* close_func          */
    globus_l_xio_test_read,                      /* read_func           */
    globus_l_xio_test_write,                     /* write_func          */
    globus_l_xio_test_cntl,                      /* handle_cntl_func    */

    globus_l_xio_test_target_init,               /* target_init_func    */
    NULL,
    globus_l_xio_test_target_destroy,            /* target_destroy_finc */

    /*
     *  No server functions.
     */
    NULL,                                        /* server_init_func    */
    NULL,                                        /* server_accept_func  */
    NULL,                                        /* server_destroy_func */
    NULL,                                        /* server_cntl_func    */

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_l_xio_test_attr_init,                 /* attr_init_func      */
    globus_l_xio_test_attr_copy,                 /* attr_copy_func      */
    globus_l_xio_test_attr_cntl,                 /* attr_cntl_func      */
    globus_l_xio_test_attr_destroy,              /* attr_destroy_func   */
};
