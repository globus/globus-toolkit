#include "globus_xio_driver.h"
#include "globus_xio_test_driver.h"

static int
globus_l_xio_test_activate();

static int
globus_l_xio_test_deactivate();

typedef struct globus_l_xio_test_attr_s
{
    globus_bool_t                       inline_finish;
    globus_bool_t                       failures;
    float                               nbyte_percent;
    globus_reltime_t                    delay;
} globus_l_xio_test_attr_t;

typedef struct globus_l_xio_test_handle_s
{
    globus_xio_driver_context_t         context;
    globus_xio_operation_t              op;
} globus_l_xio_test_handle_t;

static globus_l_xio_test_attr_t         globus_l_default_attr;

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

static
int
globus_l_xio_test_activate(void)
{
    globus_l_default_attr.inline = GLOBUS_FALSE;
    globus_l_default_attr.failure = GLOBUS_FALSE;
    GlobusTimeReltimeSet(globus_l_default_attr.delay, 0, 0);

    return globus_module_activate(GLOBUS_COMMON_MODULE);
}

static
int
globus_l_xio_test_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

/*
 *  initialize a driver attribute
 */
static
globus_result_t
globus_l_xio_test_attr_init(
    void **                             out_attr)
{
    globus_l_xio_test_attr_t *          attr;

    attr = (globus_l_xio_test_attr_t *)
                globus_malloc(sizeof(globus_l_xio_test_attr_t));
    memset(attr, '\0', sizeof(globus_l_xio_test_attr_t));

    *out_attr = attr;

    return GLOBUS_SUCCESS;
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
    globus_l_xio_test_attr_t *          attr;
    int                                 usecs;

    attr = (globus_l_xio_test_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_TEST_SET_INLINE:
            attr->inline_finish = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TEST_SET_FAILURES:
            attr->failures = va_arg(ap, int);
            break;

        case GLOBUS_XIO_FILE_SET_USECS:
            usecs = va_arg(ap, int);
            GlobusTimeRetimeSet(attr->delay, 0, usecs);
            *out_int = attr->mode;
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
    globus_l_xio_test_attr_t *          attr;

    attr = (globus_l_xio_test_attr_t *)
                globus_malloc(sizeof(globus_l_xio_test_attr_t));
    memcpy(attr, src, sizeof(globus_l_xio_test_attr_t));

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
    /* TODO: add failure cases */
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
    /* TODO: add failure cases */
    return GLOBUS_SUCCESS;
}

void
globus_l_xio_operation_kickout(
    void *                              user_arg)
{
    globus_l_xio_test_handle_t *        dh;
    globus_size_t                       nbytes;

    dh = (globus_l_xio_test_handle_t *) user_arg;

    /* this is kindof cheating */
    switch(dh->op->type)
    {
        case GLOBUS_XIO_OPERATION_TYPE_OPEN:
            GlobusXIODriverFinishedOpen(dh->context, dh, dh->op, \
                GLOBUS_SUCCESS);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_CLOSE:
            GlobusXIODriverFinishedClose(dh->op, GLOBUS_SUCCESS);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_READ:
            GlobusXIODriverFinishedRead(dh->op, GLOBUS_SUCCESS, nbytes);
            break;

        case GLOBUS_XIO_OPERATION_TYPE_WRITE:
            GlobusXIODriverFinishedWrite(dh->op, GLOBUS_SUCCESS, nbytes);
            break;
    }    

}
/*
 *  open a file
 */
static
globus_result_t
globus_l_xio_test_open(
    void **                             out_handle,
    void *                              driver_attr,
    void *                              driver_target,
    globus_xio_driver_context_t         context,
    globus_xio_driver_operation_t       op)
{
    /* TODO: add failure cases */
    globus_l_xio_test_attr_t *          attr;
    globus_l_xio_test_handle_t *        dh;

    attr = (globus_l_xio_test_attr_t *) driver_attr;

    dh = (globus_l_xio_test_handle_t *) globus_malloc(
            sizeof(globus_l_xio_test_handle_t));
    dh->op = op;
    dh->context = context;

    if(attr == NULL)
    {
        attr = &globus_l_default_attr;
    }

    if(attr->inline)
    {
        GlobusXIODriverFinishedOpen(context, 0x10, op, GLOBUS_SUCCESS);
    }
    else
    {
        globus_callback_space_register_oneshot(
            NULL,
            &attr->delay,
            globus_l_xio_operation_kickout,
            (void *)dh,
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
    globus_xio_driver_context_t         context,
    globus_xio_driver_operation_t       op)
{
    /* TODO: add failure cases */
    globus_l_xio_test_attr_t *          attr;
    globus_l_xio_test_handle_t *        dh;

    attr = (globus_l_xio_test_attr_t *) driver_attr;
    dh = (globus_l_xio_test_handle_t *) driver_handle;

    dh->op = op;
    if(attr == NULL)
    {
        attr = &globus_l_default_attr;
    }

    if(attr->inline)
    {
        GlobusXIODriverFinishedOpen(context, 0x10, op, GLOBUS_SUCCESS);
    }
    else
    {
        globus_callback_space_register_oneshot(
            NULL,
            &attr->delay,
            globus_l_xio_operation_kickout,
            (void *)dh,
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
    globus_xio_driver_operation_t       op)
{
    /* TODO: add failure cases */
    globus_l_xio_test_attr_t *          attr;
    globus_l_xio_test_handle_t *        dh;

    attr = (globus_l_xio_test_attr_t *) driver_attr;
    dh = (globus_l_xio_test_handle_t *) driver_handle;

    dh->op = op;
    if(attr == NULL)
    {
        attr = &globus_l_default_attr;
    }

    if(attr->inline)
    {
        GlobusXIODriverFinishedOpen(context, 0x10, op, GLOBUS_SUCCESS);
    }
    else
    {
        globus_callback_space_register_oneshot(
            NULL,
            &attr->delay,
            globus_l_xio_operation_kickout,
            (void *)dh,
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
    globus_xio_driver_operation_t       op)
{
    /* TODO: add failure cases */
    globus_l_xio_test_attr_t *          attr;
    globus_l_xio_test_handle_t *        dh;

    attr = (globus_l_xio_test_attr_t *) driver_attr;
    dh = (globus_l_xio_test_handle_t *) driver_handle;

    dh->op = op;
    if(attr == NULL)
    {
        attr = &globus_l_default_attr;
    }

    if(attr->inline)
    {
        GlobusXIODriverFinishedOpen(context, 0x10, op, GLOBUS_SUCCESS);
    }
    else
    {
        globus_callback_space_register_oneshot(
            NULL,
            &attr->delay,
            globus_l_xio_operation_kickout,
            (void *)dh,
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
    /* TODO: add failure cases */
    return GLOBUS_SUCCESS;
}

static globus_xio_driver_t globus_l_xio_test_info =
{
    /*
     *  main io interface functions
     */
    globus_l_xio_test_open,                      /* open_func           */
    globus_l_xio_test_close,                     /* close_func          */
    globus_l_xio_test_read,                      /* read_func           */
    globus_l_xio_test_write,                     /* write_func          */
    globus_l_xio_test_cntl,                      /* handle_cntl_func    */

    globus_l_xio_test_target_init,               /* target_init_func    */
    globus_l_xio_test_target_destory,            /* target_destroy_finc */

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
