#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

static globus_mutex_t                   globus_l_mutex;
static globus_cond_t                    globus_l_cond;
static globus_bool_t                    globus_l_closed = GLOBUS_FALSE;

#define OP_COUNT                            16

static void
close_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
data_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        if(result == GLOBUS_SUCCESS)
        {
            printf("WARINING: data allback should have a failure code\n");
        }
        if(globus_l_closed)
        {
            failed_exit("the close callback occurred prior to all data"
                        "callbacks returning");
        }
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
open_cb2(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    return;
}

static void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;
    int                                         ctr;
    globus_byte_t *                             buffer;
    globus_size_t                               buffer_length;

    buffer = globus_l_test_info.buffer;
    buffer_length = globus_l_test_info.buffer_length;

    globus_mutex_lock(&globus_l_mutex);
    {
        for(ctr = 0; ctr < OP_COUNT; ctr++)
        {

            res = globus_xio_register_write(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    data_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

            res = globus_xio_register_read(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    data_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
        }
        res = globus_xio_register_close(
                handle,
                NULL,
                close_cb,
                user_arg);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

int
close_cancel_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_xio_target_t                     target;
    globus_result_t                         res;
    globus_xio_attr_t                       attr;

    globus_l_closed = GLOBUS_FALSE;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    parse_parameters(argc, argv, stack, attr);

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, NULL);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_register_open(
            &handle,
            attr,
            target,
            open_cb,
            NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    globus_l_closed = GLOBUS_FALSE;
    res = globus_xio_register_open(
            &handle,
            attr,
            target,
            open_cb2,
            NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_register_close(
            handle,
            NULL,
            close_cb,
            NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    res = globus_xio_attr_destroy(attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    test_common_end();

    globus_mutex_destroy(&globus_l_mutex);
    globus_cond_destroy(&globus_l_cond);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}
