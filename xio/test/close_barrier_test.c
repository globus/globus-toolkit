#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

static globus_mutex_t                   globus_l_mutex;
static globus_cond_t                    globus_l_cond;
static globus_bool_t                    globus_l_close_called = GLOBUS_FALSE;
static globus_bool_t                    globus_l_closed = GLOBUS_FALSE;

#define OP_COUNT                            8
#define SLEEP_TIME                          3

void
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

void
data_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    globus_result_t                             res;

    globus_mutex_lock(&globus_l_mutex);
    {
        if(!globus_l_close_called)
        {
            globus_l_close_called = GLOBUS_TRUE;
            res = globus_xio_register_close(
                    handle,
                    NULL,
                    close_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_thread_blocking_will_block();
    sleep(SLEEP_TIME);

    globus_mutex_lock(&globus_l_mutex);
    {
        if(globus_l_closed)
        {
            failed_exit("the close callback occurred prior to all data"
                        "callbacks returning");
        }
    }
    globus_mutex_unlock(&globus_l_mutex);
}

void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;
    int                                         ctr;
    globus_byte_t *                             buffer;
    globus_size_t                               buffer_length = 1024;

    for(ctr = 0; ctr < OP_COUNT; ctr++)
    {
        if(globus_l_test_info.write_count > 0)
        {
            res = globus_xio_register_write(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    data_cb,
                    user_arg);
        }
        else
        {
            res = globus_xio_register_read(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    data_cb,
                    user_arg);
        }
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    }
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_xio_driver_t                     driver;
    globus_xio_target_t                     target;
    globus_result_t                         res;
    globus_abstime_t                        end_time;
    globus_xio_attr_t                       attr;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    rc = globus_module_activate(GLOBUS_XIO_TEST_TRANSPORT_DRIVER_MODULE);
    globus_assert(rc == 0);

    globus_xio_driver_load("test", &driver);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    parse_parameters(argc, argv, driver, attr);

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, NULL);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_push_driver(stack, driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

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
        GlobusTimeAbstimeSet(end_time, SLEEP_TIME, 0);
        globus_cond_timedwait(&globus_l_cond, &globus_l_mutex, &end_time);
    }
    globus_mutex_unlock(&globus_l_mutex);
    
    globus_xio_driver_unload("test", &driver);
    
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}
