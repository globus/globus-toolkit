#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

#define OP_COUNT 8

static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_closed = GLOBUS_FALSE;
static globus_bool_t                        globus_l_close_called=GLOBUS_FALSE;

static void
data_close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_xio_close(handle, NULL);
}

int
unload_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     test_driver;
    globus_xio_driver_t                     debug_driver;
    globus_xio_driver_t                     bounce_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_xio_target_t                     target;
    globus_result_t                         res;
    globus_condattr_t                       condattr;

    globus_l_closed = GLOBUS_FALSE;
    globus_l_close_called = GLOBUS_FALSE;

    /*
     *  activate once
     */
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_load("test", &test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_driver_load("debug", &debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_push_driver(stack, test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, &condattr);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_open(
            &handle,
            NULL,
            target);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    /*
     *  activate twice
     */
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    res = globus_xio_driver_load("test", &test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_driver_load("debug", &debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_driver_load("bounce", &bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_push_driver(stack, test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_open(
            &handle,
            NULL,
            target);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_register_read(
        handle,
        globus_l_test_info.buffer,
        globus_l_test_info.buffer_length,
        globus_l_test_info.buffer_length,
        NULL,
        data_close_cb,
        NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_register_write(
        handle,
        globus_l_test_info.buffer,
        globus_l_test_info.buffer_length,
        globus_l_test_info.buffer_length,
        NULL,
        NULL,
        NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}
