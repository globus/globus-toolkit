#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

#define OP_COUNT 8

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
    globus_byte_t                           buffer[1024];

    /*
     *  activate once
     */
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    /* simple unload test */
    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_load("test", &test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_open(
            &handle,
            NULL,
            target);

    res = globus_xio_driver_unload(test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    fprintf(stderr, "succes\n"); fflush(stderr);

    /* outstanding open unload test */
    fprintf(stderr, "Outstanding open test..."); fflush(stderr);
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

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_register_open(
            &handle,
            NULL,
            target,
            NULL,
            NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_driver_unload(test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    fprintf(stderr, "succes\n"); fflush(stderr);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);
    /*
     *  activate twice
     */
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    /* outstanding operation test */
    fprintf(stderr, "Outstanding operation test..."); fflush(stderr);
    res = globus_xio_driver_load("test", &test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_driver_load("debug", &debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_driver_load("bounce", &bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_stack_push_driver(stack, test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_open(
            &handle,
            NULL,
            target);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_register_read(
        handle,
        buffer,
        sizeof(buffer),
        sizeof(buffer),
        NULL,
        data_close_cb,
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
