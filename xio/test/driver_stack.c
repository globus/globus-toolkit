#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_stack_driver.h"

int
stack_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     stack_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_xio_target_t                     target;
    globus_result_t                         res;
    globus_byte_t                           buffer[1024];

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    /* simple unload test */
    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_driver_load("stack", &stack_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_push_driver(stack, stack_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_open(
        &handle,
        NULL,
        target);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_write(
            handle,
            buffer,
            sizeof(buffer),
            sizeof(buffer),
            NULL,
            NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_close(handle, NULL);

    res = globus_xio_driver_unload(stack_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}
