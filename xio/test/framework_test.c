#include "globus_xio.h"


int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_xio_driver_t                     driver;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(res, __LINE__);

    res = globus_xio_stack_push_driver(stack, driver, NULL);
    test_res(res, __LINE__);

    res = globus_xio_target_init(&target, NULL, "whatever", stack);
    test_res(res, __LINE__);


    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    return 0;
}
