#include "globus_i_xio.h"

globus_result_t
globus_xio_stack_init(
    globus_xio_stack_t *                        stack,
    globus_xio_attr_t                           stack_attr)
{

    l_stack->driver_stack = NULL;
}

globus_result_t
globus_xio_stack_push_driver(
    globus_xio_stack_t                          stack,
    globus_xio_driver_t                         driver)
{
    globus_list_insert(&l_stack->driver_stack, driver);
}

globus_result_t
globus_xio_stack_destroy(
    globus_xio_stack_t                          stack)
{
    globus_list_free(&l_stack->driver_stack);
}

