#include "globus_common.h"

static
int
globus_l_test_module_activate(void);

static
int
globus_l_test_module_deactivate(void);

globus_module_descriptor_t              globus_scheduler_event_module_ptr =
{
    "test module",
    globus_l_test_module_activate,
    globus_l_test_module_deactivate,
    NULL,
    NULL,
    NULL,
    NULL
};

int
globus_l_test_module_activate(void)
{
    printf("ok\n");
    return 0;
}

int
globus_l_test_module_deactivate(void)
{
    printf("ok\n");
    return 0;
}

/* main() */
