#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_stack_driver.h"

static int
globus_l_xio_stack_activate();

static int
globus_l_xio_stack_deactivate();

#include "version.h"

globus_module_descriptor_t  globus_i_xio_stack_module =
{
    "globus_xio_stack",
    globus_l_xio_stack_activate,
    globus_l_xio_stack_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef struct globus_l_xio_stack_info_s
{
    globus_xio_driver_t                 debug_driver;
    globus_xio_driver_t                 test_driver;
} globus_l_xio_stack_info_t;

static globus_result_t
globus_l_xio_stack_push(
    globus_xio_driver_t                 driver,
    globus_xio_stack_t                  stack)
{
    globus_l_xio_stack_info_t *         stack_info;

    globus_xio_driver_get_user_data(driver, (void **)&stack_info);

    globus_xio_stack_push_driver(stack, stack_info->test_driver);
    globus_xio_stack_push_driver(stack, stack_info->debug_driver);

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_stack_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;
    globus_l_xio_stack_info_t *         stack_info;

    stack_info = globus_malloc(sizeof(globus_l_xio_stack_info_t));
    globus_xio_driver_load("debug", &stack_info->debug_driver);
    globus_xio_driver_load("test", &stack_info->test_driver);

    res = globus_xio_driver_init(&driver, "stack", stack_info);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        globus_l_xio_stack_push);

    globus_xio_driver_set_server(
        driver,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_stack_unload(
    globus_xio_driver_t                 driver)
{
    globus_l_xio_stack_info_t *         stack_info;

    globus_xio_driver_get_user_data(driver, (void **)&stack_info);

    globus_xio_driver_unload(stack_info->debug_driver);
    globus_xio_driver_unload(stack_info->test_driver);
    globus_free(stack_info);
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_stack_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return rc;
}

static
int
globus_l_xio_stack_deactivate(void)
{
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    stack,
    &globus_i_xio_stack_module,
    globus_l_xio_stack_load,
    globus_l_xio_stack_unload);
