#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_null.h"

static int
globus_l_xio_null_activate();

static int
globus_l_xio_null_deactivate();

#include "version.h"

GlobusXIODefineModule(null) =
{
    "globus_xio_null",
    globus_l_xio_null_activate,
    globus_l_xio_null_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static globus_result_t
globus_l_xio_null_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "null", NULL);
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
	NULL);

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
globus_l_xio_null_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    null,
    globus_l_xio_null_init,
    globus_l_xio_null_destroy);

static
int
globus_l_xio_null_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(null);
    }
    return rc;
}

static
int
globus_l_xio_null_deactivate(void)
{
    GlobusXIOUnRegisterDriver(null);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
