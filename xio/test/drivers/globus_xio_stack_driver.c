/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_stack_driver.h"

static int
globus_l_xio_stack_activate();

static int
globus_l_xio_stack_deactivate();

#include "version.h"

GlobusXIODefineModule(stack) =
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
globus_l_xio_stack_init(
    globus_xio_driver_t *               out_driver)
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
globus_l_xio_stack_destroy(
    globus_xio_driver_t                 driver)
{
    globus_l_xio_stack_info_t *         stack_info;

    globus_xio_driver_get_user_data(driver, (void **)&stack_info);

    globus_xio_driver_unload(stack_info->debug_driver);
    globus_xio_driver_unload(stack_info->test_driver);
    globus_free(stack_info);
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    stack,
    globus_l_xio_stack_init,
    globus_l_xio_stack_destroy);

static
int
globus_l_xio_stack_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(stack);
    }
    return rc;
}

static
int
globus_l_xio_stack_deactivate(void)
{
    GlobusXIOUnRegisterDriver(stack);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
