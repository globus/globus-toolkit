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
#include "globus_xio_null_pass.h"

static int
globus_l_xio_null_pass_activate();

static int
globus_l_xio_null_pass_deactivate();

#include "version.h"

GlobusXIODefineModule(null_pass) =
{
    "globus_xio_null_pass",
    globus_l_xio_null_pass_activate,
    globus_l_xio_null_pass_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


static globus_result_t
globus_l_xio_null_pass_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    return globus_xio_driver_pass_server_init(op, contact_info, NULL);
}

static globus_result_t
globus_l_xio_null_pass_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;

    res = globus_xio_driver_pass_accept(accept_op, NULL, NULL);

    return res;
}

static globus_result_t
globus_l_xio_null_pass_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_null_pass_server_destroy(
    void *                              driver_server)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_null_pass_link_destroy(
    void *                              driver_link)
{
    return GLOBUS_SUCCESS;
}



/*
 *  open
 */
static
globus_result_t
globus_l_xio_null_pass_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
  
    res = globus_xio_driver_pass_open(op, contact_info, NULL, NULL);

    return res;
}

/*
 *  close
 */
static
globus_result_t
globus_l_xio_null_pass_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;

    res = globus_xio_driver_pass_close(op, NULL, NULL);

    return res;
}

/*
 *  read
 */
static
globus_result_t
globus_l_xio_null_pass_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_read(op, 
        (globus_xio_iovec_t *)iovec, iovec_count, wait_for, NULL, NULL);

    return res;
}

/*
 *  write
 */
static
globus_result_t
globus_l_xio_null_pass_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_write(op, 
        (globus_xio_iovec_t *)iovec, iovec_count, wait_for, NULL, NULL);

    return res;
}

static
globus_result_t
globus_l_xio_null_pass_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_null_pass_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "null_pass", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_null_pass_open,
        globus_l_xio_null_pass_close,
        globus_l_xio_null_pass_read,
        globus_l_xio_null_pass_write,
        globus_l_xio_null_pass_cntl,
        NULL);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_null_pass_server_init,
        globus_l_xio_null_pass_accept,
        globus_l_xio_null_pass_server_destroy,
        globus_l_xio_null_pass_server_cntl,
        NULL,
        globus_l_xio_null_pass_link_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_null_pass_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    null_pass,
    globus_l_xio_null_pass_init,
    globus_l_xio_null_pass_destroy);

static
int
globus_l_xio_null_pass_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(null_pass);
    }
    return rc;
}

static
int
globus_l_xio_null_pass_deactivate(void)
{
    GlobusXIOUnRegisterDriver(null_pass);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
