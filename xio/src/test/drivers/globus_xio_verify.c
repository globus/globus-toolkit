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
#include "globus_xio_verify.h"

#define _SERVER "test_server_string"
#define _LINK "test_link_string"
#define _HANDLE "test_handle_string"
#define _ATTR   "test_attr_string"

static int
globus_l_xio_verify_activate();

static int
globus_l_xio_verify_deactivate();

#include "version.h"

GlobusXIODefineModule(verify) =
{
    "globus_xio_verify",
    globus_l_xio_verify_activate,
    globus_l_xio_verify_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


static globus_result_t
globus_l_xio_verify_attr_init(
    void **                             out_attr)
{
    *out_attr = (void *) strdup(_ATTR);

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_verify_attr_destroy(
    void *                              driver_attr)
{
    char *                              tst_str;

    tst_str = (char *) driver_attr;

    if(strcmp(tst_str, _ATTR) != 0)
    {
        globus_assert(!"Attr string doesn't match");
    }
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_verify_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              tst_str;

    tst_str = (char *) driver_attr;

    if(strcmp(tst_str, _ATTR) != 0)
    {
        globus_assert(!"Attr string doesn't match");
    }

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_verify_attr_copy(
    void **                             dst,
    void *                              src)
{
    char *                              tst_str;

    tst_str = (char *) dst;

    if(strcmp(tst_str, _ATTR) != 0)
    {
        globus_assert(!"Attr string doesn't match");
    }

    *dst = (void *) strdup(_ATTR);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_verify_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    return globus_xio_driver_pass_server_init(
        op, contact_info, strdup(_SERVER));
}

static globus_result_t
globus_l_xio_verify_link_destroy(
    void *                              driver_link)
{
    char *                              tst_str;

    tst_str = (char *) driver_link;
    if(strcmp(tst_str, _LINK) != 0)
    {
        globus_assert(!"Link string doesn't match");
    }
    free(tst_str);

    return GLOBUS_SUCCESS;
}


void
globus_l_xio_verify_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_accept(op, strdup(_LINK), result);
}

static globus_result_t
globus_l_xio_verify_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;
    char *                              tst_str;

    tst_str = (char *) driver_server;
    if(strcmp(tst_str, _SERVER) != 0)
    {
        globus_assert(!"Server string doesn't match");
    }

    res = globus_xio_driver_pass_accept(accept_op,
        globus_l_xio_verify_accept_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_verify_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    char *                              tst_str;

    tst_str = (char *) driver_server;
    if(strcmp(tst_str, _SERVER) != 0)
    {
        globus_assert(!"Server string doesn't match");
    }

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_verify_server_destroy(
    void *                              driver_server)
{
    char *                              tst_str;

    tst_str = (char *) driver_server;
    if(strcmp(tst_str, _SERVER) != 0)
    {
        globus_assert(!"Server string doesn't match");
    }

    free(tst_str);

    return GLOBUS_SUCCESS;
}

/*
 *  open
 */
void
globus_l_xio_verify_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_open(strdup(_HANDLE), op, result);
}   

static
globus_result_t
globus_l_xio_verify_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    char *                              tst_str;

    tst_str = (char *) driver_link;
    if(tst_str && strcmp(tst_str, _LINK) != 0)
    {
        globus_assert(!"Server string doesn't match");
    }

    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_verify_open_cb, NULL);

    return res;
}

/*
 *  close
 */
void
globus_l_xio_verify_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    globus_xio_driver_finished_close(op, result);
}   

static
globus_result_t
globus_l_xio_verify_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    char *                              tst_str;

    tst_str = (char *) driver_specific_handle;
    if(strcmp(tst_str, _HANDLE) != 0)
    {
        globus_assert(!"Handle string doesn't match");
    }

    res = globus_xio_driver_pass_close(op,
        globus_l_xio_verify_close_cb, NULL);

    globus_free(tst_str);

    return res;
}

/*
 *  read
 */
void
globus_l_xio_verify_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_read(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_verify_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    char *                              tst_str;

    tst_str = (char *) driver_specific_handle;
    if(strcmp(tst_str, _HANDLE) != 0)
    {
        globus_assert(!"Handle string doesn't match");
    }

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_read(op, (globus_xio_iovec_t *)iovec, 
        iovec_count, wait_for,
        globus_l_xio_verify_read_cb, NULL);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_verify_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_write(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_verify_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    char *                              tst_str;

    tst_str = (char *) driver_specific_handle;
    if(strcmp(tst_str, _HANDLE) != 0)
    {
        globus_assert(!"Handle string doesn't match");
    }

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_write( 
        op, (globus_xio_iovec_t *) iovec, iovec_count, wait_for, 
        globus_l_xio_verify_write_cb, NULL);

    return res;
}

static
globus_result_t
globus_l_xio_verify_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    char *                              tst_str;

    tst_str = (char *) driver_specific_handle;
    if(strcmp(tst_str, _HANDLE) != 0)
    {
        globus_assert(!"Handle string doesn't match");
    }
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_verify_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "verify", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_verify_open,
        globus_l_xio_verify_close,
        globus_l_xio_verify_read,
        globus_l_xio_verify_write,
        globus_l_xio_verify_cntl,
        NULL);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_verify_server_init,
        globus_l_xio_verify_accept,
        globus_l_xio_verify_server_destroy,
        globus_l_xio_verify_server_cntl,
        NULL,
        globus_l_xio_verify_link_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_verify_attr_init,
        globus_l_xio_verify_attr_copy,
        globus_l_xio_verify_attr_cntl,
        globus_l_xio_verify_attr_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_verify_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    verify,
    globus_l_xio_verify_init,
    globus_l_xio_verify_destroy);

static
int
globus_l_xio_verify_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(verify);
    }
    return rc;
}

static
int
globus_l_xio_verify_deactivate(void)
{
    GlobusXIOUnRegisterDriver(verify);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
