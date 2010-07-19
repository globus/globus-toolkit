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
#include "globus_xio_debug.h"

static int
globus_l_xio_debug_activate();

static int
globus_l_xio_debug_deactivate();

#include "version.h"

GlobusXIODefineModule(debug) =
{
    "globus_xio_debug",
    globus_l_xio_debug_activate,
    globus_l_xio_debug_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static void
debug_driver_log(
    char *                              fmt,
    ...)
{
    va_list                             ap;

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, fmt);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    fprintf(stderr, "DEBUG DRIVER: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");

    va_end(ap);
}

static globus_result_t
globus_l_xio_debug_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    debug_driver_log("server init");
    return globus_xio_driver_pass_server_init(op, contact_info, NULL);
}

void
globus_l_xio_debug_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    debug_driver_log("finished accept");
    globus_xio_driver_finished_accept(op, NULL, result);
}

static globus_result_t
globus_l_xio_debug_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;

    debug_driver_log("finished accept");

    res = globus_xio_driver_pass_accept(accept_op,
        globus_l_xio_debug_accept_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_debug_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    debug_driver_log("server cntl");

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_debug_server_destroy(
    void *                              driver_server)
{
    debug_driver_log("server destroy");

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_debug_link_destroy(
    void *                              driver_link)
{
    debug_driver_log("link destroy");

    return GLOBUS_SUCCESS;
}



/*
 *  open
 */
void
globus_l_xio_debug_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    debug_driver_log("finished open");

    globus_xio_driver_finished_open(NULL, op, result);
}   

static
globus_result_t
globus_l_xio_debug_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    
    debug_driver_log("open");

    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_debug_open_cb, NULL);

    return res;
}

/*
 *  close
 */
void
globus_l_xio_debug_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    debug_driver_log("finished close");
    globus_xio_driver_finished_close(op, result);
}   

static
globus_result_t
globus_l_xio_debug_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;

    debug_driver_log("close");

    res = globus_xio_driver_pass_close(op,
        globus_l_xio_debug_close_cb, NULL);

    return res;
}

/*
 *  read
 */
void
globus_l_xio_debug_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    debug_driver_log("finished read");

    globus_xio_driver_finished_read(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_debug_read(
    void *                              driver_spcific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    debug_driver_log("read");

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_read(op, 
        (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_debug_read_cb, NULL);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_debug_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    debug_driver_log("finished write");

    globus_xio_driver_finished_write(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_debug_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    debug_driver_log("write");

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_write(op, 
        (globus_xio_iovec_t *) iovec, iovec_count, wait_for,
        globus_l_xio_debug_write_cb, NULL);

    return res;
}

static
globus_result_t
globus_l_xio_debug_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    debug_driver_log("handle cntl");

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_debug_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "debug", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_debug_open,
        globus_l_xio_debug_close,
        globus_l_xio_debug_read,
        globus_l_xio_debug_write,
        globus_l_xio_debug_cntl,
        NULL);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_debug_server_init,
        globus_l_xio_debug_accept,
        globus_l_xio_debug_server_destroy,
        globus_l_xio_debug_server_cntl,
        NULL,
        globus_l_xio_debug_link_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_debug_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    debug,
    globus_l_xio_debug_init,
    globus_l_xio_debug_destroy);

static
int
globus_l_xio_debug_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(debug);
    }
    
    return rc;
}

static
int
globus_l_xio_debug_deactivate(void)
{
    GlobusXIOUnRegisterDriver(debug);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
