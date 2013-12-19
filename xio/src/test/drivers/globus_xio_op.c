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
#include "globus_xio_op.h"

static int
globus_l_xio_op_activate();

static int
globus_l_xio_op_deactivate();

void
globus_l_xio_op_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

void
globus_l_xio_op_obb_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

typedef struct globus_l_xio_op_handle_s
{
    int                                 count;
    globus_mutex_t                      mutex;
    globus_xio_iovec_t                  iovec;
    globus_byte_t                       bs_buf[1];

    globus_xio_operation_t              close_op;
    globus_xio_driver_handle_t          driver_handle;
} globus_l_xio_op_handle_t;

#include "version.h"

GlobusXIODefineModule(op) =
{
    "globus_xio_op",
    globus_l_xio_op_activate,
    globus_l_xio_op_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 *  read
 */
void
globus_l_xio_op_obb_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_xio_op_handle_t *          op_handle;
    globus_result_t                     res;
    globus_bool_t                       done = GLOBUS_FALSE;

    op_handle = (globus_l_xio_op_handle_t *) user_arg;

    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->count++;
        if(op_handle->count < 10 && result == GLOBUS_SUCCESS)
        {
            res = globus_xio_driver_pass_read(op, 
                &op_handle->iovec, 1, 1,
                globus_l_xio_op_obb_read_cb, op_handle);

            if(res != GLOBUS_SUCCESS)
            {
                result = res;
                done = GLOBUS_TRUE;
            }
        }
        else
        {
            done = GLOBUS_TRUE;
        }

        if(done)
        {
            op_handle->count = 10; /* fake close into working */
            globus_xio_driver_operation_destroy(op);
            if(op_handle->close_op != NULL)
            {
                res = globus_xio_driver_pass_close(op_handle->close_op,
                    globus_l_xio_op_close_cb, op_handle);
            }
        }
    }
    globus_mutex_unlock(&op_handle->mutex);
}

void
globus_l_xio_op_obb_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_xio_op_handle_t *          op_handle;
    globus_result_t                     res;

    op_handle = (globus_l_xio_op_handle_t *) user_arg;

    res = globus_xio_driver_pass_write(op, 
        &op_handle->iovec, 
        1, 1,
        globus_l_xio_op_obb_write_cb, op_handle);

    if(res != GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&op_handle->mutex);
        {
            op_handle->count = 10; /* fake close into working */
            globus_xio_driver_operation_destroy(op);
            if(op_handle->close_op != NULL)
            {
                res = globus_xio_driver_pass_close(op_handle->close_op,
                    globus_l_xio_op_close_cb, op_handle);
            }
        }
        globus_mutex_unlock(&op_handle->mutex);
    }
}


/*
 *  open
 */
void
globus_l_xio_op_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_op_handle_t *          op_handle = NULL;
    globus_xio_operation_t              driver_op;

    if(result == GLOBUS_SUCCESS)
    {
        op_handle = (globus_l_xio_op_handle_t *) 
            globus_malloc(sizeof(globus_l_xio_op_handle_t));
        op_handle->count = 0;
        op_handle->iovec.iov_base = &op_handle->bs_buf;
        op_handle->iovec.iov_len = 1;
        op_handle->close_op = NULL;
        op_handle->driver_handle = globus_xio_operation_get_driver_handle(op);

        globus_mutex_init(&op_handle->mutex, NULL);

        result = globus_xio_driver_operation_create(
            &driver_op, op_handle->driver_handle);
        if(result == GLOBUS_SUCCESS)
        {
            result = globus_xio_driver_pass_read(driver_op, 
                &op_handle->iovec, 1, 1,
                globus_l_xio_op_obb_read_cb, op_handle);
        }
    }

    globus_xio_driver_finished_open(op_handle, op, result);
}   

static
globus_result_t
globus_l_xio_op_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
  
    res = globus_xio_driver_pass_open(op, contact_info,
        globus_l_xio_op_open_cb, NULL);

    return res;
}

/*
 *  close
 */
void
globus_l_xio_op_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    globus_xio_driver_finished_close(op, result);
}   

static
globus_result_t
globus_l_xio_op_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_l_xio_op_handle_t *          op_handle;

    op_handle = (globus_l_xio_op_handle_t *) driver_specific_handle;

    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->close_op = op;
        if(op_handle->count >= 10)
        {
            res = globus_xio_driver_pass_close(op_handle->close_op,
                globus_l_xio_op_close_cb, op_handle);
        }
    }
    globus_mutex_unlock(&op_handle->mutex);

    return res;
}

/*
 *  read
 */
void
globus_l_xio_op_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_read(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_op_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_read(op, 
        (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_op_read_cb, NULL);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_op_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_write(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_op_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = globus_xio_operation_get_wait_for(op);

    res = globus_xio_driver_pass_write(op, (globus_xio_iovec_t *)iovec, 
        iovec_count, wait_for,
        globus_l_xio_op_write_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_op_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "op", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_op_open,
        globus_l_xio_op_close,
        globus_l_xio_op_read,
        globus_l_xio_op_write,
        NULL,
        NULL);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_op_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    op,
    globus_l_xio_op_init,
    globus_l_xio_op_destroy);

static
int
globus_l_xio_op_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(op);
    }
    return rc;
}

static
int
globus_l_xio_op_deactivate(void)
{
    GlobusXIOUnRegisterDriver(op);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
