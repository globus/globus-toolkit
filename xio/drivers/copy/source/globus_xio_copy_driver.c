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
#include "globus_xio_copy_driver.h"
#include "version.h"

GlobusDebugDefine(GLOBUS_XIO_GRIDFTP_COPY);
GlobusXIODeclareDriver(copy);

typedef struct
{
    globus_result_t                     result;
    globus_xio_operation_t              op;
    globus_xio_operation_t              close_op;
    globus_bool_t                       outstanding;
    globus_bool_t                       closing;
    globus_fifo_t                       cb_q;
    globus_mutex_t                      mutex;
} xio_l_copy_handle_t;

typedef struct xio_l_copy_buff_s
{
    globus_xio_iovec_t *                iov;
    int                                 iovc;
    globus_size_t                       wait_for;
    xio_l_copy_handle_t *               whos_my_daddy;
} xio_l_copy_buff_t;

static
int
xio_l_copy_activate(void);

static
int
xio_l_copy_deactivate(void);

static
globus_result_t
xio_l_cb_next_write(
    xio_l_copy_handle_t *               handle,
    globus_bool_t *                     posted);

static
void
xio_l_copy_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

GlobusXIODefineModule(copy) =
{
    "globus_xio_copy",
    xio_l_copy_activate,
    xio_l_copy_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
xio_l_copy_activate()
{
    int rc;
    GlobusXIOName(xio_l_copy);

    GlobusDebugInit(GLOBUS_XIO_GRIDFTP_COPY, TRACE);
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    GlobusXIORegisterDriver(copy);
    return GLOBUS_SUCCESS;

error_xio_system_activate:
    GlobusDebugDestroy(GLOBUS_XIO_GRIDFTP_COPY);
    return rc;
}


static
int
xio_l_copy_deactivate()
{   
    int rc;
    GlobusXIOName(xio_l_copy_deactivate);
    
    GlobusXIOUnRegisterDriver(copy);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    GlobusDebugDestroy(GLOBUS_XIO_GRIDFTP_COPY);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusDebugDestroy(GLOBUS_XIO_GRIDFTP_COPY);
    return rc;
}

static
void
xio_l_copy_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_copy_handle_t *               handle;
    globus_xio_driver_handle_t          dh;

    handle =(xio_l_copy_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error_param;
    }

    dh = globus_xio_operation_get_driver_handle(op);
    if(dh == NULL)
    {
        goto error_param;
    }

    result = globus_xio_driver_operation_create(&handle->op, dh);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_param;
    }

    globus_xio_driver_finished_open(handle, op, GLOBUS_SUCCESS);

    return;

error_param:
    globus_mutex_destroy(&handle->mutex);
    globus_fifo_destroy(&handle->cb_q);
    globus_xio_driver_finished_open(handle, op, result);
    globus_free(handle);
}

globus_result_t
xio_l_copy_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    xio_l_copy_handle_t *               handle;

    handle = (xio_l_copy_handle_t *)
        globus_calloc(1, sizeof(xio_l_copy_handle_t));

    /* make own op */
    globus_mutex_init(&handle->mutex, NULL);
    globus_fifo_init(&handle->cb_q);

        /*alter resource and pass down */
    result = globus_xio_driver_pass_open(
        op, contact_info, xio_l_copy_open_cb, handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    return GLOBUS_SUCCESS;

error_pass:
    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
    return result;
}

static
void
xio_l_copy_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    int                                 i;
    globus_bool_t                       close_it = GLOBUS_FALSE;
    xio_l_copy_buff_t *                 cb;
    xio_l_copy_handle_t *               handle;
    globus_bool_t                       p;

    cb = (xio_l_copy_buff_t *) user_arg;
    handle = cb->whos_my_daddy;

    /* have to check if closing */

    globus_mutex_lock(&handle->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        for(i = 0; i < cb->iovc; i++)
        {
            globus_free(cb->iov[i].iov_base);
        }
        globus_free(cb->iov);
        globus_free(cb);
        handle->outstanding = GLOBUS_FALSE;
        result = xio_l_cb_next_write(handle, &p);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        /* if nothing was posted (here that means there is nothing to
            post) and we are closing we can proceed with the close */
        if(!p && handle->closing)
        {
            result = globus_xio_driver_pass_close(
                handle->close_op, xio_l_copy_close_cb, handle);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_pass;
            }

        }
    }
    globus_mutex_unlock(&handle->mutex);

    return;

error_pass:
error:
    if(handle->result == GLOBUS_SUCCESS)
    {
        handle->result = result;
    }

    globus_assert(!handle->outstanding);
    if(handle->closing)
    {
        result = globus_xio_driver_pass_close(
            handle->close_op, xio_l_copy_close_cb, handle);

        if(result != GLOBUS_SUCCESS)
        {
            close_it = GLOBUS_TRUE;
        }
    }

    globus_mutex_unlock(&handle->mutex);

    if(close_it)
    {
        globus_xio_driver_finished_close(handle->close_op, handle->result);

        /* XXX clean it up */
        globus_xio_driver_operation_destroy(handle->op);
        globus_mutex_destroy(&handle->mutex);
        globus_fifo_destroy(&handle->cb_q);
        globus_free(handle);
    }
}

static
globus_result_t
xio_l_copy_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t*           iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_size_t                       wait_for;
    globus_result_t                     result;

    wait_for = globus_xio_operation_get_wait_for(op);

    result = globus_xio_driver_pass_read(
        op,
        (globus_xio_iovec_t *)iovec,
        iovec_count,
        wait_for,
        NULL,
        NULL);

    return result;
}

static
globus_result_t
xio_l_cb_next_write(
    xio_l_copy_handle_t *               handle,
    globus_bool_t *                     posted)
{
    globus_result_t                     result;
    globus_bool_t                       p = GLOBUS_FALSE;
    xio_l_copy_buff_t *                 cb;

    if(!handle->outstanding && !globus_fifo_empty(&handle->cb_q))
    {
        cb = (xio_l_copy_buff_t *)globus_fifo_dequeue(&handle->cb_q);

        result = globus_xio_driver_pass_write(
            handle->op,
            cb->iov,
            cb->iovc,
            cb->wait_for,
            xio_l_copy_write_cb,
            cb);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_pass;
        }
        p = GLOBUS_TRUE;
        handle->outstanding = GLOBUS_TRUE;
    }

    if(posted != NULL)
    {
        *posted = p;
    }

    return GLOBUS_SUCCESS;

error_pass:
    if(posted != NULL)
    {
        *posted = p;
    }

    return result;
}

static
globus_result_t
xio_l_copy_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    int                                 i;
    xio_l_copy_handle_t *               handle;
    xio_l_copy_buff_t *                 cb;
    globus_size_t                       wait_for;
    globus_xio_iovec_t *                new_iov;

    handle = (xio_l_copy_handle_t *) driver_specific_handle;

    globus_mutex_lock(&handle->mutex);
    {
        /*if we already have anerror, just report it */
        if(handle->result != GLOBUS_SUCCESS)
        {
            goto error_already;
        }

        cb = (xio_l_copy_buff_t *)  globus_calloc(
            1, sizeof(xio_l_copy_buff_t));

        wait_for = 0;
        new_iov = (globus_xio_iovec_t *) globus_calloc(
            iovec_count, sizeof(globus_xio_iovec_t));
        for(i = 0; i < iovec_count; i++)
        {
            new_iov[i].iov_base = globus_malloc(iovec[i].iov_len);
            new_iov[i].iov_len = iovec[i].iov_len;
            memcpy(
                new_iov[i].iov_base,
                iovec[i].iov_base,
                iovec[i].iov_len);
            wait_for += new_iov[i].iov_len;
        }
        cb->iov = new_iov;
        cb->iovc= iovec_count;
        cb->whos_my_daddy = handle;
        cb->wait_for = wait_for;

        globus_fifo_enqueue(&handle->cb_q, cb);

        result = xio_l_cb_next_write(handle, NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_pass;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    globus_xio_driver_finished_write(op, GLOBUS_SUCCESS, wait_for);

    return GLOBUS_SUCCESS;

error_pass:
    for(i = 0; i < iovec_count; i++)
    {
        globus_free(new_iov[i].iov_base);
    }
    globus_free(new_iov);

    if(handle->result == GLOBUS_SUCCESS)
    {
        handle->result = result;
    }

error_already:
    globus_mutex_unlock(&handle->mutex);

    return result;
}

static
void
xio_l_copy_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_copy_handle_t *               handle;

    handle = (xio_l_copy_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            if(handle->result == GLOBUS_SUCCESS)
            {
                handle->result = result;
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);

    globus_mutex_destroy(&handle->mutex);
    globus_fifo_destroy(&handle->cb_q);

    globus_xio_driver_finished_close(op, handle->result);
    globus_free(handle);
}


static
globus_result_t
xio_l_copy_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    xio_l_copy_handle_t *               handle;

    handle = (xio_l_copy_handle_t *) driver_specific_handle;

    globus_mutex_lock(&handle->mutex);
    {
        globus_assert(!handle->closing);

        handle->close_op = op;
        handle->closing = GLOBUS_TRUE;
        if(globus_fifo_empty(&handle->cb_q) && !handle->outstanding)
        {
            result = globus_xio_driver_pass_close(
                op, xio_l_copy_close_cb, handle);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_pass;
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

error_pass:

    globus_mutex_unlock(&handle->mutex);
    /* XXX cloean up the handle */

    globus_xio_driver_operation_destroy(handle->op);
    globus_mutex_destroy(&handle->mutex);
    globus_fifo_destroy(&handle->cb_q);
    globus_free(handle);

    return result;
}

static
globus_result_t
xio_l_copy_attr_init(
    void **                             out_attr)
{
    return GLOBUS_SUCCESS;
}


static globus_xio_string_cntl_table_t  
    xio_l_copy_string_opts_table[] =
{
    {"c", 23,
        globus_xio_string_cntl_int},
    {NULL, 0, NULL}
};

static
globus_result_t
xio_l_copy_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    switch(cmd)
    {
        default:
            break;
    }

    return GLOBUS_SUCCESS;
}


static
globus_result_t
xio_l_copy_attr_copy(
    void **                             dst,
    void *                              src)
{
    return GLOBUS_SUCCESS;
}


static
globus_result_t
xio_l_copy_attr_destroy(
    void *                              driver_attr)
{
    return GLOBUS_SUCCESS;
}


static
globus_result_t
xio_l_copy_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(xio_l_copy_init);

    result = globus_xio_driver_init(&driver, "copy", NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "xio_l_driver_init", result);
        goto error_init;
    }
    globus_xio_driver_set_transform(
        driver,
        xio_l_copy_open,
        xio_l_copy_close,
        xio_l_copy_read,
        xio_l_copy_write,
        NULL,
        NULL);
    globus_xio_driver_set_attr(
        driver,
        xio_l_copy_attr_init,
        xio_l_copy_attr_copy,
        xio_l_copy_attr_cntl,
        xio_l_copy_attr_destroy);

    globus_xio_driver_string_cntl_set_table(
        driver,
        xio_l_copy_string_opts_table);

    *out_driver = driver;

    return GLOBUS_SUCCESS;

error_init:
    return result;
}


static
void
xio_l_copy_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


GlobusXIODefineDriver(
    copy,
    xio_l_copy_init,
    xio_l_copy_destroy);
