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
#include "globus_xio_token_bucket_driver.h"

GlobusDebugDefine(GLOBUS_XIO_TOKEN_BUCKET);
GlobusXIODeclareDriver(token_bucket);

#define XIO_TB_GROUP_TABLE_SIZE 64

typedef enum
{
    GLOBUS_XIO_TB_DEBUG_ERROR = 1,
    GLOBUS_XIO_TB_DEBUG_WARNING = 2,
    GLOBUS_XIO_TB_DEBUG_TRACE = 4,
    GLOBUS_XIO_TB_DEBUG_INFO = 8,
} globus_xio_tb_debug_levels_t;


#define GlobusXIOTBDebugPrintf(level, message)                              \
    GlobusDebugPrintf(GLOBUS_XIO_TOKEN_BUCKET, level, message)

#define GlobusXIOTBDebugEnter()                                             \
    GlobusXIOTBDebugPrintf(                                                 \
        GLOBUS_XIO_TB_DEBUG_TRACE,                                          \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOTBDebugExit()                                              \
    GlobusXIOTBDebugPrintf(                                                 \
        GLOBUS_XIO_TB_DEBUG_TRACE,                                          \
        ("[%s] Exiting\n", _xio_name))


#define DEFAULT_PERIOD_US               100
/* set to a gigabit per sec.  unit is kilabits */
#define DEFAULT_RATE                    (1024*1024*1024/8)
#define DEFAULT_BURST                   (5000000)

static int
globus_l_xio_token_bucket_activate();

static int
globus_l_xio_token_bucket_deactivate();

#include "version.h"

GlobusXIODefineModule(token_bucket) =
{
    "globus_xio_token_bucket",
    globus_l_xio_token_bucket_activate,
    globus_l_xio_token_bucket_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef void
(*l_xio_tb_finished_func_t)(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nread);

typedef globus_result_t
(*l_xio_tb_pass_func_t)(
    globus_xio_operation_t              op,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       wait_for,
    globus_xio_driver_data_callback_t   cb,
    void *                              user_arg);

/* 
 *  a NULL group name implies a limit per handle, ie: no group
 *  or group of 1
 */
typedef struct l_xio_tb_attr_s
{
    globus_off_t                        rate;
    int                                 us_period;
    globus_size_t                       burst_size;
    char *                              group_name;
} l_xio_tb_attr_t;

typedef struct l_xio_tb_rw_attr_s
{
    l_xio_tb_attr_t                     read_attr;
    l_xio_tb_attr_t                     write_attr;
} l_xio_tb_attr_rw_t;

static l_xio_tb_attr_rw_t               l_xio_tb_default_attr;

typedef struct l_xio_token_bucket_op_handle_s
{
    globus_mutex_t                      mutex;
    globus_fifo_t                       q;
    globus_off_t                        allowed;
    globus_off_t                        per_tic;
    globus_callback_handle_t            cb_handle;
    globus_reltime_t                    us_period;
    l_xio_tb_finished_func_t            finished_func;
    l_xio_tb_pass_func_t                pass_func;
    globus_bool_t                       outstanding;
    globus_bool_t                       done;
    globus_size_t                       max_allowed;
    int                                 ref;
    char *                              group_name;
} l_xio_token_bucket_op_handle_t;

typedef struct l_xio_token_bucket_data_s
{
    globus_xio_operation_t              op;
    globus_xio_iovec_t *                iov;
    int                                 iovc;
    globus_xio_iovec_t *                current_iov;
    int                                 current_iovc;
    globus_size_t                       wait_for;
    globus_off_t                        nbytes;
    globus_object_t *                   error;
    l_xio_token_bucket_op_handle_t *    op_handle;
} l_xio_token_bucket_data_t;

typedef struct l_xio_token_bucket_handle_s
{
    globus_result_t                     close_result;
    globus_xio_operation_t              close_op;
    l_xio_token_bucket_op_handle_t *    read_handle;
    l_xio_token_bucket_op_handle_t *    write_handle;
} l_xio_token_bucket_handle_t;

static
void
l_xio_tb_net_ops(
    l_xio_token_bucket_op_handle_t *    op_handle);

static globus_mutex_t                   xio_l_tb_hash_mutex;
static globus_hashtable_t               l_tb_read_group_hash;
static globus_hashtable_t               l_tb_write_group_hash;

static
void
l_xio_token_bucket_destroy_op_handle(
    l_xio_token_bucket_op_handle_t *    op_handle)
{
    globus_fifo_destroy(&op_handle->q);
    globus_mutex_destroy(&op_handle->mutex);
    assert(op_handle->ref == 0);

    globus_free(op_handle);
}

static
void
l_xio_token_bucket_destroy_handle(
    l_xio_token_bucket_handle_t *       handle)
{
    GlobusXIOName(l_xio_token_bucket_destroy_handle);

    GlobusXIOTBDebugEnter();

    l_xio_token_bucket_destroy_op_handle(handle->read_handle);
    l_xio_token_bucket_destroy_op_handle(handle->write_handle);

    globus_free(handle);

    GlobusXIOTBDebugExit();
}

static
void
globus_l_xio_token_bucket_error_cb(
    void *                              user_arg)
{
    l_xio_token_bucket_op_handle_t *    op_handle;
    l_xio_token_bucket_data_t *         data;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_token_bucket_error_cb);

    GlobusXIOTBDebugEnter();
    data = (l_xio_token_bucket_data_t *) user_arg;
    op_handle = data->op_handle;

    result = globus_error_put(data->error);

    op_handle->finished_func(data->op, result, data->nbytes);
    globus_mutex_lock(&op_handle->mutex);
    {
        /* since we are done just remove it */
        globus_fifo_dequeue(&op_handle->q);
        op_handle->outstanding = GLOBUS_FALSE;
        l_xio_tb_net_ops(op_handle);
    }
    globus_mutex_unlock(&op_handle->mutex);

    globus_free(data->iov);
    globus_free(data->current_iov);
    globus_free(data);
    GlobusXIOTBDebugExit();
}

static
void
globus_l_xio_token_bucket_op_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    l_xio_token_bucket_op_handle_t *    op_handle;
    l_xio_token_bucket_data_t *         data;
    GlobusXIOName(globus_l_xio_token_bucket_op_cb);

    GlobusXIOTBDebugEnter();
    data = (l_xio_token_bucket_data_t *) user_arg;
    op_handle = data->op_handle;

    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIOTBDebugPrintf(GLOBUS_XIO_TB_DEBUG_INFO,
            ("    error setting done true\n"));
        op_handle->done = GLOBUS_TRUE;
    }
    data->nbytes += nbytes;

    if(op_handle->done)
    {
        op_handle->finished_func(data->op, result, data->nbytes);
    }
    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->outstanding = GLOBUS_FALSE;
        if(op_handle->done)
        {
            globus_fifo_dequeue(&op_handle->q);
            globus_free(data->iov);
            globus_free(data->current_iov);
            globus_free(data);
        }
        l_xio_tb_net_ops(op_handle);
    }
    globus_mutex_unlock(&op_handle->mutex);
    GlobusXIOTBDebugExit();
}


/*
 *   called locked
 */
static
void
l_xio_tb_net_ops(
    l_xio_token_bucket_op_handle_t *    op_handle)
{
    globus_size_t                       len;
    globus_size_t                       wait_for;
    globus_result_t                     res;
    l_xio_token_bucket_data_t *         data;
    GlobusXIOName(l_xio_tb_net_ops);

    GlobusXIOTBDebugEnter();
    if(op_handle->outstanding)
    {
        return;
    }
    if(!globus_fifo_empty(&op_handle->q) && op_handle->allowed > 0)
    {
        data = (l_xio_token_bucket_data_t *) globus_fifo_peek(&op_handle->q);

        /* copies over at most allowed or total, whichever is smaller */
        GlobusIXIOUtilCopyNIovec(
            data->current_iov, data->current_iovc,
            data->iov, data->iovc, op_handle->allowed);
        GlobusXIOUtilIovTotalLength(len, data->iov, data->iovc);
        if(len > op_handle->allowed)
        {
            /* if there are bytes left in the iov adjust it so that the
                next data op starts in the right place */
            GlobusIXIOUtilAdjustIovec(
                data->iov, data->iovc, op_handle->allowed);
            len = op_handle->allowed;
        }
        op_handle->allowed -= len;

        /* if we have exceded the wait for we are done */
        if(len > data->wait_for)
        {
            GlobusXIOTBDebugPrintf(GLOBUS_XIO_TB_DEBUG_INFO,
                ("    setting done true\n"));
            op_handle->done = GLOBUS_TRUE;
            wait_for = data->wait_for;
            data->wait_for = 0;
        }
        else
        {
            data->wait_for -= len;
            wait_for = len;
        }

        op_handle->outstanding = GLOBUS_TRUE;
        res = op_handle->pass_func(
            data->op, 
            (globus_xio_iovec_t *)data->current_iov, 
            data->current_iovc,
            wait_for,
            globus_l_xio_token_bucket_op_cb,
            data);
        if(res != GLOBUS_SUCCESS)
        {
            /* kick out one shot */
            op_handle->done = GLOBUS_TRUE;
            data->error = globus_error_get(res);
            globus_fifo_dequeue(&op_handle->q);
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_xio_token_bucket_error_cb,
                data);
        }
    }
    GlobusXIOTBDebugExit();
}

static
void
l_xio_tb_ticker_cb(
    void *                              user_arg)
{
    l_xio_token_bucket_op_handle_t *    op_handle;
    GlobusXIOName(l_xio_tb_ticker_cb);

    GlobusXIOTBDebugEnter();
    op_handle = (l_xio_token_bucket_op_handle_t *) user_arg;

    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->allowed += op_handle->per_tic;
        if(op_handle->allowed > op_handle->max_allowed &&
            op_handle->max_allowed != -1)
        {
            op_handle->allowed = op_handle->max_allowed;
        }
        l_xio_tb_net_ops(op_handle);
    }
    globus_mutex_unlock(&op_handle->mutex);
    GlobusXIOTBDebugExit();
}

/*
 *  check to see if op handle is in table.  if so destroy
 *  passed in one and retrun the one in the table with a 
 *  hugher ref count.  If not, keep the new one and start the time 
 */
static
l_xio_token_bucket_op_handle_t *
xio_l_tb_start_ticker(
    globus_hashtable_t *                table,
    l_xio_token_bucket_op_handle_t *    handle)
{
    globus_bool_t                       start = GLOBUS_FALSE;
    l_xio_token_bucket_op_handle_t *    tmp_h = NULL;

    if(handle == NULL)
    {
        return NULL;
    }

    if(handle->group_name != NULL)
    {
        tmp_h = (l_xio_token_bucket_op_handle_t *)
            globus_hashtable_lookup(table, handle->group_name);
        /* if there was a successfull lookup */
        if(tmp_h != NULL)
        {
            l_xio_token_bucket_destroy_op_handle(handle);
            handle = tmp_h;
        }
        else
        {
            globus_hashtable_insert(table, handle->group_name, handle);
        }
    }

    /* need to lock to up ref for all */
    globus_mutex_lock(&handle->mutex);
    {
        handle->ref++;
        if(handle->ref == 1)
        {
            start = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    /* if it is a new handle (first in group or NULL group) */
    if(start)
    {
        globus_callback_register_periodic(
            &handle->cb_handle,
            &handle->us_period,
            &handle->us_period,
            l_xio_tb_ticker_cb,
            handle);
    }
    return handle;
}

static
void
globus_l_xio_token_bucket_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(globus_l_xio_token_bucket_open_cb);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) user_arg;

    globus_xio_driver_finished_open(handle, op, result);

    if(result != GLOBUS_SUCCESS)
    {
        l_xio_token_bucket_destroy_handle(handle);
    }
    else
    {
        globus_mutex_lock(&xio_l_tb_hash_mutex);
        {
            handle->write_handle = xio_l_tb_start_ticker(
                &l_tb_write_group_hash, handle->write_handle);
            handle->read_handle = xio_l_tb_start_ticker(
                &l_tb_read_group_hash, handle->read_handle);
        }
        globus_mutex_unlock(&xio_l_tb_hash_mutex);
    }
    GlobusXIOTBDebugExit();
}

static
l_xio_token_bucket_op_handle_t *
xio_l_tb_attr_to_handle(
    l_xio_token_bucket_handle_t *       daddy,
    globus_hashtable_t *                table,
    l_xio_tb_attr_t *                   attr,
    l_xio_tb_finished_func_t            finished_func,
    l_xio_tb_pass_func_t                pass_func)
{
    l_xio_token_bucket_op_handle_t *    handle;

    if(attr->rate < 0)
    {
        return NULL;
    }
    handle = (l_xio_token_bucket_op_handle_t *) globus_calloc(
        sizeof(l_xio_token_bucket_op_handle_t), 1);
    if(handle == NULL)
    {
        goto error;
    }
    globus_fifo_init(&handle->q);
    globus_mutex_init(&handle->mutex, NULL);
    handle->finished_func = finished_func;
    handle->pass_func = pass_func;

    handle->per_tic = (int)((float)attr->rate *
        ((float)attr->us_period / 1000000.0f));
    GlobusTimeReltimeSet(handle->us_period, 0, attr->us_period);
    handle->max_allowed = attr->burst_size;

    if(attr->group_name != NULL)
    {
        handle->group_name = strdup(attr->group_name);
    }

    return handle;
error:
    return NULL;
}

static
globus_result_t
globus_l_xio_token_bucket_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_token_bucket_handle_t *       handle;
    l_xio_tb_attr_rw_t *                attr;
    GlobusXIOName(globus_l_xio_token_bucket_open);

    GlobusXIOTBDebugEnter();
    if(driver_attr == NULL)
    {
        attr = &l_xio_tb_default_attr;
    }
    else
    {
        attr = (l_xio_tb_attr_rw_t *) driver_attr;
    }

    handle = (l_xio_token_bucket_handle_t *) 
        globus_calloc(1, sizeof(l_xio_token_bucket_handle_t));

    handle->read_handle = xio_l_tb_attr_to_handle(
        handle,
        &l_tb_read_group_hash,
        &attr->read_attr,
        globus_xio_driver_finished_read,
        globus_xio_driver_pass_read);

    handle->write_handle = xio_l_tb_attr_to_handle(
        handle,
        &l_tb_write_group_hash,
        &attr->write_attr,
        globus_xio_driver_finished_write,
        globus_xio_driver_pass_write);

    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_token_bucket_open_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusXIOTBDebugExit();
    return GLOBUS_SUCCESS;
error:
    l_xio_token_bucket_destroy_handle(handle);
    return res;

}

static
globus_bool_t
xio_l_tb_ref_dec(
    globus_hashtable_t *                table,
    l_xio_token_bucket_handle_t *       handle,
    l_xio_token_bucket_op_handle_t *    op_handle,
    globus_callback_func_t              cb)
{
    globus_bool_t                       b = GLOBUS_FALSE;

    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->ref--;
        if(op_handle->ref == 0)
        {
            b = GLOBUS_TRUE;
            if(op_handle->group_name != NULL)
            {
                globus_hashtable_remove(table, op_handle->group_name);
            }
            globus_callback_unregister(
                op_handle->cb_handle,
                cb,
                handle,
                NULL);
        }
    }
    globus_mutex_unlock(&op_handle->mutex);

    return b;
}

static
void
l_xio_tb_write_unreg(
    void *                              user_arg)
{
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(l_xio_tb_read_unreg);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) user_arg;

    l_xio_token_bucket_destroy_op_handle(handle->write_handle);
    globus_xio_driver_finished_close(handle->close_op, handle->close_result);
    globus_free(handle);

    GlobusXIOTBDebugExit();

}

static
void
l_xio_tb_read_unreg(
    void *                              user_arg)
{
    globus_bool_t                       b = GLOBUS_FALSE;
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(l_xio_tb_read_unreg);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) user_arg;

    globus_mutex_lock(&xio_l_tb_hash_mutex);
    {
        if(handle->write_handle != NULL)
        {
            b = xio_l_tb_ref_dec(&l_tb_write_group_hash, handle,
                handle->write_handle, l_xio_tb_write_unreg);
        }
    }
    globus_mutex_unlock(&xio_l_tb_hash_mutex);

    l_xio_token_bucket_destroy_op_handle(handle->read_handle);
    if(!b)
    {
        globus_xio_driver_finished_close(handle->close_op, handle->close_result);
        globus_free(handle);
    }

    GlobusXIOTBDebugExit();
}

static
void
globus_l_xio_token_bucket_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_bool_t                       b = GLOBUS_FALSE;
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(globus_l_xio_token_bucket_close_cb);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) user_arg;
    handle->close_result = result;

    globus_mutex_lock(&xio_l_tb_hash_mutex);
    {
        if(handle->read_handle != NULL)
        {
            b = xio_l_tb_ref_dec(&l_tb_read_group_hash, handle,
                handle->read_handle, l_xio_tb_read_unreg);
        }
        if(!b)
        {
            if(handle->write_handle != NULL)
            {
                b = xio_l_tb_ref_dec(&l_tb_write_group_hash, handle,
                    handle->write_handle, l_xio_tb_write_unreg);
            }
        }
    }
    globus_mutex_unlock(&xio_l_tb_hash_mutex);

    if(!b)
    {
        globus_xio_driver_finished_close(op, handle->close_result);
        globus_free(handle);
    }
}
/*
 *  close
 */
static
globus_result_t
globus_l_xio_token_bucket_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(globus_l_xio_token_bucket_close);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) driver_specific_handle;

    handle->close_op = op;
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_token_bucket_close_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* gotta make sure not a grouper */

    GlobusXIOTBDebugExit();

    return GLOBUS_SUCCESS;
error:

    return res;
}

/*
 *  read
 */
static
globus_result_t
globus_l_xio_token_bucket_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_token_bucket_handle_t *       handle;
    l_xio_token_bucket_data_t *         data;
    GlobusXIOName(globus_l_xio_token_bucket_read);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) driver_specific_handle;

    if(handle->read_handle == NULL)
    {
        globus_size_t wait_for = globus_xio_operation_get_wait_for(op);
        res = globus_xio_driver_pass_read(
            op,
            (globus_xio_iovec_t *)iovec,
            iovec_count,
            wait_for,
            NULL,
            NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        data = (l_xio_token_bucket_data_t *) globus_calloc(
            1, sizeof(l_xio_token_bucket_data_t));
        data->op = op;
        data->iovc = iovec_count;
        data->current_iovc = iovec_count;
        data->iov = (globus_xio_iovec_t *)
            globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
        data->current_iov = (globus_xio_iovec_t *)
            globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
        data->op_handle = handle->read_handle;
        data->wait_for = globus_xio_operation_get_wait_for(op);
    
        GlobusIXIOUtilTransferIovec(data->iov, iovec, iovec_count);

        globus_mutex_lock(&data->op_handle->mutex);
        {
            globus_fifo_enqueue(&data->op_handle->q, data);
            l_xio_tb_net_ops(data->op_handle);
        }
        globus_mutex_unlock(&data->op_handle->mutex);
    }
    GlobusXIOTBDebugExit();

    return GLOBUS_SUCCESS;
error:
    return res;
}

/*
 *  write
 */
static
globus_result_t
globus_l_xio_token_bucket_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_token_bucket_handle_t *       handle;
    l_xio_token_bucket_data_t *         data;
    GlobusXIOName(globus_l_xio_token_bucket_write);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) driver_specific_handle;

    if(handle->write_handle == NULL)
    {
        globus_size_t wait_for = globus_xio_operation_get_wait_for(op);
        res = globus_xio_driver_pass_write(
            op,
            (globus_xio_iovec_t *)iovec,
            iovec_count,
            wait_for,
            NULL,
            NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        data = (l_xio_token_bucket_data_t *) globus_calloc(
            1, sizeof(l_xio_token_bucket_data_t));
        data->op = op;
        data->iovc = iovec_count;
        data->current_iovc = iovec_count;
        data->iov = (globus_xio_iovec_t *)
            globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
        data->current_iov = (globus_xio_iovec_t *)
            globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
        data->op_handle = handle->write_handle;
        data->wait_for = globus_xio_operation_get_wait_for(op);
    
        GlobusIXIOUtilTransferIovec(data->iov, iovec, iovec_count);

        globus_mutex_lock(&data->op_handle->mutex);
        {
            globus_fifo_enqueue(&data->op_handle->q, data);
            l_xio_tb_net_ops(data->op_handle);
        }
        globus_mutex_unlock(&data->op_handle->mutex);
    }
    GlobusXIOTBDebugExit();

    return GLOBUS_SUCCESS;
error:
    return res;
}

static
globus_result_t
globus_l_xio_token_bucket_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_tb_attr_copy(
    void **                             dst,
    void *                              src)
{
    l_xio_tb_attr_rw_t *                src_attr;
    l_xio_tb_attr_rw_t *                dst_attr;

    src_attr = (l_xio_tb_attr_rw_t *) src;
    dst_attr = (l_xio_tb_attr_rw_t *) globus_calloc(1, sizeof(l_xio_tb_attr_rw_t));

    dst_attr->read_attr.rate = src_attr->read_attr.rate;
    dst_attr->read_attr.burst_size = src_attr->read_attr.burst_size;
    dst_attr->read_attr.us_period = src_attr->read_attr.us_period;
    dst_attr->write_attr.rate = src_attr->write_attr.rate;
    dst_attr->write_attr.us_period = src_attr->write_attr.us_period;
    dst_attr->write_attr.burst_size = src_attr->write_attr.burst_size;

    if(src_attr->read_attr.group_name != NULL)
    {
        dst_attr->read_attr.group_name =
            strdup(src_attr->read_attr.group_name);
    }
    if(src_attr->write_attr.group_name != NULL)
    {
        dst_attr->write_attr.group_name =
            strdup(src_attr->write_attr.group_name);
    }

    *dst = dst_attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_tb_attr_init(
    void **                             out_driver_attr)
{
    l_xio_tb_attr_t *                   attr;

    globus_l_xio_tb_attr_copy((void **)&attr, (void *)&l_xio_tb_default_attr);

    *out_driver_attr = attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_tb_attr_destroy(
    void *                              driver_attr)
{
    l_xio_tb_attr_rw_t *                attr;

    attr = (l_xio_tb_attr_rw_t *) driver_attr;
    globus_free(attr);

    return GLOBUS_SUCCESS;
}


static globus_xio_string_cntl_table_t  tb_l_string_opts_table[] =
{
    {"rate", GLOBUS_XIO_TOKEN_BUCKET_SET_RATE, globus_xio_string_cntl_formated_off},
    {"read_rate", GLOBUS_XIO_TOKEN_BUCKET_SET_READ_RATE, globus_xio_string_cntl_formated_off},
    {"write_rate", GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_RATE, globus_xio_string_cntl_formated_off},
    {"period", GLOBUS_XIO_TOKEN_BUCKET_SET_PERIOD, globus_xio_string_cntl_formated_int},
    {"read_period", GLOBUS_XIO_TOKEN_BUCKET_SET_READ_PERIOD, globus_xio_string_cntl_formated_int},
    {"write_period", GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_PERIOD, globus_xio_string_cntl_formated_int},
    {NULL, 0, NULL}
};


static
globus_result_t
globus_l_xio_tb_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              group;
    l_xio_tb_attr_rw_t *                attr;
    GlobusXIOName(globus_l_xio_tb_attr_cntl);

    attr = (l_xio_tb_attr_rw_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_TOKEN_BUCKET_SET_RATE:
            attr->read_attr.rate = va_arg(ap, globus_size_t);
            attr->write_attr.rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_PERIOD:
            attr->read_attr.us_period = va_arg(ap, int);
            attr->write_attr.us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_READ_RATE:
            attr->read_attr.rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_READ_PERIOD:
            attr->read_attr.us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_RATE:
            attr->write_attr.rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_PERIOD:
            attr->write_attr.us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_GROUP:
            group = va_arg(ap, char *);
            if(group == NULL)
            {
                goto error;
            }
            attr->write_attr.group_name = strdup(group);
            attr->read_attr.group_name = strdup(group);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_READ_GROUP:
            group = va_arg(ap, char *);
            if(group == NULL)
            {
                goto error;
            }
            attr->read_attr.group_name = strdup(group);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_GROUP:
            group = va_arg(ap, char *);
            if(group == NULL)
            {
                goto error;
            }
            attr->write_attr.group_name = strdup(group);
            break;

        default:
            break;
    }

    return GLOBUS_SUCCESS;
error:
    return 0x1;
}


static globus_result_t
globus_l_xio_token_bucket_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "token_bucket", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_token_bucket_open,
        globus_l_xio_token_bucket_close,
        globus_l_xio_token_bucket_read,
        globus_l_xio_token_bucket_write,
        globus_l_xio_token_bucket_cntl,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_tb_attr_init,
        globus_l_xio_tb_attr_copy,
        globus_l_xio_tb_attr_cntl,
        globus_l_xio_tb_attr_destroy);


    globus_xio_driver_string_cntl_set_table(driver, tb_l_string_opts_table);


    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_token_bucket_destroy(
    globus_xio_driver_t                 driver)
{
    globus_hashtable_destroy(&l_tb_read_group_hash);
    globus_hashtable_destroy(&l_tb_write_group_hash);
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    token_bucket,
    globus_l_xio_token_bucket_init,
    globus_l_xio_token_bucket_destroy);

static
int
globus_l_xio_token_bucket_activate(void)
{
    int                                 rc;

    GlobusDebugInit(GLOBUS_XIO_TOKEN_BUCKET, TRACE);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(token_bucket);
    }
    globus_hashtable_init(
        &l_tb_read_group_hash,
        XIO_TB_GROUP_TABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_hashtable_init(
        &l_tb_write_group_hash,
        XIO_TB_GROUP_TABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_mutex_init(&xio_l_tb_hash_mutex, NULL);
    
    l_xio_tb_default_attr.read_attr.rate = DEFAULT_RATE;
    l_xio_tb_default_attr.read_attr.us_period = DEFAULT_PERIOD_US;
    l_xio_tb_default_attr.read_attr.burst_size = -1;
    l_xio_tb_default_attr.read_attr.group_name = NULL;

    l_xio_tb_default_attr.write_attr.rate = DEFAULT_RATE;
    l_xio_tb_default_attr.write_attr.us_period = DEFAULT_PERIOD_US;
    l_xio_tb_default_attr.write_attr.burst_size = -1;
    l_xio_tb_default_attr.write_attr.group_name = NULL;

    return rc;
}

static
int
globus_l_xio_token_bucket_deactivate(void)
{
    globus_hashtable_destroy(&l_tb_read_group_hash);
    globus_hashtable_destroy(&l_tb_write_group_hash);
    globus_mutex_destroy(&xio_l_tb_hash_mutex);

    GlobusXIOUnRegisterDriver(token_bucket);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}

static
globus_result_t
xio_l_tb_set_group(
    char *                              group_name,
    globus_off_t                        rate,
    int                                 us_period,
    globus_size_t                       burst_size,
    globus_bool_t *                     in_out_create,
    globus_hashtable_t *                table,
    l_xio_tb_finished_func_t            finished_func,
    l_xio_tb_pass_func_t                pass_func)
{
    globus_bool_t                       create = GLOBUS_TRUE;
    l_xio_token_bucket_op_handle_t *    handle;

    if(in_out_create != NULL)
    {
        create = *in_out_create;
    }

    globus_mutex_lock(&xio_l_tb_hash_mutex);
    {
        handle = (l_xio_token_bucket_op_handle_t *)
            globus_hashtable_lookup(table, group_name);

        if(handle == NULL)
        {
            if(!create)
            {
                goto error_create;
            }
            create = GLOBUS_TRUE;

            handle = (l_xio_token_bucket_op_handle_t *)
                globus_calloc(sizeof(l_xio_token_bucket_op_handle_t), 1);
            if(handle == NULL)
            {
                goto error_alloc;
            }
            globus_mutex_init(&handle->mutex, NULL);
            globus_fifo_init(&handle->q);
            handle->group_name = strdup(group_name);

            handle->finished_func = finished_func;
            handle->pass_func = pass_func;

            globus_hashtable_insert(table, handle->group_name, handle);
        }
        else
        {
            create = GLOBUS_FALSE;
        }

        globus_mutex_lock(&handle->mutex);
        {
            handle->per_tic = (int)((float)rate * ((float)us_period / 1000000.0f));
            GlobusTimeReltimeSet(handle->us_period, 0, us_period);
            handle->max_allowed = burst_size;
        }
        globus_mutex_unlock(&handle->mutex);
    }
    globus_mutex_unlock(&xio_l_tb_hash_mutex);

    if(in_out_create != NULL)
    {
        *in_out_create = create;
    }

    return GLOBUS_SUCCESS;

error_alloc:
error_create:

    return 0x1;
}

globus_result_t
globus_xio_token_bucket_set_read_group(
    char *                              group_name,
    globus_off_t                        rate,
    int                                 us_period,
    globus_size_t                       burst_size,
    globus_bool_t *                     in_out_create)
{
    return xio_l_tb_set_group(
        group_name,
        rate,
        us_period,
        burst_size,
        in_out_create,
        &l_tb_read_group_hash,
        globus_xio_driver_finished_read,
        globus_xio_driver_pass_read);
}

globus_result_t
globus_xio_token_bucket_set_write_group(
    char *                              group_name,
    globus_off_t                        rate,
    int                                 us_period,
    globus_size_t                       burst_size,
    globus_bool_t *                     in_out_create)
{
    return xio_l_tb_set_group(
        group_name,
        rate,
        us_period,
        burst_size,
        in_out_create,
        &l_tb_write_group_hash,
        globus_xio_driver_finished_write,
        globus_xio_driver_pass_write);
}
