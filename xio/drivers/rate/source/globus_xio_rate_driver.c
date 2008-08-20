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
#include "globus_xio_rate_driver.h"

GlobusDebugDefine(GLOBUS_XIO_TOKEN_BUCKET);
GlobusXIODeclareDriver(rate);

#define XIO_RATE_GROUP_TABLE_SIZE 64

typedef enum
{
    GLOBUS_XIO_RATE_DEBUG_ERROR = 1,
    GLOBUS_XIO_RATE_DEBUG_WARNING = 2,
    GLOBUS_XIO_RATE_DEBUG_TRACE = 4,
    GLOBUS_XIO_RATE_DEBUG_INFO = 8,
} globus_xio_rate_debug_levels_t;


#define GlobusXIOTBDebugPrintf(level, message)                              \
    GlobusDebugPrintf(GLOBUS_XIO_TOKEN_BUCKET, level, message)

#define GlobusXIOTBDebugEnter()                                             \
    GlobusXIOTBDebugPrintf(                                                 \
        GLOBUS_XIO_RATE_DEBUG_TRACE,                                          \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOTBDebugExit()                                              \
    GlobusXIOTBDebugPrintf(                                                 \
        GLOBUS_XIO_RATE_DEBUG_TRACE,                                          \
        ("[%s] Exiting\n", _xio_name))


#define DEFAULT_PERIOD_US               50000
/* set to a gigabit per sec.  unit is kilabits */
#define DEFAULT_RATE                    (1024*1024*1024/8)
#define DEFAULT_BURST                   (5000000)

static int
globus_l_xio_rate_activate();

static int
globus_l_xio_rate_deactivate();

#include "version.h"

GlobusXIODefineModule(rate) =
{
    "globus_xio_rate",
    globus_l_xio_rate_activate,
    globus_l_xio_rate_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef void
(*l_xio_rate_finished_func_t)(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nread);

typedef globus_result_t
(*l_xio_rate_pass_func_t)(
    globus_xio_operation_t              op,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       wait_for,
    globus_xio_driver_data_callback_t   cb,
    void *                              user_arg);

typedef struct l_xio_rate_attr_s
{
    globus_off_t                        rate;
    int                                 us_period;
    globus_size_t                       burst_size;
} l_xio_rate_attr_t;

typedef struct l_xio_rate_rw_attr_s
{
    l_xio_rate_attr_t                     read_attr;
    l_xio_rate_attr_t                     write_attr;
} l_xio_rate_attr_rw_t;

static l_xio_rate_attr_rw_t               l_xio_rate_default_attr;

typedef struct l_xio_rate_op_handle_s
{
    globus_mutex_t                      mutex;
    globus_off_t                        allowed;
    globus_off_t                        per_tic;
    globus_callback_handle_t            cb_handle;
    globus_reltime_t                    us_period;
    l_xio_rate_finished_func_t            finished_func;
    l_xio_rate_pass_func_t                pass_func;
    globus_bool_t                       outstanding;
    globus_size_t                       max_allowed;
    int                                 ref;
    struct l_xio_rate_data_s *          data;
} l_xio_rate_op_handle_t;

typedef struct l_xio_rate_data_s
{
    globus_xio_operation_t              op;
    globus_xio_iovec_t *                iov;
    int                                 iovc;
    globus_off_t                        nbytes;
    globus_object_t *                   error;
    l_xio_rate_op_handle_t *            op_handle;
} l_xio_rate_data_t;

typedef struct l_xio_rate_handle_s
{
    globus_result_t                     close_result;
    globus_xio_operation_t              close_op;
    l_xio_rate_op_handle_t *            read_handle;
    l_xio_rate_op_handle_t *            write_handle;
} l_xio_rate_handle_t;

static
void
l_xio_rate_net_ops(
    l_xio_rate_op_handle_t *    op_handle);

static globus_mutex_t                   xio_l_rate_hash_mutex;

static
void
l_xio_rate_destroy_op_handle(
    l_xio_rate_op_handle_t *    op_handle)
{
    globus_mutex_destroy(&op_handle->mutex);
    assert(op_handle->ref == 0);

    globus_free(op_handle);
}

static
void
l_xio_rate_destroy_handle(
    l_xio_rate_handle_t *       handle)
{
    GlobusXIOName(l_xio_rate_destroy_handle);

    GlobusXIOTBDebugEnter();

    l_xio_rate_destroy_op_handle(handle->read_handle);
    l_xio_rate_destroy_op_handle(handle->write_handle);

    globus_free(handle);

    GlobusXIOTBDebugExit();
}

static
void
globus_l_xio_rate_error_cb(
    void *                              user_arg)
{
    l_xio_rate_op_handle_t *            op_handle;
    l_xio_rate_data_t *                 data;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_rate_error_cb);

    GlobusXIOTBDebugEnter();
    data = (l_xio_rate_data_t *) user_arg;
    op_handle = data->op_handle;

    result = globus_error_put(data->error);

    op_handle->finished_func(data->op, result, 0);

    globus_free(data->iov);
    globus_free(data);
    GlobusXIOTBDebugExit();
}

static
void
globus_l_xio_rate_op_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    l_xio_rate_op_handle_t *            op_handle;
    l_xio_rate_data_t *                 data;
    GlobusXIOName(globus_l_xio_rate_op_cb);

    GlobusXIOTBDebugEnter();
    data = (l_xio_rate_data_t *) user_arg;
    op_handle = data->op_handle;

    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIOTBDebugPrintf(GLOBUS_XIO_RATE_DEBUG_INFO,
            ("    error setting done true\n"));
    }

    op_handle->finished_func(data->op, result, nbytes);
    globus_free(data);

    globus_mutex_unlock(&op_handle->mutex);
    GlobusXIOTBDebugExit();
}


/*
 *   called locked
 */
static
void
l_xio_rate_net_ops(
    l_xio_rate_op_handle_t *    op_handle)
{
    globus_size_t                       len;
    globus_result_t                     res;
    l_xio_rate_data_t *         data;
    GlobusXIOName(l_xio_rate_net_ops);

    GlobusXIOTBDebugEnter();
    if(op_handle->outstanding)
    {
        return;
    }
    if(op_handle->data != NULL && op_handle->allowed > 0)
    {
        data = (l_xio_rate_data_t *) op_handle->data;

        GlobusXIOUtilIovTotalLength(len, data->iov, data->iovc);
        if(len > op_handle->allowed)
        {
            /* if there are bytes left in the iov adjust it so that the
                next data op starts in the right place */
            len = op_handle->allowed;
        }
        op_handle->allowed -= len;

        op_handle->data = NULL;
        res = op_handle->pass_func(
            data->op, 
            (globus_xio_iovec_t *)data->iov, 
            data->iovc,
            len,
            globus_l_xio_rate_op_cb,
            data);
        if(res != GLOBUS_SUCCESS)
        {
            /* kick out one shot */
            data->error = globus_error_get(res);
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_xio_rate_error_cb,
                data);
        }
    }
    GlobusXIOTBDebugExit();
}

static
void
l_xio_rate_ticker_cb(
    void *                              user_arg)
{
    l_xio_rate_op_handle_t *    op_handle;
    GlobusXIOName(l_xio_rate_ticker_cb);

    GlobusXIOTBDebugEnter();
    op_handle = (l_xio_rate_op_handle_t *) user_arg;

    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->allowed += op_handle->per_tic;
        if(op_handle->allowed > op_handle->max_allowed &&
            op_handle->max_allowed != -1)
        {
            op_handle->allowed = op_handle->max_allowed;
        }
        l_xio_rate_net_ops(op_handle);
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
l_xio_rate_op_handle_t *
xio_l_rate_start_ticker(
    l_xio_rate_op_handle_t *            handle)
{
    globus_bool_t                       start = GLOBUS_FALSE;

    if(handle == NULL)
    {
        return NULL;
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

    if(start)
    {
        globus_callback_register_periodic(
            &handle->cb_handle,
            &handle->us_period,
            &handle->us_period,
            l_xio_rate_ticker_cb,
            handle);
    }
    return handle;
}

static
void
globus_l_xio_rate_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    l_xio_rate_handle_t *       handle;
    GlobusXIOName(globus_l_xio_rate_open_cb);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) user_arg;

    globus_xio_driver_finished_open(handle, op, result);

    if(result != GLOBUS_SUCCESS)
    {
        l_xio_rate_destroy_handle(handle);
    }
    else
    {
        globus_mutex_lock(&xio_l_rate_hash_mutex);
        {
            handle->write_handle = xio_l_rate_start_ticker(
                handle->write_handle);
            handle->read_handle = xio_l_rate_start_ticker(
                handle->read_handle);
        }
        globus_mutex_unlock(&xio_l_rate_hash_mutex);
    }
    GlobusXIOTBDebugExit();
}

static
l_xio_rate_op_handle_t *
xio_l_rate_attr_to_handle(
    l_xio_rate_handle_t *               daddy,
    l_xio_rate_attr_t *                   attr,
    l_xio_rate_finished_func_t            finished_func,
    l_xio_rate_pass_func_t                pass_func)
{
    l_xio_rate_op_handle_t *            handle;

    if(attr->rate < 0)
    {
        return NULL;
    }
    handle = (l_xio_rate_op_handle_t *) globus_calloc(
        sizeof(l_xio_rate_op_handle_t), 1);
    if(handle == NULL)
    {
        goto error;
    }
    globus_mutex_init(&handle->mutex, NULL);
    handle->finished_func = finished_func;
    handle->pass_func = pass_func;

    if(attr->burst_size < 0)
    {
        attr->burst_size = 2 * attr->rate;
    }

    handle->per_tic = (int)((float)attr->rate *
        ((float)attr->us_period / 1000000.0f));
    GlobusTimeReltimeSet(handle->us_period, 0, attr->us_period);
    handle->max_allowed = attr->burst_size;

    return handle;
error:
    return NULL;
}

static
globus_result_t
globus_l_xio_rate_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_rate_handle_t *       handle;
    l_xio_rate_attr_rw_t *                attr;
    GlobusXIOName(globus_l_xio_rate_open);

    GlobusXIOTBDebugEnter();
    if(driver_attr == NULL)
    {
        attr = &l_xio_rate_default_attr;
    }
    else
    {
        attr = (l_xio_rate_attr_rw_t *) driver_attr;
    }

    handle = (l_xio_rate_handle_t *) 
        globus_calloc(1, sizeof(l_xio_rate_handle_t));

    handle->read_handle = xio_l_rate_attr_to_handle(
        handle,
        &attr->read_attr,
        globus_xio_driver_finished_read,
        globus_xio_driver_pass_read);

    handle->write_handle = xio_l_rate_attr_to_handle(
        handle,
        &attr->write_attr,
        globus_xio_driver_finished_write,
        globus_xio_driver_pass_write);

    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_rate_open_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusXIOTBDebugExit();
    return GLOBUS_SUCCESS;
error:
    l_xio_rate_destroy_handle(handle);
    return res;

}

static
globus_bool_t
xio_l_rate_ref_dec(
    l_xio_rate_handle_t *               handle,
    l_xio_rate_op_handle_t *            op_handle,
    globus_callback_func_t              cb)
{
    globus_bool_t                       b = GLOBUS_FALSE;

    globus_mutex_lock(&op_handle->mutex);
    {
        op_handle->ref--;
        if(op_handle->ref == 0)
        {
            b = GLOBUS_TRUE;
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
l_xio_rate_write_unreg(
    void *                              user_arg)
{
    l_xio_rate_handle_t *       handle;
    GlobusXIOName(l_xio_rate_read_unreg);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) user_arg;

    l_xio_rate_destroy_op_handle(handle->write_handle);
    globus_xio_driver_finished_close(handle->close_op, handle->close_result);
    globus_free(handle);

    GlobusXIOTBDebugExit();

}

static
void
l_xio_rate_read_unreg(
    void *                              user_arg)
{
    globus_bool_t                       b = GLOBUS_FALSE;
    l_xio_rate_handle_t *       handle;
    GlobusXIOName(l_xio_rate_read_unreg);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) user_arg;

    globus_mutex_lock(&xio_l_rate_hash_mutex);
    {
        if(handle->write_handle != NULL)
        {
            b = xio_l_rate_ref_dec(handle,
                handle->write_handle, l_xio_rate_write_unreg);
        }
    }
    globus_mutex_unlock(&xio_l_rate_hash_mutex);

    l_xio_rate_destroy_op_handle(handle->read_handle);
    if(!b)
    {
        globus_xio_driver_finished_close(handle->close_op, handle->close_result);
        globus_free(handle);
    }

    GlobusXIOTBDebugExit();
}

static
void
globus_l_xio_rate_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_bool_t                       b = GLOBUS_FALSE;
    l_xio_rate_handle_t *       handle;
    GlobusXIOName(globus_l_xio_rate_close_cb);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) user_arg;
    handle->close_result = result;

    globus_mutex_lock(&xio_l_rate_hash_mutex);
    {
        if(handle->read_handle != NULL)
        {
            b = xio_l_rate_ref_dec(handle,
                handle->read_handle, l_xio_rate_read_unreg);
        }
        if(!b)
        {
            if(handle->write_handle != NULL)
            {
                b = xio_l_rate_ref_dec(handle,
                    handle->write_handle, l_xio_rate_write_unreg);
            }
        }
    }
    globus_mutex_unlock(&xio_l_rate_hash_mutex);

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
globus_l_xio_rate_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_rate_handle_t *       handle;
    GlobusXIOName(globus_l_xio_rate_close);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) driver_specific_handle;

    handle->close_op = op;
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_rate_close_cb, handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }

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
globus_l_xio_rate_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_rate_handle_t *       handle;
    l_xio_rate_data_t *         data;
    GlobusXIOName(globus_l_xio_rate_read);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) driver_specific_handle;

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
        data = (l_xio_rate_data_t *) globus_calloc(
            1, sizeof(l_xio_rate_data_t));
        data->op = op;
        data->iovc = iovec_count;
        data->iov = (globus_xio_iovec_t *)
            globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
        data->op_handle = handle->read_handle;
        data->op_handle->data = data;
    
        GlobusIXIOUtilTransferIovec(data->iov, iovec, iovec_count);

        globus_mutex_lock(&data->op_handle->mutex);
        {
            l_xio_rate_net_ops(data->op_handle);
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
globus_l_xio_rate_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    l_xio_rate_handle_t *       handle;
    l_xio_rate_data_t *         data;
    GlobusXIOName(globus_l_xio_rate_write);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_rate_handle_t *) driver_specific_handle;

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
        data = (l_xio_rate_data_t *) globus_calloc(
            1, sizeof(l_xio_rate_data_t));
        data->op = op;
        data->iovc = iovec_count;
        data->iov = (globus_xio_iovec_t *)
            globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
        data->op_handle = handle->write_handle;
        data->op_handle->data = data;
    
        GlobusIXIOUtilTransferIovec(data->iov, iovec, iovec_count);

        globus_mutex_lock(&data->op_handle->mutex);
        {
            l_xio_rate_net_ops(data->op_handle);
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
globus_l_xio_rate_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_rate_attr_copy(
    void **                             dst,
    void *                              src)
{
    l_xio_rate_attr_rw_t *                src_attr;
    l_xio_rate_attr_rw_t *                dst_attr;

    src_attr = (l_xio_rate_attr_rw_t *) src;
    dst_attr = (l_xio_rate_attr_rw_t *) globus_calloc(1, sizeof(l_xio_rate_attr_rw_t));

    dst_attr->read_attr.rate = src_attr->read_attr.rate;
    dst_attr->read_attr.burst_size = src_attr->read_attr.burst_size;
    dst_attr->read_attr.us_period = src_attr->read_attr.us_period;
    dst_attr->write_attr.rate = src_attr->write_attr.rate;
    dst_attr->write_attr.us_period = src_attr->write_attr.us_period;
    dst_attr->write_attr.burst_size = src_attr->write_attr.burst_size;

    *dst = dst_attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_rate_attr_init(
    void **                             out_driver_attr)
{
    l_xio_rate_attr_t *                   attr;

    globus_l_xio_rate_attr_copy((void **)&attr, (void *)&l_xio_rate_default_attr);

    *out_driver_attr = attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_rate_attr_destroy(
    void *                              driver_attr)
{
    l_xio_rate_attr_rw_t *                attr;

    attr = (l_xio_rate_attr_rw_t *) driver_attr;
    globus_free(attr);

    return GLOBUS_SUCCESS;
}


static globus_xio_string_cntl_table_t  rate_l_string_opts_table[] =
{
    {"rate", GLOBUS_XIO_RATE_SET_RATE, globus_xio_string_cntl_formated_off},
    {"read_rate", GLOBUS_XIO_RATE_SET_READ_RATE, globus_xio_string_cntl_formated_off},
    {"write_rate", GLOBUS_XIO_RATE_SET_WRITE_RATE, globus_xio_string_cntl_formated_off},
    {"period", GLOBUS_XIO_RATE_SET_PERIOD, globus_xio_string_cntl_formated_int},
    {"read_period", GLOBUS_XIO_RATE_SET_READ_PERIOD, globus_xio_string_cntl_formated_int},
    {"write_period", GLOBUS_XIO_RATE_SET_WRITE_PERIOD, globus_xio_string_cntl_formated_int},
    {"burst", GLOBUS_XIO_RATE_SET_BURST, globus_xio_string_cntl_formated_int},
    {"read_burst", GLOBUS_XIO_RATE_SET_READ_BURST, globus_xio_string_cntl_formated_int},
    {"write_burst", GLOBUS_XIO_RATE_SET_WRITE_BURST, globus_xio_string_cntl_formated_int},
    {NULL, 0, NULL}
};


static
globus_result_t
globus_l_xio_rate_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    l_xio_rate_attr_rw_t *                attr;
    GlobusXIOName(globus_l_xio_rate_attr_cntl);

    attr = (l_xio_rate_attr_rw_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_RATE_SET_RATE:
            attr->read_attr.rate = va_arg(ap, globus_size_t);
            attr->write_attr.rate = attr->read_attr.rate;
            break;

        case GLOBUS_XIO_RATE_SET_PERIOD:
            attr->read_attr.us_period = va_arg(ap, int);
            attr->write_attr.us_period = attr->read_attr.us_period;
            break;

        case GLOBUS_XIO_RATE_SET_READ_RATE:
            attr->read_attr.rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_RATE_SET_READ_PERIOD:
            attr->read_attr.us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_RATE_SET_WRITE_RATE:
            attr->write_attr.rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_RATE_SET_WRITE_PERIOD:
            attr->write_attr.us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_RATE_SET_BURST:
            attr->read_attr.burst_size = va_arg(ap, globus_size_t);
            attr->write_attr.burst_size = attr->read_attr.burst_size;
            break;

        case GLOBUS_XIO_RATE_SET_READ_BURST:
            attr->read_attr.burst_size = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_RATE_SET_WRITE_BURST:
            attr->write_attr.burst_size = va_arg(ap, globus_size_t);
            break;

        default:
            break;
    }

    return GLOBUS_SUCCESS;
}


static globus_result_t
globus_l_xio_rate_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "rate", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_rate_open,
        globus_l_xio_rate_close,
        globus_l_xio_rate_read,
        globus_l_xio_rate_write,
        globus_l_xio_rate_cntl,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_rate_attr_init,
        globus_l_xio_rate_attr_copy,
        globus_l_xio_rate_attr_cntl,
        globus_l_xio_rate_attr_destroy);


    globus_xio_driver_string_cntl_set_table(driver, rate_l_string_opts_table);


    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_rate_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    rate,
    globus_l_xio_rate_init,
    globus_l_xio_rate_destroy);

static
int
globus_l_xio_rate_activate(void)
{
    int                                 rc;

    GlobusDebugInit(GLOBUS_XIO_TOKEN_BUCKET, TRACE);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(rate);
    }
    globus_mutex_init(&xio_l_rate_hash_mutex, NULL);
    
    l_xio_rate_default_attr.read_attr.rate = DEFAULT_RATE;
    l_xio_rate_default_attr.read_attr.us_period = DEFAULT_PERIOD_US;
    l_xio_rate_default_attr.read_attr.burst_size = -1;

    l_xio_rate_default_attr.write_attr.rate = DEFAULT_RATE;
    l_xio_rate_default_attr.write_attr.us_period = DEFAULT_PERIOD_US;
    l_xio_rate_default_attr.write_attr.burst_size = -1;

    return rc;
}

static
int
globus_l_xio_rate_deactivate(void)
{
    globus_mutex_destroy(&xio_l_rate_hash_mutex);

    GlobusXIOUnRegisterDriver(rate);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
