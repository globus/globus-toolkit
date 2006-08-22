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
#define DEFAULT_RATE                    ((1024*1024)/8)
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

typedef struct l_xio_tb_attr_s
{
    globus_off_t                        read_rate;
    int                                 read_us_period;
    globus_size_t                       read_burst_size;
    globus_off_t                        write_rate;
    int                                 write_us_period;
    globus_size_t                       write_burst_size;
} l_xio_tb_attr_t;

static l_xio_tb_attr_t                  l_xio_tb_default_attr =
{
    DEFAULT_RATE,
    DEFAULT_PERIOD_US,
    -1,
    DEFAULT_RATE,
    DEFAULT_PERIOD_US,
    -1
};

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
    l_xio_token_bucket_op_handle_t      read_handle;
    l_xio_token_bucket_op_handle_t      write_handle;
} l_xio_token_bucket_handle_t;

static
void
l_xio_tb_net_ops(
    l_xio_token_bucket_op_handle_t *    op_handle);

static
int
l_xio_tb_kmint(
    char *                              arg,
    globus_off_t *                      out_i)
{
    int                                 i;
    int                                 sc;

    sc = sscanf(arg, "%d", &i);
    if(sc != 1)
    {
        return 1;
    }
    if(strchr(arg, 'K') != NULL)
    {
        *out_i = (globus_off_t)i * 1024;
    }
    else if(strchr(arg, 'M') != NULL)
    {
        *out_i = (globus_off_t)i * 1024 * 1024;
    }
    else if(strchr(arg, 'G') != NULL)
    {
        *out_i = (globus_off_t)i * 1024 * 1024 * 1024;
    }
    else
    {
        *out_i = (globus_off_t)i;
    }

    return 0;
}

static
void
l_xio_token_bucket_destroy_handle(
    l_xio_token_bucket_handle_t *       handle)
{
    GlobusXIOName(l_xio_token_bucket_destroy_handle);

    GlobusXIOTBDebugEnter();

    globus_fifo_destroy(&handle->write_handle.q);
    globus_mutex_destroy(&handle->write_handle.mutex);
    globus_fifo_destroy(&handle->write_handle.q);
    globus_mutex_destroy(&handle->read_handle.mutex);

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
        globus_callback_register_periodic(
            &handle->read_handle.cb_handle,
            &handle->read_handle.us_period,
            &handle->read_handle.us_period,
            l_xio_tb_ticker_cb,
            &handle->read_handle);
        globus_callback_register_periodic(
            &handle->write_handle.cb_handle,
            &handle->write_handle.us_period,
            &handle->write_handle.us_period,
            l_xio_tb_ticker_cb,
            &handle->write_handle);
    }
    GlobusXIOTBDebugExit();
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
    l_xio_tb_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_token_bucket_open);

    GlobusXIOTBDebugEnter();
    if(driver_attr == NULL)
    {
        attr = &l_xio_tb_default_attr;
    }
    else
    {
        attr = (l_xio_tb_attr_t *) driver_attr;
    }

    handle = (l_xio_token_bucket_handle_t *) 
        globus_calloc(1, sizeof(l_xio_token_bucket_handle_t));

    globus_fifo_init(&handle->read_handle.q);
    globus_mutex_init(&handle->read_handle.mutex, NULL);
    handle->read_handle.finished_func = globus_xio_driver_finished_read;
    handle->read_handle.pass_func = globus_xio_driver_pass_read;
    handle->read_handle.per_tic = (int)((float)attr->read_rate *  
        ((float)attr->read_us_period / 1000000.0f));
    GlobusTimeReltimeSet(handle->read_handle.us_period,0,attr->read_us_period);
    handle->read_handle.max_allowed = attr->read_burst_size;

    globus_fifo_init(&handle->write_handle.q);
    globus_mutex_init(&handle->write_handle.mutex, NULL);
    handle->write_handle.finished_func = globus_xio_driver_finished_write;
    handle->write_handle.pass_func = globus_xio_driver_pass_write;
    handle->write_handle.per_tic = ((float)attr->write_rate * 
        ((float)attr->write_us_period / 1000000.0f));
    GlobusTimeReltimeSet(
        handle->write_handle.us_period,0,attr->write_us_period);
    handle->write_handle.max_allowed = attr->write_burst_size;


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
void
l_xio_tb_write_unreg(
    void *                              user_arg)
{
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(l_xio_tb_write_unreg);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) user_arg;
    l_xio_token_bucket_destroy_handle(handle);
    GlobusXIOTBDebugExit();
}

static
void
l_xio_tb_read_unreg(
    void *                              user_arg)
{
    l_xio_token_bucket_handle_t *       handle;
    GlobusXIOName(l_xio_tb_read_unreg);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) user_arg;

    globus_callback_unregister(
        handle->write_handle.cb_handle,
        l_xio_tb_write_unreg,
        handle,
        NULL);
    GlobusXIOTBDebugExit();
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

    res = globus_xio_driver_pass_close(op, NULL, NULL);

    globus_callback_unregister(
        handle->read_handle.cb_handle,
        l_xio_tb_read_unreg,
        handle,
        NULL);
    GlobusXIOTBDebugExit();

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
    l_xio_token_bucket_handle_t *       handle;
    l_xio_token_bucket_data_t *         data;
    GlobusXIOName(globus_l_xio_token_bucket_read);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) driver_specific_handle;

    data = (l_xio_token_bucket_data_t *) globus_calloc(
        1, sizeof(l_xio_token_bucket_data_t));
    data->op = op;
    data->iovc = iovec_count;
    data->current_iovc = iovec_count;
    data->iov = (globus_xio_iovec_t *)
        globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
    data->current_iov = (globus_xio_iovec_t *)
        globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
    data->op_handle = &handle->read_handle;
    data->wait_for = globus_xio_operation_get_wait_for(op);
    
    GlobusIXIOUtilTransferIovec(data->iov, iovec, iovec_count);

    globus_mutex_lock(&data->op_handle->mutex);
    {
        globus_fifo_enqueue(&data->op_handle->q, data);
        l_xio_tb_net_ops(data->op_handle);
    }
    globus_mutex_unlock(&data->op_handle->mutex);
    GlobusXIOTBDebugExit();

    return GLOBUS_SUCCESS;
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
    l_xio_token_bucket_handle_t *       handle;
    l_xio_token_bucket_data_t *         data;
    GlobusXIOName(globus_l_xio_token_bucket_write);

    GlobusXIOTBDebugEnter();
    handle = (l_xio_token_bucket_handle_t *) driver_specific_handle;

    data = (l_xio_token_bucket_data_t *) globus_calloc(
        1, sizeof(l_xio_token_bucket_data_t));
    data->op = op;
    data->iovc = iovec_count;
    data->current_iovc = iovec_count;
    data->iov = (globus_xio_iovec_t *)
        globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
    data->current_iov = (globus_xio_iovec_t *)
        globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
    data->op_handle = &handle->write_handle;
    data->wait_for = globus_xio_operation_get_wait_for(op);
    
    GlobusIXIOUtilTransferIovec(data->iov, iovec, iovec_count);

    globus_mutex_lock(&data->op_handle->mutex);
    {
        globus_fifo_enqueue(&data->op_handle->q, data);
        l_xio_tb_net_ops(data->op_handle);
    }
    globus_mutex_unlock(&data->op_handle->mutex);
    GlobusXIOTBDebugExit();

    return GLOBUS_SUCCESS;
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
    l_xio_tb_attr_t *                   src_attr;
    l_xio_tb_attr_t *                   dst_attr;

    src_attr = (l_xio_tb_attr_t *) src;
    dst_attr = (l_xio_tb_attr_t *) globus_calloc(1, sizeof(l_xio_tb_attr_t));

    dst_attr->read_rate = src_attr->read_rate;
    dst_attr->read_burst_size = src_attr->read_burst_size;
    dst_attr->read_us_period = src_attr->read_us_period;
    dst_attr->write_rate = src_attr->write_rate;
    dst_attr->write_us_period = src_attr->write_us_period;
    dst_attr->write_burst_size = src_attr->write_burst_size;

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
    l_xio_tb_attr_t *                   attr;

    attr = (l_xio_tb_attr_t *) driver_attr;
    globus_free(attr);

    return GLOBUS_SUCCESS;
}


static globus_i_xio_attr_parse_table_t  gsi_l_string_opts_table[] =
{
    {"rate", GLOBUS_XIO_TOKEN_BUCKET_SET_RATE, },
    {"read_rate", GLOBUS_XIO_TOKEN_BUCKET_SET_READ_RATE, },
    {"write_rate", GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_RATE, },
    {"period", GLOBUS_XIO_TOKEN_BUCKET_SET_PERIOD, },
    {"read_period", GLOBUS_XIO_TOKEN_BUCKET_SET_READ_PERIOD, },
    {"write_period", GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_PERIOD, },
    {"burst", , },
    {NULL, 0, NULL}
};


static
void
globus_l_xio_tb_attr_parse_opts(
    l_xio_tb_attr_t *                   attr,
    char *                              opts)
{
    globus_off_t                        rate;
    int                                 sc;
    int                                 int_val;
    char *                              tmp_str;
    char *                              key;
    char *                              val;
    GlobusXIOName(globus_l_xio_tb_attr_parse_opts);

    if(opts == NULL)
    {
        return;
    }

    key = "rate=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = strdup(tmp_str + strlen(key));
        tmp_str = strchr(val, '#');
        if(tmp_str != NULL)
        {
            *tmp_str = '\0';
        }

        sc = l_xio_tb_kmint(val, &rate);
        if(sc == 0)
        {
            attr->read_rate = rate / 8;
            attr->write_rate = rate / 8;
        }
        free(val);
    }
    key = "burst=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = strdup(tmp_str + strlen(key));
        tmp_str = strchr(val, '#');
        if(tmp_str != NULL)
        {
            *tmp_str = '\0';
        }

        sc = l_xio_tb_kmint(val, &rate);
        if(sc == 0)
        {
            attr->read_burst_size = rate;
            attr->write_burst_size = rate;
        }
        free(val);
    }
    key = "period=";
    tmp_str = strstr(opts, key);
    if(tmp_str != NULL)
    {
        val = strdup(tmp_str + strlen(key));
        tmp_str = strchr(val, '#');
        if(tmp_str != NULL)
        {
            *tmp_str = '\0';
        }
        sc = sscanf(val, "%d", &int_val);
        if(sc == 1)
        {
            attr->read_us_period = int_val;
            attr->write_us_period = int_val;
        }
        free(val);
    }
}

static
globus_result_t
globus_l_xio_tb_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              opts;
    l_xio_tb_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_tb_attr_cntl);

    attr = (l_xio_tb_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_SET_STRING_OPTIONS:
            opts = va_arg(ap, char *);
            globus_l_xio_tb_attr_parse_opts(attr, opts);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_RATE:
            attr->read_rate = va_arg(ap, globus_size_t);
            attr->write_rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_PERIOD:
            attr->read_us_period = va_arg(ap, int);
            attr->write_us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_READ_RATE:
            attr->read_rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_READ_PERIOD:
            attr->read_us_period = va_arg(ap, int);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_RATE:
            attr->write_rate = va_arg(ap, globus_size_t);
            break;

        case GLOBUS_XIO_TOKEN_BUCKET_SET_WRITE_PERIOD:
            attr->write_us_period = va_arg(ap, int);
            break;
    }

    return GLOBUS_SUCCESS;
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


    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_token_bucket_destroy(
    globus_xio_driver_t                 driver)
{
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
    
    return rc;
}

static
int
globus_l_xio_token_bucket_deactivate(void)
{
    GlobusXIOUnRegisterDriver(token_bucket);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
