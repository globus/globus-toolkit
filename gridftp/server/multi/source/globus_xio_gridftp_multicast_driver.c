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
#include "globus_xio_gridftp_multicast_driver.h"
#include "globus_ftp_client.h"  
#include "version.h"

GlobusDebugDefine(GLOBUS_XIO_GRIDFTP_MULTICAST);
GlobusXIODeclareDriver(gridftp_multicast);

#define GlobusXIOGridftpMulticastDebugPrintf(level, message)                  \
    GlobusDebugPrintf(GLOBUS_XIO_GRIDFTP_MULTICAST, level, message)

#define GlobusXIOGridftpMulticastDebugEnter()                                 \
    GlobusXIOGridftpMulticastDebugPrintf(                                     \
        GLOBUS_L_XIO_GRIDFTP_MULTICAST_DEBUG_TRACE,                                         \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOGridftpMulticastDebugExit()                                  \
    GlobusXIOGridftpMulticastDebugPrintf(                                     \
        GLOBUS_L_XIO_GRIDFTP_MULTICAST_DEBUG_TRACE,                                         \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOGridftpMulticastDebugExitWithError()                         \
    GlobusXIOGridftpMulticastDebugPrintf(                                     \
        GLOBUS_L_XIO_GRIDFTP_MULTICAST_DEBUG_TRACE,                                         \
        ("[%s] Exiting with error\n", _xio_name))


#define GlobusXIOGMCNoOpError(_r)                                           \
    globus_error_put(GlobusXIOGMCNoOpErrorObj(_r))

#define GlobusXIOGMCNoOpErrorObj(_reason)                                   \
    globus_error_construct_error(                                           \
        GlobusXIOMyModule(gridftp_multicast),                               \
        NULL,                                                               \
        GLOBUS_XIO_GRIDFTP_MULTICAST_ERROR_NOOP,                            \
        __FILE__,                                                           \
        _xio_name,                                                          \
        __LINE__,                                                           \
        _XIOSL(_reason))                                


enum xio_l_error_levels
{
    GLOBUS_L_XIO_GRIDFTP_MULTICAST_DEBUG_TRACE          = 1,
    GLOBUS_L_XIO_GRIDFTP_MULTICAST_DEBUG_INTERNAL_TRACE
};

typedef enum xio_l_gmc_state_e
{
    XIO_GMC_STATE_OPENING = 1,
    XIO_GMC_STATE_OPEN,
    XIO_GMC_STATE_OPENING_ERROR,
    XIO_GMC_STATE_ERROR,
    XIO_GMC_STATE_CLOSING
} xio_l_gmc_state_t;

typedef struct xio_l_gridftp_multicast_attr_s
{
    globus_list_t *                     urls;
    int                                 P;
    globus_size_t                       tcp_bs;
    int                                 cast_count;
    globus_bool_t                       pass_write;
} xio_l_gridftp_multicast_attr_t;

typedef struct
{
    globus_ftp_client_handleattr_t      handle_attr;
    globus_ftp_client_operationattr_t   op_attr;
    char *                              stack_str;
    globus_ftp_client_handle_t          client_h;
    globus_bool_t                       closed;
    globus_bool_t                       closing;
    char *                              url;
    int                                 ndx;
    globus_fifo_t                       url_q;
    struct xio_l_gridftp_multicast_handle_s *   whos_my_daddy;
    globus_byte_t                       mt_buf[1];
} xio_l_gmc_ftp_handle_t;

typedef struct xio_l_gridftp_multicast_handle_s
{
    globus_mutex_t                      mutex;
    xio_l_gmc_ftp_handle_t *            ftp_handles;
    globus_xio_operation_t              open_op;
    globus_xio_operation_t              write_op;
    globus_xio_operation_t              close_op;
    int                                 op_count;
    int                                 write_op_count;
    int                                 ftps;
    globus_bool_t                       pass_write;
    xio_l_gmc_state_t                   state;
    globus_result_t                     result;
    globus_off_t                        offset;
    char *                              local_url;
    int                                 P;
    int                                 tcp_bs;
    globus_size_t                       nbytes;
} xio_l_gridftp_multicast_handle_t;

static
int
xio_l_gridftp_multicast_activate(void);

static
int
xio_l_gridftp_multicast_deactivate(void);

GlobusXIODefineModule(gridftp_multicast) =
{
    "globus_xio_gridftp_multicast",
    xio_l_gridftp_multicast_activate,
    xio_l_gridftp_multicast_deactivate,
    NULL,
    NULL,
    &local_version
};

static xio_l_gridftp_multicast_attr_t   xio_l_gmc_default_attr;

static
globus_result_t
xio_l_gmc_setup_forwarder(
    xio_l_gmc_ftp_handle_t *            ftp_handle,
    globus_fifo_t *                     url_q,
    int                                 max_str_len,
    int                                 each_cast_count);

static
void
xio_l_gmc_destroy_forwarder(
    xio_l_gmc_ftp_handle_t *            ftp_handle);

static
void
xio_l_gmc_handle_destroy(
    xio_l_gridftp_multicast_handle_t *  handle)
{
    int                                 i;
    xio_l_gmc_ftp_handle_t *            ftp_handle;

    globus_mutex_destroy(&handle->mutex);
    for(i = 0; i < handle->ftps; i++)
    {
        ftp_handle = &handle->ftp_handles[i];

        globus_fifo_destroy(&ftp_handle->url_q);
    }

    globus_free(handle->ftp_handles);
    globus_free(handle);
}

static
globus_result_t
xio_l_gmc_merge_error(
    globus_result_t                     old_result,
    globus_object_t *                   new_err_obj,
    char *                              url,
    char *                              stack_str,
    const char *                        func_name,
    int                                 line)
{
    globus_object_t *                   err;
    char *                              old_string;
    char *                              new_reason;
    char *                              reason;

    if(old_result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(old_result);
        old_string = globus_error_print_friendly(err);
        globus_object_free(err);
    }
    else
    {
        old_string = strdup("");
    }
    new_reason = globus_error_print_friendly(new_err_obj);

    reason = globus_common_create_string(
        "FAIL: %s: %s\n%s", url, new_reason, old_string);

    err = globus_error_construct_error(
         GlobusXIOMyModule(gridftp_multicast),
         NULL,
         GLOBUS_XIO_GRIDFTP_MULTICAST_ERROR_TRANSFER_FAILURES,
         __FILE__,
        func_name,
       __LINE__,
        reason);

    globus_free(old_string);
    globus_free(new_reason);
    globus_free(reason);

    return globus_error_put(err);
}


static
int
xio_l_gridftp_multicast_activate()
{
    int rc;
    GlobusXIOName(xio_l_gridftp_activate);

    GlobusDebugInit(GLOBUS_XIO_GRIDFTP_MULTICAST, TRACE);
    GlobusXIOGridftpMulticastDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }
    rc = globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_ftp_client_activate;
    }
    GlobusXIORegisterDriver(gridftp_multicast);
    GlobusXIOGridftpMulticastDebugExit();
    return GLOBUS_SUCCESS;

error_ftp_client_activate:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
error_xio_system_activate:
    GlobusXIOGridftpMulticastDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_GRIDFTP_MULTICAST);
    return rc;
}


static
int
xio_l_gridftp_multicast_deactivate()
{   
    int rc;
    GlobusXIOName(xio_l_gridftp_multicast_deactivate);
    
    GlobusXIOGridftpMulticastDebugEnter();
    GlobusXIOUnRegisterDriver(gridftp_multicast);
    rc = globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    GlobusXIOGridftpMulticastDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_GRIDFTP_MULTICAST);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusXIOGridftpMulticastDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_GRIDFTP_MULTICAST);
    return rc;
}


static
void
xio_l_gmc_put_done(
    void *                              user_arg,
    globus_ftp_client_handle_t *        in_handle,
    globus_object_t *                   err)
{
    int                                 i;
    globus_bool_t                       finish_open = GLOBUS_FALSE;
    globus_bool_t                       finish_close = GLOBUS_FALSE;
    xio_l_gridftp_multicast_handle_t *  handle;
    xio_l_gmc_ftp_handle_t *            ftp_handle;
    globus_result_t                     result;
    GlobusXIOName(xio_l_gmc_put_done);

    ftp_handle = (xio_l_gmc_ftp_handle_t *) user_arg;
    handle = ftp_handle->whos_my_daddy;

    globus_mutex_lock(&handle->mutex);
    {
        ftp_handle->closed = GLOBUS_TRUE;
        handle->ftps--;
        globus_ftp_client_handle_destroy(&ftp_handle->client_h);
        if(err != NULL)
        {
            result = globus_error_put(globus_object_copy(err));
            goto error;
        }

        switch(handle->state)
        {
            case XIO_GMC_STATE_OPEN:
                /* XXX this is a premature end?  must close all the others */
                handle->state = XIO_GMC_STATE_ERROR;
                break;

            case XIO_GMC_STATE_ERROR:
                break;

            case XIO_GMC_STATE_OPENING_ERROR:
                result = handle->result;
                handle->op_count--;
                if(handle->op_count == 0)
                {
                    finish_open = GLOBUS_TRUE;
                }
                break;

            case XIO_GMC_STATE_OPENING:
                handle->op_count--;
                if(handle->op_count == 0)
                {
                    finish_open = GLOBUS_TRUE;
                    handle->state = XIO_GMC_STATE_OPEN;
                }
                break;

            case XIO_GMC_STATE_CLOSING:
                handle->op_count--;
                if(handle->op_count == 0)
                {
                    finish_close = GLOBUS_TRUE;
                }
                break;
        }

    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_open)
    {
        globus_xio_driver_finished_open(handle, handle->open_op, result);

        if(result != GLOBUS_SUCCESS)
        {
            xio_l_gmc_handle_destroy(handle);
        }
    }
    if(finish_close)
    {
        globus_xio_driver_finished_close(handle->close_op, handle->result);

        xio_l_gmc_handle_destroy(handle);
    }

    return;

error:

    handle->result = xio_l_gmc_merge_error(
        handle->result,
        err,
        ftp_handle->url,
        ftp_handle->stack_str,
        _xio_name,
        __LINE__);
    switch(handle->state)
    {
        case XIO_GMC_STATE_OPEN:
            handle->state = XIO_GMC_STATE_ERROR;
            /* walk through and close all the others */
            break;

        case XIO_GMC_STATE_ERROR:
            break;

        case XIO_GMC_STATE_OPENING:
            handle->state = XIO_GMC_STATE_OPENING_ERROR;
            /* kill every thing that is still open */
            for(i = 0; i < handle->ftps; i++)
            {
                xio_l_gmc_destroy_forwarder(&handle->ftp_handles[i]);
            }
        case XIO_GMC_STATE_OPENING_ERROR:
            /* set the error */
            handle->result = xio_l_gmc_merge_error(
                handle->result,
                err,
                ftp_handle->url,
                ftp_handle->stack_str,
                _xio_name,
                __LINE__);

            handle->op_count--;
            if(handle->op_count == 0)
            {
                finish_open = GLOBUS_TRUE;
            }
            break;

        case XIO_GMC_STATE_CLOSING:
            handle->op_count--;
            if(handle->op_count == 0)
            {
                finish_close = GLOBUS_TRUE;
            }
            break;
    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_open)
    {
        globus_xio_driver_finished_open(handle, handle->open_op, result);

        xio_l_gmc_handle_destroy(handle);
    }
    if(finish_close)
    {
        globus_xio_driver_finished_close(handle->close_op, handle->result);

        xio_l_gmc_handle_destroy(handle);
    }
}

static
void
xio_l_gridftp_multicast_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_bool_t                       finish_open = GLOBUS_FALSE;
    int                                 i;
    xio_l_gridftp_multicast_handle_t *  handle;
    GlobusXIOName(xio_l_gridftp_multicast_open_cb);

    handle = (xio_l_gridftp_multicast_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        switch(handle->state)
        {
            case XIO_GMC_STATE_OPENING:
                finish_open = GLOBUS_TRUE;
                handle->state = XIO_GMC_STATE_OPEN;
                result = GLOBUS_SUCCESS;
                break;

            case XIO_GMC_STATE_OPENING_ERROR:
                handle->op_count--;
                if(handle->op_count == 0)
                {
                    finish_open = GLOBUS_TRUE;
                }
                result = handle->result;
                break;

            case XIO_GMC_STATE_ERROR:
            case XIO_GMC_STATE_OPEN:
            case XIO_GMC_STATE_CLOSING:
                globus_assert(0 && "bad state");
        }
    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_open)
    {
        globus_xio_driver_finished_open(handle, handle->open_op, result);

        if(result != GLOBUS_SUCCESS)
        {
            xio_l_gmc_handle_destroy(handle);
        }
    }

    return;

error:

    /* XXX need to merge in result */

    switch(handle->state)
    {
        case XIO_GMC_STATE_OPENING:
            handle->state = XIO_GMC_STATE_OPENING_ERROR;
            handle->op_count--;
            if(handle->op_count == 0)
            {
                finish_open = GLOBUS_TRUE;
            }
            else
            {
                /* shut down everything that is open */
                for(i = 0; i < handle->ftps; i++)
                {
                    xio_l_gmc_destroy_forwarder(&handle->ftp_handles[i]);
                }
            }

            break;

        case XIO_GMC_STATE_OPENING_ERROR:
            handle->op_count--;
            if(handle->op_count == 0)
            {
                finish_open = GLOBUS_TRUE;
            }
            break;

        case XIO_GMC_STATE_ERROR:
        case XIO_GMC_STATE_OPEN:
        case XIO_GMC_STATE_CLOSING:
            globus_assert(0 && "bad state");
    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_open)
    {
        globus_xio_driver_finished_open(handle, handle->open_op, result);

        globus_assert(result != GLOBUS_SUCCESS);
        xio_l_gmc_handle_destroy(handle);
    }
}

globus_result_t
xio_l_gridftp_multicast_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    int                                 error_cast_count;
    int                                 each_cast_count;
    int                                 total_url_count;
    int                                 cast_count;
    char *                              str;
    globus_list_t *                     list;
    int                                 i;
    xio_l_gridftp_multicast_attr_t *    attr;
    xio_l_gridftp_multicast_handle_t *  handle;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 str_max_len = 0;
    globus_fifo_t                       url_q;
    GlobusXIOName(xio_l_gridftp_multicast_open);

    attr = (xio_l_gridftp_multicast_attr_t *) driver_attr;

    if(attr == NULL)
    {
        /*set attr to some default */
        attr = &xio_l_gmc_default_attr;
    }

    handle = (xio_l_gridftp_multicast_handle_t *) globus_calloc(
        1, sizeof(xio_l_gridftp_multicast_handle_t));
    globus_mutex_init(&handle->mutex, NULL);
    handle->local_url = strdup(contact_info->unparsed);
    handle->P = attr->P;    
    handle->tcp_bs = attr->tcp_bs;
    handle->pass_write = attr->pass_write;

    /* move the list in the attr to a fifo */
    globus_fifo_init(&url_q);
    for(list = attr->urls;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        str = (char *) globus_list_first(list);
        globus_fifo_enqueue(&url_q, globus_libc_strdup(str));

        /* get the largest possible string length for later mem management */
        str_max_len += strlen(str);
    }

    /* turn down the cast count if we do not have enough urls left */
    cast_count = attr->cast_count;
    if(globus_fifo_size(&url_q) < cast_count)
    {
        cast_count = globus_fifo_size(&url_q);
    }

    /* here down is where callbacks start to be registered so we lock */
    globus_mutex_lock(&handle->mutex);
    {
        handle->open_op = op;
        /* if we have anyone to forward onto */
        total_url_count = globus_fifo_size(&url_q);
        if(cast_count != 0)
        {
            /* allocate a forwarder handle for everyone that needs one */
            handle->ftp_handles = (xio_l_gmc_ftp_handle_t *)
                globus_calloc(cast_count, sizeof(xio_l_gmc_ftp_handle_t));
            for(i = 0; i < cast_count; i++)
            {
                handle->ftp_handles[i].whos_my_daddy = handle;
                handle->ftp_handles[i].url = (char *)
                    globus_fifo_dequeue(&url_q);
                handle->ftp_handles[i].ndx = i;
                globus_fifo_init(&handle->ftp_handles[i].url_q);
            }
            each_cast_count = total_url_count / cast_count;

            /* if not an even divisor give each 1 extra for an even
                distribution of the remainder */
            if(total_url_count % cast_count != 0)
            {
                each_cast_count++;
            }

            /* attach the next url strings to all the receivers */
            for(i = 0; i < cast_count; i++)
            {
                result = xio_l_gmc_setup_forwarder(
                    &handle->ftp_handles[i],
                    &url_q, str_max_len, each_cast_count);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_forward_setup;
                }

                /* keep a count of successfull ones for clean up */
                error_cast_count++;
                handle->op_count++;
                handle->ftps++;
            }
        }

        if(handle->pass_write)
        {
            /*alter resource and pass down */
            result = globus_xio_driver_pass_open(
                op, contact_info, xio_l_gridftp_multicast_open_cb, handle);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_disk_open;
            }
            handle->op_count++;
        }

        if(handle->op_count == 0)
        {
            /* This is the only case when we should return an error */
            result = GlobusXIOGMCNoOpError("Nothing to open");
            goto error_no_operations;
        }

        handle->state = XIO_GMC_STATE_OPENING;
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

error_forward_setup:
error_disk_open:

    for(i = 0; i < error_cast_count; i++)
    {
        xio_l_gmc_destroy_forwarder(&handle->ftp_handles[i]);
        handle->result = result;
        result = GLOBUS_SUCCESS; /* gotta wait for callbacks */
    }
    handle->state = XIO_GMC_STATE_OPENING_ERROR;

    globus_mutex_unlock(&handle->mutex);

error_no_operations:
    xio_l_gmc_handle_destroy(handle);

    return result;
}

static
void
xio_l_gmc_destroy_forwarder(
    xio_l_gmc_ftp_handle_t *            ftp_handle)
{
    globus_result_t                     result;

    if(ftp_handle->closing)
    {
        return;
    }

    ftp_handle->closing = GLOBUS_TRUE;
    result = globus_ftp_client_abort(&ftp_handle->client_h);
}

static
globus_result_t
xio_l_gmc_setup_forwarder(
    xio_l_gmc_ftp_handle_t *            ftp_handle,
    globus_fifo_t *                     url_q,
    int                                 max_str_len,
    int                                 each_cast_count)
{
    int                                 cast_count;
    char *                              stack_str;
    int                                 stack_str_ndx;
    int                                 i;
    char *                              str;
    globus_result_t                     result;
    char                                delim = '#';
    xio_l_gridftp_multicast_handle_t *  handle;
    globus_ftp_control_parallelism_t    para;

    handle = ftp_handle->whos_my_daddy;

    cast_count = 0;
    stack_str = malloc(max_str_len);
    stack_str_ndx = 0;
    for(i = 0; i < each_cast_count; i++)
    {
        if(!globus_fifo_empty(url_q))
        {
            str = (char *) globus_fifo_dequeue(url_q);
            globus_fifo_enqueue(&ftp_handle->url_q, str);

            stack_str[stack_str_ndx] = delim;
            stack_str_ndx++;
            strcpy(&stack_str[stack_str_ndx], str);
            stack_str_ndx += strlen(str);
            cast_count++;
        }
        stack_str[stack_str_ndx] = '\0';
    }
    /* if we have anyone to send to */
    globus_ftp_client_handleattr_init(&ftp_handle->handle_attr);
    globus_ftp_client_operationattr_init(&ftp_handle->op_attr);

    result = globus_ftp_client_operationattr_set_mode(
        &ftp_handle->op_attr,
        GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }

    para.fixed.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
    para.fixed.size = handle->P;
    result = globus_ftp_client_operationattr_set_parallelism(
        &ftp_handle->op_attr,
        &para);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }

    if(*stack_str != '\0')
    {
        ftp_handle->stack_str = globus_common_create_string(
            "file,gridftp_multicast:urls=%s", stack_str);

        result = globus_ftp_client_operationattr_set_disk_stack(
            &ftp_handle->op_attr,
            ftp_handle->stack_str);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_attr;
        }
    }
    result = globus_ftp_client_handle_init(
        &ftp_handle->client_h, &ftp_handle->handle_attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    result = globus_ftp_client_put(
        &ftp_handle->client_h,
        ftp_handle->url,
        &ftp_handle->op_attr,
        NULL,
        xio_l_gmc_put_done,
        ftp_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_handle;
    }
    globus_free(stack_str);

    return GLOBUS_SUCCESS;

error_handle:
    globus_ftp_client_handle_destroy(&ftp_handle->client_h);
error_attr:
    globus_ftp_client_handleattr_destroy(&ftp_handle->handle_attr);
    globus_ftp_client_operationattr_destroy(&ftp_handle->op_attr);
    globus_free(stack_str);

    /* is this safe ? */
    return result;
}

static
void
xio_l_gmc_ftp_write_cb(
    void *                              user_arg,
    globus_ftp_client_handle_t *        in_handle,
    globus_object_t *                   err,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    globus_bool_t                       finish_write = GLOBUS_FALSE;
    xio_l_gridftp_multicast_handle_t *  handle;
    xio_l_gmc_ftp_handle_t *            ftp_handle;
    GlobusXIOName(xio_l_gmc_ftp_write_cb);

    ftp_handle = (xio_l_gmc_ftp_handle_t *) user_arg;
    handle = ftp_handle->whos_my_daddy;

    globus_mutex_lock(&handle->mutex);
    {
        handle->write_op_count--;
        if(err != NULL)
        {
            handle->result = xio_l_gmc_merge_error(
                handle->result,
                err,
                ftp_handle->url,
                ftp_handle->stack_str,
                _xio_name,
                __LINE__);
        }
        if(handle->write_op_count == 0 && handle->write_op != NULL)
        {
            finish_write = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_write)
    {
        globus_xio_driver_finished_write(
            handle->write_op, handle->result, handle->nbytes);
    }
}

static
void
xio_l_gmc_disk_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_bool_t                       finish_write = GLOBUS_FALSE;
    xio_l_gridftp_multicast_handle_t *  handle;
    GlobusXIOName(xio_l_gmc_disk_write_cb);

    handle = (xio_l_gridftp_multicast_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        handle->write_op_count--;
        if(result != GLOBUS_SUCCESS)
        {
            handle->result = xio_l_gmc_merge_error(
                handle->result,
                globus_error_get(result),
                handle->local_url,
                "",
                _xio_name,
                __LINE__);
        }
        if(handle->write_op_count == 0)
        {
            finish_write = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_write)
    {
        globus_xio_driver_finished_write(
            handle->write_op, handle->result, handle->nbytes);
    }
}

static
globus_result_t
xio_l_gridftp_multicast_read(
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
xio_l_gridftp_multicast_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_size_t                       wait_for;
    int                                 i;
    int                                 j;
    xio_l_gridftp_multicast_handle_t *  handle;
    xio_l_gmc_ftp_handle_t *            ftp_handle;
    globus_result_t                     result;
    globus_off_t                        offset;
    GlobusXIOName(xio_l_gridftp_multicast_write);
    
    handle = (xio_l_gridftp_multicast_handle_t *) driver_specific_handle;

    globus_mutex_lock(&handle->mutex);
    {
        handle->write_op = op;
        switch(handle->state)
        {
            case XIO_GMC_STATE_OPEN:
                /* this is the standard case */
                for(i = 0; i < handle->ftps; i++)
                {
                    ftp_handle = &handle->ftp_handles[i];
                    offset = 0;
                    for(j = 0; j < iovec_count; j++)
                    {
                        if(iovec[j].iov_len > 0)
                        {
                            result = globus_ftp_client_register_write(
                                &ftp_handle->client_h,
                                iovec[j].iov_base,
                                iovec[j].iov_len,
                                handle->offset,
                                GLOBUS_FALSE,
                                xio_l_gmc_ftp_write_cb,
                                ftp_handle);
                            if(result != GLOBUS_SUCCESS)
                            {
                                goto error_register;
                            }
                            offset += iovec[j].iov_len;
                            handle->write_op_count++;
                        }
                    }
                }
                handle->offset += offset;

                wait_for = 0;
                for(i = 0; i < iovec_count; i++)
                {
                    wait_for += iovec[i].iov_len;
                }
                handle->nbytes = wait_for;
                if(handle->pass_write)
                {
                    result = globus_xio_driver_pass_write(
                        op,
                        (globus_xio_iovec_t *)iovec,
                        iovec_count,
                        wait_for,
                        xio_l_gmc_disk_write_cb,
                        handle);
                    if(result != GLOBUS_SUCCESS)
                    {
                        goto error_pass;
                    }
                    handle->write_op_count++;
                }
                break;

            case XIO_GMC_STATE_ERROR:
                /* an ftp error occured out of band. just return an
                    error */
                result = handle->result;
                goto error_state;
                break;
    
            case XIO_GMC_STATE_OPENING_ERROR:
            case XIO_GMC_STATE_OPENING:
            case XIO_GMC_STATE_CLOSING:
                /* none of these should be possible */
                globus_assert(0 && "bad state");
                break;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

error_pass:
error_register:
    for(i = 0; i < handle->ftps; i++)
    {
        xio_l_gmc_destroy_forwarder(&handle->ftp_handles[i]);
    }
error_state:

    handle->write_op = NULL;

    globus_mutex_unlock(&handle->mutex);

    return result;
}

static
void
xio_l_gmc_eof_cb(
    void *                              user_arg,
    globus_ftp_client_handle_t *        in_handle,
    globus_object_t *                   err,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    xio_l_gmc_ftp_handle_t *            ftp_handle;
    xio_l_gridftp_multicast_handle_t *  handle;
    GlobusXIOName(xio_l_gmc_eof_cb);

    ftp_handle = (xio_l_gmc_ftp_handle_t *) user_arg;
    handle = ftp_handle->whos_my_daddy;

    globus_mutex_lock(&handle->mutex);
    {
        if(err != NULL)
        {
            /* XXX merge in result */
            handle->result = globus_error_put(err);
        }
    }
    globus_mutex_unlock(&handle->mutex);
}

static
void
xio_l_gmc_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_bool_t                       finish_close = GLOBUS_FALSE;
    xio_l_gridftp_multicast_handle_t *  handle;
    GlobusXIOName(xio_l_gmc_close_cb);
    
    handle = (xio_l_gridftp_multicast_handle_t *) user_arg;
    globus_mutex_lock(&handle->mutex);
    {
        handle->op_count--;

        if(result != GLOBUS_SUCCESS)
        {
            /* XXX merge in result */
            handle->result = result;
        }
        if(handle->op_count == 0)
        {
            finish_close = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    if(finish_close)
    {
        globus_xio_driver_finished_close(handle->close_op, handle->result);
    }
}


static
globus_result_t
xio_l_gridftp_multicast_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    int                                 i;
    xio_l_gmc_ftp_handle_t *            ftp_handle;
    xio_l_gridftp_multicast_handle_t *  handle;
    GlobusXIOName(xio_l_gridftp_multicast_close);
    
    handle = (xio_l_gridftp_multicast_handle_t *) driver_specific_handle;

    globus_mutex_lock(&handle->mutex);
    {
        handle->close_op = op;
        switch(handle->state)
        {
            case XIO_GMC_STATE_OPEN:
                /* this is the standard case, write an eof, then wait for
                    closes */
            case XIO_GMC_STATE_ERROR:
                handle->state = XIO_GMC_STATE_CLOSING;
                handle->close_op = op;

                handle->op_count = handle->ftps;
                for(i = 0; i < handle->ftps; i++)
                {
                    ftp_handle = &handle->ftp_handles[i];
                    result = globus_ftp_client_register_write(
                        &ftp_handle->client_h,
                        ftp_handle->mt_buf,
                        0,
                        handle->offset,
                        GLOBUS_TRUE,
                        xio_l_gmc_eof_cb,
                        ftp_handle);
                    if(result != GLOBUS_SUCCESS)
                    {
                        /* XXX record error, but then treat as normal.
                            no matter what we need to get all the done
                            callbacks. so nothing to sweat */
                    }
                }

                if(handle->pass_write)
                {
                    result = globus_xio_driver_pass_close(
                        op, xio_l_gmc_close_cb, handle);
                    if(result != GLOBUS_SUCCESS)
                    {
                        goto error_pass;
                    }
                    handle->op_count++;
                }
                break;
    
            case XIO_GMC_STATE_OPENING_ERROR:
            case XIO_GMC_STATE_OPENING:
            case XIO_GMC_STATE_CLOSING:
                /* none of these should be possible */
                globus_assert(0 && "bad state");
                break;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

error_pass:
    globus_mutex_unlock(&handle->mutex);

    return result;


}

static
globus_result_t
xio_l_gridftp_multicast_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xio_l_gridftp_multicast_attr_init(
    void **                             out_attr)
{
    xio_l_gridftp_multicast_attr_t *    attr;

    attr = (xio_l_gridftp_multicast_attr_t *) 
        globus_calloc(1, sizeof(xio_l_gridftp_multicast_attr_t));

    attr->P = xio_l_gmc_default_attr.P;
    attr->tcp_bs = xio_l_gmc_default_attr.tcp_bs;
    attr->cast_count = xio_l_gmc_default_attr.cast_count;
    attr->pass_write = xio_l_gmc_default_attr.pass_write;
    
    *out_attr = attr;

    return GLOBUS_SUCCESS;
}


static globus_xio_string_cntl_table_t  
    xio_l_gridftp_multicast_string_opts_table[] =
{
    {"P", GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_PARALLEL,
        globus_xio_string_cntl_int},
    {"tcpbs", GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_TCPBS,
        globus_xio_string_cntl_formated_int},
    {"urls", GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_URLS,
        globus_xio_string_cntl_string_list},
    {"local_write", GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_LOCAL_WRITE,
        globus_xio_string_cntl_bool},
    {NULL, 0, NULL}
};

static
globus_result_t
xio_l_gridftp_multicast_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char **                             argv;
    int                                 i;
    xio_l_gridftp_multicast_attr_t *    attr;

    attr = (xio_l_gridftp_multicast_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_PARALLEL:
            attr->P = va_arg(ap, int);
            break;

        case GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_TCPBS:
            attr->tcp_bs = (globus_size_t) va_arg(ap, int);
            break;

            break;

        case GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_URLS:
            argv = (char **) va_arg(ap, char **);
            for(i = 0; argv[i] != NULL; i++)
            {
                globus_list_insert(&attr->urls, globus_libc_strdup(argv[i]));
            }
            break;

        case GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_LOCAL_WRITE:
            attr->pass_write = (globus_bool_t) va_arg(ap, globus_bool_t);
            break;
    }

    return GLOBUS_SUCCESS;
}


static
globus_result_t
xio_l_gridftp_multicast_attr_copy(
    void **                             dst,
    void *                              src)
{
    char *                              str;
    xio_l_gridftp_multicast_attr_t *    dst_attr; 
    xio_l_gridftp_multicast_attr_t *    src_attr;
    globus_list_t *                     list; 
    globus_fifo_t                       q;

    src_attr = (xio_l_gridftp_multicast_attr_t *) src;
    xio_l_gridftp_multicast_attr_init((void **)&dst_attr);

    dst_attr->P = src_attr->P;
    dst_attr->tcp_bs = src_attr->tcp_bs;
    dst_attr->cast_count = src_attr->cast_count;
    dst_attr->pass_write = src_attr->pass_write;

    globus_fifo_init(&q);
    for(list = src_attr->urls;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        str = (char *) globus_list_first(list);
        globus_fifo_enqueue(&q, globus_libc_strdup(str));
    }
    dst_attr->urls = globus_fifo_convert_to_list(&q);
    globus_fifo_destroy(&q);

    *dst = dst_attr;

    return GLOBUS_SUCCESS;
}


static
globus_result_t
xio_l_gridftp_multicast_attr_destroy(
    void *                              driver_attr)
{
    char *                              str;
    xio_l_gridftp_multicast_attr_t *    attr;

    attr = (xio_l_gridftp_multicast_attr_t *) driver_attr;

    while(!globus_list_empty(attr->urls))
    {
        str = (char *) globus_list_remove(&attr->urls, attr->urls);
        globus_free(str);
    }
    globus_list_free(attr->urls);
    globus_free(attr);

    return GLOBUS_SUCCESS;
}


static
globus_result_t
xio_l_gridftp_multicast_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(xio_l_gridftp_multicast_init);

    GlobusXIOGridftpMulticastDebugEnter();
    result = globus_xio_driver_init(&driver, "gridftp_multicast", NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "xio_l_driver_init", result);
        goto error_init;
    }
    globus_xio_driver_set_transform(
        driver,
        xio_l_gridftp_multicast_open,
        xio_l_gridftp_multicast_close,
        xio_l_gridftp_multicast_read,
        xio_l_gridftp_multicast_write,
        xio_l_gridftp_multicast_cntl,
        NULL);
    globus_xio_driver_set_attr(
        driver,
        xio_l_gridftp_multicast_attr_init,
        xio_l_gridftp_multicast_attr_copy,
        xio_l_gridftp_multicast_attr_cntl,
        xio_l_gridftp_multicast_attr_destroy);

    globus_xio_driver_string_cntl_set_table(
        driver,
        xio_l_gridftp_multicast_string_opts_table);

    *out_driver = driver;


    xio_l_gmc_default_attr.urls = NULL;
    xio_l_gmc_default_attr.P = 1;
    xio_l_gmc_default_attr.tcp_bs = 131072;
    xio_l_gmc_default_attr.cast_count = 2;
    xio_l_gmc_default_attr.pass_write = GLOBUS_TRUE;

    GlobusXIOGridftpMulticastDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIOGridftpMulticastDebugExitWithError();
    return result;
}


static
void
xio_l_gridftp_multicast_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


GlobusXIODefineDriver(
    gridftp_multicast,
    xio_l_gridftp_multicast_init,
    xio_l_gridftp_multicast_destroy);
