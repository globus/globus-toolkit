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

#include "globus_xio.h"
#include "globus_i_xio.h"

/*
 *  read_op_list adn write_op_list
 *  ------------------------------
 *  list of operations whos callbacks have not yet *returned*.
 *  
 *  cancel walks this list and sets all operations to canceled, 
 *  calling the driver callbck if neccessary.  This goes for ops
 *  that are finsihed and currently in the users callback.  However
 *  this causes no problem because the cancled flag will not be looked
 *  at again, and the no driver will be registered for such csllbacks.
 */
/********************************************************************
 *                   data structure macros
 *******************************************************************/
#define GlobusXIOHandleSetup(h, a)                                          \
do                                                                          \
{                                                                           \
    globus_i_xio_handle_t *             _h;                                 \
    globus_i_xio_attr_t *               _a;                                 \
                                                                            \
    _h = (h);                                                               \
    _a = (a);                                                               \
                                                                            \
    if(_a != NULL)                                                          \
    {                                                                       \
        _h->open_timeout_cb = _a->open_timeout_cb;                          \
        GlobusTimeReltimeCopy(_h->open_timeout_period,                      \
            _a->open_timeout_period);                                       \
        _h->read_timeout_cb = _a->read_timeout_cb;                          \
        GlobusTimeReltimeCopy(_h->read_timeout_period,                      \
            _a->read_timeout_period);                                       \
        _h->write_timeout_cb = _a->write_timeout_cb;                        \
        GlobusTimeReltimeCopy(_h->write_timeout_period,                     \
            _a->write_timeout_period);                                      \
        _h->close_timeout_cb = _a->close_timeout_cb;                        \
        GlobusTimeReltimeCopy(_h->close_timeout_period,                     \
            _a->close_timeout_period);                                      \
        _h->timeout_arg = _a->timeout_arg;                                  \
    }                                                                       \
} while(0)

#define GlobusLXIOActiveTest()                                              \
    if(!globus_l_xio_active) return GlobusXIOErrorNotActivated()
/* 
 *  module activation
 */

#include "version.h"
#include "globus_i_xio.h"
#include "globus_xio.h"

char * globus_i_xio_handle_state_name_table[] =
{
    "GLOBUS_XIO_HANDLE_STATE_NONE",
    "GLOBUS_XIO_HANDLE_STATE_CLIENT",
    "GLOBUS_XIO_HANDLE_STATE_ACCEPTED",
    "GLOBUS_XIO_HANDLE_STATE_OPENING",
    "GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED",
    "GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING",
    "GLOBUS_XIO_HANDLE_STATE_OPEN",
    "GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED",
    "GLOBUS_XIO_HANDLE_STATE_CLOSING",
    "GLOBUS_XIO_HANDLE_STATE_CLOSED",
};

char * globus_i_xio_op_state_name_table[] =
{
    "GLOBUS_XIO_OP_STATE_NONE",
    "GLOBUS_XIO_OP_STATE_OPERATING",
    "GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING",
    "GLOBUS_XIO_OP_STATE_FINISH_WAITING",
    "GLOBUS_XIO_OP_STATE_FINISHED",
};

char * globus_i_xio_context_state_name_table[] =
{
    "GLOBUS_XIO_CONTEXT_STATE_NONE",
    "GLOBUS_XIO_CONTEXT_STATE_OPENING",
    "GLOBUS_XIO_CONTEXT_STATE_OPEN",
    "GLOBUS_XIO_CONTEXT_STATE_OPEN_FAILED",
    "GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED",
    "GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED",
    "GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED_AND_CLOSING",
    "GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED_AND_CLOSING",
    "GLOBUS_XIO_CONTEXT_STATE_CLOSING",
    "GLOBUS_XIO_CONTEXT_STATE_OPENING_AND_CLOSING",
    "GLOBUS_XIO_CONTEXT_STATE_CLOSED",
};

                                                                                
globus_i_xio_timer_t                    globus_i_xio_timeout_timer;
globus_list_t *                         globus_i_xio_outstanding_handles_list;
globus_mutex_t                          globus_i_xio_mutex;
globus_cond_t                           globus_i_xio_cond;

static globus_bool_t                    globus_l_xio_active = GLOBUS_FALSE;

GlobusDebugDefine(GLOBUS_XIO);

static globus_result_t
globus_l_xio_register_close(
    globus_i_xio_op_t *                 op);

static globus_result_t
globus_l_xio_handle_cancel_operations(
    globus_i_xio_handle_t *             xio_handle,
    int                                 mask);

static globus_bool_t
globus_l_xio_timeout_callback(
    void *                              user_arg);

static void
globus_l_xio_open_close_callback(
    globus_i_xio_op_t *                 op,
    globus_result_t                     result,
    void *                              user_arg);

void
globus_i_xio_monitor_init(
    globus_i_xio_monitor_t *            monitor)
{
    monitor->count = 0;
}

void
globus_i_xio_monitor_destroy(
    globus_i_xio_monitor_t *            monitor)
{
}

static
globus_bool_t
globus_l_xio_handle_timeout_always(
    globus_xio_handle_t                 handle,
    globus_xio_operation_type_t         type,
    void *                              user_arg)
{
    return GLOBUS_TRUE;
}

void
globus_l_xio_oneshot_wrapper_cb(
    void *                              user_arg)
{
    globus_i_xio_space_info_t *         space_info;
    globus_i_xio_handle_t *             handle;
    globus_result_t                     res;

    space_info = (globus_i_xio_space_info_t *) user_arg;

    handle = space_info->handle;

    if(space_info->unregister)
    {
        /* remove my reference to the handle */
        res = globus_callback_unregister(space_info->ch, NULL, NULL, NULL);
        if(res != GLOBUS_SUCCESS)
        {
            globus_panic(GLOBUS_XIO_MODULE,res,_XIOSL("failed to unregister oneshot"));
        }
        globus_mutex_lock(&handle->context->cancel_mutex);
        {
            globus_list_remove(&handle->cb_list,
                globus_list_search(handle->cb_list, space_info));
        }   
        globus_mutex_unlock(&handle->context->cancel_mutex);
    }
    space_info->func(space_info->user_arg);
    globus_free(space_info);
}

static void
globus_l_xio_cancel_data_ops(
    globus_i_xio_handle_t *             handle)
{
    globus_list_t *                     list;
    globus_i_xio_op_t *                 tmp_op;
    GlobusXIOName(globus_l_xio_cancel_data_ops);

    GlobusXIODebugInternalEnter();

    for(list = handle->read_op_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        tmp_op = (globus_i_xio_op_t *) globus_list_first(list);
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
            (_XIOSL("[%s] : canceling read op @ 0x%x\n"), 
            _xio_name, tmp_op));
        globus_i_xio_operation_cancel(tmp_op, -1);
    }

    for(list = handle->write_op_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        tmp_op = (globus_i_xio_op_t *) globus_list_first(list);
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
            (_XIOSL("[%s] : canceling write op @ 0x%x\n"), 
            _xio_name, tmp_op));
        globus_i_xio_operation_cancel(tmp_op, -1);
    }
    GlobusXIODebugInternalExit();
}

void
globus_l_xio_open_close_callback_kickout(
    void *                              user_arg);

static
void
globus_l_xio_handle_unopened_close_callback(
    void *                              user_arg)
{
    globus_i_xio_op_t *                 op;
    globus_i_xio_handle_t *             handle;
    GlobusXIOName(globus_l_xio_handle_unopened_close_callback);

    GlobusXIODebugInternalEnter();
    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;
    
    globus_mutex_lock(&handle->context->mutex);
    GlobusXIOHandleStateChange(handle, GLOBUS_XIO_HANDLE_STATE_CLOSING);
    globus_mutex_unlock(&handle->context->mutex);
    
    globus_l_xio_open_close_callback_kickout(op);
    
    GlobusXIODebugInternalExit();
}

static
globus_result_t
globus_l_xio_handle_pre_close(
    globus_i_xio_handle_t *             handle,
    globus_xio_attr_t                   attr,
    globus_xio_callback_t               cb,
    void *                              user_arg,
    globus_bool_t                       blocking)
{
    void *                              driver_attr;
    int                                 ctr;
    globus_bool_t                       destroy_handle;
    globus_i_xio_op_t *                 op;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_handle_pre_close);

    GlobusXIODebugInternalEnter();

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto err;
    }
    
    /*
     *  set up the operation
     */
    op->type = GLOBUS_XIO_OPERATION_TYPE_CLOSE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_cb = cb;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1;/*for first pass there is no return*/
    op->blocking = blocking;
    if(blocking)
    {
        op->blocked_thread = GlobusXIOThreadSelf();
    }
    
    switch(handle->state)
    {
        /* the following 3 states catch the case where a handle is closed
         * either before opening (accepted or client) or after an open has
         * failed (open failed).  We don't pass the close down in these cases,
         * so we fake a close.
         */
        case GLOBUS_XIO_HANDLE_STATE_ACCEPTED:
            for(ctr = 0;  ctr < handle->context->stack_size; ctr++)
            {
                if(handle->context->entry[ctr].driver_handle &&
                    handle->context->entry[ctr].driver->link_destroy_func)
                {
                    handle->context->entry[ctr].driver->link_destroy_func(
                        handle->context->entry[ctr].driver_handle);
                }
            }
        /* fall through */
        case GLOBUS_XIO_HANDLE_STATE_CLIENT:
        case GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED:
            attr = NULL;
            
            /* pretend we were opening (as this is the pre-opened state) */
            GlobusXIOHandleStateChange(handle,
                GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING);
            op->state = GLOBUS_XIO_OP_STATE_FINISH_WAITING;
            handle->ref++; /* for the opperation */
            
            globus_i_xio_register_oneshot(
                handle,
                globus_l_xio_handle_unopened_close_callback,
                op,
                op->blocking ? GLOBUS_CALLBACK_GLOBAL_SPACE : handle->space);
            
            break;
        
        /* if opening, cancel the open */
        case GLOBUS_XIO_HANDLE_STATE_OPENING:
            globus_assert(handle->open_op != NULL);

            if(attr == NULL || !attr->no_cancel)
            {
                globus_mutex_lock(&handle->context->cancel_mutex);
                {
                    GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
                        (_XIOSL("[%s] : canceling open op @ 0x%x\n"), 
                        _xio_name, handle->open_op));
                    /* we delay the pass close until the open callback */
                    globus_i_xio_operation_cancel(handle->open_op, -1);

                    /* cancel any data ops */
                    globus_l_xio_cancel_data_ops(handle);
                }
                globus_mutex_unlock(&handle->context->cancel_mutex);
            }
            GlobusXIOHandleStateChange(handle,
                GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING);
            break;
        
        case GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED:
            GlobusXIOHandleStateChange(handle,
                GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING);
            break;
            
        case GLOBUS_XIO_HANDLE_STATE_OPEN:
            GlobusXIOHandleStateChange(handle,
                GLOBUS_XIO_HANDLE_STATE_CLOSING);

            if(attr == NULL || !attr->no_cancel)
            {
                /* cancel any data ops */
                globus_mutex_lock(&handle->context->cancel_mutex);
                {
                    globus_l_xio_cancel_data_ops(handle);
                }
                globus_mutex_unlock(&handle->context->cancel_mutex);
            }
            break;
            
        case GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING:
        case GLOBUS_XIO_HANDLE_STATE_CLOSED:
        case GLOBUS_XIO_HANDLE_STATE_CLOSING:
            res = GlobusXIOErrorInvalidState(handle->state);
            goto err;
            break;

        default:
            res = GlobusXIOErrorParameter("handle");
            goto err;
            break;
    }

    /* set up op */
    for(ctr = 0; ctr < handle->context->stack_size; ctr++)
    {
        op->entry[ctr].close_attr = NULL;
        if(attr != NULL)
        {
            driver_attr = NULL;
            GlobusIXIOAttrGetDS(driver_attr, attr,
                handle->context->entry[ctr].driver);

            if(driver_attr != NULL)
            {
                handle->context->entry[ctr].driver->attr_copy_func(
                    &op->entry[ctr].close_attr, driver_attr);
            }
        }
    }
    handle->close_op = op;
    
    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  err:
    handle->ref++;
        /* so destroy handle can't be true (will be removed in next call) */
    op->ref = 0;
    globus_i_xio_op_destroy(op, &destroy_handle);

    GlobusXIODebugInternalExitWithError();
    return res;
}

void
globus_i_xio_close_handles(
    globus_xio_driver_t                 driver)
{
    globus_list_t *                     tmp_list;
    globus_list_t *                     c_handles = NULL;
    globus_xio_handle_t                 handle;
    globus_i_xio_context_t *            context;
    globus_xio_server_t                 server;
    globus_i_xio_op_t *                 dd;
    globus_xio_attr_t                   attr;
    globus_bool_t                       found;
    int                                 ctr;
    globus_i_xio_monitor_t              monitor;
    globus_result_t                     res;
    GlobusXIOName(globus_i_xio_close_handles);

    GlobusXIODebugInternalEnter();
    
    GlobusXIODebugPrintf(
        GLOBUS_XIO_DEBUG_INFO, 
        (_XIOSL("[globus_i_xio_close_handles]: closing driver @0x%x, %s\n"), 
        driver, driver ? driver->name : "(null)"));
        
    globus_i_xio_monitor_init(&monitor);
    
    /* first destroy all of the dds, as they have references on the handle */
    globus_mutex_lock(&globus_i_xio_mutex);
    {
        tmp_list = globus_list_copy(globus_i_xio_outstanding_dds_list);
        while(!globus_list_empty(tmp_list))
        {
            dd = (globus_i_xio_op_t *) globus_list_remove(&tmp_list, tmp_list);
            context = dd->_op_context;
            globus_mutex_lock(&context->mutex);
            {
                found = GLOBUS_FALSE;
                for(ctr = 0; 
                    ctr < context->stack_size && !found; 
                    ctr++)
                {
                    GlobusXIODebugPrintf(
                        GLOBUS_XIO_DEBUG_INFO_VERBOSE, 
                        (_XIOSL("[globus_i_xio_close_handles]: checking dd @0x%x "
                            "driver @0x%x, %s\n"), 
                        dd,
                        context->entry[ctr].driver,
                        context->entry[ctr].driver->name));
        
                    if(driver == NULL || 
                        context->entry[ctr].driver == driver)
                    {
                        GlobusXIODebugPrintf(
                            GLOBUS_XIO_DEBUG_INFO, 
                            (_XIOSL("[globus_i_xio_close_handles] : "
                            "will destroy dd @0x%x\n"), dd));

                        found = GLOBUS_TRUE;
                        globus_list_insert(&c_handles, dd);
                    }
                }
            }
            globus_mutex_unlock(&context->mutex);
        }
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
    while(!globus_list_empty(c_handles))
    {
        dd = (globus_i_xio_op_t *) globus_list_remove(&c_handles, c_handles);
        globus_xio_data_descriptor_destroy(dd);
    }

    globus_mutex_lock(&globus_i_xio_mutex);
    {
        /* close all open handles */
        tmp_list = globus_list_copy(globus_i_xio_outstanding_handles_list);
        while(!globus_list_empty(tmp_list))
        {
            handle = (globus_xio_handle_t) 
                globus_list_remove(&tmp_list, tmp_list);

            globus_assert(handle->context != NULL);
            globus_mutex_lock(&handle->context->mutex);
            {
                /* if it is still in the list i must have no monitor */
                globus_assert(handle->sd_monitor == NULL);
                found = GLOBUS_FALSE;
                for(ctr = 0; 
                    ctr < handle->context->stack_size && !found; 
                    ctr++)
                {
                    GlobusXIODebugPrintf(
                        GLOBUS_XIO_DEBUG_INFO_VERBOSE, 
                        (_XIOSL("[globus_i_xio_close_handles]: checking handle @0x%x "
                            "driver @0x%x, %s\n"), 
                        handle,
                        handle->context->entry[ctr].driver,
                        handle->context->entry[ctr].driver->name));
        
                    /* cancel on al handles */
                    if(driver == NULL || 
                        handle->context->entry[ctr].driver == driver)
                    {
                        GlobusXIODebugPrintf(
                            GLOBUS_XIO_DEBUG_INFO, 
                            (_XIOSL("[globus_i_xio_close_handles] : "
                            "will wait on handle @0x%x state=%d\n"), 
                            handle, handle->state));

                        found = GLOBUS_TRUE;

                        /* remove from the main list */
                        globus_list_remove(
                            &globus_i_xio_outstanding_handles_list,
                            globus_list_search(
                                globus_i_xio_outstanding_handles_list, handle));

                        handle->sd_monitor = &monitor;
                        monitor.count++;
                        if(handle->state 
                            != GLOBUS_XIO_HANDLE_STATE_CLOSING &&
                           handle->state 
                            != GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING &&
                           handle->state 
                            != GLOBUS_XIO_HANDLE_STATE_CLOSED)
                        {
                            /* i suspect that res will always be true here */
                            res = globus_l_xio_handle_pre_close(
                                handle, NULL, NULL, NULL, GLOBUS_TRUE);
                            if(res != GLOBUS_SUCCESS)
                            {
                                /* if pree close fails we will not wait on 
                                    this handle */
                                monitor.count--;
                            }
                            else if(handle->state
                                != GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING)
                            {
                                globus_list_insert(&c_handles, handle);
                                GlobusXIODebugPrintf(
                                    GLOBUS_XIO_DEBUG_INFO, 
                                    (_XIOSL("[globus_i_xio_close_handles] : "
                                    "registersing close on handle @0x%x\n"), 
                                    handle));
                            }
                        }
                    }
                }
            }
            globus_mutex_unlock(&handle->context->mutex);
        }
        
        /* close all open servers */
        tmp_list = globus_list_copy(globus_i_xio_outstanding_servers_list);
        while(!globus_list_empty(tmp_list))
        {
            server = (globus_xio_server_t) 
                globus_list_remove(&tmp_list, tmp_list);
            
            globus_mutex_lock(&server->mutex);
            {
                globus_assert(server->sd_monitor == NULL);
                found = GLOBUS_FALSE;
                for(ctr = 0; 
                    ctr < server->stack_size && !found; 
                    ctr++)
                {
                    if(driver == NULL || 
                        server->entry[ctr].driver == driver)
                    {
                        found = GLOBUS_TRUE;
                        GlobusXIODebugPrintf(
                            GLOBUS_XIO_DEBUG_INFO, 
                            (_XIOSL("[globus_i_xio_close_handles] : "
                            "will wait on server @0x%x state=%d\n"), 
                            server, server->state));
                            
                        globus_list_remove(
                            &globus_i_xio_outstanding_servers_list,
                            globus_list_search(
                                globus_i_xio_outstanding_servers_list, server));
                        
                        server->sd_monitor = &monitor;
                        monitor.count++;
                        
                        if(server->state != 
                            GLOBUS_XIO_SERVER_STATE_CLOSE_PENDING &&
                            server->state != GLOBUS_XIO_SERVER_STATE_CLOSING &&
                            server->state != GLOBUS_XIO_SERVER_STATE_CLOSED)
                        {
                            res = globus_i_xio_server_close(
                                server, NULL, NULL);
                            if(res != GLOBUS_SUCCESS)
                            {
                                monitor.count--;
                            }
                        }
                    }
                }
            }
            globus_mutex_unlock(&server->mutex);
        }
        
        /* destroy the internals of all attrs */
        tmp_list = globus_list_copy(globus_i_xio_outstanding_attrs_list);
        while(!globus_list_empty(tmp_list))
        {
            attr = (globus_xio_attr_t)
                globus_list_remove(&tmp_list, tmp_list);
            for(ctr = 0;
                ctr < attr->ndx && 
                    driver != NULL && 
                    attr->entry[ctr].driver != driver;
                ctr++)
            { }

            if(ctr < attr->ndx)
            {
                globus_list_remove(
                    &globus_i_xio_outstanding_attrs_list,
                    globus_list_search(
                        globus_i_xio_outstanding_attrs_list, attr));
                            
                for(ctr = 0; ctr < attr->ndx; ctr++)
                {
                    attr->entry[ctr].driver->attr_destroy_func(
                        attr->entry[ctr].driver_data);
                }
                
                attr->unloaded = GLOBUS_TRUE;
            }
        }
    }
    globus_mutex_unlock(&globus_i_xio_mutex);

    while(!globus_list_empty(c_handles))
    {
        handle = (globus_xio_handle_t)
            globus_list_remove(&c_handles, c_handles);

        res = globus_l_xio_register_close(handle->close_op);
        if(res != GLOBUS_SUCCESS)
        {
            globus_mutex_lock(&globus_i_xio_mutex);
            {
                /* since callbak will not be called we dec here */
                monitor.count--;
            }
            globus_mutex_unlock(&globus_i_xio_mutex);
        }
    }

    globus_mutex_lock(&globus_i_xio_mutex);
    {
        while(monitor.count != 0)
        {
            globus_cond_wait(&globus_i_xio_cond, &globus_i_xio_mutex);
        }
    }
    globus_mutex_unlock(&globus_i_xio_mutex);

    globus_i_xio_monitor_destroy(&monitor);

    GlobusXIODebugInternalExit();
}

void
globus_i_xio_register_oneshot(
    globus_i_xio_handle_t *             handle,
    globus_callback_func_t              cb,
    void *                              user_arg,
    globus_callback_space_t             space)
{
    globus_result_t                     res;
    globus_i_xio_space_info_t *         space_info;
    globus_callback_handle_t *          ch = NULL;
    GlobusXIOName(globus_i_xio_register_oneshot);

    GlobusXIODebugInternalEnter();

    if(handle != NULL && space != GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        space_info = (globus_i_xio_space_info_t *)
            globus_malloc(sizeof(globus_i_xio_space_info_t));
        ch = &space_info->ch;
        space_info->func = cb;
        space_info->unregister = GLOBUS_TRUE;
        space_info->handle = handle;
        cb = globus_l_xio_oneshot_wrapper_cb;
        space_info->user_arg = user_arg;
        user_arg = space_info;
        globus_mutex_lock(&handle->context->cancel_mutex);
        {
            globus_list_insert(&handle->cb_list, space_info);
        }
        globus_mutex_unlock(&handle->context->cancel_mutex);
    }

    GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO, 
        (_XIOSL("registering to space %d, user_arg = 0x%x\n"), 
        space, user_arg));
    res = globus_callback_space_register_oneshot(
                ch,
                NULL,
                cb,
                user_arg,
                space);
    if(res != GLOBUS_SUCCESS)
    {
        globus_panic(GLOBUS_XIO_MODULE, res, _XIOSL("failed to register oneshot"));
    }
    GlobusXIODebugInternalExit();
}

static int
globus_l_xio_activate()
{
    int                                 rc;
    GlobusXIOName(globus_l_xio_activate);

    GlobusXIODebugInternalEnter();

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != 0)
    {
        return rc;
    }

    globus_mutex_init(&globus_i_xio_mutex, NULL);
    globus_cond_init(&globus_i_xio_cond, NULL);
    globus_i_xio_timer_init(&globus_i_xio_timeout_timer);
    globus_i_xio_outstanding_handles_list = NULL;
    globus_i_xio_outstanding_servers_list = NULL;
    globus_i_xio_outstanding_attrs_list = NULL;
    globus_i_xio_outstanding_dds_list = NULL;
    globus_l_xio_active = GLOBUS_TRUE;
    
    globus_i_xio_load_init();

    GlobusDebugInit(GLOBUS_XIO,
        ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);
    
    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;
}



static int
globus_l_xio_deactivate()
{
    int                                 rc;
    GlobusXIOName(globus_l_xio_deactivate);

    GlobusXIODebugInternalEnter();

    globus_mutex_destroy(&globus_i_xio_mutex);
    globus_cond_destroy(&globus_i_xio_cond);
    globus_i_xio_timer_destroy(&globus_i_xio_timeout_timer);
    globus_i_xio_load_destroy();
    globus_l_xio_active = GLOBUS_FALSE;

    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GlobusXIODebugInternalExit();

/*    GlobusDebugDestroy(GLOBUS_XIO);
*/    
    return rc;
}

globus_module_descriptor_t              globus_i_xio_module =
{
    "globus_xio",
    globus_l_xio_activate,
    globus_l_xio_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

void
globus_l_xio_read_write_callback_kickout(
    void *                              user_arg);

/********************************************************************
 *                      Internal functions 
 *******************************************************************/

/*
 *  This is called when either an open or a close completes.
 */
static void
globus_l_xio_open_close_callback(
    globus_i_xio_op_t *                 op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_xio_handle_t *             handle;
    globus_bool_t                       fire_callback = GLOBUS_TRUE;
    GlobusXIOName(globus_l_xio_open_close_callback);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
                    (_XIOSL("[%s] : op@ 0x%x op->type=%d handle->state=%d\n"), 
                    _xio_name, op, op->type, handle->state));
        /* state can be either opening or closing.*/
        switch(handle->state)
        {
            case GLOBUS_XIO_HANDLE_STATE_CLOSING:
                globus_assert(op->type == GLOBUS_XIO_OPERATION_TYPE_CLOSE);
                handle->close_op = NULL;
                break;

            case GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING:
                globus_assert(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN);
                break;

            case GLOBUS_XIO_HANDLE_STATE_OPENING:
                globus_assert(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN);
                if(result != GLOBUS_SUCCESS)
                {
                    GlobusXIOHandleStateChange(handle,
                        GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED);
                }
                else
                {
                    GlobusXIOHandleStateChange(handle,
                        GLOBUS_XIO_HANDLE_STATE_OPEN);
                }
                break;

            case GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED:
            case GLOBUS_XIO_HANDLE_STATE_OPEN:
            case GLOBUS_XIO_HANDLE_STATE_CLOSED:
            default:
                globus_assert(0);
        }

        /* set to finished for the sake of the timeout */
        if(op->state == GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING)
        {
            fire_callback = GLOBUS_FALSE;
        }
        else
        {
            fire_callback = GLOBUS_TRUE;
            if(op->_op_handle_timeout_cb != NULL)
            {
                /* 
                 * unregister the cancel
                 */
                /* if the unregister fails we will get the callback */
                if(globus_i_xio_timer_unregister_timeout(
                    &globus_i_xio_timeout_timer, op))
                {
                    /* at this point we know timeout won't happen */
                    GlobusXIOOpDec(op);
                    /* since we have no yet deced for the callbacl this
                       cannot be zero */
                    globus_assert(op->ref > 0);
                }
            }
        }

        /* remove the operation from the list */
        GlobusXIOOpStateChange(op, GLOBUS_XIO_OP_STATE_FINISH_WAITING);
        op->cached_obj = GlobusXIOResultToObj(result);
        /* 
         *  when at the top don't worry about the cancel
         *  just act as though we missed it
         */
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(fire_callback)
    {
        /* we can always call in this stack since Pass macros enforce
           registration bariers and callback spaces */
        globus_l_xio_open_close_callback_kickout((void *)op);
    }

    GlobusXIODebugInternalExit();
}

/*
 *   called by the callback code.
 *   registerd by finished op when the final (user) callback
 *   is in a callback space, or if it is under the registraton
 *   call within the same callstack
 */
void
globus_l_xio_open_close_callback_kickout(
    void *                              user_arg)
{
    int                                 ctr;
    globus_result_t                     res;
    globus_i_xio_op_t *                 op;
    globus_i_xio_op_t *                 close_op = NULL;
    globus_i_xio_handle_t *             handle;
    globus_bool_t                       start_close = GLOBUS_FALSE;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_open_close_callback_kickout);

    GlobusXIODebugInternalEnter();

    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    /* call the users callback */
    if(op->_op_cb != NULL)
    {
        op->_op_cb(handle, GlobusXIOObjToResult(op->cached_obj), op->user_arg);
    }
    else if(op->cached_obj != NULL)
    {
        globus_object_free(op->cached_obj);
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        globus_assert(op->state == GLOBUS_XIO_OP_STATE_FINISH_WAITING);
        /* this is likely useless, but may help in debugging */
        GlobusXIOOpStateChange(op, GLOBUS_XIO_OP_STATE_FINISHED);

        /* clean up the links */
        if(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN)
        {
            for(ctr = 0; ctr < op->stack_size; ctr++)
            {
                if(op->entry[ctr].link != NULL &&
                    handle->context->entry[ctr].driver->link_destroy_func !=
                        NULL)
                {
                    /* ignore result code.  user should be more interested in
                        result from callback */
                    handle->context->entry[ctr].driver->link_destroy_func(
                            op->entry[ctr].link);
                }
            }
        }
        
        /* necessary for all states except GLOBUS_XIO_HANDLE_STATE_CLOSED */
        handle->open_op = NULL;
        switch(handle->state)
        {
            case GLOBUS_XIO_HANDLE_STATE_OPEN:
                globus_assert(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN);
                break;
                
            case GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED:
                globus_assert(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN);
                GlobusXIOHandleStateChange(handle,
                    GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED);
                break;

            case GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING:
                globus_assert(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN &&
                    handle->close_op != NULL);

                GlobusXIOHandleStateChange(handle,
                    GLOBUS_XIO_HANDLE_STATE_CLOSING);

                /* start the close */
                start_close = GLOBUS_TRUE;
                close_op = handle->close_op;
                break;

            case GLOBUS_XIO_HANDLE_STATE_CLOSING:
                /* could be an open op if the user calls close in the 
                    callback */
                if(op->type == GLOBUS_XIO_OPERATION_TYPE_CLOSE)
                {
                    GlobusXIOHandleStateChange(handle,
                        GLOBUS_XIO_HANDLE_STATE_CLOSED);
                    /* remove handles own reference */
                    globus_i_xio_handle_dec(handle, &destroy_handle);
                    /* destroy handle cannot possibly be true yet
                        the handle stll has the operation reference */
                    globus_assert(!destroy_handle);
                }
                break;

            /* can enter the closed state if use calls xio_close() in 
                open callback and the close callback finishes before the
                open one returns */
            case GLOBUS_XIO_HANDLE_STATE_CLOSED:
                break;

            case GLOBUS_XIO_HANDLE_STATE_OPENING:
            default:
                globus_assert(0);
        }

        /* decrement reference for the operation */
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* only gets here if coming from the operning and closing state */
    if(start_close)
    {
        res = globus_l_xio_register_close(close_op);
        if(res != GLOBUS_SUCCESS)
        {
            globus_l_xio_open_close_callback(close_op, res, NULL);
        }
        globus_assert(!destroy_handle);
    }

    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
}

/*
 *  operation callback for readv and writev operations
 *  we don't care what the result is, just so it bubbles up to the user
 */
void
globus_i_xio_read_write_callback(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_i_xio_handle_t *             handle;
    globus_bool_t                       fire_operation = GLOBUS_TRUE;
    GlobusXIOName(globus_i_xio_read_write_callback);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        globus_assert(handle->state == GLOBUS_XIO_HANDLE_STATE_OPEN ||
            handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSING);

        /* set to finished for the sake of the timeout */
        if(op->state == GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING)
        {
            fire_operation = GLOBUS_FALSE;
        }
        else
        {
            fire_operation = GLOBUS_TRUE;
            if(op->_op_handle_timeout_cb != NULL)
            {
                /* 
                 * unregister the cancel
                 */
                /* if the unregister fails we will get the callback */
                if(globus_i_xio_timer_unregister_timeout(
                    &globus_i_xio_timeout_timer, op))
                {
                    /* at this point we know timeout won't happen */
                    GlobusXIOOpDec(op);
                }
            }
        }
        GlobusXIOOpStateChange(op, GLOBUS_XIO_OP_STATE_FINISH_WAITING);

        if(op->type == GLOBUS_XIO_OPERATION_TYPE_WRITE)
        {
            GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
                (_XIOSL("[%s] : removing write op @ 0x%x\n"), 
                _xio_name, op));
            globus_list_remove(&handle->write_op_list, 
                globus_list_search(handle->write_op_list, op));
        }
        else if(op->type == GLOBUS_XIO_OPERATION_TYPE_READ)
        {
            GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
                (_XIOSL("[%s] : removing read op @ 0x%x\n"), 
                _xio_name, op));
            globus_list_remove(&handle->read_op_list, 
                globus_list_search(handle->read_op_list, op));
        }
        else
        {
            globus_assert(0);
        }

        op->cached_obj = GlobusXIOResultToObj(result);
        op->_op_nbytes = nbytes;
    }   
    globus_mutex_unlock(&handle->context->mutex);

    if(fire_operation)
    {
        globus_l_xio_read_write_callback_kickout((void *)op);
    }

    GlobusXIODebugInternalExit();
}

/*
 *  called unlocked either by the callback code or in the finsihed op
 *  state.
 */
void
globus_l_xio_read_write_callback_kickout(
    void *                              user_arg)
{
    globus_i_xio_op_t *                 op;
    globus_i_xio_handle_t *             handle;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_read_write_callback_kickout);

    GlobusXIODebugInternalEnter();

    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    if(op->is_user_dd)
    {
        op->type = GLOBUS_XIO_OPERATION_TYPE_DD;
    }

    /* call the users callback */
    if(op->_op_data_cb != NULL)
    {
        op->_op_data_cb(
            handle, 
            GlobusXIOObjToResult(op->cached_obj), 
            op->_op_mem_iovec.iov_base,
            op->_op_mem_iovec.iov_len,
            op->_op_nbytes,
            op,
            op->user_arg);
    }
    else if(op->_op_iovec_cb != NULL)
    {
        op->_op_iovec_cb(
            handle, 
            GlobusXIOObjToResult(op->cached_obj), 
            op->_op_iovec,
            op->_op_iovec_count,
            op->_op_nbytes,
            op,
            op->user_arg);
    }
    else if(op->cached_obj != NULL)
    {
        globus_object_free(op->cached_obj);
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        /*
         *  This is ok in CLOSED state because of will block stuff
         */
        globus_assert(handle->state != GLOBUS_XIO_HANDLE_STATE_OPENING);
        /* decrement reference for the operation */
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
}

/*
 *  this starts the cancel processes for the given operation.
 * 
 *  the cancel flag is to true.  every pass checks this flag and
 *  if cancel is true the pass fails and the above driver should
 *  do what it needs to do to cancel the operation.  If a driver
 *  is able to cancel it will call GlobusXIODriverCancelEanble()
 *  if at the time this function is called the operations cancel
 *  flag is set to true we register a oneshot for the cancel.
 * 
 *  If a cencel occurs while a driver is registered to receive 
 *  cancel notification then the callback is delivered to it.
 *
 *  The framework has little else to do with cancel.  The operation
 *  will come back up via the normal routes with an error.
 */
globus_result_t
globus_i_xio_operation_cancel(
    globus_i_xio_op_t *                 op,
    int                                 source_ndx)
{
    GlobusXIOName(globus_i_xio_operation_cancel);

    GlobusXIODebugInternalEnter();

    /* internal function should never be passed NULL */
    globus_assert(op != NULL);

    if(op->canceled)
    {
        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
            (_XIOSL("[%s] : op @ 0x%x alread canceled\n"), 
                    _xio_name, op));
        goto exit;
    }

    /* the timeout should only be unregistered if this call is coming
        from the user */
    if(source_ndx == -1)
    {
        /* 
         * if the user oks the cancel then remove the timeout from 
         * the poller
         */
        if(globus_i_xio_timer_unregister_timeout(
                &globus_i_xio_timeout_timer, op))
        {
            GlobusXIOOpDec(op);
        }
    }
    /* since in callback this will always be true */

    /*
     * set cancel flag
     * if a driver has a registered callback it will be called
     * if it doesn't the next pass or finished will pick it up
     * 
     * we offset by 2 because source_ndx for user == -1 and top driver == 0
     * and we want op->canceled to be non-zero when a cancel is pending.
     */
    op->canceled = source_ndx + 2;
    
    /* only cancel it if its not in source's possession
     * 
     * (op->ndx == source_ndx + 1)
     */
    if(op->ndx > source_ndx + 1)
    {
        if(op->cancel_cb != NULL)
        {
            globus_i_xio_op_entry_t * my_op;
            my_op = &op->entry[op->ndx - 1];
            GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
                (_XIOSL("[%s] : op @ 0x%x calling cancel\n"),
                        _xio_name, op));
            my_op->in_register = GLOBUS_TRUE;
            op->cancel_cb(op, op->cancel_arg, GLOBUS_XIO_ERROR_CANCELED);
            my_op->in_register = GLOBUS_FALSE;
        }
    }
    else
    {
        /* we set canceled above first to make up for the fact that the 
         * op->ndx we are reading is not stable. what may happen is that above
         * ndx may change to source_ndx + 1 immediately after we read it. this
         * would cause us to errorneously 'cancel' this op.  This is ok, since
         * we are guaranteed to hit the locked section in GlobusIXIOClearCancel
         * which will set canceled back to 0 for us
         */
        op->canceled = 0;
    }

  exit:

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;
}

static globus_bool_t
globus_l_xio_timeout_callback(
    void *                              user_arg)
{
    globus_i_xio_op_t *                 op;
    globus_i_xio_handle_t *             handle;
    /* rc is definitly set elsewhere but this gets rid of compiler warning
        and lets me know that i knew what i was doing */
    globus_bool_t                       rc = GLOBUS_FALSE;
    globus_bool_t                       fire_callback;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    globus_bool_t                       cancel;
    globus_bool_t                       timeout = GLOBUS_FALSE;
    /* delayed_cb is in same situation as rc */
    globus_callback_func_t              delayed_cb = NULL;
    globus_callback_space_t             space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;                   
    GlobusXIOName(globus_l_xio_timeout_callback);

    GlobusXIODebugInternalEnter();
    
    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        switch(op->state)
        {
            /* 
             * this case happens when a open operation first pass fails and 
             * are unable to unregister the timeout and when the operation
             * completes but we are unable to unregister the callback.
             */
            case GLOBUS_XIO_OP_STATE_FINISHED:
            case GLOBUS_XIO_OP_STATE_FINISH_WAITING:

                /* decerement the reference for the timeout callback */
                GlobusXIOOpDec(op);
                if(op->ref == 0)
                {
                    globus_i_xio_op_destroy(op, &destroy_handle);
                }

                /* remove it from the timeout list */
                rc = GLOBUS_TRUE;
                break;

            /* this case happens when we actually want to cancel the operation
                The timeout code should insure that prograess is false if this
                gets called in this state */
            case GLOBUS_XIO_OP_STATE_OPERATING:
                /* it is up to the timeout callback to set this to true */
                rc = GLOBUS_FALSE;
                /* cancel the sucker */
                globus_assert(op->_op_handle_timeout_cb != NULL);

                /* if the driver has blocked the timeout don't call it */
                if(!op->block_timeout)
                {
                    timeout = GLOBUS_TRUE;
                    /* put in canceling state to delay the accept callback */
                    GlobusXIOOpStateChange(op, 
                        GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING);
                }
                break;

            /* fail on any ohter case */
            default:
                globus_assert(0);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* if in cancel state, verfiy with user that they want to cancel */
    if(timeout)
    {
        cancel = op->_op_handle_timeout_cb(
            handle, op->type, handle->timeout_arg);
    }
    /* all non time out casses can just return */
    else
    {
        /* wait until outside of lock to free the handle */
        if(destroy_handle)
        {
            globus_i_xio_handle_destroy(handle);
        }
        goto exit;
    }
    
    /* if canceling set the res and we will remove this timer event */
    if(cancel)
    {
        rc = GLOBUS_TRUE;
        
        globus_mutex_lock(&handle->context->cancel_mutex);
        {
            /* Assume all timeouts originate from user */
            op->canceled = 1;
            if(op->cancel_cb)
            {
        	    globus_i_xio_op_entry_t * my_op;
                my_op = &op->entry[op->ndx - 1];
                my_op->in_register = GLOBUS_TRUE;
                op->cancel_cb(op, op->cancel_arg, GLOBUS_XIO_ERROR_TIMEOUT);
                my_op->in_register = GLOBUS_FALSE;
            }
        }
        globus_mutex_unlock(&handle->context->cancel_mutex);
    }
        
    globus_mutex_lock(&handle->context->mutex);
    {
        /* if callback has already arriverd set flag to later
            call accept callback and set rc to remove timed event */
        if(op->state == GLOBUS_XIO_OP_STATE_FINISH_WAITING)
        {
            fire_callback = GLOBUS_TRUE;
            rc = GLOBUS_TRUE;
        }
        /* if no accept is waiting, set state back to operating */
        else
        {
            fire_callback = GLOBUS_FALSE;
            GlobusXIOOpStateChange(op, GLOBUS_XIO_OP_STATE_OPERATING);
        }

        /* if we are remvoing the timed event */
        if(rc)
        {
            /* decremenet the op reference count and insist that it is
               not zero yet */
            op->_op_handle_timeout_cb = NULL;
            GlobusXIOOpDec(op);
            globus_assert(op->ref > 0);
        }

        /* if the accpet was pending we must call it */
        if(fire_callback)
        {
            switch(op->type)
            {
                case GLOBUS_XIO_OPERATION_TYPE_OPEN:
                case GLOBUS_XIO_OPERATION_TYPE_CLOSE:
                    delayed_cb = globus_l_xio_open_close_callback_kickout;
                    break;

                case GLOBUS_XIO_OPERATION_TYPE_READ:
                case GLOBUS_XIO_OPERATION_TYPE_WRITE:
                    delayed_cb = globus_l_xio_read_write_callback_kickout;
                    break;

                default:
                    globus_assert(0);
                    break;

            }
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(fire_callback)
    {
        if(!op->blocking)
        {
            space = handle->space;
        }
        if(space != GLOBUS_CALLBACK_GLOBAL_SPACE)
        {
            /* register a oneshot callback */
            globus_i_xio_register_oneshot(
                handle,
                delayed_cb,
                (void *)op,
                space);
        }
        /* in all other cases we can just call callback */
        else
        {
            delayed_cb((void *)op);
        }
    }

  exit:
    GlobusXIODebugInternalExit();
    return rc;
}

/*
 *
 */
globus_result_t
globus_l_xio_register_writev(
    globus_i_xio_op_t *                 op,
    int                                 ref)
{
    globus_result_t                     res;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    globus_i_xio_handle_t *             handle;
    GlobusXIOName(globus_l_xio_register_writev);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        handle->ref += ref;
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            res = GlobusXIOErrorInvalidState(handle->state);
            goto bad_state_err;
        }

        /* register timeout */
        if(op->_op_handle->write_timeout_cb != NULL)
        {
            /* op the operatin reference count for this */
            GlobusXIOOpInc(op);
            op->_op_handle_timeout_cb = handle->write_timeout_cb;
            globus_i_xio_timer_register_timeout(
                &globus_i_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &handle->write_timeout_period);
        }

        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
            (_XIOSL("[%s] : inserting write op @ 0x%x\n"), 
            _xio_name, op));
        globus_list_insert(&handle->write_op_list, op);
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    GlobusXIOOpInc(op);
    res = globus_xio_driver_pass_write(op, op->_op_iovec, op->_op_iovec_count,
        op->_op_wait_for, globus_i_xio_read_write_callback, (void *)NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto pass_err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }

    }
    globus_mutex_unlock(&handle->context->mutex);
    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  pass_err:

    globus_mutex_lock(&handle->context->mutex);
    {
        globus_list_remove(&handle->write_op_list,
            globus_list_search(handle->write_op_list, op));
        GlobusXIOOpDec(op);  /* dec for the register */
        globus_assert(op->ref > 0);
        /* in case timeout unregister fails */
        op->type = GLOBUS_XIO_OPERATION_TYPE_FINISHED;
        /* if we had a timeout, we need to unregister it */
        if(handle->write_timeout_cb != NULL)
        {
            /* if unregister works remove its reference count */
            if(globus_i_xio_timer_unregister_timeout(
                &globus_i_xio_timeout_timer, op))
            {
                GlobusXIOOpDec(op);
                globus_assert(op->ref > 0);
            }
        }
  bad_state_err:
        /* clean up the operation */
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExitWithError();
    return res;
}

/*
 *
 */
globus_result_t
globus_l_xio_register_readv(
    globus_i_xio_op_t *                 op,
    int                                 ref)
{
    globus_result_t                     res;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    globus_i_xio_handle_t *             handle;
    GlobusXIOName(globus_l_xio_register_readv);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        handle->ref += ref;
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            res = GlobusXIOErrorInvalidState(handle->state);
            goto bad_state_err;
        }
        /* this is a bit ugly 
           handle doesn't maitain this state and Pass asserts for efficieny.
           so wee need to check it here to be nice to the user */
        if(handle->context->entry[0].state != GLOBUS_XIO_CONTEXT_STATE_OPEN &&
            handle->context->entry[0].state != 
                GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED &&
            handle->context->entry[0].state !=
                GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED)
        {
            res = GlobusXIOErrorInvalidState(handle->context->entry[0].state);
            goto bad_state_err;
        }

        /* register timeout */
        if(handle->read_timeout_cb != NULL)
        {
            /* op the operatin reference count for this */
            GlobusXIOOpInc(op);
            op->_op_handle_timeout_cb = handle->read_timeout_cb;
            globus_i_xio_timer_register_timeout(
                &globus_i_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &handle->read_timeout_period);
        }

        GlobusXIODebugPrintf(GLOBUS_XIO_DEBUG_INFO_VERBOSE,
            (_XIOSL("[%s] : inserting read op @ 0x%x\n"), 
            _xio_name, op));
        globus_list_insert(&handle->read_op_list, op);
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    GlobusXIOOpInc(op);
    res = globus_xio_driver_pass_read(op, op->_op_iovec, op->_op_iovec_count,
        op->_op_wait_for, globus_i_xio_read_write_callback, (void *)NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        GlobusXIOOpDec(op); /* remove the pass reference */
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  register_err:

    globus_mutex_lock(&handle->context->mutex);
    {
        globus_list_remove(&handle->read_op_list,
            globus_list_search(handle->read_op_list, op));
        GlobusXIOOpDec(op);  /* unregister the pass */
        globus_assert(op->ref > 0);
        /* in case timeout unregister fails */
        op->type = GLOBUS_XIO_OPERATION_TYPE_FINISHED;
        /* if we had a timeout, we need to unregister it */
        if(handle->read_timeout_cb != NULL)
        {
            /* if unregister works remove its reference count */
            if(globus_i_xio_timer_unregister_timeout(
                &globus_i_xio_timeout_timer, op))
            {
                GlobusXIOOpDec(op);
                globus_assert(op->ref > 0);
            }
        }
  bad_state_err:
        /* clean up the operation */
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExitWithError();
    return res;
}

globus_result_t
globus_l_xio_register_open(
    globus_i_xio_op_t *                 op,
    const char *                        contact_string)
{
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    globus_i_xio_handle_t *             handle;
    globus_xio_contact_t                contact_info;
    globus_result_t                     res;
    int                                 ctr;
    GlobusXIOName(globus_l_xio_register_open);

    GlobusXIODebugInternalEnter();
    
    res = globus_xio_contact_parse(&contact_info, contact_string);
    if(res != GLOBUS_SUCCESS)
    {
        goto err_contact;
    }

    handle = op->_op_handle;
    
    /* accepted handles have the link structures stored in the driver_handle
     * slot. move them into the op now.
     */
    if(handle->state == GLOBUS_XIO_HANDLE_STATE_ACCEPTED)
    {
        /* stick the link in the new handle's context */
        for(ctr = 0;  ctr < op->stack_size; ctr++)
        {
            op->entry[ctr].link =
                handle->context->entry[ctr].driver_handle;
            handle->context->entry[ctr].driver_handle = NULL;
        }
    }
    
    handle->state = GLOBUS_XIO_HANDLE_STATE_OPENING;

    /* register timeout */
    if(handle->open_timeout_cb != NULL)
    {
        /* op the operatin reference count for this */
        GlobusXIOOpInc(op);
        op->_op_handle_timeout_cb = handle->open_timeout_cb;
        globus_i_xio_timer_register_timeout(
            &globus_i_xio_timeout_timer,
            op,
            &op->progress,
            globus_l_xio_timeout_callback,
            &handle->open_timeout_period);
    }
    
    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    GlobusXIOOpInc(op);
    res = globus_xio_driver_pass_open(
        op, &contact_info, globus_l_xio_open_close_callback, NULL);
    globus_xio_contact_destroy(&contact_info);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);
    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }
    
    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:

    globus_mutex_lock(&handle->context->mutex);
    {
        handle->state = GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED;
        
        GlobusXIOOpDec(op); /* dec for the register */
        globus_assert(op->ref > 0);

        if(globus_i_xio_timer_unregister_timeout(
            &globus_i_xio_timeout_timer, op))
        {
            GlobusXIOOpDec(op);
            globus_assert(op->ref > 0);
        }

        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);
    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

  err_contact:
    GlobusXIODebugInternalExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_register_close(
    globus_i_xio_op_t *                 op)
{
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    globus_i_xio_handle_t *             handle;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_register_close);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;
    globus_mutex_lock(&handle->context->mutex);
    {
        /* register timeout */
        if(handle->close_timeout_cb != NULL)
        {
            /* op the operatin reference count for this */
            GlobusXIOOpInc(op);
            op->_op_handle_timeout_cb = handle->close_timeout_cb;
            globus_i_xio_timer_register_timeout(
                &globus_i_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &handle->close_timeout_period);
        }
        handle->ref++; /* for the opperation */
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    GlobusXIOOpInc(op);
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_open_close_callback, NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);
    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  err:

    globus_mutex_lock(&handle->context->mutex);
    {
        /* the handle is closed since we will return a failure */
        handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;

        GlobusXIOOpDec(op); /* dec for the register */
        globus_assert(op->ref > 0);

        if(globus_i_xio_timer_unregister_timeout(
            &globus_i_xio_timeout_timer, op))
        {
            GlobusXIOOpDec(op);
        }
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
        globus_i_xio_handle_dec(handle, &destroy_handle);
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }
    GlobusXIODebugInternalExitWithError();

    return res;
}

/*
 *  cancel the operations
 */
static globus_result_t
globus_l_xio_handle_cancel_operations(
    globus_i_xio_handle_t *             xio_handle,
    int                                 mask)
{
    globus_list_t *                     list;
    globus_i_xio_op_t *                 tmp_op;
    GlobusXIOName(globus_l_xio_handle_cancel_operations);

    GlobusXIODebugInternalEnter();

    globus_mutex_lock(&xio_handle->context->cancel_mutex);
    {
        if(mask & GLOBUS_XIO_CANCEL_OPEN && xio_handle->open_op != NULL)
        {
            globus_i_xio_operation_cancel(xio_handle->open_op, -1);
        }
        if(mask & GLOBUS_XIO_CANCEL_CLOSE && xio_handle->close_op != NULL)
        {
            globus_i_xio_operation_cancel(xio_handle->close_op, -1);
        }
        if(mask & GLOBUS_XIO_CANCEL_READ)
        {
            /* remove all outstanding read ops */
            for(list = xio_handle->read_op_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                tmp_op = (globus_i_xio_op_t *) globus_list_first(list);
                globus_i_xio_operation_cancel(tmp_op, -1);
            }
        }
        if(mask & GLOBUS_XIO_CANCEL_WRITE)
        {
            for(list = xio_handle->write_op_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                tmp_op = (globus_i_xio_op_t *) globus_list_first(list);
                globus_i_xio_operation_cancel(tmp_op, -1);
            }
        }
    }
    globus_mutex_unlock(&xio_handle->context->cancel_mutex);

    GlobusXIODebugInternalExit();

    return GLOBUS_SUCCESS;
}
/********************************************************************
 *                        API functions 
 *                        -------------
 *******************************************************************/

globus_result_t
globus_xio_handle_create(
    globus_xio_handle_t *               handle,
    globus_xio_stack_t                  stack)
{
    globus_i_xio_handle_t *             ihandle;
    globus_i_xio_context_t *            context;
    int                                 stack_size;
    int                                 ndx;
    globus_list_t *                     list;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_handle_create);
    
    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();
    
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto error_param;
    }
    *handle = NULL; /* initialze to be nice to user */
    if(stack == NULL)
    {
        res = GlobusXIOErrorParameter("stack");
        goto error_param;
    }
    stack_size = globus_list_size(stack->driver_stack);
    if(stack_size == 0)
    {
        res = GlobusXIOErrorParameter("stack_size");
        goto error_param;
    }
    
    /* allocate and initialize context */
    context = globus_i_xio_context_create(stack_size);
    if(context == NULL)
    {
        res = GlobusXIOErrorMemory("context");
        goto error_context;
    }
    
    /* allocate and intialize the handle structure */
    ihandle = (globus_i_xio_handle_t *)
        globus_calloc(1, sizeof(globus_i_xio_handle_t));
    if(handle == NULL)
    {
        res = GlobusXIOErrorMemory("ihandle");
        goto error_handle;
    }
    /* initialize the handle */
    ihandle->ref = 1; /* itself */
    ihandle->context = context;
    ihandle->state = GLOBUS_XIO_HANDLE_STATE_CLIENT;
    ihandle->space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    for(ndx = 0, list = stack->driver_stack;
        !globus_list_empty(list);
        ndx++, list = globus_list_rest(list))
    {
        context->entry[ndx].driver = (globus_xio_driver_t) 
            globus_list_first(list);
    }
    globus_assert(ndx == stack_size);
    
    globus_mutex_lock(&globus_i_xio_mutex);
    {
        globus_list_insert(&globus_i_xio_outstanding_handles_list, ihandle);
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
    *handle = ihandle;
    
    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

error_handle:
    globus_i_xio_context_destroy(context);
    
error_context:
error_param:
    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  User Open
 *  ---------
 *  Check the parameters and state then pass to internal open function.
 */
globus_result_t
globus_xio_register_open(
    globus_xio_handle_t                 handle,
    const char *                        contact_string,
    globus_xio_attr_t                   attr,
    globus_xio_callback_t               cb,
    void *                              user_arg)
{
    void *                              driver_attr;
    globus_i_xio_op_t *                 op = NULL;
    globus_i_xio_context_t *            context;
    globus_result_t                     res;
    int                                 ctr;
    globus_callback_space_t             space = 
            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(globus_xio_register_open);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto err;
    }
    if(handle->state != GLOBUS_XIO_HANDLE_STATE_CLIENT &&
        handle->state != GLOBUS_XIO_HANDLE_STATE_ACCEPTED)
    {
        res = GlobusXIOErrorInvalidState(handle->state);
        goto err;
    }
    
    context = handle->context;
    GlobusXIOOperationCreate(op, context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto err;
    }

    GlobusXIOHandleSetup(handle, attr);

    /* all memory has been allocated, now set up the different structures */

    /*
     *  set up the operation
     */
    op->type = GLOBUS_XIO_OPERATION_TYPE_OPEN;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->ndx = 0;
    op->_op_cb = cb;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1; /* for first pass there is no return */

    handle->ref++; /* for operation */
    handle->open_op = op;

    if(attr != NULL)
    {
        space =  attr->space;
        
        /* set entries in structures */
        for(ctr = 0; ctr < context->stack_size; ctr++)
        {
            op->entry[ctr].open_attr = NULL;
            GlobusIXIOAttrGetDS(
                driver_attr, attr, context->entry[ctr].driver);

            if(driver_attr != NULL)
            {
                context->entry[ctr].driver->attr_copy_func(
                    &op->entry[ctr].open_attr, driver_attr);
            }
        }
    }
    
    handle->space = space;
    globus_callback_space_reference(space);

    res = globus_l_xio_register_open(op, contact_string);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:

    GlobusXIODebugExitWithError();

    return res;
}

/*
 *  User Read
 *  ---------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  fake the iovec structure with the dummy iovec in the operation struct
 *  Then pass to the internal readv function
 */
globus_result_t
globus_xio_register_read(
    globus_xio_handle_t                 handle,
    globus_byte_t *                     buffer,
    globus_size_t                       buffer_length,
    globus_size_t                       waitforbytes,
    globus_xio_data_descriptor_t        data_desc,
    globus_xio_data_callback_t          cb,
    void *                              user_arg)
{
    globus_i_xio_op_t *                 op;
    globus_result_t                     res;
    int                                 ref = 0;
    GlobusXIOName(globus_xio_register_read);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();
    
    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(buffer == NULL)
    {
        return GlobusXIOErrorParameter("buffer");
    }
    if(buffer_length < 0)
    {
        return GlobusXIOErrorParameter("buffer_length");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
        op->ref = 0;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    GlobusXIOOpInc(op);
    op->_op_context = handle->context;
    op->_op_data_cb = cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1;

    res = globus_l_xio_register_readv(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  exit:

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  User Readv
 *  ----------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  Then pass to the internal readv function
 */
globus_result_t
globus_xio_register_readv(
    globus_xio_handle_t                 handle,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       waitforbytes,
    globus_xio_data_descriptor_t        data_desc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                 op;
    int                                 ref = 0;
    GlobusXIOName(globus_xio_register_readv);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(iovec == NULL)
    {
        return GlobusXIOErrorParameter("iovec");
    }
    if(iovec_count <= 0)
    {
        return GlobusXIOErrorParameter("iovec_count");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
        op->ref = 0;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->_op_context = handle->context;
    GlobusXIOOpInc(op);
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1;

    res = globus_l_xio_register_readv(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    GlobusXIODebugExit();
  
    return GLOBUS_SUCCESS;
  exit:

    GlobusXIODebugExitWithError();
    return res;
}   

/*
 *  User Write
 *  ----------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  fake the iocev structure with the dummy iovec in the operation struct
 *  Then pass to the internal writev function
 */
globus_result_t
globus_xio_register_write(
    globus_xio_handle_t                 user_handle,
    globus_byte_t *                     buffer,
    globus_size_t                       buffer_length,
    globus_size_t                       waitforbytes,
    globus_xio_data_descriptor_t        data_desc,
    globus_xio_data_callback_t          cb,
    void *                              user_arg)
{
    globus_i_xio_op_t *                 op;
    globus_result_t                     res;
    globus_i_xio_handle_t *             handle;
    int                                 ref = 0;
    GlobusXIOName(globus_xio_register_write);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(buffer == NULL)
    {
        return GlobusXIOErrorParameter("buffer");
    }
    if(buffer_length < 0)
    {
        return GlobusXIOErrorParameter("buffer_length");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
        op->ref = 0;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    GlobusXIOOpInc(op);
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;

    res = globus_l_xio_register_writev(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  exit:
    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  User Writev
 *  -----------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  Then pass to the internal writev function
 */
globus_result_t
globus_xio_register_writev(
    globus_xio_handle_t                 user_handle,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       waitforbytes,
    globus_xio_data_descriptor_t        data_desc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                 op;
    globus_i_xio_handle_t *             handle;
    int                                 ref = 0;
    GlobusXIOName(globus_xio_register_writev);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    handle = (globus_i_xio_handle_t *) user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(iovec == NULL)
    {
        return GlobusXIOErrorParameter("iovec");
    }
    if(iovec_count <= 0)
    {
        return GlobusXIOErrorParameter("iovec_count");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
        op->ref = 0;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->entry[0].prev_ndx = -1;

    GlobusXIOOpInc(op);
    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;

    res = globus_l_xio_register_writev(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;
  exit:

    GlobusXIODebugExitWithError();
    return res;
}


/*
 *  User Close
 *  ----------
 *  Check the parameters and state then pass to internal function.
 */
globus_result_t
globus_xio_register_close(
    globus_xio_handle_t                 handle,
    globus_xio_attr_t                   attr,
    globus_xio_callback_t               cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    /* initialize to remove warn, but not needed */
    globus_i_xio_op_t *                 op = NULL;
    globus_bool_t                       pass = GLOBUS_TRUE;
    GlobusXIOName(globus_xio_register_close);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        if(handle->sd_monitor != NULL)
        {
            res = GlobusXIOErrorUnloaded();
        }
        else
        {
            res = globus_l_xio_handle_pre_close(
                handle, attr, cb, user_arg, GLOBUS_FALSE);
            op = handle->close_op;
            if(handle->state == GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING)
            {
                pass = GLOBUS_FALSE;
            }
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    if(pass)
    {
        res = globus_l_xio_register_close(op);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;
  err:

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  cancel outstanding operations.
 * 
 *  In the furture the attr will control what operations get canceled.
 *  For now all are canceled.
 */
globus_result_t
globus_xio_handle_cancel_operations(
    globus_xio_handle_t                 handle,
    int                                 mask)
{
    globus_i_xio_handle_t *             xio_handle;
    globus_result_t                     res;
    GlobusXIOName(globus_xio_handle_cancel_operations);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    xio_handle = handle;

    globus_mutex_lock(&xio_handle->context->mutex);
    {
        /* if closed there is nothing to cancel */
        if(xio_handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSED)
        {
            res = GlobusXIOErrorInvalidState(xio_handle->state);
        }
        else
        {
            res = globus_l_xio_handle_cancel_operations(
                    xio_handle,
                    mask);
        }
    }
    globus_mutex_unlock(&xio_handle->context->mutex);

    GlobusXIODebugExit();

    return res;
}


globus_result_t
globus_xio_handle_cntl(
    globus_xio_handle_t                 handle,
    globus_xio_driver_t                 driver,
    int                                 cmd,
    ...)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    va_list                             ap;
    globus_i_xio_context_t *            context;
    globus_xio_timeout_callback_t       timeout_cb;
    globus_reltime_t *                  delay_time;
    GlobusXIOName(globus_xio_handle_cntl);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    context = handle->context;
    if(context == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, cmd);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    if(driver != NULL)
    {
        res = globus_i_xio_driver_handle_cntl(context, 0, driver, cmd, ap);
    }
    else
    {
        globus_mutex_lock(&context->mutex);
        {
            /* do general settings */
            switch(cmd)
            {
                case GLOBUS_XIO_ATTR_SET_TIMEOUT_ALL:
                    timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                    delay_time = va_arg(ap, globus_reltime_t *);
                    handle->timeout_arg = va_arg(ap, void *);
                    if(timeout_cb == NULL)
                    {
                        timeout_cb = globus_l_xio_handle_timeout_always;
                    }

                    handle->open_timeout_cb = timeout_cb;
                    handle->close_timeout_cb = timeout_cb;
                    handle->read_timeout_cb = timeout_cb;
                    handle->write_timeout_cb = timeout_cb;

                    GlobusTimeReltimeCopy(
                        handle->open_timeout_period, *delay_time);
                    GlobusTimeReltimeCopy(
                        handle->close_timeout_period, *delay_time);
                    GlobusTimeReltimeCopy(
                        handle->read_timeout_period, *delay_time);
                    GlobusTimeReltimeCopy(
                        handle->write_timeout_period, *delay_time);
                    break;

                case GLOBUS_XIO_ATTR_SET_TIMEOUT_OPEN:
                    timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                    delay_time = va_arg(ap, globus_reltime_t *);
                    handle->timeout_arg = va_arg(ap, void *);
                    if(timeout_cb == NULL)
                    {
                        timeout_cb = globus_l_xio_handle_timeout_always;
                    }
                    handle->open_timeout_cb = timeout_cb;
                    GlobusTimeReltimeCopy(
                        handle->open_timeout_period, *delay_time);
                    break;

                case GLOBUS_XIO_ATTR_SET_TIMEOUT_CLOSE:
                    timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                    delay_time = va_arg(ap, globus_reltime_t *);
                    handle->timeout_arg = va_arg(ap, void *);
                    if(timeout_cb == NULL)
                    {
                        timeout_cb = globus_l_xio_handle_timeout_always;
                    }
                    handle->close_timeout_cb = timeout_cb;
                    GlobusTimeReltimeCopy(
                        handle->close_timeout_period, *delay_time);
                    break;

               case GLOBUS_XIO_ATTR_SET_TIMEOUT_READ:
                    timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                    delay_time = va_arg(ap, globus_reltime_t *);
                    handle->timeout_arg = va_arg(ap, void *);
                    if(timeout_cb == NULL)
                    {
                        timeout_cb = globus_l_xio_handle_timeout_always;
                    }

                    handle->read_timeout_cb = timeout_cb;
                    GlobusTimeReltimeCopy(
                        handle->read_timeout_period, *delay_time);
                    break;

                case GLOBUS_XIO_ATTR_SET_TIMEOUT_WRITE:
                    timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                    delay_time = va_arg(ap, globus_reltime_t *);
                    handle->timeout_arg = va_arg(ap, void *);
                    if(timeout_cb == NULL)
                    {
                        timeout_cb = globus_l_xio_handle_timeout_always;
                    }
                    handle->write_timeout_cb = timeout_cb;
                    GlobusTimeReltimeCopy(
                        handle->write_timeout_period, *delay_time);
                    break;

                default:
                    break;
            }
        }
        globus_mutex_unlock(&context->mutex);
    }
    va_end(ap);

    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

/************************************************************************
 *                          blocking calls
 *                          --------------
 ***********************************************************************/
globus_i_xio_blocking_t *
globus_i_xio_blocking_alloc()
{
    globus_i_xio_blocking_t *           info;

    info = (globus_i_xio_blocking_t *) 
                globus_malloc(sizeof(globus_i_xio_blocking_t));
    globus_mutex_init(&info->mutex, NULL);
    globus_cond_init(&info->cond, NULL);
    info->done = GLOBUS_FALSE;

    return info;
}

void
globus_i_xio_blocking_destroy(
    globus_i_xio_blocking_t *           info)
{
    globus_mutex_destroy(&info->mutex);
    globus_cond_destroy(&info->cond);
    globus_free(info);
}

void
globus_l_xio_blocking_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_xio_blocking_t *           info;

    info = (globus_i_xio_blocking_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->error_obj = GlobusXIOResultToObj(result);
        info->done = GLOBUS_TRUE;
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

void
globus_l_xio_blocking_data_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_xio_blocking_t *               info;
    
    info = (globus_i_xio_blocking_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->error_obj = GlobusXIOResultToObj(result);
        info->data_desc = data_desc;
        info->nbytes = nbytes;
        info->done = GLOBUS_TRUE;
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

void
globus_l_xio_blocking_iov_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_xio_blocking_t *           info;

    info = (globus_i_xio_blocking_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->error_obj = GlobusXIOResultToObj(result);
        info->data_desc = data_desc;
        info->nbytes = nbytes;
        info->done = GLOBUS_TRUE;
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

globus_result_t
globus_xio_open(
    globus_xio_handle_t                 handle,
    const char *                        contact_string,
    globus_xio_attr_t                   attr)
{
    void *                              driver_attr = NULL;
    globus_i_xio_op_t *                 op;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_xio_context_t *            context;
    int                                 ctr;
    globus_i_xio_blocking_t *           info;
    globus_callback_space_t             space = 
            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(globus_xio_open);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_err;
    }
    if(handle->state != GLOBUS_XIO_HANDLE_STATE_CLIENT &&
        handle->state != GLOBUS_XIO_HANDLE_STATE_ACCEPTED)
    {
        res = GlobusXIOErrorInvalidState(handle->state);
        goto param_err;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto param_err;
    }
    
    context = handle->context;
    GlobusXIOOperationCreate(op, context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto op_alloc_error;
    }
    info->op = op;
    
    GlobusXIOHandleSetup(handle, attr);

    /* all memory has been allocated, now set up the different structures */

    /*
     *  set up the operation
     */

    op->type = GLOBUS_XIO_OPERATION_TYPE_OPEN;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ndx = 0;
    op->ref = 1;
    op->_op_cb = globus_l_xio_blocking_cb;
    op->user_arg = info;
    op->entry[0].prev_ndx = -1; /* for first pass there is no return */
    op->blocking = GLOBUS_TRUE;
    op->blocked_thread = GlobusXIOThreadSelf();
    
    /* initialize the handle */
    handle->ref++; /* for operation */
    /* this is set for the cancel */
    handle->open_op = op;

    if(attr != NULL)
    {
        space =  attr->space;
        
        /* set entries in structures */
        for(ctr = 0; ctr < context->stack_size; ctr++)
        {
            op->entry[ctr].open_attr = NULL;
            GlobusIXIOAttrGetDS(
                driver_attr, attr, context->entry[ctr].driver);

            if(driver_attr != NULL)
            {
                context->entry[ctr].driver->attr_copy_func(
                    &op->entry[ctr].open_attr, driver_attr);
            }
        }
    }
    /* initialize the context */
    handle->space = space;
    globus_callback_space_reference(space);

    res = globus_l_xio_register_open(op, contact_string);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_err;
    }

    globus_mutex_lock(&info->mutex);
    {
        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    res = GlobusXIOObjToResult(info->error_obj);
    globus_i_xio_blocking_destroy(info);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_err;
    }

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  op_alloc_error:
    globus_i_xio_blocking_destroy(info);
    
  register_err:
  param_err:
    GlobusXIODebugExitWithError();

    return res;
}

/* 
 *  read
 */
globus_result_t
globus_xio_read(
    globus_xio_handle_t                 user_handle,
    globus_byte_t *                     buffer,
    globus_size_t                       buffer_length,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes,
    globus_xio_data_descriptor_t        data_desc)
{
    globus_i_xio_op_t *                 op;
    globus_result_t                     res;
    globus_i_xio_handle_t *             handle;
    int                                 ref = 0;
    globus_i_xio_blocking_t *           info;
    GlobusXIOName(globus_xio_read);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(buffer == NULL)
    {
        res = GlobusXIOErrorParameter("buffer");
        goto param_error;
    }
    if(buffer_length < 0)
    {
        res = GlobusXIOErrorParameter("buffer_length");
        goto param_error;
    }
    
    if(nbytes != NULL)
    {
        *nbytes = 0;
    }
    
    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
        op->ref = 0;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    GlobusXIOOpInc(op);
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = globus_l_xio_blocking_data_cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;
    op->blocked_thread = GlobusXIOThreadSelf();
    
    info->op = op;
    
    res = globus_l_xio_register_readv(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_error;
    }
    
    globus_mutex_lock(&info->mutex);
    {
        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    res = GlobusXIOObjToResult(info->error_obj);
    globus_i_xio_blocking_destroy(info);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_readv(
    globus_xio_handle_t                 user_handle,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes,
    globus_xio_data_descriptor_t        data_desc)
{
    globus_i_xio_op_t *                 op;
    globus_result_t                     res;
    globus_i_xio_handle_t *             handle;
    int                                 ref = 0;
    globus_i_xio_blocking_t *           info;
    GlobusXIOName(globus_xio_readv);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(iovec == NULL)
    {
        res = GlobusXIOErrorParameter("iovec");
        goto param_error;
    }
    if(iovec_count <= 0)
    {
        res = GlobusXIOErrorParameter("iovec_count");
        goto param_error;
    }
    
    if(nbytes != NULL)
    {
        *nbytes = 0;
    }
    
    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
        op->ref = 0;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    GlobusXIOOpInc(op);
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = globus_l_xio_blocking_iov_cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;
    op->blocked_thread = GlobusXIOThreadSelf();
    
    info->op = op;
    
    res = globus_l_xio_register_readv(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_error;
    }
        
    globus_mutex_lock(&info->mutex);
    {
        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    res = GlobusXIOObjToResult(info->error_obj);
    globus_i_xio_blocking_destroy(info);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  writes
 */
globus_result_t
globus_xio_write(
    globus_xio_handle_t                 user_handle,
    globus_byte_t *                     buffer,
    globus_size_t                       buffer_length,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes,
    globus_xio_data_descriptor_t        data_desc)
{
    globus_i_xio_op_t *                 op;
    globus_result_t                     res;
    globus_i_xio_handle_t *             handle;
    int                                 ref = 0;
    globus_i_xio_blocking_t *           info;
    GlobusXIOName(globus_xio_write);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(buffer == NULL)
    {
        res = GlobusXIOErrorParameter("buffer");
        goto param_error;
    }
    if(buffer_length < 0)
    {
        res = GlobusXIOErrorParameter("buffer_length");
        goto param_error;
    }
    
    if(nbytes != NULL)
    {
        *nbytes = 0;
    }
    
    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
        op->ref = 0;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    GlobusXIOOpInc(op);
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = globus_l_xio_blocking_data_cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;
    op->blocked_thread = GlobusXIOThreadSelf();

    info->op = op;

    res = globus_l_xio_register_writev(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_error;
    }
    
    globus_mutex_lock(&info->mutex);
    {
        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    res = GlobusXIOObjToResult(info->error_obj);
    globus_i_xio_blocking_destroy(info);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_writev(
    globus_xio_handle_t                 user_handle,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes,
    globus_xio_data_descriptor_t        data_desc)
{
    globus_i_xio_op_t *                 op;
    globus_result_t                     res;
    globus_i_xio_handle_t *             handle;
    int                                 ref = 0;
    globus_i_xio_blocking_t *           info;
    GlobusXIOName(globus_xio_writev);

    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(iovec == NULL)
    {
        res = GlobusXIOErrorParameter("iovec");
        goto param_error;
    }
    if(iovec_count <= 0)
    {
        res = GlobusXIOErrorParameter("iovec_count");
        goto param_error;
    }
    
    if(nbytes != NULL)
    {
        *nbytes = 0;
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
        op->ref = 0;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    GlobusXIOOpInc(op);
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = globus_l_xio_blocking_iov_cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;
    op->blocked_thread = GlobusXIOThreadSelf();

    info->op = op;

    res = globus_l_xio_register_writev(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_error;
    }
    
    globus_mutex_lock(&info->mutex);
    {
        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    res = GlobusXIOObjToResult(info->error_obj);
    globus_i_xio_blocking_destroy(info);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_close(
    globus_xio_handle_t                 handle,
    globus_xio_attr_t                   attr)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_xio_blocking_t *           info;
    globus_bool_t                       pass = GLOBUS_TRUE;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    int                                 ctr;
    GlobusXIOName(globus_xio_close);
 
    GlobusXIODebugEnter();
    GlobusLXIOActiveTest();

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    
    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    
    globus_mutex_lock(&handle->context->mutex);
    {
        if(handle->sd_monitor != NULL)
        {
            res = GlobusXIOErrorUnloaded();
        }
        else if(handle->state == GLOBUS_XIO_HANDLE_STATE_CLIENT ||
            handle->state == GLOBUS_XIO_HANDLE_STATE_ACCEPTED ||
            handle->state == GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED ||
            handle->state == GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED)
        {
            /* we avoid the oneshot and blocking call by handling these cases
             * now.  Since the stack was never successfully opened, we don't
             * need to pass close
             */
            if(handle->state == GLOBUS_XIO_HANDLE_STATE_ACCEPTED)
            {
                /* do need to destroy the accepted links, though */
                for(ctr = 0;  ctr < handle->context->stack_size; ctr++)
                {
                    if(handle->context->entry[ctr].driver_handle &&
                        handle->context->entry[ctr].driver->link_destroy_func)
                    {
                        handle->context->entry[ctr].driver->link_destroy_func(
                            handle->context->entry[ctr].driver_handle);
                    }
                }
            }
            
            GlobusXIOHandleStateChange(handle, GLOBUS_XIO_HANDLE_STATE_CLOSED);
            destroy_handle = GLOBUS_TRUE;
            pass = GLOBUS_FALSE;
        }
        else
        {
            res = globus_l_xio_handle_pre_close(
                handle, attr, globus_l_xio_blocking_cb, info, GLOBUS_TRUE);
            if(handle->state == 
                GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING)
            {
                pass = GLOBUS_FALSE;
            }
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(res != GLOBUS_SUCCESS)
    {
        goto register_error;
    }
    
    if(pass)
    {
        res = globus_l_xio_register_close(handle->close_op);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_error;
        }
    }
    
    if(destroy_handle)
    {
        globus_i_xio_handle_dec(handle, &destroy_handle);
        if(destroy_handle)
        {
            globus_i_xio_handle_destroy(handle);
        }
    }
    else
    {
        globus_mutex_lock(&info->mutex);
        {
            while(!info->done)
            {
                globus_cond_wait(&info->cond, &info->mutex);
            }
        }
        globus_mutex_unlock(&info->mutex);
        
        res = GlobusXIOObjToResult(info->error_obj);
    }
    
    globus_i_xio_blocking_destroy(info);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_i_xio_blocking_destroy(info);
    
    /* desroy op */
  alloc_error:
  param_error:
    GlobusXIODebugExitWithError();
    return res;
}
