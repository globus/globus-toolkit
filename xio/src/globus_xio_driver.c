#include "globus_xio.h"
#include "globus_i_xio.h"

void
globus_l_xio_op_restarted(
    globus_i_xio_op_t *                     op)
{
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_i_xio_context_t *                context;
    globus_i_xio_handle_t *                 handle;

    GlobusXIOName(globus_l_xio_op_restarted);

    GlobusXIODebugInternalEnter();

    context = op->_op_context;
    handle = op->_op_handle;
    globus_mutex_lock(&context->mutex);
    {
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, &destroy_context);
        }
    }
    globus_mutex_unlock(&context->mutex);

    if(destroy_handle)
    {
        if(destroy_context)
        {
            globus_i_xio_context_destroy(context);
        }
        globus_i_xio_handle_destroy(handle);
    }
                                                                                
    GlobusXIODebugInternalExit();
}

globus_result_t
globus_i_xio_repass_write(
    globus_i_xio_op_t *                     op)
{
    globus_i_xio_op_entry_t *               my_op;
    globus_i_xio_context_entry_t *          next_context;
    globus_result_t                         res;
    globus_xio_iovec_t *                    tmp_iovec;
    int                                     iovec_count;

    my_op = &op->entry[op->ndx - 1];
    next_context = &op->_op_context->entry[op->ndx - 1];

    /* allocate tmp iovec to the bigest it could ever be */
    if(my_op->_op_ent_fake_iovec == NULL)
    {
        my_op->_op_ent_fake_iovec = (globus_xio_iovec_t *)
            globus_malloc(sizeof(globus_xio_iovec_t) *
                my_op->_op_ent_iovec_count);
    }
    tmp_iovec = my_op->_op_ent_fake_iovec;

    GlobusIXIOUtilTransferAdjustedIovec(
        tmp_iovec, iovec_count,
        my_op->_op_ent_iovec, my_op->_op_ent_iovec_count,
        my_op->_op_ent_nbytes);

    /* repass the operation down */
    res = next_context->driver->write_func(
            next_context->driver_handle,
            tmp_iovec,
            iovec_count,
            op);

    return res;
}

globus_result_t
globus_i_xio_repass_read(
    globus_i_xio_op_t *                     op)
{
    globus_i_xio_op_entry_t *               my_op;
    globus_i_xio_context_entry_t *          next_context;
    globus_result_t                         res;
    globus_xio_iovec_t *                    tmp_iovec;
    int                                     iovec_count;

    my_op = &op->entry[op->ndx - 1];
    next_context = &op->_op_context->entry[op->ndx - 1];

    /* allocate tmp iovec to the bigest it could ever be */
    if(my_op->_op_ent_fake_iovec == NULL)
    {
        my_op->_op_ent_fake_iovec = (globus_xio_iovec_t *)
            globus_malloc(sizeof(globus_xio_iovec_t) *
                my_op->_op_ent_iovec_count);
    }
    tmp_iovec = my_op->_op_ent_fake_iovec;

    GlobusIXIOUtilTransferAdjustedIovec(
        tmp_iovec, iovec_count,
        my_op->_op_ent_iovec, my_op->_op_ent_iovec_count,
        my_op->_op_ent_nbytes);

    /* repass the operation down */
    res = next_context->driver->read_func(
            next_context->driver_handle,
            tmp_iovec,
            iovec_count,
            op);

    return res;
}

void 
globus_i_xio_pass_failed(
    globus_i_xio_op_t *                     op,
    globus_i_xio_context_entry_t *          my_context,
    globus_bool_t *                         close,
    globus_bool_t *                         destroy_handle,
    globus_bool_t *                         destroy_context)
{

    my_context->outstanding_operations--;
    /*there is an off chance that we could need to close here*/
    if((my_context->state == GLOBUS_XIO_CONTEXT_STATE_CLOSING ||
        my_context->state ==
        GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED_AND_CLOSING) &&
        my_context->outstanding_operations == 0)
    {
        globus_assert(my_context->close_op != NULL);
        *close = GLOBUS_TRUE;
    }
    op->ref--;
    if(op->ref == 0)
    {
        globus_i_xio_op_destroy(op, destroy_handle, destroy_context); 
    }

}

void
globus_i_xio_handle_destroy(
    globus_i_xio_handle_t *                 handle)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_list_remove(&globus_l_outstanding_handles_list,
            globus_list_search(globus_l_outstanding_handles_list, handle));
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
    globus_assert(handle->ref == 0);
    globus_free(handle);
}

/* 
 *  called in the context lock
 */
void
globus_i_xio_handle_dec(
    globus_i_xio_handle_t *                 handle,
    globus_bool_t *                         destroy_handle,
    globus_bool_t *                         destroy_context)
{
    globus_result_t                         res;
    globus_i_xio_context_t *                context;
    globus_i_xio_space_info_t *             space_info;

    context = handle->context;

    *destroy_handle = GLOBUS_FALSE;
    *destroy_context = GLOBUS_FALSE;

    handle->ref--; 
    if(handle->ref == 0)
    {
        globus_assert(handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSED);
        *destroy_handle = GLOBUS_TRUE;
        context->ref--;
        if(context->ref == 0)
        {
            *destroy_context = GLOBUS_TRUE;
        }
        /* purge the ch list */
        while(!globus_list_empty(handle->cb_list))
        {
            space_info = (globus_i_xio_space_info_t *)
                globus_list_remove(&handle->cb_list, handle->cb_list);
            res = globus_callback_unregister(
                    space_info->ch,
                    NULL,
                    NULL,
                    NULL);
            if(res != GLOBUS_SUCCESS)
            {
                globus_panic(GLOBUS_XIO_MODULE, res, "failed to unregister");
            }
        }
    }
}

/* 
 * called locked 
 */
void
globus_i_xio_op_destroy(
    globus_i_xio_op_t *                     op,
    globus_bool_t *                         destroy_handle,
    globus_bool_t *                         destroy_context)
{
    globus_i_xio_handle_t *                 handle;
    globus_i_xio_context_t *                context;
    int                                     ctr;

    context = op->_op_context;
    handle = op->_op_handle;

    globus_assert(op->ref == 0);

    for(ctr = 0; ctr < op->stack_size; ctr++)
    {
        if(op->entry[ctr].dd != NULL)
        {
            op->_op_context->entry[ctr].driver->attr_destroy_func(
                op->entry[ctr].dd);
        }
    }

    globus_memory_push_node(&context->op_memory, op);
    globus_i_xio_handle_dec(handle, destroy_handle, destroy_context);
}

void
globus_i_xio_will_block_cb(
    globus_thread_callback_index_t          wb_ndx,
    globus_callback_space_t                 space,
    void *                                  user_args)
{
    globus_i_xio_op_t *                     op;
    int                                     ndx;

    op = (globus_i_xio_op_t *) user_args;

    globus_thread_blocking_callback_pop(&wb_ndx);

    op->restarted = GLOBUS_TRUE;
    globus_assert(op->ndx == 0);
    ndx = op->ndx;
    while(ndx != op->stack_size)
    {
        op->ref++;
        switch(op->entry[ndx].type)
        {
            case GLOBUS_XIO_OPERATION_TYPE_OPEN:
                GlobusIXIODriverOpenDeliver(op, ndx);
                break;

            case GLOBUS_XIO_OPERATION_TYPE_READ:
                GlobusIXIODriverReadDeliver(op, ndx);
                break;

            case GLOBUS_XIO_OPERATION_TYPE_WRITE:
                GlobusIXIODriverWriteDeliver(op, ndx);
                break;

            case GLOBUS_XIO_OPERATION_TYPE_FINISHED:
                return;
                break;

            case GLOBUS_XIO_OPERATION_TYPE_CLOSE:
                break;

            default:
                globus_assert(0);
                break;
        }
        ndx = op->entry[ndx].next_ndx;
    }
}

void
globus_l_xio_driver_op_write_kickout(
    void *                                  user_arg)
{
    int                                     ndx;
    int                                     wb_ndx;
    globus_i_xio_handle_t *                 handle;
    globus_i_xio_context_entry_t *          my_context;
    globus_i_xio_context_t *                context;
    globus_i_xio_op_entry_t *               my_op;
    globus_i_xio_op_t *                     op;
    GlobusXIOName(globus_l_xio_driver_op_write_kickout);

    GlobusXIODebugInternalEnter();
    op = (globus_i_xio_op_t *) user_arg;

    my_op = &op->entry[op->ndx - 1];
    op->entry[my_op->prev_ndx].next_ndx = op->ndx;
    op->ndx = my_op->prev_ndx;
    ndx = op->ndx;
    my_context = &op->_op_context->entry[ndx];
    handle = op->_op_handle;
    context = handle->context;

    if(ndx == 0)
    {
        /* at top level the callback should never be null */
        globus_assert(my_op->_op_ent_data_cb != NULL);
        globus_thread_blocking_space_callback_push(
            globus_i_xio_will_block_cb,
            (void *) op,
            op->blocking ? GLOBUS_CALLBACK_GLOBAL_SPACE: handle->space,
            &wb_ndx);

        my_op->_op_ent_data_cb(op, op->cached_res,
            my_op->_op_ent_nbytes, my_op->user_arg);
    
        if(op->restarted)
        {
            globus_l_xio_op_restarted(op);
            goto exit;
        }
        globus_thread_blocking_callback_pop(&wb_ndx);
    }
    else
    {
        if(my_op->_op_ent_data_cb == NULL)
        {
            globus_xio_driver_finished_write(op, op->cached_res, 
                my_op->_op_ent_nbytes);
        }
        else
        {
            my_op->_op_ent_data_cb(op, op->cached_res,
                my_op->_op_ent_nbytes, my_op->user_arg);
        }
        if(op->restarted)
        {        
            globus_l_xio_op_restarted(op);
            goto exit;
        }
    }

    GlobusIXIODriverWriteDeliver(op, ndx);

  exit:
    GlobusXIODebugInternalExit();
}   
   
void
globus_l_xio_driver_purge_read_eof(
    globus_i_xio_context_entry_t *          my_context)
{
    globus_i_xio_op_t *                     tmp_op;
    GlobusXIOName(globus_l_xio_driver_purge_read_eof);

    GlobusXIODebugInternalEnter();
    while(!globus_list_empty(my_context->eof_op_list))
    {
        /* we can only get here if a eof has been received */ 
        globus_assert(my_context->state ==
            GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED ||
            my_context->state ==
                GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED ||
            my_context->state ==
                GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED_AND_CLOSING ||
            my_context->state ==
                GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED_AND_CLOSING);

        tmp_op = (globus_i_xio_op_t *)
                    globus_list_remove(&my_context->eof_op_list,
                        my_context->eof_op_list);

        globus_i_xio_register_oneshot(
            tmp_op->_op_handle,
            globus_l_xio_driver_op_read_kickout,
           (void *)tmp_op,
            tmp_op->blocking ? GLOBUS_CALLBACK_GLOBAL_SPACE: 
                                tmp_op->_op_handle->space);
    }
    GlobusXIODebugInternalExit();
}

void
globus_l_xio_driver_op_read_kickout(
    void *                                  user_arg)
{
    globus_i_xio_handle_t *                 handle;
    globus_i_xio_context_t *                context;
    globus_i_xio_context_entry_t *          my_context;
    int                                     ndx;
    int                                     wb_ndx;
    globus_i_xio_op_entry_t *               my_op;
    globus_i_xio_op_t *                     op;
    GlobusXIOName(globus_l_xio_driver_op_read_kickout);

    GlobusXIODebugInternalEnter();

    op = (globus_i_xio_op_t *) user_arg;

    my_op = &op->entry[op->ndx - 1];
    op->entry[my_op->prev_ndx].next_ndx = op->ndx;
    op->ndx = my_op->prev_ndx;
    ndx = op->ndx; /* cache this value on stack */
    my_context = &op->_op_context->entry[ndx];
    handle = op->_op_handle;
    context = handle->context;

    if(ndx == 0)
    {
        /* at top level the callback should never be null */
        globus_assert(my_op->_op_ent_data_cb != NULL);
        globus_thread_blocking_space_callback_push(
            globus_i_xio_will_block_cb,
            (void *) op,
            op->blocking ? GLOBUS_CALLBACK_GLOBAL_SPACE: handle->space,
            &wb_ndx);
        my_op->_op_ent_data_cb(op, op->cached_res,
            my_op->_op_ent_nbytes, my_op->user_arg);
        if(op->restarted) 
        {
            globus_l_xio_op_restarted(op);
            goto exit;
        }
        globus_thread_blocking_callback_pop(&wb_ndx);
    }
    else
    {
        if(my_op->_op_ent_data_cb == NULL)
        {
            globus_xio_driver_finished_read(op, op->cached_res,
                my_op->_op_ent_nbytes);
        }
        else
        {
            my_op->_op_ent_data_cb(op, op->cached_res,
                my_op->_op_ent_nbytes, my_op->user_arg);
        }
        if(op->restarted)
        {
            globus_l_xio_op_restarted(op);
            goto exit;
        }
    }

    GlobusIXIODriverReadDeliver(op, ndx);

  exit:
    GlobusXIODebugInternalExit();
}

globus_result_t
globus_i_xio_driver_start_close(
    globus_i_xio_op_t *                     op,
    globus_bool_t                           can_fail)
{
    globus_result_t                         res;
    globus_i_xio_handle_t *                 handle;
    globus_i_xio_op_entry_t *               my_op;
    globus_i_xio_context_t *                context;
    globus_i_xio_context_entry_t *          my_context;
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    GlobusXIOName(globus_i_xio_driver_start_close);

    GlobusXIODebugInternalEnter();
    op->progress = GLOBUS_TRUE;
    op->block_timeout = GLOBUS_FALSE;
    my_op = &op->entry[op->ndx - 1];
    context = op->_op_context;
    handle = op->_op_handle;
    my_context = &context->entry[op->ndx - 1];

    globus_mutex_lock(&context->mutex);
    {
        op->ref++;
    }
    globus_mutex_unlock(&context->mutex);

    my_op->in_register = GLOBUS_TRUE;
    res = my_context->driver->close_func(
                    my_context->driver_handle,
                    my_op->attr,
                    my_context,
                    op);
    my_op->in_register = GLOBUS_FALSE;

    if(res != GLOBUS_SUCCESS && !can_fail)
    {
        GlobusXIODriverFinishedClose(op, res);
    }

    globus_mutex_lock(&context->mutex);
    {
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, &destroy_context);
        }
    }
    globus_mutex_unlock(&context->mutex);

    if(destroy_handle)
    {
        if(destroy_context)
        {
            globus_i_xio_context_destroy(context);
        }
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
    return res;
}

/*
 *  driver callback kickout
 *
 *  when in a register the finish function kicks this out as a oneshot
 */
void
globus_l_xio_driver_op_close_kickout(
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op;
    globus_i_xio_op_entry_t *               my_op;
    GlobusXIOName(globus_l_xio_driver_op_kickout);

    GlobusXIODebugInternalEnter();
    op = (globus_i_xio_op_t *) user_arg;

    my_op = &op->entry[op->ndx - 1];
    op->ndx = my_op->prev_ndx;

    if(my_op->cb != NULL)
    {
        my_op->cb(
            op,
            op->cached_res,
            my_op->user_arg);
    }
    else
    {
        GlobusXIODriverFinishedClose(op, op->cached_res);
    }
    GlobusXIODebugInternalExit();
}

/*
 *  driver callback mickout
 *
 *  when in a register the finish function kicks this out as a oneshot
 */
void
globus_l_xio_driver_op_accept_kickout(
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op;
    globus_i_xio_op_entry_t *               my_op;
    GlobusXIOName(globus_l_xio_driver_op_kickout);
                                                                                
    GlobusXIODebugInternalEnter();
    op = (globus_i_xio_op_t *) user_arg;
                                                                                
    my_op = &op->entry[op->ndx - 1];
    op->ndx = my_op->prev_ndx;
                                                                                
    if(my_op->cb != NULL)
    {
        my_op->cb(
            op,
            op->cached_res,
            my_op->user_arg);
    }
    else
    {
        GlobusXIODriverFinishedAccept(op, NULL, op->cached_res);
    }
    GlobusXIODebugInternalExit();
}


void
globus_l_xio_driver_open_op_kickout(
    void *                                  user_arg)
{
    globus_i_xio_handle_t *                 handle;
    globus_i_xio_context_t *                context;
    globus_i_xio_context_entry_t *          my_context;
    int                                     ndx = 0;
    int                                     wb_ndx;
    globus_i_xio_op_entry_t *               my_op;
    globus_i_xio_op_t *                     op;
    GlobusXIOName(globus_l_xio_driver_open_op_kickout);
    
    GlobusXIODebugInternalEnter();

    op = (globus_i_xio_op_t *) user_arg;

    my_op = &op->entry[op->ndx - 1];
    op->ndx = my_op->prev_ndx;
    ndx = op->ndx;
    my_context = &op->_op_context->entry[ndx];
    handle = op->_op_handle;
    context = handle->context;

    if(ndx == 0)
    {
        /* at top level the callback should never be null */
        globus_assert(my_op->cb != NULL);
        globus_thread_blocking_space_callback_push(
            globus_i_xio_will_block_cb,
            (void *) op,
            op->blocking ? GLOBUS_CALLBACK_GLOBAL_SPACE: handle->space,
            &wb_ndx);
        my_op->cb(op, op->cached_res, my_op->user_arg);
        if(op->restarted)
        {
            globus_l_xio_op_restarted(op);
            goto exit;
        }
        globus_thread_blocking_callback_pop(&wb_ndx);
    }
    else
    {
        if(my_op->cb == NULL)
        {
            globus_xio_driver_finished_open(NULL, NULL, op, op->cached_res);
        }
        else
        {
            my_op->cb(op, op->cached_res, my_op->user_arg);
        }
        if(op->restarted)
        {
            globus_l_xio_op_restarted(op);
            goto exit;
        }
    }

    GlobusIXIODriverOpenDeliver(op, ndx);

  exit:

    GlobusXIODebugInternalExit();
}

/**************************************************************************
 *                  context driver api funcitons
 *                  ----------------------------
 *************************************************************************/
globus_result_t
globus_xio_driver_context_close(
    globus_xio_context_t                    context)
{
    globus_i_xio_context_entry_t *          context_entry;
    globus_i_xio_context_t *                xio_context;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_result_t                         res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_driver_context_close);

    GlobusXIODebugInternalEnter();

    context_entry = context;
    xio_context = context_entry->whos_my_daddy;

    globus_mutex_lock(&xio_context->mutex);
    {
        if(context_entry->state != GLOBUS_XIO_CONTEXT_STATE_CLOSED)
        {
            res = GlobusXIOErrorInvalidState(context_entry->state);
        }
        else
        {
            xio_context->ref--;
            if(xio_context->ref == 0)
            {
                destroy_context = GLOBUS_TRUE;
            }
        }
    }
    globus_mutex_unlock(&xio_context->mutex);

    /* clean up the entry */
    if(destroy_context)
    {
        globus_i_xio_context_destroy(xio_context);
    }

    GlobusXIODebugInternalExit();

    return res;
}

globus_result_t
globus_xio_driver_set_dd(
    globus_xio_operation_t                  op,
    void *                                  driver_dd)
{

}


void
globus_i_xio_context_destroy(
    globus_i_xio_context_t *                xio_context)
{
    GlobusXIOName(globus_i_xio_context_destroy);

    GlobusXIODebugInternalEnter();
    globus_assert(xio_context->ref == 0);

    globus_mutex_destroy(&xio_context->mutex);
    globus_memory_destroy(&xio_context->op_memory);
    globus_free(xio_context);
    GlobusXIODebugInternalExit();
}

globus_i_xio_context_t *
globus_i_xio_context_create(
    globus_i_xio_target_t *                 xio_target)
{
    globus_i_xio_context_t *                xio_context;
    int                                     size;
    int                                     ctr;
    GlobusXIOName(globus_i_xio_context_create);

    GlobusXIODebugInternalEnter();

    size = sizeof(globus_i_xio_context_t) +
        (sizeof(globus_i_xio_context_entry_t) * (xio_target->stack_size - 1));

    xio_context = (globus_i_xio_context_t *) globus_malloc(size);
    if(xio_context != NULL)
    {
        memset(xio_context, '\0', size);

        globus_mutex_init(&xio_context->mutex, NULL);
        xio_context->stack_size = xio_target->stack_size;
        globus_memory_init(&xio_context->op_memory,
            sizeof(globus_i_xio_op_t) +
                (sizeof(globus_i_xio_op_entry_t) *
                    (xio_target->stack_size - 1)),
            GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT);
        xio_context->ref++;
        for(ctr = 0; ctr < xio_context->stack_size; ctr++)
        {
            xio_context->entry[ctr].whos_my_daddy = xio_context;
        }
    }

    GlobusXIODebugInternalExit();

    return xio_context;
}

/**************************************************************************
 *                  macro wrapper functions
 *                  -----------------------
 *
 *  this is mainly a compile test, but who knows, someone may want it
 *************************************************************************/
void *
globus_i_xio_attr_get_ds(
    globus_i_xio_attr_t *                   attr,
    globus_xio_driver_t                     driver)
{
    void *                                  rc;

    GlobusIXIOAttrGetDS(rc, attr, driver);

    return rc;
}

/*
 *  pass functions
 */
globus_result_t
globus_xio_driver_pass_server_accept(
    globus_i_xio_op_t *                     op,
    globus_xio_driver_callback_t            cb,
    void *                                  user_arg)
{
    globus_result_t                         res;

    GlobusXIODriverPassAccept(res, op, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_open(
    globus_xio_context_t *                  out_context,
    globus_i_xio_op_t *                     op,
    globus_xio_driver_callback_t            cb,
    void *                                  user_arg)
{
    globus_result_t                         res;

    GlobusXIODriverPassOpen(res, *out_context, op, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_close(
    globus_i_xio_op_t *                     op,
    globus_xio_driver_callback_t            cb,
    void *                                  user_arg)
{
    globus_result_t                         res;

    GlobusXIODriverPassClose(res, op, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_read(
    globus_i_xio_op_t *                     op,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitfor,
    globus_xio_driver_data_callback_t       cb,
    void *                                  user_arg)
{
    globus_result_t                         res;

    GlobusXIODriverPassRead(res, op, iovec, iovec_count,  \
        waitfor, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_write(
    globus_i_xio_op_t *                     op,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitfor,
    globus_xio_driver_data_callback_t       cb,
    void *                                  user_arg)
{
    globus_result_t                         res;

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, \
        waitfor, cb, user_arg);

    return res;
}

/*
 *  finishes function wrappers
 */
void
globus_xio_driver_finished_open(
    globus_xio_context_t                    context,
    void *                                  handle,
    globus_xio_operation_t                  op,
    globus_result_t                         res)
{
    GlobusXIODriverFinishedOpen(context, handle, op, res);
}

void
globus_xio_driver_finished_close(
    globus_xio_operation_t                  op,
    globus_result_t                         res)
{
    GlobusXIODriverFinishedClose(op, res);
}

void
globus_xio_driver_finished_read(
    globus_xio_operation_t                  op,
    globus_result_t                         res,
    globus_size_t                           nbytes)
{
    GlobusXIODriverFinishedRead(op, res, nbytes);
}

void
globus_xio_driver_finished_write(
    globus_xio_operation_t                  op,
    globus_result_t                         res,
    globus_size_t                           nbytes)
{
    GlobusXIODriverFinishedWrite(op, res, nbytes);
}

void
globus_xio_driver_finished_accept(
    globus_xio_operation_t                  op,
    void *                                  target,
    globus_result_t                         res)
{
    GlobusXIODriverFinishedAccept(op, target, res);
}

/***************************************************************************
 *                      driver setup functions
 *                      ----------------------
 **************************************************************************/
globus_result_t
globus_xio_driver_init(
    globus_xio_driver_t *                   out_driver,
    const char *                            driver_name,
    void *                                  user_data)
{
    globus_i_xio_driver_t *                 driver;
    globus_result_t                         res;
    GlobusXIOName(globus_xio_driver_init);

    GlobusXIODebugEnter();

    driver = (globus_i_xio_driver_t *)
            globus_malloc(sizeof(globus_i_xio_driver_t));
    if(driver == NULL)
    {
        res = GlobusXIOErrorMemory("driver");
        goto err;
    }
    memset(driver, '\0', sizeof(globus_i_xio_driver_t));
    
    driver->name = globus_libc_strdup(driver_name);
    if(!driver->name)
    {
        globus_free(driver);
        res = GlobusXIOErrorMemory("driver->name");
        goto err;
    }
    
    driver->user_data = user_data;

    *out_driver = driver;

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_driver_destroy(
    globus_xio_driver_t                     driver)
{
    GlobusXIOName(globus_xio_driver_destroy);

    GlobusXIODebugEnter();
    globus_free(driver->name);
    globus_free(driver);
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_set_transport(
    globus_xio_driver_t                     driver,
    globus_xio_driver_transport_open_t      transport_open_func,
    globus_xio_driver_close_t               close_func,
    globus_xio_driver_read_t                read_func,
    globus_xio_driver_write_t               write_func,
    globus_xio_driver_handle_cntl_t         handle_cntl_func)
{
    GlobusXIOName(globus_xio_driver_set_transport);

    GlobusXIODebugEnter();
    driver->transport_open_func = transport_open_func;
    driver->close_func = close_func;
    driver->read_func = read_func;
    driver->write_func = write_func;
    driver->handle_cntl_func = handle_cntl_func;
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_set_transform(
    globus_xio_driver_t                     driver,
    globus_xio_driver_transform_open_t      transform_open_func,
    globus_xio_driver_close_t               close_func,
    globus_xio_driver_read_t                read_func,
    globus_xio_driver_write_t               write_func,
    globus_xio_driver_handle_cntl_t         handle_cntl_func)
{
    GlobusXIOName(globus_xio_driver_set_transform);

    GlobusXIODebugEnter();
    driver->transform_open_func = transform_open_func;
    driver->close_func = close_func;
    driver->read_func = read_func;
    driver->write_func = write_func;
    driver->handle_cntl_func = handle_cntl_func;
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_set_client(
    globus_xio_driver_t                     driver,
    globus_xio_driver_target_init_t         target_init_func,
    globus_xio_driver_target_cntl_t         target_cntl_func,
    globus_xio_driver_target_destroy_t      target_destroy_func)
{
    GlobusXIOName(globus_xio_driver_set_client);

    GlobusXIODebugEnter();
    driver->target_init_func = target_init_func;
    driver->target_cntl_func = target_cntl_func;
    driver->target_destroy_func = target_destroy_func;
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_set_server(
    globus_xio_driver_t                     driver,
    globus_xio_driver_server_init_t         server_init_func,
    globus_xio_driver_server_accept_t       server_accept_func,
    globus_xio_driver_server_destroy_t      server_destroy_func,
    globus_xio_driver_server_cntl_t         server_cntl_func,
    globus_xio_driver_target_destroy_t      target_destroy_func)
{
    GlobusXIOName(globus_xio_driver_set_server);

    GlobusXIODebugEnter();
    driver->server_init_func = server_init_func;
    driver->server_accept_func = server_accept_func;
    driver->server_destroy_func = server_destroy_func;
    driver->server_cntl_func = server_cntl_func;
    driver->target_destroy_func = target_destroy_func;
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_set_attr(
    globus_xio_driver_t                     driver,
    globus_xio_driver_attr_init_t           attr_init_func,
    globus_xio_driver_attr_copy_t           attr_copy_func,
    globus_xio_driver_attr_cntl_t           attr_cntl_func,
    globus_xio_driver_attr_destroy_t        attr_destroy_func)
{
    GlobusXIOName(globus_xio_driver_set_attr);

    GlobusXIODebugEnter();
    driver->attr_init_func = attr_init_func;
    driver->attr_copy_func = attr_copy_func;
    driver->attr_cntl_func = attr_cntl_func;
    driver->attr_destroy_func = attr_destroy_func;
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

