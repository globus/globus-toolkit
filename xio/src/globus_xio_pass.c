#include "globus_xio_pass.h"
#include "globus_xio.h"

void
globus_l_xio_driver_op_read_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    op = (globus_i_xio_op_t *) user_arg;
    GlobusIXIODriverReadDeliver(op)
}

void
globus_l_xio_driver_purge_read_eof(
    globus_i_xio_context_entry_t *                  my_context)
{
    globus_i_xio_op_t *                             tmp_op;

    while(!globus_list_empty(my_context->eof_op_list))
    {
        /* we can only get here if a eof has been received */ 
        globus_assert(my_context->state ==
            GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED ||
            my_context->state ==
                GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED ||
            my_context->state ==
                GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING ||
            my_context->state ==
                GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING);

        tmp_op = (globus_i_xio_operation_t *)
                    globus_list_remove(&my_context->read_eof_list,
                        my_context->read_eof_list);

        globus_callback_space_register_oneshot(
            NULL,
            NULL,
            globus_l_xio_driver_op_write_kickout,
           (void *)tmp_op,
            my_context->space);
    }
}

void
globus_l_xio_driver_op_write_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;

    op = (globus_i_xio_op_t *) user_arg;
    GlobusIXIODriverWriteDeliver(op);
}

globus_result_t
globus_i_xio_driver_start_close(
    globus_i_xio_op_t *                         op,
    globus_bool_t                               can_fail)
{
    globus_result_t                             res;
    globus_i_xio_op_entry_t *                   next_op;
    globus_i_xio_op_entry_t *                   my_op;
    globus_i_xio_context_entry_t *              next_context;
    int                                         caller_ndx;

    op->progress = GLOBUS_TRUE;
    op->block_timeout = GLOBUS_FALSE;
    my_op = &op->entry[op->ndx];
    my_op->in_register = GLOBUS_TRUE;
    caller_ndx = op->ndx;

    do
    {
        op->ndx++;
        next_op = &op->entry[op->ndx];
        next_context = &op->context->entry[op->ndx];
    }
    while(next_context->driver->close_func == NULL);

    next_op->caller_ndx = caller_ndx;

    res = next_context->driver->close_func(
                    next_context->driver_handle,
                    next_op->attr,
                    op->context,
                    op);
    if(res != GLOBUS_SUCCESS && !can_fail)
    {
        GlobusXIODriverFinishedClose(op, res);
    }
    my_op->in_register = GLOBUS_FALSE;

    return res;
}

/*
 *  driver callback kickout
 *
 *  when in a register the finish function kicks this out as a oneshot
 */
void
globus_l_xio_driver_op_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         xio_op;

    xio_op = (globus_i_xio_server_t *) user_arg;

    xio_op->entry[xio_p->ndx].cb(
        xio_op,
        xio_op->cached_res,
        xio_op->entry[xio_op->ndx].user_arg);
}

/**************************************************************************
 *                  context driver api funcitons
 *                  ----------------------------
 *************************************************************************/
globus_result_t
globus_xio_driver_context_close(
    globus_xio_driver_context_t                 context)
{
    globus_i_xio_context_entry_t *              context_entry;
    globus_i_xio_context_t *                    xio_context;
    globus_bool_t                               destroy_context = GLOBUS_FALSE;
    globus_result_t                             res = GLOBUS_SUCCESS;

    context_entry = context;
    xio_context = context_entry->whos_my_daddy;

    globus_mutex_lock(&context_entry->mutex);
    {
        if(context_entry->state != GLOBUS_XIO_HANDLE_STATE_CLOSED)
        {
            res = GlobusXIOErrorHandleBadState(                     \
                        "globus_xio_driver_context_close");
        }
        else
        {
            /* always called inside entry lock */
            globus_mutex_lock(&xio_context->mutex);
            {
                xio_context->ref--;
                if(xio_context->ref == 0)
                {
                    destroy_context = GLOBUS_TRUE;
                }
            }
            globus_mutex_unlock(&xio_context->mutex);
        }
    }
    globus_mutex_unlock(&context_entry->mutex);

    /* clean up the entry */
    globus_mutex_destroy(&context_entry->mutex);
    if(destroy_context)
    {
        globus_i_xio_context_destroy(xio_context);
    }

    return res;
}

void
globus_i_xio_context_destroy(
    globus_i_xio_context_t *                            xio_context)
{
    globus_assert(xio_context->ref == 0);

    globus_mutex_destroy(&xio_context->mutex);
    globus_memory_destroy(&xio_context->op_memory);
    globus_free(xio_context);
}

globus_i_xio_context_t *
globus_i_xio_context_create(
    globus_i_xio_target_t *                         xio_target)
{
    globus_i_xio_context_t *                        xio_context;
    int                                             size;
    int                                             ctr;

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

        for(ctr = 0; ctr < xio_context->stack_size; ctr++)
        {
            globus_mutex_init(&xio_context->entry[ctr].mutex, NULL);
            xio_context->entry[ctr].whos_my_daddy = xio_context;
            /* initialize all to GLOBAL, only top can change */
            xio_context->entry[ctr].space = GLOBUS_CALLBACK_GLOBAL_SPACE;
        }
    }

    return xio_context;
}

