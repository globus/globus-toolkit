#include "globus_xio_pass.h"
#include "globus_xio.h"
#include "globus_i_xio.h"

void
globus_l_xio_driver_op_read_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    op = (globus_i_xio_op_t *) user_arg;
    GlobusIXIODriverReadDeliver(op);
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

        tmp_op = (globus_i_xio_op_t *)
                    globus_list_remove(&my_context->eof_op_list,
                        my_context->eof_op_list);

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
    globus_i_xio_op_entry_t *                   my_op;
    globus_i_xio_context_entry_t *              my_context;

    op->progress = GLOBUS_TRUE;
    op->block_timeout = GLOBUS_FALSE;
    my_op = &op->entry[op->ndx - 1];
    my_op->in_register = GLOBUS_TRUE;
    my_context = &op->_op_context->entry[op->ndx - 1];

    res = my_context->driver->close_func(
                    my_context->driver_handle,
                    my_op->attr,
                    my_context,
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
    globus_i_xio_op_t *                         op;
    globus_i_xio_op_entry_t *                   my_op;

    op = (globus_i_xio_op_t *) user_arg;

    my_op = &op->entry[op->ndx - 1];
    op->ndx = my_op->caller_ndx;
    my_op->cb(
        op,
        op->cached_res,
        my_op->user_arg);
}

/**************************************************************************
 *                  context driver api funcitons
 *                  ----------------------------
 *************************************************************************/
globus_result_t
globus_xio_driver_context_close(
    globus_xio_context_t                        context)
{
    globus_i_xio_context_entry_t *              context_entry;
    globus_i_xio_context_t *                    xio_context;
    globus_bool_t                               destroy_context = GLOBUS_FALSE;
    globus_result_t                             res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_driver_context_close);

    context_entry = context;
    xio_context = context_entry->whos_my_daddy;

    globus_mutex_lock(&context_entry->mutex);
    {
        if(context_entry->state != GLOBUS_XIO_HANDLE_STATE_CLOSED)
        {
            res = GlobusXIOErrorInvalidState(context_entry->state);
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

/**************************************************************************
 *                  macro wrapper functions
 *                  -----------------------
 *
 *  this is mainly a compile test, but who knows, someone may want it
 *************************************************************************/
void *
globus_i_xio_attr_get_ds(
    globus_i_xio_attr_t *                       attr,
    globus_xio_driver_t                         driver)
{
    void *                                      rc;

    GlobusIXIOAttrGetDS(rc, attr, driver);

    return rc;
}

void *
globus_i_xio_dd_get_ds(
    globus_i_xio_dd_t *                         dd,
    globus_xio_driver_t                         driver)
{
    void *                                      rc;

    GlobusIXIODDGetDS(rc, dd, driver);

    return rc;    
}

/*
 *  pass functions
 */
globus_result_t
globus_xio_driver_pass_server_accept(
    globus_i_xio_op_t *                         op,
    globus_xio_driver_callback_t                cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    GlobusXIODriverPassServerAccept(res, op, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_open(
    globus_xio_context_t *                      out_context,
    globus_i_xio_op_t *                         op,
    globus_xio_driver_callback_t                cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    GlobusXIODriverPassOpen(res, *out_context, op, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_close(
    globus_i_xio_op_t *                         op,
    globus_xio_driver_callback_t                cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    GlobusXIODriverPassClose(res, op, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_read(
    globus_i_xio_op_t *                         op,
    globus_xio_iovec_t *                        iovec,
    int                                         iovec_count,
    globus_size_t                               waitfor,
    globus_xio_driver_data_callback_t           cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    GlobusXIODriverPassRead(res, op, iovec, iovec_count,  \
        waitfor, cb, user_arg);

    return res;
}

globus_result_t
globus_xio_driver_pass_write(
    globus_i_xio_op_t *                         op,
    globus_xio_iovec_t *                        iovec,
    int                                         iovec_count,
    globus_size_t                               waitfor,
    globus_xio_driver_data_callback_t           cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, \
        waitfor, cb, user_arg);

    return res;
}

/*
 *  finishes function wrappers
 */
void
globus_xio_driver_finished_open(
    globus_xio_context_t                        context,
    void *                                      handle,
    globus_xio_operation_t                      op,
    globus_result_t                             res)
{
    GlobusXIODriverFinishedOpen(context, handle, op, res);
}

void
globus_xio_driver_finished_close(
    globus_xio_operation_t                      op,
    globus_result_t                             res)
{
    GlobusXIODriverFinishedClose(op, res);
}

void
globus_xio_driver_finished_read(
    globus_xio_operation_t                      op,
    globus_result_t                             res,
    globus_size_t                               nbytes)
{
    GlobusXIODriverFinishedRead(op, res, nbytes);
}

void
globus_xio_driver_finished_write(
    globus_xio_operation_t                      op,
    globus_result_t                             res,
    globus_size_t                               nbytes)
{
    GlobusXIODriverFinishedWrite(op, res, nbytes);
}

void
globus_xio_driver_finished_accept(
    globus_xio_operation_t                      op,
    void *                                      target,
    globus_result_t                             res)
{
    GlobusXIODriverFinishedAccept(op, target, res);
}

