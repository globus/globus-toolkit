#include "globus_xio_pass.h"

void
globus_l_xio_driver_op_read_kickout(
    void *                                      user_arg);
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

    while(!globus_list_empty(my_context->read_eof_list))
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
    op->timeout_blocked = GLOBUS_FALSE;
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
