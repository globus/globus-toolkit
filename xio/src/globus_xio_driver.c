
/*
 *  kickout for a read or write
 */
void
globus_l_xio_driver_op_data_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         xio_op;

    xio_op = (globus_i_xio_server_t *) user_arg;

    xio_op->entry[xio_p->ndx]._op_ent_data_cb(
        xio_op,
        xio_op->cached_res,
        xio_op->entry[xio_op->ndx].nbytes,
        xio_op->entry[xio_op->ndx].user_arg);
}

/*
 *  kickout for a open close and accept
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
 *                  Macro wrapper function
 *                  -----------------------
 *  we don't really need these as far as i can tell
 *************************************************************************/
globus_result_t
globus_xio_driver_pass_accept(
    globus_xio_driver_operation_t               accept_op,
    globus_xio_driver_callback_t                cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    if(server_handle == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
    }

    GlobusXIODriverPassServerAccept(res, accept_op, cb, user_arg);

    return res;
}

void
globus_xio_driver_finished_accept(
    globus_xio_driver_operation_t               accept_op,
    void *                                      driver_target,
    globus_result_t                             result)
{
    if(accepted_handle == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
    }

    GlobusXIODriverFinishedAccept(accept_op, driver_target, result);
}   
    
void
globus_xio_driver_enable_cancel(
    globus_xio_driver_operation_t               accept_op,
    globus_bool_t *                             cancel_now,
    globus_xio_driver_accept_cancel_callback_t  cancel_cb,
    void *                                      user_arg)
{
    GlobusXIOServerEnableCancel(accept_op, *cancel_now, cancel_cb, user_arg);
}

void
globus_xio_driver_disable_cancel(
    globus_xio_driver_operation_t               accept_op)
{
    GlobusXIOServerDisableCancel(accept_op);
}

