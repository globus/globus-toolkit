



globus_result_t
globus_xio_handle_cntl(
    globus_xio_handle_t                         handle,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
}

globus_result_t
globus_xio_driver_open(
    globus_xio_driver_context_t *               context,
    globus_xio_driver_operation_t               op,
    globus_xio_driver_callback_t                cb,
    void *                                      user_arg);

globus_result_t
globus_xio_driver_finished_open(
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               open_op);

typedef globus_result_t
(*globus_xio_driver_transform_open_t)(
    void **                                     driver_handle,
    void *                                      driver_handle_attr,
    void *                                      target,
    globus_xio_driver_operation_t               op);

/**
 *  transport open
 */
typedef globus_result_t
(*globus_xio_driver_transport_open_t)(
    void **                                     driver_handle,
    void *                                      driver_handle_attr,
    void *                                      target,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op);



globus_result_t
globus_xio_register_open(
    globus_xio_handle_t *                       handle,
    globus_xio_attr_t                           attr,
    globus_xio_target_t                         target,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
    struct globus_i_xio_handle_s *              l_handle;
    struct globus_i_xio_target_s *              l_target;
    struct globus_i_xio_operation_s *           l_op;
    globus_result_t                             res = GLOBUS_SUCCESS;

    if(handle == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_register_open");
    }
    if(target == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_register_open");
    }

    l_target = (struct globus_i_xio_target_s *) target;
    l_handle = (struct globus_i_xio_handle_s *) globus_malloc(
                    sizeof(struct globus_i_xio_handle_s));
    if(l_handle == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }

    l_op = (struct globus_i_xio_operation_s *) globus_malloc(
                sizeof(struct globus_i_xio_operation_s));
    if(l_op == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }
    l_op->driver_stack = (struct globus_i_xio_driver_op_stack_s *) 
                            globus_malloc(
                                sizeof(struct globus_i_xio_driver_op_stack_s) *
                                    l_target->stack_size);
    if(l_op->driver_stack == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }

    /* intialize the operation structure */
    for(ctr = 0; ctr < l_target->stack_size; ctr++)
    {
        l_op->driver_stack[ctr].driver = l_target->target_stack[ctr].driver;
        l_op->driver_stack[ctr].driver_attr = globus_l_xio_attr_find_driver(
                l_attr, l_op->driver_stack[ctr].driver);
    }
    l_op->op_type = GLOBUS_XIO_OPERATION_OPEN;
    l_op->xio_handle = l_handle;
    l_op->current_driver_ndx = 0;

    /* copy target info to handle and destroy the target */
    /* hold off on destroying the target until we know we succeed */
    l_handle->target_stack = l_target->target_stack;
    l_handle->stack_size = l_target->stack_size;

    /* pass open on down */
    Globus_XIO_Driver_Pass_Open(
        res,
        context,
        l_op,
        cb,
        user_arg);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    } 
    /* destroy the target */
    globus_free(l_target);

    *handle = l_handle;

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:
    if(l_handle != NULL)
    {
        globus_free(l_handle);
    }
    if(l_op != NULL)
    {
        if(l_op->driver_stack != NULL)
        {
            globus_free(l_op->driver_stack);
        }
        globus_free(l_op);
    }

    return res;
}

globus_result_t
globus_xio_register_read(
    globus_xio_handle_t                         handle,
    globus_byte_t *                             buffer,
    globus_size_t                               buffer_length,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
}

globus_result_t
globus_xio_register_write(
    globus_xio_handle_t                         handle,
    globus_byte_t *                             buffer,
    globus_size_t                               buffer_length,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
}

globus_result_t
globus_xio_register_close(
    globus_xio_handle_t                         handle,
    int                                         how,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
}
