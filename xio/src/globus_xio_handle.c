#define GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT   2
/********************************************************************
 *                      MACROS
 *******************************************************************/
Globus_XIO_Driver_Pass_Open(out_res, out_context, op, cb, user_arg)
do 
{
    globus_i_xio_operation_t *                      _op;
    globus_xio_callback_t                           _cb;
    void *                                          _user_arg;
    globus_i_xio_context_t *                        _context;
    globus_i_xio_op_entry_t *                       _entry;

    _op = (op);
    _cb = (cb);
    _user_arg = (user_arg);

    /* 
     *  if op is canceled just return an error
     *  error can then be passed on back up the stack with finished op
     */
    if(_op->canceled)
    {
        out_res = ERROR;
    }
    /* if at bottom of the stack we cannot pass further down */
    else if(_op->ndx == _op->stack_size)
    {
        out_res = ERROR;
    }
    else
    {
        /* state that progress has been made */
        _op->progress = GLOBUS_TRUE;
        /* assign callback info in current slot */
        _entry = &_op->entry_array[_op->ndx];
        _entry->cb = _cb; /* this may result in a casting error */
        _entry->user_arg = _user_arg;
        /* set the callstack flag */
        _entry->in_register = GLOBUS_TRUE;
        /* find next slot. start on next and find first interseted */
        _op->ndx++; 
        while(_op->context[_op->ndx]->driver->open_func == NULL &&
              _op->ndx < _op->stack_size)
        {
            _op->ndx++;
        }

        /* 
         * if a open function is not found anywhere on the stack we have 
         * problems.  this hsould not happen ever, it is checked when
         * the stack is built.  if this does happen there is most likely
         * memory curroption
         */
        assert(_op->context[_op->ndx]->driver->open_func != NULL);

        /* call the next interface function in the stack */
        _context = &_op->context[_op->ndx];
        out_res = context->driver->open_func(
                        &_context->driver_handle,
                        _context->driver_attr,
                        _context->target,
                        _op->context,
                        _op);

        /* flip the callstack flag */
        _entry->in_register = GLOBUS_FALSE;
        out_context = _op->context;
    }
} while(0)

Globus_XIO_Driver_Finished_Open(context, open_op, res)
do 
{
    globus_result_t                                 _res;
    globus_i_xio_context_t *                        _context;
    globus_i_xio_operation_t *                      _op;
    globus_i_xio_op_entry_t *                       _entry;
    globus_reltime_t                                delay_time;

    /* set local pointers for all macro parameters */
    _op = (open_op);
    _context = (context);
    _res = (res);

    assert(_op->ndx > 0);

    _op->progress = GLOBUS_TRUE;
    /* 
     * this means that we are finishing with a different context 
     * copy the finishing one into the operations;
     */
    if(_op->context != _context && _context != NULL)
    {
        /* iterate through them all and copy handles into new slot */
        for(ctr = _op->ndx; ctr < _op->stack_size; ctr++)
        {
            _op->context[ctr].driver_handle = _control[ctr].driver_handle;
        }
    }
    /*
     * if limited we will do nothing here 
     */
    if(!_op->context[_op->ndx]->is_limited)
    {
        /* find next interested driver */
        _op->ndx--; 
        while(_op->entry_array[_op->ndx].cb == NULL && _op->ndx != 0)
        {
            _op->ndx--; 
        }
        _entry = &_op->entry_array[_op->ndx];
        /* if one is found call it, otherwise no callback is called */
        if(_entry->cb)
        {
            /* if we are at the top */
            if(op->ndx == 0)
            {
                /* set handle state to OPENED */
                globus_mutex_lock(&op->xio_handle->mutex);
                {
                    if(_res != GLOBUS_SUCCESS)
                    {
                        op->xio_handle->GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED;
                    }
                    else
                    {
                        op->xio_handle->GLOBUS_XIO_HANDLE_STATE_OPEN;
                    }
                }
                globus_mutex_unlock(&op->xio_handle->mutex);
                /* 
                 *  when at the top don't worry about the cancel
                 *  just act as though we missed it
                 */
                /*
                 *  if in a space or within the register call stack
                 *  we must register a one shot
                 */
                if(op->space != GLOBUS_CALLBACK_GLOBAL_SPACE || 
                   entry->in_register)
                {
                    /* register a oneshot callback */
                    GlobusTimeReltimeSet(delay_time, 0, 0);
                    op->cached_res = _res;
                    globus_callback_space_register_oneshot(
                        NULL,
                        delay_time,
                        globus_l_xio_open_user_kickout,
                        (void *)op,
                        op->space);
                } 
                /* in all other cases we can just call callback */
                else
                {
                    _op->cb(_op->xio_handle, _res, _op->user_arg);

                    globus_mutex_lock(&_op->cancel_mutex);
                    {
                        globus_l_xio_op_dec(_op);
                    }
                    globus_mutex_unlock(&_op->cancel_mutex);
                }
            }
            else
            {
                /* if we have been canceled set error appropriately */
                if(_op->canceled)
                {
                    _res = CANCELLED_ERROR;
                }
                /* move to the one we are about to call */
                _op->ndx--; 
                /* if in register thread then kick out a 1 shot */
                if(entry->in_register = GLOBUS_FALSE)
                {
                    GlobusTimeReltimeSet(delay_time, 0, 0);
                    _op->cached_res = _res;
                    globus_callback_space_register_oneshot(
                        NULL,
                        delay_time,
                        globus_l_xio_open_user_kickout,
                        (void *)_op,
                        GLOBUS_CALLBACK_GLOBAL_SPACE);
                }
                /* if not in a register just call it */
                else
                {
                    _entry->cb(_op, _res, _entry->user_arg);
                }
            }
        }
    }
} while (0)

/********************************************************************
 *                      Internal functions 
 *******************************************************************/
/*
 *   called by the callback code.
 *   registerd by finished op when the final (user) callback
 *   is in a callback space, or if it is under the registraton
 *   call within the same callstack
 */
void
globus_l_xio_open_user_kickout(
    void *                                      user_arg)
{
    globus_i_xio_operation_t *                  op;

    op = (globus_i_xio_operation_t *) user_arg;

    /* if going out to user space */
    op->cb(op->xio_handle, op->cached_res, op->user_arg);

    /* clean up the op */
    globus_mutex_lock(&_op->cancel_mutex);
    {
        globus_l_xio_op_dec(_op);
    }
    globus_mutex_unlock(&_op->cancel_mutex);
}

/*
 *   this function is called by the callback code.
 *
 *   it is registered as a oneshot to get out of the callstack
 *   when operation is finished (finish_op is called) from within 
 *   the same callstack in which it was registered
 */
void
globus_l_xio_open_driver_kickout(
    void *                                      user_arg)
{
    globus_i_xio_operation_t *                  op;

    op = (globus_i_xio_operation_t *) user_arg;
    op->entry_array[op->ndx].cb(op, op->cached_res, 
        op->entry_array[op->ndx].user_arg);
}

/*
 *
 */
void
globus_l_xio_cancel_callback(
    void *                                      user_arg)
{
    globus_i_xio_operation_t *                  op;
    globus_result_t                             res;

    op = (globus_i_xio_operation_t *) user_arg;

    /* lock down the op */
    globus_mutex_lock(&op->cancel_mutex);
    {
        /* 
         *  if op is waiting for a callback destroy it 
         *  this hsould only happen if callback unregister failed
         */
        if(op->ref == 1)
        {
            globus_l_xio_op_dec(op);
        }
        /* if progress has not been made reregister the callback */
        else if(!op->progress)
        {
            /* if anyone is interested in async notification */
            if(op->cancel_callback != NULL)
            {
                /* 
                 *  callback is called LOCKED, this means there are rules
                 *  for what can be done inside the callback.
                 */
                if(cancel_callback())
                {
                    res = globus_callback_unregister(
                            op->cancel_callback_handle,
                            NULL,
                            NULL,
                            NULL);
                    /* since we are in the callback this should always work */
                    assert(res == GLOBUS_SUCCESS);
                }
            }
            else
            {
                op->canceled = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&op->cancel_mutex);
    }
}

/*
 *  this should be called with the operation cancel mutex locked 
 */
void
globus_l_xio_op_dec(
    globus_i_xio_operation_t *          op)
{
    globus_i_xio_handle_t *                     xio_handle;

    op->ref--;
    if(op->ref == 0)
    {
        xio_handle = op->xio_handle;

        globus_mutex_lock(xio_handle->mutex);
        {
            xio_handle->ref--;
            /* possibly need a signal here */
        }
        globus_mutex_unlock(xio_handle->mutex);

        /* clean up the resources */
        globus_memory_push(&xio_handle->op_memory, op);
    }
}


/********************************************************************
 *                      API functions 
 *******************************************************************/
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


/*
 *  open
 */
globus_result_t
globus_xio_register_open(
    globus_xio_handle_t *                       handle,
    globus_xio_attr_t                           attr,
    globus_xio_target_t                         target,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
    globus_i_xio_handle_t *                     l_handle;
    globus_i_xio_target_t *                     l_target;
    globus_i_xio_operation_t *                  l_op;
    globus_i_xio_context_t *                    l_context;
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

    /* this is gaurenteed to be greater than zero */
    assert(l_target->stack_size > 0);

    /* allocate and initialize context */
    l_context = (globus_i_xio_context_t *)
        globus_malloc(sizeof(globus_i_xio_context_t) +
            (sizeof(globus_i_xio_context_entry_t) * l_target->stack_size - 1));
    l_context->size = l_target->stack_size;
    /* context reference count is 1 for the user handle */
    l_context->ref = 1;

    for(ctr = 0; ctr < l_context->size; ctr++)
    {
        l_context->entry_array[ctr].driver = GET DRIVER
        l_context->entry_array[ctr].target = GET DRIVER TARGET
        l_context->entry_array[ctr].driver_handle = NULL;
        l_context->entry_array[ctr].driver_attr GET ATTR
        l_context->entry_array[ctr].is_limited = GLOBUS_FALSE;
    }

    /* allocate and intialize the handle structure */
    l_handle = (struct globus_i_xio_handle_s *) globus_malloc(
                    sizeof(struct globus_i_xio_handle_s));
    if(l_handle == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }
    globus_mutex_init(&l_handle->mutex, NULL);
    /* 
     *  initialize memory for the operation structure 
     *  The operation is a stretchy array.  The size of the operation
     *  structure plus the size of the entry array
     */
    globus_memory_init(
        &l_handle->op_memory, 
        sizeof(globus_i_xio_operation_t) +
            (sizeof(globus_i_xio_op_entry_s) * l_target->stack_size - 1),
        GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT);
    l_handle->stack_size = l_target->stack_size;
    l_handle->context = l_context; /* ref set to 1 for this assignment */

    /* create operation for the open */
    op = (globus_i_xio_operation_t * )
            globus_memory_pop_node(l_handle->op_memory);
    op->op_type = GLOBUS_XIO_OPERATION_TYPE_OPEN;
    op->xio_handle = l_handle;
    op->cb = cb;
    op->cached_res = GLOBUS_SUCCESS;
    op->stack_size = l_context->stack_size;
    op->context = l_context;
    op->ndx = 0;
    op->space = Globus_XIO_Attr_Get_Space(attr);
    op->entry_array[0].user_arg = user_arg;
    op->entry_array[0].in_register = GLOBUS_TRUE;

    Globus_XIO_Driver_Pass_Open(res, tmp_context, op, cb, user_arg);

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:
    if(l_handle != NULL)
    {
        globus_free(l_handle);
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
