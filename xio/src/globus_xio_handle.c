#define GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT   2
/********************************************************************
 *                      MACROS
 *******************************************************************/

#define Globus_I_XIO_Handle_Destroy(h)                              \
{                                                                   \
    globus_i_xio_handle_t *                         _h;             \
                                                                    \
    _h = (h);                                                       \
    assert(_h->ref == 0);                                           \
    globus_mutex_destroy(_h->mutex);                                \
    globus_memory_destroy(_h->op_memory);                           \
    /* TODO what about context array */                             \
                                                                    \
    globus_free(_h);                                                \
    h = NULL;                                                       \
}

#define Globus_I_XIO_Handle_Create(h, t, c)                         \
{                                                                   \
    globus_i_xio_target_t *                         _t;             \
    globus_i_xio_handle_t *                         _h;             \
    globus_i_xio_context_t *                        _c;             \
                                                                    \
    _t = (t);                                                       \
    _c = (c);                                                       \
                                                                    \
    /* allocate and intialize the handle structure */               \
    _h = (struct globus_i_xio_handle_s *) globus_malloc(            \
                    sizeof(struct globus_i_xio_handle_s));          \
    if(_h != NULL)                                                  \
    {                                                               \
        globus_mutex_init(&_h->mutex, NULL);                        \
        /*                                                          \
         *  initialize memory for the operation structure           \
         *  The operation is a stretchy array.  The size of the     \
         *  operation structure plus the size of the entry array    \
         */                                                         \
        globus_memory_init(                                         \
            &_h->op_memory,                                         \
            sizeof(globus_i_xio_operation_t) +                      \
                (sizeof(globus_i_xio_op_entry_s) *                  \
                    _t->stack_size - 1),                            \
        GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT);                 \
        _h->stack_size = _t->stack_size;                            \
        /* context should up ref count for this assignment */       \
        _h->context = _c;                                           \
        _h->ref = 1; /* set count for its own reference */          \
    }                                                               \
    h = _h;                                                         \
}

#define Globus_I_XIO_Context_Create(c, t, a)                        \
{                                                                   \
    globus_i_xio_context_t *                        _c;             \
    globus_i_xio_target_t *                         _t;             \
    globus_i_xio_attr_t *                           _a;             \
                                                                    \
    _t = (t);                                                       \
    _a = (a);                                                       \
                                                                    \
    /* allocate and initialize context */                           \
    _c = (globus_i_xio_context_t *)                                 \
        globus_malloc(sizeof(globus_i_xio_context_t) +              \
            (sizeof(globus_i_xio_context_entry_t)                   \
                * _t->stack_size - 1));                             \
    _c->size = _t->stack_size;                                      \
    globus_mutex_init(&_c->mutex, NULL);                            \
    /* set reference count to 1 for this structure */               \
    _c->ref = 1;                                                    \
                                                                    \
    for(ctr = 0; ctr < _c->size; ctr++)                             \
    {                                                               \
        _c->entry_array[ctr].driver = _t->target_stack[ctr].driver; \
        _c->entry_array[ctr].target = t->target_stack[ctr].target;  \
        _c->entry_array[ctr].driver_handle = NULL;                  \
        _c->entry_array[ctr].driver_attr =                          \
            globus_l_xio_attr_find_driver(_a,                       \
                t->target_stack[ctr].driver);                       \
        _c->entry_array[ctr].is_limited = GLOBUS_FALSE;             \
    }                                                               \
}

#define Globus_I_XIO_Context_Destroy(c)                             \
{                                                                   \
    _c = (c);                                                       \
    globus_free(_c);                                                \
}

#define Globus_I_XIO_Operation_Create(op, type, h)                  \
do                                                                  \
{                                                                   \
    globus_i_xio_operation_t *                      _op;            \
    globus_i_xio_handle_t *                         _h;             \
                                                                    \
    _h = (h);                                                       \
    globus_mutex_lock(_h->mutex);                                   \
    /* create operation for the open */                             \
    _op = (globus_i_xio_operation_t * )                             \
            globus_memory_pop_node(&_h->op_memory);                 \
    _op->op_type = type;                                            \
    _op->xio_handle = _h;                                           \
    _op->timeout_cb = NULL;                                         \
    _op->op_list = NULL;                                            \
    _op->cached_res = GLOBUS_SUCCESS;                               \
    _op->stack_size = _h->stack_size;                               \
    _op->context = _h->context;                                     \
    _op->ndx = 0;                                                   \
    _op->ref = 0;                                                   \
    _op->space = GLOBUS_CALLBACK_GLOBAL_SPACE;                      \
    globus_mutex_unlock(_h->mutex);                                 \
} while(0)

#define Globus_I_XIO_Operation_Destroy(op)                          \
do                                                                  \
{                                                                   \
    globus_i_xio_operation_t *                      _op;            \
                                                                    \
    _op = (op);                                                     \
    assert(_op->ref == 0);                                          \
    globus_mutex_lock(_op->xio_handle->mutex);                      \
    globus_memory_push_node(&_op->xio_handle->op_memory, _op);      \
    globus_mutex_unlock(_op->xio_handle->mutex);                    \
} while(0)


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

    /* if an error occurs it is up to level above to clean up */
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
    if(!_op->entry_array[_op->ndx]->is_limited)
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
            /* if we have been canceled set error appropriately */
            if(_op->canceled)
            {
                _res = CANCELLED_ERROR;
            }
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
} while (0)

/********************************************************************
 *                      Internal functions 
 *******************************************************************/

/*
 *  this could be built into the finished macro
 */
void
globus_i_xio_top_open_callback(
    globus_xio_operation_t                      op,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_i_xio_handle_t *                     xio_handle;

    xio_handle = op->xio_handle;
    /* set handle state to OPENED */
    globus_mutex_lock(&op->xio_handle->mutex);
    {
        if(res != GLOBUS_SUCCESS)
        {
            /* clean up the resources */
            op->xio_handle->GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED;
        }
        else
        {
            op->xio_handle->GLOBUS_XIO_HANDLE_STATE_OPEN;
        }
    }
    globus_mutex_unlock(&op->xio_handle->mutex);

    globus_mutex_lock(&op->xio_handle->op_mutex);
    {
        if(op->timeout_set)
        {
            /* 
             * unregister the cancel
             */
            op->timeout_set = GLOBUS_FALSE;
            if(globus_i_xio_timer_unregister_timeout(op))
            {
                /* at this point we know timeout won't happen */
                globus_list_remove(&op->xio_handle->op_list, 
                    globus_list_search(op->xio_handle->op_list, op));
                globus_l_xio_op_dec(op);
            }
        }
    }
    globus_mutex_unlock(&op->xio_handle->op_mutex);

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
        op->cached_res = res;
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
        globus_mutex_lock(&op->cancel_mutex);
        {
            globus_l_xio_op_dec(op);
        }
        globus_mutex_unlock(&op->cancel_mutex);
        op->cb(op->xio_handle, res, op->user_arg);
    }
}



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

globus_bool_t
globus_l_xio_timeout_callback(
    void *                                      user_arg)
{
    globus_i_xio_operation_t *                  op;
    globus_bool_t                               rc = GLOBUS_FALSE;
    globus_bool_t                               tmp_rc;

    op = (globus_i_xio_operation_t *) user_arg;

    globus_mutex_lock(&op->xio_handle->op_mutex);
    {
        if(op->op_type == GLOBUS_L_XIO_OPERATION_TYPE_FINISHED)
        {
            globus_l_xio_op_dec(op);
        }
    }
    globus_mutex_unlock(&op->xio_handle->op_mutex);

    if(op->block_timeout)
    {
        return GLOBUS_FALSE;
    }
    /* destroy op */
    if(destroy_op)
    {
    }

    /* if we get here there beter be user interest */
    assert(op->user_timeout_callback != NULL);

    if(op->user_timeout_callback(
            op->xio_handle, 
            op->op_type, 
            op->user_timeout_arg))
    {
        /*  
         * lock the op for the duration of the cancel notification
         * process.  The driver notificaiotn callback os called locked
         * this insures that the driver will not receive a callback 
         * once CancelDisallow is called 
         */
        globus_mutex_lock(&op->xio_handle->op_mutex);
        {
            /* 
             * if the user oks the cancel then remove the timeout from 
             * the poller
             */
            tmp_rc = globus_i_xio_timer_unregister_timeout(op);
            /* since in callback this will always be true */
            assert(tmp_rc);

            /*
             * set cancel flag
             * if a driver has a registered callback it will be called
             * if it doesn't the next pass or finished will pick it up
             */
            op->canceled = GLOBUS_TRUE;
            if(op->cancel_callback != NULL)
            {
                op->cancel_callback(op);
                /* it is possible that the driver rejected the cancel request */
                if(!op->canceled)
                {
                    /* the driver may have aborted the cancel.  I am not
                       sure if we will need thins.  notifing the driver is
                       enough the cancel comes back when ready */
                    op->canceled = GLOBUS_TRUE;
                }
                else
                {
                    /* remove from the op list */
                }
            }
            rc = GLOBUS_FALSE;
        }
        globus_mutex_lock(&op->xio_handle->op_mutex);
    }

    return rc;
}

void
globus_l_xio_handle_dec(
    globus_i_xio_handle_t *                     xio_handle)
{
    xio_handle->ref--;
    if(xio_handle-ref == 0)
    {
        /* the reference count should only be at zero in these 2 states */
        assert(xio_handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSED ||
               xio_handle->state == GLOBUS_XIO_HANDLE_STATE_FAILED);

        /* destroy the handle */
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
        /* clean up the resources */
        globus_memory_push(&xio_handle->op_memory, op);

        globus_mutex_lock(xio_handle->mutex);
        {
            globus_l_xio_handle_dec(xio_handle)
            /* possibly need a signal here */
        }
        globus_mutex_unlock(xio_handle->mutex);
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
    globus_i_xio_handle_t *                     l_handle = NULL;
    globus_i_xio_target_t *                     l_target;
    globus_i_xio_operation_t *                  l_op;
    globus_i_xio_context_t *                    l_context = NULL;
    globus_result_t                             res = GLOBUS_SUCCESS;

    if(handle == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_register_open");
    }
    if(target == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_register_open");
    }

    *handle = NULL; /* initialze to be nice touser */
    l_target = (struct globus_i_xio_target_s *) target;

    /* this is gaurenteed to be greater than zero */
    assert(l_target->stack_size > 0);

    /* allocate and initialize context */
    Globus_I_XIO_Context_Create(l_context, l_target, attr);
    if(l_context == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }

    /* 
     *  up reference count on the context to account for the handles
     *  association with it 
     */
    l_context->ref++;
    /* allocate and intialize the handle structure */
    Globus_I_XIO_Handle_Init(l_handle, l_target, l_context);
    if(l_handle == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }

    l_handle->open_timeout = Globus_I_XIO_Attr_Open_Timeout(attr);
    GlobusTimeReltimeCopy(l_handle->open_timeout_period, attr->open_timeout_period);
    l_handle->read_timeout = Globus_I_XIO_Attr_Read_Timeout(attr);
    GlobusTimeReltimeCopy(l_handle->read_timeout_period, attr->read_timeout_period);
    l_handle->write_timeout = Globus_I_XIO_Attr_Write_Timeout(attr);
    GlobusTimeReltimeCopy(l_handle->write_timeout_period, attr->write_timeout_period);
    l_handle->close_timeout = Globus_I_XIO_Attr_Close_Timeout(attr);
    GlobusTimeReltimeCopy(l_handle->close_timeout_period, attr->close_timeout_period);

    /* create operation for the open */
    Globus_I_XIO_Operation_Create(op, GLOBUS_XIO_OPERATION_TYPE_OPEN, l_handle);
    if(l_op == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_register_open");
        goto err;
    }
    op->space = Globus_XIO_Attr_Get_Space(attr);
    op->op_type = GLOBUS_L_XIO_OPERATION_TYPE_OPEN;

    /* register timeout */
    if(l_handle->open_timeout_cb != NULL)
    {
        /* op the operatin reference count for this */
        op->ref++;
        op->timeout_cb = l_handle->open_timeout_cb;
        res = globus_i_xio_timer_register_timeout(
                g_globus_l_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &l_handle->open_timeout_period);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    Globus_XIO_Driver_Pass_Open(res, tmp_context, \
        globus_i_xio_top_open_callback, cb, user_arg);

    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    *handle = l_handle;

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:
    /* do not properly destry since this is a malloc failure */
    if(l_op != NULL)
    {
        Globus_I_XIO_Operation_Destroy(l_op);
        Globus_I_XIO_Handle_Destroy(l_handle);
        Globus_I_XIO_Context_Destroy(l_context);
    }
    if(l_context != NULL)
    {
        Globus_I_XIO_Handle_Destroy(l_handle);
        Globus_I_XIO_Context_Destroy(l_context);
    }
    if(l_handle != NULL)
    {
        Globus_I_XIO_Handle_Destroy(l_handle);
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
