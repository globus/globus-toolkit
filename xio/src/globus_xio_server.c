#include "globus_i_xio.h"

#define GlobusXIODriverPassServerAccept(res, target, server, cb, user_arg)  \
do                                                                          \
{                                                                           \
    globus_i_xio_server_t *                         _server;                \
    globus_i_xio_server_entry_t *                   _entry;                 \
    int                                             _my_ndx;                \
                                                                            \
    _server = (server);                                                     \
                                                                            \
    if(_server->canceled)                                                   \
    {                                                                       \
        out_res = OperationHasBeenCacneled();                               \
    }                                                                       \
    else if(_server->ndx == _server->stack_size)                            \
    {                                                                       \
        out_res = TryingToPassToFar();                                      \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _my_ndx = _server->ndx;                                             \
        _op->progress = GLOBUS_TRUE;                                        \
        _server->entry[_my_ndx].cb = cb;                                    \
        _server->entry[_my_ndx].user_arg = user_arg;                        \
        _server->entry[_my_ndx].in_register = GLOBUS_TRUE;                  \
        _server->ndx++;                                                     \
        while(_server->context[_server->ndx]->driver->server_accept_func    \
                    == NULL &&                                              \
              _server->ndx < _server->stack_size)                           \
        {                                                                   \
            _server->ndx++;                                                 \
        }                                                                   \
        _entry = _server->entry[_server->ndx];                              \
        res = _entry->driver->server_accept_func(                           \
                    _entry->server_handle,                                  \
                    _entry->server_attr,                                    \
                    server);                                                \
        _server->entry[_my_ndx].in_register = GLOBUS_FALSE;                 \
    }                                                                       \
}

#define GlobusXIODriverFinishedAccept(server, target, result)               \
do                                                                          \
{                                                                           \
    globus_i_xio_server_entry_t *                   _entry;                 \
    globus_i_xio_server_t *                         _server;                \
                                                                            \
    _server = (server);                                                     \
    globus_assert(_server->ndx > 0);                                        \
    _server>progress = GLOBUS_TRUE;                                         \
                                                                            \
    _server->target->entry[_server->ndx].target = (target);                 \
                                                                            \
    _server->ndx--;                                                         \
    while(_server->entry[_server->ndx].cb == NULL &&                        \
            _server->ndx != 0)                                              \
    {                                                                       \
        _server->ndx--;                                                     \
    }                                                                       \
                                                                            \
    if(_server->entry[_server->ndx].in_register)                            \
    {                                                                       \
        _server->cached_res = (result);                                     \
        globus_callback_space_register_oneshot(                             \
            NULL,                                                           \
            NULL,                                                           \
            globus_l_xio_serveraccept_kickout,                              \
            (void *)_server,                                                \
            GLOBUS_CALLBACK_GLOBAL_SPACE);                                  \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _server->entry[_server->ndx].cb(_server, result,                    \
            _server->entry[_server->ndx].user_arg);                         \
    }                                                                       \
} while(0)


/*
 *  driver callback kickout
 *
 *  when in a register the finish function kicks this out as a oneshot
 */
void
globus_l_xio_server_accept_kickout(
    void *                                      user_arg)
{
    globus_i_xio_server_t *                     xio_server;

    xio_server = (globus_i_xio_server_t *) user_arg;

    xio_server->entry[xio_server->ndx].cb(
        xio_server, 
        xio_server->cached_res,
        xio_server->entry[xio_server->ndx].user-arg);
}

/*
 *  internal top level accept callback
 */
void
globus_i_xio_server_accept_callback(
    globus_xio_server_t                         server,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_i_xio_server_t *                     xio_server;

    xio_server = server;

    globus_mutex_lock(&xio_server->mutex);
    {
        if(xio_server->canceled)
        {
            result = GlobusXIOServerCanceled();
        }

        /* if failed free the target.  this is ok before the callback
           because the user is not promised an intialized structure 
           until after the accept callback returns successfully */
        if(result != GLOBUS_SUCCESS)
        {
            globus_free(xio_server->target);
        }
        else
        {
            /* set target type to server */
            xio_server->target->type = GLOBUS_XIO_TARGET_TYPE_SERVER;
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    /* call the user callback */
    if(xio_server->cb != NULL)
    {
        xio_server->cb(server, result, server->user_arg);
    }

    /* once the callback is delivered set the state back to OPEN */ 
    globus_mutex_lock(&xio_server->mutex);
    {
        /* set back to the open state */
        xio_server->state = GLOBUS_XIO_SERVER_STATE_OPEN;
    }
    globus_mutex_unlock(&xio_server->mutex);
}

globus_result_t
globus_xio_server_init(
    globus_xio_server_t *                       server,
    globus_xio_attr_t                           server_attr,
    globus_xio_stack_t                          stack)
{
    globus_i_xio_server_t *                     xio_server;
    globus_result_t                             res;
    int                                         ctr;
    void *                                      server_attr;

    if(server == NULL)
    {
    }
    if(stack == NULL)
    {
    }
    if(globus_list_empty(stack->driver_stack))
    {
    }

    /* take what the user stack has at the time of registration */
    globus_mutex_lock(&stack->mutex);
    {
        stack_size = globus_list_size(stack->driver_stack);
        xio_server = (globus_i_xio_server_t *)
                    globus_malloc(sizeof(globus_i_xio_server_t) +
                            (sizeof(globus_i_xio_server_entry_t) *
                                    stack_size - 1));
        xio_server->stack_size = globus_list_size(stack->driver_stack);

        ctr = 0;
        for(list = stack->driver_stack;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            xio_server->entry[ctr].driver = (globus_i_xio_driver_t *)
                globus_list_first(list);

            server_attr = globus_i_xio_attr_get_ds(
                            server_attr,
                            xio_server->entry[ctr].driver);

            /* call the driver init function */
            res = xio_server->entry[ctr].driver->server_init_func(
                    &xio_server->entry[ctr].server_handle,
                    server_attr);

            ctr++;
        }
        xio_server->state = GLOBUS_XIO_SERVER_STATE_OPEN;
    }
    globus_mutex_unlock(&stack->lock);

}

globus_result_t
globus_xio_server_cntl(
    globus_xio_server_t                         server,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    globus_bool_t                               found = GLOBUS_FALSE;
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;
    va_list                                     ap;

    if(server == NULL)
    {
        return GlobusXIOErrorBadParameter();
    }

    xio_server = server;

    globus_mutex_lock(&stack->mutex);
    {
        if(driver == NULL)
        {
            /* do general things */
        }
        else
        {
            for(ctr = 0; 
                !found && ctr < server->stack_size; 
                ctr++)
            {
                if(server->entry[ctr].driver == driver)
                {
                    found = GLOBUS_TRUE;

                    va_start(ap, cmd);
                    res = server->entry[ctr].driver->server_cntl_func(
                            server->entry[ctr].server_handle,
                            cmd,
                            ap);
                    va_end(ap);
                }
            }
            if(!found)
            {
                res = DriverNotFOund();
            }
        }
    }
    globus_mutex_unlock(&stack->lock);

    return res;
}

globus_result_t
globus_xio_server_register_accept(
    globus_xio_target_t *                       out_target,
    globus_xio_attr_t                           target_attr,
    globus_xio_server_t                         server,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_i_xio_server_t *                     xio_server;
    globus_i_xio_target_t *                     l_target;

    xio_server = (globus_i_xio_server_t *) server;

    globus_mutex_lock(&xio_server->mutex);
    {
        if(xio_server->state != GLOBUS_XIO_SERVER_STATE_OPEN)
        {
            res = WrongStateForThis("globus_xio_server_register_accept");
        }
        else
        {
            io_server->state = GLOBUS_XIO_SERVER_STATE_ACCEPTING;

            l_target = (globus_i_xio_target_t *)
                            globus_malloc(sizeof(globus_i_xio_target_t) +
                                (sizeof(globus_i_xio_server_entry_t) * 
                                    (xio_server->stack_size - 1)));

            if(l_target == NULL)
            {
                res = MallocError();
            }
            else
            {
                l_target->stack_size = xio_server->stack_size;

                ctr = 0;
                for(list = stack->driver_stack;
                    !globus_list_empty(list);
                    list = globus_list_rest(list))
                {
                    xio_server->entry[ctr].server_attr = 
                        globus_i_xio_attr_get_ds(
                            xio_server->entry[ctr].driver);
                    ctr++;
                }
                l_target->type = GLOBUS_XIO_TARGET_TYPE_NONE;
                xio_server->target = l_target;

                xio_server->ndx = 0;
                xio_server->canceled = GLOBUS_FALSE;

                GlobusXIOServerRegisterAccept(res, xio_server, \
                    globus_i_xio_server_accept_callback, NULL);
            }
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    return res;
}

globus_result_t
globus_xio_server_cancel_accept(
    globus_xio_server_t                         server)
{
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_i_xio_server_t *                     xio_server;

    xio_server = (globus_i_xio_server_t *) server;

    globus_mutex_lock(&xio_server->mutex);
    {
        if(xio_server->state != GLOBUS_XIO_SERVER_STATE_ACCEPTING)
        {
            res = ThereIsNothingToCancel("globus_xio_server_cancel_accept");
        }
        else
        {
            xio_server->canceled = GLOBUS_TRUE;
            if(xio_server->cancel_cb)
            {
                xio_server->cancel_cb(xio_server);
            }            
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    return res;
}

globus_result_t
globus_xio_server_destroy(
    globus_xio_server_t                         server)
{
    globus_i_xio_server_t *                     xio_server;
    globus_result_t                             res = GLOBUS_SUCCESS;

    if(server == NULL)
    {
        return BadParameter();
    }

    xio_server = (globus_i_xio_server_t *) server;

    globus_mutex_lock(&xio_server->mutex);
    {
        if(xio_server->state == GLOBUS_XIO_SERVER_STATE_ACCEPTING)
        {
            res = NotInCorrectStateError();
        }
        else
        {
            for(ctr = 0; ctr < xio_server->stack_size; ctr++)
            {
                /* possible to lose a driver res, but you know.. so what? */
                tmp_res = xio_server->entry[ctr].driver(
                        xio_server->entry[ctr].server_handle);
                if(tmp_res != GLOBUS_SUCCESS)
                {
                    res = ADriverFailedToCompletelyDestroy();
                }
            }
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    return res;
}
