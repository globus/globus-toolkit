#include "globus_i_xio.h"

/*
 *  note:
 *
 *  both globus_xio_driver_server_t and globus_xio_driver_accept_request_t
 *  are internally cast to the same object.  The typex def difference is
 *  there to force an api.  This will help to force the driver to finish
 *  only when the callback returns.
 *
 *  Cancel Process
 *  --------------
 *  The only acception to when the can finish before a cancel occurs is 
 *  when a cnacel happens.  In the case the driver should stop what it is
 *  doing and finish with a canceled error.  All drivers above it will get
 *  this error and should finish in the same manner, by cleaning up resources
 *  involved with this accpet and the calling finish with the cancel error.
 *  Once the error reaches the top xio will find all drivers were not notified
 *  of the cancel and ask them to destroy their targets.
 */
#define GlobusXIODriverPassServerAccept(res, server, cb, user_arg)          \
do                                                                          \
{                                                                           \
    globus_i_xio_server_t *                         _server;                \
    globus_i_xio_server_entry_t *                   _entry;                 \
    int                                             _my_ndx;                \
                                                                            \
    _server = (globus_i_xio_server_t *)(server);                            \
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
    _server = (globus_i_xio_server_t *)(server);                            \
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

#define GlobusXIOServerEnableCancel(server, canceled, cb, user_arg)         \
do                                                                          \
{                                                                           \
    globus_i_xio_server_t *                         _server;                \
                                                                            \
    _server = (globus_i_xio_server_t *)(server);                            \
    globus_mutex_lock(&_server->mutex);                                     \
    {                                                                       \
        canceled = _server->canceled;                                       \
        if(!canceled)                                                       \
        {                                                                   \
            _server->cancel_cb = (cb);                                      \
            _server->cancel_user_arg = (user_arg);                          \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(&_server->mutex);                                   \
} while(0)

#define GlobusXIOServerDisableCancel(server)                                \
do                                                                          \
{                                                                           \
    globus_i_xio_server_t *                         _server;                \
                                                                            \
    _server = (globus_i_xio_server_t *)(server);                            \
    globus_mutex_lock(&_server->mutex);                                     \
    {                                                                       \
        _server->cancel_cb = NULL;                                          \
        _server->cancel_user_arg = NULL;                                    \
    }                                                                       \
    globus_mutex_unlock(&_server->mutex);                                   \
} while(0)

/**************************************************************************
 *                       Internal functions
 *                       ------------------
 *************************************************************************/
void
globus_l_xio_server_cancel_kickout(
    void *                                      user_arg)
{
    globus_i_xio_server_t *                     xio_server;

    xio_server = (globus_i_xio_server_t *) user_arg;
}

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
    globus_xio_driver_server_t                  server_handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_i_xio_server_t *                     xio_server;
    globus_i_xio_target_t *                     xio_target;
    globus_xio_accept_callback_t                cb;

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
            /* If an error occured we walk through all the drivers that
               created finished successfully and free tell them to 
               destroy their targets. If the driver did not initialize a
               target its target entry will be null.  It should be the case
               that only drivers lower in the stack than the one that 
               reported the error have targets but we make no check for
               this in case the driver stack did something strange */
            for(ctr = 0; xio_server->stack_size; ctr++)
            {
                /* if a target was intialized we need to destroy it */
                if(xio_server->target->entry[ctr].target != NULL)
                {
                    xio_server->target->entry[ctr].driver.target_destroy_func(
                        xio_server->target->entry[ctr].target);
                }
            }
            globus_free(xio_server->target);
            xio_server->target = NULL;
        }
        else
        {
            /* set target type to server */
            xio_server->target->type = GLOBUS_XIO_TARGET_TYPE_SERVER;
        }

        /* set back to open state before calling the callback */
        xio_server->state = GLOBUS_XIO_SERVER_STATE_OPEN;
        xio_target = xio_server->target;
        user_arg = xio_server->user-arg; /* reusing a parameter */
        xio_server->cb = cb;

        /* the reference count will keep the xio_server from disapearing once
           the lock is released */
    }
    globus_mutex_unlock(&xio_server->mutex);

    /* call the user callback */
    if(cb != NULL)
    {
        /* this callbacks gives the user its first look at the target */
        cb(xio_target, xio_server, result, user_arg);
    }

    /* once the callback is delivered set the state back to OPEN */ 
    globus_mutex_lock(&xio_server->mutex);
    {
        /* decrement the refrence count and free if 0 */
        xio_server->ref--;
        if(xio_server->ref == 0)
        {
            /* if reference count is 0 we must be in CLOSED state */
            assert(xio_server->state == GLOBUS_XIO_SERVER_STATE_CLOSED);
            globus_free(xio_server);
        }
    }
    globus_mutex_unlock(&xio_server->mutex);
}

/**************************************************************************
 *                         API functions
 *                         -------------
 *************************************************************************/

/*
 *  function wrappers for the macros.  no real reason to have these
 */
globus_result_t
globus_xio_driver_pass_accept(
    globus_xio_driver_server_t                  server_handle,
    globus_xio_driver_accept_callback_t         cb,
    void *                                      user_arg)
{
    globus_result_t                             res;

    if(server_handle == NULL)
    {
    }

    GlobusXIODriverPassServerAccept(res, server_handle, cb, user_arg);

    return res;
}

void
globus_xio_driver_finished_accept(
    globus_xio_accepted_handle_t                accepted_handle,
    void *                                      driver_target,
    globus_result_t                             result)
{
    if(accepted_handle == NULL)
    {
    }

    GlobusXIODriverFinishedAccept(accepted_handle, driver_target, result);
}

void
globus_xio_server_enable_cancel(
    globus_xio_driver_accept_request_t          accept_req,
    globus_bool_t *                             cancel_now,
    globus_xio_driver_accept_cancel_callback_t  cancel_cb,
    void *                                      user_arg)
{
    GlobusXIOServerEnableCancel(accept_req, *cancel_now, cancel_cb, user_arg);
}

void
globus_xio_server_disable_cancel(
    globus_xio_driver_accept_request_t          accept_req)
{
    GlobusXIOServerDisableCancel(accept_req);
}


/*
 *  initialize a server structure
 */
globus_result_t
globus_xio_server_init(
    globus_xio_server_t *                       server,
    globus_xio_attr_t                           server_attr,
    globus_xio_stack_t                          stack)
{
    globus_i_xio_server_t *                     xio_server;
    globus_result_t                             res;
    globus_bool_t                               done = GLOBUS_FALSE;
    int                                         ctr;
    int                                         ctr2;
    void *                                      ds_attr = NULL;

    if(server == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
    }
    if(stack == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
    }
    if(globus_list_empty(stack->driver_stack))
    {
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
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
        xio_server->ref = 1;
        xio_server->state = GLOBUS_XIO_SERVER_STATE_OPEN;
        xio_server->cancel_cb = NULL;
        xio_server->canceled = GLOBUS_FALSE;

        ctr = 0;
        for(list = stack->driver_stack;
            !globus_list_empty(list) && !done;
            list = globus_list_rest(list))
        {
            xio_server->entry[ctr].driver = (globus_i_xio_driver_t *)
                globus_list_first(list);

            /* no sense bothering if attr is NULL */
            if(server_attr != NULL)
            {
                ds_attr = globus_i_xio_attr_get_ds(
                                server_attr,
                                xio_server->entry[ctr].driver);
            }
            /* call the driver init function */
            res = xio_server->entry[ctr].driver->server_init_func(
                    &xio_server->entry[ctr].server_handle,
                    ds_attr);
            if(res != GLOBUS_SUCCESS)
            {
                /* clean up all the initialized servers */
                for(ctr2 = 0 ctr2 < ctr; ctr2++)
                {
                    xio_server->entry[ctr].driver->server_destroy_func(
                        xio_server->entry[ctr].server_handle);
                }
                done = GLOBUS_TRUE;
            }

            ctr++;
        }
    }
    globus_mutex_unlock(&stack->lock);

    return res;
}

/*
 *
 */
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
        return GlobusXIOErrorBadParameter("globus_xio_server_cntl");
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

/*
 *  register an accept
 */
globus_result_t
globus_xio_server_register_accept(
    globus_xio_server_t                         server,
    globus_xio_attr_t                           accpet_attr,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_i_xio_server_t *                     xio_server;
    globus_i_xio_target_t *                     xio_target;

    if(server == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_server_cntl");
    }
    
    xio_server = (globus_i_xio_server_t *) server;

    globus_mutex_lock(&xio_server->mutex);
    {
        if(xio_server->state != GLOBUS_XIO_SERVER_STATE_OPEN)
        {
            res = WrongStateForThis("globus_xio_server_register_accept");
        }
        else
        {
            xio_server->state = GLOBUS_XIO_SERVER_STATE_ACCEPTING;

            xio_target = (globus_i_xio_target_t *)
                            globus_malloc(sizeof(globus_i_xio_target_t) +
                                (sizeof(globus_i_xio_server_entry_t) * 
                                    (xio_server->stack_size - 1)));

            if(xio_target == NULL)
            {
                res = MallocError();
            }
            else
            {
                xio_server->ref++;
                xio_target->stack_size = xio_server->stack_size;

                /* arrange the attributes */
                ctr = 0;
                for(list = stack->driver_stack;
                    !globus_list_empty(list);
                    list = globus_list_rest(list))
                {
                    xio_server->entry[ctr].server_attr = 
                        globus_i_xio_attr_get_ds(
                            accpet_attr,
                            xio_server->entry[ctr].driver);
                    ctr++;
                }
                xio_target->type = GLOBUS_XIO_TARGET_TYPE_NONE;
                xio_server->target = xio_target;

                xio_server->ndx = 0;
                xio_server->canceled = GLOBUS_FALSE;
                xio_server->cancel_cb = NULL;

                GlobusXIODriverPassServerAccept(res, xio_server, \
                    globus_i_xio_server_accept_callback, NULL);
                if(res == GLOBUS_SUCCESS)
                {
                    /* add a reference for the outstanding callback */
                    xio_server->ref++;
                    if(xio_server->ref == 0)
                    {
                        globus_free(xio_server);
                    }
                }
            }
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    return res;
}

/*
 *  cancel the server
 */
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
        else if(xio_server->canceled)
        {
            res = AlreadyCacneled("globus_xio_server_cancel_accept");
        }
        else
        {
            xio_server->canceled = GLOBUS_TRUE;
            /* the callback is called locked.  within it the driver is
                allowed limited functionality.  by calling this locked
                can more efficiently pass the operation down the stack */
            if(xio_server->cancel_cb)
            {
                xio_server->cancel_cb(xio_server);
            }            
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    return res;
}

/*
 *  destroy the server
 */
globus_result_t
globus_xio_server_destroy(
    globus_xio_server_t                         server)
{
    globus_i_xio_server_t *                     xio_server;
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_result_t                             tmp_res;

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
            xio_server->state = GLOBUS_XIO_SERVER_STATE_CLOSED;
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

            /* dec refrence count then free.  this makes sure we don't free
               while in a user callback */
            xio_server->ref--;
            if(xio_server->ref == 0)
            {
                globus_free(xio_server);
            }
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    return res;
}
