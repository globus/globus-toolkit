#include "globus_i_xio.h"

/*
 *  note:
 *
 *  both globus_xio_driver_server_t and globus_xio_driver_accept_request_t
 *  are internally cast to the same object.  The typedef difference is
 *  there to force an api.  This will help to force the driver to finish
 *  only when the callback returns.
 *
 *  Cancel Process
 *  --------------
 *  The only exception to when the accept can finish before the callback occurs
 *  is when a cancel happens.  In the case the driver should stop what it is
 *  doing and finish with a canceled error.  All drivers above it will get
 *  this error and should finish in the same manner, by cleaning up resources
 *  involved with this accpet and the calling finish with the cancel error.
 *  Once the error reaches the top xio will find all drivers were not notified
 *  of the cancel and ask them to destroy their targets.
 *
 *  Errors
 *  ------
 *  There are two times when an error can happens.  The first is in the 
 *  callback.  The process for dealing with this is exctly as a canceled
 *  accept...  The top callback comes back with an error and all successfully
 *  created driver targets are destroyed.
 *
 *  The second case is if the Pass fails.  Once a driver calls pass it must
 *  only return the error code that pass returns.  If that error code is 
 *  GLOBUS_SUCESS then the driver should expect a callback, if it is not 
 *  the driver will not receive the callback for which it registered.  This
 *  rule allows the framework to know that if it receives an error from
 *  pass at the top level that no driver has an outstanding callback.
 *  
 */
#define GlobusXIODriverPassServerAccept(res, server, cb, user_arg)          \
do                                                                          \
{                                                                           \
    globus_i_xio_server_t *                         _server;                \
    globus_i_xio_server_entry_t *                   _next_entry;            \
    globus_i_xio_server_entry_t *                   _my_entry;              \
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
        _server->xio_target->progress = GLOBUS_TRUE;                        \
        _my_entry = &_server->entry[_server->ndx];                          \
        _my_entry->cb = (cb);                                               \
        _my_entry->user_arg = (user_arg);                                   \
        _my_entry->in_register = GLOBUS_TRUE;                               \
        do                                                                  \
        {                                                                   \
            _server->ndx++;                                                 \
            _next_entry = &_server->entry[_server->ndx];                    \
        }                                                                   \
        while(_next_entry->driver->server_accept_func == NULL)              \
                                                                            \
        /* at time that stack is built this will be varified */             \
        globus_assert(_server->ndx <= _server->stack_size);                 \
        res = _next_entry->driver->server_accept_func(                      \
                    _next_entry->server_handle,                             \
                    _next_entry->server_attr,                               \
                    server);                                                \
        _my_entry->in_register = GLOBUS_FALSE;                              \
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
    _server->target->progress = GLOBUS_TRUE;                                \
                                                                            \
    _server->target->entry[_server->ndx].target = (target);                 \
                                                                            \
    do                                                                      \
    {                                                                       \
        _server->ndx--;                                                     \
    }                                                                       \
    while(_server->entry[_server->ndx].cb == NULL &&                        \
            _server->ndx != 0)                                              \
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
/*
 *  driver callback kickout
 *
 *  when in a register the finish function kicks this out as a oneshot
 */
void
globus_l_xio_server_driver_accept_kickout(
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
 *  this is the only mechanism for delivering a callback to the user 
 */
void
globus_l_xio_server_accept_kickout(
    globus_i_xio_target_t *                     xio_target)
{
    /* call the users callback */

    xio_target->accept_cb(
        xio_target,
        xio_target->xio_server,
        xio_target->cached_res,
        xio_target->accept_arg);
 
    /* lock up and do some clean up */
 
    globus_mutex_lock(&xio_server->mutex);
    {
        assert(xio_server->state == GLOBUS_XIO_SERVER_STATE_ACCEPTING);
        assert(xio_target->state == GLOBUS_XIO_TARGET_STATE_SERVER ||
                xio_target->state == GLOBUS_XIO_TARGET_STATE_CLOSED);

        /* decrement reference for the callback */
        xio_target->ref--;
        /* definitly should have referene to itself remaining */
        globus_assert(xio_target->ref > 0);

        /* if the operation failed we move target to closed state */
        if(xio_target->cached_res != GLOBUS_SUCCESS)
        {
            /* insit if error we are in the closed state */
            globus_assert(xio_target->state == GLOBUS_XIO_TARGET_STATE_CLOSED);
            /* If an error occured we walk through all the drivers that
               created finished successfully and free tell them to 
               destroy their targets. If the driver did not initialize a
               target its target entry will be null.  It should be the case
               that only drivers lower in the stack than the one that 
               reported the error have targets but we make no check for
               this in case the driver stack did something strange */
            for(ctr = 0; xio_target->stack_size; ctr++)
            {
                /* if a target was intialized we need to destroy it */
                if(xio_server->target->entry[ctr].target != NULL)
                {
                    xio_server->target->entry[ctr].driver.target_destroy_func(
                        xio_server->target->entry[ctr].target);
                }
            }

            xio_target->ref--;
            if(xio_target->ref == 0)
            {
                xio_server->ref--;
                globus_free(xio_target);
                if(xio_server->ref == 0)
                {
                    assert(xio_server->state == GLOBUS_XIO_SERVER_STATE_CLOSED);
                    globus_free(xio_server);
                }
            }
            xio_server->target = NULL;
        }
    }
    globus_mutex_unlock(&xio_server->mutex);
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
    globus_bool_t                               accept = GLOBUS_TRUE;

    xio_server = server;
    xio_target = xio_server->target;

    globus_mutex_lock(&xio_server->mutex);
    {
        /* if in this state it means that the user either has or is about to
           get a cancel callback.  we must delay the delivery of this
           callback until that returns */
        xio_target->cached_res = result;
        if(xio_target->state == GLOBUS_XIO_TARGET_STATE_TIMEOUT_PENDING)
        {
            accept = GLOBUS_FALSE;
            xio_target->state = GLOBUS_XIO_TARGET_STATE_ACCEPT_WAITING;
        }
        else
        {
            /* if there is an outstanding accept callback */
            if(xio_target->accept_timeout != NULL)
            {
                if(globus_i_xio_timer_unregister_timeout(xio_target))
                {
                    xio_target->ref--;
                    globus_assert(xio_target->ref > 0);
                }
            }

            if(xio_target->canceled)
            {
                xio_target->cached_res = GlobusXIOServerCanceled();
            }

            if(xio_target->cached_res == GLOBUS_SUCCESS)
            {
                xio_target->state = GLOBUS_XIO_TARGET_STATE_ACCEPT_SERVER;
            }
            else
            {
                xio_target->state = GLOBUS_XIO_TARGET_STATE_ACCEPT_CLOSED;
            }
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    /* we may be delaying the callback until cancel returns */
    if(accept)
    {
        globus_l_xio_server_accept_kickout(xio_target);
    }
}

globus_bool_t
globus_l_xio_accept_timeout_callback(
    void *                                      user_arg)
{
    globus_i_xio_target_t *                     xio_target;
    globus_i_xio_server_t *                     xio_server;
    globus_bool_t                               rc;
    globus_bool_t                               accept;
    globus_bool_t                               timeout;

    xio_target = (globus_i_xio_target_t *) user_arg;
    xio_server = xio_target->xio_server;

    globus_mutex_lock(&xio_server->mutex);
    {
        switch(xio_target->state)
        {
            /* this case only happens when we have a timeout registered on the
            target taht we were unable to cancel and the AcceptPass failed */
            case GLOBUS_XIO_TARGET_STATE_CLOSED:

                /* insist that only 1 ref is left for this target, don't 
                   bother decrementing, just destroy it */
                assert(xio_target->ref == 1);
                globus_free(xio_target);
                /* remove the reference for the target on the server */
                xio_server->ref--;
                if(xio_server->ref == 0)
                {
                    /* if reference count is 0 we must be in CLOSED state */
                    assert(xio_server->state == GLOBUS_XIO_SERVER_STATE_CLOSED);
                    globus_free(xio_server);
                }

                /* remove it from the timeout list */
                rc = GLOBUS_TRUE;
                break;

            /* this case happens when the server was succefully created but
                we were unable to cancel the timeout callback */
            case GLOBUS_XIO_TARGET_STATE_SERVER:

                /* decerement the reference for the timeout callback */
                xio_target->ref--;

                /* target should never hit zero in this state */
                globus_assert(xio_target->ref > 0);
                /* remove it from the timeout list */
                rc = GLOBUS_TRUE;
                break;

            /* this case happens when we actually want to cancel the operation
                The timeout code should insure that prograess is false if this
                gets called in this state */
            case GLOBUS_XIO_TARGET_STATE_ACCEPTING:
                /* it is up to the timeout callback to set this to true */
                rc = GLOBUS_FALSE;
                /* cancel the sucker */
                assert(!xio_target->progress);
                assert(xio_server->accept_timeout != NULL);

                /* set cancel flag for later unlocked work */
                timeout_cb = xio_server->accept_timeout;
                user_arg = xio_server->timeout_arg;
                /* we don't need to cache the server object in local stack
                   because state insures that it will not go away */

                /* put in canceling state to delay the accept callback */
                xio_target->state = GLOBUS_XIO_TARGET_TYPE_TIMEOUT_PENDING;
                break;

            /* no reason we should get to this state */
            case GLOBUS_XIO_TARGET_STATE_CLIENT:
            default:
                globus_assert(0);
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    /* if in cancel state, verfiy with user that they want to cancel */
    if(timeout)
    {
        cancel = timeout_cb(xio_server, user_arg);
    }
    /* all non time out casses can just return */
    else
    {
        return rc;
    }

    globus_mutex_lock(&xio_server->mutex);
    {
        /* if canceling set the res and we will remove this timer event */
        if(cancel)
        {
            xio_target->cached_res = GlouxXIOErrorCanceled();
            rc = GLOBUS_TRUE;
            xio_target->canceled = GLOBUS_TRUE;
            if(xio_target->cancel_cb)
            {
                xio_server->xio_target->cancel_cb(xio_server);
            }            
        }

        /* if an accept callback has already arriverd set flag to later
            call accept callback and set rc to remove timed event */
        if(xio_target->state == GLOBUS_XIO_TARGET_STATE_ACCEPT_WAITING)
        {
            accept = GLOBUS_TRUE;
            rc = GLOBUS_TRUE;

            /* set the rext state based on the result code */
            if(xio_target->cached_res == GLOBUS_SUCCESS)
            {
                xio_target->state = GLOBUS_XIO_TARGET_STATE_SERVER;
            }
            else
            {
                xio_target->state = GLOBUS_XIO_TARGET_STATE_CLOSED;
            }
        }
        /* if no accept is waiting, set state back to accepting */
        else
        {
            xio_target->state = GLOBUS_XIO_TARGET_STATE_ACCEPTING;
        }

        /* if we are remvoing the timed event */
        if(rc)
        {
            /* decremenet the target reference count and insist that it is
               not zero yet */
            xio_target->ref--;
            globus_assert(xio_target->ref > 0);
        }
    }
    globus_mutex_unlock(&xio_server->mutex);

    /* if the accpet was pending we must call it */
    if(accept)
    {
        globus_l_xio_server_accept_kickout(xio_target);
    }

    return rc;
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
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
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
        return GlobusXIOErrorBadParameter("globus_xio_server_init");
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

        /* timeout handling */
        xio_server->accept_timeout = server_attr->accept_timeout;

        /* walk through the stack and add each entry to the array */
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
    globus_xio_attr_t                           accept_attr,
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
                xio_target->state = GLOBUS_XIO_TARGET_STATE_ACCEPTING;
                xio_target->stack_size = xio_server->stack_size;
                xio_target->xio_server = xio_server;
                xio_target->ref = 1;
                xio_target->cancel_cb = NULL;
                xio_target->canceled = GLOBUS_FALSE;
                xio_target->progess = GLOBUS_TRUE;
                xio_target->ndx = 0;

                /* get all the driver specific attrs and put htem in the 
                    correct place */
                for(ctr = 0; ctr < xio_target->stack_size; ctr++)
                {
                    xio_target->entry[ctr].accept_attr = 
                        globus_i_xio_attr_get_ds(
                            accept_attr,
                            xio_server->entry[ctr].driver);
                }

                /*i deal with timeout if there is one */
                if(xio_server->accept_timeout != NULL)
                {
                    xio_target->ref++;
                    globus_i_xio_timer_register_timeout(
                        g_globus_l_xio_timeout_timer,
                        xio_target,
                        &xio_target->progess,
                        globus_l_xio_accept_timeout_callback,
                        &l_handle->open_timeout_period);
                }

                /* add a reference to the server for this target */
                xio_server->ref++;
                /* no sense unlocking here since accepts are serialized 
                    anyway */
                GlobusXIODriverPassServerAccept(res, xio_target, \
                    globus_i_xio_server_accept_callback, NULL);

                /* if the register failed */
                if(res != GLOBUS_SUCCESS)
                {
                    /* set target to invalid type */
                    xio_target->state = GLOBUS_XIO_TARGET_TYPE_CLOSED;

                    /* if a timeout was registered we must unregister it */
                    if(xio_server->accept_timeout != NULL)
                    {
                        if(globus_i_xio_timer_unregister_timeout(xio_target))
                        {
                            xio_target->ref--;
                            globus_assert(xio_target->ref > 0);
                        }
                    }
                    xio_target->ref--;
                    if(xio_target == 0)
                    {
                        xio_server->ref--;  /* remove the targets reference */
                        globus_free(xio_target);
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
            /* the callback is called locked.  within it the driver is
                allowed limited functionality.  by calling this locked
                can more efficiently pass the operation down the stack */
            xio_server->xio_target->canceled = GLOBUS_TRUE;
            if(xio_server->xio_target->cancel_cb)
            {
                xio_server->xio_target->cancel_cb(xio_server);
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
