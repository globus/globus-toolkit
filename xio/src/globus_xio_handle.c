#include "globus_xio.h"
#include "globus_i_xio.h"

/*
 *  read_op_list adn write_op_list
 *  ------------------------------
 *  list of operations whos callbacks have not yet *returned*.
 *  
 *  cancel walks this list and sets all operations to canceled, 
 *  calling the driver callbck if neccessary.  This goes for ops
 *  that are finsihed and currently in the users callback.  However
 *  this causes no problem because the cancled flag will not be looked
 *  at again, and the no driver will be registered for such csllbacks.
 */
/********************************************************************
 *                   data structure macros
 *******************************************************************/
#define GlobusXIOHandleCreate(h, s, a)                                      \
do                                                                          \
{                                                                           \
    globus_i_xio_handle_t *                         _h;                     \
    globus_i_xio_attr_t *                           _a;                     \
                                                                            \
    _a = (a);                                                               \
                                                                            \
    /* allocate and intialize the handle structure */                       \
    _h = (struct globus_i_xio_handle_s *) globus_malloc(                    \
                    sizeof(globus_i_xio_handle_t));                         \
    if(_h != NULL)                                                          \
    {                                                                       \
        memset(_h, '\0', sizeof(globus_i_xio_handle_t));                    \
        /*                                                                  \
         *  initialize memory for the operation structure                   \
         *  The operation is a stretchy array.  The size of the             \
         *  operation structure plus the size of the entry array            \
         */                                                                 \
        _h->stack_size = (s);                                               \
                                                                            \
        if(_a != NULL)                                                      \
        {                                                                   \
            _h->open_timeout_cb = _a->open_timeout_cb;                      \
            GlobusTimeReltimeCopy(_h->open_timeout_period,                  \
                _a->open_timeout_period);                                   \
            _h->read_timeout_cb = _a->read_timeout_cb;                      \
            GlobusTimeReltimeCopy(_h->read_timeout_period,                  \
                _a->read_timeout_period);                                   \
            _h->write_timeout_cb = _a->write_timeout_cb;                    \
            GlobusTimeReltimeCopy(_h->write_timeout_period,                 \
                _a->write_timeout_period);                                  \
            _h->close_timeout_cb = _a->close_timeout_cb;                    \
            GlobusTimeReltimeCopy(_h->close_timeout_period,                 \
                _a->close_timeout_period);                                  \
        }                                                                   \
    }                                                                       \
                                                                            \
    globus_list_insert(&globus_l_outstanding_handles_list, _h);             \
    h = _h;                                                                 \
} while(0)

/* 
 *  module activation
 */

#include "version.h"
#include "globus_i_xio.h"
#include "globus_xio.h"


globus_i_xio_timer_t                        globus_l_xio_timeout_timer;

globus_list_t *                             globus_l_outstanding_handles_list;
globus_mutex_t                              globus_l_mutex;
globus_cond_t                               globus_l_cond;

GlobusDebugDefine(GLOBUS_XIO);

static int
globus_l_xio_activate()
{
    int                                     rc;
    GlobusXIOName(globus_l_xio_activate);

    GlobusXIODebugInternalEnter();

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != 0)
    {
        return rc;
    }

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, NULL);
    globus_i_xio_timer_init(&globus_l_xio_timeout_timer);
    globus_l_outstanding_handles_list = NULL;
    
    globus_i_xio_load_init();

    GlobusDebugInit(GLOBUS_XIO,
        GLOBUS_XIO_DEBUG_INFO
        GLOBUS_XIO_DEBUG_INFO_VERBOSE
        GLOBUS_XIO_DEBUG_WARNING
        GLOBUS_XIO_DEBUG_ERROR);
    
    return GLOBUS_SUCCESS;
}


void
globus_l_xio_deactivate_close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    void *                                  user_arg)
{
}

static int
globus_l_xio_deactivate()
{
    globus_list_t *                         list;
    globus_result_t                         res;
    globus_xio_handle_t                     handle;
    GlobusXIOName(globus_l_xio_deactivate);

    GlobusXIODebugInternalEnter();
    /* is this good enough for user callback spaces and deadlock ?? */

/* NOTHING FOR NOW 
    globus_mutex_lock(&globus_l_mutex);
    {
        for(list = globus_l_outstanding_handles_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            handle = (globus_xio_handle_t) globus_list_first(list);
            res = globus_xio_register_close(
                    handle,
                    NULL,
                    globus_l_xio_deactivate_close_cb,
                    NULL);
        }
        while(!globus_list_empty(globus_l_outstanding_handles_list))
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);
*/
    globus_mutex_destroy(&globus_l_mutex);
    globus_cond_destroy(&globus_l_cond);
    globus_i_xio_timer_destroy(&globus_l_xio_timeout_timer);
    globus_i_xio_load_destroy();

    GlobusDebugDestroy(GLOBUS_XIO);
    
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

globus_module_descriptor_t                  globus_i_xio_module =
{
    "globus_xio",
    globus_l_xio_activate,
    globus_l_xio_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

void
globus_l_xio_open_close_callback_kickout(
    void *                                  user_arg);

void
globus_l_xio_read_write_callback_kickout(
    void *                                  user_arg);

/********************************************************************
 *                      Internal functions 
 *******************************************************************/

/*
 *  This is called when either an open or a close completes.
 */
void
globus_i_xio_open_close_callback(
    globus_i_xio_op_t *                     op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_i_xio_handle_t *                 handle;
    globus_bool_t                           fire_callback = GLOBUS_TRUE;
    GlobusXIOName(globus_i_xio_open_close_callback);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        /* state can be either opening or closing.*/
        switch(handle->state)
        {
            /* closed if open returned with failure but a close callback
               was still pending */
            case GLOBUS_XIO_HANDLE_STATE_CLOSED:
            case GLOBUS_XIO_HANDLE_STATE_CLOSING:
                break;

            case GLOBUS_XIO_HANDLE_STATE_OPENING:
                if(result != GLOBUS_SUCCESS)
                {
                    handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;
                }
                else
                {
                    handle->state = GLOBUS_XIO_HANDLE_STATE_OPEN;
                }
                break;

            default:
                globus_assert(0);
        }

        /* set to finished for the sake of the timeout */
        if(op->state == GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING)
        {
            fire_callback = GLOBUS_FALSE;
        }
        else
        {
            fire_callback = GLOBUS_TRUE;
            if(op->_op_handle_timeout_cb != NULL)
            {
                /* 
                 * unregister the cancel
                 */
                /* if the unregister fails we will get the callback */
                if(globus_i_xio_timer_unregister_timeout(
                    &globus_l_xio_timeout_timer, op))
                {
                    /* at this point we know timeout won't happen */
                    op->ref--;
                    /* since we have no yet deced for the callbacl this
                       cannot be zero */
                    globus_assert(op->ref > 0);
                }
            }
        }

        /* remove the operation from the list */

        op->state = GLOBUS_XIO_OP_STATE_FINISH_WAITING;
        op->cached_res = result;
        /* 
         *  when at the top don't worry about the cancel
         *  just act as though we missed it
         */
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(fire_callback)
    {
        /* we can always call in this stack since Pass macros enforce
           registration bariers and callback spaces */
        globus_l_xio_open_close_callback_kickout((void *)op);
    }

    GlobusXIODebugInternalExit();
}

/*
 *   called by the callback code.
 *   registerd by finished op when the final (user) callback
 *   is in a callback space, or if it is under the registraton
 *   call within the same callstack
 */
void
globus_l_xio_open_close_callback_kickout(
    void *                                  user_arg)
{
    int                                     ctr;
    globus_i_xio_op_t *                     op;
    globus_i_xio_target_t *                 target;
    globus_i_xio_handle_t *                 handle;
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_open_close_callback_kickout);

    GlobusXIODebugInternalEnter();

    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    /* call the users callback */
    if(op->_op_cb != NULL)
    {
        op->_op_cb(handle, op->cached_res, op->user_arg);
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        globus_assert(op->state == GLOBUS_XIO_OP_STATE_FINISH_WAITING);

        /* clean up the target */
        if(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN)
        {
            target = handle->target;
            for(ctr = 0;  ctr < target->stack_size; ctr++)
            {
                if(target->entry[ctr].target != NULL)
                {
                    /* ignore result code.  user should be more interested in
                        result from callback */
                    target->entry[ctr].driver->target_destroy_func(
                            target->entry[ctr].target);
                }
            }
            globus_free(target);
            handle->target = NULL;
        }

        /* this is likely useless, but may help in debugging */
        op->state = GLOBUS_XIO_OP_STATE_FINISHED;

        if(op->type == GLOBUS_XIO_OPERATION_TYPE_CLOSE)
        {
            handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;
        
            globus_i_xio_handle_dec(handle, &destroy_handle, &destroy_context);
            /* destroy handle cannot possibly be true yet 
                the handle stll has the operation reference */
            globus_assert(!destroy_handle);
            handle->close_op = NULL;
        }
        else if(op->type == GLOBUS_XIO_OPERATION_TYPE_OPEN)
        {
            if(op->cached_res != GLOBUS_SUCCESS)
            {
                handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;
                globus_i_xio_handle_dec(handle, &destroy_handle, 
                    &destroy_context);
                /* destroy handle cannot possibly be true yet 
                    the handle stll has the operation reference */
                globus_assert(!destroy_handle);
            }
            /* if we arealready trying to close than we have uped the
                reference count and need to dec it */
            else if(handle->close_op != NULL)
            {
                globus_i_xio_handle_dec(handle, &destroy_handle, 
                    &destroy_context);
                globus_assert(!destroy_handle);
            }
            handle->open_op = NULL;
        }

        /* decrement reference for the operation */
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, &destroy_context);
        }

    }
    globus_mutex_unlock(&handle->context->mutex);

    if(destroy_handle)
    {
        if(destroy_context)
        {
            globus_i_xio_context_destroy(handle->context);
        }
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
}

/*
 *  operation callback for readv and writev operations
 *  we don't care what the result is, just so it bubbles up to the user
 */
void
globus_i_xio_read_write_callback(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_i_xio_handle_t *                 handle;
    globus_bool_t                           fire_operation = GLOBUS_TRUE;
    GlobusXIOName(globus_i_xio_read_write_callback);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        globus_assert(handle->state == GLOBUS_XIO_HANDLE_STATE_OPEN ||
            handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSING);

        /* set to finished for the sake of the timeout */
        if(op->state == GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING)
        {
            fire_operation = GLOBUS_FALSE;
        }
        else
        {
            fire_operation = GLOBUS_TRUE;
            if(op->_op_handle_timeout_cb != NULL)
            {
                /* 
                 * unregister the cancel
                 */
                /* if the unregister fails we will get the callback */
                if(globus_i_xio_timer_unregister_timeout(
                    &globus_l_xio_timeout_timer, op))
                {
                    /* at this point we know timeout won't happen */
                    op->ref--;
                }
            }
        }
        op->state = GLOBUS_XIO_OP_STATE_FINISH_WAITING;

        if(op->type == GLOBUS_XIO_OPERATION_TYPE_WRITE)
        {
            globus_list_remove(&handle->write_op_list, 
                globus_list_search(handle->write_op_list, op));
        }
        else if(op->type == GLOBUS_XIO_OPERATION_TYPE_READ)
        {
            globus_list_remove(&handle->read_op_list, 
                globus_list_search(handle->read_op_list, op));
        }

        op->cached_res = result;
        op->_op_nbytes = nbytes;
    }   
    globus_mutex_unlock(&handle->context->mutex);

    if(fire_operation)
    {
        globus_l_xio_read_write_callback_kickout((void *)op);
    }

    GlobusXIODebugInternalExit();
}

/*
 *  called unlocked either by the callback code or in the finsihed op
 *  state.
 */
void
globus_l_xio_read_write_callback_kickout(
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op;
    globus_i_xio_handle_t *                 handle;
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_read_write_callback_kickout);

    GlobusXIODebugInternalEnter();

    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    /* call the users callback */
    if(op->_op_data_cb != NULL)
    {
        op->_op_data_cb(
            handle, 
            op->cached_res, 
            op->_op_mem_iovec.iov_base,
            op->_op_mem_iovec.iov_len,
            op->_op_nbytes,
            NULL, /* TODO: dd stuff */
            op->user_arg);
    }
    else if(op->_op_iovec_cb != NULL)
    {
        op->_op_iovec_cb(
            handle, 
            op->cached_res, 
            op->_op_iovec,
            op->_op_iovec_count,
            op->_op_nbytes,
            NULL, /* TODO: dd stuff */
            op->user_arg);
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        /*
         *  This is ok in CLOSED state because of will block stuff
         */
        globus_assert(handle->state != GLOBUS_XIO_HANDLE_STATE_OPENING);
        /* decrement reference for the operation */
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, &destroy_context);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(destroy_handle)
    {
        if(destroy_context)
        {
            globus_i_xio_context_destroy(handle->context);
        }
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExit();
}

/*
 *  this starts the cancel processes for the given operation.
 * 
 *  the cancel flag is to true.  every pass checks this flag and
 *  if cancel is true the pass fails and the above driver should
 *  do what it needs to do to cancel the operation.  If a driver
 *  is able to cancel it will call GlobusXIODriverCancelEanble()
 *  if at the time this function is called the operations cancel
 *  flag is set to true we register a oneshot for the cancel.
 * 
 *  If a cencel occurs while a driver is registered to receive 
 *  cancel notification then the callback is delivered to it.
 *
 *  The framework has little else to do with cancel.  The operation
 *  will come back up via the normal routes with an error.
 */
globus_result_t
globus_l_xio_operation_cancel(
    globus_i_xio_op_t *                     op)
{
    globus_bool_t                           tmp_rc;
    GlobusXIOName(globus_l_xio_operation_cancel);

    GlobusXIODebugInternalEnter();

    /* internal function should never be passed NULL */
    globus_assert(op != NULL);

    if(op->canceled)
    {
        return GLOBUS_SUCCESS;
    }
    /* 
     * if the user oks the cancel then remove the timeout from 
     * the poller
     */
    tmp_rc = globus_i_xio_timer_unregister_timeout(
                &globus_l_xio_timeout_timer, op);
    /* since in callback this will always be true */

    /*
     * set cancel flag
     * if a driver has a registered callback it will be called
     * if it doesn't the next pass or finished will pick it up
     */
    op->canceled = GLOBUS_TRUE;
    if(op->cancel_cb != NULL)
    {
        op->cancel_cb(op, op->cancel_arg);
    }

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;
}

globus_bool_t
globus_l_xio_timeout_callback(
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op;
    globus_i_xio_handle_t *                 handle;
    globus_bool_t                           rc;
    globus_bool_t                           fire_callback;
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_bool_t                           cancel;
    globus_bool_t                           timeout = GLOBUS_FALSE;
    globus_callback_func_t                  delayed_cb;
    globus_callback_space_t                 space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;                   
    GlobusXIOName(globus_l_xio_timeout_callback);

    GlobusXIODebugInternalEnter();
    
    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        switch(op->state)
        {
            /* 
             * this case happens when a open operation first pass fails and 
             * are unable to unregister the timeout and when the operation
             * completes but we are unable to unregister the callback.
             */
            case GLOBUS_XIO_OP_STATE_FINISHED:
            case GLOBUS_XIO_OP_STATE_FINISH_WAITING:

                /* decerement the reference for the timeout callback */
                op->ref--;
                if(op->ref == 0)
                {
                    globus_i_xio_op_destroy(op, &destroy_handle, 
                        &destroy_context);
                }

                /* remove it from the timeout list */
                rc = GLOBUS_TRUE;
                break;

            /* this case happens when we actually want to cancel the operation
                The timeout code should insure that prograess is false if this
                gets called in this state */
            case GLOBUS_XIO_OP_STATE_OPERATING:
                /* it is up to the timeout callback to set this to true */
                rc = GLOBUS_FALSE;
                /* cancel the sucker */
                globus_assert(!op->progress);
                globus_assert(op->_op_handle_timeout_cb != NULL);

                /* if the driver has blocked the timeout don't call it */
                if(!op->block_timeout)
                {
                    timeout = GLOBUS_TRUE;
                    /* put in canceling state to delay the accept callback */
                    op->state = GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING;
                }
                break;

            /* fail on any ohter case */
            default:
                globus_assert(0);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* if in cancel state, verfiy with user that they want to cancel */
    if(timeout)
    {
        cancel = op->_op_handle_timeout_cb(handle, op->type);
    }
    /* all non time out casses can just return */
    else
    {
        /* wait until outside of lock to free the handle */
        if(destroy_handle)
        {
            if(destroy_context)
            {
                globus_i_xio_context_destroy(handle->context);
            }
            globus_i_xio_handle_destroy(handle);
        }
        goto exit;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        /* if canceling set the res and we will remove this timer event */
        if(cancel)
        {
            op->cached_res = GlobusXIOErrorTimedout();
            rc = GLOBUS_TRUE;
            op->canceled = GLOBUS_TRUE;
            if(op->cancel_cb)
            {
                op->cancel_cb(op, op->cancel_arg);
            }
        }

        /* if callback has already arriverd set flag to later
            call accept callback and set rc to remove timed event */
        if(op->state == GLOBUS_XIO_OP_STATE_FINISH_WAITING)
        {
            fire_callback = GLOBUS_TRUE;
            rc = GLOBUS_TRUE;
        }
        /* if no accept is waiting, set state back to operating */
        else
        {
            fire_callback = GLOBUS_FALSE;
            op->state = GLOBUS_XIO_OP_STATE_OPERATING;
        }

        /* if we are remvoing the timed event */
        if(rc)
        {
            /* decremenet the target reference count and insist that it is
               not zero yet */
            op->_op_handle_timeout_cb = NULL;
            op->ref--;
            globus_assert(op->ref > 0);
        }

        /* if the accpet was pending we must call it */
        if(fire_callback)
        {
            switch(op->type)
            {
                case GLOBUS_XIO_OPERATION_TYPE_OPEN:
                case GLOBUS_XIO_OPERATION_TYPE_CLOSE:
                    delayed_cb = globus_l_xio_open_close_callback_kickout;
                    break;

                case GLOBUS_XIO_OPERATION_TYPE_READ:
                case GLOBUS_XIO_OPERATION_TYPE_WRITE:
                    delayed_cb = globus_l_xio_read_write_callback_kickout;
                    break;

                default:
                    globus_assert(0);
                    break;

            }
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(fire_callback)
    {
        if(!op->blocking)
        {
            space = handle->space;
        }
        if(space != GLOBUS_CALLBACK_GLOBAL_SPACE)
        {
            /* register a oneshot callback */
            globus_callback_space_register_oneshot(
                NULL,
                NULL,
                delayed_cb,
                (void *)op,
                space);
        }
        /* in all other cases we can just call callback */
        else
        {
            delayed_cb((void *)op);
        }
    }

  exit:
    GlobusXIODebugInternalExit();
    return rc;
}

/*
 *
 */
globus_result_t
globus_l_xio_register_writev(
    globus_i_xio_op_t *                     op,
    int                                     ref)
{
    globus_result_t                         res;
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_i_xio_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_register_writev);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            res = GlobusXIOErrorInvalidState(handle->state);
            goto bad_state_err;
        }

        /* register timeout */
        if(op->_op_handle->write_timeout_cb != NULL)
        {
            /* op the operatin reference count for this */
            op->ref++;
            op->_op_handle_timeout_cb = handle->write_timeout_cb;
            globus_i_xio_timer_register_timeout(
                &globus_l_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &handle->write_timeout_period);
        }

        globus_list_insert(&handle->write_op_list, op);
        /* may be zero if it was already referenced via data descriptor */
        handle->ref += ref;
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    op->ref++;
    GlobusXIODriverPassWrite(res, op, op->_op_iovec, op->_op_iovec_count,     \
        op->_op_wait_for, globus_i_xio_read_write_callback, (void *)NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto pass_err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }

    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  pass_err:

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--; /* dec for the register */
        globus_assert(op->ref > 0);
        /* in case timeout unregister fails */
        op->type = GLOBUS_XIO_OPERATION_TYPE_FINISHED;
        /* if we had a timeout, we need to unregister it */
        if(handle->write_timeout_cb != NULL)
        {
            /* if unregister works remove its reference count */
            if(globus_i_xio_timer_unregister_timeout(
                &globus_l_xio_timeout_timer, op))
            {
                op->ref--;
                globus_assert(op->ref > 0);
            }
        }
        /* clean up the operation */
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
  bad_state_err:
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExitWithError();
    return res;
}

/*
 *
 */
globus_result_t
globus_l_xio_register_readv(
    globus_i_xio_op_t *                     op,
    int                                     ref)
{
    globus_result_t                         res;
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_i_xio_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_register_readv);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    globus_mutex_lock(&handle->context->mutex);
    {
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            res = GlobusXIOErrorInvalidState(handle->state);
            goto bad_state_err;
        }
        /* this is a bit ugly 
           handle doesn't maitain this state and Pass asserts for efficieny.
           so wee need to check it here to be nice to the user */
        if(handle->context->entry[0].state != GLOBUS_XIO_CONTEXT_STATE_OPEN &&
           handle->context->entry[0].state != 
            GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED)
        {
            res = GlobusXIOErrorInvalidState(handle->context->entry[0].state);
            goto bad_state_err;
        }

        /* register timeout */
        if(handle->read_timeout_cb != NULL)
        {
            /* op the operatin reference count for this */
            op->ref++;
            op->_op_handle_timeout_cb = handle->read_timeout_cb;
            globus_i_xio_timer_register_timeout(
                &globus_l_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &handle->read_timeout_period);
        }

        globus_list_insert(&handle->read_op_list, op);
        handle->ref += ref;
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    op->ref++;
    GlobusXIODriverPassRead(res, op, op->_op_iovec, op->_op_iovec_count,     \
        op->_op_wait_for, globus_i_xio_read_write_callback, (void *)NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto register_err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--; /* remove the pass reference */
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }

    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  register_err:

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--;  /* unregister the pass */
        globus_assert(op->ref > 0);
        /* in case timeout unregister fails */
        op->type = GLOBUS_XIO_OPERATION_TYPE_FINISHED;
        /* if we had a timeout, we need to unregister it */
        if(handle->read_timeout_cb != NULL)
        {
            /* if unregister works remove its reference count */
            if(globus_i_xio_timer_unregister_timeout(
                &globus_l_xio_timeout_timer, op))
            {
                op->ref--;
                globus_assert(op->ref > 0);
            }
        }
        /* clean up the operation */
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
  bad_state_err:
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExitWithError();
    return res;
}

globus_result_t
globus_l_xio_register_open(
    globus_i_xio_op_t *                     op)
{
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_i_xio_handle_t *                 handle;
    globus_result_t                         res;
    globus_i_xio_context_t *                context;
    globus_xio_context_t                    tmp_context;
    GlobusXIOName(globus_l_xio_register_open);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;

    handle->state = GLOBUS_XIO_HANDLE_STATE_OPENING;

    /* register timeout */
    if(handle->open_timeout_cb != NULL)
    {
        /* op the operatin reference count for this */
        op->ref++;
        op->_op_handle_timeout_cb = handle->open_timeout_cb;
        globus_i_xio_timer_register_timeout(
            &globus_l_xio_timeout_timer,
            op,
            &op->progress,
            globus_l_xio_timeout_callback,
            &handle->open_timeout_period);
    }
    handle->open_op = op;

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    op->ref++;
    GlobusXIODriverPassOpen(res, tmp_context, op, \
        globus_i_xio_open_close_callback, NULL);
    
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }

    }
    globus_mutex_unlock(&handle->context->mutex);
    
    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--; /* dec for the register */
        globus_assert(op->ref > 0);

        context = op->_op_context;
        if(globus_i_xio_timer_unregister_timeout(
            &globus_l_xio_timeout_timer, op))
        {
            op->ref--;
            globus_assert(op->ref > 0);
        }

        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
        handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;
        globus_i_xio_handle_dec(handle, &destroy_handle, &destroy_context);
    }
    globus_mutex_unlock(&handle->context->mutex);
    if(destroy_handle)
    {
        if(destroy_context)
        {
            globus_i_xio_context_destroy(handle->context);
        }
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugInternalExitWithError();
    return res;
}

globus_result_t
globus_l_xio_register_close(
    globus_i_xio_op_t *                     op)
{
    globus_bool_t                           destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           destroy_context = GLOBUS_FALSE;
    globus_list_t *                         list;
    globus_i_xio_handle_t *                 handle;
    globus_i_xio_op_t *                     tmp_op;
    globus_result_t                         res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_register_close);

    GlobusXIODebugInternalEnter();

    handle = op->_op_handle;
    globus_mutex_lock(&handle->context->mutex);
    {
        /* 
         *  if the user requests a cancel kill all open ops
         *  if they didn't the close will not happen until all ops finish 
         */
        /* all canceling is done with cancel op locked */
        globus_mutex_lock(&handle->cancel_mutex);
        {
            /* if open is outstanding there cannot be a read or write */
            if(handle->open_op != NULL)
            {
                /* we delay the pass close until the open callback */
                globus_l_xio_operation_cancel(handle->open_op);

                /* this next line is strange.  what happens is this,
                   typically read if open comes back with a failure we
                   clean up the handle right after the open callback is
                   called.  However if it is an error due to a close
                   being called then we can't destroy because we have 
                   a close callback to call.  we up the refrence count here
                   to force this.
                */
                handle->ref++;
            }
            else
            {
                for(list = handle->read_op_list;
                    !globus_list_empty(list);
                    list = globus_list_rest(list))
                {
                    tmp_op = (globus_i_xio_op_t *) globus_list_first(list);
                    globus_l_xio_operation_cancel(tmp_op);
                }
    
                for(list = handle->write_op_list;
                    !globus_list_empty(list);
                    list = globus_list_rest(list))
                {
                    tmp_op = (globus_i_xio_op_t *) globus_list_first(list);
                    globus_l_xio_operation_cancel(tmp_op);
                }
            }
        }
        globus_mutex_unlock(&handle->cancel_mutex);

        /* register timeout */
        if(handle->close_timeout_cb != NULL)
        {
            /* op the operatin reference count for this */
            op->ref++;
            op->_op_handle_timeout_cb = handle->close_timeout_cb;
            globus_i_xio_timer_register_timeout(
                &globus_l_xio_timeout_timer,
                op,
                &op->progress,
                globus_l_xio_timeout_callback,
                &handle->close_timeout_period);
        }
        handle->ref++; /* for the operation */
    }
    globus_mutex_unlock(&handle->context->mutex);

    /* add reference count for the pass.  does not need to be done locked
       since no one has op until it is passed  */
    op->ref++;
    GlobusXIODriverPassClose(res, op, globus_i_xio_open_close_callback, NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--;
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }

    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIODebugInternalExit();
    return GLOBUS_SUCCESS;

  err:

    globus_mutex_lock(&handle->context->mutex);
    {
        op->ref--; /* dec for the register */
        globus_assert(op->ref > 0);

        if(globus_i_xio_timer_unregister_timeout(
            &globus_l_xio_timeout_timer, op))
        {
            op->ref--;
        }
        op->ref--; 
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle, 
                    &destroy_context);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
        globus_i_xio_handle_dec(handle, &destroy_handle, &destroy_context);
    }
    globus_mutex_unlock(&handle->context->mutex);

    if(destroy_handle)
    {
        if(destroy_context)
        {
            globus_i_xio_context_destroy(handle->context);
        }
        globus_i_xio_handle_destroy(handle);
    }
    GlobusXIODebugInternalExitWithError();

    return res;
}

/*
 *  cancel the operations
 */
globus_result_t
globus_l_xio_handle_cancel_operations(
    globus_i_xio_handle_t *                 xio_handle,
    int                                     mask)
{
    globus_list_t *                         list;
    globus_i_xio_op_t *                     tmp_op;
    globus_result_t                         res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_handle_cancel_operations);

    GlobusXIODebugInternalEnter();

    globus_mutex_lock(&xio_handle->cancel_mutex);
    {
        if(mask & GLOBUS_XIO_CANCEL_OPEN)
        {
            if(xio_handle->open_op == NULL)
            {
                res = GlobusXIOErrorNotRegistered();
            }
            else
            {
                res = globus_l_xio_operation_cancel(xio_handle->open_op);
            }
        }
        if(mask & GLOBUS_XIO_CANCEL_CLOSE)
        {
            if(xio_handle->close_op == NULL)
            {
                res = GlobusXIOErrorNotRegistered();
            }
            else
            {
                res = globus_l_xio_operation_cancel(xio_handle->close_op);
            }
        }
        if(mask & GLOBUS_XIO_CANCEL_READ)
        {
            if(globus_list_empty(xio_handle->read_op_list))
            {
                res = GlobusXIOErrorNotRegistered();
            }
            else
            {
                /* remove all outstanding read ops */
                for(list = xio_handle->read_op_list;
                    !globus_list_empty(list);
                    list = globus_list_rest(list))
                {
                    tmp_op = (globus_i_xio_op_t *) 
                                globus_list_first(list);
                    res = globus_l_xio_operation_cancel(tmp_op);
                }
            }
        }
        if(mask & GLOBUS_XIO_CANCEL_WRITE)
        {
            if(globus_list_empty(xio_handle->write_op_list))
            {
                res = GlobusXIOErrorNotRegistered();
            }
            else
            {
                for(list = xio_handle->write_op_list;
                    !globus_list_empty(list);
                    list = globus_list_rest(list))
                {
                    tmp_op = (globus_i_xio_op_t *)  
                                globus_list_first(list);
                    res = globus_l_xio_operation_cancel(tmp_op);
                }
            }
        }
    }
    globus_mutex_unlock(&xio_handle->cancel_mutex);

    if(res != GLOBUS_SUCCESS)
    {
        GlobusXIODebugInternalExit();
    }
    else
    {
        GlobusXIODebugInternalExitWithError();
    }

    /* cancel doesn't fail sonce it is a best effort method */
    return res;
}
/********************************************************************
 *                        API functions 
 *                        -------------
 *******************************************************************/
/*
 *  User Open
 *  ---------
 *  Check the parameters and state then pass to internal open function.
 */
globus_result_t
globus_xio_register_open(
    globus_xio_handle_t *                   user_handle,
    globus_xio_attr_t                       user_attr,
    globus_xio_target_t                     user_target,
    globus_xio_callback_t                   cb,
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op = NULL;
    globus_i_xio_handle_t *                 handle = NULL;
    globus_i_xio_target_t *                 target;
    globus_i_xio_context_t *                context = NULL;
    globus_result_t                         res = GLOBUS_SUCCESS;
    int                                     ctr;
    globus_callback_space_t                 space = 
            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(globus_xio_register_open);

    GlobusXIODebugEnter();

    if(user_handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto err;
    }
    if(user_target == NULL)
    {
        res = GlobusXIOErrorParameter(target);
        goto err;
    }

    *user_handle = NULL; /* initialze to be nice to user */
    target = (globus_i_xio_target_t *) user_target;

    /* this is gaurenteed to be greater than zero */
    globus_assert(target->stack_size > 0);

    /* allocate and initialize context */
    context = globus_i_xio_context_create(target);
    if(context == NULL)
    {
        res = GlobusXIOErrorMemory("context");
        goto err;
    }

    /* allocate and intialize the handle structure */
    GlobusXIOHandleCreate(handle, target->stack_size, user_attr);
    if(handle == NULL)
    {
        res = GlobusXIOErrorMemory("handle");
        goto err;
    }

    GlobusXIOOperationCreate(op, context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto err;
    }

    /* all memory has been allocated, now set up the different structures */

    /*
     *  set up the operation
     */
    op->type = GLOBUS_XIO_OPERATION_TYPE_OPEN;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_cb = cb;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1; /* for first pass there is no return */
    op->_op_context = context;

    /* initialize the handle */
    handle->ref = 2; /* itself, operation */
    handle->context = context;
    /* this is set for the cancel */
    handle->open_op = op;
    handle->outstanding_operations = 1; /* open operation */

    if(user_attr != NULL)
    {
        space =  user_attr->space;
    }
    /* initialize the context */
    handle->space = space;
    globus_callback_space_reference(space);


    handle->target = target;
    /* set entries in structures */
    for(ctr = 0; ctr < handle->stack_size; ctr++)
    {
        context->entry[ctr].driver = target->entry[ctr].driver;

        if(user_attr != NULL)
        {
            GlobusIXIOAttrGetDS(op->entry[ctr].attr,                    \
                user_attr, target->entry[ctr].driver);
        }
        else
        {
            op->entry[ctr].attr = NULL;
        }
    }


    res = globus_l_xio_register_open(op);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    *user_handle = handle;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:

    if(op != NULL)
    {
        globus_bool_t b;
        globus_i_xio_op_destroy(op, &b, &b);
    }
    if(handle != NULL)
    {
        handle->context = NULL;
        globus_i_xio_handle_destroy(handle);
    }
    if(context != NULL)
    {
        globus_i_xio_context_destroy(context);
    }

    GlobusXIODebugExitWithError();

    return res;
}

/*
 *  User Read
 *  ---------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  fake the iovec structure with the dummy iovec in the operation struct
 *  Then pass to the internal readv function
 */
globus_result_t
globus_xio_register_read(
    globus_xio_handle_t                     handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_data_callback_t              cb,
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op;
    globus_result_t                         res;
    int                                     ref = 0;
    GlobusXIOName(globus_xio_register_read);

    GlobusXIODebugEnter();
    
    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(buffer == NULL)
    {
        return GlobusXIOErrorParameter("buffer");
    }
    if(buffer_length < 0)
    {
        return GlobusXIOErrorParameter("buffer_length");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_context = handle->context;
    op->_op_data_cb = cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1;

    res = globus_l_xio_register_readv(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  exit:

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  User Readv
 *  ----------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  Then pass to the internal readv function
 */
globus_result_t
globus_xio_register_readv(
    globus_xio_handle_t                     handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_iovec_callback_t             cb,
    void *                                  user_arg)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                     op;
    int                                     ref = 0;
    GlobusXIOName(globus_xio_register_readv);

    GlobusXIODebugEnter();

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(iovec == NULL)
    {
        return GlobusXIOErrorParameter("iovec");
    }
    if(iovec_count <= 0)
    {
        return GlobusXIOErrorParameter("iovec_count");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->ref = 1;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1;

    res = globus_l_xio_register_readv(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    GlobusXIODebugExit();
  
    return GLOBUS_SUCCESS;
  exit:

    GlobusXIODebugExitWithError();
    return res;
}   

/*
 *  User Write
 *  ----------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  fake the iocev structure with the dummy iovec in the operation struct
 *  Then pass to the internal writev function
 */
globus_result_t
globus_xio_register_write(
    globus_xio_handle_t                     user_handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_data_callback_t              cb,
    void *                                  user_arg)
{
    globus_i_xio_op_t *                     op;
    globus_result_t                         res;
    globus_i_xio_handle_t *                 handle;
    int                                     ref = 0;
    GlobusXIOName(globus_xio_register_write);

    GlobusXIODebugEnter();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(buffer == NULL)
    {
        return GlobusXIOErrorParameter("buffer");
    }
    if(buffer_length < 0)
    {
        return GlobusXIOErrorParameter("buffer_length");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->ref = 1;
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;

    res = globus_l_xio_register_writev(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  exit:
    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  User Writev
 *  -----------
 *  Check the parameters and state
 *  If everything is ok create and setup the operation structure
 *  Then pass to the internal writev function
 */
globus_result_t
globus_xio_register_writev(
    globus_xio_handle_t                     user_handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_iovec_callback_t             cb,
    void *                                  user_arg)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                     op;
    globus_i_xio_handle_t *                 handle;
    int                                     ref = 0;
    GlobusXIOName(globus_xio_register_writev);

    GlobusXIODebugEnter();

    handle = (globus_i_xio_handle_t *) user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(iovec == NULL)
    {
        return GlobusXIOErrorParameter("iovec");
    }
    if(iovec_count <= 0)
    {
        return GlobusXIOErrorParameter("iovec_count");
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto exit;
        }
        ref = 1;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->entry[0].prev_ndx = -1;

    op->ref = 1;
    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;

    res = globus_l_xio_register_writev(op, ref);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;
  exit:

    GlobusXIODebugExitWithError();
    return res;
}


/*
 *  User Close
 *  ----------
 *  Check the parameters and state then pass to internal function.
 */
globus_result_t
globus_xio_register_close(
    globus_xio_handle_t                     handle,
    globus_xio_attr_t                       attr,
    globus_xio_callback_t                   cb,
    void *                                  user_arg)
{
    globus_result_t                         res;
    int                                     ctr;
    globus_i_xio_op_t *                     op;
    GlobusXIOName(globus_xio_register_close);

    GlobusXIODebugEnter();

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        if(handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSING)
        {
            globus_mutex_unlock(&handle->context->mutex);
            res = GlobusXIOErrorInvalidState(handle->state);
            goto err;
        }
        else
        {
            handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;
            /* this is set for the cancel */
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto err;
    }

    /*
     *  set up the operation
     */
    handle->close_op = op;
    op->type = GLOBUS_XIO_OPERATION_TYPE_CLOSE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_cb = cb;
    op->user_arg = user_arg;
    op->entry[0].prev_ndx = -1;/*for first pass there is no return*/

    /* set up op */
    for(ctr = 0; ctr < handle->stack_size; ctr++)
    {
        if(attr != NULL)
        {
            GlobusIXIOAttrGetDS(op->entry[ctr].attr, attr,          \
                handle->context->entry[ctr].driver);
        }
        else
        {
            op->entry[ctr].attr = NULL;
        }
    }

     res = globus_l_xio_register_close(op);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;
  err:

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  cancel outstanding operations.
 * 
 *  In the furture the attr will control what operations get canceled.
 *  For now all are canceled.
 */
globus_result_t
globus_xio_handle_cancel_operations(
    globus_xio_handle_t                     handle,
    int                                     mask)
{
    globus_i_xio_handle_t *                 xio_handle;
    globus_result_t                         res;
    GlobusXIOName(globus_xio_register_close);

    GlobusXIODebugEnter();

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    xio_handle = handle;

    globus_mutex_lock(&xio_handle->context->mutex);
    {
        /* if closed there is nothing to cancel */
        if(xio_handle->state == GLOBUS_XIO_HANDLE_STATE_CLOSED)
        {
            res = GlobusXIOErrorInvalidState(xio_handle->state);
        }
        else
        {
            res = globus_l_xio_handle_cancel_operations(
                    xio_handle,
                    mask);
        }
    }
    globus_mutex_unlock(&xio_handle->context->mutex);

    GlobusXIODebugExit();

    return res;
}


globus_result_t
globus_xio_handle_cntl(
    globus_xio_handle_t                     handle,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...)
{
    globus_result_t                         res;
    int                                     ctr;
    int                                     ndx;
    va_list                                 ap;
    globus_i_xio_context_t *                context;
    GlobusXIOName(globus_xio_handle_cntl);

    GlobusXIODebugEnter();

    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, cmd);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    context = handle->context;
    if(driver != NULL)
    {
        ndx = -1;
        for(ctr = 0; ctr < context->stack_size && ndx == -1; ctr++)
        {
            if(driver == context->entry[ctr].driver)
            {
                res = context->entry[ctr].driver->handle_cntl_func(
                        context->entry[ctr].driver_handle,
                        cmd,
                        ap);
                if(res != GLOBUS_SUCCESS)
                {
                    goto exit;
                }
                ndx = ctr;
            }
        }
        if(ndx == -1)
        {
            /* throw error */
            res = GlobusXIOErrorInvalidDriver("not found");
            goto exit;
        }
    }
    else
    {
        /* do general settings */
    }

  exit:
    va_end(ap);

    GlobusXIODebugExit();

    return res;
}

/************************************************************************
 *                          blocking calls
 *                          --------------
 ***********************************************************************/
globus_i_xio_blocking_t *
globus_i_xio_blocking_alloc()
{
    globus_i_xio_blocking_t *               info;

    info = (globus_i_xio_blocking_t *) 
                globus_malloc(sizeof(globus_i_xio_blocking_t));
    globus_mutex_init(&info->mutex, NULL);
    globus_cond_init(&info->cond, NULL);
    info->done = GLOBUS_FALSE;

    return info;
}

void
globus_i_xio_blocking_destroy(
    globus_i_xio_blocking_t *               info)
{
    globus_mutex_destroy(&info->mutex);
    globus_cond_destroy(&info->cond);
    globus_free(info);
}

void
globus_l_xio_blocking_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_i_xio_blocking_t *               info;

    info = (globus_i_xio_blocking_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->res = result;
        info->done = GLOBUS_TRUE;
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

void
globus_l_xio_blocking_data_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    globus_i_xio_blocking_t *               info;
    
    info = (globus_i_xio_blocking_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->res = result;
        info->data_desc = data_desc;
        info->nbytes = nbytes;
        info->done = GLOBUS_TRUE;
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

void
globus_l_xio_blocking_iov_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    globus_xio_iovec_t *                    iovec,
    int                                     count,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_i_xio_blocking_t *               info;

    info = (globus_i_xio_blocking_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->done = GLOBUS_TRUE;
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

globus_result_t
globus_xio_open(
    globus_xio_handle_t *                   user_handle,
    globus_xio_attr_t                       user_attr,
    globus_xio_target_t                     user_target)
{
    globus_i_xio_op_t *                     op = NULL;
    globus_i_xio_handle_t *                 handle = NULL;
    globus_i_xio_target_t *                 target;
    globus_i_xio_context_t *                context = NULL;
    globus_result_t                         res = GLOBUS_SUCCESS;
    int                                     ctr;
    globus_i_xio_blocking_t *               info;
    globus_callback_space_t                 space = 
            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(globus_xio_register_open);

    GlobusXIODebugEnter();

    if(user_handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_err;
    }
    if(user_target == NULL)
    {
        res = GlobusXIOErrorParameter("target");
        goto param_err;
    }

    *user_handle = NULL; /* initialze to be nice to user */
    target = (globus_i_xio_target_t *) user_target;

    /* this is gaurenteed to be greater than zero */
    globus_assert(target->stack_size > 0);

    /* allocate and initialize context */
    context = globus_i_xio_context_create(target);
    if(context == NULL)
    {
        res = GlobusXIOErrorMemory("context");
        goto param_err;
    }

    /* allocate and intialize the handle structure */
    GlobusXIOHandleCreate(handle, target->stack_size, user_attr);
    if(handle == NULL)
    {
        res = GlobusXIOErrorMemory("handle");
        goto handle_alloc_err;
    }

    GlobusXIOOperationCreate(op, context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto op_alloc_err;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto info_alloc_error;
    }
    info->op = op;

    /* all memory has been allocated, now set up the different structures */

    /*
     *  set up the operation
     */

    op->type = GLOBUS_XIO_OPERATION_TYPE_OPEN;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_cb = globus_l_xio_blocking_cb;
    op->user_arg = info;
    op->entry[0].prev_ndx = -1; /* for first pass there is no return */
    op->_op_context = context;

    /* initialize the handle */
    handle->ref = 2; /* itself, operation */
    handle->context = context;
    /* this is set for the cancel */
    handle->open_op = op;
    handle->outstanding_operations = 1; /* open operation */

    if(user_attr != NULL)
    {
        space =  user_attr->space;
    }
    /* initialize the context */
    handle->space = space;
    globus_callback_space_reference(space);


    handle->target = target;
    /* set entries in structures */
    for(ctr = 0; ctr < handle->stack_size; ctr++)
    {
        context->entry[ctr].driver = target->entry[ctr].driver;

        if(user_attr != NULL)
        {
            GlobusIXIOAttrGetDS(op->entry[ctr].attr,                    \
                user_attr, target->entry[ctr].driver);
        }
        else
        {
            op->entry[ctr].attr = NULL;
        }
    }

    globus_mutex_lock(&info->mutex);
    {
        res = globus_l_xio_register_open(op);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_err;
        }

        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(info->res != GLOBUS_SUCCESS)
    {
        res = info->res;
        goto register_err;
    }
    globus_i_xio_blocking_destroy(info);

    *user_handle = handle;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  register_err:
    globus_i_xio_blocking_destroy(info);

  info_alloc_error:
    {
        globus_bool_t           destroy_handle;
        globus_bool_t           destroy_context;

        globus_i_xio_op_destroy(op, &destroy_handle, &destroy_context);
    }
  op_alloc_err:
    handle->context = NULL;
    globus_i_xio_handle_destroy(handle);

  handle_alloc_err:
    globus_i_xio_context_destroy(context);
    *user_handle = NULL;

  param_err:
    GlobusXIODebugExitWithError();

    return res;
}

/* 
 *  read
 */
globus_result_t
globus_xio_read(
    globus_xio_handle_t                     user_handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc)
{
    globus_i_xio_op_t *                     op;
    globus_result_t                         res;
    globus_i_xio_handle_t *                 handle;
    int                                     ref = 0;
    globus_i_xio_blocking_t *               info;
    GlobusXIOName(globus_xio_read);

    GlobusXIODebugEnter();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(buffer == NULL)
    {
        res = GlobusXIOErrorParameter("buffer");
        goto param_error;
    }
    if(buffer_length <= 0)
    {
        res = GlobusXIOErrorParameter("buffer_length");
        goto param_error;
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->ref = 1;
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = globus_l_xio_blocking_data_cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;

    info->op = op;

    globus_mutex_lock(&info->mutex);
    {
        res = globus_l_xio_register_readv(op, ref);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_error;
        }

        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    if(info->res != GLOBUS_SUCCESS)
    {
        res = info->res;
        goto alloc_error;
    }
    globus_i_xio_blocking_destroy(info);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_mutex_unlock(&info->mutex);
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    GlobusXIODebugExitWithError();

    if(nbytes != NULL)
    {
        *nbytes = 0;
    }

    return res;
}

globus_result_t
globus_xio_readv(
    globus_xio_handle_t                     user_handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc)
{
    globus_i_xio_op_t *                     op;
    globus_result_t                         res;
    globus_i_xio_handle_t *                 handle;
    int                                     ref = 0;
    globus_i_xio_blocking_t *               info;
    GlobusXIOName(globus_xio_readv);

    GlobusXIODebugEnter();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(iovec == NULL)
    {
        res = GlobusXIOErrorParameter("buffer");
        goto param_error;
    }
    if(iovec_count <= 0)
    {
        res = GlobusXIOErrorParameter("buffer_length");
        goto param_error;
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->ref = 1;
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = globus_l_xio_blocking_iov_cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;

    info->op = op;

    globus_mutex_lock(&info->mutex);
    {
        res = globus_l_xio_register_readv(op, ref);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_error;
        }

        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    if(info->res != GLOBUS_SUCCESS)
    {
        res = info->res;
        goto alloc_error;
    }
    globus_i_xio_blocking_destroy(info);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_mutex_unlock(&info->mutex);
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    if(nbytes != NULL)
    {
        *nbytes = 0;
    }

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *  writes
 */
globus_result_t
globus_xio_write(
    globus_xio_handle_t                     user_handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc)
{
    globus_i_xio_op_t *                     op;
    globus_result_t                         res;
    globus_i_xio_handle_t *                 handle;
    int                                     ref = 0;
    globus_i_xio_blocking_t *               info;
    GlobusXIOName(globus_xio_write);

    GlobusXIODebugEnter();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(buffer == NULL)
    {
        res = GlobusXIOErrorParameter("buffer");
        goto param_error;
    }
    if(buffer_length <= 0)
    {
        res = GlobusXIOErrorParameter("buffer_length");
        goto param_error;
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->ref = 1;
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = globus_l_xio_blocking_data_cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;

    info->op = op;

    globus_mutex_lock(&info->mutex);
    {
        res = globus_l_xio_register_writev(op, ref);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_error;
        }

        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    if(info->res != GLOBUS_SUCCESS)
    {
        res = info->res;
        goto alloc_error;
    }
    globus_i_xio_blocking_destroy(info);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_mutex_unlock(&info->mutex);
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:
    if(nbytes != NULL)
    {
        *nbytes = 0;
    }

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_writev(
    globus_xio_handle_t                     user_handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc)
{
    globus_i_xio_op_t *                     op;
    globus_result_t                         res;
    globus_i_xio_handle_t *                 handle;
    int                                     ref = 0;
    globus_i_xio_blocking_t *               info;
    GlobusXIOName(globus_xio_writev);

    GlobusXIODebugEnter();

    handle = user_handle;

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }
    if(iovec == NULL)
    {
        res = GlobusXIOErrorParameter("buffer");
        goto param_error;
    }
    if(iovec_count <= 0)
    {
        res = GlobusXIOErrorParameter("buffer_length");
        goto param_error;
    }

    op = data_desc;
    if(op == NULL)
    {
        GlobusXIOOperationCreate(op, handle->context);
        if(op == NULL)
        {
            res = GlobusXIOErrorMemory("operation");
            goto param_error;
        }
        ref = 1;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->ref = 1;
    op->entry[0].prev_ndx = -1;

    op->_op_handle = handle;
    op->_op_context = handle->context;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = globus_l_xio_blocking_iov_cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = info;
    op->blocking = GLOBUS_TRUE;

    info->op = op;

    globus_mutex_lock(&info->mutex);
    {
        res = globus_l_xio_register_writev(op, ref);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_error;
        }

        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(nbytes != NULL)
    {
        *nbytes = info->nbytes;
    }

    if(info->res != GLOBUS_SUCCESS)
    {
        res = info->res;
        goto alloc_error;
    }
    globus_i_xio_blocking_destroy(info);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_mutex_unlock(&info->mutex);
    globus_i_xio_blocking_destroy(info);
  alloc_error:
    /* desroy op */

  param_error:

    if(nbytes != NULL)
    {
        *nbytes = 0;
    }

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_close(
    globus_xio_handle_t                     handle,
    globus_xio_attr_t                       attr)
{
    globus_result_t                         res;
    int                                     ctr;
    globus_i_xio_op_t *                     op;
    globus_i_xio_blocking_t *               info;
    GlobusXIOName(globus_xio_register_close);

    GlobusXIODebugEnter();

    /* error echecking */
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto param_error;
    }

    globus_mutex_lock(&handle->context->mutex);
    {
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            globus_mutex_unlock(&handle->context->mutex);
            res = GlobusXIOErrorInvalidState(handle->state);
            goto param_error;
        }
        else
        {
            handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;
            /* this is set for the cancel */
        }
    }
    globus_mutex_unlock(&handle->context->mutex);

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        res = GlobusXIOErrorMemory("operation");
        goto param_error;
    }

    info = globus_i_xio_blocking_alloc();
    if(info == NULL)
    {
        res = GlobusXIOErrorMemory("internal strucature");
        goto alloc_error;
    }

    /*
     *  set up the operation
     */
    handle->close_op = op;
    op->type = GLOBUS_XIO_OPERATION_TYPE_CLOSE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_cb = globus_l_xio_blocking_cb;
    op->user_arg = info;
    op->entry[0].prev_ndx = -1;/*for first pass there is no return*/

    info->op = op;

    /* set up op */
    for(ctr = 0; ctr < handle->stack_size; ctr++)
    {
        if(attr != NULL)
        {
            GlobusIXIOAttrGetDS(op->entry[ctr].attr, attr,
                handle->context->entry[ctr].driver);
        }
        else
        {
            op->entry[ctr].attr = NULL;
        }
    }

    globus_mutex_lock(&info->mutex);
    {
        res = globus_l_xio_register_close(op);
        if(res != GLOBUS_SUCCESS)
        {
            goto register_error;
        }

        while(!info->done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
    }
    globus_mutex_unlock(&info->mutex);

    if(info->res != GLOBUS_SUCCESS)
    {
        res = info->res;
        goto alloc_error;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  register_error:
    globus_mutex_unlock(&info->mutex);
  alloc_error:
    /* desroy op */

  param_error:
    GlobusXIODebugExitWithError();
    return res;
}
