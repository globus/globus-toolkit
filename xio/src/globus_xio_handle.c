#include "globus_xio_pass.h"
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
#define GlobusXIOHandleDestroy(_in_h)                                       \
do                                                                          \
{                                                                           \
    globus_i_xio_handle_t *                         _h;                     \
                                                                            \
    _h = (_in_h);                                                           \
    globus_list_remove(&globus_l_outstanding_handles_list,                  \
        globus_list_search(globus_l_outstanding_handles_list, _h));         \
    globus_assert(_h->ref == 0);                                            \
    globus_mutex_destroy(&_h->mutex);                                       \
    globus_free(_h);                                                        \
} while(0)

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
        globus_mutex_init(&_h->mutex, NULL);                                \
        /*                                                                  \
         *  initialize memory for the operation structure                   \
         *  The operation is a stretchy array.  The size of the             \
         *  operation structure plus the size of the entry array            \
         */                                                                 \
        _h->stack_size = (s);                                               \
                                                                            \
        _h->open_timeout_cb = _a->open_timeout_cb;                          \
        GlobusTimeReltimeCopy(_h->open_timeout_period,                      \
            _a->open_timeout_period);                                       \
        _h->read_timeout_cb = _a->read_timeout_cb;                          \
        GlobusTimeReltimeCopy(_h->read_timeout_period,                      \
            _a->read_timeout_period);                                       \
        _h->write_timeout_cb = _a->write_timeout_cb;                        \
        GlobusTimeReltimeCopy(_h->write_timeout_period,                     \
            _a->write_timeout_period);                                      \
        _h->close_timeout_cb = _a->close_timeout_cb;                        \
        GlobusTimeReltimeCopy(_h->close_timeout_period,                     \
            _a->close_timeout_period);                                      \
    }                                                                       \
                                                                            \
    globus_list_insert(&globus_l_outstanding_handles_list, _h);             \
    h = _h;                                                                 \
} while(0)

#define GlobusXIOOperationCreate(op, c)                                     \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                                 _op;                \
    globus_i_xio_context_t *                             _c;                \
                                                                            \
    _c = (c);                                                               \
    _op = (globus_i_xio_op_t * )                                            \
            globus_memory_pop_node(&_c->op_memory);                         \
    if(_op != NULL)                                                         \
    {                                                                       \
        memset(_op, '\0', sizeof(globus_i_xio_op_t));                       \
        _op->_op_context = _c;                                              \
        _op->stack_size = _c->stack_size;                                   \
        _op->progress = GLOBUS_TRUE;                                        \
    }                                                                       \
    op = _op;                                                               \
} while(0)

#define GlobusXIOOperationDestroy(op)                                       \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (op);                                                             \
    globus_assert(_op->ref == 0);                                           \
    globus_memory_push_node(&_op->_op_context->op_memory, _op);             \
} while(0)

#define GlobusIXIOHandleDec(free, h)                                        \
do                                                                          \
{                                                                           \
    globus_i_xio_handle_t *                         _h;                     \
                                                                            \
    _h = (h);                                                               \
    _h->ref--;                                                              \
    if(_h->ref == 0)                                                        \
    {                                                                       \
        /* if the handle ref gets down to zero we must be in one            \
         * of the followninf staes.  The statement is that the handle       \
         * only goes away when it is closed or a open fails                 \
         */                                                                 \
        globus_assert(                                                      \
            _h->state == GLOBUS_XIO_HANDLE_STATE_CLOSED);                   \
        free = GLOBUS_TRUE;                                                 \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        free = GLOBUS_FALSE;                                                \
    }                                                                       \
} while(0)

/* 
 *  module activation
 */

#include "version.h"
#include "globus_i_xio.h"
#include "globus_xio.h"


globus_i_xio_timer_t                        globus_l_xio_timeout_timer;
static globus_list_t *                      globus_l_outstanding_handles_list;
static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;

static int
globus_l_xio_activate()
{
    int                                                 rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != 0)
    {
        return rc;
    }

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, NULL);
    globus_i_xio_timer_init(&globus_l_xio_timeout_timer);
    globus_l_outstanding_handles_list = NULL;

    return GLOBUS_SUCCESS;
}

static int
globus_l_xio_deactivate()
{
    /* is this good enough for user callback spaces and deadlock ?? */
    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_list_empty(globus_l_outstanding_handles_list))
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_mutex_destroy(&globus_l_mutex);
    globus_cond_destroy(&globus_l_cond);
    globus_i_xio_timer_destroy(&globus_l_xio_timeout_timer);

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
    void *                                      user_arg);

void
globus_l_xio_read_write_callback_kickout(
    void *                                      user_arg);

/********************************************************************
 *                      Internal functions 
 *******************************************************************/

/*
 *  This is called when either an open or a close completes.
 */
void
globus_i_xio_open_close_callback(
    globus_i_xio_op_t *                         op,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_i_xio_handle_t *                     handle;
    globus_bool_t                               fire_callback = GLOBUS_TRUE;

    handle = op->_op_handle;

    globus_mutex_lock(&handle->mutex);
    {   
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
    globus_mutex_unlock(&handle->mutex);

    if(fire_callback)
    {
        /* we can always call in this stack since Pass macros enforce
           registration bariers and callback spaces */
        globus_l_xio_open_close_callback_kickout((void *)op);
    }
}

/*
 *   called by the callback code.
 *   registerd by finished op when the final (user) callback
 *   is in a callback space, or if it is under the registraton
 *   call within the same callstack
 */
void
globus_l_xio_open_close_callback_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    globus_i_xio_handle_t *                     handle;
    globus_bool_t                               destroy_handle = GLOBUS_FALSE;

    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    /* call the users callback */
    if(op->_op_cb != NULL)
    {
        op->_op_cb(handle, op->cached_res, op->user_arg);
    }

    globus_mutex_lock(&handle->mutex);
    {
        globus_assert(op->state == GLOBUS_XIO_OP_STATE_FINISH_WAITING);

        /* this is likely useless, but may help in debugging */
        op->state = GLOBUS_XIO_OP_STATE_FINISHED;

        /* 
         *  if we were trying toclose or the open has a failed result.
         */
        if(op->type == GLOBUS_XIO_OPERATION_TYPE_CLOSE ||
           op->cached_res != GLOBUS_SUCCESS)
        {
            GlobusIXIOHandleDec(destroy_handle, handle);
            /* destroy handle cannot possibly be true yet 
                the handle stll has the operation reference */
            globus_assert(!destroy_handle);

            /* we can remove both open and close since this branch
               only enters if open failed or close happened.  in either
               case both are removed */
            handle->close_op = NULL;
        }
        handle->open_op = NULL;

        /* decrement reference for the operation */
        op->ref--;
        if(op->ref == 0)
        {
            GlobusXIOOperationDestroy(op);
            GlobusIXIOHandleDec(destroy_handle, handle);
        }

    }
    globus_mutex_unlock(&handle->mutex);

    if(destroy_handle)
    {
        GlobusXIOHandleDestroy(handle);
    }
}

/*
 *  operation callback for readv and writev operations
 *  we don't care what the result is, just so it bubbles up to the user
 */
void
globus_i_xio_read_write_callback(
    globus_xio_operation_t                      op,
    globus_result_t                             result,
    globus_size_t                               nbytes,
    void *                                      user_arg)
{
    globus_i_xio_handle_t *                     handle;
    globus_bool_t                               fire_operation = GLOBUS_TRUE;

    handle = op->_op_handle;

    globus_mutex_lock(&handle->mutex);
    {
        globus_assert(handle->state == GLOBUS_XIO_HANDLE_STATE_OPEN &&
            handle->state != GLOBUS_XIO_HANDLE_STATE_CLOSING);

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

        op->cached_res = result;
        op->_op_nbytes = nbytes;
    }   
    globus_mutex_unlock(&handle->mutex);

    /*
     *  if in a space or within the register call stack
     *  we must register a one shot
     */
    if(fire_operation)
    {
        globus_l_xio_read_write_callback_kickout((void *)op);
    }
}

/*
 *  called unlocked either by the callback code or in the finsihed op
 *  state.
 */
void
globus_l_xio_read_write_callback_kickout(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    globus_i_xio_handle_t *                     handle;
    globus_bool_t                               destroy_handle = GLOBUS_FALSE;

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

    globus_mutex_lock(&handle->mutex);
    {
        /*
         *  This is legit in all states except for OPENING and CLOSED
         */
        globus_assert(handle->state != GLOBUS_XIO_HANDLE_STATE_CLOSED &&
            handle->state != GLOBUS_XIO_HANDLE_STATE_OPENING);
        /* decrement reference for the operation */
        op->ref--;
        if(op->ref == 0)
        {
            GlobusXIOOperationDestroy(op);
            /* remove refrence for operation */
            GlobusIXIOHandleDec(destroy_handle, handle);
            /* destroy handle cannot possibly be true yet 
                the handle stll has its own reference */
            globus_assert(!destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->mutex);
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
    globus_i_xio_op_t *                         op)
{
    globus_bool_t                               tmp_rc;

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
    globus_assert(tmp_rc);

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

    return GLOBUS_SUCCESS;
}

globus_bool_t
globus_l_xio_timeout_callback(
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    globus_i_xio_handle_t *                     handle;
    globus_bool_t                               rc;
    globus_bool_t                               fire_callback;
    globus_bool_t                               destroy_handle = GLOBUS_FALSE;
    globus_bool_t                               cancel;
    globus_bool_t                               timeout = GLOBUS_FALSE;
    globus_callback_func_t                      delayed_cb;
    GlobusXIOName(globus_l_xio_timeout_callback);
    
    op = (globus_i_xio_op_t *) user_arg;
    handle = op->_op_handle;

    globus_mutex_lock(&handle->mutex);
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
                    /* remove the reference for the target on the server */
                    handle->ref--;
                    if(handle->ref == 0)
                    {
                        GlobusXIOOperationDestroy(op);
                        GlobusIXIOHandleDec(destroy_handle, handle);
                    }
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
    globus_mutex_unlock(&handle->mutex);

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
            globus_free(handle);
        }
        return rc;
    }

    globus_mutex_lock(&handle->mutex);
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
    globus_mutex_unlock(&handle->mutex);

    if(fire_callback)
    {
        if(op->_op_context->entry[0].space != GLOBUS_CALLBACK_GLOBAL_SPACE)
        {
            /* register a oneshot callback */
            globus_callback_space_register_oneshot(
                NULL,
                NULL,
                delayed_cb,
                (void *)op,
                op->_op_context->entry[0].space);
        }
        /* in all other cases we can just call callback */
        else
        {
            delayed_cb((void *)op);
        }
    }

    return rc;
}

/*
 *
 */
globus_result_t
globus_l_xio_register_writev(
    globus_i_xio_op_t *                         op)
{
    globus_result_t                             res;
    globus_bool_t                               destroy_handle;
    globus_i_xio_handle_t *                     handle;
    GlobusXIOName(globus_l_xio_register_writev);

    handle = op->_op_handle;

    globus_mutex_lock(&handle->mutex);
    {
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            globus_mutex_unlock(&handle->mutex);
            res = GlobusXIOErrorInvalidState(handle->state);
            goto err;
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

        handle->ref++;
    }
    globus_mutex_unlock(&handle->mutex);

    GlobusXIODriverPassWrite(res, op, op->_op_iovec, op->_op_iovec_count,     \
        op->_op_wait_for, globus_i_xio_read_write_callback, (void *)NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    globus_mutex_lock(&handle->mutex);
    {
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
            GlobusXIOOperationDestroy(op);
            /* remove the operations reference to the handle */
            GlobusIXIOHandleDec(destroy_handle, handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return res;
}

/*
 *
 */
globus_result_t
globus_l_xio_register_readv(
    globus_i_xio_op_t *                         op)
{
    globus_result_t                             res;
    globus_bool_t                               destroy_handle;
    globus_i_xio_handle_t *                     handle;
    globus_xio_context_t                        tmp_context;
    GlobusXIOName(globus_l_xio_register_readv);

    handle = op->_op_handle;

    globus_mutex_lock(&handle->mutex);
    {
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            globus_mutex_unlock(&handle->mutex);
            res = GlobusXIOErrorInvalidState(handle->state);
            goto err;
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

        handle->ref++;
    }
    globus_mutex_unlock(&handle->mutex);

    GlobusXIODriverPassRead(res, op, op->_op_iovec, op->_op_iovec_count,     \
        op->_op_wait_for, globus_i_xio_read_write_callback, (void *)NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    globus_mutex_lock(&handle->mutex);
    {
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
            GlobusXIOOperationDestroy(op);
            /* remove the operations reference to the handle */
            GlobusIXIOHandleDec(destroy_handle, op->_op_handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return res;
}

globus_result_t
globus_l_xio_register_open(
    globus_i_xio_op_t *                         op)
{
    globus_bool_t                               destroy_handle = GLOBUS_FALSE;
    globus_i_xio_handle_t *                     handle;
    globus_result_t                             res;
    globus_xio_context_t                        tmp_context = NULL;

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

    handle->ref++; /* for the operation */

    GlobusXIODriverPassOpen(res, tmp_context, op, \
        globus_i_xio_open_close_callback, NULL);
    
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:

    if(globus_i_xio_timer_unregister_timeout(&globus_l_xio_timeout_timer, op))
    {
        op->ref--;
    }
    op->ref--;
    if(op->ref == 0)
    {
        GlobusXIOOperationDestroy(op);
        /* remove the operations reference to the handle */
        GlobusIXIOHandleDec(destroy_handle, handle);
        /* handle should always have a reference left at this point */
        globus_assert(!destroy_handle);
    }
    GlobusIXIOHandleDec(destroy_handle, handle);
    globus_i_xio_context_destroy(op->_op_context);
    if(destroy_handle)
    {
        GlobusXIOHandleDestroy(handle);
    }

    return res;
}

globus_result_t
globus_l_xio_register_close(
    globus_i_xio_op_t *                         op)
{
    globus_bool_t                               destroy_handle = GLOBUS_FALSE;
    globus_list_t *                             list;
    globus_i_xio_handle_t *                     handle;
    globus_i_xio_op_t *                         tmp_op;
    globus_result_t                             res = GLOBUS_SUCCESS;

    handle = op->_op_handle;
    globus_mutex_lock(&handle->mutex);
    {
        /* 
         *  if the user requests a cancel kill all open ops
         *  if they didn't the close will not happen until all ops finish 
         */
        /* all canceling is done with cancel op locked */
        globus_mutex_lock(&handle->cancel_mutex);
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
    globus_mutex_unlock(&handle->mutex);

    GlobusXIODriverPassClose(res, op, globus_i_xio_open_close_callback, NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    globus_mutex_lock(&handle->mutex);
    {
        if(globus_i_xio_timer_unregister_timeout(
            &globus_l_xio_timeout_timer, op))
        {
            op->ref--;
        }
        op->ref--; 
        if(op->ref == 0)
        {
            GlobusXIOOperationDestroy(op);
            /* remove the operations reference to the handle */
            GlobusIXIOHandleDec(destroy_handle, handle);
            /* handle should always have a reference left at this point */
            globus_assert(!destroy_handle);
        }
        GlobusIXIOHandleDec(destroy_handle, handle);
        if(destroy_handle)
        {
            GlobusXIOHandleDestroy(handle);
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return res;
}

/*
 *  cancel the operations
 */
globus_result_t
globus_l_xio_handle_cancel_operations(
    globus_i_xio_handle_t *                     xio_handle,
    globus_i_xio_attr_t *                       attr)
{
    globus_list_t *                             list;
    globus_i_xio_op_t *                         tmp_op;
    globus_result_t                             res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_handle_cancel_operations);

    globus_mutex_lock(&xio_handle->cancel_mutex);
    {
        if(attr->cancel_open)
        {
            if(xio_handle->open_op == NULL)
            {
                res = GlobusXIOErrorNotRegistered();
            }
            else
            {
                globus_l_xio_operation_cancel(xio_handle->open_op);
            }
        }
        if(attr->cancel_close)
        {
            if(xio_handle->close_op == NULL)
            {
                res = GlobusXIOErrorNotRegistered();
            }
            else
            {
                globus_l_xio_operation_cancel(xio_handle->close_op);
            }
        }
        if(attr->cancel_read)
        {
            if(!globus_list_empty(xio_handle->read_op_list))
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
                    globus_l_xio_operation_cancel(tmp_op);
                }
            }
        }
        if(attr->cancel_write)
        {
            if(!globus_list_empty(xio_handle->write_op_list))
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
                    globus_l_xio_operation_cancel(tmp_op);
                }
            }
        }
    }
    globus_mutex_unlock(&xio_handle->cancel_mutex);

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
    globus_xio_handle_t *                       user_handle,
    globus_xio_attr_t                           user_attr,
    globus_xio_target_t                         user_target,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op = NULL;
    globus_i_xio_handle_t *                     handle = NULL;
    globus_i_xio_target_t *                     target;
    globus_i_xio_context_t *                    context = NULL;
    globus_result_t                             res = GLOBUS_SUCCESS;
    int                                         ctr;
    GlobusXIOName(globus_xio_register_open);

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
    op->entry[0].caller_ndx = -1; /* for first pass there is no return */

    /* initialize the handle */
    handle->ref = 2; /* itself, operation */
    handle->context = context;
    /* this is set for the cancel */
    handle->open_op = op;
    handle->outstanding_operations = 1; /* open operation */

    /* initialize the context */
    context->ref = 1; /* for the refrence the handle has */
    context->entry[0].space = user_attr->space;
    globus_callback_space_reference(context->entry[0].space);

    /* set entries in structures */
    for(ctr = 0; ctr < handle->stack_size; ctr++)
    {
        context->entry[ctr].driver = target->entry[ctr].driver;

        op->entry[ctr].target = target->entry[ctr].target;
        GlobusIXIOAttrGetDS(op->entry[ctr].attr,                    \
            user_attr, target->entry[ctr].driver);
    }


    res = globus_l_xio_register_open(op);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    return GLOBUS_SUCCESS;

    /*
     * error handling 
     */
  err:

    if(op != NULL)
    {
        GlobusXIOOperationDestroy(op);
    }
    if(handle != NULL)
    {
        GlobusXIOHandleDestroy(handle);
    }
    if(context != NULL)
    {
        globus_i_xio_context_destroy(context);
    }

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
    globus_xio_handle_t                         handle,
    globus_byte_t *                             buffer,
    globus_size_t                               buffer_length,
    globus_size_t                               waitforbytes,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_data_callback_t                  cb,
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    globus_result_t                             res;
    GlobusXIOName(globus_xio_register_read);
    
    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }
    if(buffer == NULL)
    {
        return GlobusXIOErrorParameter("buffer");
    }
    if(buffer_length <= 0)
    {
        return GlobusXIOErrorParameter("buffer_length");
    }

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        globus_mutex_unlock(&handle->mutex);
        res = GlobusXIOErrorMemory("operation");
        goto exit;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_data_cb = cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].caller_ndx = -1;

    res = globus_l_xio_register_readv(op);

  exit:

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
    globus_xio_handle_t                         handle,
    globus_xio_iovec_t *                        iovec,
    int                                         iovec_count,
    globus_size_t                               waitforbytes,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_iovec_callback_t                 cb,
    void *                                      user_arg)
{
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                         op;
    GlobusXIOName(globus_xio_register_readv);

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

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        globus_mutex_unlock(&handle->mutex);
        res = GlobusXIOErrorMemory("operation");
        goto err;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_READ;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].caller_ndx = -1;

    res = globus_l_xio_register_readv(op);
  
  err:

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
    globus_xio_handle_t                         user_handle,
    globus_byte_t *                             buffer,
    globus_size_t                               buffer_length,
    globus_size_t                               waitforbytes,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_data_callback_t                  cb,
    void *                                      user_arg)
{
    globus_i_xio_op_t *                         op;
    globus_result_t                             res;
    globus_i_xio_handle_t *                     handle;
    GlobusXIOName(globus_xio_register_write);

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
    if(buffer_length <= 0)
    {
        return GlobusXIOErrorParameter("buffer_length");
    }

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        globus_mutex_unlock(&handle->mutex);
        res = GlobusXIOErrorMemory("operation");
        goto exit;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_data_cb = cb;
    op->_op_iovec_cb = NULL;
    op->_op_mem_iovec.iov_base = buffer;
    op->_op_mem_iovec.iov_len = buffer_length;
    op->_op_iovec_count = 1;
    op->_op_iovec = &op->_op_mem_iovec;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].caller_ndx = -1;

    res = globus_l_xio_register_writev(op);

  exit:
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
    globus_xio_handle_t                         user_handle,
    globus_xio_iovec_t *                        iovec,
    int                                         iovec_count,
    globus_size_t                               waitforbytes,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_iovec_callback_t                 cb,
    void *                                      user_arg)
{
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                         op;
    globus_i_xio_handle_t *                     handle;
    GlobusXIOName(globus_xio_register_writev);

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

    GlobusXIOOperationCreate(op, handle->context);
    if(op == NULL)
    {
        globus_mutex_unlock(&handle->mutex);
        res = GlobusXIOErrorMemory("operation");
        goto err;
    }
    /* set up the operation */
    op->type = GLOBUS_XIO_OPERATION_TYPE_WRITE;
    op->state = GLOBUS_XIO_OP_STATE_OPERATING;
    op->_op_handle = handle;
    op->ref = 1;
    op->_op_data_cb = NULL;
    op->_op_iovec_cb = cb;
    op->_op_iovec = iovec;
    op->_op_iovec_count = iovec_count;
    op->_op_wait_for = waitforbytes;
    op->user_arg = user_arg;
    op->entry[0].caller_ndx = -1;

    res = globus_l_xio_register_writev(op);

  err:

    return res;
}


/*
 *  User Close
 *  ----------
 *  Check the parameters and state then pass to internal function.
 */
globus_result_t
globus_xio_register_close(
    globus_xio_handle_t                         handle,
    globus_xio_attr_t                           attr,
    globus_xio_callback_t                       cb,
    void *                                      user_arg)
{
    globus_result_t                             res;
    int                                         ctr;
    globus_i_xio_op_t *                         op;
    GlobusXIOName(globus_xio_register_close);

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    globus_mutex_lock(&handle->mutex);
    {
        if(handle->state != GLOBUS_XIO_HANDLE_STATE_OPEN)
        {
            globus_mutex_unlock(&handle->mutex);
            res = GlobusXIOErrorInvalidState(handle->state);
            goto err;
        }
        else
        {
            handle->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;
            /* this is set for the cancel */
        }
    }
    globus_mutex_unlock(&handle->mutex);

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
    op->entry[0].caller_ndx = -1;/*for first pass there is no return*/

    /* set up op */
    for(ctr = 0; ctr < handle->stack_size; ctr++)
    {
        GlobusIXIOAttrGetDS(op->entry[ctr].attr, attr, handle->context->entry[ctr].driver);
    }

     res = globus_l_xio_register_close(op);

  err:

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
    globus_xio_handle_t                         handle,
    globus_xio_attr_t                           attr)
{
    globus_i_xio_handle_t *                     xio_handle;
    globus_result_t                             res;
    GlobusXIOName(globus_xio_register_close);

    /* error echecking */
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    xio_handle = handle;

    globus_mutex_lock(&xio_handle->mutex);
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
                    attr);
        }
    }
    globus_mutex_unlock(&xio_handle->mutex);

    return res;
}
