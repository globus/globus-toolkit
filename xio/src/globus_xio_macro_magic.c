#include "globus_i_xio.h"

/************************************************************************
 *                              open
 *                              ----
 ***********************************************************************/


void
globus_xio_driver_pass_open_DEBUG(
    globus_result_t *                     _out_res,
    globus_xio_context_t *                _out_context,
    globus_xio_operation_t                _in_op,
    globus_xio_driver_callback_t          _in_cb,
    void *                                _in_user_arg)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_handle_t *                 _handle;
    globus_i_xio_context_t *                _context;
    globus_i_xio_context_entry_t *          _my_context;
    globus_i_xio_op_entry_t *               _my_op;
    int                                     _caller_ndx;
    globus_result_t                         _res;
    globus_bool_t                           _destroy_handle = GLOBUS_FALSE;
    globus_bool_t                           _close = GLOBUS_FALSE;
    globus_xio_driver_t                     _driver;
    GlobusXIOName(GlobusXIODriverPassOpen);

    _op = (_in_op);
    globus_assert(_op->ndx < _op->stack_size);
    _handle = _op->_op_handle;
    _context = _handle->context;
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    if(_op->canceled)
    {
        _res = GlobusXIOErrorCanceled();
    }
    else
    {
        _my_context = &_context->entry[_op->ndx];
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPENING;
        _my_context->outstanding_operations++;
        _caller_ndx = _op->ndx;

        do
        {
            _driver = _context->entry[_op->ndx].driver;
            _op->ndx++;
        }
        while(_driver->transport_open_func == NULL &&
              _driver->transform_open_func == NULL);

        /* hold a reference until open callback returns */
        _context->ref++;

        _my_op = &_op->entry[_op->ndx - 1];
        _my_op->cb = (_in_cb);
        _my_op->user_arg = (_in_user_arg);
        _my_op->in_register = GLOBUS_TRUE;
        _my_op->caller_ndx = _caller_ndx;
        /* at time that stack is built this will be varified */
        globus_assert(_op->ndx <= _context->stack_size);

        /* ok to do this unlocked because no one else has it yet */
        _op->ref++; /* gotta count the pass */
        if(_op->ndx == _op->stack_size)
        {
            _res = _driver->transport_open_func(
                        _handle->target->entry[_op->ndx - 1].target,
                        _my_op->attr,
                        _my_context,
                        _op);
        }
        else
        {
            _res = _driver->transform_open_func(
                        _handle->target->entry[_op->ndx - 1].target,
                        _my_op->attr,
                        _op);
        }
        _my_op->in_register = GLOBUS_FALSE;
        globus_mutex_lock(&_context->mutex);
        {
            /* it is possible that the operations finished completely by
               this point.  if finishing with an error it is possible that
                we need to free the handle */
            _op->ref--;
            if(_op->ref == 0)
            {
                GlobusXIOOperationDestroy(_op);
                GlobusIXIOHandleDec(_destroy_handle, _handle);
            }
            if(_res != GLOBUS_SUCCESS)
            {
                _my_context->outstanding_operations--;
                /*there is an off chance that we could need to close here*/
                if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||
                    _my_context->state ==
                    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&
                    _my_context->outstanding_operations == 0)
                {
                    globus_assert(_my_context->close_op != NULL);
                    _close = GLOBUS_TRUE;
                }
            }
        }
        globus_mutex_unlock(&_context->mutex);

        if(_destroy_handle)
        {
            GlobusXIOHandleDestroy(_handle);
        }

        GlobusXIODebugSetOut(_out_context, _my_context);
        GlobusXIODebugSetOut(_out_res, _res);
    }
}


void
globus_xio_driver_finished_open_DEBUG(
    globus_xio_context_t                  _in_context,
    void *                                _in_dh,
    globus_xio_operation_t                _in_op,
    globus_result_t                       _in_res)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_context_entry_t *          _my_context;
    globus_i_xio_context_t *                _context;
    globus_i_xio_op_entry_t *               _my_op;
    globus_result_t                         _res;
    int                                     _ctr;
    globus_callback_space_t                 _space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(GlobusXIODriverFinishedOpen);

    _res = (_in_res);
    _op = (globus_i_xio_op_t *)(_in_op);
    globus_assert(_op->ndx >= 0);
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    /*
     * this means that we are finishing with a different context
     * copy the finishing one into the operations;
     */
    if(_op->_op_context != _in_context->whos_my_daddy &&
            _in_context != NULL)
    {
        globus_assert(0); /* for now we are dumping */
        /* iterate through them all and copy handles into new slot */
        for(_ctr = _op->ndx + 1; _ctr < _op->stack_size; _ctr++)
        {
            _op->_op_context->entry[_ctr].driver_handle =
                _in_context->whos_my_daddy->entry[_ctr].driver_handle;
        }
    }

    _context = _op->_op_context;
    _context->entry[_op->ndx - 1].driver_handle = (_in_dh);
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];
    /* no operation can happen while in OPENING state so no need to lock */
    if(_res != GLOBUS_SUCCESS)
    {
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;
    }
    else
    {
        if(_my_context->state == GLOBUS_XIO_HANDLE_STATE_OPENING)
        {
            _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPEN;
        }
        _context->ref++;
    }

    if(_my_op->caller_ndx == 0 && !_op->blocking)
    {
        _space = _op->_op_handle->space;
    }
    _op->cached_res = _res;
    if(_my_op->in_register ||
        _space != GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        GlobusXIODebugInregisterOneShot();
        globus_callback_space_register_oneshot(
            NULL,
            NULL,
            globus_l_xio_driver_open_op_kickout,
            (void *)_op,
            _space);
    }
    else
    {
        GlobusIXIODriverOpenDeliver(_op);
    }
}

void
globus_xio_driver_open_deliver_DEBUG(
    globus_xio_operation_t                          op)
{
    globus_i_xio_op_t *                             _op;
    globus_result_t                                 _res;
    globus_i_xio_op_t *                             _close_op;
    globus_i_xio_op_entry_t *                       _my_op;
    globus_i_xio_context_entry_t *                  _my_context;
    globus_i_xio_context_t *                        _context;
    globus_bool_t                                   _close = GLOBUS_FALSE;
    globus_bool_t                                   _destroy_context =
                                                        GLOBUS_FALSE;
    globus_callback_space_t                 _space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(GlobusIXIODriverOpenDeliver);

    _op = (op);
    _context = _op->_op_context;
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];

    _res = _op->cached_res;
    _op->ndx = _my_op->caller_ndx;
    _my_op->cb(_op, _res, _my_op->user_arg);

    /* LOCK */
    globus_mutex_lock(&_context->mutex);
    {
        /* remove the reference help to make sure the context is not
           destroyed until all open callbacks have returned */
        _context->ref--;
        if(_context->ref == 0)
        {
            _destroy_context = GLOBUS_TRUE;
        }

        _my_context->outstanding_operations--;

        /* if we have a close delayed */
        if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSED ||
            _my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING) &&
            _my_context->outstanding_operations == 0 &&
            _my_context->close_op != NULL)
        {
            _close = GLOBUS_TRUE;
            _close_op = _my_context->close_op;
        }
    }
    globus_mutex_unlock(&_context->mutex);

    if(_destroy_context)
    {
        globus_i_xio_context_destroy(_context);
    }
    if(_close)
    {
        /* if closed before fully opened and open was successful we need
           to start the regular close process */
        if(_res == GLOBUS_SUCCESS)
        {
            globus_i_xio_driver_start_close(_close_op, GLOBUS_FALSE);
        }
        /* if open failed then just kickout the close */
        else
        {
            _close_op->cached_res = GLOBUS_SUCCESS;
            if(_close_op->entry[_close_op->ndx - 1].caller_ndx == 0 &&
                    !_close_op->blocking)
            {
                _space = _close_op->_op_handle->space;
            }
            globus_callback_space_register_oneshot(
                NULL,
                NULL,
                globus_l_xio_driver_op_kickout,
                (void *)_close_op,
                _space);
        }
    }
}


/************************************************************************
 *                          close
 *                          -----
 ***********************************************************************/

void
globus_xio_driver_pass_close_DEBUG(
    globus_result_t *                     _out_res,
    globus_xio_operation_t                _in_op,
    globus_xio_driver_callback_t          _in_cb,
    void *                                _in_ua)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_handle_t *                 _handle;
    globus_i_xio_context_t *                _context;
    globus_i_xio_context_entry_t *          _my_context;
    globus_bool_t                           _pass;
    globus_i_xio_op_entry_t *               _my_op;
    int                                     _caller_ndx;
    globus_result_t                         _res = GLOBUS_SUCCESS;
    globus_xio_driver_t                     _driver;
    GlobusXIOName(GlobusXIODriverPassClose);

    _op = (_in_op);
    globus_assert(_op->ndx < _op->stack_size);
    _handle = _op->_op_handle;
    _context = _handle->context;
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    if(_op->canceled && _op->type != GLOBUS_XIO_OPERATION_TYPE_OPEN)
    {
        _res = GlobusXIOErrorCanceled();
    }
    else
    {
        _caller_ndx = _op->ndx;
        _my_context = &_context->entry[_op->ndx];

        do
        {
            _driver = _context->entry[_op->ndx].driver;
            _op->ndx++;
        }
        while(_driver->close_func == NULL);
        _my_op = &_op->entry[_op->ndx - 1];


        /* deal with context state */
        globus_mutex_lock(&_context->mutex);
        {
            switch(_my_context->state)
            {
                case GLOBUS_XIO_HANDLE_STATE_OPEN:
                case GLOBUS_XIO_HANDLE_STATE_OPENING:
                    _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;
                    break;

                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:
                    _my_context->state =
                        GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING;
                    break;

                case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED:
                    _my_context->state =
                        GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING;
                    break;

                default:
                    globus_assert(0);
            }
            /* a barrier will never happen if the level above already did th
                close barrier and this level has not created any driver ops.
                in this case outstanding_operations is garentueed to be zero
            */
            if(_my_context->outstanding_operations == 0)
            {
                _pass = GLOBUS_TRUE;
            }
            /* cache the op for close barrier */
            else
            {
                _pass = GLOBUS_FALSE;
                _my_context->close_op = _op;
            }
        }
        globus_mutex_unlock(&_context->mutex);

        _my_op->cb = (_in_cb);
        _my_op->user_arg = (_in_ua);
        _my_op->caller_ndx = _caller_ndx;
        /* op can be checked outside of lock */
        if(_pass)
        {
            _res = globus_i_xio_driver_start_close(_op, GLOBUS_TRUE);
        }
    }
    if(_res != GLOBUS_SUCCESS)
    {
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;
    }
    GlobusXIODebugSetOut(_out_res, _res);
}

void
globus_xio_driver_finished_close_DEBUG(
    globus_xio_operation_t                op,
    globus_result_t                       _in_res)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_context_entry_t *          _my_context;
    globus_i_xio_context_t *                _context;
    globus_i_xio_op_entry_t *               _my_op;
    globus_result_t                         _res;
    globus_callback_space_t                 _space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(GlobusXIODriverFinishedClose);

    _res = (_in_res);
    _op = (globus_i_xio_op_t *)(op);
    globus_assert(_op->ndx > 0);
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    _context = _op->_op_context;
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];

    /* don't need to lock because barrier makes contntion not possible */
    _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;

    globus_assert(_op->ndx >= 0); /* otherwise we are not in bad memory */
    _op->cached_res = _res;
    if(_my_op->caller_ndx == 0 && !_op->blocking)
    {
        _space = _op->_op_handle->space;
    }
    if(_my_op->in_register ||
        _space != GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        GlobusXIODebugInregisterOneShot();
        globus_callback_space_register_oneshot(
            NULL,
            NULL,
            globus_l_xio_driver_op_kickout,
            (void *)_op,
            _space);
    }
    else
    {
        _op->ndx = _my_op->caller_ndx;
        _my_op->cb(_op, _op->cached_res, _my_op->user_arg);
    }
}


/************************************************************************
 *                              write
 *                              -----
 ***********************************************************************/

void
globus_xio_driver_pass_write_DEBUG(
    globus_result_t *                     _out_res,
    globus_xio_operation_t                _in_op,
    globus_xio_iovec_t *                  _in_iovec,
    int                                   _in_iovec_count,
    globus_size_t                         _in_wait_for,
    globus_xio_driver_data_callback_t     _in_cb,
    void *                                _in_user_arg)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_op_entry_t *               _my_op;
    globus_i_xio_context_entry_t *          _my_context;
    globus_i_xio_context_entry_t *          _next_context;
    globus_i_xio_context_t *                _context;
    globus_bool_t                           _close = GLOBUS_FALSE;
    int                                     _caller_ndx;
    globus_result_t                         _res = GLOBUS_SUCCESS;
    globus_xio_driver_t                     _driver;
    globus_bool_t                           _destroy_handle = GLOBUS_FALSE;
    GlobusXIOName(GlobusXIODriverPassWrite);

    _op = (_in_op);
    _context = _op->_op_context;
    _my_context = &_context->entry[_op->ndx];
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;
    _caller_ndx = _op->ndx;

    globus_assert(_op->ndx < _op->stack_size);

    /* error checking */
    globus_assert(_my_context->state == GLOBUS_XIO_HANDLE_STATE_OPEN ||
        _my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED ||
        _my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED);
    if(_op->canceled)
    {
        _res = GlobusXIOErrorCanceled();
    }
    else
    {
        /* set up the entry */
        _caller_ndx = _op->ndx;
        do
        {
            _next_context = &_context->entry[_op->ndx];
            _driver = _next_context->driver;
            _op->ndx++;
        }
        while(_driver->write_func == NULL);

        _my_op = &_op->entry[_op->ndx - 1];
        _my_op->caller_ndx = _caller_ndx;
        _my_op->_op_ent_data_cb = (_in_cb);
        _my_op->user_arg = (_in_user_arg);
        _my_op->_op_ent_iovec = (_in_iovec);
        _my_op->_op_ent_iovec_count = (_in_iovec_count);
        _my_op->_op_ent_nbytes = 0;
        _my_op->_op_ent_wait_for = (_in_wait_for);
        /* set the callstack flag */
        _my_op->in_register = GLOBUS_TRUE;

        globus_mutex_lock(&_context->mutex);
        {
            _my_context->outstanding_operations++;
            _op->ref++;
        }
        globus_mutex_unlock(&_context->mutex);
        _res = _driver->write_func(
                        _next_context->driver_handle,
                        _my_op->_op_ent_iovec,
                        _my_op->_op_ent_iovec_count,
                        _op);

        /* flip the callstack flag */
        _my_op->in_register = GLOBUS_FALSE;
        globus_mutex_lock(&_context->mutex);
        {
            _op->ref--;
            if(_op->ref == 0)
            {
                GlobusXIOOperationDestroy(_op);
                GlobusIXIOHandleDec(_destroy_handle, _op->_op_handle);
                /* we cannot be set to destroy yet, because handle has not
                    yet finished the close process */
                globus_assert(!_destroy_handle);
            }

            if(_res != GLOBUS_SUCCESS)
            {
                _my_context->outstanding_operations--;
                /*there is an off chance that we could need to close here*/
                if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||
                    _my_context->state ==
                    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&
                    _my_context->outstanding_operations == 0)
                {
                    globus_assert(_my_context->close_op != NULL);
                    _close = GLOBUS_TRUE;
                }
            }
        }
        globus_mutex_unlock(&_context->mutex);
    }

    if(_close)
    {
        globus_i_xio_driver_start_close(_my_context->close_op,
                GLOBUS_FALSE);
    }
    GlobusXIODebugSetOut(_out_res, _res);
}


void
globus_xio_driver_finished_write_DEBUG(
    globus_xio_operation_t                op,
    globus_result_t                       result,
    globus_size_t                         nbytes)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_op_entry_t *               _my_op;
    globus_result_t                         _res;
    globus_bool_t                           _fire_cb = GLOBUS_TRUE;
    globus_xio_iovec_t *                    _tmp_iovec;
    globus_i_xio_context_entry_t *          _my_context;
    globus_i_xio_context_entry_t *          _next_context;
    globus_i_xio_context_t *                _context;
    int                                     _iovec_count;
    globus_callback_space_t                 _space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(GlobusXIODriverFinishedWrite);

    _op = (globus_i_xio_op_t *)(op);
    _res = (result);
    _op->progress = GLOBUS_TRUE;
     _op->block_timeout = GLOBUS_FALSE;

    _context = _op->_op_context;
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];

    _op->cached_res = _res;

    globus_assert(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPENING &&
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_CLOSED);

    _my_op->_op_ent_nbytes += nbytes;
    /* if not all bytes were written */
    if(_my_op->_op_ent_nbytes < _my_op->_op_ent_wait_for &&
        _res == GLOBUS_SUCCESS)
    {
        /* if not enough bytes read set the fire_cb deafult to false */
        _fire_cb = GLOBUS_FALSE;
        /* allocate tmp iovec to the bigest it could ever be */
        if(_my_op->_op_ent_fake_iovec == NULL)
        {
            _my_op->_op_ent_fake_iovec = (globus_xio_iovec_t *)
                globus_malloc(sizeof(globus_xio_iovec_t) *
                    _my_op->_op_ent_iovec_count);
        }
        _tmp_iovec = _my_op->_op_ent_fake_iovec;

        GlobusIXIOUtilTransferAdjustedIovec(
            _tmp_iovec, _iovec_count,
            _my_op->_op_ent_iovec, _my_op->_op_ent_iovec_count,
            _my_op->_op_ent_nbytes);

        _next_context = &_context->entry[_op->ndx - 1];
        /* repass the operation down */
        _res = _next_context->driver->write_func(
                _next_context->driver_handle,
                _tmp_iovec,
                _iovec_count,
                _op);
        if(_res != GLOBUS_SUCCESS)
        {
            _fire_cb = GLOBUS_TRUE;
        }
    }
    if(_fire_cb)
    {
        if(_my_op->_op_ent_fake_iovec != NULL)
        {
            globus_free(_my_op->_op_ent_fake_iovec);
            _my_op->_op_ent_fake_iovec = NULL;
        }
        if(_my_op->caller_ndx == 0 && !_op->blocking)
        {
            _space = _op->_op_handle->space;
        }
        if(_my_op->in_register ||
            _space != GLOBUS_CALLBACK_GLOBAL_SPACE)
        {
            GlobusXIODebugInregisterOneShot();
            globus_callback_space_register_oneshot(
                NULL,
                NULL,
                globus_l_xio_driver_op_write_kickout,
                (void *)_op,
                _space);
        }
        else
        {
            GlobusIXIODriverWriteDeliver(_op);
        }
    }
}

void
globus_xio_driver_write_deliver_DEBUG(
    globus_xio_operation_t                          op)
{
    globus_i_xio_op_t *                             _op;
    globus_i_xio_op_t *                             _close_op;
    globus_i_xio_op_entry_t *                       _my_op;
    globus_i_xio_context_entry_t *                  _my_context;
    globus_i_xio_context_t *                        _context;
    globus_bool_t                                   _close = GLOBUS_FALSE;

    _op = (op);
    _context = _op->_op_context;
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];

    _op->ndx = _my_op->caller_ndx;
    _my_op->_op_ent_data_cb(_op, _op->cached_res, _my_op->_op_ent_nbytes,
                _my_op->user_arg);

    /* LOCK */
    globus_mutex_lock(&_context->mutex);
    {
        _my_context->outstanding_operations--;

        /* if we have a close delayed */
        if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||
            _my_context->state ==
                GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&
            _my_context->outstanding_operations == 0)
        {
            globus_assert(_my_context->close_op != NULL);
            _close = GLOBUS_TRUE;
            _close_op = _my_context->close_op;
        }
    }
    globus_mutex_unlock(&_context->mutex);

    if(_close)
    {
        globus_i_xio_driver_start_close(_close_op, GLOBUS_FALSE);
    }
}

/************************************************************************
 *                           read
 *                           ----
 ***********************************************************************/

void
globus_xio_driver_pass_read_DEBUG(
    globus_result_t *                               _out_res,
    globus_xio_operation_t                          _in_op,
    globus_xio_iovec_t *                            _in_iovec,
    int                                             _in_iovec_count,
    globus_size_t                                   _in_wait_for,
    globus_xio_driver_data_callback_t               _in_cb,
    void *                                          _in_user_arg)
{
    globus_i_xio_op_t *                     _op;
    globus_i_xio_op_entry_t *               _my_op;
    globus_i_xio_context_entry_t *          _next_context;
    globus_i_xio_context_entry_t *          _my_context;
    globus_i_xio_context_t *                _context;
    int                                     _caller_ndx;
    globus_result_t                         _res;
    globus_bool_t                           _close = GLOBUS_FALSE;
    globus_xio_driver_t                     _driver;
    globus_bool_t                           _destroy_handle = GLOBUS_FALSE;
    GlobusXIOName(GlobusXIODriverPassRead);

    _op = (_in_op);
    _context = _op->_op_context;
    _my_context = &_context->entry[_op->ndx];
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;
    _caller_ndx = _op->ndx;

    globus_assert(_op->ndx < _op->stack_size);

    /* error checking */
    globus_assert(_my_context->state == GLOBUS_XIO_HANDLE_STATE_OPEN ||
        _my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED);
    if(_op->canceled)
    {
        _res = GlobusXIOErrorCanceled();
    }
    else if(_my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED)
    {
        if(_op->cached_res == GLOBUS_SUCCESS)
        {
            _op->cached_res = GlobusXIOErrorEOF();
        }
        globus_list_insert(&_my_context->eof_op_list, _op);
        _my_context->outstanding_operations++;
    }
    else
    {
        /* find next slot. start on next and find first interseted */
        do
        {
            _next_context = &_context->entry[_op->ndx];
            _driver = _next_context->driver;
            _op->ndx++;
        }
        while(_driver->read_func == NULL);

        _my_op = &_op->entry[_op->ndx - 1];
        _my_op->caller_ndx = _caller_ndx;
        _my_op->_op_ent_data_cb = (_in_cb);
        _my_op->user_arg = (_in_user_arg);
        _my_op->_op_ent_iovec = (_in_iovec);
        _my_op->_op_ent_iovec_count = (_in_iovec_count);
        _my_op->_op_ent_nbytes = 0;
        _my_op->_op_ent_wait_for = (_in_wait_for);
        /* set the callstack flag */

        globus_mutex_lock(&_context->mutex);
        {
            _my_context->outstanding_operations++;
            _my_context->read_operations++;
            _op->ref++;
        }
        globus_mutex_unlock(&_context->mutex);
        _my_op->in_register = GLOBUS_TRUE;

        _res = _driver->read_func(
                        _next_context->driver_handle,
                        _my_op->_op_ent_iovec,
                        _my_op->_op_ent_iovec_count,
                        _op);

        /* flip the callstack flag */
        _my_op->in_register = GLOBUS_FALSE;
        globus_mutex_lock(&_context->mutex);
        {
            _op->ref--;
            if(_op->ref == 0)
            {
                GlobusXIOOperationDestroy(_op);
                GlobusIXIOHandleDec(_destroy_handle, _op->_op_handle);
                /* we cannot be set to destroy yet, because handle has not
                    yet finished the close process */
                globus_assert(!_destroy_handle);
            }

            if(_res != GLOBUS_SUCCESS)
            {
                _my_context->outstanding_operations--;
                _my_context->read_operations--;
                if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||
                    _my_context->state ==
                       GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&
                    _my_context->outstanding_operations == 0)
                {
                    globus_assert(_my_context->close_op != NULL);
                    _close = GLOBUS_TRUE;
                }
            }
        }
        globus_mutex_unlock(&_context->mutex);
    }

    if(_close)
    {
        globus_i_xio_driver_start_close(_my_context->close_op,
                GLOBUS_FALSE);
    }

    GlobusXIODebugSetOut(_out_res, _res);
}


void
globus_xio_driver_finished_read_DEBUG(
    globus_xio_operation_t                          op,
    globus_result_t                                 result,
    globus_size_t                                   nbytes)
{
    globus_i_xio_op_t *                             _op;
    globus_i_xio_op_entry_t *                       _my_op;
    globus_result_t                                 _res;
    globus_bool_t                                   _fire_cb = GLOBUS_TRUE;
    globus_xio_iovec_t *                            _tmp_iovec;
    globus_i_xio_context_entry_t *                  _my_context;
    globus_i_xio_context_entry_t *                  _next_context;
    globus_i_xio_context_t *                        _context;
    int                                             _iovec_count;
    globus_callback_space_t                 _space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(GlobusXIODriverFinishedRead);

    _op = (globus_i_xio_op_t *)(op);
    _res = (result);
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    _context = _op->_op_context;
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];
    _op->cached_res = _res;

    globus_assert(_op->ndx > 0);
    globus_assert(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPENING &&
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_CLOSED &&
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED &&
        _my_context->state !=
            GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING);

    _my_op->_op_ent_nbytes += nbytes;

    if(_res != GLOBUS_SUCCESS && globus_xio_error_is_eof(_res))
    {
        globus_mutex_lock(&_context->mutex);
        {
            switch(_my_context->state)
            {
                case GLOBUS_XIO_HANDLE_STATE_OPEN:
                    _my_context->state =
                        GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED;
                    break;

                case GLOBUS_XIO_HANDLE_STATE_CLOSING:
                    _my_context->state =
                        GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING;
                    break;

                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING:
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:
                    break;

                default:
                    globus_assert(0);
                    break;
            }
            _my_context->read_eof = GLOBUS_TRUE;
            _my_context->read_operations--;
            if(_my_context->read_operations > 0)
            {
                globus_list_insert(&_my_context->eof_op_list, _op);
                _fire_cb = GLOBUS_FALSE;
            }
        }
        globus_mutex_unlock(&_context->mutex);
    }
    /* if not all bytes were read */
    else if(_my_op->_op_ent_nbytes < _my_op->_op_ent_wait_for &&
        _res == GLOBUS_SUCCESS)
    {
        /* if not enough bytes read set the fire_cb deafult to false */
        _fire_cb = GLOBUS_FALSE;
        /* allocate tmp iovec to the bigest it could ever be */
        if(_my_op->_op_ent_fake_iovec == NULL)
        {
            _my_op->_op_ent_fake_iovec = (globus_xio_iovec_t *)
                globus_malloc(sizeof(globus_xio_iovec_t) *
                    _my_op->_op_ent_iovec_count);
        }
        _tmp_iovec = _my_op->_op_ent_fake_iovec;

        GlobusIXIOUtilTransferAdjustedIovec(
            _tmp_iovec, _iovec_count,
            _my_op->_op_ent_iovec, _my_op->_op_ent_iovec_count,
            _my_op->_op_ent_nbytes);

        _next_context = &_context->entry[_op->ndx - 1];
        /* repass the operation down */
        _res = _next_context->driver->read_func(
                _next_context->driver_handle,
                _tmp_iovec,
                _iovec_count,
                _op);
        if(_res != GLOBUS_SUCCESS)
        {
            _fire_cb = GLOBUS_TRUE;
        }
    }

    if(_fire_cb)
    {
        /* if a temp iovec struct was used for fullfulling waitfor,
          we can free it now */
        if(_my_op->_op_ent_fake_iovec != NULL)
        {
            globus_free(_my_op->_op_ent_fake_iovec);
            _my_op->_op_ent_fake_iovec = NULL;
        }

        if(_my_op->caller_ndx == 0 && !_op->blocking)
        {
            _space = _op->_op_handle->space;
        }
        if(_my_op->in_register ||
            _space != GLOBUS_CALLBACK_GLOBAL_SPACE)
        {
            _op->cached_res = (_res);
            GlobusXIODebugInregisterOneShot();
            globus_callback_space_register_oneshot(
                NULL,
                NULL,
                globus_l_xio_driver_op_read_kickout,
                (void *)_op,
                _space);
        }
        else
        {
            GlobusIXIODriverReadDeliver(_op);
        }
    }
}


void
globus_xio_driver_read_deliver_DEBUG(
    globus_xio_operation_t                          op)
{
    globus_i_xio_op_t *                             _op;
    globus_i_xio_op_entry_t *                       _my_op;
    globus_i_xio_context_entry_t *                  _my_context;
    globus_bool_t                                   _purge;
    globus_bool_t                                   _close = GLOBUS_FALSE;
    globus_i_xio_context_t *                        _context;
    GlobusXIOName(GlobusIXIODriverReadDeliver);

    GlobusXIODebugInternalEnter();

    _op = (op);
    _context = _op->_op_context;
    _my_op = &_op->entry[_op->ndx - 1];
    _my_context = &_context->entry[_my_op->caller_ndx];

    /* call the callback */
    _op->ndx = _my_op->caller_ndx;
    _my_op->_op_ent_data_cb(_op, _op->cached_res, _my_op->_op_ent_nbytes,
                _my_op->user_arg);


    globus_mutex_lock(&_context->mutex);
    {
        _purge = GLOBUS_FALSE;
        if(_my_context->read_eof)
        {
            switch(_my_context->state)
            {
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:
                    _purge = GLOBUS_TRUE;
                    _my_context->state =
                        GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED;
                    break;

                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING:
                    _purge = GLOBUS_TRUE;
                    _my_context->state =
                        GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING;
                    break;

                case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING:
                case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED:
                    break;

                default:
                    globus_assert(0);
            }

            /* if we get an operation with EOF type we definitly must
               have no outstanding reads */
            globus_assert(_my_context->read_operations == 0);
        }
        else
        {
            _my_context->read_operations--;
            /* if no more read operations are outstanding and we are waiting
             * on EOF, purge eof list */
            if(_my_context->read_operations == 0 &&
                (_my_context->state ==
                    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED ||
                 _my_context->state ==
                    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING))
            {
                _purge = GLOBUS_TRUE;
            }
        }

        _my_context->outstanding_operations--;
        if(_purge)
        {
             globus_l_xio_driver_purge_read_eof(_my_context);
        }

        if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||
            _my_context->state ==
                GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&
           _my_context->outstanding_operations == 0)
        {
            _close = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&_context->mutex);

    if(_close)
    {
        globus_i_xio_driver_start_close(_my_context->close_op,
                GLOBUS_FALSE);
    }
    GlobusXIODebugInternalExit();
}


/************************************************************************
 *                          accept
 *                          ------
 ***********************************************************************/

void
globus_xio_driver_pass_accept_DEBUG(
    globus_result_t *                               _out_res,
    globus_xio_operation_t                          _in_op,
    globus_xio_driver_callback_t                    _in_cb,
    void *                                          _in_user_arg)
{
    globus_i_xio_op_t *                             _op;
    globus_i_xio_server_t *                         _server;
    globus_i_xio_server_entry_t *                   _my_server;
    globus_i_xio_op_entry_t *                       _my_op;
    int                                             _caller_ndx;
    globus_result_t                                 _res;
    globus_xio_driver_t                             _driver;
    GlobusXIOName(GlobusXIODriverPassServerAccept);

    _op = (globus_i_xio_op_t *)(_in_op);
    globus_assert(_op->ndx < _op->stack_size);
    _server = _op->_op_server;
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    if(_op->canceled)
    {
        _res = GlobusXIOErrorCanceled();
    }
    else
    {
        _caller_ndx = _op->ndx;
        do
        {
            _my_op = &_op->entry[_op->ndx];
            _my_server = &_server->entry[_op->ndx];
            _driver = _my_server->driver;
            _op->ndx++;
        }
        while(_driver->server_accept_func == NULL);

        _my_op->cb = (_in_cb);
        _my_op->user_arg = (_in_user_arg);
        _my_op->caller_ndx = (_caller_ndx);
        _my_op->in_register = GLOBUS_TRUE;

        _res = _driver->server_accept_func(
                    _my_server->server_handle,
                    _my_op->attr,
                    _op);
        _my_op->in_register = GLOBUS_FALSE;
    }
    GlobusXIODebugSetOut(_out_res, _res);
}


void
globus_xio_driver_finished_accept_DEBUG(
    globus_xio_operation_t                          _in_op,
    void *                                          _in_target,
    globus_result_t                                 _in_res)
{
    globus_i_xio_op_t *                             _op;
    globus_i_xio_op_entry_t *                       _my_op;
    globus_callback_space_t                 _space =
                            GLOBUS_CALLBACK_GLOBAL_SPACE;
    GlobusXIOName(GlobusXIODriverFinishedAccept);

    _op = (globus_i_xio_op_t *)(_in_op);
    globus_assert(_op->ndx > 0);
    _op->progress = GLOBUS_TRUE;
    _op->block_timeout = GLOBUS_FALSE;

    _my_op = &_op->entry[_op->ndx - 1];
    _op->cached_res = (_in_res);

    _my_op->target = (_in_target);

    if(_my_op->caller_ndx == 0 && !_op->blocking)
    {
        _space = _op->_op_server->space;
    }
    if(_my_op->in_register ||
        _space != GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        GlobusXIODebugInregisterOneShot();
        globus_callback_space_register_oneshot(
            NULL,
            NULL,
            globus_l_xio_driver_op_kickout,
            (void *)_op,
            _space);
    }
    else
    {
        _op->ndx = _my_op->caller_ndx;
        _my_op->cb(_op, _op->cached_res, _my_op->user_arg);
    }
}


