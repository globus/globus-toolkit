#if !defined(GLOBUS_XIO_PASS_MACRO_H)
#define GLOBUS_XIO_PASS_MACRO_H 1

#include "globus_common.h"

/************************************************************************
 *                      attribute macros
 ***********************************************************************/
#define GlobusIXIOAttrGetDS(ds, attr, driver)                               \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_attr_t *                       _attr;                      \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _attr = (attr);                                                         \
    _driver = (driver);                                                     \
                                                                            \
    _entry = _attr->entry;                                                  \
    for(_ctr = 0; _ctr < _attr->ndx && _ds == NULL; _ctr++)                 \
    {                                                                       \
        if(_entry[_ctr].driver == driver)                                   \
        {                                                                   \
            _ds = entry[ctr].driver_data;                                   \
        }                                                                   \
    }                                                                       \
    ds = _ds;                                                               \
} while(0)
    
#define GlobusIXIODDGetDS(ds, dd, driver)                                   \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_dd_t *                         _dd;                        \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _dd = (dd);                                                             \
    _driver = (driver);                                                     \
                                                                            \
    _entry = _dd->entry;                                                    \
    for(_ctr = 0; _ctr < _dd->stack_size && _ds == NULL; _ctr++)            \
    {                                                                       \
        if(_entry[_ctr].driver == driver)                                   \
        {                                                                   \
            _ds = entry[ctr].driver_data;                                   \
        }                                                                   \
    }                                                                       \
    ds = _ds;                                                               \
} while(0)

/************************************************************************
 *                      pass macros
 ***********************************************************************/

/*
 *  for the server
 */
#define GlobusXIODriverPassServerAccept(res, op, cb, user_arg)              \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_server_t *                         _server;                \
    globus_i_xio_op_entry_t *                       _next_entry;            \
    globus_i_xio_op_entry_t *                       _my_entry;              \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    _server = _op->_op_server;                                              \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    if(_op->canceled)                                                       \
    {                                                                       \
        out_res = OperationHasBeenCacneled();                               \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->timeout_blocked = GLOBUS_FALSE;                                \
        _my_entry = &_op->entry[_op->ndx];                                  \
        _my_entry->cb = (cb);                                               \
        _my_entry->user_arg = (user_arg);                                   \
        _my_entry->in_register = GLOBUS_TRUE;                               \
        _caller_ndx = _op->ndx;                                             \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_entry = &_op->entry[_op->ndx];                            \
        }                                                                   \
        while(_next_entry->driver->server_accept_func == NULL)              \
        _next_entry->caller_ndx = _caller_ndx;                              \
                                                                            \
        /* at time that stack is built this will be varified */             \
        globus_assert(_op->ndx <= _op->stack_size);                         \
        res = _next_entry->driver->server_accept_func(                      \
                    _server->entry[_op->ndx]->server_handle,                \
                    _my_entry->_op_ent_accept_attr,                         \
                    _op);                                                   \
        _my_entry->in_register = GLOBUS_FALSE;                              \
    }                                                                       \
}

#define GlobusXIODriverFinishedAccept(op, target, result)                   \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->timeout_blocked = GLOBUS_FALSE;                                    \
                                                                            \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _op->ndx = _caller_ndx;                                                 \
    _op->entry[_op->ndx].target = (target);                                 \
                                                                            \
    if(_op->entry[_op->ndx].in_register)                                    \
    {                                                                       \
        _op->cached_res = (result);                                         \
        globus_callback_space_register_oneshot(                             \
            NULL,                                                           \
            NULL,                                                           \
            globus_l_xio_driver_op_kickout,                                 \
            (void *)_op,                                                    \
            GLOBUS_CALLBACK_GLOBAL_SPACE);                                  \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->entry[_op->ndx].cb(_op, result,                                \
            _op->entry[_op->ndx].user_arg);                                 \
    }                                                                       \
} while(0)

/*
 *  Open
 */
/* open does not need to lock */
#define GlobusXIODriverPassOpen(out_res, out_context, op, cb, user_arg)     \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_handle_t *                         _handle;                \
    globus_i_xio_context_t *                        _context;               \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_op_entry_t *                       _next_op;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    int                                             _caller_ndx;            \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    _op = (op);                                                             \
    _handle = _op->_op_handle;                                              \
    _context = _handle->contex;                                             \
    _my_context = &_context->entry[_op->ndx];                               \
    _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPENING;                   \
    _caller_ndx = _op->ndx;                                                 \
                                                                            \
    if(_op->canceled)                                                       \
    {                                                                       \
        out_res = OperationHasBeenCacneled();                               \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->timeout_blocked = GLOBUS_FALSE;                                \
        _my_op = &_op->entry[_op->ndx];                                     \
        _my_op->cb = (cb);                                                  \
        _my_op->user_arg = (user_arg);                                      \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_op = &_op->entry[_op->ndx];                               \
            _next_context = &_context->entry[_op->ndx];                     \
        }                                                                   \
        while(_next_op->driver->transport_open == NULL &&                   \
              _next_op->driver->transform_open == NULL);                    \
        _next_op->caller_ndx = _caller_ndx;                                 \
        /* at time that stack is built this will be varified */             \
        globus_assert(_op->ndx <= _server->stack_size);                     \
        if(_op->ndx == _op->stack_size)                                     \
        {                                                                   \
            out_res = _next_context->driver->transport_open(                \
                        _next_op->target,                                   \
                        _next_op->attr,                                     \
                        _context,                                           \
                        _op);                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            out_res = _next_context->driver->transform_open(                \
                        _next_op->target,                                   \
                        _next_op->attr,                                     \
                        _op);                                               \
        }                                                                   \
        _my_op->in_register = GLOBUS_FALSE;                                 \
        out_context = _context;                                             \
    }                                                                       \
} while(0)


/* open does not need to lock */
#define GlobusXIODriverFinishedOpen(context, dh, op, res)                   \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_t *                        _context;               \
    globus_i_xio_op_entry_t *                       _next_op;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_result_t                                 _res;                   \
    int                                             _caller_ndx;            \
                                                                            \
    _res = (res);                                                           \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->timeout_blocked = GLOBUS_FALSE;                                    \
                                                                            \
    /*                                                                      \
     * this means that we are finishing with a different context            \
     * copy the finishing one into the operations;                          \
     */                                                                     \
    if(_op->context != _context && _context != NULL)                        \
    {                                                                       \
        /* iterate through them all and copy handles into new slot */       \
        for(ctr = _op->ndx + 1; ctr < _op->stack_size; ctr++)               \
        {                                                                   \
            _op->context[ctr].driver_handle = _control[ctr].driver_handle;  \
        }                                                                   \
    }                                                                       \
                                                                            \
    _context = _op->context;                                                \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _my_context = &_context->entry[_caller_ndx];                            \
    _my_context->driver_handle = (dh);                                      \
    _my_op = _op->entry[_caller_ndx];                                       \
    /* no operation can happen while in OPENING state so no need to lock */ \
    if((res) != GLOBUS_SUCCESS)                                             \
    {                                                                       \
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPEN;                  \
    }                                                                       \
                                                                            \
    _op->ndx = _caller_ndx;                                                 \
    if(!_my_op->is_limited)                                                 \
    {                                                                       \
        /* if still in register call stack or at top level and a user       \
           requested a callback space */                                    \
        if(_my_op->.in_register ||                                          \
            _my_context->space != GLOBUS_CALLBACK_GLOBAL_SPACE)             \
        {                                                                   \
            _op->cached_res = _res;                                         \
            globus_callback_space_register_oneshot(                         \
                NULL,                                                       \
                NULL,                                                       \
                globus_l_xio_driver_op_kickout,                             \
                (void *)_op,                                                \
                _my_context->space);                                        \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _op->entry[_op->ndx].cb(_op, _res,                              \
                _op->entry[_op->ndx].user_arg);                             \
        }                                                                   \
    }                                                                       \
} while(0)

/*
 *  Close
 */
#define GlobusXIODriverPassClose(out_res, op, cb, user_arg)                 \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_handle_t *                         _handle;                \
    globus_i_xio_context_t *                        _my_context;            \
    globus_bool_t *                                 _pass;                  \
    globus_i_xio_op_entry_t *                       _my_op;                 \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    _op = (op);                                                             \
    _handle = _op->_op_handle;                                              \
    _context = _handle->contex;                                             \
    _my_op = &_op->entry[_op->ndx];                                         \
                                                                            \
    /* deal with context state */                                           \
    globus_mutex_lock(&_my_context->mutex);                                 \
    {                                                                       \
        switch(_my_context->state)                                          \
        {                                                                   \
            case GLOBUS_XIO_HANDLE_STATE_OPEN:                              \
                _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;       \
                break;                                                      \
                                                                            \
            case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:                      \
                _my_context->state =                                        \
                    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING;       \
                break                                                       \
                                                                            \
            case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED:                     \
                _my_context->state =                                        \
                    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING;      \
                break;                                                      \
                                                                            \
            default:                                                        \
                globus_assert(0);                                           \
        }                                                                   \
        /* a barrier will never happen if the level above already did the   \
            close barrier and this level has not created any driver ops.    \
            in this case outstanding_operations is garentueed to be zero    \
         */                                                                 \
        if(_my_context->outstanding_operations == 0)                        \
        {                                                                   \
            _pass = GLOBUS_TRUE;                                            \
        }                                                                   \
        /* cache the op for close barrier */                                \
        else                                                                \
        {                                                                   \
            _pass = GLOBUS_FALSE;                                           \
            _my_context->close_op = _op;                                    \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(&_my_context->mutex);                               \
                                                                            \
    _my_op->cb = (cb);                                                      \
    _my_op->user_arg = (user_arg);                                          \
    /* op can be checked outside of lock */                                 \
    if(_op->canceled)                                                       \
    {                                                                       \
        out_res = OperationHasBeenCacneled();                               \
    }                                                                       \
    else if(_pass)                                                          \
    {                                                                       \
        out_res = globus_i_xio_driver_start_close(_op, GLOBUS_TRUE);        \
    }                                                                       \
                                                                            \
    if(out_res != GLOBUS_SUCCESS)                                           \
    {                                                                       \
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                \
    }                                                                       \
} while(0)


#define GlobusXIODriverFinishedClose(op, res)                               \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_t *                        _context;               \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
                                                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->timeout_blocked = GLOBUS_FALSE;                                    \
                                                                            \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _context = _op->context;                                                \
    _my_context = &context->entry[_caller_ndx];                             \
    _my_op = &_op->entry[_caller_ndx];                                      \
    /* don't need to lock because barrier makes contntion not possible */   \
    _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                    \
                                                                            \
    _op->ndx = _caller_ndx;                                                 \
    globus_assert(_op->ndx >= 0); /* otherwise we are not in bad memory */  \
    /* space is only not global by user request in the top level of the     \
     * of operations */                                                     \
    _op->cached_res = (result);                                             \
    if(_my_op->in_register ||                                               \
            _my_context->space != GLOBUS_CALLBACK_GLOBAL_SPACE)             \
    {                                                                       \
        globus_callback_space_register_oneshot(                             \
            NULL,                                                           \
            NULL,                                                           \
            globus_l_xio_driver_op_kickout,                                 \
            (void *)_op,                                                    \
            _my_context->space);                                            \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _my_op->cb(_op, _op->cached_res, _my_op->user_arg);                 \
    }                                                                       \
                                                                            \
} while(0)


/*
 *  write
 */
#define GlobusXIODriverPassWrite(out_res, op, iovec, iovec_count,           \
    cb, wait_for, user_arg)                                                 \
do                                                                          \
{                                                                           \
    globus_i_xio_operation_t *                      _op;                    \
    globus_i_xio_op_entry_t *                       _next_op;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_context_t *                        _context;               \
    globus_bool_t                                   _close = GLOBUS_FALSE;  \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (op);                                                             \
    _context = _op->context;                                                \
    _my_context = &_context->entry[_op->ndx];                               \
    _my_op = &_op->entry[_op->ndx];                                         \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
                                                                            \
    globus_mutex_lock(&_my_context->mutex);                                 \
                                                                            \
    /* error checking */                                                    \
    if(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPEN &&                \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED &&       \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_DELIVERED)            \
    {                                                                       \
        out_res = GlobusXIOErrorNotOpen("GlobusXIODriverPassWrite");        \
    }                                                                       \
    else if(_op->canceled)                                                  \
    {                                                                       \
        out_res = GlobusXIOErrorOperationCanceled(                          \
                        "GlobusXIODriverPassWrite");                        \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->timeout_blocked = GLOBUS_FALSE;                                \
        /* set up the entry */                                              \
        _my_op = &_op->entry[_op->ndx];                                     \
        _my_op->data_cb = (cb);                                             \
        _my_op->user_arg = (user_arg);                                      \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        _my_op->iovec = (iovec);                                            \
        _my_op->iovec_count = (iovec_count);                                \
        _my_op->nwritten = 0;                                               \
        _my_op->wait_for = (wait_for);                                      \
        /* set the callstack flag */                                        \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        _caller_ndx = _op->ndx;                                             \
        /* find next slot. start on next and find first interseted */       \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_op = &_op->entry[_op->ndx];                               \
            _next_context = &_context->entry[_op->ndx];                     \
        }                                                                   \
        while(_next_context->driver->write_func == NULL)                    \
                                                                            \
        _my_context->outstanding_operations++;                              \
        _next_op->caller_ndx = _caller_ndx;                                 \
                                                                            \
        /* UNLOCK */                                                        \
        globus_mutex_unlock(&_context->mutex);                              \
                                                                            \
        out_res = _next_context->driver->write_func(                        \
                        _next_context->driver_handle,                       \
                        _my_op->iovec,                                      \
                        _my_op->iovec_count,                                \
                        _op);                                               \
                                                                            \
        /* LOCK */                                                          \
        globus_mutex_lock(&_context->mutex);                                \
                                                                            \
        /* flip the callstack flag */                                       \
        _my_op->in_register = GLOBUS_FALSE;                                 \
        if(out_res != GLOBUS_SUCCESS)                                       \
        {                                                                   \
            _my_context->outstanding_operations--;                          \
            /* there is an off chance that we could need to close here */   \
           if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||     \
                _my_context->state ==                                       \
                    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&   \
                _my_context->outstanding_operations == 0)                   \
            {                                                               \
                globus_assert(_my_context->close_op != NULL);               \
                _close = GLOBUS_TRUE;                                       \
            }                                                               \
        }                                                                   \
        out_context = _context;                                             \
    }                                                                       \
    globus_mutex_unlock(&_context->mutex);                                  \
                                                                            \
    if(_close)                                                              \
    {                                                                       \
        globus_i_xio_driver_start_close(_op, GLOBUS_FALSE);                 \
    }                                                                       \
} while(0)


#define GlobusXIODriverFinishedWrite(op, result, nbytes)                    \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_result_t                                 _res;                   \
    globus_bool_t                                   _fire_cb = GLOBUS_TRUE; \
    globus_iovec_t *                                _tmp_iovec;             \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_context_t *                        _context;               \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    globus_assert(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPENING &&  \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_CLOSED);              \
    _op->progress = GLOBUS_TRUE;                                            \
                                                                            \
    _caller_ndx =_op->entry[_op->ndx].caller_ndx;                           \
    _my_op = &_op->entry[_caller_ndx];                                      \
    _context = _op->context;                                                \
    _my_context = _context->entry[_caller_ndx];                             \
    _res = (result);                                                        \
                                                                            \
    _my_op->_op_ent_nbytes += nbytes;                                       \
    /* if not all bytes were written */                                     \
    if(_my_op->_op_ent_nbytes < _my_op->_op_ent_wait_for &&                 \
        _res == GLOBUS_SUCCESS)                                             \
    {                                                                       \
        /* if not enough bytes read set the fire_cb deafult to false */     \
        fire_cb = GLOBUS_FALSE;                                             \
        /* allocate tmp iovec to the bigest it could ever be */             \
        if(_my_op->_op_ent_fake_iovec == NULL)                              \
        {                                                                   \
            _my_op->_op_ent_fake_iovec = (globus_iovec_t *)                 \
                globus_malloc(sizeof(globus_iovec_t) *                      \
                    _my_op->_op_ent_iovec_count);                           \
        }                                                                   \
        _tmp_iovec = _my_op->_op_ent_fake_iovec;                            \
                                                                            \
        GlobusIXIOSystemTransferAdjustedIovec(                              \
            _tmp_iovec, _iovec_count,                                       \
            _my_op->_op_ent_iovec, _my_op->_op_ent_iovec_count,             \
            _my_op->_op_ent_nwritten);                                      \
                                                                            \
        _next_context = &_context->entry[_op->ndx];                         \
        /* repass the operation down */                                     \
        _res = _next_context->driver->write_func(                           \
                _next_context->driver_handle,                               \
                _tmp_iovec,                                                 \
                _iovec_count,                                               \
                _op);                                                       \
        if(_res != GLOBUS_SUCCESS)                                          \
        {                                                                   \
            fire_cb = GLOBUS_TRUE;                                          \
        }                                                                   \
    }                                                                       \
    if(fire_cb)                                                             \
    {                                                                       \
        _op->ndx = _caller_ndx;                                             \
        _op->cached_res = _res;                                             \
        if(_my_entry->fake_iovec != NULL)                                   \
        {                                                                   \
            globus_free(_my_op->fake_iovec);                                \
        }                                                                   \
        if(_my_op->in_register)                                             \
        {                                                                   \
            globus_callback_space_register_oneshot(                         \
                NULL,                                                       \
                NULL,                                                       \
                globus_l_xio_driver_op_write_kickout,                       \
                (void *)_op,                                                \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                              \
        }                                                                   \
        else                                                                \
        {                                                                   \
            GlobusIXIODriverWriteDeliver(_op);                              \
        }                                                                   \
    }                                                                       \
} while(0)

#define GlobusIXIODriverWriteDeliver(op)                                    \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_bool_t                                   _purge;                 \
    globus_bool_t                                   _close = GLOBUS_FALSE;  \
                                                                            \
    _op = (op);                                                             \
    _my_op = &_op->entry[_op->ndx];                                         \
    _my_context = &_op->context.entry[_op->ndx];                            \
                                                                            \
    _my_op->_op_ent_data_cb(_op, _op->cached_res, _my_op->nbytes,           \
                _my_op->user_arg);                                          \
                                                                            \
    /* LOCK */                                                              \
    globus_mutex_lock(&_my_context->mutex);                                 \
    {                                                                       \
        _my_context->outstanding_operations--;                              \
                                                                            \
        /* if we have a close delayed */                                    \
        if((_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING ||        \
            _my_context->state ==                                           \
                GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING) &&       \
            _my_context->outstanding_operations == 0)                       \
        {                                                                   \
            globus_assert(_my_context->close_op != NULL);                   \
            _close = GLOBUS_TRUE;                                           \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(&_my_context->mutex);                               \
                                                                            \
    if(_close)                                                              \
    {                                                                       \
        globus_i_xio_driver_start_close(_op, GLOBUS_FALSE);                 \
    }                                                                       \
} while(0)
/*
 *  read
 */
#define GlobusXIODriverPassRead(out_res, op, iovec, iovec_count,           \
    cb, wait_for, user_arg)                                                 \
do                                                                          \
{                                                                           \
    globus_i_xio_operation_t *                      _op;                    \
    globus_i_xio_op_entry_t *                       _next_op;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_context_t *                        _context;               \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (op);                                                             \
    _context = _op->context;                                                \
    _my_context = _context->entry[_op->ndx];                                \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
                                                                            \
    /* LOCK */                                                              \
    globus_mutex_lock(&_context->mutex);                                    \
                                                                            \
    /* error checking */                                                    \
    if(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPEN &&                \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED)         \
    {                                                                       \
        out_res = GlobusXIOErrorNotOpen("GlobusXIODriverPassRead");         \
    }                                                                       \
    else if(_op->canceled)                                                  \
    {                                                                       \
        out_res = GlobusXIOErrorOperationCanceled(                          \
                        "GlobusXIODriverPassRead");                         \
    }                                                                       \
    else if(_my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED)     \
    {                                                                       \
        _my_context->cached_res = GlobusXIOErrorReadEOF();                  \
        globus_list_insert(&_my_context->eof_op_list, _op);                 \
        _my_context->outstanding_operations++;                              \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->timeout_blocked = GLOBUS_FALSE;                                \
        /* set up the entry */                                              \
        _my_op = &_op->entry[_op->ndx];                                     \
        _my_op->data_cb = (cb);                                             \
        _my_op->user_arg = (user_arg);                                      \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        _my_op->iovec = (iovec);                                            \
        _my_op->iovec_count = (iovec_count);                                \
        _my_op->nread = 0;                                                  \
        _my_op->wait_for = (wait_for);                                      \
        /* set the callstack flag */                                        \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        _caller_ndx = _op->ndx;                                             \
        /* find next slot. start on next and find first interseted */       \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_op = &_op->entry[_op->ndx];                               \
        }                                                                   \
        while(_next_op->driver->write_func == NULL)                         \
                                                                            \
        _next_context = _context->entry[_op->ndx];                          \
        _next_op->caller_ndx = caller_ndx;                                  \
        _my_context->outstanding_operations++;                              \
        _my_context->read_operations++;                                     \
                                                                            \
        /* UNLOCK */                                                        \
        globus_mutex_unlock(&_context->mutex);                              \
                                                                            \
        out_res = _next_context->driver->read_func(                         \
                        _next_context->driver_handle,                       \
                        _my_entry->iovec,                                   \
                        _my_entry->iovec_count,                             \
                        _op);                                               \
                                                                            \
        /* LOCK */                                                          \
        globus_mutex_lock(&_context->mutex);                                \
                                                                            \
        /* flip the callstack flag */                                       \
        _my_op->in_register = GLOBUS_FALSE;                                 \
        if(out_res != GLOBUS_SUCCESS)                                       \
        {                                                                   \
            _my_context->outstanding_operations--;                        \
            _my_context->read_operations--;                               \
        }                                                                   \
        out_context = _op->context;                                         \
    }                                                                       \
                                                                            \
    globus_mutex_unlock(&_context->mutex);                                  \
} while(0)


#define GlobusXIODriverFinishedRead(op, result, nread)                      \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_result_t                                 _res;                   \
    globus_bool_t                                   _fire_cb = GLOBUS_TRUE; \
    globus_iovec_t *                                _tmp_iovec;             \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    globus_assert(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPENING &&  \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_CLOSED &&             \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED &&      \
        _my_context->state !=                                               \
            GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING);             \
    _op->progress = GLOBUS_TRUE;                                            \
                                                                            \
    /* deal with wait for stuff */                                          \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _my_op = &_op->entry[_caller_ndx];                                      \
    _my_context = &_op->context.entry[_caller_ndx];                         \
    _next_context = &_op->context.entry[_op->ndx];                          \
    _res = (result);                                                        \
    _my_op->_op_ent_nbytes += nbytes;                                       \
    _op->ndx = _caller_ndx;                                                 \
                                                                            \
    if(GlobusXIOErrorIsEOF(result))                                         \
    {                                                                       \
        globus_mutex_lock(&_my_context->mutex);                             \
        {                                                                   \
            switch(_my_context->state)                                      \
            {                                                               \
                case GLOBUS_XIO_HANDLE_STATE_OPEN:                          \
                    _my_context->state =                                    \
                        GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED;               \
                    break;                                                  \
                                                                            \
                case GLOBUS_XIO_HANDLE_STATE_CLOSING:                       \
                    _my_context->state =                                    \
                        GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING;   \
                    break;                                                  \
                                                                            \
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING:      \
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:                  \
                    break;                                                  \
                                                                            \
                default:                                                    \
                    globus_assert(0);                                       \
                    break;                                                  \
            }                                                               \
            _my_op->eof = GLOBUS_TRUE;                                      \
            _my_context->read_operations--;                                 \
            if(_my_context->read_operations > 0)                            \
            {                                                               \
                globus_list_insert(&_my_context->eof_op_list, _op);         \
                _fire_cb = GLOBUS_FALSE;                                    \
            }                                                               \
            op->cached_res = (result);                                      \
        }                                                                   \
        globus_mutex_unlock(&_my_context->mutex);                           \
    }                                                                       \
    /* if not all bytes were read */                                        \
    else if(_my_op->_op_ent_nbytes < _my_op->_op_ent_wait_for &&            \
        _res == GLOBUS_SUCCESS)                                             \
    {                                                                       \
        /* if not enough bytes read set the fire_cb deafult to false */     \
        fire_cb = GLOBUS_FALSE;                                             \
        /* allocate tmp iovec to the bigest it could ever be */             \
        if(_my_op->_op_ent_fake_iovec == NULL)                              \
        {                                                                   \
            _my_op->_op_ent_fake_iovec = (globus_iovec_t *)                 \
                globus_malloc(sizeof(globus_iovec_t) *                      \
                    _my_op->_op_ent_iovec_count);                           \
        }                                                                   \
        _tmp_iovec = _my_op->_op_ent_fake_iovec;                            \
                                                                            \
        GlobusIXIOSystemTransferAdjustedIovec(                              \
            _tmp_iovec, _iovec_count,                                       \
            _my_op->_op_ent_iovec, _my_op->_op_ent_iovec_count,             \
            _my_op->_op_ent_nbytes);                                        \
                                                                            \
        /* repass the operation down */                                     \
        _res = _next_context->driver->read_func(                            \
                _next_context->driver_handle,                               \
                _tmp_iovec,                                                 \
                _iovec_count,                                               \
                _op);                                                       \
        if(_res != GLOBUS_SUCCESS)                                          \
        {                                                                   \
            fire_cb = GLOBUS_TRUE;                                          \
        }                                                                   \
    }                                                                       \
                                                                            \
    if(_fire_cb)                                                            \
    {                                                                       \
        if(_my_op->in_register)                                             \
        {                                                                   \
            _op->cached_res = (_res);                                       \
            globus_callback_space_register_oneshot(                         \
                NULL,                                                       \
                NULL,                                                       \
                globus_l_xio_driver_op_read_kickout,                        \
                (void *)_op,                                                \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                              \
        }                                                                   \
        else                                                                \
        {                                                                   \
            GlobusIXIODriverReadDeliver(_op);                               \
        }                                                                   \
    }                                                                       \
} while(0)

#define GlobusIXIODriverReadDeliver(op)                                     \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_bool_t                                   _purge;                 \
    globus_bool_t                                   _close = GLOBUS_FALSE;  \
                                                                            \
    _op = (op);                                                             \
    _my_op = &_op->entry[_op->ndx];                                         \
    _my_context = &_op->context.entry[_op->ndx];                            \
                                                                            \
    /* call the callback */                                                 \
    _my_op->cb(_op, _res, _my_op->user_arg);                                \
                                                                            \
    /* if a temp iovec struct was used for fullfulling waitfor,             \
      we can free it now */.                                                \
    if(_my_op->fake_iovec != NULL)                                          \
    {                                                                       \
        globus_free(_my_entry->fake_iovec);                                 \
    }                                                                       \
                                                                            \
    globus_mutex_lock(&_my_context->mutex);                                 \
    {                                                                       \
        _purge = GLOBUS_FALSE;                                              \
        if(_my_op->read_eof)                                                \
        {                                                                   \
            switch(_my_context->state)                                      \
            {                                                               \
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:                  \
                    _purge = GLOBUS_TRUE;                                   \
                    _my_context->state =                                    \
                        GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED;              \
                    break;                                                  \
                                                                            \
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING:      \
                    _purge = GLOBUS_TRUE;                                   \
                    _my_context->state =                                    \
                        GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING;  \
                    break;                                                  \
                                                                            \
                case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING:     \
                case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED:                 \
                    break;                                                  \
                                                                            \
                default:                                                    \
                    globus_assert(0);                                       \
            }                                                               \
                                                                            \
            /* if we get an operation with EOF type we definitly must       \
               have no outstanding reads */                                 \
            globus_assert(_my_context->read_operations == 0);               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _my_context->read_operations--;                                 \
            /* if no more read operations are outstanding and we are waiting\
             * on EOF, purge eof list */                                    \
            if(_my_context->read_operations == 0 &&                         \
                (_my_context->state ==                                      \
                    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED ||                 \
                 _my_context->state ==                                      \
                    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING))      \
            {                                                               \
                _purge = GLOBUS_TRUE;                                       \
            }                                                               \
        }                                                                   \
                                                                            \
        _my_context->outstanding_operations--;                              \
        if(_purge)                                                          \
        {                                                                   \
             globus_l_xio_driver_purge_read_eof(_my_context);               \
        }                                                                   \
                                                                            \
        if(_my_context->state == GLOBUS_XIO_HANDLE_STATE_CLOSING &&         \
           _my_context->state ==                                            \
                GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING &&        \
           _my_context->outstanding_operations == 0)                        \
        {                                                                   \
            _close = GLOBUS_TRUE;                                           \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(&_my_context->mutex);                               \
                                                                            \
    if(_close)                                                              \
    {                                                                       \
        globus_i_xio_driver_start_close(_op, GLOBUS_FALSE);                 \
    }                                                                       \
} while(0)

/*
 *  cancel and timeout functions 
 */
#define GlobusXIODriverBlockTimeout(_op)                                    \
do                                                                          \
{                                                                           \
} while(0)

#define GlobusXIODriverUnblockTimeout(_op)                                  \
do                                                                          \
{                                                                           \
} while(0)

#define GlobusXIODriverEnableCancel(op, canceled, cb, user_arg)             \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_mutex_t *                                _mutex;                 \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    if(_op->type == GLOBUS_XIO_OPERATION_TYPE_ACCEPT)                       \
    {                                                                       \
        _mutex = _op->_op_server->mutex;                                    \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _mutex = _op->_op_handle->mutex;                                    \
    }                                                                       \
    globus_mutex_lock(_mutex);                                              \
    {                                                                       \
        canceled = _op->canceled;                                           \
        if(!_op->canceled)                                                  \
        {                                                                   \
            _op->cancel_cb = (cb);                                          \
            _op->cancel_user_arg = (user_arg);                              \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(_mutex);                                            \
} while(0)

#define GlobusXIODriverDisableCancel(server)                                \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_mutex_t *                                _mutex;                 \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    if(_op->type == GLOBUS_XIO_OPERATION_TYPE_ACCEPT)                       \
    {                                                                       \
        _mutex = _op->_op_server->mutex;                                    \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _mutex = _op->_op_handle->mutex;                                    \
    }                                                                       \
    globus_mutex_lock(_mutex);                                              \
    {                                                                       \
        _op->cancel_cb = NULL;                                              \
        _op->cancel_user_arg = NULL;                                        \
    }                                                                       \
    globus_mutex_unlock(_mutex);                                            \
} while(0)

/*********************************************************************
 *              function signatures used by the macros
 ********************************************************************/
void
globus_l_xio_driver_op_read_kickout(
    void *                                      user_arg);

void
globus_l_xio_driver_purge_read_eof(
    globus_i_xio_context_entry_t *                  my_context);

void
globus_l_xio_driver_op_write_kickout(
    void *                                      user_arg);

globus_result_t
globus_i_xio_driver_start_close(
    globus_i_xio_op_t *                         op,
    globus_bool_t                               can_fail);

#endif
