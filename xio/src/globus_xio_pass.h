#if !defined(GLOBUS_XIO_PASS_H)
#define GLOBUS_XIO_PASS_H 1

#include "globus_common.h"
#include "globus_xio.h"
#include "globus_i_xio.h"
#include "globus_xio_util.h"

/************************************************************************
 *                      attribute macros
 ***********************************************************************/
#define GlobusIXIOAttrGetDS(_out_ds, _in_attr, _in_driver)                  \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_attr_t *                       _attr;                      \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _attr = (_in_attr);                                                     \
    _driver = (_in_driver);                                                 \
                                                                            \
    _entry = _attr->entry;                                                  \
    for(_ctr = 0; _ctr < _attr->ndx && _ds == NULL; _ctr++)                 \
    {                                                                       \
        if(_entry[_ctr].driver == _driver)                                  \
        {                                                                   \
            _ds = _entry[_ctr].driver_data;                                 \
        }                                                                   \
    }                                                                       \
    _out_ds = _ds;                                                          \
} while(0)
    
#define GlobusIXIODDGetDS(_out_ds, _in_dd, _in_driver)                      \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_dd_t *                         _dd;                        \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _dd = (_in_dd);                                                         \
    _driver = (_in_driver);                                                 \
                                                                            \
    _entry = _dd->entry;                                                    \
    for(_ctr = 0; _ctr < _dd->stack_size && _ds == NULL; _ctr++)            \
    {                                                                       \
        if(_entry[_ctr].driver == _driver)                                  \
        {                                                                   \
            _ds = _entry[_ctr].driver_data;                                 \
        }                                                                   \
    }                                                                       \
    _out_ds = _ds;                                                          \
} while(0)

/************************************************************************
 *                      pass macros
 ***********************************************************************/

/*
 *  for the server
 */
#define GlobusXIODriverPassServerAccept(_out_res, _in_op, _in_cb,           \
            _in_user_arg)                                                   \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_server_t *                         _server;                \
    globus_i_xio_server_entry_t *                   _server_entry;          \
    globus_i_xio_op_entry_t *                       _next_entry;            \
    globus_i_xio_op_entry_t *                       _my_entry;              \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(_in_op);                                    \
    _server = _op->_op_server;                                              \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    if(_op->canceled)                                                       \
    {                                                                       \
        _out_res = GlobusXIOErrorOperationCanceled(                         \
                    "GlobusXIODriverPassServerAccept");                     \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->block_timeout = GLOBUS_FALSE;                                  \
        _my_entry = &_op->entry[_op->ndx];                                  \
        _my_entry->cb = (_in_cb);                                           \
        _my_entry->user_arg = (_in_user_arg);                               \
        _my_entry->in_register = GLOBUS_TRUE;                               \
        _caller_ndx = _op->ndx;                                             \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_entry = &_op->entry[_op->ndx];                            \
            _server_entry = &_server->entry[_op->ndx];                      \
        }                                                                   \
        while(_server_entry->driver->server_accept_func == NULL);           \
        _my_entry->caller_ndx = _caller_ndx;                                \
                                                                            \
        /* at time that stack is built this will be varified */             \
        globus_assert(_op->ndx <= _op->stack_size);                         \
        _out_res = _server_entry->driver->server_accept_func(               \
                    _server_entry->server_handle,                           \
                    _my_entry->attr,                                        \
                    _op);                                                   \
        _my_entry->in_register = GLOBUS_FALSE;                              \
    }                                                                       \
} while(0)

#define GlobusXIODriverFinishedAccept(_in_op, _in_target, _in_res)          \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (globus_i_xio_op_t *)(_in_op);                                    \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->block_timeout = GLOBUS_FALSE;                                      \
                                                                            \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _op->ndx = _caller_ndx;                                                 \
    _op->entry[_op->ndx].target = (_in_target);                             \
                                                                            \
    if(_op->entry[_op->ndx].in_register)                                    \
    {                                                                       \
        _op->cached_res = (_in_res);                                        \
        globus_callback_space_register_oneshot(                             \
            NULL,                                                           \
            NULL,                                                           \
            globus_l_xio_driver_op_kickout,                                 \
            (void *)_op,                                                    \
            GLOBUS_CALLBACK_GLOBAL_SPACE);                                  \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->entry[_op->ndx].cb(_op, _op->cached_res,                       \
            _op->entry[_op->ndx].user_arg);                                 \
    }                                                                       \
} while(0)

/*
 *  Open
 */
/* open does not need to lock */
#define GlobusXIODriverPassOpen(_out_res, _out_context,                     \
            _in_op, _in_cb, _in_user_arg)                                   \
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
    _op = (_in_op);                                                         \
    _handle = _op->_op_handle;                                              \
    _context = _handle->context;                                           \
    _my_context = &_context->entry[_op->ndx];                               \
    _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPENING;                   \
    _caller_ndx = _op->ndx;                                                 \
                                                                            \
    if(_op->canceled)                                                       \
    {                                                                       \
        _out_res = GlobusXIOErrorOperationCanceled(                         \
                        "GlobusXIODriverPassOpen");                         \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->block_timeout = GLOBUS_FALSE;                                  \
        _my_op = &_op->entry[_op->ndx];                                     \
        _my_op->cb = (_in_cb);                                              \
        _my_op->user_arg = (_in_user_arg);                                  \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_op = &_op->entry[_op->ndx];                               \
            _next_context = &_context->entry[_op->ndx];                     \
        }                                                                   \
        while(_next_context->driver->transport_open_func == NULL &&         \
              _next_context->driver->transform_open_func == NULL);          \
        _next_op->caller_ndx = _caller_ndx;                                 \
        /* at time that stack is built this will be varified */             \
        globus_assert(_op->ndx <= _context->stack_size);                    \
        if(_op->ndx == _op->stack_size)                                     \
        {                                                                   \
            _out_res = _next_context->driver->transport_open_func(          \
                        _next_op->target,                                   \
                        _next_op->attr,                                     \
                        _my_context,                                        \
                        _op);                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _out_res = _next_context->driver->transform_open_func(          \
                        _next_op->target,                                   \
                        _next_op->attr,                                     \
                        _op);                                               \
        }                                                                   \
        _my_op->in_register = GLOBUS_FALSE;                                 \
        _out_context = _my_context;                                         \
    }                                                                       \
} while(0)


/* open does not need to lock */
#define GlobusXIODriverFinishedOpen(_in_context, _in_dh, _in_op, _in_res)   \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_t *                        _context;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_result_t                                 _res;                   \
    int                                             _caller_ndx;            \
    int                                             _ctr;                   \
                                                                            \
    _res = (_in_res);                                                       \
    _op = (globus_i_xio_op_t *)(_in_op);                                    \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->block_timeout = GLOBUS_FALSE;                                      \
                                                                            \
    /*                                                                      \
     * this means that we are finishing with a different context            \
     * copy the finishing one into the operations;                          \
     */                                                                     \
    if(_op->_op_context != _in_context->whos_my_daddy &&                    \
            _in_context != NULL)                                            \
    {                                                                       \
        /* iterate through them all and copy handles into new slot */       \
        for(_ctr = _op->ndx + 1; _ctr < _op->stack_size; _ctr++)            \
        {                                                                   \
            _op->_op_context->entry[_ctr].driver_handle =                   \
                _in_context->whos_my_daddy->entry[_ctr].driver_handle;      \
        }                                                                   \
    }                                                                       \
                                                                            \
    _context = _op->_op_context;                                            \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _my_context = &_context->entry[_caller_ndx];                            \
    _my_context->driver_handle = (_in_dh);                                  \
    _my_op = &_op->entry[_caller_ndx];                                      \
    /* no operation can happen while in OPENING state so no need to lock */ \
    if(_res != GLOBUS_SUCCESS)                                              \
    {                                                                       \
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPEN;                  \
        globus_mutex_lock(&_context->mutex);                                \
        {                                                                   \
            _context->ref++;                                                \
        }                                                                   \
        globus_mutex_unlock(&_context->mutex);                              \
    }                                                                       \
                                                                            \
    _op->ndx = _caller_ndx;                                                 \
    if(!_my_op->is_limited)                                                 \
    {                                                                       \
        /* if still in register call stack or at top level and a user       \
           requested a callback space */                                    \
        if(_my_op->in_register ||                                           \
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
#define GlobusXIODriverPassClose(_out_res, _in_op, _in_cb, _in_ua)          \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_handle_t *                         _handle;                \
    globus_i_xio_context_t *                        _context;               \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_bool_t                                   _pass;                  \
    globus_i_xio_op_entry_t *                       _my_op;                 \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    _op = (_in_op);                                                         \
    _handle = _op->_op_handle;                                              \
    _context = _handle->context;                                            \
    _my_op = &_op->entry[_op->ndx];                                         \
    _my_context = &_context->entry[_op->ndx];                               \
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
                break;                                                      \
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
    _my_op->cb = (_in_cb);                                                 \
    _my_op->user_arg = (_in_ua);                                            \
    /* op can be checked outside of lock */                                 \
    if(_op->canceled)                                                       \
    {                                                                       \
        _out_res = GlobusXIOErrorOperationCanceled(                         \
                        "GlobusXIODriverPassClose");                        \
    }                                                                       \
    else if(_pass)                                                          \
    {                                                                       \
        _out_res = globus_i_xio_driver_start_close(_op, GLOBUS_TRUE);       \
    }                                                                       \
                                                                            \
    if(_out_res != GLOBUS_SUCCESS)                                          \
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
    globus_i_xio_op_entry_t *                       _my_op;                 \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
                                                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->block_timeout = GLOBUS_FALSE;                                      \
                                                                            \
    _caller_ndx = _op->entry[_op->ndx].caller_ndx;                          \
    _context = _op->_op_context;                                            \
    _my_context = &_context->entry[_caller_ndx];                            \
    _my_op = &_op->entry[_caller_ndx];                                      \
    /* don't need to lock because barrier makes contntion not possible */   \
    _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                    \
                                                                            \
    _op->ndx = _caller_ndx;                                                 \
    globus_assert(_op->ndx >= 0); /* otherwise we are not in bad memory */  \
    /* space is only not global by user request in the top level of the     \
     * of operations */                                                     \
    _op->cached_res = (res);                                                \
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
#define GlobusXIODriverPassWrite(_out_res, _in_op,                          \
            _in_iovec, _in_iovec_count,                                     \
            _in_wait_for, _in_cb, _in_user_arg)                             \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _next_op;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_context_t *                        _context;               \
    globus_bool_t                                   _close = GLOBUS_FALSE;  \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (_in_op);                                                         \
    _context = _op->_op_context;                                            \
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
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED)        \
    {                                                                       \
        _out_res = GlobusXIOErrorHandleBadState("GlobusXIODriverPassWrite"); \
    }                                                                       \
    else if(_op->canceled)                                                  \
    {                                                                       \
        _out_res = GlobusXIOErrorOperationCanceled(                          \
                        "GlobusXIODriverPassWrite");                        \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->block_timeout = GLOBUS_FALSE;                                  \
        /* set up the entry */                                              \
        _my_op = &_op->entry[_op->ndx];                                     \
        _my_op->_op_ent_data_cb = (_in_cb);                                 \
        _my_op->user_arg = (_in_user_arg);                                  \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        _my_op->_op_ent_iovec = (_in_iovec);                                \
        _my_op->_op_ent_iovec_count = (_in_iovec_count);                    \
        _my_op->_op_ent_nbytes = 0;                                         \
        _my_op->_op_ent_wait_for = (_in_wait_for);                          \
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
        while(_next_context->driver->write_func == NULL);                   \
                                                                            \
        _my_context->outstanding_operations++;                              \
        _next_op->caller_ndx = _caller_ndx;                                 \
                                                                            \
        /* UNLOCK */                                                        \
        globus_mutex_unlock(&_my_context->mutex);                              \
                                                                            \
        _out_res = _next_context->driver->write_func(                       \
                        _next_context->driver_handle,                       \
                        _my_op->_op_ent_iovec,                              \
                        _my_op->_op_ent_iovec_count,                        \
                        _op);                                               \
                                                                            \
        /* LOCK */                                                          \
        globus_mutex_lock(&_my_context->mutex);                                \
                                                                            \
        /* flip the callstack flag */                                       \
        _my_op->in_register = GLOBUS_FALSE;                                 \
        if(_out_res != GLOBUS_SUCCESS)                                       \
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
    }                                                                       \
    globus_mutex_unlock(&_my_context->mutex);                               \
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
    globus_xio_iovec_t *                            _tmp_iovec;             \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_context_t *                        _context;               \
    int                                             _caller_ndx;            \
    int                                             _iovec_count;           \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    globus_assert(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPENING &&  \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_CLOSED);              \
    _op->progress = GLOBUS_TRUE;                                            \
                                                                            \
    _caller_ndx =_op->entry[_op->ndx].caller_ndx;                           \
    _my_op = &_op->entry[_caller_ndx];                                      \
    _context = _op->_op_context;                                            \
    _my_context = &_context->entry[_caller_ndx];                            \
    _res = (result);                                                        \
                                                                            \
    _my_op->_op_ent_nbytes += nbytes;                                       \
    /* if not all bytes were written */                                     \
    if(_my_op->_op_ent_nbytes < _my_op->_op_ent_wait_for &&                 \
        _res == GLOBUS_SUCCESS)                                             \
    {                                                                       \
        /* if not enough bytes read set the fire_cb deafult to false */     \
        _fire_cb = GLOBUS_FALSE;                                            \
        /* allocate tmp iovec to the bigest it could ever be */             \
        if(_my_op->_op_ent_fake_iovec == NULL)                              \
        {                                                                   \
            _my_op->_op_ent_fake_iovec = (globus_xio_iovec_t *)             \
                globus_malloc(sizeof(globus_xio_iovec_t) *                  \
                    _my_op->_op_ent_iovec_count);                           \
        }                                                                   \
        _tmp_iovec = _my_op->_op_ent_fake_iovec;                            \
                                                                            \
        GlobusIXIOUtilTransferAdjustedIovec(                                \
            _tmp_iovec, _iovec_count,                                       \
            _my_op->_op_ent_iovec, _my_op->_op_ent_iovec_count,             \
            _my_op->_op_ent_nbytes);                                        \
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
            _fire_cb = GLOBUS_TRUE;                                         \
        }                                                                   \
    }                                                                       \
    if(_fire_cb)                                                            \
    {                                                                       \
        _op->ndx = _caller_ndx;                                             \
        _op->cached_res = _res;                                             \
        if(_my_op->_op_ent_fake_iovec != NULL)                              \
        {                                                                   \
            globus_free(_my_op->_op_ent_fake_iovec);                        \
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
    globus_bool_t                                   _close = GLOBUS_FALSE;  \
                                                                            \
    _op = (op);                                                             \
    _my_op = &_op->entry[_op->ndx];                                         \
    _my_context = &_op->_op_context->entry[_op->ndx];                       \
                                                                            \
    _my_op->_op_ent_data_cb(_op, _op->cached_res, _my_op->_op_ent_nbytes,   \
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
#define GlobusXIODriverPassRead(_out_res, _in_op, _in_iovec,                \
            _in_iovec_count, _in_wait_for, _in_cb, _in_user_arg)            \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _next_op;               \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_i_xio_context_entry_t *                  _next_context;          \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_t *                        _context;               \
    int                                             _caller_ndx;            \
                                                                            \
    _op = (_in_op);                                                         \
    _context = _op->_op_context;                                            \
    _my_context = &_context->entry[_op->ndx];                               \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
                                                                            \
    /* LOCK */                                                              \
    globus_mutex_lock(&_my_context->mutex);                                 \
                                                                            \
    /* error checking */                                                    \
    if(_my_context->state != GLOBUS_XIO_HANDLE_STATE_OPEN &&                \
        _my_context->state != GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED)         \
    {                                                                       \
        _out_res = GlobusXIOErrorHandleBadState("GlobusXIODriverPassRead"); \
    }                                                                       \
    else if(_op->canceled)                                                  \
    {                                                                       \
        _out_res = GlobusXIOErrorOperationCanceled(                         \
                        "GlobusXIODriverPassRead");                         \
    }                                                                       \
    else if(_my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED)     \
    {                                                                       \
        _op->cached_res = GlobusXIOErrorReadEOF();                          \
        globus_list_insert(&_my_context->eof_op_list, _op);                 \
        _my_context->outstanding_operations++;                              \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->block_timeout = GLOBUS_FALSE;                                  \
        /* set up the entry */                                              \
        _my_op = &_op->entry[_op->ndx];                                     \
        _my_op->_op_ent_data_cb = (_in_cb);                                 \
        _my_op->user_arg = (_in_user_arg);                                  \
        _my_op->in_register = GLOBUS_TRUE;                                  \
        _my_op->_op_ent_iovec = (_in_iovec);                                \
        _my_op->_op_ent_iovec_count = (_in_iovec_count);                    \
        _my_op->_op_ent_nbytes = 0;                                         \
        _my_op->_op_ent_wait_for = (_in_wait_for);                          \
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
        while(_next_context->driver->write_func == NULL);                   \
                                                                            \
        _next_op->caller_ndx = _caller_ndx;                                 \
        _my_context->outstanding_operations++;                              \
        _my_context->read_operations++;                                     \
                                                                            \
        /* UNLOCK */                                                        \
        globus_mutex_unlock(&_my_context->mutex);                           \
                                                                            \
        _out_res = _next_context->driver->read_func(                        \
                        _next_context->driver_handle,                       \
                        _my_op->_op_ent_iovec,                              \
                        _my_op->_op_ent_iovec_count,                        \
                        _op);                                               \
                                                                            \
        /* LOCK */                                                          \
        globus_mutex_lock(&_my_context->mutex);                             \
                                                                            \
        /* flip the callstack flag */                                       \
        _my_op->in_register = GLOBUS_FALSE;                                 \
        if(_out_res != GLOBUS_SUCCESS)                                      \
        {                                                                   \
            _my_context->outstanding_operations--;                          \
            _my_context->read_operations--;                                 \
        }                                                                   \
    }                                                                       \
                                                                            \
    globus_mutex_unlock(&_my_context->mutex);                               \
} while(0)


#define GlobusXIODriverFinishedRead(op, result, nread)                      \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _my_op;                 \
    globus_result_t                                 _res;                   \
    globus_bool_t                                   _fire_cb = GLOBUS_TRUE; \
    globus_xio_iovec_t *                            _tmp_iovec;             \
    globus_i_xio_context_entry_t *                  _my_context;            \
    globus_i_xio_context_entry_t *                  _next_context;          \
    int                                             _caller_ndx;            \
    int                                             _iovec_count;           \
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
    _my_context = &_op->_op_context->entry[_caller_ndx];                    \
    _next_context = &_op->_op_context->entry[_op->ndx];                     \
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
            _my_op->_op_ent_read_eof = GLOBUS_TRUE;                         \
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
        _fire_cb = GLOBUS_FALSE;                                            \
        /* allocate tmp iovec to the bigest it could ever be */             \
        if(_my_op->_op_ent_fake_iovec == NULL)                              \
        {                                                                   \
            _my_op->_op_ent_fake_iovec = (globus_xio_iovec_t *)             \
                globus_malloc(sizeof(globus_xio_iovec_t) *                  \
                    _my_op->_op_ent_iovec_count);                           \
        }                                                                   \
        _tmp_iovec = _my_op->_op_ent_fake_iovec;                            \
                                                                            \
        GlobusIXIOUtilTransferAdjustedIovec(                                \
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
            _fire_cb = GLOBUS_TRUE;                                        \
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
    _my_context = &_op->_op_context->entry[_op->ndx];                       \
                                                                            \
    /* call the callback */                                                 \
    _my_op->_op_ent_data_cb(_op, _op->cached_res, _my_op->_op_ent_nbytes,   \
                _my_op->user_arg);                                          \
                                                                            \
                                                                            \
    /* if a temp iovec struct was used for fullfulling waitfor,             \
      we can free it now */                                                 \
    if(_my_op->_op_ent_fake_iovec != NULL)                                  \
    {                                                                       \
        globus_free(_my_op->_op_ent_fake_iovec);                            \
    }                                                                       \
                                                                            \
    globus_mutex_lock(&_my_context->mutex);                                 \
    {                                                                       \
        _purge = GLOBUS_FALSE;                                              \
        if(_my_op->_op_ent_read_eof)                                        \
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
        _mutex = &_op->_op_server->mutex;                                   \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _mutex = &_op->_op_handle->mutex;                                   \
    }                                                                       \
    globus_mutex_lock(_mutex);                                              \
    {                                                                       \
        canceled = _op->canceled;                                           \
        if(!_op->canceled)                                                  \
        {                                                                   \
            _op->cancel_cb = (cb);                                          \
            _op->cancel_arg = (user_arg);                                   \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(_mutex);                                            \
} while(0)

#define GlobusXIODriverDisableCancel(op)                                    \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_mutex_t *                                _mutex;                 \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    if(_op->type == GLOBUS_XIO_OPERATION_TYPE_ACCEPT)                       \
    {                                                                       \
        _mutex = &_op->_op_server->mutex;                                   \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _mutex = &_op->_op_handle->mutex;                                   \
    }                                                                       \
    globus_mutex_lock(_mutex);                                              \
    {                                                                       \
        _op->cancel_cb = NULL;                                              \
        _op->cancel_arg = NULL;                                             \
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
    globus_i_xio_context_entry_t *              my_context);

void
globus_l_xio_driver_op_write_kickout(
    void *                                      user_arg);

globus_result_t
globus_i_xio_driver_start_close(
    globus_i_xio_op_t *                         op,
    globus_bool_t                               can_fail);

void
globus_l_xio_driver_op_kickout(
    void *                                      user_arg);

#endif
