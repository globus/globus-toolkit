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
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_entry = &_op->entry[_op->ndx];                            \
        }                                                                   \
        while(_next_entry->driver->server_accept_func == NULL)              \
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
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->timeout_blocked = GLOBUS_FALSE;                                    \
                                                                            \
    _op->entry[_op->ndx].target = (target);                                 \
                                                                            \
    do                                                                      \
    {                                                                       \
        _op->ndx--;                                                         \
    }                                                                       \
    while(_op->entry[_op->ndx].cb == NULL &&                                \
            _op->ndx != 0)                                                  \
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
#define GlobusXIODriverPassOpen(out_res, out_context, op, cb, user_arg)     \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_handle_t *                         _handle;                \
    globus_i_xio_context_t *                        _context;               \
    globus_i_xio_op_entry_t *                       _next_entry;            \
    globus_i_xio_op_entry_t *                       _my_entry;              \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    _op = (op);                                                             \
    _handle = _op->_op_handle;                                              \
    _context = _handle->contex;                                             \
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
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_entry = &_op->entry[_op->ndx];                            \
        }                                                                   \
        while(_next_entry->driver->transport_open == NULL &&                \
              _next_entry->driver->transform_open == NULL)                  \
                                                                            \
        /* at time that stack is built this will be varified */             \
        globus_assert(_op->ndx <= _server->stack_size);                     \
        if(_op->ndx == _op->stack_size)                                     \
        {                                                                   \
            out_res = _context->entry[_op->ndx].driver->transport_open(     \
                        _op->entry[_op->ndx].target,                        \
                        _op->entry[_op->ndx].attr,                          \
                        _context,                                           \
                        _op);                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            out_res = _context->entry[_op->ndx].driver->transform_open(     \
                        _op->entry[_op->ndx].target,                        \
                        _op->entry[_op->ndx].attr,                          \
                        _op);                                               \
        }                                                                   \
        _my_entry->in_register = GLOBUS_FALSE;                              \
        out_context = _context;                                             \
    }                                                                       \
} while(0)


#define GlobusXIODriverFinishedOpen(context, dh, op, res)                   \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
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
    _op->context->entry[_op->ndx].driver_handle = (dh);                     \
                                                                            \
    /* TODO: driver op limited pass */                                      \
    if(!_op->entry_array[_op->ndx]->is_limited)                             \
    {                                                                       \
        do                                                                  \
        {                                                                   \
            _op->ndx--;                                                     \
        }                                                                   \
        while(_op->entry[_op->ndx].cb == NULL &&                            \
                _op->ndx != 0)                                              \
                                                                            \
        globus_assert(_op->entry[_op->ndx].cb != NULL);                     \
        if(_op->entry[_op->ndx].in_register)                                \
        {                                                                   \
            _op->cached_res = (result);                                     \
            globus_callback_space_register_oneshot(                         \
                NULL,                                                       \
                NULL,                                                       \
                globus_l_xio_driver_op_kickout,                             \
                (void *)_op,                                                \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                              \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _op->entry[_op->ndx].cb(_op, result,                            \
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
    globus_i_xio_context_t *                        _context;               \
    globus_i_xio_op_entry_t *                       _next_entry;            \
    globus_i_xio_op_entry_t *                       _my_entry;              \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    _op = (op);                                                             \
    _handle = _op->_op_handle;                                              \
    _context = _handle->contex;                                             \
    if(_op->canceled)                                                       \
    {                                                                       \
        out_res = OperationHasBeenCacneled();                               \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        /* TODO: add driver_op barrier for close */                         \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->timeout_blocked = GLOBUS_FALSE;                                \
        _my_entry = &_op->entry[_op->ndx];                                  \
        _my_entry->cb = (cb);                                               \
        _my_entry->user_arg = (user_arg);                                   \
        _my_entry->in_register = GLOBUS_TRUE;                               \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_entry = &_op->entry[_op->ndx];                            \
        }                                                                   \
        while(_next_entry->driver->close_func)                              \
                                                                            \
        /* at time that stack is built this will be varified */             \
        globus_assert(_op->ndx <= _server->stack_size);                     \
        out_res = _context->entry[_op->ndx].driver->close_func(             \
                    _op->context->entry[_op->ndx].driver_handle,            \
                    _op->entry[_op->ndx].attr,                              \
                    _context,                                               \
                    _op);                                                   \
        _my_entry->in_register = GLOBUS_FALSE;                              \
        out_context = _context;                                             \
    }                                                                       \
} while(0)


#define GlobusXIODriverFinishedClose(op, res)                               \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
    _op->timeout_blocked = GLOBUS_FALSE;                                    \
                                                                            \
    _op->context->entry[_op->ndx].driver_handle = (dh);                     \
                                                                            \
     /* TODO: driver_op stuff */                                            \
        do                                                                  \
        {                                                                   \
            _op->ndx--;                                                     \
        }                                                                   \
        while(_op->entry[_op->ndx].cb == NULL &&                            \
                _op->ndx != 0)                                              \
                                                                            \
        globus_assert(_op->entry[_op->ndx].cb != NULL);                     \
        if(_op->entry[_op->ndx].in_register)                                \
        {                                                                   \
            _op->cached_res = (result);                                     \
            globus_callback_space_register_oneshot(                         \
                NULL,                                                       \
                NULL,                                                       \
                globus_l_xio_driver_op_kickout,                             \
                (void *)_op,                                                \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                              \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _op->entry[_op->ndx].cb(_op, result,                            \
                _op->entry[_op->ndx].user_arg);                             \
        }                                                                   \
} while(0)



/*
 *  write
 */
#define                                                                     \
#define GlobusXIODriverPassWrite(out_res, op, iovec, iovec_count,           \
    cb, wait_for, user_arg)                                                 \
do                                                                          \
{                                                                           \
    globus_i_xio_operation_t *                      _op;                    \
    globus_i_xio_op_entry_t *                       _next_entry;            \
    globus_i_xio_op_entry_t *                       _my_entry;              \
    globus_i_xio_context_ent_t *                    _context;               \
                                                                            \
    _op = (op);                                                             \
                                                                            \
    if(_op->canceled)                                                       \
    {                                                                       \
        out_res = GlobusXIOErrorOperationCanceled(                          \
                        "Globus_XIO_Driver_Pass_Write");                    \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        globus_assert(_op->ndx < _op->stack_size);                          \
        _op->progress = GLOBUS_TRUE;                                        \
        _op->timeout_blocked = GLOBUS_FALSE;                                \
        _my_entry = &_op->entry[_op->ndx];                                  \
        _my_entry->data_cb = (cb);                                          \
        _my_entry->user_arg = (user_arg);                                   \
        _my_entry->in_register = GLOBUS_TRUE;                               \
        _my_entry->iovec = (iovec);                                         \
        _my_entry->iovec_count = (iovec_count);                             \
        /* set the callstack flag */                                        \
        _my_entry->in_register = GLOBUS_TRUE;                               \
        _my_entry->nwritten = 0;                                          \
        _my_entry->wait_for = (wait_for);                                   \
        /* find next slot. start on next and find first interseted */       \
        do                                                                  \
        {                                                                   \
            _op->ndx++;                                                     \
            _next_entry = &_op->entry[_op->ndx];                            \
        }                                                                   \
        while(_next_entry->driver->write_func == NULL)                      \
                                                                            \
        _context = &_op->context[_op->ndx];                                 \
        out_res = context->driver->write_func(                              \
                        _context->driver_handle,                            \
                        _my_entry->iovec,                                   \
                        _my_entry->iovec_count,                             \
                        _op);                                               \
                                                                            \
        /* flip the callstack flag */                                       \
        _my_entry->in_register = GLOBUS_FALSE;                              \
        out_context = _op->context;                                         \
    }                                                                       \
} while(0)


#define GlobusXIODriverFinishedWrite(op, result, nwritten)                  \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_i_xio_op_entry_t *                       _my_entry;              \
    globus_i_xio_op_entry_t *                       _next_entry;            \
    globus_result_t                                 _res;                   \
    globus_bool_t                                   _fire_cb = GLOBUS_TRUE; \
    globus_iovec_t *                                _tmp_iovec;             \
    int                                             _my_ndx;                \
    int                                             _next_ndx;              \
    globus_size_t                                   _offset;                \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    globus_assert(_op->ndx > 0);                                            \
    _op->progress = GLOBUS_TRUE;                                            \
                                                                            \
    /* deal with wait for stuff */                                          \
    _my_ndx = _op->ndx;                                                     \
    _my_entry = &_op->entry[_my_ndx];                                       \
    _next_ndx =_op->ndx;                                                    \
    _res = result;                                                          \
    do                                                                      \
    {                                                                       \
        _next_ndx--;                                                        \
        _next_entry = &_op->entry[_next_ndx];                               \
    }                                                                       \
    while(_my_entry->_op_ent_data_cb == NULL)                               \
                                                                            \
    _next_entry->_op_ent_nwritten += nwritten;                              \
    /* if not all bytes were written */                                     \
    if(_next_entry->_op_ent_nwritten < _next_entry->_op_ent_wait_for)       \
    {                                                                       \
        /* if not enough bytes read set the fire_cb deafult to false */     \
        fire_cb = GLOBUS_FALSE;                                             \
        /* allocate tmp iovec to the bigest it could ever be */             \
        if(_next_entry->_op_ent_fake_iovec == NULL)                         \
        {                                                                   \
            _next_entry->_op_ent_fake_iovec = (globus_iovec_t *)            \
                globus_malloc(sizeof(globus_iovec_t) *                      \
                    _next_entry->_op_ent_iovec_count);                      \
        }                                                                   \
        /* find the first partialy empty iovec */                           \
        _offset = 0;                                                        \
        _iovec_ndx = 0;                                                     \
        while(_offset + _next_entry->iovec[_iovec_ndx].iov_len <            \
                _next_entry->_op_ent_nwritten)                              \
        {                                                                   \
            _offset += _next_entry->iovec[_iovec_ndx].iov_len;              \
            _iovec_ndx++;                                                   \
        }                                                                   \
                                                                            \
        _tmp_iovec = &_next_entry->iovec[iovec_ndx];                        \
        _iovec_count = _next_entry->iovec_count - _iovec_ndx;               \
        _offset = _next_entry->_op_ent_nwritten - _offset;                  \
        /* set up first entry */                                            \
        _next_entry->_op_ent_fake_iovec[0].iov_base =                       \
            &_next_entry->_op_ent_iovec[_iovec_ndx].iov_bass[offset];       \
        _next_entry->_op_ent_fake_iovec[0].iov_len =                        \
            _next_entry->_op_ent_iovec[_iovec_ndx].iov_len - offset;        \
        /* simply coping in the remaining ones */                           \
        for(ctr = 1; ctr < _iovec_count; ctr++)                             \
        {                                                                   \
            _next_entry->_op_ent_fake_iovec[ctr].iov_base =                 \
                _next_entry->_op_ent_iovec[_iovec_ndx + ctr].iov_bass;      \
            _next_entry->_op_ent_fake_iovec[ctr].iov_len =                  \
                _next_entry->_op_ent_iovec[_iovec_ndx + ctr].iov_len;       \
        }                                                                   \
        /* repass the operation down */                                     \
        _res = context->driver->write_func(                                 \
                _context->driver_handle,                                    \
                _next_entry->_op_ent_fake_iovec,                            \
                _iovec_count,                                               \
                _op);                                                       \
        if(_res != GLOBUS_SUCCESS)                                          \
        {                                                                   \
            fire_cb = GLOBUS_TRUE;                                          \
        }                                                                   \
    }                                                                       \
    if(fire_cb)                                                             \
    {                                                                       \
        if(_next_entry->fake_iovec != NULL)                                 \
        {                                                                   \
            globus_free(_next_entry->fake_iovec);                           \
        }                                                                   \
        if(_op->entry[_op->ndx].in_register)                                \
        {                                                                   \
            _op->cached_res = (_res);                                       \
            globus_callback_space_register_oneshot(                         \
                NULL,                                                       \
                NULL,                                                       \
                globus_l_xio_driver_op_data_kickout,                        \
                (void *)_op,                                                \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                              \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _op->entry[_op->ndx].cb(_op, _res,                              \
                _op->entry[_op->ndx].user_arg);                             \
        }                                                                   \
    }                                                                       \
} while(0)

/*
 *  read
 */


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
globus_l_xio_driver_op_data_kickout(
    void *                                      user_arg);

void
globus_l_xio_driver_op_kickout(
    void *                                      user_arg);

#endif
