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
    GlobusXIOName(GlobusXIODriverPassServerAccept);                         \
                                                                            \
    _op = (globus_i_xio_op_t *)(_in_op);                                    \
    _server = _op->_op_server;                                              \
                                                                            \
    globus_assert(_op->ndx < _op->stack_size);                              \
    if(_op->canceled)                                                       \
    {                                                                       \
        _out_res = GlobusXIOErrorCanceled();                                \
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
 *  cancel and timeout functions 
 */
#define GlobusXIODriverBlockTimeout(_in_op)                                 \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (_in_op);                                                         \
    _op->block_timeout = GLOBUS_TRUE;                                       \
} while(0)

#define GlobusXIODriverUnblockTimeout(_in_op)                               \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (_in_op);                                                         \
    _op->block_timeout = GLOBUS_FALSE;                                      \
} while(0)

#define GlobusXIOOperationRefreshTimeout(_in_op)                            \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (_in_op);                                                         \
    _op->progress = GLOBUS_TRUE;                                            \
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

#define GlobusXIOOperationGetWaitFor(_in_op)                                \
    ((_in_op)->entry[_in_op->ndx - 1]._op_ent_wait_for)

#define GlobusXIOOperationGetDriverHandle(_in_op)                           \
    ((_in_op)->_op_context->entry[_in_op->ndx - 1].driver_handle)

#define GlobusXIOOperationGetContext(_in_op)                                \
    &((_in_op)->_op_context->entry[_in_op->ndx - 1])

#define GlobusXIOOperationGetDataDescriptor(op) NULL
/*********************************************************************
 *              function signatures used by the macros
 ********************************************************************/

#endif
