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
