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
    GlobusXIOName(GlobusXIODriverPassRead);                                 \
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
        _out_res = GlobusXIOErrorInvalidState(_my_context->state);          \
    }                                                                       \
    else if(_op->canceled)                                                  \
    {                                                                       \
        _out_res = GlobusXIOErrorCanceled();                                \
    }                                                                       \
    else if(_my_context->state == GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED)     \
    {                                                                       \
        _op->cached_res = GlobusXIOErrorEOF();                              \
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
    if(_res != GLOBUS_SUCCESS && globus_xio_error_is_eof(_res))             \
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
/*********************************************************************
 *              function signatures used by the macros
 ********************************************************************/

#endif
