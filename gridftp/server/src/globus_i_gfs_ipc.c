
#include "globus_i_gridftp_server.h"
#include "globus_gridftp_server.h"

#define GFS_IPC_HEADER_SIZE         (sizeof(uint32_t) + 1)
#define GFS_IPC_DEFAULT_BUFFER_SIZE 1024

#define GFSEncodeUInt32(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if((globus_byte_t *)_buf - (globus_byte_t *)_start + 4 > _len)      \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
    }                                                                   \
    _cw = htonl((uint32_t)_w);                                          \
    memcpy(_buf, &_cw, 4);                                              \
    _buf += 4;                                                          \
} while(0)


#define GFSDecodeUInt32(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if(_len - 4 <= 0)                                                   \
    {                                                                   \
    }                                                                   \
    else                                                                \
    {                                                                   \
        memcpy(&_cw, _buf, 4);                                          \
        _w = htonl((uint32_t)_cw);                                      \
        _buf += 4;                                                      \
        _len -= 4;                                                      \
    }                                                                   \
} while(0)


#ifdef WORDS_BIGENDIAN                                               
#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
    do                                                                  \
    {                                                                   \
        uint64_t                            _cw;                        \
        if((globus_byte_t *)_buf - (globus_byte_t *)_start + 8 > _len)  \
        {                                                               \
            _len *= 2;                                                  \
            _start = globus_libc_realloc(_start, _len);                 \
        }                                                               \
                                                                        \
        {                                                               \
            _cw = _w;                                                   \
        }                                                               \
    } while(0)
#else                                                                
#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
    do                                                                  \
    {                                                                   \
        uint64_t                            _cw;                        \
        if((globus_byte_t *)_buf - (globus_byte_t *)_start + 8 > _len)  \
        {                                                               \
            _len *= 2;                                                  \
            _start = globus_libc_realloc(_start, _len);                 \
        }                                                               \
                                                                        \
        {                                                               \
            uint32_t                        lo = _w & 0xffffffff;       \
            uint32_t                        hi = _w >> 32U;             \
            lo = ntohl(lo);                                             \
            hi = ntohl(hi);                                             \
            _cw = ((uint64_t) lo) << 32U | hi;                          \
        }                                                               \
        memcpy(_buf, &_cw, 8);                                          \
        _buf += 8;                                                      \
    } while(0)
#endif                                                               


#ifdef WORDS_BIGENDIAN                                               
#define GFSDecodeUInt64(_buf, _len, _w)                                 \
    do                                                                  \
    {                                                                   \
        uint64_t                            _cw;                        \
                                                                        \
        memcpy(&_w, _buf, 8);                                           \
        {                                                               \
            _cw = _w;                                                   \
        }                                                               \
    } while(0)
#else                                                                
#define GFSDecodeUInt64(_buf, _len, _w)                                 \
    do                                                                  \
    {                                                                   \
        uint64_t                            _cw;                        \
                                                                        \
        memcpy(&_w, _buf, 8);                                           \
        {                                                               \
            uint32_t                        lo = w & 0xffffffff;        \
            uint32_t                        hi = w >> 32U;              \
            lo = ntohl(lo);                                             \
            hi = ntohl(hi);                                             \
            _cw = ((uint64_t) lo) << 32U | hi;                          \
        }                                                               \
        _buf += 8;                                                      \
    } while(0)
#endif                                                               


#define GFSEncodeChar(_start, _len, _buf, _w)                           \
do                                                                      \
{                                                                       \
    if((globus_byte_t *)_buf - (globus_byte_t *)_start >= _len)         \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
    }                                                                   \
    *_buf = _w;                                                         \
    _buf++;                                                             \
} while(0)

#define GFSDecodeChar(_buf, _len, _w)                                   \
do                                                                      \
{                                                                       \
    _w = *_buf;                                                         \
    _buf++;                                                             \
} while(0)

#define GFSEncodeString(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    char *                              _str;                           \
    for(_str = _w; *_str != '\0'; _str++)                               \
    {                                                                   \
        GFSEncodeChar(_start, _len, _buf, *_str);                       \
    }                                                                   \
    GFSEncodeChar(_start, _len, _buf, *_str);                           \
} while(0)

#define GFSDecodeString(_buf, _len, _w, _max)                           \
do                                                                      \
{                                                                       \
    char *                              _str;                           \
                                                                        \
    while(*_buf != '\0')                                                \
    {                                                                   \
                                                         \
    }                                                                   \
                                                                        \
    GFSDecodeChar(_buf, _str);                                          \
} while(0)

/*** XXX  this will eventually determine if the data node is part of a
 * a different process and perform ipc to that process.  for now, the data
 * node is assumed to be part of the same process and these calls are merely
 * wrappers
 */
typedef struct
{
    void *                              callback1;
    void *                              callback2;
    void *                              user_arg;
} globus_l_gfs_ipc_bounce_t;

typedef struct globus_i_gfs_ipc_handle_s
{
    char *                              contact_string;
    globus_xio_handle_t                 xio_handle;
    globus_bool_t                       local;

    globus_hashtable_t                  call_table;
    globus_gfs_ipc_iface_t              iface;

    globus_bool_t                       writing;
    globus_fifo_t                       write_q;

    globus_mutex_t                      mutex;
    globus_gfs_ipc_state_t              state;  
    
    globus_gfs_ipc_open_close_callback_t open_cb;
    globus_gfs_ipc_open_close_callback_t close_cb;   
    globus_gfs_ipc_error_callback_t     error_cb;
    void *                              open_arg;    
    void *                              close_arg;    
    void *                              error_arg;

    globus_size_t                       buffer_size;
} globus_i_gfs_ipc_handle_t;

/* callback and id relation */
typedef struct globus_gfs_ipc_request_s
{
    globus_gfs_ipc_handle_t             ipc;
    globus_gfs_ipc_request_type_t       type;
    int                                 id;
    globus_gfs_ipc_callback_t           cb;
    globus_gfs_ipc_callback_t           event_cb;
    void *                              user_arg;
    globus_gfs_ipc_reply_t              reply;
} globus_gfs_ipc_request_t;

static globus_xio_stack_t               globus_l_gfs_ipc_stack;

/************************************************************************
 *   open
 *
 *  open, on error call open_cb with an error, not error_cb
 ***********************************************************************/
static void
globus_l_gfs_ipc_open_kickout(
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
    if(ipc->open_cb != NULL)
    {
        ipc->open_cb(ipc, GLOBUS_SUCCESS, ipc->open_arg);
    }
}

static void
globus_l_gfs_ipc_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(result == GLOBUS_SUCCESS)
    {
        globus_l_gfs_ipc_open_kickout(ipc);
    }
    else
    {
        ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
        ipc->open_cb(ipc, result, ipc->open_arg);
    }
}

/*
 *  create ipc handle with active connection
 */
globus_result_t
globus_gfs_ipc_open(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t              iface,
    const char *                        contact_string,
    globus_gfs_ipc_open_close_callback_t open_cb,
    void *                              open_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc = NULL;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_open);
    
    if(ipc_handle == NULL)
    {
        res = GlobusGFSErrorParameter("ipc_handle");
        goto err;
    }
    if(iface == NULL)
    {
        res = GlobusGFSErrorParameter("iface");
        goto err;
    }

    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        res = GlobusGFSErrorMemory("ipc");
        goto err;
    }
    ipc->iface = iface;
    ipc->open_cb = open_cb;
    ipc->error_cb = error_cb;
    ipc->open_arg = open_arg;
    ipc->error_arg = error_arg;
    ipc->state = GLOBUS_GFS_IPC_STATE_OPENING;
    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_mutex_init(&ipc->mutex, NULL);

    /* if local fake the callback */
    if(ipc->contact_string == NULL)
    {
        ipc->local = GLOBUS_FALSE;
        res = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_ipc_open_kickout,
            ipc);
    }
    /* do xio open */
    else
    {
        res = globus_xio_handle_create(
            &ipc->xio_handle, globus_l_gfs_ipc_stack);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        res = globus_xio_register_open(
            ipc->xio_handle,
            contact_string,
            NULL,
            globus_l_gfs_ipc_open_cb,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    *ipc_handle = ipc;
    
    return GLOBUS_SUCCESS;

  err:
    if(ipc != NULL)
    {
        globus_hashtable_destroy(&ipc->call_table);
        globus_mutex_destroy(&ipc->mutex);
        globus_free(ipc);
    }
    return res;
}

/*
 *  convert an xio handle into IPC.  this is used for passively (server
 *  socket) created connections.  This cannot create local connection types
 */
globus_result_t
globus_gfs_ipc_handle_create(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t              iface,
    globus_xio_handle_t                 xio_handle,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc = NULL;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_handle_create);

    if(ipc_handle == NULL)
    {
        res = GlobusGFSErrorParameter("ipc_handle");
        goto err;
    }
    if(iface == NULL)
    {
        res = GlobusGFSErrorParameter("iface");
        goto err;
    }

    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        res = GlobusGFSErrorMemory("ipc");
        goto err;
    }
    ipc->iface = iface;
    ipc->error_cb = error_cb;
    ipc->error_arg = error_arg;
    ipc->local = GLOBUS_TRUE;
    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_mutex_init(&ipc->mutex, NULL);

    *ipc_handle = ipc;
    return GLOBUS_SUCCESS;

  err:

    return res;
}

/************************************************************************
 *  close
 *  
 *  the user may call close at anytime.  XIO gaurentees that all
 *  out standing callbacks are called before the close callback.  this
 *  code leverages this by calling all callbacks in the hashtable that
 *  are waiting for a read before calling the user close callback.
 ***********************************************************************/
static void
globus_l_gfs_ipc_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_request_t *          request;
    globus_gfs_ipc_reply_t              reply;
    globus_list_t *                     list;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    /* should not need to lock since xio will call this after all callbacks
        have returned from user */
    globus_hashtable_to_list(&ipc->call_table, &list);

    while(!globus_list_empty(list))
    {
        request = (globus_gfs_ipc_request_t *)
            globus_list_remove(&list, list);

        request->cb(
            request->ipc, result, &reply, request->user_arg);
    }

    /* ignore result t, not much to care about at this point */
    if(ipc->close_cb)
    {
        ipc->close_cb(ipc, result, ipc->close_arg);
    }
    /* clean it up */
    globus_hashtable_destroy(&ipc->call_table);
    globus_mutex_destroy(&ipc->mutex);
    globus_free(ipc);
}

/**********************************************************************
 *   read logic
 *   ----------
 *
 *   2 callbacks, i for header one for body.  Header is always the 
 *   same items and size.  In it the size of the body is read, the 
 *   body callback is then posted with that size.  There is always
 *   at least 1 callback posted.
 *********************************************************************/
static void
globus_l_gfs_ipc_read_body_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_byte_t *                     ptr;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_size_t                       size;

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    /* parse based on type
       callout on all types excet for reply, reply needs lock */
    switch(request->type)
    {
        case GLOBUS_GFS_IPC_TYPE_FINAL_REPLY:
        case GLOBUS_GFS_IPC_TYPE_INTERMEDIATE_REPLY:

        case GLOBUS_GFS_IPC_TYPE_RECV:
        case GLOBUS_GFS_IPC_TYPE_SEND:
        case GLOBUS_GFS_IPC_TYPE_LIST:
            break;

        case GLOBUS_GFS_IPC_TYPE_COMMAND:
            ptr = buffer;
            size = len;

            break;

        case GLOBUS_GFS_IPC_TYPE_PASSIVE:
        case GLOBUS_GFS_IPC_TYPE_ACTIVE:
        case GLOBUS_GFS_IPC_TYPE_DESTROY:

        default:
            break;
    }

    new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);

    res = globus_xio_register_read(
        handle,
        new_buf,
        GFS_IPC_HEADER_SIZE,
        GFS_IPC_HEADER_SIZE,
        NULL,
        globus_l_gfs_ipc_read_body_cb,
        ipc);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    globus_free(buffer);

    return;

  err:
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    ipc->error_cb(ipc, res, ipc->error_arg);
}

static void
globus_l_gfs_ipc_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    globus_byte_t *                     new_buf;
    int                                 reply_size;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_size_t                       size;
    GlobusGFSName(globus_l_gfs_ipc_read_header_cb);

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    size = len;
    ptr = buffer;
    GFSDecodeChar(ptr, size, type);
    GFSDecodeUInt32(ptr, size, id);
    GFSDecodeUInt32(ptr, size, reply_size);

    globus_free(buffer);
    new_buf = globus_malloc(reply_size);

    globus_mutex_lock(&ipc->mutex);
    {
        switch(type)
        {
            case GLOBUS_GFS_IPC_TYPE_FINAL_REPLY:
            case GLOBUS_GFS_IPC_TYPE_INTERMEDIATE_REPLY:
                request = (globus_gfs_ipc_request_t *)
                    globus_hashtable_lookup(&ipc->call_table, (void *)id);
                if(request == NULL)
                {
                    /* XXX this means that other side wrote bad things */
                }
                break;

            case GLOBUS_GFS_IPC_TYPE_RECV:
            case GLOBUS_GFS_IPC_TYPE_SEND:
            case GLOBUS_GFS_IPC_TYPE_LIST:
            case GLOBUS_GFS_IPC_TYPE_COMMAND:
            case GLOBUS_GFS_IPC_TYPE_PASSIVE:
            case GLOBUS_GFS_IPC_TYPE_ACTIVE:
            case GLOBUS_GFS_IPC_TYPE_DESTROY:
                request = (globus_gfs_ipc_request_t *)
                    globus_calloc(sizeof(globus_gfs_ipc_request_t), 1);
                if(request == NULL)
                {
                    res = GlobusGFSErrorMemory("request");
                    goto err;
                }
                request->id = id;
                request->type = type;
                request->ipc = ipc;

            default:
                /* XXX a bad message */
                break;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    res = globus_xio_register_read(
        handle,
        new_buf,
        reply_size,
        reply_size,
        NULL,
        globus_l_gfs_ipc_read_body_cb,
        request);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return;

  err:
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    ipc->error_cb(ipc, res, ipc->error_arg);
}

/************************************************************************
 *  reply
 *  -----
 *  easy.  queuing driver is used with xio so any number of writes can
 *  be pushed in.  On sucess the callback is ignored, on error the 
 *  user error callback is called notifing them that the ipc channel 
 *  is broken.  The user still needs to close
 *
 *  for local a one shot back to the original callback is arranged
 ***********************************************************************/
static void
globus_l_gfs_ipc_finished_reply_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *       request;

    request = (globus_gfs_ipc_request_t *) user_arg;

    /* call the user callback */
    request->cb(
        request->ipc, 
        GLOBUS_SUCCESS,
        &request->reply,
        request->user_arg);

    /* free the resources */
    globus_free(request);
}
static void
globus_l_gfs_ipc_event_reply_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *       request;

    request = (globus_gfs_ipc_request_t *) user_arg;

    /* call the user callback */
    request->event_cb(
        request->ipc,
        GLOBUS_SUCCESS,
        &request->reply,
        request->user_arg);

    /* free the resources */
    globus_free(request);
}

/*
 *  only interesting if it failed
 */
static void
globus_l_gfs_ipc_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_free(buffer);
    if(result != GLOBUS_SUCCESS)
    {
        if(ipc->error_cb)
        {
            ipc->error_cb(ipc, result, ipc->error_arg);
        }
    }
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply_finished(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       msg_size;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_gfs_ipc_request_t *          request;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_reply_finished);

    /* TODO: copy reply to request struct */
    ipc = ipc_handle;
    globus_mutex_lock(&ipc_handle->mutex);
    {
        /* if local register one shot to get out of recurisve call stack
            troubles */
        if(ipc->local)
        {
            request = (globus_gfs_ipc_request_t *) 
                globus_hashtable_remove(
                    &ipc->call_table,
                    (void *)reply->id);
            if(request == NULL)
            {
                goto err;
            }

            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_finished_reply_kickout,
                request);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* serialize the reply */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_FINAL_REPLY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, reply->type);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->code);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, strlen(reply->msg));
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, reply->msg);

            /* encode the specific types */
            switch(reply->type)
            {
                case GLOBUS_GFS_IPC_TYPE_COMMAND:
                    break;

                default:
                    break;
            }

            msg_size = ptr - buffer;
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, size_ptr, msg_size);
            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_reply_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc_handle->mutex);

    return res;
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_request_t *          request;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_reply_event);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc_handle->mutex);
    {
        /* if local register one shot to get out of recurisve call stack
            troubles */
        if(ipc->local)
        {
            request = (globus_gfs_ipc_request_t *) 
                globus_hashtable_lookup(
                    &ipc_handle->call_table,
                    (void *)reply->id);
            if(request == NULL)
            {
                goto err;
            }

            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_event_reply_kickout,
                request);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* serialize the reply */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc_handle->mutex);

    return res;
}

/************************************************************************
 *   remote function calls
 *
 *   local: call directly to iface function
 *
 *   remote: serialize all needed information into a buffer and
 *   send it.  any number can be sent at once due to the queung 
 *   buffer.  Callback is ignored unless it fails, in which case 
 *   the user error callback is called and the user is expected to 
 *   close
 ***********************************************************************/
/*
 *  write callback
 */
static void
globus_l_gfs_ipc_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_error_callback_t     error_cb = NULL;

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    globus_free(buffer);
    /* on error remoe from the hashtable.  we could just wait for the
       close for this but we may as well have this callback do something */
    if(result != GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&ipc->mutex);
        {
            globus_hashtable_remove(&ipc->call_table, (void *)request->id);
            error_cb = request->ipc->error_cb;
        }
        globus_mutex_unlock(&ipc->mutex);

        if(error_cb)
        {
            error_cb(request->ipc, result, request->user_arg);
            globus_free(request);
        }
    }
}

globus_result_t
globus_gfs_ipc_set_user(
    globus_gfs_ipc_handle_t             ipc_handle,
    const char *                        user_dn,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_set_user);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            res = GlobusGFSErrorMemory("request");
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;

        ipc->state = GLOBUS_GFS_IPC_STATE_AUTHENTICATING;

        if(ipc->local)
        {
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_finished_reply_kickout,
                request);
        }
        else
        {
            globus_hashtable_insert(
                &ipc_handle->call_table,
                (void *)request->id,
                request);

            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_AUTH);
            /* bs id, no response */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, strlen(user_dn));
            GFSEncodeString(buffer, ipc->buffer_size, ptr, user_dn);

            msg_size = ptr - buffer;
            GFSEncodeUInt32(buffer, ipc->buffer_size, size_ptr, msg_size);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }

    return res;
}

globus_result_t
globus_gfs_ipc_set_cred(
    globus_gfs_ipc_handle_t             ipc_handle,
    gss_cred_id_t                       del_cred,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    return GLOBUS_SUCCESS;
}

/*
 *  receive
 *
 *  tell the remote process to receive a file
 */
globus_result_t
globus_gfs_ipc_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       recv_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_recv);

    request = (globus_gfs_ipc_request_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
    request->id = (int) request;
    request->cb = cb;
    request->event_cb = event_cb;
    request->user_arg = user_arg;

    globus_hashtable_insert(
        &ipc_handle->call_table,
        (void *)request->id,
        request);
    
    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        ipc_handle->iface->recv_func(
            ipc_handle,
            request->id,
            recv_state);
    }
    else
    {
        /* i like wires */
    }
    
    return GLOBUS_SUCCESS;
}


/*
 *  send
 *  
 *  tell remote process to send a file
 */

globus_result_t
globus_gfs_ipc_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_send);

    request = (globus_gfs_ipc_request_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
    request->id = (int) request;
    request->cb = cb;
    request->event_cb = event_cb;
    request->user_arg = user_arg;

    globus_hashtable_insert(
        &ipc_handle->call_table,
        (void *)request->id,
        request);
    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        ipc_handle->iface->send_func(
            ipc_handle,
            request->id,
            send_state);
    }
    else
    {
        /* i like wires */
    }
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gfs_ipc_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       data_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer = NULL;
    GlobusGFSName(globus_gfs_ipc_request_list);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            res = GlobusGFSErrorMemory("request");
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc->call_table,
            (void *)request->id,
            request);

        if(ipc->local)
        {
        }
        else
        {
        }
    }
    globus_mutex_unlock(&ipc->mutex);
    
    return GLOBUS_SUCCESS;

  err:
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }
    return res;
}
/*
 *  command
 *
 *  tell remote side to execute the given command
 */
globus_result_t
globus_gfs_ipc_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_command_state_t *        cmd_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_size_t                       size;
    globus_size_t                       msg_size;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    GlobusGFSName(globus_gfs_ipc_request_command);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;

        globus_hashtable_insert(
            &ipc->call_table,
            (void *)request->id,
            request);

        if(ipc->local)
        {
            ipc->iface->command_func(
                ipc,
                request->id,
                cmd_state);
        }
        else
        {
            size = GFS_IPC_DEFAULT_BUFFER_SIZE;
            buffer = globus_malloc(size);
            ptr = buffer;
            GFSEncodeChar(buffer, size, ptr, GLOBUS_GFS_IPC_TYPE_COMMAND);
            GFSEncodeUInt32(buffer, size, ptr, id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, -1);
            GFSEncodeUInt32(buffer, size, ptr, cmd_state->command);
            GFSEncodeString(buffer, size, ptr, cmd_state->pathname);
            GFSEncodeUInt64(buffer, size, ptr, cmd_state->cksm_offset);
            GFSEncodeUInt64(buffer, size, ptr, cmd_state->cksm_length);
            GFSEncodeString(buffer, size, ptr, cmd_state->cksm_alg);
            GFSEncodeString(buffer, size, ptr, cmd_state->cksm_response);
            GFSEncodeUInt32(buffer, size, ptr, cmd_state->chmod_mode);
            GFSEncodeString(buffer, size, ptr, cmd_state->rnfr_pathname);

            /* now that we know size, add it in */
            msg_size = ptr - buffer;
            GFSEncodeUInt32(buffer, size, ptr, msg_size);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }

    return res;
}

/*
 *  active data
 *
 *  tell remote side to create an active data connection
 */
globus_result_t
globus_gfs_ipc_request_active_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       size;
    globus_size_t                       msg_size;
    int                                 ctr;
    globus_i_gfs_ipc_handle_t *         ipc;
    
    GlobusGFSName(globus_gfs_ipc_request_active_data);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    
        if(ipc->local)
        {
            ipc_handle->iface->active_func(
                ipc_handle,
                request->id,
                data_state);
        }
        else
        {
            size = GFS_IPC_DEFAULT_BUFFER_SIZE;
            buffer = globus_malloc(size);
            ptr = buffer;
            GFSEncodeChar(buffer, size, ptr, GLOBUS_GFS_IPC_TYPE_ACTIVE);
            GFSEncodeUInt32(buffer, size, ptr, request->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, -1);
            GFSEncodeUInt32(buffer, size, ptr, data_state->cs_count);
            for(ctr = 0; ctr < data_state->cs_count; ctr++)
            {
                GFSEncodeString(
                    buffer, size, ptr, data_state->contact_strings[ctr]);
            }
            GFSEncodeUInt32(buffer, size, ptr, data_state->net_prt);

            /* now that we know size, add it in */
            msg_size = ptr - buffer;
            GFSEncodeUInt32(buffer, size, ptr, msg_size);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }
    return res;
}


/*
 *  passive data
 *
 *  tell remote side to do passive data connection
 */

globus_result_t
globus_gfs_ipc_request_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_request_passive_data);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    
        if(ipc->local)
        {
            ipc->iface->passive_func(
                ipc,
                request->id,
                data_state);
        }
        else
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_PASSIVE);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->min);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->max);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->best);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->net_prt);

            /* now that we know size, add it in */
            msg_size = ptr - buffer;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }
    return res;
}


/*
 *  send resource request
 */

globus_result_t
globus_gfs_ipc_request_resource_query(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_resource_state_t *       resource_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_request_resource_query);

    ipc = ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    
        if(ipc->local)
        {
            ipc_handle->iface->resource_func(
                ipc_handle,
                request->id,
                resource_state);
        }
        else
        {
        }
    }
    globus_mutex_unlock(&ipc->mutex);
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }
    return res;
}


/* 
 *  tell remote side to provide list info
 */


/*
 *  destroy a data connection associated with the given ID
 */
void
globus_gfs_ipc_data_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,   
    int                                 data_connection_id)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_data_destroy);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    if(ipc->xio_handle == GLOBUS_NULL)
    {
        ipc->iface->data_destroy_func(data_connection_id);
    }
    else
    {
        /* i like wires */
    }
}


globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_close);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->local)
        {
            /* it is illegal to register a callback in local mode.
               further, in local mode the user must be aware that all
               their callbacks have returned before calling close.
               since there will only be 1 ipc handle for local that is
               detroyed at shutdown, i suspect this will not be a problem */
            if(cb != NULL)
            {
                
            }
            globus_hashtable_destroy(&ipc->call_table);
            globus_mutex_destroy(&ipc->mutex);
            globus_free(ipc);
            res = GLOBUS_SUCCESS;
        }
        else
        {
            ipc->close_cb = cb;
            ipc->close_arg = user_arg;
            switch(ipc->state)
            {
                case GLOBUS_GFS_IPC_STATE_OPENING:
                case GLOBUS_GFS_IPC_STATE_OPEN:

                    ipc->state = GLOBUS_GFS_IPC_STATE_CLOSING;
                    res = globus_xio_register_close(
                        ipc->xio_handle,
                        NULL,
                        globus_l_gfs_ipc_close_cb,
                        ipc);
                break;

                default:
                    res = GlobusGFSErrorParameter("ipc_handle");
                    break;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    return res;
}

