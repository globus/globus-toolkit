
#include "globus_i_gridftp_server.h"

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


#define GFSDecodeUInt32(_error, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if(_len - 4 <= 0)                                                   \
    {                                                                   \
        _error = GLOBUS_TRUE;                                           \
    }                                                                   \
    else                                                                \
    {                                                                   \
        memcpy(&_cw, _buf, 4);                                          \
        _w = htonl((uint32_t)_cw);                                      \
        _buf += 4;                                                      \
        _len -= 4;                                                      \
    }                                                                   \
} while(0)

#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    uint64_t                            _cw;                            \
    if((globus_byte_t *)_buf - (globus_byte_t *)_start + 8 > _len)      \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
    }                                                                   \
                                                                        \
#   ifdef WORDS_BIGENDIAN                                               \
    {                                                                   \
        _cw = _w;                                                       \
    }                                                                   \
#   else                                                                \
    {                                                                   \
        uint32_t                        lo = w & 0xffffffff;            \
        uint32_t                        hi = w >> 32U;                  \
        lo = ntohl(lo);                                                 \
        hi = ntohl(hi);                                                 \
        _cw = ((uint64_t) lo) << 32U | hi;                              \
    }                                                                   \
    memcpy(_buf, &_cw, 8);                                              \
    _buf += 8;                                                          \
#   endif                                                               \
} while(0)

#define GFSDecodeUInt64(_error, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    uint64_t                            _cw;                            \
                                                                        \
    memcpy(&_w, _buf, 8);                                               \
#   ifdef WORDS_BIGENDIAN                                               \
    {                                                                   \
        _cw = _w;                                                       \
    }                                                                   \
#   else                                                                \
    {                                                                   \
        uint32_t                        lo = w & 0xffffffff;            \
        uint32_t                        hi = w >> 32U;                  \
        lo = ntohl(lo);                                                 \
        hi = ntohl(hi);                                                 \
        _cw = ((uint64_t) lo) << 32U | hi;                              \
    }                                                                   \
    _buf += 8;                                                          \
#   endif                                                               \
} while(0)

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

#define GFSDecodeChar(_error, _len, _buf, _w)                           \
do                                                                      \
{                                                                       \
    w = *_buf;                                                          \
    _buf++;                                                             \
} while(0)

#define GFSEncodeString(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    char *                              _str;                           \
    for(_str = _w; *_str != '\0'; _str++)                               \
    {                                                                   \
        GFSEncodeChar(_start, _len, _buf, _str);                        \
    }                                                                   \
    GFSEncodeChar(_start, _len, _buf, _str);                            \
} while(0)

#define GFSDecodeString(_buf, _w, _max)                                 \
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
    globus_xio_handle_t                 xio_handle;
                                                                                
    globus_hashtable_t                  call_table;
    globus_gfs_ipc_iface_t              iface;
                                                                                
    globus_bool_t                       writing;
    globus_fifo_t                       write_q;
                                                                                
    globus_mutex_t                      mutex;
                                                                                
} globus_i_gfs_ipc_handle_t;


/************************************************************************
 *   open
 *
 *  in connectioncase of ipc the user calls open.  when the connection
 *  is esstablished the open callback is called.  if no error occurs
 *  the handle is set to the open state and the user open cb is called.
 *  If and error does occur the error callback is called and the user
 *  is expected to close. 
 ***********************************************************************/
static void
globus_l_gfs_ipc_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&ipc->mutex);
    {
        /* if success the we jsut move to open, else user needs to close */
        if(result == GLOBUS_SUCCESS)
        {
            ipc->state = GLOBUS_GFS_IPC_STATE_OPENED;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_assert(ipc->cb != NULL && ipc->error_cb != NULL);

    if(result == GLOBUS_SUCCESS)
    {
        ipc->open_cb(ipc, ipc->open_user_arg);
    }
    else
    {
        ipc->error_cb(ipc, result, ipc->user_arg);
    }
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
    globus_gfs_ipc_call_entry_t *       call_entry;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    /* should not need to lock since xio will call this after all callbacks
        have returned from user */
    globus_hashtable_to_list(&ipc->call_table, &list);

    while(!globus_list_empty(list))
    {
        call_entry = (globus_i_gfs_ipc_handle_t *)
            globus_list_remove(&list, list);

        call_entry->cb(
            call_entry->ipc_handle, &call_entry->reply, result,
            call_entry->user_arg);
    }

    /* ignore result t, not much to care about at this point */
    if(ipc->close_cb)
    {
        ipc->close_cb(ipc, ipc->close_user_arg);
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
    globus_gfs_ipc_call_entry_t *       call_entry;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_callback_t           cb = NULL;

    call_entry = (globus_gfs_ipc_call_entry_t *) user_arg;
    ipc = call_entry->ipc;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    /* parse based on type
       callout on all types excet for reply, reply needs lock */
    switch(call_entry->type)
    {
        case GLOBUS_GFS_IPC_TYPE_FINAL_REPLY:
        case GLOBUS_GFS_IPC_TYPE_INTERMEDIATE_REPLY:

        case GLOBUS_GFS_IPC_TYPE_RECV:
        case GLOBUS_GFS_IPC_TYPE_SEND:
        case GLOBUS_GFS_IPC_TYPE_LIST:
            break;

        case GLOBUS_GFS_IPC_TYPE_COMMAND:
            ptr = buffer;
            GFSDecodeUInt32(ptr, cmd_state->command);
            GFSDecodeString(ptr, cmd_state->pathname);
            GFSDecodeUInt64(ptr, cmd_state->cksm_offset);
            GFSDecodeUInt64(ptr, cmd_state->cksm_length);
            GFSDecodeString(ptr, cmd_state->cksm_alg);
            GFSDecodeString(ptr, cmd_state->cksm_response);
            GFSDecodeUInt32(ptr, cmd_state->chmod_mode);
            GFSDecodeString(cmd_state->rnfr_pathname);

            ipc->iface->command_func(
                ipc,
                call_entry->id,
                &cmd_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_PASSIVE:
        case GLOBUS_GFS_IPC_TYPE_ACTIVE:
        case GLOBUS_GFS_IPC_TYPE_DESTROY:

        default:
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
    ipc->error_cb(ipc, res, ipc->user_arg);
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
    globus_gfs_ipc_call_entry_t *       call_entry;
    globus_gfs_ipc_callback_t           cb = NULL;
    char                                type;
    int                                 id;
    globus_byte_t *                     new_buf;
    int                                 reply_size;
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    ptr = buffer;
    GFSDecodeChar(ptr, type);
    GFSDecodeUInt32(ptr, id);
    GFSDecodeUInt32(ptr, reply_size);

    globus_free(buffer);
    new_buf = globus_malloc(reply_size);

    globus_mutex_lock(&ipc->mutex);
    {
        switch(type)
        {
            case GLOBUS_GFS_IPC_TYPE_FINAL_REPLY:
            case GLOBUS_GFS_IPC_TYPE_INTERMEDIATE_REPLY:
                call_entry = (globus_gfs_ipc_call_entry_t *)
                    globus_hashtable_lookup(&ipc->call_table, id);
                if(call_entry == NULL)
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
                call_entry = (globus_gfs_ipc_call_entry_t *)
                    globus_calloc(sizeof(globus_gfs_ipc_call_entry_t), 1);
                if(call_entry == NULL)
                {
                    res = memoryError;
                    goto err;
                }
                call_entry->id = id;
                call_entry->type = type;
                call_entry->ipc = ipc;

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
        call_entry);
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
    ipc->error_cb(ipc, res, ipc->user_arg);
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
globus_l_gfs_ipc_reply_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_call_entry_t *       call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) user_arg;

    /* call the user callback */
    call_entry->cb(
        call_entry->ipc_handle, call_entry->reply, call_entry->cached_res,
        call_entry->user_arg);

    /* free the resources */
    globus_free(call_entry);
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
            ipc->error_cb(ipc, result, ipc->error_user_arg);
        }
    }
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply)
{
    globus_gfs_ipc_call_entry_t *       call_entry;

    globus_mutex_lock(&ipc_handle->mutex);
    {
        /* if local register one shot to get out of recurisve call stack
            troubles */
        if(ipc->local)
        {
            call_entry = (globus_gfs_ipc_call_entry_t *) 
                globus_hashtable_remove(
                    &ipc_handle->call_table,
                    reply->id);
            if(call_entry == NULL)
            {
                goto err;
            }

            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_reply_kickout,
                call_entry);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* serialize the reply */
            buffer = globus_malloc(ipc_handle->reply_size);
            ptr = buffer;
            GFSEncodeChar(buffer, ipc_handle->reply_size, ptr, _REPLY);
            GFSEncodeUInt32(buffer, ipc_handle->reply_size, ptr, reply->id);
            GFSEncodeUInt32(buffer, ipc_handle->reply_size, ptr, reply->code);
            GFSEncodeUInt32(
                buffer, ipc_handle->reply_size, ptr, strlen(reply->msg));
            GFSEncodeString(
                buffer, ipc_handle->reply_size, ptr, reply->msg);

            /* encode the specific types */
            switch(reply->type)
            {
                case:
            }

            buffer_len = ptr - buffer;
            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                buffer_len,
                buffer_len,
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
    globus_gfs_ipc_call_entry_t *       call_entry;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_callback_t           error_cb = NULL;

    call_entry = (globus_gfs_ipc_call_entry_t *) user_arg;
    ipc = call_entry->ipc;

    globus_free(buffer);
    /* on error remoe from the hashtable.  we could just wait for the
       close for this but we may as well have this callback do something */
    if(result != GLOBUS_SUCESS)
    {
        globus_mutex_lock(&ipc->mutex);
        {
            globus_hashtable_remove(&ipc->call_table, call_entry->id);
            error_cb = call_entry->error_cb;
        }
        globus_mutex_unlock(&ipc->mutex);

        if(error_cb)
        {
            error_cb(call_entry->ipc, 
                &call_entry->reply, result, call_entry->user_arg);
            globus_free(call_entry);
        }
    }
}

/*
 *  call the remote function
 */
globus_result_t
globus_gfs_ipc_set_state(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_server_state_t *         server_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_call_entry_t *       call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
    call_entry->id = (int) call_entry;
    call_entry->cb = cb;
    call_entry->user_arg = user_arg;

    globus_hashtable_insert(
        &ipc_handle->call_table,
        call_entry->id,
        (void *) call_entry);
    
    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        result = ipc_handle->iface->state_func(
            ipc_handle,
            call_entry->id,
            server_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}


/*
 *  receive
 *
 *  tell the remote process to receive a file
 */
globus_result_t
globus_gfs_ipc_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_state_t *       recv_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_call_entry_t *       call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
    call_entry->id = (int) call_entry;
    call_entry->cb = cb;
    call_entry->event_cb = event_cb;
    call_entry->user_arg = user_arg;

    globus_hashtable_insert(
        &ipc_handle->call_table,
        call_entry->id,
        (void *) call_entry);
    
    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        result = ipc_handle->iface->recv_func(
            ipc_handle,
            call_entry->id,
            recv_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}


/*
 *  send
 *  
 *  tell remote process to send a file
 */

globus_result_t
globus_gfs_ipc_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_call_entry_t *       call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
    call_entry->id = (int) call_entry;
    call_entry->cb = cb;
    call_entry->event_cb = event_cb;
    call_entry->user_arg = user_arg;

    globus_hashtable_insert(
        &ipc_handle->call_table,
        call_entry->id,
        (void *) call_entry);
    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        result = ipc_handle->iface->send_func(
            ipc_handle,
            call_entry->id,
            send_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}

globus_result_t
globus_gfs_ipc_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_call_entry_t *       call_entry;

    globus_mutex_lock(&ipc->mutex);
    {
        call_entry = (globus_gfs_ipc_call_entry_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
        if(call_entry == NULL)
        {
            goto err;
        }
        call_entry->id = (int) call_entry;
        call_entry->cb = cb;
        call_entry->event_cb = event_cb;
        call_entry->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            call_entry->id,
            (void *) call_entry);

        if(ipc->local)
        {
            res = ipc_handle->iface->passive_func(
                ipc,
                call_entry->id,
                data_state);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
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
    if(call_entry != NULL)
    {
        globus_free(call_entry);
    }
    return res;
}
/*
 *  command
 *
 *  tell remote side to execute the given command
 */
globus_result_t
globus_gfs_ipc_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_command_state_t *        cmd_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_size_t                       size;
    globus_byte_t *                     buffer;
    globus_result_t                     res;
    globus_gfs_ipc_call_entry_t *       call_entry;
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        call_entry = (globus_gfs_ipc_call_entry_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
        if(call_entry == NULL)
        {
            goto err;
        }
        call_entry->id = (int) call_entry;
        call_entry->cb = cb;
        call_entry->user_arg = user_arg;
        call_entry->ipc_handle = ipc_handle;

        globus_hashtable_insert(
            &ipc->call_table,
            call_entry->id,
            (void *) call_entry);

        if(ipc->local)
        {
            res = ipc->iface->command_func(
                ipc,
                call_entry->id,
                cmd_state);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
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

            call_entry->buffer = buffer;
            call_entry->buffer_len = ptr - buffer;

            /* now that we know size, add it in */
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, call_entry->buffer_len);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                call_entry->buffer,
                call_entry->buffer_len,
                call_entry->buffer_len,
                globus_l_gfs_ipc_write_cb,
                call_entry);
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
    if(call_entry != NULL)
    {
        globus_free(call_entry);
    }

    return res;
}

/*
 *  active data
 *
 *  tell remote side to create an active data connection
 */
globus_result_t
globus_gfs_ipc_active_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_call_entry_t *       call_entry;

    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        call_entry = (globus_gfs_ipc_call_entry_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
        if(call_entry == NULL)
        {
            goto err;
        }
        call_entry->id = (int) call_entry;
        call_entry->cb = cb;
        call_entry->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            call_entry->id,
            (void *) call_entry);
    
        if(ipc->local)
        {
            res = ipc_handle->iface->active_func(
                ipc_handle,
                call_entry->id,
                data_state);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
        else
        {
            size = GFS_IPC_DEFAULT_BUFFER_SIZE;
            buffer = globus_malloc(size);
            ptr = buffer;
            GFSEncodeChar(buffer, size, ptr, GLOBUS_GFS_IPC_TYPE_ACTIVE);
            GFSEncodeUInt32(buffer, size, ptr, call_entry->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, -1);
            GFSEncodeUInt32(buffer, size, ptr, data_state->cs_count);
            for(ctr = 0; ctr < data_state->cs_count; ctr++)
            {
                GFSEncodeString(
                    buffer, size, ptr, data_state->contact_strings[ctr]);
            }
            GFSEncodeUInt32(buffer, size, ptr, data_state->net_prt);

            call_entry->buffer = buffer;
            call_entry->buffer_len = ptr - buffer;

            /* now that we know size, add it in */
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, call_entry->buffer_len);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                call_entry->buffer,
                call_entry->buffer_len,
                call_entry->buffer_len,
                globus_l_gfs_ipc_write_cb,
                call_entry);
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
    if(call_entry != NULL)
    {
        globus_free(call_entry);
    }
    return res;
}


/*
 *  passive data
 *
 *  tell remote side to do passive data connection
 */

globus_result_t
globus_gfs_ipc_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_call_entry_t *       call_entry = NULL;
    globus_byte_t *                     buffer = NULL;

    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        call_entry = (globus_gfs_ipc_call_entry_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
        if(call_entry == NULL)
        {
            goto err;
        }
        call_entry->id = (int) call_entry;
        call_entry->cb = cb;
        call_entry->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            call_entry->id,
            (void *) call_entry);
    
        if(ipc->local)
        {
            res = ipc_handle->iface->passive_func(
                ipc_handle,
                call_entry->id,
                data_state);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
        else
        {
            size = GFS_IPC_DEFAULT_BUFFER_SIZE;
            buffer = globus_malloc(size);
            ptr = buffer;
            GFSEncodeChar(buffer, size, ptr, GLOBUS_GFS_IPC_TYPE_PASSIVE);
            GFSEncodeUInt32(buffer, size, ptr, call_entry->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, -1);
            GFSEncodeUInt32(buffer, size, ptr, data_state->min);
            GFSEncodeUInt32(buffer, size, ptr, data_state->max);
            GFSEncodeUInt32(buffer, size, ptr, data_state->best);
            GFSEncodeUInt32(buffer, size, ptr, data_state->net_prt);

            call_entry->buffer = buffer;
            call_entry->buffer_len = ptr - buffer;

            /* now that we know size, add it in */
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, call_entry->buffer_len);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                call_entry->buffer,
                call_entry->buffer_len,
                call_entry->buffer_len,
                globus_l_gfs_ipc_write_cb,
                call_entry);
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
    if(call_entry != NULL)
    {
        globus_free(call_entry);
    }
    return res;
}


/*
 *  send resource request
 */

globus_result_t
globus_gfs_ipc_resource_query(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_resource_state_t *       resource_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_call_entry_t *       call_entry = NULL;
    globus_byte_t *                     buffer = NULL;

    globus_mutex_lock(&ipc->mutex);
    {
        call_entry = (globus_gfs_ipc_call_entry_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t));
        if(call_entry == NULL)
        {
            goto err;
        }
        call_entry->id = (int) call_entry;
        call_entry->cb = cb;
        call_entry->user_arg = user_arg;

        globus_hashtable_insert(
            &ipc_handle->call_table,
            call_entry->id,
            (void *) call_entry);
    
        if(ipc->local)
        {
            res = ipc_handle->iface->resource_func(
                ipc_handle,
                call_entry->id,
                resource_state);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
        else
        {
            size = GFS_IPC_DEFAULT_BUFFER_SIZE;
            buffer = globus_malloc(size);
            ptr = buffer;
            GFSEncodeChar(buffer, size, ptr, GLOBUS_GFS_IPC_TYPE_PASSIVE);
            GFSEncodeUInt32(buffer, size, ptr, call_entry->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, -1);
            GFSEncodeString(buffer, size, ptr, resource_state->pathname);
            GFSEncodeUInt32(buffer, size, ptr, resource_state->mask);

            call_entry->buffer = buffer;
            call_entry->buffer_len = ptr - buffer;

            /* now that we know size, add it in */
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, size, ptr, call_entry->buffer_len);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                call_entry->buffer,
                call_entry->buffer_len,
                call_entry->buffer_len,
                globus_l_gfs_ipc_write_cb,
                call_entry);
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
    if(call_entry != NULL)
    {
        globus_free(call_entry);
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
    globus_result_t                     result;

    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        result = ipc_handle->iface->data_destroy_func(data_connection_id);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}



globus_result_t
globus_gfs_ipc_open(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t *            iface,
    char *                              user_name,
    char *                              contact_string,
    globus_bool_t                       passive,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_handle_t));
    
    ipc->iface = iface;
    
    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    globus_mutex_init(ipc->mutex, NULL);

    /* if local punt on all the xio stuff */
    if(cb == NULL)
    {
        ipc->local = GLOBUS_TRUE;
        return GLOBUS_SUCCESS;
    }

    /* do xio open */
    globus_mutex_lock(&ipc->mutex);
    {
        if(!passive)
        {
            res = globus_xio_handle_create(
                &ipc->xio_handle, globus_l_gfs_ipc_stack);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }

            ipc->cb = cb;
            ipc->user_arg = user_arg;
            ipc->error_cb = error_cb;
            ipc->state = GLOBUS_GFS_IPC_STATE_OPENNING;
            res = globus_xio_register_open(
                &ipc->xio_handle,
                contact_string,
                NULL,
                globus_l_gfs_ipc_open_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    *ipc_handle = ipc;
    
    return GLOBUS_SUCCESS;

  err:
    globus_hashtable_destroy(&ipc->call_table);
    globus_mutex_destroy(&ipc->mutex);
    globus_free(ipc);

    return res;
}

globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t *           ipc_handle,
    cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

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
            ipc->user_arg = user_arg;
            case(ipc->state)
            {
                case GLOBUS_GFS_IPC_STATE_OPENNING:
                case GLOBUS_GFS_IPC_STATE_OPEN:

                ipc->state = GLOBUS_GFS_IPC_STATE_CLOSING;
                res = globus_xio_register_close(
                    ipc->handle,
                    NULL,
                    globus_l_gfs_ipc_close_cb,
                    ipc);
                break;

                default:
                    res = ERROR;
                    break;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    return res;
}

