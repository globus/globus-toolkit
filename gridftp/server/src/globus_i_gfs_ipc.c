
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

#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
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

#define GFSEncodeChar(_start, _len, _buf, _w)                           \
do                                                                      \
{                                                                       \
    if((globus_byte_t *)_buf - (globus_byte_t *)_start >= _len)         \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
    }                                                                   \
    *_buf = _w;                                                         \
    _buff++;                                                            \
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

/**********************************************************************
 *  IPC communication functions
 *
 *********************************************************************/
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
    globus_gfs_ipc_handle_t             ipc_handle,

    call_entry = (globus_gfs_ipc_call_entry_t *) user_arg;
    ipc_handle = call_entry->ipc_handle;

    globus_mutex_lock(&ipc_handle->mutex);
    {
        if(result != GLOBUS_SUCESS)
        {
        }
        else
        {
            /* simply process the next message */
            ipc_handle->writting = GLOBUS_FALSE;
            globus_l_gfs_ipc_msg_next(ipc_handle);
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    globus_free(call_entry->buffer);
    globus_free(call_entry);
}

static void
globus_l_gfs_ipc_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_gfs_ipc_handle_t             ipc_handle;

    ipc_handle = (globus_gfs_ipc_handle_t) user_arg;


}

static globus_result_t
globus_l_gfs_ipc_msg_next(
    globus_gfs_ipc_handle_t             ipc_handle)
{
    globus_gfs_ipc_call_entry_t *       call_entry;
    globus_result_t                     res;

    /* if writting already do nothing */
    if(ipc_handle->writting)
    {
        return GLOBUS_SUCCESS;
    }

    call_entry = (globus_gfs_ipc_call_entry_t *)
        globus_fifo_dequeue(ipc_handle->write_q);

    /* if the list is empty, do nothing */
    if(call_entry == NULL)
    {
        return GLOBUS_SUCCESS;
    }

    ipc_handle->writting = GLOBUS_TRUE;
    res = globus_xio_register_write(
        ipc_handle->xio_handle,
        call_entry->buffer,
        call_entry->buffer_len,
        call_entry->buffer_len,
        globus_l_gfs_ipc_write_cb,
        call_entry);

    return res;
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

    /* XX parameter checlking */
    globus_mutex_lock(&ipc_handle->mutex);
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
            &ipc_handle->call_table,
            call_entry->id,
            (void *) call_entry);
    
        if(ipc_handle->xio_handle == GLOBUS_NULL)
        {
            res = ipc_handle->iface->command_func(
                ipc_handle,
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
            GFSEncodeChar(buffer, size, ptr, GFS_IPC_PROC_ID_RECV);
            GFSEncodeUInt32(buffer, size, ptr, id);
            GFSEncodeUInt32(buffer, size, ptr, cmd_state->command);
            GFSEncodeString(buffer, size, ptr, cmd_state->pathname);
            GFSEncodeUInt64(buffer, size, ptr, cmd_state->cksm_offset);
            GFSEncodeUInt64(buffer, size, ptr, cmd_state->cksm_length);
            GFSEncodeString(buffer, size, ptr, cmd_state->cksm_alg);
            GFSEncodeString(buffer, size, ptr, cmd_state->cksm_response);
            GFSEncodeUInt32(buffer, size, ptr, cmd_state->chmod_mode);
            GFSEncodeString(buffer, size, ptr, cmd_state->rnfr_pathname);

            call_entry->buffer = buffer;

            globus_fifo_enqueue(ipc_handle->write_q, call_entry);
            res = globus_l_gfs_ipc_msg_next(ipc_handle);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);
    
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
        result = ipc_handle->iface->active_func(
            ipc_handle,
            call_entry->id,
            data_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
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
        result = ipc_handle->iface->passive_func(
            ipc_handle,
            call_entry->id,
            data_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}


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
        result = ipc_handle->iface->resource_func(
            ipc_handle,
            call_entry->id,
            resource_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}


/* 
 *  tell remote side to provide list info
 */

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
        result = ipc_handle->iface->passive_func(
            ipc_handle,
            call_entry->id,
            data_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
}

globus_result_t
globus_gfs_ipc_init(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_handle_t                 xio_handle)
{
    ipc_handle = (globus_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_handle_t));
    
    ipc_handle->xio_handle = xio_handle;
    ipc_handle->iface = iface;
    
    globus_hashtable_init(
        &ipc_handle->call_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_gfs_ipc_reply(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply)
{

    return GLOBUS_SUCCESS;
}


