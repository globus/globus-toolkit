
#include "globus_i_gridftp_server.h"
#include "globus_gridftp_server.h"

static globus_xio_driver_t              globus_l_gfs_tcp_driver = GLOBUS_NULL;

/*
 *  header:
 *  type:    single charater representing type of message
 *  id:      4 bytes of message id
 *  size:    remaining size of message
 */
#define GFS_IPC_HEADER_SIZE         (sizeof(uint32_t)+sizeof(uint32_t)+1)
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
        goto decode_err;                                                \
    }                                                                   \
    memcpy(&_cw, _buf, 4);                                              \
    _w = htonl((uint32_t)_cw);                                          \
    _buf += 4;                                                          \
    _len -= 4;                                                          \
} while(0)


/*
 *  if architecture is big endian already
 */
#ifdef WORDS_BIGENDIAN                                               

#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    if((globus_byte_t *)_buf - (globus_byte_t *)_start + 8 > _len)      \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
    }                                                                   \
    memcpy(_buf, &_w, 8);                                               \
    _buf += 8;                                                          \
} while(0)

#define GFSDecodeUInt64(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    if(_len - 8 <= 0)                                                   \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
                                                                        \
    memcpy(&_w, _buf, 8);                                               \
    _buf += 8;                                                          \
    _len -= 8;                                                          \
} while(0)

#else                                                                
/* not a big indian arch */
#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    uint64_t                            _cw;                            \
    uint32_t                            _lo = _w & 0xffffffff;          \
    uint32_t                            _hi = _w >> 32U;                \
                                                                        \
    if((globus_byte_t *)_buf - (globus_byte_t *)_start + 8 > _len)      \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
    }                                                                   \
                                                                        \
    _lo = ntohl(_lo);                                                   \
    _hi = ntohl(_hi);                                                   \
    _cw = ((uint64_t) _lo) << 32U | _hi;                                \
    memcpy(_buf, &_cw, 8);                                              \
    _buf += 8;                                                          \
} while(0)

#define GFSDecodeUInt64(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    uint64_t                            _cw;                            \
    uint32_t                            _lo;                            \
    uint32_t                            _hi;                            \
                                                                        \
    if(_len - 8 <= 0)                                                   \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
                                                                        \
    memcpy(&_w, _buf, 8);                                               \
    _lo = _w & 0xffffffff;                                              \
    _hi = _w >> 32U;                                                    \
    _lo = ntohl(_lo);                                                   \
    _hi = ntohl(_hi);                                                   \
    _cw = ((uint64_t) _lo) << 32U | _hi;                                \
    _buf += 8;                                                          \
    _len -= 8;                                                          \
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
    *_buf = (char)_w;                                                   \
    _buf++;                                                             \
} while(0)

#define GFSDecodeChar(_buf, _len, _w)                                   \
do                                                                      \
{                                                                       \
    if(_len - 1 <= 0)                                                   \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    _w = *_buf;                                                         \
    _buf++;                                                             \
    _len--;                                                             \
} while(0)

#define GFSEncodeString(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    char *                              _str;                           \
    for(_str = (char *)_w; *_str != '\0'; _str++)                       \
    {                                                                   \
        GFSEncodeChar(_start, _len, _buf, *_str);                       \
    }                                                                   \
    GFSEncodeChar(_start, _len, _buf, *_str);                           \
} while(0)

#define GFSDecodeString(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    int                                 _ctr;                           \
    /* make sure that strip in terminated properly */                   \
    for(_ctr = 0; _ctr < _len && _buf[_ctr] != '\0'; _ctr++);           \
    if(_buf[_ctr] != '\0')                                              \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    _w = strdup(_buf);                                                  \
    _buf += strlen(_buf) + 1;                                           \
} while(0)

/*** XXX  this will eventually determine if the data node is part of a
 * a different process and perform ipc to that process.  for now, the data
 * node is assumed to be part of the same process and these calls are merely
 * wrappers
 */
 
globus_gfs_ipc_iface_t  globus_gfs_ipc_default_iface = 
{
    globus_i_gfs_data_recv_request,
    globus_i_gfs_data_send_request,
    globus_i_gfs_data_command_request,
    globus_i_gfs_data_active_request,
    globus_i_gfs_data_passive_request,
    NULL,
    globus_i_gfs_data_resource_request,
    globus_i_gfs_data_list_request,
    NULL,
    NULL
};

typedef struct
{
    void *                              callback1;
    void *                              callback2;
    void *                              user_arg;
} globus_l_gfs_ipc_bounce_t;

typedef struct globus_i_gfs_ipc_handle_s
{
    uid_t                               uid;
    const char *                        contact_string;
    globus_xio_handle_t                 xio_handle;
    globus_bool_t                       local;

    globus_hashtable_t                  call_table;
    globus_gfs_ipc_iface_t *            iface;

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
    globus_gfs_ipc_reply_t *            reply;
} globus_gfs_ipc_request_t;

static globus_xio_stack_t               globus_l_gfs_ipc_stack;

static void
globus_l_gfs_ipc_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

/************************************************************************
 *   open
 *
 *  open, on error call open_cb with an error, not error_cb
 ***********************************************************************/
static void
globus_l_gfs_ipc_open_kickout(
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_result_t                     res;
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
    if(ipc->open_cb != NULL)
    {
        ipc->open_cb(ipc, GLOBUS_SUCCESS, ipc->open_arg);
    }

    if(!ipc->local)
    {
        new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
        res = globus_xio_register_read(
            ipc->xio_handle,
            new_buf,
            GFS_IPC_HEADER_SIZE,
            GFS_IPC_HEADER_SIZE,
            NULL,
            globus_l_gfs_ipc_read_header_cb,
            ipc);
        if(res != GLOBUS_SUCCESS && ipc->error_cb)
        {
            ipc->error_cb(ipc, res, ipc->error_arg);
            globus_free(new_buf);
        }
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
    globus_gfs_ipc_iface_t *            iface,
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
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        res = GlobusGFSErrorMemory("ipc");
        goto err;
    }
    ipc->iface = iface;
    ipc->contact_string = contact_string;
    ipc->open_cb = open_cb;
    ipc->error_cb = error_cb;
    ipc->open_arg = open_arg;
    ipc->error_arg = error_arg;
    ipc->state = GLOBUS_GFS_IPC_STATE_OPENING;
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_mutex_init(&ipc->mutex, NULL);

    /* if local fake the callback */
    if(ipc->contact_string == NULL)
    {
        ipc->local = GLOBUS_TRUE;
        res = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_ipc_open_kickout,
            ipc);
    }
    /* do xio open */
    else
    {
        ipc->local = GLOBUS_FALSE;

        res = globus_xio_driver_load("tcp", &globus_l_gfs_tcp_driver);
        
        res = globus_xio_stack_init(
            &globus_l_gfs_ipc_stack, GLOBUS_NULL);
    
        res = globus_xio_stack_push_driver(
            globus_l_gfs_ipc_stack, globus_l_gfs_tcp_driver);

        res = globus_xio_handle_create(
            &ipc->xio_handle, globus_l_gfs_ipc_stack);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        res = globus_xio_register_open(
            ipc->xio_handle,
            ipc->contact_string,
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
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_handle_t                 xio_handle,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc = NULL;
    globus_result_t                     res;
    globus_byte_t *                     read_buf;
    
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
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        res = GlobusGFSErrorMemory("ipc");
        goto err;
    }
    ipc->iface = iface;
    ipc->error_cb = error_cb;
    ipc->error_arg = error_arg;
    ipc->local = GLOBUS_FALSE;
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    ipc->xio_handle = xio_handle;

    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_mutex_init(&ipc->mutex, NULL);

    read_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
    res = globus_xio_register_read(
        ipc->xio_handle,
        read_buf,
        GFS_IPC_HEADER_SIZE,
        GFS_IPC_HEADER_SIZE,
        NULL,
        globus_l_gfs_ipc_read_header_cb,
        ipc);
    if(res != GLOBUS_SUCCESS && ipc->error_cb)
    {
        ipc->error_cb(ipc, res, ipc->error_arg);
        globus_free(read_buf);
    }

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

/*
 *  decode functions
 */
static globus_gfs_command_state_t *
globus_l_gfs_ipc_unpack_command(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_command_state_t *        cmd_state;

    cmd_state = (globus_gfs_command_state_t *)
        globus_malloc(sizeof(globus_gfs_command_state_t));
    if(cmd_state == NULL)
    {
        return NULL;
    }

    GFSDecodeUInt32(buffer, len, cmd_state->command);
    GFSDecodeString(buffer, len, cmd_state->pathname);
    GFSDecodeUInt64(buffer, len, cmd_state->cksm_offset);
    GFSDecodeUInt64(buffer, len, cmd_state->cksm_length);
    GFSDecodeString(buffer, len, cmd_state->cksm_alg);
    GFSDecodeString(buffer, len, cmd_state->cksm_response);
    GFSDecodeUInt32(buffer, len, cmd_state->chmod_mode);
    GFSDecodeString(buffer, len, cmd_state->rnfr_pathname);

    return cmd_state;

  decode_err:
    globus_free(cmd_state);

    return NULL;
}

static globus_gfs_transfer_state_t *
globus_l_gfs_ipc_unpack_transfer(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_transfer_state_t *       trans_state;
    int                                 ctr;
    int                                 range_size;
    globus_off_t                        offset;
    globus_off_t                        length;

    trans_state = (globus_gfs_transfer_state_t *)
        globus_malloc(sizeof(globus_gfs_transfer_state_t));
    if(trans_state == NULL)
    {
        return NULL;
    }
    globus_range_list_init(&trans_state->range_list);

    GFSDecodeString(buffer, len, trans_state->pathname);
    GFSDecodeString(buffer, len, trans_state->module_name);
    GFSDecodeString(buffer, len, trans_state->module_args);
    GFSDecodeUInt64(buffer, len, trans_state->partial_offset);
    GFSDecodeUInt64(buffer, len, trans_state->partial_length);

    /* unpack range list */
    GFSDecodeUInt32(buffer, len, range_size);
    for(ctr = 0; ctr < range_size; ctr++)
    {
        GFSDecodeUInt64(buffer, len, offset);
        GFSDecodeUInt64(buffer, len, length);
        globus_range_list_insert(trans_state->range_list, offset, length);
    }
    GFSDecodeUInt32(buffer, len, trans_state->data_handle_id);

    /* unpack op */

    return trans_state;

  decode_err:
    globus_range_list_destroy(trans_state->range_list);
    globus_free(trans_state);

    return NULL;
}

static globus_gfs_data_state_t *
globus_l_gfs_ipc_unpack_data(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_data_state_t *           data_state;
    char                                ch;
    int                                 ctr;

    data_state = (globus_gfs_data_state_t *)
        globus_malloc(sizeof(globus_gfs_data_state_t));
    if(data_state == NULL)
    {
        return NULL;
    }

    GFSDecodeChar(buffer, len, ch);
    data_state->ipv6 = (globus_bool_t) ch;
    GFSDecodeUInt32(buffer, len, data_state->nstreams);
    GFSDecodeChar(buffer, len, data_state->mode);
    GFSDecodeChar(buffer, len, data_state->type);
    GFSDecodeUInt32(buffer, len, data_state->tcp_bufsize);
    GFSDecodeUInt32(buffer, len, data_state->blocksize);
    GFSDecodeChar(buffer, len, data_state->prot);
    GFSDecodeChar(buffer, len, data_state->dcau);
    GFSDecodeChar(buffer, len, ch);
    data_state->net_prt = ch;

    GFSDecodeUInt32(buffer, len, data_state->cs_count);
    for(ctr = 0; ctr < data_state->cs_count; ctr++)
    {
        GFSDecodeString(buffer, len, data_state->contact_strings[ctr]);
    }

    return data_state;

  decode_err:
    globus_free(data_state);

    return NULL;
}

static globus_gfs_resource_state_t *
globus_l_gfs_ipc_unpack_resource(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_resource_state_t *       resource_state;
    char                                ch;

    resource_state = (globus_gfs_resource_state_t *)
        globus_malloc(sizeof(globus_gfs_resource_state_t));
    if(resource_state == NULL)
    {
        return NULL;
    }

    GFSDecodeChar(buffer, len, ch);
    resource_state->file_only = (globus_bool_t) ch;
    GFSDecodeString(buffer, len, resource_state->pathname);

    return resource_state;

  decode_err:
    globus_free(resource_state);

    return NULL;
}

static int
globus_l_gfs_ipc_unpack_data_destroy(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    int *                               data_connection_id)
{
    int                                 id;

    GFSDecodeUInt32(buffer, len, id);
    *data_connection_id = id;

    return 0;

  decode_err:

    return -1;
}

static char *
globus_l_gfs_ipc_unpack_user(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    char *                              user_dn;

    GFSDecodeString(buffer, len, user_dn);
                                                                                
    return user_dn;

  decode_err:

    return NULL;
}

static int
globus_l_gfs_ipc_unpack_cred(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    gss_buffer_desc *                   out_gsi_buffer)
{
    gss_buffer_desc                     gsi_buffer;

    GFSDecodeUInt32(buffer, len, gsi_buffer.length);
    gsi_buffer.value = buffer;

    *out_gsi_buffer = gsi_buffer;

    return 0;

  decode_err:

    return -1;
}

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
    globus_byte_t *                     new_buf = NULL;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_command_state_t *        cmd_state;
    globus_gfs_transfer_state_t *       trans_state;
    globus_gfs_data_state_t *           data_state;
    globus_gfs_resource_state_t *       resource_state;
    int                                 rc;
    int                                 data_connection_id;
    gss_buffer_desc                     gsi_buffer;
    gss_cred_id_t                       cred;
    char *                              user_dn;

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
            break;

        case GLOBUS_GFS_IPC_TYPE_AUTH:
            rc = globus_l_gfs_ipc_unpack_cred(ipc, buffer, len, &gsi_buffer);
            if(rc != 0)
            {
            }
            ipc->iface->set_cred(ipc, request->id, cred);
            break;

        case GLOBUS_GFS_IPC_TYPE_USER:
            user_dn = globus_l_gfs_ipc_unpack_user(ipc, buffer, len);
            if(user_dn == NULL)
            {
            }
            ipc->iface->set_user(ipc, request->id, user_dn);
            break;

        case GLOBUS_GFS_IPC_TYPE_RESOURCE:
            resource_state = globus_l_gfs_ipc_unpack_resource(
                ipc, buffer, len);
            if(resource_state == NULL)
            {
            }
            ipc->iface->resource_func(ipc, request->id, resource_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_RECV:
            trans_state = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_state == NULL)
            {
            }
            ipc->iface->recv_func(ipc, request->id, trans_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_SEND:
            trans_state = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_state == NULL)
            {
            }
            ipc->iface->send_func(ipc, request->id, trans_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_LIST:
            trans_state = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_state == NULL)
            {
            }
            ipc->iface->list_func(ipc, request->id, trans_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_COMMAND:
            cmd_state = globus_l_gfs_ipc_unpack_command(ipc, buffer, len);
            if(cmd_state == NULL)
            {
            }
            ipc->iface->command_func(ipc, request->id, cmd_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_PASSIVE:
            data_state = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
            if(data_state == NULL)
            {
            }
            ipc->iface->passive_func(ipc, request->id, data_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_ACTIVE:
            data_state = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
            if(data_state == NULL)
            {
            }
            ipc->iface->active_func(ipc, request->id, data_state);
            break;

        case GLOBUS_GFS_IPC_TYPE_DESTROY:
            rc = globus_l_gfs_ipc_unpack_data_destroy(
                ipc, buffer, len, &data_connection_id);
            if(rc != 0)
            {
            }
            ipc->iface->data_destroy_func(data_connection_id);

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
        globus_l_gfs_ipc_read_header_cb,
        ipc);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_free(buffer);

    return;

  err:
    globus_free(buffer);
    if(new_buf != NULL)
    {
        globus_free(new_buf);
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
                    res = GlobusGFSErrorIPC();
                    goto lock_err;
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
                    goto lock_err;
                }
                request->id = id;
                request->type = type;
                request->ipc = ipc;

            default:
                res = GlobusGFSErrorIPC();
                goto lock_err;
                break;
        }

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
            goto lock_err;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    return;

  lock_err:
    globus_mutex_unlock(&ipc->mutex);

  decode_err:
  err:
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(ipc->error_cb != NULL)
    {
        ipc->error_cb(ipc, res, ipc->error_arg);
    }
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
        request->reply,
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
        request->reply,
        request->user_arg);

    /* dont! free the resources */
    //globus_free(request);
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

            request->reply = reply;
            request->type = reply->type;
            
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_finished_reply_kickout,
                request);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_FINAL_REPLY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack the body--this part is like a reply header */
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
                case GLOBUS_GFS_IPC_TYPE_AUTH:
                    break;

                case GLOBUS_GFS_IPC_TYPE_RECV:
                    break;

                case GLOBUS_GFS_IPC_TYPE_SEND:
                    break;

                case GLOBUS_GFS_IPC_TYPE_LIST:
                    break;

                case GLOBUS_GFS_IPC_TYPE_COMMAND:
                    break;

                case GLOBUS_GFS_IPC_TYPE_PASSIVE:
                    break;

                case GLOBUS_GFS_IPC_TYPE_ACTIVE:
                    break;

                case GLOBUS_GFS_IPC_TYPE_DESTROY:
                    break;

                default:
                    break;
            }

            msg_size = ptr - buffer - GFS_IPC_HEADER_SIZE;
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
            
            request->reply = reply;
            request->type = reply->type;
            
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

        if(!ipc->local)
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_AUTH);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            /* body */
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
        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->set_user(ipc, request->id, user_dn);
    }

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
    gss_buffer_desc                     gsi_buffer;
    int                                 maj_rc;
    int                                 min_rc;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_set_cred);

    /* sreialize the cred */
    maj_rc = gss_export_cred(&min_rc, del_cred, NULL, 0, &gsi_buffer);
    if(maj_rc != GSS_S_COMPLETE)
    {
        return GlobusGFSErrorParameter("del_cred");
    }

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;

        if(!ipc->local)
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_AUTH);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, gsi_buffer.length);
            /* body */
            memcpy(ptr, gsi_buffer.value, gsi_buffer.length);

            msg_size = ptr - buffer + gsi_buffer.length;
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

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->set_cred(ipc, request->id, del_cred);
    }

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }

    return res;
    return GLOBUS_SUCCESS;
}

/* pack and send function for list send and receive */
static globus_result_t
globus_l_gfs_ipc_transfer_pack(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    globus_gfs_transfer_state_t *       trans_state,
    globus_gfs_ipc_request_t *          request)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    int                                 id;
    globus_result_t                     res;
    int                                 range_size;
    int                                 ctr;
    globus_off_t                        offset;
    globus_off_t                        length;

    id = (int) request;

    /* pack the header */
    buffer = globus_malloc(ipc->buffer_size);
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, id);
    size_ptr = ptr;
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
    /* pack the body */
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_state->pathname);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_state->module_name);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_state->module_args);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_state->partial_offset);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_state->partial_length);

    /* pack range list */
    range_size = globus_range_list_size(trans_state->range_list);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, id);
    for(ctr = 0; ctr < range_size; ctr++)
    {
        globus_range_list_at(trans_state->range_list, ctr, &offset, &length);
        GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, offset);
        GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, length);
    }

    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_state->data_handle_id);
    /* TODO: pack op */

    /* now that we know size, add it in */
    msg_size = ptr - buffer - GFS_IPC_HEADER_SIZE;
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

    res = globus_xio_register_write(
        ipc->xio_handle,
        buffer,
        msg_size,
        msg_size,
        NULL,
        globus_l_gfs_ipc_write_cb,
        request);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(buffer);
    }

    return res;
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
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_recv);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_IPC_TYPE_RECV, recv_state, request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->recv_func(ipc_handle, request->id, recv_state);
    }

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    return res;
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
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_send);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_IPC_TYPE_SEND, send_state, request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->send_func(ipc_handle, request->id, send_state);
    }

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    return res;
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
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_list);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_IPC_TYPE_LIST, data_state, request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->list_func(ipc_handle, request->id, data_state);
    }

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

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

        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_COMMAND);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, cmd_state->command);
            GFSEncodeString(buffer, ipc->buffer_size, ptr, cmd_state->pathname);
            GFSEncodeUInt64(
                buffer, ipc->buffer_size, ptr, cmd_state->cksm_offset);
            GFSEncodeUInt64(
                buffer, ipc->buffer_size, ptr, cmd_state->cksm_length);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_state->cksm_alg);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_state->cksm_response);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, cmd_state->chmod_mode);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_state->rnfr_pathname);

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

        globus_hashtable_insert(
            &ipc->call_table,
            (void *)request->id,
            request);

    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->command_func(ipc, request->id, cmd_state);
    }
    
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

static globus_result_t
globus_l_gfs_ipc_pack_data(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_request_t *          request)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    int                                 id;
    globus_result_t                     res;
    int                                 ctr;

    /* pack the header */
    buffer = globus_malloc(ipc->buffer_size);
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, id);
    size_ptr = ptr;
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

    /* pack body */
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_state->ipv6);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->nstreams);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_state->mode);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_state->type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->tcp_bufsize);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->blocksize);

    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_state->prot);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_state->dcau);

    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_state->net_prt);

    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_state->cs_count);
    for(ctr = 0; ctr < data_state->cs_count; ctr++)
    {
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, data_state->contact_strings[ctr]);
    }

    /* now that we know size, add it in */
    msg_size = ptr - buffer - GFS_IPC_HEADER_SIZE;
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

    res = globus_xio_register_write(
        ipc->xio_handle,
        buffer,
        msg_size,
        msg_size,
        NULL,
        globus_l_gfs_ipc_write_cb,
        request);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(buffer);
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
            res = GlobusGFSErrorMemory("request");
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_pack_data(
                ipc,
                GLOBUS_GFS_IPC_TYPE_ACTIVE,
                data_state,
                request); 
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    
        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->active_func(
            ipc_handle,
            request->id,
            data_state);
    }
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

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
    globus_gfs_ipc_request_t *          request;
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
            res = GlobusGFSErrorMemory("request");
            goto err;
        }
        request->id = (int) request;
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_pack_data(
                ipc,
                GLOBUS_GFS_IPC_TYPE_PASSIVE,
                data_state,
                request); 
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    
        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->passive_func(
            ipc_handle,
            request->id,
            data_state);
    }
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    return res;
}


/*
 *  send resource request
 */

globus_result_t
globus_gfs_ipc_request_resource(
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
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_request_resource);

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
        request->ipc = ipc_handle;

        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_COMMAND);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, resource_state->file_only);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, resource_state->pathname);

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

        globus_hashtable_insert(
            &ipc_handle->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->resource_func(
            ipc_handle,
            request->id,
            resource_state);
    }
    
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
globus_result_t
globus_gfs_ipc_data_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,   
    int                                 data_connection_id)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_byte_t *                     size_ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_data_destroy);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->id = (int) request;
        request->ipc = ipc_handle;

        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_IPC_TYPE_DESTROY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            size_ptr = ptr;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_connection_id);

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

        globus_hashtable_insert(
            &ipc->call_table,
            (void *)request->id,
            request);
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->data_destroy_func(data_connection_id);
    }

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

