#ifndef GLOBUS_I_GFS_IPC_H
#define GLOBUS_I_GFS_IPC_H

typedef struct globus_i_gfs_ipc_handle_s * globus_gfs_ipc_handle_t;

#include "globus_i_gridftp_server.h"

/************************************************************************
 *   packing macros
 *   --------------
 ***********************************************************************/
#define GFSEncodeUInt32(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    uint32_t                            _cw;                            \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    /* verify buffer size */                                            \
    if(_ndx + 4 > _len)                                                 \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
    _cw = htonl((uint32_t)_w);                                          \
    memcpy(_buf, &_cw, 4);                                              \
    _buf += 4;                                                          \
} while(0)

#define GFSDecodeUInt32P(_buf, _len, _w)                                \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if(_len - 4 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    memcpy(&_cw, _buf, 4);                                              \
    _w = (void *) htonl((uint32_t)_cw);                                 \
    _buf += 4;                                                          \
    _len -= 4;                                                          \
} while(0)

#define GFSDecodeUInt32(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if(_len - 4 < 0)                                                    \
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
#if !defined(WORDS_BIGENDIAN)


#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    if(_ndx + 8 > _len)                                                 \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
    memcpy(_buf, &_w, 8);                                               \
    _buf += 8;                                                          \
} while(0)

#define GFSDecodeUInt64(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    if(_len - 8 < 0)                                                    \
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
    globus_size_t                       _ndx;                           \
    uint64_t                            _cw;                            \
    uint32_t                            _lo = _w & 0xffffffff;          \
    uint32_t                            _hi = _w >> 32U;                \
                                                                        \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    if(_ndx + 8 > _len)                                                 \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
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
    if(_len - 8 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
                                                                        \
    memcpy(&_cw, _buf, 8);                                              \
    _lo = _cw & 0xffffffff;                                             \
    _hi = _cw >> 32U;                                                   \
    _lo = ntohl(_lo);                                                   \
    _hi = ntohl(_hi);                                                   \
    _w = ((uint64_t) _lo) << 32U | _hi;                                 \
    _buf += 8;                                                          \
    _len -= 8;                                                          \
} while(0)
#endif                                                               

#define GFSEncodeChar(_start, _len, _buf, _w)                           \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    if(_ndx >= _len)                                                    \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
    *_buf = (char)_w;                                                   \
    _buf++;                                                             \
} while(0)

#define GFSDecodeChar(_buf, _len, _w)                                   \
do                                                                      \
{                                                                       \
    if(_len - 1 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    _w = (char)*_buf;                                                   \
    _buf++;                                                             \
    _len--;                                                             \
} while(0)

#define GFSEncodeString(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    char *                              _str=(char*)_w;                 \
    if(_str == NULL)                                                    \
    {                                                                   \
        GFSEncodeUInt32(_start, _len, _buf, 0);                         \
    }                                                                   \
    else                                                                \
    {                                                                   \
        GFSEncodeUInt32(_start, _len, _buf, strlen(_str)+1);            \
        for(_str = (char *)_w; *_str != '\0'; _str++)                   \
        {                                                               \
            GFSEncodeChar(_start, _len, _buf, *_str);                   \
        }                                                               \
    }                                                                   \
} while(0)

#define GFSDecodeString(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    int                                 _ctr;                           \
    uint32_t                            _sz;                            \
    /* make sure that strip in terminated properly */                   \
    GFSDecodeUInt32(_buf, _len, _sz);                                   \
    if(_sz > 0)                                                         \
    {                                                                   \
        _w = malloc(_sz);                                               \
        for(_ctr = 0; _ctr < _sz - 1; _ctr++)                           \
        {                                                               \
            GFSDecodeChar(_buf, _len, _w[_ctr]);                        \
        }                                                               \
        _w[_ctr] = '\0';                                                \
    }                                                                   \
    else                                                                \
    {                                                                   \
        _w = NULL;                                                      \
    }                                                                   \
} while(0)

typedef globus_gfs_operation_type_t     globus_gfs_ipc_request_type_t;
typedef globus_gfs_finished_info_t      globus_gfs_ipc_reply_t;
typedef globus_gfs_event_info_t         globus_gfs_ipc_event_reply_t;
typedef globus_gfs_data_finished_info_t globus_gfs_ipc_data_reply_t;
typedef globus_gfs_cmd_finshed_info_t   globus_gfs_ipc_command_reply_t;
typedef globus_gfs_stat_finished_info_t globus_gfs_ipc_stat_reply_t;

typedef enum
{
    GLOBUS_GFS_IPC_USER_TYPE_INT32,
    GLOBUS_GFS_IPC_USER_TYPE_INT64,
    GLOBUS_GFS_IPC_USER_TYPE_CHAR,
    GLOBUS_GFS_IPC_USER_TYPE_STRING
} globus_gfs_ipc_user_type_t;

typedef struct globus_i_gfs_community_s
{
    char *                              root;
    char *                              name;
    int                                 cs_count;
    char **                             cs;
} globus_i_gfs_community_t;

/*
 *  callbacks
 *
 *  all functions have the same callback, they examine the
 *  globus_gfs_ipc_reply_t() structure for their specific info
 *
 *  error_cb
 *  can be called at anytime.  typically means the ipc connection broke
 *  in an irrecoverable way.  Even tho this is called all outstanding
 *  callbacks will still be called (but with an error)
 */
 
 /*
 *  replying
 *
 *  every comman requires a reply and comes with a reply id.  to reply
 *  the requested side must fill in the globus_gfs_ipc_reply_t
 *  structure and then pass it
 *  to the function: globus_gfs_ipc_reply();  That call will result in
 *  the ipc communication that will untilimately call the callback
 *  on the callers side.
 */
typedef void
(*globus_gfs_ipc_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_event_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_ipc_event_reply_t *      reply,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_open_close_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_error_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_reply_finished(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply);

globus_result_t
globus_gfs_ipc_reply_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_event_reply_t *      reply);

/*
 *  sending
 *
 *  every command has a corresponding iface function.  A call to a
 *  command function results in a call to the correspoding iface
 *  function on the other side of the channel.
 *
 *  all parmeters are wrapped in a structure corresponding to
 *  each function call type.  those structures are defined below
 */

typedef void
(*globus_i_gfs_ipc_data_callback_t)(
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg);

typedef void
(*globus_i_gfs_ipc_data_event_callback_t)(
    globus_gfs_ipc_event_reply_t *      reply,
    void *                              user_arg);

/*************************************************************************
 *  interface function
 *  ------------------
 *
 ************************************************************************/
/* works with handle get */
typedef void
(*globus_gfs_ipc_iface_session_start_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    const gss_ctx_id_t                  context,
    globus_gfs_session_info_t *         session_info,
    globus_i_gfs_ipc_data_callback_t    cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_start_session(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/* works with release */
typedef void
(*globus_gfs_ipc_iface_session_stop_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle);

globus_result_t
globus_gfs_ipc_iface_session_stop(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle);

typedef void
(*globus_gfs_ipc_iface_set_cred_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    gss_cred_id_t                       del_cred);

globus_result_t
globus_gfs_ipc_set_cred(
    globus_gfs_ipc_handle_t             ipc_handle,
    gss_cred_id_t                       del_cred);

typedef void
(*globus_gfs_ipc_iface_buffer_send_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    globus_byte_t *                     buffer,
    int                                 buffer_type,
    globus_size_t                       buffer_len);

globus_result_t
globus_gfs_ipc_request_buffer_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_byte_t *                     buffer,
    int                                 buffer_type,
    globus_size_t                       buffer_len);

/*
 *  receive
 *
 *  tell the remote process to receive a file
 */
typedef void
(*globus_gfs_ipc_iface_recv_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_transfer_info_t *        recv_info,
    globus_i_gfs_ipc_data_callback_t          cb,
    globus_i_gfs_ipc_data_event_callback_t    event_cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_info_t *        recv_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg);

/*
 *  send
 *  
 *  tell remote process to send a file
 */
typedef void
(*globus_gfs_ipc_iface_send_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_transfer_info_t *        send_info,
    globus_i_gfs_ipc_data_callback_t          cb,
    globus_i_gfs_ipc_data_event_callback_t    event_cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_info_t *        send_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_iface_list_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_transfer_info_t *        list_info,
    globus_i_gfs_ipc_data_callback_t    cb,
    globus_i_gfs_ipc_data_event_callback_t    event_cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_info_t *        data_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg);

/*
 *  command
 *
 *  tell remote side to execute the given command
 */
typedef void
(*globus_gfs_ipc_iface_command_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_command_info_t *         cmd_info,
    globus_i_gfs_ipc_data_callback_t    cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_command_info_t *         cmd_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  active data
 *
 *  tell remote side to create an active data connection
 */
typedef void
(*globus_gfs_ipc_iface_active_data_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_ipc_data_callback_t    cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_active_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_info_t *            data_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  passive data
 *
 *  tell remote side to do passive data connection
 */
typedef void
(*globus_gfs_ipc_iface_passive_data_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_ipc_data_callback_t    cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_info_t *            data_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  send stat request
 */
typedef void
(*globus_gfs_ipc_iface_stat_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    int                                 id,
    globus_gfs_stat_info_t *            stat_info,
    globus_i_gfs_ipc_data_callback_t    cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_stat_info_t *            stat_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

void
globus_gfs_ipc_reply_session(
    globus_gfs_ipc_handle_t             ipc,
    globus_result_t                     result,
    void *                              user_arg);

/*
 * poke transfer event request
 */
typedef void
(*globus_gfs_ipc_iface_transfer_event_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    globus_gfs_event_info_t *           event_info);


globus_result_t
globus_gfs_ipc_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_event_info_t *           event_info);


/*
 *  destroy a data connection associated with the given ID
 */
typedef void
(*globus_gfs_ipc_iface_data_destroy_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_handle,
    void *                              data_arg);

globus_result_t
globus_gfs_ipc_request_data_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              data_arg);

typedef struct globus_i_gfs_ipc_iface_s
{
    globus_gfs_ipc_iface_session_start_t    session_start_func;
    globus_gfs_ipc_iface_session_stop_t     session_stop_func;
    globus_gfs_ipc_iface_recv_t             recv_func;
    globus_gfs_ipc_iface_send_t             send_func;
    globus_gfs_ipc_iface_command_t          command_func;
    globus_gfs_ipc_iface_active_data_t      active_func;
    globus_gfs_ipc_iface_passive_data_t     passive_func;
    globus_gfs_ipc_iface_data_destroy_t     data_destroy_func;
    globus_gfs_ipc_iface_stat_t             stat_func;
    globus_gfs_ipc_iface_list_t             list_func;
    globus_gfs_ipc_iface_transfer_event_t   transfer_event_func;
    globus_gfs_ipc_iface_set_cred_t         set_cred;
    globus_gfs_ipc_iface_buffer_send_t      buffer_send;
} globus_gfs_ipc_iface_t;

/* 
 *  getting an IPC handle
 */

/* 
 *  create an IPC handle from a xio system handle, can be used
 *  imediately, is not in handle table
 */
globus_result_t
globus_gfs_ipc_handle_create(
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_system_handle_t          system_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg);

/*
 *  actually close the handle
 */
globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_handle_release(
    globus_gfs_ipc_handle_t             ipc_handle);

globus_result_t
globus_gfs_ipc_session_stop(
    globus_gfs_ipc_handle_t             ipc_handle);

globus_result_t
globus_gfs_ipc_handle_get_max_available_count(
    const char *                        user_id,
    const char *                        pathname,
    int *                               count);

globus_result_t
globus_gfs_ipc_handle_obtain_by_path(
    int *                               p_handle_count,
    const char *                        pathname,
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg);
    
globus_result_t
globus_gfs_ipc_init(
    globus_bool_t                       requester,
    char **                             in_out_listener);

/*
 *
 */
void
globus_gfs_ipc_add_server(
    globus_xio_server_t                 server_handle);

globus_result_t
globus_gfs_ipc_handle_obtain(
    int *                               handle_count,
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg);

globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_handle_release(
    globus_gfs_ipc_handle_t             ipc_handle);

/* 
 *
 */

/* 
 *   community functions
 */
globus_result_t
globus_gfs_community_get_nodes(
    const char *                        pathname,
    char **                             contact_strings,
    int *                               count);

extern globus_gfs_ipc_iface_t  globus_gfs_ipc_default_iface;

#endif
