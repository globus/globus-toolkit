
#include "globus_i_gridftp_server.h"

/* single mutex, assuming low contention, only used for handle tables,
   not ipc communication */
static globus_mutex_t                   globus_l_ipc_mutex;
static globus_hashtable_t               globus_l_ipc_handle_table;
static int                              globus_l_ipc_handle_count = 0;
static int                              globus_l_ipc_handle_max = 1024;
static globus_i_gfs_community_t *       globus_l_gfs_ipc_community_default;
static globus_list_t *                  globus_l_gfs_ipc_community_list = NULL;
static globus_xio_stack_t               globus_l_gfs_ipc_xio_stack;

typedef enum globus_l_gfs_ipc_state_s
{
    GLOBUS_GFS_IPC_STATE_OPENING,
    GLOBUS_GFS_IPC_STATE_OPEN,
    GLOBUS_GFS_IPC_STATE_GETTING,
    GLOBUS_GFS_IPC_STATE_IN_USE,
    GLOBUS_GFS_IPC_STATE_ERROR,
    GLOBUS_GFS_IPC_STATE_CLOSING,
    GLOBUS_GFS_IPC_STATE_CLOSED
} globus_l_gfs_ipc_state_t;

static globus_xio_driver_t              globus_l_gfs_tcp_driver = GLOBUS_NULL;
static globus_xio_driver_t              globus_l_gfs_queue_driver = GLOBUS_NULL;

/*
 *  header:
 *  type:    single charater representing type of message
 *  id:      4 bytes of message id
 *  size:    remaining size of message
 */
#define GFS_IPC_HEADER_SIZE         (sizeof(uint32_t) + sizeof(uint32_t) + 1)
#define GFS_IPC_HEADER_SIZE_OFFSET  (sizeof(uint32_t) + 1)
#define GFS_IPC_DEFAULT_BUFFER_SIZE 8 * 1024
#define GFS_IPC_VERSION             '\1'

/*** XXX  this will eventually determine if the data node is part of a
 * a different process and perform ipc to that process.  for now, the data
 * node is assumed to be part of the same process and these calls are merely
 * wrappers
 */
 
globus_gfs_ipc_iface_t  globus_gfs_ipc_default_iface = 
{
    globus_i_gfs_data_request_recv,
    globus_i_gfs_data_request_send,
    globus_i_gfs_data_request_command,
    globus_i_gfs_data_request_active,
    globus_i_gfs_data_request_passive,
    NULL,
    globus_i_gfs_data_request_stat,
    globus_i_gfs_data_request_list,
    globus_i_gfs_data_request_transfer_event,
    NULL,
    NULL
};

/* callback and id relation */
typedef struct globus_gfs_ipc_request_s
{
    globus_gfs_ipc_handle_t             ipc;
    globus_gfs_ipc_request_type_t       type;
    int                                 id;
    globus_gfs_ipc_callback_t           cb;
    globus_gfs_ipc_event_callback_t     event_cb;
    void *                              user_arg;
    globus_gfs_ipc_reply_t *            reply;
    globus_gfs_ipc_event_reply_t *      event_reply;
    void *                              info_struct;
} globus_gfs_ipc_request_t;

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
    globus_l_gfs_ipc_state_t            state;

    globus_result_t                     cached_res;
    globus_gfs_ipc_open_close_callback_t open_cb;
    globus_gfs_ipc_open_close_callback_t close_cb;
    globus_gfs_ipc_error_callback_t     error_cb;
    void *                              open_arg;
    void *                              close_arg;
    void *                              error_arg;
                                                                                
    globus_size_t                       buffer_size;
                                                                                
    char *                              hash_str;
    char *                              user_id;
} globus_i_gfs_ipc_handle_t;

static globus_result_t
globus_l_gfs_ipc_close(
    globus_i_gfs_ipc_handle_t *         ipc);

static void
globus_l_gfs_ipc_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static void
globus_l_gfs_ipc_finished_reply_kickout(
    void *                              user_arg);

static void
globus_l_gfs_ipc_event_reply_kickout(
    void *                              user_arg);

static void
globus_l_gfs_ipc_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);

static void
globus_l_gfs_ipc_error_kickout(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_result_t                     res);

static void
globus_l_gfs_ipc_request_destroy(
    globus_gfs_ipc_request_t *          request)
{
    globus_gfs_ipc_data_reply_t *       data_reply;
    globus_gfs_ipc_command_reply_t *    command_reply;
    globus_gfs_ipc_stat_reply_t *       stat_reply;
    globus_gfs_command_info_t *         cmd_info;
    globus_gfs_transfer_info_t *        trans_info;
    globus_gfs_data_info_t *            data_info;
    globus_gfs_stat_info_t *            stat_info;
    char *                              user_dn;
    int                                 ctr;

    /* if there is a reply struch clean it up */
    if(request->reply != NULL)
    {
        switch(request->reply->type)
        {
            /* nothing to do for these */
            case GLOBUS_GFS_OP_AUTH:
            case GLOBUS_GFS_OP_USER:
            case GLOBUS_GFS_OP_RECV:
            case GLOBUS_GFS_OP_SEND:
            case GLOBUS_GFS_OP_LIST:
            case GLOBUS_GFS_OP_DESTROY:
            case GLOBUS_GFS_OP_ACTIVE:
            case GLOBUS_GFS_OP_TRANSFER:
                break;

            case GLOBUS_GFS_OP_STAT:
                stat_reply = (globus_gfs_ipc_stat_reply_t *)
                    &request->reply->info.stat;
                if(stat_reply->stat_array != NULL)
                {
                    globus_free(stat_reply->stat_array);
                }
                // globus_free(stat_reply);
                break;

            case GLOBUS_GFS_OP_COMMAND:
                command_reply = (globus_gfs_ipc_command_reply_t *)
                    &request->reply->info.command;
                if(command_reply->created_dir != NULL)
                {
                    globus_free(command_reply->created_dir);
                }
                if(command_reply->checksum != NULL)
                {
                    globus_free(command_reply->checksum);
                }
                // globus_free(command_reply);
                break;

            case GLOBUS_GFS_OP_PASSIVE:
                data_reply = (globus_gfs_ipc_data_reply_t *)
                    &request->reply->info.data;
                if(data_reply->contact_strings != NULL)
                {
                    for(ctr = 0; ctr < data_reply->cs_count; ctr++)
                    {
                        globus_free((char *)data_reply->contact_strings[ctr]);
                    }
                    globus_free(data_reply->contact_strings);
                }
                // globus_free(data_reply);
                break;

            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
        globus_free(request->reply);
    }

    /* if there was an info structure clean it up */
    if(request->info_struct != NULL)
    {
        switch(request->reply->type)
        {
            /* nothing to do for these */
            case GLOBUS_GFS_OP_USER:
            case GLOBUS_GFS_OP_AUTH:
                user_dn = (char *) request->info_struct;
                globus_free(user_dn);
                break;

            case GLOBUS_GFS_OP_STAT:
                stat_info = 
                    (globus_gfs_stat_info_t *) request->info_struct;
                if(stat_info->pathname != NULL)
                {
                    globus_free(stat_info->pathname);
                }
                globus_free(stat_info);
                break;

            case GLOBUS_GFS_OP_RECV:
            case GLOBUS_GFS_OP_SEND:
            case GLOBUS_GFS_OP_LIST:
                trans_info =
                    (globus_gfs_transfer_info_t *) request->info_struct;
                if(trans_info->pathname != NULL)
                {
                    globus_free(trans_info->pathname);
                }
                if(trans_info->module_name != NULL)
                {
                    globus_free(trans_info->module_name);
                }
                if(trans_info->module_args != NULL)
                {
                    globus_free(trans_info->module_args);
                }
                if(trans_info->list_type != NULL)
                {
                    globus_free((char *)trans_info->list_type);
                }
                globus_range_list_destroy(trans_info->range_list);
                globus_free(trans_info);
                break;

            case GLOBUS_GFS_OP_COMMAND:
                cmd_info =
                    (globus_gfs_command_info_t *) request->info_struct;
                if(cmd_info->pathname != NULL)
                {
                    globus_free(cmd_info->pathname);
                }
                if(cmd_info->cksm_alg != NULL)
                {
                    globus_free(cmd_info->cksm_alg);
                }
                if(cmd_info->rnfr_pathname != NULL)
                {
                    globus_free(cmd_info->rnfr_pathname);
                }
                globus_free(cmd_info);
                break;

            case GLOBUS_GFS_OP_PASSIVE:
            case GLOBUS_GFS_OP_ACTIVE:
                data_info = 
                    (globus_gfs_data_info_t *) request->info_struct;
                if(data_info->subject != NULL)
                {
                    globus_free(data_info->subject);
                }
                globus_free(data_info);
                break;

            case GLOBUS_GFS_OP_DESTROY:
                break;

            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
    }

    globus_free(request);
}

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

    if(ipc->open_cb != NULL)
    {
        ipc->open_cb(ipc, GLOBUS_SUCCESS, ipc->open_arg);
    }
    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        globus_l_ipc_handle_count++;
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);
}

static void
globus_l_gfs_ipc_get_kickout(
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_error_callback_t     error_cb = NULL;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(ipc->open_cb != NULL)
    {
        ipc->open_cb(ipc, GLOBUS_SUCCESS, ipc->open_arg);
    }

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_GETTING:
                ipc->state = GLOBUS_GFS_IPC_STATE_IN_USE;
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR:
                error_cb = ipc->error_cb;
                break;

            default:
                globus_assert(0 && "memory corruption?");
                break;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(error_cb != NULL)
    {
        error_cb(ipc, ipc->cached_res, ipc->error_arg);
    }

}

static void
globus_l_gfs_ipc_error_kickout(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_result_t                     res)
{
    globus_gfs_ipc_error_callback_t     error_cb = NULL;

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            /* need to delay error callback until after the get callback
                is delivered */
            case GLOBUS_GFS_IPC_STATE_GETTING:
                ipc->cached_res = res;
                ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
                break;

            case GLOBUS_GFS_IPC_STATE_OPEN:
                globus_l_gfs_ipc_close(ipc);
                break;
            /* user has the handle and needs to be told it is no longer
                any good */
            case GLOBUS_GFS_IPC_STATE_IN_USE:
                ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
                error_cb = ipc->error_cb;
                break;

            /* once closing we no longer care about errors, and user
                certianly doesn't */
            case GLOBUS_GFS_IPC_STATE_CLOSING:
                ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
                break;
    
            case GLOBUS_GFS_IPC_STATE_OPENING:
            case GLOBUS_GFS_IPC_STATE_CLOSED:
            case GLOBUS_GFS_IPC_STATE_ERROR:
            default:
                globus_assert(0 && "memory corruption?");
                break;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(error_cb != NULL)
    {
        error_cb(ipc, res, ipc->error_arg);
    }
}

static void
globus_l_gfs_ipc_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     new_buf;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(result == GLOBUS_SUCCESS)
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
        if(res != GLOBUS_SUCCESS)
        {
            globus_free(new_buf);
            result = res;
        }
    }

    if(ipc->open_cb != NULL)
    {
        ipc->open_cb(ipc, result, ipc->open_arg);
    }

    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_ipc_close(ipc);
    }
    else
    {
        globus_mutex_lock(&globus_l_ipc_mutex);
        {
            globus_l_ipc_handle_count++;
        }
        globus_mutex_unlock(&globus_l_ipc_mutex);
    }
}

/*
 *  create ipc handle with active connection
 */
static globus_result_t
globus_l_gfs_ipc_open(
    globus_gfs_ipc_iface_t *            iface,
    const char *                        hash_str,
    const char *                        user_id,
    const char *                        contact_string,
    globus_gfs_ipc_open_close_callback_t open_cb,
    void *                              open_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc = NULL;
    globus_result_t                     res;
    globus_xio_attr_t                   xio_attr;
    GlobusGFSName(globus_gfs_ipc_open);
    
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
    ipc->user_id = (char *)user_id;
    ipc->hash_str = (char *)hash_str;
    ipc->open_cb = open_cb;
    ipc->error_cb = error_cb;
    ipc->open_arg = open_arg;
    ipc->error_arg = error_arg;
    ipc->state = GLOBUS_GFS_IPC_STATE_OPENING;
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_voidp_hash,
        globus_hashtable_voidp_keyeq);
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
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    /* do xio open */
    else
    {
        ipc->local = GLOBUS_FALSE;

        res = globus_xio_attr_init(&xio_attr);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        res = globus_xio_attr_cntl(xio_attr, globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_SET_NODELAY, GLOBUS_TRUE);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }

        res = globus_xio_handle_create(
            &ipc->xio_handle, globus_l_gfs_ipc_xio_stack);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        res = globus_xio_register_open(
            ipc->xio_handle,
            ipc->contact_string,
            xio_attr,
            globus_l_gfs_ipc_open_cb,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        
        globus_xio_attr_destroy(xio_attr);
    }

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

static globus_result_t
globus_l_gfs_ipc_close(
    globus_i_gfs_ipc_handle_t *         ipc)
{   
    globus_result_t                     res;
    GlobusGFSName(globus_l_gfs_ipc_close);

    switch(ipc->state)
    {
        case GLOBUS_GFS_IPC_STATE_OPENING:
        case GLOBUS_GFS_IPC_STATE_OPEN:
        case GLOBUS_GFS_IPC_STATE_GETTING:
        case GLOBUS_GFS_IPC_STATE_IN_USE:
        case GLOBUS_GFS_IPC_STATE_ERROR:

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

    return res;
}

/*
 *  convert an xio handle into IPC.  this is used for passively (server
 *  socket) created connections.  This cannot create local connection types
 */
globus_result_t
globus_gfs_ipc_handle_create(
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_system_handle_t          system_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc = NULL;
    globus_result_t                     res;
    globus_xio_attr_t                   xio_attr;
    GlobusGFSName(globus_gfs_ipc_handle_create);

    if(iface == NULL)
    {
        res = GlobusGFSErrorParameter("iface");
        goto err;
    }

    res = globus_xio_attr_init(&xio_attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    res = globus_xio_attr_cntl(xio_attr, globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_HANDLE, system_handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    res = globus_xio_attr_cntl(xio_attr, globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_NODELAY, GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        res = GlobusGFSErrorMemory("ipc");
        goto err;
    }
    res = globus_xio_handle_create(
        &ipc->xio_handle, globus_l_gfs_ipc_xio_stack);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    ipc->state = GLOBUS_GFS_IPC_STATE_OPENING;
    ipc->iface = iface;
    ipc->error_cb = error_cb;
    ipc->error_arg = error_arg;
    ipc->local = GLOBUS_FALSE;
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    ipc->open_cb = cb;
    ipc->open_arg = user_arg;

    globus_hashtable_init(
        &ipc->call_table,
        256,
        globus_hashtable_voidp_hash,
        globus_hashtable_voidp_keyeq);
    globus_mutex_init(&ipc->mutex, NULL);

    res = globus_xio_register_open(
        ipc->xio_handle, 
        NULL, 
        xio_attr,
        globus_l_gfs_ipc_open_cb,
        ipc);
    globus_xio_attr_destroy(xio_attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

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
    globus_list_t *                     search;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    /* remove this handle from the cache */
    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        list = (globus_list_t *) globus_hashtable_remove(
            &globus_l_ipc_handle_table, ipc->hash_str);
        search = globus_list_search(list, ipc);
        if(!globus_list_empty(search))
        {
            globus_list_remove(&list, search);
        }
        if(!globus_list_empty(list))
        {
            globus_hashtable_insert(
                &globus_l_ipc_handle_table,
                ipc->hash_str,
                list);
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

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

static 
globus_gfs_ipc_reply_t *
globus_l_gfs_ipc_unpack_reply(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    int                                 ctr;
    char                                ch;
    char *                              str;
    globus_gfs_ipc_reply_t *            reply;

    reply = (globus_gfs_ipc_reply_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
    if(reply == NULL)
    {
        return NULL;
    }

    /* pack the body--this part is like a reply header */
    GFSDecodeChar(buffer, len, reply->type);
    GFSDecodeUInt32(buffer, len, reply->code);
    GFSDecodeString(buffer, len, reply->msg);

    /* encode the specific types */
    switch(reply->type)
    {
        case GLOBUS_GFS_OP_RECV:
            break;

        case GLOBUS_GFS_OP_SEND:
            break;

        case GLOBUS_GFS_OP_LIST:
            break;

        case GLOBUS_GFS_OP_STAT:
            GFSDecodeUInt32(buffer, len, reply->info.stat.stat_count);
            reply->info.stat.stat_array = (globus_gfs_stat_t *)
                globus_calloc(sizeof(globus_gfs_stat_t), 1);
            if(reply->info.stat.stat_array == NULL)
            {
                goto decode_err;
            }
            for(ctr = 0; ctr < reply->info.stat.stat_count; ctr++)
            {
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].mode);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].nlink);
                GFSDecodeString(buffer, len, str);
                if(strlen(str) < MAXPATHLEN)
                {
                    strcpy(reply->info.stat.stat_array[ctr].name, str);
                    globus_free(str);
                }
                else
                {
                    goto decode_err;
                }
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].uid);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].gid);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].size);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].atime);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].ctime);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].mtime);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].dev);
                GFSDecodeUInt32(
                    buffer, len, reply->info.stat.stat_array[ctr].ino);
            }
            GFSDecodeUInt32(
                buffer, len, reply->info.stat.uid);

            break;

        case GLOBUS_GFS_OP_COMMAND:
            GFSDecodeChar(
                buffer, len, reply->info.command.command);
            GFSDecodeString(
                buffer, len, reply->info.command.checksum);
            GFSDecodeString(
                buffer, len, reply->info.command.created_dir);
            break;

        case GLOBUS_GFS_OP_PASSIVE:
            GFSDecodeUInt32(
                buffer, len, reply->info.data.data_handle_id);
            GFSDecodeUInt32(
                buffer, len, reply->info.data.cs_count);
            reply->info.data.contact_strings = (const char **)
                globus_malloc(sizeof(char *) * reply->info.data.cs_count);
            for(ctr = 0; ctr < reply->info.data.cs_count; ctr++)
            {
                GFSDecodeString(
                    buffer, len, reply->info.data.contact_strings[ctr]);
            }
            GFSDecodeChar(buffer, len, ch);
            reply->info.data.ipv6 = (int)ch;
            GFSDecodeChar(buffer, len, ch);
            reply->info.data.bi_directional = (int)ch;
            break;

        case GLOBUS_GFS_OP_ACTIVE:
            GFSDecodeUInt32(
                buffer, len, reply->info.data.data_handle_id);
            GFSDecodeChar(buffer, len, ch);
            reply->info.data.bi_directional = (int)ch;
            break;

        case GLOBUS_GFS_OP_DESTROY:
            break;

        default:
            break;
    }

    return reply;

  decode_err:
    if(reply != NULL)
    {
        if(reply->info.stat.stat_array != NULL)
        {
            globus_free(reply->info.stat.stat_array);
        }
        globus_free(reply);
    }
                                                                                
    return NULL;
}

static 
globus_gfs_ipc_event_reply_t *
globus_l_gfs_ipc_unpack_event_reply(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    int                                 ctr;
    int                                 range_size;
    globus_gfs_ipc_event_reply_t *      reply;
    globus_off_t                        offset;
    globus_off_t                        length;
    
    reply = (globus_gfs_ipc_event_reply_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_event_reply_t));
    if(reply == NULL)
    {
        return NULL;
    }

    GFSDecodeChar(buffer, len, reply->type);
    GFSDecodeUInt32(buffer, len, reply->stripe_ndx);

    /* encode the specific types */
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            GFSDecodeUInt32(buffer, len, reply->transfer_id);
            break;
            
        case GLOBUS_GFS_EVENT_DISCONNECTED:
            break;
            
        case GLOBUS_GFS_EVENT_BYTES_RECVD:
            GFSDecodeUInt64(buffer, len, reply->recvd_bytes);
            break;
            
        case GLOBUS_GFS_EVENT_RANGES_RECVD:
            globus_range_list_init(&reply->recvd_ranges);
            GFSDecodeUInt32(buffer, len, range_size);
            for(ctr = 0; ctr < range_size; ctr++)
            {
                GFSDecodeUInt64(buffer, len, offset);
                GFSDecodeUInt64(buffer, len, length);
                globus_range_list_insert(reply->recvd_ranges, offset, length);
            }
            break;
            
        default:
            break;
    }

    return reply;

  decode_err:  /* label used in macros */
    if(reply != NULL)
    {
        globus_free(reply);
    }
                                                                                
    return NULL;
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
static globus_gfs_command_info_t *
globus_l_gfs_ipc_unpack_command(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_command_info_t *        cmd_info;

    cmd_info = (globus_gfs_command_info_t *)
        globus_malloc(sizeof(globus_gfs_command_info_t));
    if(cmd_info == NULL)
    {
        return NULL;
    }

    GFSDecodeUInt32(buffer, len, cmd_info->command);
    GFSDecodeString(buffer, len, cmd_info->pathname);
    GFSDecodeUInt64(buffer, len, cmd_info->cksm_offset);
    GFSDecodeUInt64(buffer, len, cmd_info->cksm_length);
    GFSDecodeString(buffer, len, cmd_info->cksm_alg);
    GFSDecodeUInt32(buffer, len, cmd_info->chmod_mode);
    GFSDecodeString(buffer, len, cmd_info->rnfr_pathname);

    return cmd_info;

  decode_err:
    globus_free(cmd_info);

    return NULL;
}

static globus_gfs_transfer_info_t *
globus_l_gfs_ipc_unpack_transfer(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_transfer_info_t *        trans_info;
    int                                 ctr;
    int                                 range_size;
    globus_off_t                        offset;
    globus_off_t                        length;

    trans_info = (globus_gfs_transfer_info_t *)
        globus_malloc(sizeof(globus_gfs_transfer_info_t));
    if(trans_info == NULL)
    {
        return NULL;
    }
    globus_range_list_init(&trans_info->range_list);

    GFSDecodeString(buffer, len, trans_info->pathname);
    GFSDecodeString(buffer, len, trans_info->module_name);
    GFSDecodeString(buffer, len, trans_info->module_args);
    GFSDecodeString(buffer, len, trans_info->list_type);    
    GFSDecodeUInt64(buffer, len, trans_info->partial_offset);
    GFSDecodeUInt64(buffer, len, trans_info->partial_length);
    GFSDecodeUInt32(buffer, len, trans_info->data_handle_id);

    /* unpack range list */
    GFSDecodeUInt32(buffer, len, range_size);
    for(ctr = 0; ctr < range_size; ctr++)
    {
        GFSDecodeUInt64(buffer, len, offset);
        GFSDecodeUInt64(buffer, len, length);
        globus_range_list_insert(trans_info->range_list, offset, length);
    }

    /* unpack op */

    return trans_info;

  decode_err:
    globus_range_list_destroy(trans_info->range_list);
    globus_free(trans_info);

    return NULL;
}

static globus_gfs_data_info_t *
globus_l_gfs_ipc_unpack_data(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_data_info_t *            data_info;
    char                                ch;
    int                                 ctr;

    data_info = (globus_gfs_data_info_t *)
        globus_malloc(sizeof(globus_gfs_data_info_t));
    if(data_info == NULL)
    {
        return NULL;
    }

    GFSDecodeChar(buffer, len, ch);
    data_info->ipv6 = (globus_bool_t) ch;
    GFSDecodeUInt32(buffer, len, data_info->nstreams);
    GFSDecodeChar(buffer, len, data_info->mode);
    GFSDecodeChar(buffer, len, data_info->type);
    GFSDecodeUInt32(buffer, len, data_info->tcp_bufsize);
    GFSDecodeUInt32(buffer, len, data_info->blocksize);
    GFSDecodeChar(buffer, len, data_info->prot);
    GFSDecodeChar(buffer, len, data_info->dcau);
    GFSDecodeUInt32(buffer, len, data_info->max_cs);

    GFSDecodeUInt32(buffer, len, data_info->cs_count);
    data_info->contact_strings = (const char **) 
        globus_malloc(sizeof(char *) * data_info->cs_count);
    for(ctr = 0; ctr < data_info->cs_count; ctr++)
    {
        GFSDecodeString(buffer, len, data_info->contact_strings[ctr]);
    }
    GFSDecodeString(buffer, len, data_info->pathname);
    
    return data_info;

  decode_err:
    globus_free(data_info);

    return NULL;
}

static globus_gfs_stat_info_t *
globus_l_gfs_ipc_unpack_stat(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_stat_info_t *            stat_info;
    char                                ch;

    stat_info = (globus_gfs_stat_info_t *)
        globus_malloc(sizeof(globus_gfs_stat_info_t));
    if(stat_info == NULL)
    {
        return NULL;
    }

    GFSDecodeChar(buffer, len, ch);
    stat_info->file_only = (globus_bool_t) ch;
    GFSDecodeString(buffer, len, stat_info->pathname);

    return stat_info;

  decode_err:
    globus_free(stat_info);

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


static int
globus_l_gfs_ipc_unpack_event_request(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    int *                               transfer_id,
    int *                               event_type)
{
    char                                id;

    GFSDecodeUInt32(buffer, len, *transfer_id);
    GFSDecodeChar(buffer, len, id);
    *event_type = (int) id;

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
globus_l_gfs_ipc_unpack_user_buffer(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_byte_t **                    out_buf,
    globus_size_t *                     out_len)
{
    globus_size_t                       buffer_length;

    GFSDecodeUInt32(buffer, len, buffer_length);
    *out_buf = buffer;
    *out_len = buffer_length;
                                                                                
    return 0;

  decode_err:

    return -1;
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
    globus_gfs_command_info_t *         cmd_info;
    globus_gfs_transfer_info_t *        trans_info;
    globus_gfs_data_info_t *            data_info;
    globus_gfs_stat_info_t *            stat_info;
    globus_gfs_ipc_reply_t *            reply;
    globus_byte_t *                     user_buffer;
    globus_size_t                       user_buffer_length;
    globus_gfs_ipc_event_reply_t *      event_reply;
    int                                 rc;
    int                                 data_connection_id;
    gss_buffer_desc                     gsi_buffer;
    gss_cred_id_t                       cred;
    char *                              user_dn;
    int                                 event_type;
    int                                 transfer_id;
    GlobusGFSName(globus_l_gfs_ipc_read_body_cb);

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
        case GLOBUS_GFS_OP_FINAL_REPLY:
            reply = globus_l_gfs_ipc_unpack_reply(ipc, buffer, len);
            if(reply == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            reply->id = request->id;
            if(request == NULL)
            {
                goto err;
            }
            request->reply = reply;
            globus_l_gfs_ipc_finished_reply_kickout(request);
            break;

        case GLOBUS_GFS_OP_EVENT_REPLY:
            event_reply = 
                globus_l_gfs_ipc_unpack_event_reply(ipc, buffer, len);
            if(event_reply == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            event_reply->id = request->id;
            if(request == NULL)
            {
                goto err;
            }
            request->event_reply = event_reply;
            globus_l_gfs_ipc_event_reply_kickout(request);
            break;

        case GLOBUS_GFS_OP_AUTH:
            rc = globus_l_gfs_ipc_unpack_cred(ipc, buffer, len, &gsi_buffer);
            if(rc != 0)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = NULL;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->set_cred(ipc, cred);
            break;

        case GLOBUS_GFS_OP_USER:
            user_dn = globus_l_gfs_ipc_unpack_user(ipc, buffer, len);
            if(user_dn == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = user_dn;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->set_user(ipc, user_dn);
            break;

        case GLOBUS_GFS_OP_USER_BUFFER:
            rc = globus_l_gfs_ipc_unpack_user_buffer(
                ipc, buffer, len, &user_buffer, &user_buffer_length);
            if(rc != 0)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            ipc->iface->set_user_buffer(ipc, user_buffer, user_buffer_length);
            globus_free(request);
            break;

        case GLOBUS_GFS_OP_STAT:
            stat_info = globus_l_gfs_ipc_unpack_stat(
                ipc, buffer, len);
            if(stat_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = stat_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->stat_func(
                ipc, request->id, stat_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_RECV:
            trans_info = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = trans_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->recv_func(
                ipc, request->id, trans_info, NULL, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_SEND:
            trans_info = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = trans_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->send_func(
                ipc, request->id, trans_info, NULL, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_LIST:
            trans_info = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = trans_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->list_func(
                ipc, request->id, trans_info, NULL, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_COMMAND:
            cmd_info = globus_l_gfs_ipc_unpack_command(ipc, buffer, len);
            if(cmd_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = cmd_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->command_func(
                ipc, request->id, cmd_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_PASSIVE:
            data_info = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
            if(data_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = data_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->passive_func(
                ipc, request->id, data_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_ACTIVE:
            data_info = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
            if(data_info == NULL)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = data_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->active_func(
                ipc, request->id, data_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_DESTROY:
            rc = globus_l_gfs_ipc_unpack_data_destroy(
                ipc, buffer, len, &data_connection_id);
            if(rc != 0)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->call_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->data_destroy_func(data_connection_id);
            break;
            
        case GLOBUS_GFS_OP_EVENT:
            rc = globus_l_gfs_ipc_unpack_event_request(
                ipc, buffer, len, &transfer_id, &event_type);
            if(rc != 0)
            {
                res = GlobusGFSErrorIPC();
                goto err;
            }
            ipc->iface->transfer_event_func(ipc, transfer_id, event_type);
            break;
            
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
    globus_free(request);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(new_buf != NULL)
    {
        globus_free(new_buf);
    }   
    globus_l_gfs_ipc_error_kickout(ipc, res);

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
    globus_byte_t *                     new_buf = NULL;
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

    new_buf = globus_malloc(reply_size);
    if(new_buf == NULL)
    {
        res = GlobusGFSErrorMemory("new_buf");
        goto err;
    }

    globus_mutex_lock(&ipc->mutex);
    {
        switch(type)
        {
            case GLOBUS_GFS_OP_FINAL_REPLY:
                request = (globus_gfs_ipc_request_t *)
                    globus_hashtable_remove(&ipc->call_table, (void *)id);
                if(request == NULL)
                {
                    res = GlobusGFSErrorIPC();
                    goto lock_err;
                }
                request->type = type;
                break;
                
            case GLOBUS_GFS_OP_EVENT_REPLY:
                request = (globus_gfs_ipc_request_t *)
                    globus_hashtable_lookup(&ipc->call_table, (void *)id);
                if(request == NULL)
                {
                    res = GlobusGFSErrorIPC();
                    goto lock_err;
                }
                request->type = type;                
                break;
                
            case GLOBUS_GFS_OP_EVENT:
            case GLOBUS_GFS_OP_RECV:
            case GLOBUS_GFS_OP_SEND:
            case GLOBUS_GFS_OP_LIST:
            case GLOBUS_GFS_OP_COMMAND:
            case GLOBUS_GFS_OP_PASSIVE:
            case GLOBUS_GFS_OP_ACTIVE:
            case GLOBUS_GFS_OP_DESTROY:
            case GLOBUS_GFS_OP_STAT:
            case GLOBUS_GFS_OP_USER_BUFFER:
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
                break;
            default:
                res = GlobusGFSErrorIPC();
                goto lock_err;
                break;
        }

        res = globus_xio_register_read(
            handle,
            new_buf,
            reply_size - GFS_IPC_HEADER_SIZE,
            reply_size - GFS_IPC_HEADER_SIZE,
            NULL,
            globus_l_gfs_ipc_read_body_cb,
            request);
        if(res != GLOBUS_SUCCESS)
        {
            goto lock_err;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_free(buffer);

    return;

  lock_err:
    globus_mutex_unlock(&ipc->mutex);

  decode_err:
    res = GlobusGFSErrorIPC();
  err:
    if(buffer != NULL)
    {
        //globus_free(buffer);
    }
    globus_l_gfs_ipc_error_kickout(ipc, res);
    if(new_buf != NULL)
    {
        globus_free(new_buf);
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
    globus_gfs_ipc_request_t *          request;

    request = (globus_gfs_ipc_request_t *) user_arg;

    /* call the user callback */
    request->cb(
        request->ipc, 
        GLOBUS_SUCCESS,
        request->reply,
        request->user_arg);

    globus_l_gfs_ipc_request_destroy(request);
}
static void
globus_l_gfs_ipc_event_reply_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;

    request = (globus_gfs_ipc_request_t *) user_arg;

    /* call the user callback */
    request->event_cb(
        request->ipc,
        GLOBUS_SUCCESS,
        request->event_reply,
        request->user_arg);
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
        globus_l_gfs_ipc_error_kickout(ipc, result);
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
    int                                 ctr;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       msg_size;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_gfs_ipc_request_t *          request;
    char                                ch;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_reply_finished);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc_handle->mutex);
    {
        /* if local register one shot to get out of recurisve call stack
            troubles */
        request = (globus_gfs_ipc_request_t *) 
            globus_hashtable_remove(
            &ipc->call_table,
            (void *)reply->id);
        if(request == NULL)
        {
            goto err;
        }
        request->reply = reply;

        if(ipc->local)
        {
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
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_FINAL_REPLY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack the body--this part is like a reply header */
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, reply->type);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->code);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, reply->msg);

            /* encode the specific types */
            switch(reply->type)
            {
                case GLOBUS_GFS_OP_AUTH:
                    break;

                case GLOBUS_GFS_OP_RECV:
                    break;

                case GLOBUS_GFS_OP_SEND:
                    break;

                case GLOBUS_GFS_OP_LIST:
                    break;

                case GLOBUS_GFS_OP_STAT:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.stat.stat_count);
                    for(ctr = 0; ctr < reply->info.stat.stat_count; ctr++)
                    {
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].mode);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].nlink);
                        GFSEncodeString(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].name);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].uid);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].gid);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].size);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].atime);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].ctime);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].mtime);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].dev);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].ino);
                    }
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.stat.uid);

                    break;

                case GLOBUS_GFS_OP_COMMAND:
                    GFSEncodeChar(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.command.command);
                    GFSEncodeString(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.command.checksum);
                    GFSEncodeString(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.command.created_dir);
                    break;

                case GLOBUS_GFS_OP_PASSIVE:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.data.data_handle_id);
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.data.cs_count);
                    for(ctr = 0; ctr < reply->info.data.cs_count; ctr++)
                    {
                        GFSEncodeString(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.data.contact_strings[ctr]);
                    }
                    ch = (char) reply->info.data.ipv6;
                    GFSEncodeChar(buffer, ipc->buffer_size, ptr, ch);
                    ch = (char) reply->info.data.bi_directional;
                    GFSEncodeChar(buffer, ipc->buffer_size, ptr, ch);
                    break;

                case GLOBUS_GFS_OP_ACTIVE:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.data.data_handle_id);
                    ch = (char) reply->info.data.bi_directional;
                    GFSEncodeChar(buffer, ipc->buffer_size, ptr, ch);
                    break;

                case GLOBUS_GFS_OP_DESTROY:
                    break;

                default:
                    break;
            }

            msg_size = ptr - buffer;
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, msg_size);
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
    globus_gfs_ipc_event_reply_t *      reply)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_request_t *          request;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_result_t                     res;
    globus_off_t                        offset;
    globus_off_t                        length;
    int                                 range_size;
    int                                 ctr;
    int                                 msg_size;
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
            
            request->event_reply = reply;
            request->reply = NULL;
            
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_event_reply_kickout,
                request);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_EVENT_REPLY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack the body--this part is like a reply header */
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, reply->type);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, reply->stripe_ndx);

            /* encode the specific types */
            switch(reply->type)
            {
                case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, reply->transfer_id);
                    break;
                    
                case GLOBUS_GFS_EVENT_DISCONNECTED:
                    break;
                    
                case GLOBUS_GFS_EVENT_BYTES_RECVD:
                    GFSEncodeUInt64(
                        buffer, ipc->buffer_size, ptr, reply->recvd_bytes);
                    break;
                    
                case GLOBUS_GFS_EVENT_RANGES_RECVD:
                    range_size = globus_range_list_size(reply->recvd_ranges);
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, range_size);
                    for(ctr = 0; ctr < range_size; ctr++)
                    {
                        globus_range_list_at(
                            reply->recvd_ranges, ctr, &offset, &length);
                        GFSEncodeUInt64(
                            buffer, ipc->buffer_size, ptr, offset);
                        GFSEncodeUInt64(
                            buffer, ipc->buffer_size, ptr, length);
                    }
                    break;
                    
                default:
                    break;
            }

            msg_size = ptr - buffer;
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, msg_size);
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

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    /* on error remoe from the hashtable.  we could just wait for the
       close for this but we may as well have this callback do something */
    if(result != GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&ipc->mutex);
        {
            globus_hashtable_remove(&ipc->call_table, (void *)request->id);
            globus_free(request);
        }
        globus_mutex_unlock(&ipc->mutex);

        globus_l_gfs_ipc_error_kickout(ipc, result);
    }
    globus_free(buffer);
}

static void
globus_l_gfs_ipc_nocb_write_cb(
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

    /* on error remoe from the hashtable.  we could just wait for the
       close for this but we may as well have this callback do something */
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_ipc_error_kickout(ipc, result);
    }
    globus_free(buffer);
}

globus_result_t
globus_gfs_ipc_set_user(
    globus_gfs_ipc_handle_t             ipc_handle,
    const char *                        user_dn)
{
    globus_gfs_ipc_request_t *          request = NULL;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_set_user);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        if(!ipc->local)
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_AUTH);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            /* body */
            GFSEncodeString(buffer, ipc->buffer_size, ptr, user_dn);
            
            msg_size = ptr - buffer;
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
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

    if(ipc->local)
    {
        ipc_handle->iface->set_user(ipc, user_dn);
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
globus_gfs_ipc_set_user_buffer(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_byte_t *                     user_buffer,
    globus_size_t                       buffer_len)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_set_user_buffer);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        if(!ipc->local)
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_USER_BUFFER);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, buffer_len);
            /* body */
            memcpy(ptr, user_buffer, buffer_len);

            msg_size = ptr - buffer + buffer_len;
            res = globus_xio_register_write(
                ipc->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_nocb_write_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->set_user_buffer(ipc, buffer, buffer_len);
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
    gss_cred_id_t                       del_cred)
{
    gss_buffer_desc                     gsi_buffer;
    int                                 maj_rc;
    int                                 min_rc;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
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
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        if(!ipc->local)
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_AUTH);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
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
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->set_cred(ipc, del_cred);
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

/* pack user defined type */
static globus_byte_t *
globus_l_gfs_ipc_user_type_pack(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    char *                              struct_desc,
    void *                              user_struct)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    int                                 id;
    int                                 pad;
    globus_byte_t *                     struct_ptr;
    char *                              str_ptr;

    buffer = globus_malloc(ipc->buffer_size);
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, id);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
    /* pack the body */
    GFSEncodeString(buffer, ipc->buffer_size, ptr, struct_desc);

    struct_ptr = (globus_byte_t *) user_struct;
    for(str_ptr = struct_desc; *str_ptr != '\0'; str_ptr++)
    {
        switch(*str_ptr)
        {
            case GLOBUS_GFS_IPC_USER_TYPE_INT32:
                pad = (int)struct_ptr % sizeof(uint32_t);
                if(pad != 0)
                {
                    struct_ptr += (sizeof(uint32_t) - pad);
                }
                GFSEncodeUInt32(buffer, ipc->buffer_size, ptr,
                    (*((uint32_t *)struct_ptr)));
                struct_ptr += sizeof(uint32_t);
                break;

            case GLOBUS_GFS_IPC_USER_TYPE_INT64:
                pad = (int)struct_ptr % sizeof(uint64_t);
                if(pad != 0)
                {
                    struct_ptr += (sizeof(uint64_t) - pad);
                }
                GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, 
                    (*((uint64_t *)struct_ptr)));
                struct_ptr += sizeof(uint64_t);
                break;

            case GLOBUS_GFS_IPC_USER_TYPE_CHAR:
                GFSEncodeChar(buffer, ipc->buffer_size, ptr, *struct_ptr);
                struct_ptr++;
                break;

            case GLOBUS_GFS_IPC_USER_TYPE_STRING:
                GFSEncodeString(buffer, ipc->buffer_size, ptr, struct_ptr);
                struct_ptr += strlen(struct_ptr) + 1;
                break;
        }
    }

    return buffer;
}
    


/* pack and send function for list send and receive */
static globus_result_t
globus_l_gfs_ipc_transfer_pack(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    globus_gfs_transfer_info_t *        trans_info,
    globus_gfs_ipc_request_t *          request)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
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
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
    /* pack the body */
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->pathname);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->module_name);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->module_args);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->list_type);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_info->partial_offset);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_info->partial_length);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_info->data_handle_id);

    /* pack range list */
    range_size = globus_range_list_size(trans_info->range_list);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, range_size);
    for(ctr = 0; ctr < range_size; ctr++)
    {
        globus_range_list_at(trans_info->range_list, ctr, &offset, &length);
        GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, offset);
        GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, length);
    }

    /* TODO: pack op */

    msg_size = ptr - buffer;
    /* now that we know size, add it in */
    ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
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
    globus_gfs_transfer_info_t *        recv_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_recv);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        
        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_OP_RECV, recv_info, request);
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
        ipc_handle->iface->recv_func(
            ipc_handle, request->id, recv_info, NULL, NULL, NULL);
    }
    *id = request->id;

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
    globus_gfs_transfer_info_t *        send_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_send);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_OP_SEND, send_info, request);
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
        ipc->iface->send_func(
            ipc_handle, request->id, send_info, NULL, NULL, NULL);
    }
    *id = request->id;

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    return res;
}

globus_result_t
globus_gfs_ipc_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_info_t *        data_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_list);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->id = (int) request;
        request->cb = cb;
        request->ipc = ipc_handle;
        request->event_cb = event_cb;
        request->user_arg = user_arg;

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_OP_LIST, data_info, request);
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
        ipc->iface->list_func(
            ipc_handle, request->id, data_info, NULL, NULL, NULL);
    }
    *id = request->id;

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
    globus_gfs_command_info_t *         cmd_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_size_t                       msg_size;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    GlobusGFSName(globus_gfs_ipc_request_command);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

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
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_COMMAND);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, cmd_info->command);
            GFSEncodeString(buffer, ipc->buffer_size, ptr, cmd_info->pathname);
            GFSEncodeUInt64(
                buffer, ipc->buffer_size, ptr, cmd_info->cksm_offset);
            GFSEncodeUInt64(
                buffer, ipc->buffer_size, ptr, cmd_info->cksm_length);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_info->cksm_alg);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, cmd_info->chmod_mode);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_info->rnfr_pathname);

            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
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
        ipc->iface->command_func(
            ipc, request->id, cmd_info, NULL, NULL);
    }
    *id = request->id;
    
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
globus_gfs_ipc_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 transfer_id,
    int                                 event_type)
{
    globus_size_t                       msg_size;
    globus_result_t                     res;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_transfer_event);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    request = (globus_gfs_ipc_request_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
    if(request == NULL)
    {
        goto err;
    }
    request->ipc = ipc_handle;

    /* XXX parameter checking */
    globus_mutex_lock(&ipc->mutex);
    {
        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_EVENT);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1); //no reply, no id
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, transfer_id);
            GFSEncodeChar(buffer, ipc->buffer_size, ptr, event_type);

            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
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

    if(ipc->local)
    {
        ipc->iface->transfer_event_func(ipc, transfer_id, event_type);
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
    
     

static
globus_result_t
globus_l_gfs_ipc_pack_data(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    globus_gfs_data_info_t *           data_info,
    globus_gfs_ipc_request_t *          request)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    int                                 id;
    globus_result_t                     res;
    int                                 ctr;

    id = (int) request;
    /* pack the header */
    buffer = globus_malloc(ipc->buffer_size);
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

    /* pack body */
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->ipv6);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->nstreams);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->mode);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->tcp_bufsize);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->blocksize);

    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->prot);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->dcau);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->max_cs);

    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->cs_count);
    for(ctr = 0; ctr < data_info->cs_count; ctr++)
    {
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, data_info->contact_strings[ctr]);
    }
    GFSEncodeString(buffer, ipc->buffer_size, ptr, data_info->pathname);
    
    msg_size = ptr - buffer;
    /* now that we know size, add it in */
    ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
    
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
    globus_gfs_data_info_t *            data_info,
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
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

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
                GLOBUS_GFS_OP_ACTIVE,
                data_info,
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
            data_info, 
            NULL, 
            NULL);
    }
    *id = request->id;
    
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
    globus_gfs_data_info_t *            data_info,
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
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

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
                GLOBUS_GFS_OP_PASSIVE,
                data_info,
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
            data_info,
            NULL,
            NULL);
    }
    *id = request->id;
    
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    return res;
}


/*
 *  send stat request
 */

globus_result_t
globus_gfs_ipc_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_stat_info_t *            stat_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_request_stat);

    ipc = ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

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
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_STAT);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, stat_info->file_only);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, stat_info->pathname);

            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
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
        ipc_handle->iface->stat_func(
            ipc_handle,
            request->id,
            stat_info, 
            NULL, 
            NULL);
    }
    *id = request->id;
    
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
globus_gfs_ipc_request_data_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,   
    int                                 data_connection_id)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_request_data_destroy);

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

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
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_DESTROY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_connection_id);
            
            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
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
    globus_gfs_ipc_handle_t             ipc_handle,
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
                globus_assert(0 && "local not allowed to have cb");
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

            res = globus_l_gfs_ipc_close(ipc);
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    return res;
}
/*
 *   caching stuff
 */

void
globus_gfs_ipc_init()
{
    globus_list_t *                     community_list;
    globus_list_t *                     list;
    globus_result_t                     res;

    res = globus_xio_driver_load("tcp", &globus_l_gfs_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
    }
    res = globus_xio_driver_load("queue", &globus_l_gfs_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
    }
    
    res = globus_xio_stack_init(&globus_l_gfs_ipc_xio_stack, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
    }
        
    res = globus_xio_stack_push_driver(
        globus_l_gfs_ipc_xio_stack, globus_l_gfs_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
    }
    res = globus_xio_stack_push_driver(
        globus_l_gfs_ipc_xio_stack, globus_l_gfs_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
    }

    community_list = globus_i_gfs_config_list("community");

    globus_assert(!globus_list_empty(community_list) && 
        "i said it wouldnt be empty");

    globus_l_gfs_ipc_community_default = 
        (globus_i_gfs_community_t *) globus_list_first(community_list);

    list = globus_list_rest(community_list);
    if(list != NULL)
    {
        globus_l_gfs_ipc_community_list = 
            globus_list_copy(globus_list_rest(community_list));
    }
    else
    {
        globus_l_gfs_ipc_community_list = NULL;
    }

    globus_hashtable_init(
        &globus_l_ipc_handle_table,
        globus_l_ipc_handle_max,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    globus_mutex_init(&globus_l_ipc_mutex, NULL); 

    return;
}

void
globus_gfs_ipc_destroy()
{
    globus_hashtable_destroy(&globus_l_ipc_handle_table);
    globus_mutex_destroy(&globus_l_ipc_mutex);
}

static
globus_result_t
globus_l_gfs_ipc_handle_get(
    const char *                        user_id,
    const char *                        cs,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    char *                              hash_str;
    globus_result_t                     res;
    globus_list_t *                     list = NULL;
    GlobusGFSName(globus_l_gfs_ipc_handle_get);

    hash_str = globus_common_create_string("%s::%s", user_id, cs);
    if(hash_str == NULL)
    {
        res = GlobusGFSErrorMemory("hash_str");
        goto err;
    }
    list = (globus_list_t *) globus_hashtable_remove(
        &globus_l_ipc_handle_table, (void *)hash_str);

    /* if entry not there create it */
    if(globus_list_empty(list))
    {
        res = globus_l_gfs_ipc_open(
            iface,
            hash_str,
            user_id,
            cs,
            cb,
            user_arg,
            error_cb,
            error_user_arg);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    /* if there is one just kick it out */
    else
    {
        ipc = (globus_i_gfs_ipc_handle_t *) globus_list_remove(&list, list);
        if(!globus_list_empty(list))
        {
            globus_hashtable_insert(
                &globus_l_ipc_handle_table,
                (void *)hash_str,
                list);
        }
        /* update callback info */
        globus_assert(ipc != NULL);
        ipc->open_cb = cb;
        ipc->error_cb = error_cb;
        ipc->open_arg = user_arg;
        ipc->error_arg = error_user_arg;
        ipc->state = GLOBUS_GFS_IPC_STATE_GETTING;

        res = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_ipc_get_kickout,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    
    return GLOBUS_SUCCESS;

  err:

    return res;
}

/*
 *  put ipc handle back into cache
 */
globus_result_t
globus_gfs_ipc_handle_release(
    globus_gfs_ipc_handle_t             ipc_handle)
{
    globus_result_t                     res;
    globus_list_t *                     list;
    GlobusGFSName(globus_gfs_ipc_handle_release);

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPENING)
        {
            res = GlobusGFSErrorParameter("ipc_handle");
            goto err;
        }

        ipc_handle->state = GLOBUS_GFS_IPC_STATE_OPEN;
        /* get the list of handles for the user, insert this one and 
            put it back in table */
        list = (globus_list_t *) globus_hashtable_remove(
            &globus_l_ipc_handle_table, ipc_handle->hash_str);
        globus_list_insert(&list, ipc_handle);
        globus_hashtable_insert(
            &globus_l_ipc_handle_table, ipc_handle->hash_str, list);
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return res;
}

/*************************************************************************
 *   community stuff
 *   ---------------
 ************************************************************************/
static globus_i_gfs_community_t *
globus_l_gfs_ipc_find_community(
    const char *                        path)
{
    int                                 root_len;
    int                                 last_len = 0;
    globus_list_t *                     list;
    globus_i_gfs_community_t *          community;
    globus_i_gfs_community_t *          found;

    found = globus_l_gfs_ipc_community_default;
    for(list = globus_l_gfs_ipc_community_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        community = (globus_i_gfs_community_t *) globus_list_first(list);
        root_len = strlen(community->root);
        /* make sure the path is shorter */
        if(root_len > last_len && strlen(path) <= root_len)
        {
            if(strncmp(path, community->root, root_len) == 0)
            {
                found = community;
                last_len = root_len;
            }
        }
    }

    return found;
}

globus_result_t
globus_l_gfs_community_get_nodes(
    const char *                        pathname,
    const char *                        user_id,
    char ***                            contact_strings,
    int *                               count)
{
    globus_i_gfs_community_t *          community;
    char **                             cs;
    globus_list_t *                     list;
    int *                               size_a;
    int                                 ctr;
    char *                              hast_str;
    globus_result_t                     res;

    community = globus_l_gfs_ipc_find_community(pathname);

    /* now order the contact strings best we can */
    cs = (char **) globus_malloc(sizeof(char *) * community->cs_count);
    if(cs == NULL)
    {
        goto err;
    }
    size_a = (int *) globus_malloc(sizeof(int) * community->cs_count);
    if(size_a == NULL)
    {
        goto err;
    }

    for(ctr = 0; ctr < community->cs_count; ctr++)
    {
        hast_str = globus_common_create_string(
            "%s::%s", 
            user_id, community->cs[ctr]);
        if(hast_str == NULL)
        {
            goto err;
        }

        list = (globus_list_t *) globus_hashtable_lookup(
            &globus_l_ipc_handle_table, hast_str);
        size_a[ctr] = globus_list_size(list);
        cs[ctr] = community->cs[ctr];
    }

    /* sort */

    /* clean up */
    globus_free(size_a);
    if(contact_strings != NULL)
    {
        *contact_strings = cs;
    }
    if(count != NULL)
    {
        *count = community->cs_count;
    }
    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gfs_ipc_handle_get_by_contact(
    const char *                        user_id,
    const char *                        contact_string,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_result_t                     res;
    char *                              hash_str = NULL;
    GlobusGFSName(globus_gfs_ipc_handle_get_by_contact);

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        res = globus_l_gfs_ipc_handle_get(
            user_id, contact_string, iface, cb, user_arg, error_cb, error_user_arg);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    globus_free(hash_str);
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    if(hash_str != NULL)
    {
        globus_free(hash_str);
    }

    return res;
}

globus_result_t
globus_gfs_ipc_handle_get(
    const char *                        user_id,
    const char *                        pathname,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    char **                             cs;
    int                                 cs_count;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_handle_get);

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        res = globus_l_gfs_community_get_nodes(
            pathname, user_id, &cs, &cs_count);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        if(cs_count < 1)
        {
            res = GlobusGFSErrorMemory("no contacts");
            goto err;
        }

        res = globus_l_gfs_ipc_handle_get(
            user_id, (const char *) cs[0], 
            iface, cb, user_arg, error_cb, error_user_arg);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return res;
}

