
#include "globus_i_gridftp_server.h"
/* provides local_extensions */
#include "extensions.h"

static globus_gfs_storage_iface_t *     globus_l_gfs_dsi = NULL;
globus_extension_registry_t             globus_i_gfs_dsi_registry;
globus_extension_handle_t               globus_i_gfs_active_dsi_handle;

typedef enum
{
    GLOBUS_L_GFS_DATA_REQUESTING = 1,
    GLOBUS_L_GFS_DATA_CONNECTING,
    GLOBUS_L_GFS_DATA_CONNECTED,
    GLOBUS_L_GFS_DATA_ABORTING,
    GLOBUS_L_GFS_DATA_ABORT_CLOSING,
    GLOBUS_L_GFS_DATA_FINISH,
    GLOBUS_L_GFS_DATA_COMPLETING,
    GLOBUS_L_GFS_DATA_COMPLETE
} globus_l_gfs_data_state_t;

typedef enum
{
    GLOBUS_L_GFS_DATA_HANDLE_INUSE = 1,
    GLOBUS_L_GFS_DATA_HANDLE_VALID,
    GLOBUS_L_GFS_DATA_HANDLE_INVALID
} globus_l_gfs_data_handle_state_t;

typedef struct
{
    globus_gfs_operation_t   op;
    
    union
    {
        globus_gridftp_server_write_cb_t write;
        globus_gridftp_server_read_cb_t  read;
    } callback;
    void *                              user_arg;
} globus_l_gfs_data_bounce_t;

typedef struct
{
    gss_cred_id_t                       del_cred;   
    void *                              session_arg;
    void *                              data_handle;
    globus_mutex_t                      mutex;
} globus_l_gfs_data_session_t;

typedef struct
{
    struct globus_l_gfs_data_operation_s * op;
    globus_l_gfs_data_handle_state_t    state;
    globus_gfs_data_info_t              info;
    globus_ftp_control_handle_t         data_channel;
    int                                 remote_handle_id;
    globus_bool_t                       is_mine;
} globus_l_gfs_data_handle_t;  

typedef struct globus_l_gfs_data_operation_s
{
    globus_l_gfs_data_state_t           state;
    globus_bool_t                       writing;
    globus_l_gfs_data_handle_t *        data_handle;
    
    globus_l_gfs_data_session_t *       session_handle;

    int                                 id;
    globus_gfs_ipc_handle_t             ipc_handle;
    
    uid_t                               uid;
    /* transfer stuff */
    globus_range_list_t                 range_list;
    globus_off_t                        partial_offset;
    globus_off_t                        partial_length;
    const char *                        list_type;

    globus_off_t                        max_offset;
    globus_off_t                        recvd_bytes;
    globus_range_list_t                 recvd_ranges;
    
    int                                 nstreams;
    int                                 stripe_count;
    int *                               eof_count;
    int                                 node_count;
    int                                 node_ndx;
    int                                 write_stripe;
    
    int                                 write_delta;
    int                                 stripe_chunk;
    globus_range_list_t                 stripe_range_list;
    
    /* command stuff */
    globus_gfs_command_type_t           command;
    char *                              pathname;
    globus_off_t                        cksm_offset;
    globus_off_t                        cksm_length;
    char *                              cksm_alg;
    char *                              cksm_response;
    mode_t                              chmod_mode;
    char *                              rnfr_pathname;    
    /**/
    
    int                                 transfer_id; 
    int                                 event_mask;
    
    globus_i_gfs_data_callback_t        callback;
    globus_i_gfs_data_event_callback_t  event_callback;
    void *                              user_arg;

    int                                 ref;
    globus_result_t                     cached_res;
} globus_l_gfs_data_operation_t;

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    int                                 event_type;
} globus_l_gfs_data_trev_bounce_t;

typedef struct
{
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 id;
    globus_l_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    globus_i_gfs_data_callback_t        callback;
    void *                              user_arg;
} globus_l_gfs_data_active_bounce_t;

typedef struct
{
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 id;
    globus_l_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    char *                              contact_string;
    globus_i_gfs_data_callback_t        callback;
    void *                              user_arg;
} globus_l_gfs_data_passive_bounce_t;

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    globus_object_t *                   error;
    int                                 stat_count;
    globus_gfs_stat_t *                 stat_array;
} globus_l_gfs_data_stat_bounce_t;

static
void
globus_l_gfs_data_end_transfer_kickout(
    void *                              user_arg);

static
void
globus_l_gfs_data_start_abort(
    globus_l_gfs_data_operation_t *     op);

void
globus_i_gfs_monitor_init(
    globus_i_gfs_monitor_t *            monitor)
{
    globus_mutex_init(&monitor->mutex, NULL);
    globus_cond_init(&monitor->cond, NULL);
    monitor->done = GLOBUS_FALSE;
}

void
globus_i_gfs_monitor_wait(
    globus_i_gfs_monitor_t *            monitor)
{
    globus_mutex_lock(&monitor->mutex);
    {
        while(!monitor->done)
        {
            globus_cond_wait(&monitor->cond, &monitor->mutex);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
globus_i_gfs_monitor_destroy(
    globus_i_gfs_monitor_t *            monitor)
{
    globus_mutex_destroy(&monitor->mutex);
    globus_cond_destroy(&monitor->cond);
}

void
globus_i_gfs_monitor_signal(
    globus_i_gfs_monitor_t *            monitor)
{
    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
globus_i_gfs_data_init()
{
    char *                              dsi_name;
    
    dsi_name = globus_i_gfs_config_string("dsi");
    
    globus_extension_register_builtins(local_extensions);
    
    globus_l_gfs_dsi = (globus_gfs_storage_iface_t *) globus_extension_lookup(
        &globus_i_gfs_active_dsi_handle, GLOBUS_GFS_DSI_REGISTRY, dsi_name);
    if(!globus_l_gfs_dsi)
    {
        char                            buf[256];
        
        snprintf(buf, 256, "globus_gridftp_server_%s", dsi_name);
        buf[255] = 0;
    
        if(globus_extension_activate(buf) != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_ERR, "Unable to activate %s\n", buf);
            exit(1);
        }
        
        globus_l_gfs_dsi = (globus_gfs_storage_iface_t *) globus_extension_lookup(
            &globus_i_gfs_active_dsi_handle, GLOBUS_GFS_DSI_REGISTRY, dsi_name);
    }
    
    if(!globus_l_gfs_dsi)
    {
        globus_i_gfs_log_message(
           GLOBUS_I_GFS_LOG_ERR, "Couldn't find the %s extension\n", dsi_name);
        exit(1);
    }
}

static
globus_result_t
globus_l_gfs_data_operation_init(
    globus_l_gfs_data_operation_t **    u_op)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_operation_init);
    
    op = (globus_l_gfs_data_operation_t *) 
        globus_calloc(1, sizeof(globus_l_gfs_data_operation_t));
    if(!op)
    {
        result = GlobusGFSErrorMemory("op");
        goto error_alloc;
    }
    
    op->recvd_ranges = GLOBUS_NULL;
    globus_range_list_init(&op->recvd_ranges);
    globus_range_list_init(&op->stripe_range_list);
    op->recvd_bytes = 0;
    op->max_offset = -1;
    
    *u_op = op;
    return GLOBUS_SUCCESS;
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_operation_destroy(
    globus_l_gfs_data_operation_t *     op)
{
    if(op->recvd_ranges)
    {
        globus_range_list_destroy(op->recvd_ranges);
    }
    globus_free(op);
}

    
void
globus_i_gfs_data_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_stat_info_t *            stat_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_stat_request);

    session_handle = (globus_l_gfs_data_session_t *) session_id;

    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->ipc_handle = ipc_handle;
    op->id = id;
    op->uid = getuid();
    
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->callback = cb;
    op->user_arg = user_arg;
    
    globus_l_gfs_dsi->stat_func(op, stat_info, session_handle->session_arg);
    
    return;

error_op:
    return;
}

static
void
globus_l_gfs_data_stat_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_stat_bounce_t * bounce_info;
    globus_gfs_ipc_reply_t *            reply;   

    bounce_info = (globus_l_gfs_data_stat_bounce_t *) user_arg;

    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
 
    reply->type = GLOBUS_GFS_OP_STAT;
    reply->id = bounce_info->op->id;
    reply->result = bounce_info->error ? 
        globus_error_put(bounce_info->error) : GLOBUS_SUCCESS;
    reply->info.stat.stat_array =  bounce_info->stat_array;
    reply->info.stat.stat_count =  bounce_info->stat_count;

    if(bounce_info->op->callback != NULL)
    {
        bounce_info->op->callback(
            reply,
            bounce_info->op->user_arg);
    }
    else
    {    
        globus_gfs_ipc_reply_finished(
            bounce_info->op->ipc_handle,
            reply);
    }
                
    globus_l_gfs_data_operation_destroy(bounce_info->op);
    globus_free(bounce_info);
}

void
globus_i_gfs_data_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_command_info_t *         cmd_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_command_request);

    session_handle = (globus_l_gfs_data_session_t *) session_id;

    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    op->ipc_handle = ipc_handle;
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->command = cmd_info->command;
    op->pathname = cmd_info->pathname;
    op->callback = cb;
    op->user_arg = user_arg;
    
    globus_l_gfs_dsi->command_func(op, cmd_info, session_handle->session_arg);

    return;
    
error_op:
    return;
}

static
globus_result_t
globus_l_gfs_data_handle_init(
    globus_l_gfs_data_handle_t **       u_handle,
    globus_gfs_data_info_t *            data_info)
{
    globus_l_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_dcau_t           dcau;
    GlobusGFSName(globus_l_gfs_data_handle_init);
    
    handle = (globus_l_gfs_data_handle_t *) 
        globus_malloc(sizeof(globus_l_gfs_data_handle_t));
    if(!handle)
    {
        result = GlobusGFSErrorMemory("handle");
        goto error_alloc;
    }
    
    memcpy(&handle->info, data_info, sizeof(globus_gfs_data_info_t));
    
    result = globus_ftp_control_handle_init(&handle->data_channel);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_handle_init", result);
        goto error_data;
    }

    handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
    handle->op = NULL;

    result = globus_ftp_control_local_mode(
        &handle->data_channel, handle->info.mode);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_mode", result);
        goto error_control;
    }
    
    result = globus_ftp_control_local_type(
        &handle->data_channel, handle->info.type, 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_type", result);
        goto error_control;
    }
    
    if(handle->info.tcp_bufsize > 0)
    {
        globus_ftp_control_tcpbuffer_t  tcpbuffer;
        
        tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
        tcpbuffer.fixed.size = handle->info.tcp_bufsize;
        
        result = globus_ftp_control_local_tcp_buffer(
            &handle->data_channel, &tcpbuffer);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_tcp_buffer", result);
            goto error_control;
        }
    }
    
    if(handle->info.mode == 'S')
    {
        handle->info.nstreams = 1;
    }
    else
    {
        globus_ftp_control_parallelism_t  parallelism;
        
        globus_assert(handle->info.mode == 'E');
        
        parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
        parallelism.fixed.size = handle->info.nstreams;
        
        result = globus_ftp_control_local_parallelism(
            &handle->data_channel, &parallelism);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_parallelism", result);
            goto error_control;
        }

        result = globus_ftp_control_local_send_eof(
            &handle->data_channel, GLOBUS_FALSE);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_send_eof", result);
            goto error_control;
        }
    }
    dcau.mode = handle->info.dcau;
    dcau.subject.mode = handle->info.dcau;
    dcau.subject.subject = handle->info.subject;
    result = globus_ftp_control_local_dcau(
        &handle->data_channel, &dcau, handle->info.del_cred);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_dcau", result);
        goto error_control;
    }
    if(handle->info.dcau != 'N')
    {
        result = globus_ftp_control_local_prot(
            &handle->data_channel, handle->info.prot);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_prot", result);
            goto error_control;
        }
    }
    if(handle->info.ipv6)
    {
        result = globus_ftp_control_ipv6_allow(
            &handle->data_channel, GLOBUS_TRUE);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_ipv6_allow", result);
            goto error_control;
        }
    }

    *u_handle = handle;
    return GLOBUS_SUCCESS;

error_control:
    globus_ftp_control_handle_destroy(&handle->data_channel);
    
error_data:
    globus_free(handle);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_abort_kickout(
    void *                              user_arg)
{
    globus_bool_t                       start_finish = GLOBUS_FALSE;
    globus_l_gfs_data_operation_t *     op;

    op = (globus_l_gfs_data_operation_t *) user_arg;

    if(globus_l_gfs_dsi->trev_func != NULL &&
        op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT &&
        op->data_handle->is_mine)
    {
        globus_l_gfs_dsi->trev_func(
            op->transfer_id,
            GLOBUS_GFS_EVENT_TRANSFER_ABORT,
            op->session_handle->session_arg);
    }

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->state)
        {
            /* if finished was called while waiting for this */
            case GLOBUS_L_GFS_DATA_FINISH:
                start_finish = GLOBUS_TRUE;
                break;

            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                op->state = GLOBUS_L_GFS_DATA_ABORTING;
                break;

            case GLOBUS_L_GFS_DATA_CONNECTING:
            case GLOBUS_L_GFS_DATA_CONNECTED:
            case GLOBUS_L_GFS_DATA_REQUESTING:
            case GLOBUS_L_GFS_DATA_ABORTING:
            case GLOBUS_L_GFS_DATA_COMPLETING:
            case GLOBUS_L_GFS_DATA_COMPLETE:
            default:
                globus_assert(0 && "bad state, possible memory corruption");
                break;
        }

        op->ref--;
        globus_assert(op->ref > 0);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(start_finish)
    {
        globus_l_gfs_data_end_transfer_kickout(op);
    }
}

static
void
globus_l_gfs_data_abort_fc_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    globus_l_gfs_data_abort_kickout(callback_arg);
}
    
static
void
globus_l_gfs_data_fc_finished_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    globus_l_gfs_data_end_transfer_kickout(callback_arg);
}

static
void
globus_l_gfs_data_destroy_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    globus_l_gfs_data_handle_t *        data_handle;
    GlobusGFSName(globus_i_gfs_data_handle_destroy);

    data_handle = (globus_l_gfs_data_handle_t *) callback_arg;
    if(data_handle->is_mine)
    {
        globus_ftp_control_handle_destroy(&data_handle->data_channel);
    }

    globus_free(data_handle);
}

/* 
 *  control side telling data side that it needs to tear down
 *  a data connection.  This is needed because connections maybe 
 *  cached beyond the lifespan of a transfer.
 * 
 *  if it comes in while the handle is INUSE then treat it like an abort,
 *  if it is on an invlaid handle then it is already closed and all
 *  that must be done is free the memory.  If it is valid, then we must
 *  close it
 */
void
globus_i_gfs_data_destroy_handle(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 data_connection_id)
{
    globus_bool_t                       pass = GLOBUS_FALSE;
    globus_result_t                     result;
    globus_l_gfs_data_session_t *       session_handle;    
    globus_l_gfs_data_handle_t *        data_handle;
    GlobusGFSName(globus_i_gfs_data_handle_destroy);

    session_handle = (globus_l_gfs_data_session_t *) session_id;
    data_handle = (globus_l_gfs_data_handle_t *) data_connection_id;
    
    session_handle->data_handle = NULL;

    globus_mutex_lock(&session_handle->mutex);
    {
        switch(data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                globus_assert(data_handle->op != NULL);
                globus_l_gfs_data_start_abort(data_handle->op);
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
                data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INVALID;
                if(globus_l_gfs_dsi->data_destroy_func != NULL &&
                    !data_handle->is_mine)
                {
                    pass = GLOBUS_TRUE;
                }
                else
                {
                    result = globus_ftp_control_data_force_close(
                        &data_handle->data_channel,
                        globus_l_gfs_data_destroy_cb,
                        data_handle);
                    if(result != GLOBUS_SUCCESS)
                    {
                        globus_free(data_handle);
                    }
                }
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_INVALID:
                if(data_handle->is_mine)
                {
                    globus_ftp_control_handle_destroy(
                        &data_handle->data_channel);
                }
                globus_free(data_handle);
                break;

            default:
                globus_assert(0 && "likey memory corruption");
        }
    }
    globus_mutex_unlock(&session_handle->mutex);

    if(pass)
    {
        globus_l_gfs_dsi->data_destroy_func(
            data_connection_id, session_handle->session_arg);
    }
    return;    
}

static
void
globus_l_gfs_data_passive_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    globus_gfs_ipc_reply_t *            reply;   
    
    bounce_info = (globus_l_gfs_data_passive_bounce_t *) user_arg;

    bounce_info->handle->is_mine = GLOBUS_TRUE;
        
    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
    reply->info.data.contact_strings = (const char **) 
        globus_calloc(1, sizeof(char *));
 
    reply->type = GLOBUS_GFS_OP_PASSIVE;
    reply->id = bounce_info->id;
    reply->result = GLOBUS_SUCCESS;
    reply->info.data.data_handle_id = (int) bounce_info->handle;
    reply->info.data.bi_directional = bounce_info->bi_directional;
    reply->info.data.cs_count = 1;
    *reply->info.data.contact_strings = (const char *) 
        globus_libc_strdup(bounce_info->contact_string);;
    
    if(bounce_info->callback != NULL)
    {
        bounce_info->callback(
            reply,
            bounce_info->user_arg);        
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            bounce_info->ipc_handle,
            reply);
    }
        
    globus_free(bounce_info->contact_string);
    globus_free(bounce_info);
}

void
globus_i_gfs_data_request_passive(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t      address;
    globus_sockaddr_t                   addr;
    char *                              cs;
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    globus_l_gfs_data_operation_t *     op;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_request_passive);

    session_handle = (globus_l_gfs_data_session_t *) session_id;

    if(globus_l_gfs_dsi->passive_func != NULL)
    {
        result = globus_l_gfs_data_operation_init(&op);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_operation_init", result);
            goto error_op;
        }
        
        op->ipc_handle = ipc_handle;
        op->id = id;
        op->state = GLOBUS_L_GFS_DATA_REQUESTING;
        op->pathname = data_info->pathname;
        op->callback = cb;
        op->user_arg = user_arg;
        globus_l_gfs_dsi->passive_func(
            op, data_info, session_handle->session_arg);
    }
    else
    {
        result = globus_l_gfs_data_handle_init(&handle, data_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_handle_init", result);
            goto error_handle;
        }
        
        address.host[0] = 1; /* prevent address lookup */
        address.port = 0;
        result = globus_ftp_control_local_pasv(&handle->data_channel, &address);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_pasv", result);
            goto error_control;
        }

        /* XXX This needs to be smarter.  The address should be the same one
         * the user is connected to on the control channel (at least when
         * operating as a normal standalone server)
         */
        /* its ok to use AF_INET here since we are requesting the LOCAL
         * address.  we just use AF_INET to store the port
         */
        GlobusLibcSockaddrSetFamily(addr, AF_INET);
        GlobusLibcSockaddrSetPort(addr, address.port);
        result = globus_libc_addr_to_contact_string(
            &addr, GLOBUS_LIBC_ADDR_LOCAL | GLOBUS_LIBC_ADDR_NUMERIC, &cs);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_libc_addr_to_contact_string", result);
            goto error_control;
        }
        
        bounce_info = (globus_l_gfs_data_passive_bounce_t *)
            globus_malloc(sizeof(globus_l_gfs_data_passive_bounce_t));
        if(!bounce_info)
        {
            result = GlobusGFSErrorMemory("bounce_info");
            goto error_alloc;
        }
        
        bounce_info->ipc_handle = ipc_handle;
        bounce_info->id = id;
        bounce_info->handle = handle;
        bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
        bounce_info->contact_string = cs;
        bounce_info->callback = cb;
        bounce_info->user_arg = user_arg;

        session_handle->data_handle = handle;
        
        result = globus_callback_register_oneshot(
            GLOBUS_NULL,
            GLOBUS_NULL,
            globus_l_gfs_data_passive_kickout,
            bounce_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_callback_register_oneshot", result);
            goto error_oneshot;
        }
    }
    return;

error_oneshot:
    globus_free(bounce_info);
    
error_alloc:
    globus_free(cs);
    
error_control:
    //globus_i_gfs_data_destroy_handle(handle);
    
error_handle:
error_op:
    return;
}

static
void
globus_l_gfs_data_active_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_active_bounce_t * bounce_info;
    globus_gfs_ipc_reply_t *            reply;   

    bounce_info = (globus_l_gfs_data_active_bounce_t *) user_arg;

    bounce_info->handle->is_mine = GLOBUS_TRUE;
    
    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));

    reply->type = GLOBUS_GFS_OP_ACTIVE;
    reply->id = bounce_info->id;
    reply->result = GLOBUS_SUCCESS;
    reply->info.data.data_handle_id = (int) bounce_info->handle;
    reply->info.data.bi_directional = bounce_info->bi_directional;
    
    if(bounce_info->callback != NULL)
    {
        bounce_info->callback(
            reply,
            bounce_info->user_arg);        
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            bounce_info->ipc_handle,
            reply);
    }
  
    globus_free(bounce_info);
}

void
globus_i_gfs_data_request_active(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t *    addresses;
    int                                 i;
    globus_l_gfs_data_active_bounce_t * bounce_info;
    globus_l_gfs_data_operation_t *     op;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_request_active);

    session_handle = (globus_l_gfs_data_session_t *) session_id;

    if(globus_l_gfs_dsi->active_func != NULL)
    {
        result = globus_l_gfs_data_operation_init(&op);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_operation_init", result);
            goto error_op;
        }
        
        op->ipc_handle = ipc_handle;
        op->id = id;
        op->state = GLOBUS_L_GFS_DATA_REQUESTING;
        op->pathname = data_info->pathname;
        op->callback = cb;
        op->user_arg = user_arg;
        globus_l_gfs_dsi->active_func(op, data_info, session_handle->session_arg);
    }
    else
    {
        result = globus_l_gfs_data_handle_init(&handle, data_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_handle_init", result);
            goto error_handle;
        }
        addresses = (globus_ftp_control_host_port_t *)
            globus_malloc(sizeof(globus_ftp_control_host_port_t) * 
                data_info->cs_count);
        if(!addresses)
        {
            result = GlobusGFSErrorMemory("addresses");
            goto error_addresses;
        }
        
        for(i = 0; i < data_info->cs_count; i++)
        {
            result = globus_libc_contact_string_to_ints(
                data_info->contact_strings[i],
                addresses[i].host,  &addresses[i].hostlen, &addresses[i].port);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_libc_contact_string_to_ints", result);
                goto error_format;
            }
        }
        
        if(data_info->cs_count == 1)
        {
            result = globus_ftp_control_local_port(
                &handle->data_channel, addresses);
        }
        else
        {
            result = globus_ftp_control_local_spor(
                &handle->data_channel, addresses, data_info->cs_count);
        }
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_port/spor", result);
            goto error_control;
        }
        
        bounce_info = (globus_l_gfs_data_active_bounce_t *)
            globus_malloc(sizeof(globus_l_gfs_data_active_bounce_t));
        if(!bounce_info)
        {
            result = GlobusGFSErrorMemory("bounce_info");
            goto error_alloc;
        }
        
        bounce_info->ipc_handle = ipc_handle;
        bounce_info->id = id;
        bounce_info->handle = handle;
        bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
        bounce_info->callback = cb;
        bounce_info->user_arg = user_arg;
        
        session_handle->data_handle = handle;
        
        result = globus_callback_register_oneshot(
            GLOBUS_NULL,
            GLOBUS_NULL,
            globus_l_gfs_data_active_kickout,
            bounce_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_callback_register_oneshot", result);
            goto error_oneshot;
        }
        
        globus_free(addresses);
    }
    return;

error_oneshot:
    globus_free(bounce_info);
    
error_alloc:
error_control:
error_format:
    globus_free(addresses);
    
error_addresses:
   // globus_i_gfs_data_destroy_handle(handle);
error_handle:
error_op:
    return;
}

    
void
globus_i_gfs_data_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_transfer_info_t *        recv_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_recv_request);

    session_handle = (globus_l_gfs_data_session_t *) session_id;
    data_handle = (globus_l_gfs_data_handle_t *) recv_info->data_handle_id;

    if(data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    if(!data_handle->is_mine)
    {
        recv_info->data_handle_id = data_handle->remote_handle_id;
    }
    
    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }

    op->ipc_handle = ipc_handle;    
    op->session_handle = session_handle;
    op->ref = 1;
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->writing = GLOBUS_FALSE;
    op->data_handle = data_handle;
    data_handle->op = op;
    op->range_list = recv_info->range_list;
    op->partial_offset = recv_info->partial_offset;
    op->callback = cb;
    op->event_callback = event_cb;
    op->user_arg = user_arg;
    op->node_ndx = recv_info->node_ndx;
    op->node_count = recv_info->node_count;    
    op->stripe_count = recv_info->stripe_count;

    /* events and disconnects cannot happen while i am in this
        function */
    globus_assert(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID);
    data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INUSE;
    
    globus_l_gfs_dsi->recv_func(op, recv_info, session_handle->session_arg);

    return;

error_op:
error_handle:
    return;
}

    
void
globus_i_gfs_data_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_transfer_info_t *        send_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg)   
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_send_request);

    session_handle = (globus_l_gfs_data_session_t *) session_id;
    data_handle = (globus_l_gfs_data_handle_t *) send_info->data_handle_id;

    if(data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    if(!data_handle->is_mine)
    {
        send_info->data_handle_id = data_handle->remote_handle_id;
    }

    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    op->ipc_handle = ipc_handle;
    op->session_handle = session_handle;
    op->ref = 1;
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->writing = GLOBUS_TRUE;
    op->data_handle = data_handle;
    data_handle->op = op;
    op->range_list = send_info->range_list;
    op->partial_length = send_info->partial_length;
    op->partial_offset = send_info->partial_offset;
    op->callback = cb;
    op->event_callback = event_cb;
    op->user_arg = user_arg;
    op->node_ndx = send_info->node_ndx;
    op->write_stripe = 0;
    op->stripe_chunk = send_info->node_ndx;
    op->node_count = send_info->node_count;    
    op->stripe_count = send_info->stripe_count;
    op->nstreams = send_info->nstreams;
    op->eof_count = (int *) globus_malloc(op->stripe_count * sizeof(int));

    /* events and disconnects cannot happen while i am in this
        function */
    globus_assert(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID);
    data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INUSE;

    globus_l_gfs_dsi->send_func(op, send_info, session_handle->session_arg);

    return;

error_op:
error_handle:
    return;
}

static
void
globus_l_gfs_data_list_write_cb(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_gridftp_server_control_list_buffer_free(buffer);
    
    globus_gridftp_server_finished_transfer(op, result); 
}


static
void
globus_l_gfs_data_list_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_data_list_stat_cb);
    globus_gfs_operation_t   op;
    globus_byte_t *                     list_buffer;
    globus_size_t                       buffer_len;
    globus_l_gfs_data_bounce_t *        bounce_info;
    globus_result_t                     result;
 
    op = (globus_gfs_operation_t) user_arg;
    bounce_info = (globus_l_gfs_data_bounce_t *) op->user_arg;

    result = globus_gridftp_server_control_list_buffer_alloc(
            op->list_type,
            op->uid,
            reply->info.stat.stat_array, 
            reply->info.stat.stat_count,
            &list_buffer,
            &buffer_len);
    
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
           "globus_gridftp_server_control_list_buffer_alloc", result);
        goto error;
    }
    
    globus_gridftp_server_begin_transfer(op, 0, NULL);
    
    result = globus_gridftp_server_register_write(
        op,
        list_buffer,  
        buffer_len,
        0,
        -1,
        globus_l_gfs_data_list_write_cb,
        bounce_info);

    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_gridftp_server_register_write", result);
        goto error;
    }

    return;
    
error:
    globus_gridftp_server_finished_transfer(op, result); 
    return;
}

void
globus_i_gfs_data_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 id,
    globus_gfs_transfer_info_t *        list_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     stat_op;
    globus_l_gfs_data_operation_t *     data_op;
    globus_result_t                     result;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_gfs_stat_info_t *            stat_info;
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_list_request);

    session_handle = (globus_l_gfs_data_session_t *) session_id;
    data_handle = (globus_l_gfs_data_handle_t *) list_info->data_handle_id;

    if(data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    if(!data_handle->is_mine)
    {
        list_info->data_handle_id = data_handle->remote_handle_id;
    }

    result = globus_l_gfs_data_operation_init(&data_op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }

    data_op->ipc_handle = ipc_handle;    
    data_op->session_handle = session_handle;
    data_op->ref = 1;
    data_op->id = id;
    data_op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    data_op->writing = GLOBUS_TRUE;
    data_op->data_handle = data_handle;
    data_handle->op = data_op;
    data_op->list_type = list_info->list_type;
    data_op->uid = getuid();
    /* XXX */
    data_op->callback = cb;
    data_op->event_callback = event_cb;
    data_op->user_arg = user_arg;
    data_op->node_ndx = list_info->node_ndx;
    data_op->write_stripe = 0;
    data_op->stripe_chunk = list_info->node_ndx;
    data_op->node_count = list_info->node_count;    
    data_op->stripe_count = list_info->stripe_count;
    data_op->nstreams = list_info->nstreams;
    data_op->eof_count = (int *) 
        globus_malloc(data_op->stripe_count * sizeof(int));
    
    if(globus_l_gfs_dsi->list_func != NULL)
    {
        globus_l_gfs_dsi->list_func(
            data_op, list_info, session_handle->session_arg);
    }
    else
    {    
        result = globus_l_gfs_data_operation_init(&stat_op);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_operation_init", result);
            goto error_op;
        }
        stat_op->state = GLOBUS_L_GFS_DATA_REQUESTING;
        stat_op->callback = globus_l_gfs_data_list_stat_cb;
        stat_op->user_arg = data_op;
        
        stat_info = (globus_gfs_stat_info_t *) 
            globus_calloc(1, sizeof(globus_gfs_stat_info_t));
        
        stat_info->pathname = list_info->pathname;
        stat_info->file_only = GLOBUS_FALSE;
    
        /* events and disconnects cannot happen while i am in this
            function */
        globus_assert(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID);
        data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INUSE;
    
        globus_l_gfs_dsi->stat_func(
            stat_op, stat_info, session_handle->session_arg);
    }
    
    return;

error_handle:
error_op:
    return;
}

/***********************************************************************
 *  finished transfer callbacks
 *  ---------------------------
 **********************************************************************/
static
void
globus_l_gfs_data_begin_cb(
    void *                              callback_arg,
    struct globus_ftp_control_handle_s * handle,
    unsigned int                        stripe_ndx,
    globus_bool_t                       reused,
    globus_object_t *                   error)
{
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_bool_t                       connect_event = GLOBUS_FALSE;
    globus_result_t                     res;
    globus_gfs_ipc_event_reply_t *      event_reply;
    globus_l_gfs_data_operation_t *     op;

    op = (globus_l_gfs_data_operation_t *) callback_arg;

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->state)
        {
            case GLOBUS_L_GFS_DATA_CONNECTING:
                if(error != NULL)
                {
                    /* something wrong, start the abort process */
                    res = globus_error_put(error);
                    goto err_lock;
                }
                /* everything is well, send the begin event */
                op->state = GLOBUS_L_GFS_DATA_CONNECTED;
                connect_event = GLOBUS_TRUE;
                op->ref--;
                globus_assert(op->ref > 0);
                break;

            /* this happens when a transfer is aborted before a connection
                is esstablished.  it could be in this state
                depending on how quickly the abort process happens.  */
            case GLOBUS_L_GFS_DATA_ABORTING:
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
            case GLOBUS_L_GFS_DATA_FINISH:
                op->ref--;
                globus_assert(op->ref > 0);
                break;

                /* we need to dec the reference count and clean up if needed.
                also we ignore the error value here, it is likely canceled */
            case GLOBUS_L_GFS_DATA_COMPLETING:
                op->ref--;
                if(op->ref == 0)
                {
                    destroy_op = GLOBUS_TRUE;
                    op->state = GLOBUS_L_GFS_DATA_COMPLETE;
                }
                break;

            case GLOBUS_L_GFS_DATA_COMPLETE:
            case GLOBUS_L_GFS_DATA_CONNECTED:
            case GLOBUS_L_GFS_DATA_REQUESTING:
            default:
                globus_assert(0 && "not possible state.  memory corruption");
                break;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(connect_event)
    {
        event_reply = (globus_gfs_ipc_event_reply_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_event_reply_t));
        if(event_reply == NULL)
        {
            goto err;
        }
        event_reply->type = GLOBUS_GFS_EVENT_TRANSFER_CONNECTED;
        event_reply->id = op->id;
        event_reply->transfer_id = (int) op;
        if(op->event_callback != NULL)
        {
            op->event_callback(event_reply, op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(op->ipc_handle, event_reply);
        }
    }
    else if(destroy_op)
    {
        /* pass the complete event */
        if(globus_l_gfs_dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            globus_l_gfs_dsi->trev_func(
                op->transfer_id,
                GLOBUS_GFS_EVENT_TRANSFER_COMPLETE,
                op->session_handle->session_arg);
        }
        /* destroy the op */
        globus_l_gfs_data_operation_destroy(op);
    }

    return;

  err:
    globus_mutex_lock(&op->session_handle->mutex);

  err_lock:
    /* start abort process */
    globus_l_gfs_data_start_abort(op);
    globus_mutex_unlock(&op->session_handle->mutex);

    globus_assert(0 && "REMOVE THIS");
}

static
void
globus_l_gfs_data_end_transfer_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_ipc_event_reply_t *      event_reply;
    globus_gfs_ipc_reply_t *            reply;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;

    op = (globus_l_gfs_data_operation_t *) user_arg;

    reply = (globus_gfs_ipc_reply_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
    if(reply == NULL)
    {
    }
    if(op->data_handle->info.mode != 'E')
    {
        op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INVALID;
    }

    if(op->data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_INVALID)
    {
        event_reply = (globus_gfs_ipc_event_reply_t *)
            globus_calloc(1, sizeof(globus_gfs_ipc_event_reply_t));
        if(event_reply == NULL)
        {
        }
        event_reply->id = op->id;
        event_reply->data_handle_id = (int) op->data_handle;

        event_reply->type = GLOBUS_GFS_EVENT_DISCONNECTED;
        if(op->event_callback != NULL)
        {
            op->event_callback(
                event_reply,
                op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(
                op->ipc_handle,
                event_reply);
        }
    }

    reply->type = GLOBUS_GFS_OP_TRANSFER;
    reply->id = op->id;
    reply->result = op->cached_res;

    /* tell the control side the finished was called */
    if(op->callback != NULL)
    {
        op->callback(reply, op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            op->ipc_handle,
            reply);
    }

    /* remove the refrence for this callback.  It is posible the before
        aquireing this lock the completing state occured and we are
        ready to finish */
    globus_mutex_lock(&op->session_handle->mutex);
    {
        op->ref--;
        if(op->ref == 0)
        {
            destroy_op = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(destroy_op)
    {
        /* pass the complete event */
        if(globus_l_gfs_dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            globus_l_gfs_dsi->trev_func(
                op->transfer_id,
                GLOBUS_GFS_EVENT_TRANSFER_COMPLETE,
                op->session_handle->session_arg);
        }
        /* destroy the op */
        globus_l_gfs_data_operation_destroy(op);
    }
}

static
void
globus_l_gfs_data_end_read_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_ipc_event_reply_t *      event_reply;
    globus_gfs_ipc_reply_t *            reply;

    op = (globus_l_gfs_data_operation_t *) user_arg;

    reply = (globus_gfs_ipc_reply_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
    event_reply = (globus_gfs_ipc_event_reply_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_event_reply_t));
    if(event_reply == NULL)
    {
        /* XXX MIKEY XXX is panic ok here? */
    }
                                                                            
    event_reply->id = op->id;
    event_reply->recvd_bytes = op->recvd_bytes;
    event_reply->recvd_ranges = op->recvd_ranges;
                                                                            
    event_reply->type = GLOBUS_GFS_EVENT_BYTES_RECVD;
    if(op->event_callback != NULL)
    {
        op->event_callback(
            event_reply,
            op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_event(
            op->ipc_handle,
            event_reply);
    }

    event_reply->type = GLOBUS_GFS_EVENT_RANGES_RECVD;
    if(op->event_callback != NULL)
    {
        op->event_callback(
            event_reply,
            op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_event(
            op->ipc_handle,
            event_reply);
    }

    globus_l_gfs_data_end_transfer_kickout(op);
}

static
void
globus_l_gfs_data_send_eof_cb(
    void *                              callback_arg,
    struct globus_ftp_control_handle_s * handle,
    globus_object_t *				    error)
{
    globus_l_gfs_data_operation_t *     op;

    op = (globus_l_gfs_data_operation_t *) callback_arg;
    if(error != NULL)
    {
        /* XXX this should be thread safe see not in write_eof cb */
        op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INVALID;
        op->cached_res = globus_error_put(error);
    }
    globus_l_gfs_data_end_transfer_kickout(op);
}

static
void
globus_l_gfs_data_write_eof_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{    
    /* XXX mode s only */
    globus_result_t                     result;  
    int                                 i;
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_write_eof_cb);
    
    op = (globus_l_gfs_data_operation_t *) user_arg;

    if(error != NULL)
    {
        /* XXX this should be thread safe since we only get this
            callback after a finsihed_transfer() from the user.  we 
            could still get events or disconnects, but the abort process
            does not touch the data_handle->state */    
        op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INVALID;
        op->cached_res = globus_error_put(error);
        globus_l_gfs_data_end_transfer_kickout(op);
    }
    else
    {
        if(op->data_handle->info.mode == 'E')
        {        
            for(i = 0; i < op->stripe_count; i++)
            {
                op->eof_count[i] = 
                    (op->node_ndx == 0) ?
                    (op->node_count - 1) * op->data_handle->info.nstreams :
                    0;
            }

            result = globus_ftp_control_data_send_eof(
                &op->data_handle->data_channel,
                op->eof_count,
                op->stripe_count,
                (op->node_ndx == 0) ? GLOBUS_TRUE : GLOBUS_FALSE,
                globus_l_gfs_data_send_eof_cb,
                op);
            if(result != GLOBUS_SUCCESS)
            {
                globus_i_gfs_log_result(
                    "ERROR", result);
                op->cached_res = result;
                globus_l_gfs_data_end_transfer_kickout(op);
            }
            if(op->node_ndx != 0)
            {
            }
        }
        else
        {
            globus_l_gfs_data_end_transfer_kickout(op);
        }
    }
}


static
void
globus_l_gfs_data_write_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_l_gfs_data_write_cb);
    
    bounce_info = (globus_l_gfs_data_bounce_t *) user_arg;
    
    bounce_info->callback.write(
        bounce_info->op,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        buffer,
        length,
        bounce_info->user_arg);
        
    globus_free(bounce_info);
}

static
void
globus_l_gfs_data_read_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_l_gfs_data_read_cb);
    
    bounce_info = (globus_l_gfs_data_bounce_t *) user_arg;
    
    bounce_info->callback.read(
        bounce_info->op,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        buffer,
        length,
        offset,
        eof,
        bounce_info->user_arg);
    
    globus_free(bounce_info);
}

static
void
globus_l_gfs_data_transfer_event_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_trev_bounce_t *   bounce_info;
    globus_gfs_ipc_event_reply_t *      event_reply;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_data_transfer_event_kickout);

    bounce_info = (globus_l_gfs_data_trev_bounce_t *) user_arg;
    event_reply = (globus_gfs_ipc_event_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_event_reply_t));
         
    event_reply->id = bounce_info->op->id;
    event_reply->node_ndx = bounce_info->op->node_ndx;
    globus_mutex_lock(&bounce_info->op->session_handle->mutex);
    {    
        switch(bounce_info->event_type)
        {
            case GLOBUS_GFS_EVENT_BYTES_RECVD:
                event_reply->recvd_bytes = bounce_info->op->recvd_bytes;
                bounce_info->op->recvd_bytes = 0;
                event_reply->type = GLOBUS_GFS_EVENT_BYTES_RECVD;
                break;
            
            case GLOBUS_GFS_EVENT_RANGES_RECVD:
                event_reply->type = GLOBUS_GFS_EVENT_RANGES_RECVD;
                event_reply->recvd_ranges = bounce_info->op->recvd_ranges;
                break;
            
            default:
                globus_assert(0 && "invalid state, not possible");
                break;
        } 
    }
    globus_mutex_unlock(&bounce_info->op->session_handle->mutex);

    if(bounce_info->op->event_callback != NULL)
    {
        bounce_info->op->event_callback(
            event_reply,
            bounce_info->op->user_arg);        
    }
    else
    {
        globus_gfs_ipc_reply_event(
            bounce_info->op->ipc_handle,
            event_reply);
    }

    globus_mutex_lock(&bounce_info->op->session_handle->mutex);
    {    
        /* XXX MIKEY XXX  whats this all about?  should it be in other lock */
        if(bounce_info->event_type == GLOBUS_GFS_EVENT_RANGES_RECVD)
        {
            globus_range_list_remove(
                bounce_info->op->recvd_ranges, 0, GLOBUS_RANGE_LIST_MAX);
        }
        bounce_info->op->ref--;
        if(bounce_info->op->ref == 0)
        {
            destroy_op = GLOBUS_TRUE;
            globus_assert(
                bounce_info->op->state == GLOBUS_L_GFS_DATA_COMPLETING);
        }
    }
    globus_mutex_unlock(&bounce_info->op->session_handle->mutex);

    if(destroy_op)
    {
        /* pass the complete event */
        if(globus_l_gfs_dsi->trev_func &&
            bounce_info->op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            globus_l_gfs_dsi->trev_func(
                bounce_info->op->transfer_id,
                GLOBUS_GFS_EVENT_TRANSFER_COMPLETE,
                bounce_info->op->session_handle->session_arg);
        }
        globus_l_gfs_data_operation_destroy(bounce_info->op);
    }

    globus_free(bounce_info);       
}

/* must be called locked */
static
void
globus_l_gfs_data_start_abort(
    globus_l_gfs_data_operation_t *     op)
{
    globus_result_t                     res;

    switch(op->state)
    {
        case GLOBUS_L_GFS_DATA_REQUESTING:
            op->state = GLOBUS_L_GFS_DATA_ABORTING;
            break;

        case GLOBUS_L_GFS_DATA_CONNECTING:
        case GLOBUS_L_GFS_DATA_CONNECTED:
            op->state = GLOBUS_L_GFS_DATA_ABORT_CLOSING;
            op->ref++;
            if(op->data_handle->is_mine)
            {
                res = globus_ftp_control_data_force_close(
                    &op->data_handle->data_channel,
                    globus_l_gfs_data_abort_fc_cb, op);
                if(res != GLOBUS_SUCCESS)
                {
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_data_abort_kickout,
                        op);
                }
            }
            else
            {
                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_data_abort_kickout,
                    op);
            }
            break;

        /* everything post finished can ignore abort, because dsi is already
            done and connections should be torn down, or in the process
            of tearing down */
        case GLOBUS_L_GFS_DATA_FINISH:
        case GLOBUS_L_GFS_DATA_COMPLETING:
        case GLOBUS_L_GFS_DATA_COMPLETE:
            break;

        case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
        case GLOBUS_L_GFS_DATA_ABORTING:
            /* do nothing cause it has already been done */
            break;

        default:
            break;
    }
}

void
globus_i_gfs_data_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id,
    int                                 transfer_id,
    int                                 event_type)
{
    globus_result_t                     result;
    globus_l_gfs_data_trev_bounce_t *   bounce_info;
    globus_l_gfs_data_session_t *       session_handle;
    globus_l_gfs_data_operation_t *     op;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_bool_t                       pass = GLOBUS_FALSE;
    GlobusGFSName(globus_i_gfs_data_kickoff_event);

    session_handle = (globus_l_gfs_data_session_t *) session_id;
    op = (globus_l_gfs_data_operation_t *) transfer_id;

    if(op == NULL)
    {
        globus_assert(0 && "i wanna know when this happens");
    }
    globus_mutex_lock(&op->session_handle->mutex);
    {
        globus_assert(op->data_handle != NULL);

        /* this is the final event.  dec reference */
        switch(event_type)
        {
            /* if this event has been received we SHOULD be in complete state
                if we are not it is a bad message and we ignore it */
            case GLOBUS_GFS_EVENT_TRANSFER_COMPLETE:
                if(op->state == GLOBUS_L_GFS_DATA_FINISH)
                {
                    /* even tho we are passing do not up the ref because this
                        is the barrier message */
                    op->state = GLOBUS_L_GFS_DATA_COMPLETING;
                    pass = GLOBUS_TRUE;
                }
                else
                {
                    /* XXX log a bad message */
                    globus_assert(0 && "for now we assert");
                    pass = GLOBUS_FALSE;
                }
                break;

            case GLOBUS_GFS_EVENT_BYTES_RECVD:
            case GLOBUS_GFS_EVENT_RANGES_RECVD:
                /* we ignore these 2 events for everything except the
                    connected state */
                /* if finished already happened ignore these completely */
                if(op->state != GLOBUS_L_GFS_DATA_CONNECTED)
                {
                    pass = GLOBUS_FALSE;
                }
                else
                {
                    /* if the DSI is handling these events */
                    if(globus_l_gfs_dsi->trev_func != NULL &&
                        event_type & op->event_mask)
                    {
                        op->ref++;
                        pass = GLOBUS_TRUE;
                    }
                    /* if DSI not handling, take care of for them */
                    else
                    {
                        pass = GLOBUS_FALSE;
                        /* since this will be put in a callback we must up 
                            ref */
                        op->ref++;

                        bounce_info = (globus_l_gfs_data_trev_bounce_t *)
                            globus_malloc(
                                sizeof(globus_l_gfs_data_trev_bounce_t));
                        if(!bounce_info)
                        {
                            result = GlobusGFSErrorMemory("bounce_info");
                        }
                
                        bounce_info->event_type = event_type;
                        bounce_info->op = 
                            (globus_l_gfs_data_operation_t *) transfer_id;
        
                        globus_callback_register_oneshot(
                            NULL,
                            NULL,
                            globus_l_gfs_data_transfer_event_kickout,
                            bounce_info);
                    }
                }
                break;

            case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
                /* start the abort process */
                globus_l_gfs_data_start_abort(op);
                break;
                
            /* only pass though if in connected state and the dsi wants
                the event */
            default:
                if(op->state != GLOBUS_L_GFS_DATA_CONNECTED ||
                    globus_l_gfs_dsi->trev_func == NULL ||
                    !(event_type & op->event_mask))
                {
                    pass = GLOBUS_FALSE;
                }
                else
                {
                    op->ref++;
                    pass = GLOBUS_TRUE;
                }
                break;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    /* if is possible that events slip through here after setting to 
        GLOBUS_L_GFS_DATA_COMPLETE.  This is ok because the only
        gauretee made is that none will come after 
        GLOBUS_GFS_EVENT_TRANSFER_COMPLETE.  This is gaurenteed with
        the reference count. */
    if(pass)
    {
        /* if a TRANSFER_COMPLETE event we must respect the barrier */
        if(event_type != GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            globus_l_gfs_dsi->trev_func(
                op->transfer_id, event_type, session_handle->session_arg);
        }
        globus_mutex_lock(&op->session_handle->mutex);
        {
            op->ref--;
            if(op->ref == 0)
            {
                globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING);
                destroy_op = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&op->session_handle->mutex);
        if(destroy_op)
        {
            if(globus_l_gfs_dsi->trev_func &&
                op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
            {
                globus_l_gfs_dsi->trev_func(
                    op->transfer_id,
                    GLOBUS_GFS_EVENT_TRANSFER_COMPLETE,
                    op->session_handle->session_arg);
            }
            /* destroy the op */
            globus_l_gfs_data_operation_destroy(op);
        }
    }

    return;
}

static
void
globus_l_gfs_data_ipc_error_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_log_result(
        "IPC ERROR", result);
    
    return;
}

static
void
globus_l_gfs_data_ipc_open_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_monitor_t *            monitor;

    monitor = (globus_i_gfs_monitor_t *) user_arg;

    globus_i_gfs_monitor_signal(monitor);
}


globus_result_t
globus_i_gfs_data_node_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact)
{
    globus_result_t                     res;
    globus_i_gfs_monitor_t              monitor;

    globus_i_gfs_monitor_init(&monitor);
    
    res = globus_gfs_ipc_handle_create(
        &globus_gfs_ipc_default_iface,
        system_handle,
        globus_l_gfs_data_ipc_open_cb,
        &monitor,
        globus_l_gfs_data_ipc_error_cb,
        NULL);

    globus_i_gfs_monitor_wait(&monitor);
    globus_i_gfs_monitor_destroy(&monitor);

    return res;
}

void
globus_i_gfs_data_session_start(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    const char *                        user_dn,
    gss_cred_id_t                       del_cred,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_gfs_finished_info_t *        finished_info; 
    globus_l_gfs_data_session_t *       session_handle;    
    gss_buffer_desc                     buffer;
    int                                 maj_stat;
    int                                 min_stat;    
    GlobusGFSName(globus_i_gfs_data_session_start);

    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_session_start", result);
        goto error_op;
    }
    session_handle = (globus_l_gfs_data_session_t *)
        globus_calloc(1, sizeof(globus_l_gfs_data_session_t));
    if(session_handle == NULL)
    {
        /* XXX deal with this */
    }
    globus_mutex_init(&session_handle->mutex, NULL);

    if(del_cred != NULL)
    {    
        maj_stat = gss_export_cred(
            &min_stat, del_cred, NULL, 0, &buffer);
        if(maj_stat != GSS_S_COMPLETE)
        {
            result = GlobusGFSErrorWrapFailed("gss_export_cred", min_stat);
            goto error_cred;
        }
        maj_stat = gss_import_cred(
            &min_stat, 
            &session_handle->del_cred, 
            GSS_C_NO_OID, 
            0, 
            &buffer, 
            0, 
            NULL);
        if(maj_stat != GSS_S_COMPLETE)
        {
            result = GlobusGFSErrorWrapFailed("gss_import_cred", min_stat);
            goto error_import;
        }
        maj_stat = gss_release_buffer(&min_stat, &buffer);
        if(maj_stat != GSS_S_COMPLETE)
        {
            result = GlobusGFSErrorWrapFailed("gss_release_buffer", min_stat);
            goto error_import;
        }
        
    }
    
    op->session_handle = session_handle;
    op->ipc_handle = ipc_handle;
    op->id = id;
    op->uid = getuid();
    
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->callback = cb;
    op->user_arg = user_arg;
    
    if(globus_l_gfs_dsi->init_func != NULL)
    {
        globus_l_gfs_dsi->init_func(op, user_dn, del_cred);
    }
    else
    {
        finished_info = (globus_gfs_finished_info_t *)            
            globus_calloc(1, sizeof(globus_gfs_finished_info_t)); 
                                                                  
        finished_info->type = GLOBUS_GFS_OP_SESSION_START;          
        finished_info->session_id = (int) session_handle;

        globus_gridftp_server_operation_finished(                 
            op,                                                   
            GLOBUS_SUCCESS,                                               
            finished_info);                                       
    }    
    
    return;

error_import:
    gss_release_buffer(&min_stat, &buffer);
    
error_cred:
    finished_info = (globus_gfs_finished_info_t *)            
        globus_calloc(1, sizeof(globus_gfs_finished_info_t)); 
                                                              
    finished_info->type = GLOBUS_GFS_OP_SESSION_START;          
    finished_info->session_id = (int) session_handle;
    finished_info->result = result;                          
                                                              
    globus_gridftp_server_operation_finished(                 
        op,                                                   
        result,                                               
        finished_info);
    globus_free(finished_info);                                      
    globus_l_gfs_data_operation_destroy(op);

error_op:
    return;
}

void
globus_i_gfs_data_session_stop(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 session_id)
{
    globus_l_gfs_data_session_t *       session_handle;    
    GlobusGFSName(globus_i_gfs_data_session_stop);

    session_handle = (globus_l_gfs_data_session_t *) session_id;
    if(session_handle != NULL)
    {
        if(session_handle->data_handle != NULL)
        {
            globus_i_gfs_data_destroy_handle(
                ipc_handle, session_id, (int) session_handle->data_handle);
        }    
        if(globus_l_gfs_dsi->destroy_func != NULL)
        {
            globus_l_gfs_dsi->destroy_func(session_handle->session_arg);
        }
    
        globus_free(session_handle);
    }
}



/************************************************************************
 * 
 * Public functions
 * 
 ***********************************************************************/

void
globus_gridftp_server_finished_command(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    char *                              command_data)
{
    globus_gfs_ipc_reply_t *            reply;   
    GlobusGFSName(globus_gridftp_server_finished_command);

    /* XXX gotta do a oneshot */
    switch(op->command)
    {
      case GLOBUS_GFS_CMD_CKSM:
        op->cksm_response = globus_libc_strdup(command_data);
        break;      
      case GLOBUS_GFS_CMD_MKD:
      case GLOBUS_GFS_CMD_RMD:
      case GLOBUS_GFS_CMD_DELE:
      case GLOBUS_GFS_CMD_RNTO:
      case GLOBUS_GFS_CMD_SITE_CHMOD:
      default:
        break;      
    }

    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
 
    reply->type = GLOBUS_GFS_OP_COMMAND;
    reply->id = op->id;
    reply->result = result;
    reply->info.command.command = op->command;
    reply->info.command.checksum = op->cksm_response;
    reply->info.command.created_dir = op->pathname;

    if(op->callback != NULL)
    {
        op->callback(
            reply,
            op->user_arg);        
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            op->ipc_handle,
            reply);
    }

    globus_l_gfs_data_operation_destroy(op);
    
    return;
}

void
globus_gridftp_server_finished_stat(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count)
{
    globus_l_gfs_data_stat_bounce_t * bounce_info;
    globus_gfs_stat_t *      stat_copy;
    GlobusGFSName(globus_gridftp_server_finished_stat);

    stat_copy = (globus_gfs_stat_t *)
        globus_malloc(sizeof(globus_gfs_stat_t) * stat_count);
    memcpy(
        stat_copy,
        stat_array,
        sizeof(globus_gfs_stat_t) * stat_count);

    bounce_info = (globus_l_gfs_data_stat_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_stat_bounce_t));
    if(bounce_info == NULL)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
        
    bounce_info->op = op;
    bounce_info->error = result == GLOBUS_SUCCESS 
        ? GLOBUS_NULL : globus_error_get(result);
    bounce_info->stat_count = stat_count;
    bounce_info->stat_array = stat_copy;
    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_data_stat_kickout,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        goto error_oneshot;
    }

    return;

error_oneshot:
error_alloc:
    globus_panic(
        GLOBUS_NULL,
        result,
        "[%s:%d] Unrecoverable error",
        _gfs_name,
        __LINE__);
    return;
}

globus_result_t
globus_gridftp_server_begin_transfer(
    globus_gfs_operation_t              op,
    int                                 event_mask,
    void *                              event_arg)
{
    globus_bool_t                       pass_abort = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_result_t                     res;
    globus_result_t                     result;
    globus_gfs_ipc_event_reply_t *      event_reply;
    GlobusGFSName(globus_gridftp_server_begin_transfer);
    
    op->event_mask = event_mask;
    op->transfer_id = (int) event_arg;

    event_reply = (globus_gfs_ipc_event_reply_t *)
        globus_calloc(1, sizeof(globus_gfs_ipc_event_reply_t));
    if(event_reply == NULL)
    {
        res = GlobusGFSErrorMemory("event_reply");
        goto err;
    }

    /* increase refrence count for the events.  This gets decreased when
        the COMPLETE event occurs.  it is safe to increment outside of a
        lock because until we enable events there should be no
        contention
       increase the reference count a second time for this function.
       It is possible that after enabling events but before getting the lock
        that we: 1) get an abort, 2) get a finished() from dsi, 
        3) get a complete, 4) free the op.  if this happens there will
        be no memory at op->mutex. we get around this with an extra
        reference count */
    op->ref += 2; 
    event_reply->type = GLOBUS_GFS_EVENT_TRANSFER_BEGIN;
    event_reply->id = op->id;
    event_reply->transfer_id = (int) op;
    if(op->event_callback != NULL)
    {
        op->event_callback(event_reply, op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_event(op->ipc_handle, event_reply);
    }
    /* at this point events can happen that change the state before
        the lock is aquired */

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->state)
        {
            /* if going according to plan */
            case GLOBUS_L_GFS_DATA_REQUESTING:
                op->state = GLOBUS_L_GFS_DATA_CONNECTING;
                if(op->writing)
                {
                    result = globus_ftp_control_data_connect_write(
                        &op->data_handle->data_channel,
                        globus_l_gfs_data_begin_cb,
                        op);
                }
                else
                {
                    result = globus_ftp_control_data_connect_read(
                        &op->data_handle->data_channel,
                        globus_l_gfs_data_begin_cb,
                        op);
                }
                if(result != GLOBUS_SUCCESS)
                {
                    op->state = GLOBUS_L_GFS_DATA_ABORTING;
                    /* if the connects fail tell the dsi to abort */
                    op->cached_res = result;
                    if(globus_l_gfs_dsi->trev_func != NULL &&
                        op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT &&
                        !op->data_handle->is_mine)
                    {
                        pass_abort = GLOBUS_TRUE;
                        op->ref++;
                    }
                }
                else
                {
                    op->ref++; /* for the begin callback on success */
                }
                break;

            /* if in this state we have delayed the pass to the dsi until
                after we know they have requested events */
            case GLOBUS_L_GFS_DATA_ABORTING:
                if(globus_l_gfs_dsi->trev_func != NULL &&
                    op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT &&
                    !op->data_handle->is_mine)
                {
                    pass_abort = GLOBUS_TRUE;
                    op->ref++;
                }
                break;

            /* we are waiting for the force close callback to return */
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                break;

            /* nothing to do here, finishing is in the works */
            case GLOBUS_L_GFS_DATA_FINISH:
                break;

            /* if this happens we went through all the step in the above 
                doc box. */
            case GLOBUS_L_GFS_DATA_COMPLETING:
                break;

            /* the reference counting should make htis not possible */
            case GLOBUS_L_GFS_DATA_COMPLETE:
                globus_assert(0 && 
                    "reference counts are likely messed up");
                break;

            /* this could only happen if the dsi did something bad, like
                maybe call this function twice? */
            case GLOBUS_L_GFS_DATA_CONNECTING:
            case GLOBUS_L_GFS_DATA_CONNECTED:
                globus_assert(0 && 
                    "In connecting state before it should be possible");
                break;
            default:
                globus_assert(0 && "this should not be possible");
                break;
        }

        op->ref--;
        if(op->ref == 0)
        {
            globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING);
            destroy_op = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(pass_abort)
    {
        globus_l_gfs_dsi->trev_func(
            op->transfer_id,
            GLOBUS_GFS_EVENT_TRANSFER_ABORT,
            op->session_handle->session_arg);
        globus_mutex_lock(&op->session_handle->mutex);
        {
            op->ref--;
            if(op->ref == 0)
            {
                globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING);
                destroy_op = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&op->session_handle->mutex);
    }

    if(destroy_op)
    {
        if(globus_l_gfs_dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            /* XXX does this call need to be in a oneshot? */
            globus_l_gfs_dsi->trev_func(
                op->transfer_id,
                GLOBUS_GFS_EVENT_TRANSFER_COMPLETE,
                op->session_handle->session_arg);
        }
        /* destroy the op */
        globus_l_gfs_data_operation_destroy(op);
    }

    return GLOBUS_SUCCESS;

err:
    return result;
}

void
globus_gridftp_server_finished_transfer(
    globus_gfs_operation_t              op,
    globus_result_t                     result)
{
    GlobusGFSName(globus_gridftp_server_finished_transfer);

    globus_mutex_lock(&op->session_handle->mutex);
    {
        /* move the data_handle state to VALID.  at first error if will
            be moved to invalid */
        op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
        switch(op->state)
        {
            /* this is the normal case */
            case GLOBUS_L_GFS_DATA_CONNECTED:
                if(result != GLOBUS_SUCCESS)
                {
                    op->cached_res = result;
                    goto err_lock;
                }
                if(op->writing)
                {
                    result = globus_ftp_control_data_write(
                        &op->data_handle->data_channel,
                        "",
                        0,
                        0,
                        GLOBUS_TRUE,
                        globus_l_gfs_data_write_eof_cb,
                        op);
                    if(result != GLOBUS_SUCCESS)
                    {
                        op->cached_res = result;
                        goto err_lock;
                    }
                }
                else
                {
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_data_end_read_kickout,
                        op);
                }
                break;

            case GLOBUS_L_GFS_DATA_REQUESTING:
            case GLOBUS_L_GFS_DATA_ABORTING:
                if(result != GLOBUS_SUCCESS)
                {
                    op->cached_res = result;
                    goto err_lock;
                }
                op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INVALID;
                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_data_end_transfer_kickout,
                    op);
                break;

            /* waiting for a force close callback to return.  will switch
                to the finished state, when the force close callback comes
                back it will continue the finish process */
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                break;

            case GLOBUS_L_GFS_DATA_CONNECTING:
                if(result != GLOBUS_SUCCESS)
                {
                    op->cached_res = result;
                }
                goto err_lock; 
                break;

            case GLOBUS_L_GFS_DATA_COMPLETING:
            case GLOBUS_L_GFS_DATA_COMPLETE:
            case GLOBUS_L_GFS_DATA_FINISH:
            default:
                globus_assert(0 && "Invalid state");
                break;
        }
        op->state = GLOBUS_L_GFS_DATA_FINISH;
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    return;

err_lock:
    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INVALID;
    op->state = GLOBUS_L_GFS_DATA_FINISH;
    /* do force close */
    if(op->data_handle->is_mine)
    {
        result = globus_ftp_control_data_force_close(
            &op->data_handle->data_channel,
            globus_l_gfs_data_fc_finished_cb, op);
        if(result != GLOBUS_SUCCESS)
        {
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_data_end_transfer_kickout,
                op);
        }
    }
    else
    {
        globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_data_end_transfer_kickout,
            op);
    }
    globus_mutex_unlock(&op->session_handle->mutex);
}

void
globus_gridftp_server_operation_finished(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_finished_info_t *        finished_info)
{
    finished_info->id = op->id;
    finished_info->result = result;

    /* XXX gotta do a onesot here */
    switch(finished_info->type)
    {
        case GLOBUS_GFS_OP_SESSION_START:
            if(op->session_handle)
            {
                op->session_handle->session_arg = 
                    (void *) finished_info->session_id;
            }
            finished_info->session_id = (int) op->session_handle;
            break;
        case GLOBUS_GFS_OP_PASSIVE:
        case GLOBUS_GFS_OP_ACTIVE:
            {
                globus_l_gfs_data_handle_t * data_handle;
                data_handle = (globus_l_gfs_data_handle_t *) 
                    globus_calloc(1, sizeof(globus_l_gfs_data_handle_t));
                data_handle->remote_handle_id = 
                    (int) finished_info->info.data.data_handle_id;
                data_handle->is_mine = GLOBUS_FALSE;
                finished_info->info.data.data_handle_id = (int) data_handle;
            }
            break;
        default:
            break;
    }

    if(op->callback != NULL)
    {
        op->callback(
            finished_info,
            op->user_arg);        
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            op->ipc_handle,
            finished_info);
    }
    
    return;  
}
    
void
globus_gridftp_server_operation_event(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_event_info_t *           event_info)
{
    event_info->id = op->id;

    /* XXX gotta do a onesot here ?? */
    switch(event_info->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            op->transfer_id = event_info->transfer_id; 
            event_info->transfer_id = (int) op;
            break;
        default:
            break;
    }        

    if(op->event_callback != NULL)
    {
        op->event_callback(
            event_info,
            op->user_arg);        
    }
    else
    {
        globus_gfs_ipc_reply_event(
            op->ipc_handle,
            event_info);
    }

    return;
}

void
globus_gridftp_server_update_bytes_written(
    globus_gfs_operation_t              op,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    GlobusGFSName(globus_gridftp_server_update_bytes_written);

    globus_mutex_lock(&op->session_handle->mutex);
    {
        op->recvd_bytes += length;
        globus_range_list_insert(op->recvd_ranges, offset, length);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    return;
}

void
globus_gridftp_server_get_optimal_concurrency(
    globus_gfs_operation_t              op,
    int *                               count)
{
    GlobusGFSName(globus_gridftp_server_get_optimal_concurrency);
    
    *count = op->data_handle->info.nstreams * op->stripe_count * 2;
}

void
globus_gridftp_server_get_block_size(
    globus_gfs_operation_t              op,
    globus_size_t *                     block_size)
{
    GlobusGFSName(globus_gridftp_server_get_block_size);
    
    *block_size = op->data_handle->info.blocksize;
}


/* this is used to translate the restart and partial offset/lengths into
    a sets of ranges to transfer... storage interface shouldn't know about
    partial or restart semantics, it only needs to know which offsets to 
    read from the data source, and what offset to write to data sink
    (dest offset only matters for mode e, but again, storage interface 
    doesn't know about modes)
*/
void
globus_gridftp_server_get_write_range(
    globus_gfs_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta,
    globus_off_t *                      transfer_delta)
{
    GlobusGFSName(globus_gridftp_server_get_write_range);
    globus_off_t                        tmp_off = 0;
    globus_off_t                        tmp_len = -1;
    globus_off_t                        tmp_write = 0;
    globus_off_t                        tmp_transfer = 0;
    int                                 rc;

    if(globus_range_list_size(op->range_list))
    {
        rc = globus_range_list_remove_at(
            op->range_list,
            0,
            &tmp_off,
            &tmp_len);
    }
    if(op->data_handle->info.mode == 'S')
    {
        tmp_write = tmp_off;
    }
    if(op->partial_offset > 0)
    {
        tmp_off += op->partial_offset;
        tmp_write += op->partial_offset;
        tmp_transfer = 0 - op->partial_offset;
    }
    if(offset)
    {
        *offset = tmp_off;
    }
    if(length)
    {
        *length = tmp_len;
    }
    if(write_delta)
    {
        *write_delta = tmp_write;
    }
    if(transfer_delta)
    {
        *transfer_delta = tmp_transfer;
    }
    return;
}

void
globus_gridftp_server_get_read_range(
    globus_gfs_operation_t              op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta)
{
    globus_off_t                        tmp_off = 0;
    globus_off_t                        tmp_len = -1;
    globus_off_t                        tmp_write = 0;
    int                                 rc;
    globus_off_t                        start_offset;
    globus_off_t                        end_offset;
    globus_off_t                        stripe_block_size;
    int                                 size;
    int                                 i;
    GlobusGFSName(globus_gridftp_server_get_read_range);
    
    globus_mutex_lock(&op->session_handle->mutex);
    {
        stripe_block_size = op->data_handle->info.blocksize * 2;
        start_offset = op->stripe_chunk * stripe_block_size;
        end_offset = start_offset + stripe_block_size;
            
        if(globus_range_list_size(op->stripe_range_list))
        {
            rc = globus_range_list_remove_at(
                op->stripe_range_list,
                0,
                &tmp_off,
                &tmp_len);
        
            tmp_write = op->write_delta;
        }
        else if((size = globus_range_list_size(op->range_list)) != 0)
        {
            for(i = 0; i < size; i++)
            {
                rc = globus_range_list_at(
                    op->range_list,
                    i,
                    &tmp_off,
                    &tmp_len);
        
                if(op->partial_length != -1)
                {
                    if(tmp_len == -1)
                    {
                        tmp_len = op->partial_length;
                    }
                    if(tmp_off + tmp_len > op->partial_length)
                    {
                        tmp_len = op->partial_length - tmp_off;
                        if(tmp_len < 0)
                        {
                            tmp_len = 0;
                        }
                    }
                }
                
                if(op->partial_offset > 0)
                {
                    tmp_off += op->partial_offset;
                    tmp_write = 0 - op->partial_offset;
                }
                
                globus_range_list_insert(
                    op->stripe_range_list, tmp_off, tmp_len);
                op->write_delta = tmp_write;
            }
            globus_range_list_remove(
                op->stripe_range_list, 0, start_offset);
            globus_range_list_remove(
                op->stripe_range_list, end_offset, GLOBUS_RANGE_LIST_MAX);
            op->stripe_chunk += op->node_count;
            
            if(globus_range_list_size(op->stripe_range_list))
            {
                rc = globus_range_list_remove_at(
                    op->stripe_range_list,
                    0,
                    &tmp_off,
                    &tmp_len);
            
                tmp_write = op->write_delta;
            }
            else
            {
                tmp_len = 0;
                tmp_off = 0;
                tmp_write = 0;
            }
        }
        else
        {
            tmp_len = 0;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);
    if(offset)
    {
        *offset = tmp_off;
    }
    if(length)
    {
        *length = tmp_len;
    }
    if(write_delta)
    {
        *write_delta = tmp_write;
    }
    
    return; 
}

globus_result_t
globus_gridftp_server_register_read(
    globus_gfs_operation_t   op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,  
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_gridftp_server_register_read);
    
    bounce_info = (globus_l_gfs_data_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = op;
    bounce_info->callback.read = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_ftp_control_data_read(
        &op->data_handle->data_channel,
        buffer,
        length,
        globus_l_gfs_data_read_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_data_read", result);
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}


globus_result_t
globus_gridftp_server_register_write(
    globus_gfs_operation_t   op,
    globus_byte_t *                     buffer,  
    globus_size_t                       length,  
    globus_off_t                        offset,  
    int                                 stripe_ndx,  
    globus_gridftp_server_write_cb_t    callback,  
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_gridftp_server_register_write);
    
    bounce_info = (globus_l_gfs_data_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = op;
    bounce_info->callback.write = callback;
    bounce_info->user_arg = user_arg;

    if(op->data_handle->info.mode == 'E')
    {
        /* XXX not sure what this is all about */
        globus_mutex_lock(&op->session_handle->mutex);
        {
            if(stripe_ndx != -1)
            {
                op->write_stripe = stripe_ndx;
            }
            if(op->write_stripe >= op->stripe_count)
            {
                globus_assert(op->stripe_count && "stripe_count must be > 0");
                op->write_stripe %= op->stripe_count;
            }    
            result = globus_ftp_control_data_write_stripe(
                &op->data_handle->data_channel,
                buffer,
                length,
                offset,
                GLOBUS_FALSE,
                op->write_stripe,
                globus_l_gfs_data_write_cb,
                bounce_info);
                
            op->write_stripe++;
        }    
        globus_mutex_unlock(&op->session_handle->mutex);
    }
    else
    {
        result = globus_ftp_control_data_write(
            &op->data_handle->data_channel,
            buffer,
            length,
            offset,
            GLOBUS_FALSE,
            globus_l_gfs_data_write_cb,
            bounce_info);
    }
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_data_write", result);
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

