
#include "globus_i_gridftp_server.h"

typedef enum
{
    GLOBUS_L_GFS_DATA_REQUESTING,
    GLOBUS_L_GFS_DATA_PENDING,
    GLOBUS_L_GFS_DATA_COMPLETE,
    GLOBUS_L_GFS_DATA_ERROR,
    GLOBUS_L_GFS_DATA_ERROR_COMPLETE
} globus_l_gfs_data_state_t;

typedef struct
{
    globus_gridftp_server_operation_t   op;
    
    union
    {
        globus_gridftp_server_write_cb_t write;
        globus_gridftp_server_read_cb_t  read;
    } callback;
    void *                              user_arg;
} globus_l_gfs_data_bounce_t;

typedef struct globus_l_gfs_data_operation_s
{
    globus_i_gfs_server_instance_t *    instance;
    globus_l_gfs_data_state_t           state;
    globus_mutex_t                      lock;
    globus_i_gfs_data_handle_t *        data_handle;
    globus_bool_t                       sending;

    globus_gridftp_server_control_op_t  control_op;
    
    int                                 id;
    globus_gfs_ipc_handle_t             ipc_handle;
    
    uid_t                               uid;
    /* transfer stuff */
    globus_range_list_t                 range_list;
    globus_off_t                        partial_offset;
    globus_off_t                        partial_length;
    const char *                        list_type;

    globus_off_t                        max_offset;
    globus_off_t                        recvd_bytes[1];
    globus_range_list_t                 recvd_ranges;
    
    /* command stuff */
    globus_i_gfs_command_t              command;
    char *                              pathname;
    globus_off_t                        cksm_offset;
    globus_off_t                        cksm_length;
    char *                              cksm_alg;
    char *                              cksm_response;
    mode_t                              chmod_mode;
    char *                              rnfr_pathname;    
    /**/
    
//    globus_i_gfs_data_command_cb_t      command_callback;
    globus_i_gfs_data_resource_cb_t     resource_callback;
//    globus_i_gfs_data_transfer_cb_t     transfer_callback;
//    globus_i_gfs_data_transfer_event_cb_t event_callback;
    void *                              user_arg;
} globus_l_gfs_data_operation_t;

globus_i_gfs_data_attr_t                globus_i_gfs_data_attr_defaults = 
{
    GLOBUS_FALSE,                       /* ipv6 */
    1,                                  /* nstreams */
    'S',                                /* mode */
    'A',                                /* type */
    0,                                  /* tcp_bufsize (sysdefault) */
    256 * 1024                          /* blocksize */
};

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
    
    globus_mutex_init(&op->lock, GLOBUS_NULL);
    op->recvd_ranges = GLOBUS_NULL;
    globus_range_list_init(&op->recvd_ranges);
    op->recvd_bytes[0] = 0;
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
    globus_mutex_destroy(&op->lock);
    globus_free(op);
}

/* XXX */
globus_result_t
globus_l_gfs_file_resource(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    int                                 mask);
    
globus_result_t
globus_i_gfs_data_resource_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_resource_state_t *       resource_state)
/*
    globus_i_gfs_server_instance_t *    instance,
    const char *                        pathname,
    globus_bool_t                       file_only,
    globus_i_gfs_data_resource_cb_t     callback,
    void *                              user_arg)
*/
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_resource_request);
    
    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
//    op->resource_callback = callback;
//    op->user_arg = user_arg;
    
    /* XXX */
    result = globus_l_gfs_file_resource(
        op, 
        resource_state->pathname, 
        resource_state->file_only ? GLOBUS_GFS_FILE_ONLY : 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(op);
    
error_op:
    return result;
}

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    globus_object_t *                   error;
    int                                 stat_count;
    globus_gridftp_server_stat_t        stat_info_array[1];
} globus_l_gfs_data_resource_bounce_t;

static
void
globus_l_gfs_data_resource_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_resource_bounce_t * bounce_info;
    
    bounce_info = (globus_l_gfs_data_resource_bounce_t *) user_arg;
    if(bounce_info->op->resource_callback != NULL)
    {
        bounce_info->op->resource_callback(
            bounce_info->op->instance,
            bounce_info->error
                ? globus_error_put(bounce_info->error) : GLOBUS_SUCCESS,
            bounce_info->stat_info_array,
            bounce_info->stat_count,
            bounce_info->op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_t *            reply;   
        reply = (globus_gfs_ipc_reply_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
     
        reply->type = GLOBUS_GFS_IPC_TYPE_RESOURCE;
        reply->id = bounce_info->op->id;
        reply->result = bounce_info->error ? 
            globus_error_put(bounce_info->error) : GLOBUS_SUCCESS;
        reply->info.resource.stat_info =  bounce_info->stat_info_array;
        reply->info.resource.stat_count =  bounce_info->stat_count;
    
        globus_gfs_ipc_reply_finished(
            bounce_info->op->ipc_handle,
            reply);
    }
                
    globus_l_gfs_data_operation_destroy(bounce_info->op);
    globus_free(bounce_info);
}

void
globus_gridftp_server_finished_command(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    const char *                        command_data)
{
    GlobusGFSName(globus_gridftp_server_finished_command);
    
    globus_mutex_lock(&op->lock);
    {
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
    }
    globus_mutex_unlock(&op->lock);

    switch(op->command)
    {
      case GLOBUS_I_GFS_CMD_CKSM:
        op->cksm_response = globus_libc_strdup(command_data);
        break;      
      case GLOBUS_I_GFS_CMD_MKD:
      case GLOBUS_I_GFS_CMD_RMD:
      case GLOBUS_I_GFS_CMD_DELE:
      case GLOBUS_I_GFS_CMD_RNTO:
      case GLOBUS_I_GFS_CMD_SITE_CHMOD:
      default:
        break;
      
    }

    {
    globus_gfs_ipc_reply_t *            reply;   
    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
 
    reply->type = GLOBUS_GFS_IPC_TYPE_COMMAND;
    reply->id = op->id;
    reply->result = result;
    reply->info.command.command = op->command;
    reply->info.command.checksum = op->cksm_response;

    globus_gfs_ipc_reply_finished(
        op->ipc_handle,
        reply);
    }
/*
    op->command_callback(
        op->instance,
        result,
        op->cmd_attr,
        op->user_arg);
*/        
    globus_l_gfs_data_operation_destroy(op);
    
    return;
}

void
globus_gridftp_server_finished_resource(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info_array,
    int                                 stat_count)
{
    globus_bool_t                       delay;
    globus_l_gfs_data_resource_bounce_t * bounce_info;
    GlobusGFSName(globus_gridftp_server_finished_resource);
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            delay = GLOBUS_TRUE;
        }
        else
        {
            delay = GLOBUS_FALSE;
        }
        
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
    }
    globus_mutex_unlock(&op->lock);
    
    if(delay)
    {
        bounce_info = (globus_l_gfs_data_resource_bounce_t *)
            globus_malloc(
                sizeof(globus_l_gfs_data_resource_bounce_t) + 
                sizeof(globus_gridftp_server_stat_t) * stat_count);
        if(!bounce_info)
        {
            result = GlobusGFSErrorMemory("bounce_info");
            goto error_alloc;
        }
        
        bounce_info->op = op;
        bounce_info->error = result == GLOBUS_SUCCESS 
            ? GLOBUS_NULL : globus_error_get(result);
        bounce_info->stat_count = stat_count;
        memcpy(
            bounce_info->stat_info_array,
            stat_info_array,
            sizeof(globus_gridftp_server_stat_t) * stat_count);
        
        result = globus_callback_register_oneshot(
            GLOBUS_NULL,
            GLOBUS_NULL,
            globus_l_gfs_data_resource_kickout,
            bounce_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_callback_register_oneshot", result);
            goto error_oneshot;
        }
    }
    else
    {
        if(op->resource_callback != NULL)
        {
            op->resource_callback(
                op->instance,
                result,
                stat_info_array,
                stat_count,
                op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_t *            reply;   
            reply = (globus_gfs_ipc_reply_t *) 
                globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
         
            reply->type = GLOBUS_GFS_IPC_TYPE_RESOURCE;
            reply->id = op->id;
            reply->result = result;
            reply->info.resource.stat_info = stat_info_array;
            reply->info.resource.stat_count = stat_count;
            reply->info.resource.uid = op->uid;
            
            globus_gfs_ipc_reply_finished(
                op->ipc_handle,
                reply);
        }
            
        globus_l_gfs_data_operation_destroy(op);
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
}

/* XXX */
globus_result_t
globus_l_gfs_file_mkdir(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname);
globus_result_t
globus_l_gfs_file_rmdir(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname);
globus_result_t
globus_l_gfs_file_delete(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname);
globus_result_t
globus_l_gfs_file_rename(
    globus_gridftp_server_operation_t   op,
    const char *                        from_pathname,
    const char *                        to_pathname);
globus_result_t
globus_l_gfs_file_chmod(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    mode_t                              mode);
globus_result_t
globus_l_gfs_file_cksm(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    const char *                        algorithm,
    globus_off_t                        offset,
    globus_off_t                        length);
    
globus_result_t
globus_i_gfs_data_command_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_command_state_t *        cmd_state)
/*
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    globus_i_gfs_ipc_command_cb_t       callback,
    void *                              user_arg)
*/
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_command_request);
    
    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
//    op->command_callback = callback;
//    op->user_arg = user_arg;
    
    switch(cmd_state->command)
    {
      
      case GLOBUS_I_GFS_CMD_MKD:
        result = globus_l_gfs_file_mkdir(op, cmd_state->pathname);
        break;
      case GLOBUS_I_GFS_CMD_RMD:
        result = globus_l_gfs_file_rmdir(op, cmd_state->pathname);
        break;
      case GLOBUS_I_GFS_CMD_DELE:
        result = globus_l_gfs_file_delete(op, cmd_state->pathname);
        break;
      case GLOBUS_I_GFS_CMD_RNTO:
        result = globus_l_gfs_file_rename(
            op, cmd_state->rnfr_pathname, cmd_state->pathname);
        break;
      case GLOBUS_I_GFS_CMD_SITE_CHMOD:
        result = globus_l_gfs_file_chmod(
            op, cmd_state->pathname, cmd_state->chmod_mode);
        break;
      case GLOBUS_I_GFS_CMD_CKSM:
        result = globus_l_gfs_file_cksm(
            op, 
            cmd_state->pathname, 
            cmd_state->cksm_alg,
            cmd_state->cksm_offset,
            cmd_state->cksm_length);
        break;
      
      default:
        result = GLOBUS_FAILURE;
        break;
    }
      
    if(result != GLOBUS_SUCCESS)
    {
        goto error_command;
    }    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_command:
    globus_l_gfs_data_operation_destroy(op);
    
error_op:
    return result;
}

static
globus_result_t
globus_l_gfs_data_handle_init(
    globus_i_gfs_data_handle_t **       u_handle,
    globus_i_gfs_data_attr_t *          attr)
{
    globus_i_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_data_handle_init);
    
    handle = (globus_i_gfs_data_handle_t *) 
        globus_malloc(sizeof(globus_i_gfs_data_handle_t));
    if(!handle)
    {
        result = GlobusGFSErrorMemory("handle");
        goto error_alloc;
    }
    
    if(!attr)
    {
        attr = &globus_i_gfs_data_attr_defaults;
    }

    memcpy(&handle->attr, attr, sizeof(globus_i_gfs_data_attr_t));
    
    result = globus_ftp_control_handle_init(&handle->data_channel);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_handle_init", result);
        goto error_data;
    }
    
    result = globus_ftp_control_local_mode(
        &handle->data_channel, handle->attr.mode);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_mode", result);
        goto error_control;
    }
    
    result = globus_ftp_control_local_type(
        &handle->data_channel, handle->attr.type, 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_type", result);
        goto error_control;
    }
    
    if(handle->attr.tcp_bufsize > 0)
    {
        globus_ftp_control_tcpbuffer_t  tcpbuffer;
        
        tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
        tcpbuffer.fixed.size = handle->attr.tcp_bufsize;
        
        result = globus_ftp_control_local_tcp_buffer(
            &handle->data_channel, &tcpbuffer);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_tcp_buffer", result);
            goto error_control;
        }
    }
    
    if(handle->attr.mode == 'S')
    {
        handle->attr.nstreams = 1;
    }
    else
    {
        globus_ftp_control_parallelism_t  parallelism;
        
        globus_assert(handle->attr.mode == 'E');
        
        parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
        parallelism.fixed.size = handle->attr.nstreams;
        
        result = globus_ftp_control_local_parallelism(
            &handle->data_channel, &parallelism);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_parallelism", result);
            goto error_control;
        }
    }

    result = globus_ftp_control_local_dcau(
        &handle->data_channel, &attr->dcau, attr->delegated_cred);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_dcau", result);
        goto error_control;
    }
    if(attr->dcau.mode != GLOBUS_FTP_CONTROL_DCAU_NONE)
    {
        result = globus_ftp_control_local_prot(
            &handle->data_channel, attr->prot);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_prot", result);
            goto error_control;
        }
    }
    
    handle->ref = 1;
    handle->closed = GLOBUS_FALSE;
    globus_mutex_init(&handle->lock, GLOBUS_NULL);
    
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
globus_l_gfs_data_close_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *			error)
{
    globus_i_gfs_data_handle_t *        handle;
    
    handle = (globus_i_gfs_data_handle_t *) callback_arg;
    
    globus_i_gfs_data_handle_destroy(handle);
}

static
globus_result_t
globus_i_gfs_data_handle_close(
    globus_i_gfs_data_handle_t *        handle)
{
    globus_result_t                     result;
    
    globus_mutex_lock(&handle->lock);
    {
        if(!handle->closed)
        {
            result = globus_ftp_control_data_force_close(
                &handle->data_channel, globus_l_gfs_data_close_cb, handle);
            if(result == GLOBUS_SUCCESS)
            {
                handle->ref++;
            }
            
            handle->closed = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->lock);
    
    return result;
}

void
globus_i_gfs_data_handle_destroy(
    globus_i_gfs_data_handle_t *        handle)
{
    globus_bool_t                       destroy;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_handle_destroy);
    
    if(handle == GLOBUS_NULL)
    {
        goto error;
    }
    globus_mutex_lock(&handle->lock);
    {
        if(--handle->ref == 0)
        {
            destroy = GLOBUS_TRUE;
        }
        else
        {
            destroy = GLOBUS_FALSE;
        }
    }
    globus_mutex_unlock(&handle->lock);
    
    if(destroy)
    {
        if(!handle->closed)
        {
            result = globus_i_gfs_data_handle_close(handle);
            if(result == GLOBUS_SUCCESS)
            {
                destroy = GLOBUS_FALSE;
            }
        }
        
        if(destroy)
        {
            globus_mutex_destroy(&handle->lock);
            globus_ftp_control_handle_destroy(&handle->data_channel);
            globus_free(handle);
        }
    }
error:
    return;    
}

typedef struct
{
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 id;
//    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    char *                              contact_string;
//    globus_i_gfs_data_passive_cb_t      callback;
//    void *                              user_arg;
} globus_l_gfs_data_passive_bounce_t;

static
void
globus_l_gfs_data_passive_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    
    bounce_info = (globus_l_gfs_data_passive_bounce_t *) user_arg;
    
    {
    globus_gfs_ipc_reply_t *            reply;   
    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
 
    reply->type = GLOBUS_GFS_IPC_TYPE_PASSIVE;
    reply->id = bounce_info->id;
    reply->result = GLOBUS_SUCCESS;
    reply->info.data.data_handle_id = (int) bounce_info->handle;
    reply->info.data.bi_directional = bounce_info->bi_directional;
    reply->info.data.cs_count = 1;
    reply->info.data.contact_strings = 
        (const char **) &bounce_info->contact_string;
    
    globus_gfs_ipc_reply_finished(
        bounce_info->ipc_handle,
        reply);
    }

/*
    bounce_info->callback(
        bounce_info->instance,
        GLOBUS_SUCCESS,
        bounce_info->handle,
        bounce_info->bi_directional,
        (const char **) &bounce_info->contact_string,
        1,
        bounce_info->user_arg);
*/
    
    globus_free(bounce_info->contact_string);
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_data_passive_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state)
/*
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    globus_i_gfs_data_passive_cb_t      callback,
    void *                              user_arg)
*/
{
    globus_i_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t      address;
    globus_sockaddr_t                   addr;
    char *                              cs;
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    GlobusGFSName(globus_i_gfs_data_passive_request);
    
    /* gotta get data_attr_t info here (from kept state) */
    result = globus_l_gfs_data_handle_init(&handle, NULL);
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
    
//    bounce_info->instance = instance;
    bounce_info->ipc_handle = ipc_handle;
    bounce_info->id = id;
    bounce_info->handle = handle;
    bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
    bounce_info->contact_string = cs;
//    bounce_info->callback = callback;
//    bounce_info->user_arg = user_arg;
    
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
    
    return GLOBUS_SUCCESS;

error_oneshot:
    globus_free(bounce_info);
    
error_alloc:
    globus_free(cs);
    
error_control:
    globus_i_gfs_data_handle_destroy(handle);
    
error_handle:
    return result;
}

typedef struct
{
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 id;
    // globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    // globus_i_gfs_data_active_cb_t       callback;
    // void *                              user_arg;
} globus_l_gfs_data_active_bounce_t;

static
void
globus_l_gfs_data_active_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_active_bounce_t * bounce_info;
    
    bounce_info = (globus_l_gfs_data_active_bounce_t *) user_arg;

    {
    globus_gfs_ipc_reply_t *            reply;   
    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));

    reply->type = GLOBUS_GFS_IPC_TYPE_ACTIVE;
    reply->id = bounce_info->id;
    reply->result = GLOBUS_SUCCESS;
    reply->info.data.data_handle_id = (int) bounce_info->handle;
    reply->info.data.bi_directional = bounce_info->bi_directional;
    
    globus_gfs_ipc_reply_finished(
        bounce_info->ipc_handle,
        reply);
    }

/*    
    bounce_info->callback(
        bounce_info->instance,
        GLOBUS_SUCCESS,
        bounce_info->handle,
        bounce_info->bi_directional,
        bounce_info->user_arg);
*/  
  
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_data_active_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state)
/*
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    const char **                       contact_strings,
    int                                 cs_count,
    globus_i_gfs_data_active_cb_t       callback,
    void *                              user_arg)
*/
{
    globus_i_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t *    addresses;
    int                                 i;
    globus_l_gfs_data_active_bounce_t * bounce_info;
    GlobusGFSName(globus_i_gfs_data_active_request);
    
    result = globus_l_gfs_data_handle_init(&handle, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_handle_init", result);
        goto error_handle;
    }
    addresses = (globus_ftp_control_host_port_t *)
        globus_malloc(sizeof(globus_ftp_control_host_port_t) * 
            data_state->cs_count);
    if(!addresses)
    {
        result = GlobusGFSErrorMemory("addresses");
        goto error_addresses;
    }
    
    for(i = 0; i < data_state->cs_count; i++)
    {
        int                             rc;
        
        rc = sscanf(
            data_state->contact_strings[i],
            "%d.%d.%d.%d:%hu",
            &addresses[i].host[0],
            &addresses[i].host[1],
            &addresses[i].host[2], 
            &addresses[i].host[3], 
            &addresses[i].port);
        if(rc < 5)
        {
            result = GlobusGFSErrorGeneric("Bad contact string");
            goto error_format;
        }
    }
    
    
    if(data_state->cs_count == 1)
    {
        result = globus_ftp_control_local_port(
            &handle->data_channel, addresses);
    }
    else
    {
        result = globus_ftp_control_local_spor(
            &handle->data_channel, addresses, data_state->cs_count);
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
    
//    bounce_info->instance = instance;
    bounce_info->ipc_handle = ipc_handle;
    bounce_info->id = id;
    bounce_info->handle = handle;
    bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
//    bounce_info->callback = callback;
//    bounce_info->user_arg = user_arg;
    
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
    
    return GLOBUS_SUCCESS;

error_oneshot:
    globus_free(bounce_info);
    
error_alloc:
error_control:
error_format:
    globus_free(addresses);
    
error_addresses:
    globus_i_gfs_data_handle_destroy(handle);
    
error_handle:
    return result;
}

/* XXX */
globus_result_t
globus_l_gfs_file_recv(
    globus_gridftp_server_operation_t   op,
    const char *                        arguments,
    const char *                        pathname);
    
globus_result_t
globus_i_gfs_data_recv_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state)
/*
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_handle_t *        data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_data_transfer_cb_t     callback,
    globus_i_gfs_data_transfer_event_cb_t event_callback,
    void *                              user_arg)
*/
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_i_gfs_data_handle_t *        data_handle;
    GlobusGFSName(globus_i_gfs_data_recv_request);

    data_handle = (globus_i_gfs_data_handle_t *)
        recv_state->data_handle_id;

    if(result != GLOBUS_SUCCESS || data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    if(data_handle->closed)
    {
        result = GlobusGFSErrorData("Data handle has been closed");
        goto error_handle;
    }
    
    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->data_handle = data_handle;
    op->sending = GLOBUS_FALSE;
//    op->transfer_callback = callback;
//    op->event_callback = event_callback;
//    op->user_arg = user_arg;
    
    /* XXX */
    result = globus_l_gfs_file_recv(
        op, 
        recv_state->module_args, 
        recv_state->pathname);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("recv_hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(op);

error_op:
error_handle:
    return result;
}

/* XXX */
globus_result_t
globus_l_gfs_file_send(
    globus_gridftp_server_operation_t   op,
    const char *                        arguments,
    const char *                        pathname);
    
globus_result_t
globus_i_gfs_data_send_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state)
/*    
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_handle_t *        data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_data_transfer_cb_t     callback,
    globus_i_gfs_data_transfer_event_cb_t event_callback,
    void *                              user_arg)
*/    
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_i_gfs_data_handle_t *        data_handle;
    GlobusGFSName(globus_i_gfs_data_send_request);

    data_handle = (globus_i_gfs_data_handle_t *)
        send_state->data_handle_id;

    if(result != GLOBUS_SUCCESS || data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    if(data_handle->closed)
    {
        result = GlobusGFSErrorData("Data handle has been closed");
        goto error_handle;
    }
    
    result = globus_l_gfs_data_operation_init(&op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
        
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->data_handle = data_handle;
    op->sending = GLOBUS_TRUE;
//    op->transfer_callback = callback;
//    op->event_callback = event_callback;
//    op->user_arg = user_arg;
    
    /* XXX */
    result = globus_l_gfs_file_send(
        op, 
        send_state->module_args,
        send_state->pathname);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("send_hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(op);

error_op:
error_handle:
    return result;
}

static
void
globus_l_gfs_data_list_write_cb(
    globus_gridftp_server_operation_t   op,
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
globus_l_gfs_data_list_resource_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_data_list_resource_cb);
    globus_gridftp_server_operation_t   op;
    globus_byte_t *                     list_buffer;
    globus_size_t                       buffer_len;
    globus_l_gfs_data_bounce_t *        bounce_info;
    
 
    op = (globus_gridftp_server_operation_t) user_arg;
    bounce_info = (globus_l_gfs_data_bounce_t *) op->user_arg;

    result = globus_gridftp_server_control_list_buffer_alloc(
            op->list_type,
            op->uid,
            stat_info, 
            stat_count,
            &list_buffer,
            &buffer_len);
    
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
           "globus_gridftp_server_control_list_buffer_alloc", result);
        goto error;
    }
    
    globus_gridftp_server_begin_transfer(op);
    
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
    op->state = GLOBUS_L_GFS_DATA_ERROR;
    globus_gridftp_server_finished_transfer(op, result); 

    return;
}

globus_result_t
globus_i_gfs_data_list_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       list_state)
/*
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_handle_t *        data_handle,
    const char *                        pathname,
    globus_i_gfs_data_transfer_cb_t     callback,
    globus_i_gfs_data_transfer_event_cb_t event_callback,
    void *                              user_arg)
*/
{
    globus_l_gfs_data_operation_t *     resource_op;
    globus_l_gfs_data_operation_t *     data_op;
    globus_result_t                     result;
    globus_i_gfs_data_handle_t *        data_handle;
    GlobusGFSName(globus_i_gfs_data_list_request);

    data_handle = (globus_i_gfs_data_handle_t *)
        list_state->data_handle_id;

    if(result != GLOBUS_SUCCESS || data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    if(data_handle->closed)
    {
        result = GlobusGFSErrorData("Data handle has been closed");
        goto error_handle;
    }

    result = globus_l_gfs_data_operation_init(&data_op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }

    data_op->id = id;
    data_op->state = GLOBUS_L_GFS_DATA_PENDING;
    data_op->data_handle = data_handle;
    data_op->sending = GLOBUS_TRUE;
    data_op->list_type = list_state->list_type;
    data_op->uid = getuid();
    /* XXX */
//    data_op->transfer_callback = callback;
//    data_op->event_callback = event_callback;
//    data_op->user_arg = user_arg;
    
    result = globus_l_gfs_data_operation_init(&resource_op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    resource_op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    resource_op->resource_callback = globus_l_gfs_data_list_resource_cb;
    resource_op->user_arg = data_op;

    /* XXX */
    result = globus_l_gfs_file_resource(
        resource_op, 
        list_state->pathname,
        0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("list_hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&resource_op->lock);
    {
        if(resource_op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            resource_op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&resource_op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(data_op);
    globus_l_gfs_data_operation_destroy(resource_op);

error_op:
error_handle:
    return result;
}


void
globus_gridftp_server_begin_transfer(
    globus_gridftp_server_operation_t   op)
{
    globus_result_t                     result;
    GlobusGFSName(globus_gridftp_server_begin_transfer);
    
    if(op->sending)
    {
        result = globus_ftp_control_data_connect_write(
            &op->data_handle->data_channel, GLOBUS_NULL, GLOBUS_NULL);
    }
    else
    {
        result = globus_ftp_control_data_connect_read(
            &op->data_handle->data_channel, GLOBUS_NULL, GLOBUS_NULL);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_connect;
    }

    {
    globus_gfs_ipc_reply_t *            event_reply;   
    event_reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));

    event_reply->type = GLOBUS_GFS_IPC_TYPE_EVENT;
    event_reply->id = op->id;
    event_reply->event = GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN;

    globus_gfs_ipc_reply_event(
        op->ipc_handle,
        event_reply);
    }
/*
    op->event_callback(
        op->instance,
        GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN,
        GLOBUS_NULL,
        op->user_arg);
*/    
    return;
    
error_connect:
    op->state = GLOBUS_L_GFS_DATA_ERROR;
    globus_gridftp_server_finished_transfer(op, result);
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
    globus_gridftp_server_operation_t   op;
    GlobusGFSName(globus_l_gfs_data_write_eof_cb);
    
    op = (globus_gridftp_server_operation_t) user_arg;
    
    /* XXX mode s only */
    /* racey shit here */
    globus_gfs_ipc_reply_t *            reply;   
    reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));

    reply->type = GLOBUS_GFS_IPC_TYPE_TRANSFER;
    reply->id = op->id;
    reply->result = error ? 
        globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS;
    reply->event = GLOBUS_I_GFS_EVENT_DISCONNECTED;

    globus_gfs_ipc_reply_event(
        op->ipc_handle,
        reply);

    /*
    op->event_callback(
        op->instance,
        GLOBUS_I_GFS_EVENT_DISCONNECTED,
        op->data_handle,
        op->user_arg);
    */
             
    globus_gfs_ipc_reply_finished(
        op->ipc_handle,
        reply);
    /*            
    op->transfer_callback(
        op->instance,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        op->user_arg);
    */
    
    globus_l_gfs_data_operation_destroy(op);
}

void
globus_gridftp_server_finished_transfer(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result)
{
    GlobusGFSName(globus_gridftp_server_finished_transfer);
    
    switch(op->state)
    {
      case GLOBUS_L_GFS_DATA_PENDING:
      case GLOBUS_L_GFS_DATA_REQUESTING:
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
        
        if(result == GLOBUS_SUCCESS && op->sending)
        {
            result = globus_ftp_control_data_write(
                &op->data_handle->data_channel,
                "",
                0,
                0,
                GLOBUS_TRUE,
                globus_l_gfs_data_write_eof_cb,
                op);
        }
        
        if(result != GLOBUS_SUCCESS || !op->sending)
        {
            globus_gridftp_server_control_event_send_perf(
               op->control_op,
               0,
               op->recvd_bytes[0]);
            globus_gridftp_server_control_event_send_restart(
               op->control_op,
               op->recvd_ranges);
           
            /* XXX mode s only */
            /* racey shit here */
            globus_gfs_ipc_reply_t *            reply;   
            reply = (globus_gfs_ipc_reply_t *) 
                globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));

            reply->type = GLOBUS_GFS_IPC_TYPE_TRANSFER;
            reply->id = op->id;
            reply->result = result;
            reply->event = GLOBUS_I_GFS_EVENT_DISCONNECTED;
        
            globus_gfs_ipc_reply_event(
                op->ipc_handle,
                reply);
            /*
            op->event_callback(
                op->instance,
                GLOBUS_I_GFS_EVENT_DISCONNECTED,
                op->data_handle,
                op->user_arg);
            */
                     
            globus_gfs_ipc_reply_finished(
                op->ipc_handle,
                reply);
            /*
            op->transfer_callback(
                op->instance,
                result,
                op->user_arg);
            */
            
            globus_l_gfs_data_operation_destroy(op);
        }
        break;
        
      case GLOBUS_L_GFS_DATA_ERROR_COMPLETE:
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
        
        globus_l_gfs_data_operation_destroy(op);
        break;
      
      /* this state always means this was called internally */
      case GLOBUS_L_GFS_DATA_ERROR:
        globus_i_gfs_data_handle_close(op->data_handle);
        /* racey shit here */
        globus_gfs_ipc_reply_t *            reply;   
        reply = (globus_gfs_ipc_reply_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
     
        reply->type = GLOBUS_GFS_IPC_TYPE_TRANSFER;
        reply->id = op->id;
        reply->result = result;
        reply->event = GLOBUS_I_GFS_EVENT_DISCONNECTED;
    
        globus_gfs_ipc_reply_event(
            op->ipc_handle,
            reply);
       
        /*
        op->event_callback(
            op->instance,
            GLOBUS_I_GFS_EVENT_DISCONNECTED,
            op->data_handle,
            op->user_arg);
        */
                 
        globus_gfs_ipc_reply_finished(
            op->ipc_handle,
            reply);
        /*
        op->transfer_callback(
            op->instance,
            result,
            op->user_arg);
        */
        op->state = GLOBUS_L_GFS_DATA_ERROR_COMPLETE;
        break;
      
      default:
        globus_assert(0 && "Invalid state");
        break;
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

globus_result_t
globus_gridftp_server_register_write(
    globus_gridftp_server_operation_t   op,
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
    
    result = globus_ftp_control_data_write(
        &op->data_handle->data_channel,
        buffer,
        length,
        offset,
        GLOBUS_FALSE,
        globus_l_gfs_data_write_cb,
        bounce_info);
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
    
globus_result_t
globus_gridftp_server_register_read(
    globus_gridftp_server_operation_t   op,
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

/* aborts all pending operations and calls callbacks */
void
globus_gridftp_server_flush_queue(
    globus_gridftp_server_operation_t   op)
{
    GlobusGFSName(globus_gridftp_server_flush_queue);
    
    globus_i_gfs_data_handle_close(op->data_handle);
    {  /* racey shit here */
    globus_gfs_ipc_reply_t *            event_reply;   
    event_reply = (globus_gfs_ipc_reply_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_reply_t));
 
    event_reply->type = GLOBUS_GFS_IPC_TYPE_EVENT;
    event_reply->id = op->id;
    event_reply->event = GLOBUS_I_GFS_EVENT_DISCONNECTED;

    globus_gfs_ipc_reply_event(
        op->ipc_handle,
        event_reply);
    }
    /*
    op->event_callback(
        op->instance,
        GLOBUS_I_GFS_EVENT_DISCONNECTED,
        op->data_handle,
        op->user_arg);
    */
}

void
globus_gridftp_server_update_bytes_written(
    globus_gridftp_server_operation_t   op,
    int                                 stripe_ndx,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    GlobusGFSName(globus_gridftp_server_update_bytes_written);

    op->recvd_bytes[stripe_ndx] += length;
    globus_range_list_insert(op->recvd_ranges, offset, length);

    return;
}

void
globus_gridftp_server_get_optimal_concurrency(
    globus_gridftp_server_operation_t   op,
    int *                               count)
{
    GlobusGFSName(globus_gridftp_server_get_optimal_concurrency);
    
    *count = op->data_handle->attr.nstreams * 2;
}

void
globus_gridftp_server_get_block_size(
    globus_gridftp_server_operation_t   op,
    globus_size_t *                     block_size)
{
    GlobusGFSName(globus_gridftp_server_get_block_size);
    
    *block_size = op->data_handle->attr.blocksize;
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
    globus_gridftp_server_operation_t   op,
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
    if(op->data_handle->attr.mode == 'S')
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
    globus_gridftp_server_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta)
{
    GlobusGFSName(globus_gridftp_server_get_read_range);
    globus_off_t                        tmp_off = 0;
    globus_off_t                        tmp_len = -1;
    globus_off_t                        tmp_write = 0;
    int                                 rc;
    
    if(globus_range_list_size(op->range_list))
    {
        rc = globus_range_list_remove_at(
            op->range_list,
            0,
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
    }
    else
    {
        tmp_len = 0;
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
    
    return; 
}

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    int                                 event_type;
} globus_l_gfs_data_trev_bounce_t;


void
globus_l_gfs_data_transfer_event_kickout(
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_data_transfer_event_kickout);
    globus_l_gfs_data_trev_bounce_t *   bounce_info;
    
    bounce_info = (globus_l_gfs_data_trev_bounce_t *) user_arg;
    
    switch(bounce_info->event_type)
    {
      case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF:
        globus_gridftp_server_control_event_send_perf(
           bounce_info->op->control_op,
           0,
           bounce_info->op->recvd_bytes[0]);
        break;
      case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART:
        globus_gridftp_server_control_event_send_restart(
           bounce_info->op->control_op,
           bounce_info->op->recvd_ranges);
        break;
        
      default:
        break;
    } 

    globus_free(bounce_info);       
}

void
globus_i_gfs_data_transfer_event(
    globus_i_gfs_server_instance_t *    instance,
    int                                 event_type)
{
    GlobusGFSName(globus_i_gfs_data_kickoff_event);
    globus_result_t                     result;
    globus_l_gfs_data_trev_bounce_t *   bounce_info;
    
    bounce_info = (globus_l_gfs_data_trev_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_trev_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = instance->op;
    bounce_info->event_type = event_type;
    
    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_data_transfer_event_kickout,
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
    return;  
}
