
#include "globus_i_gridftp_server.h"


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

static
void
globus_l_gfs_data_resource_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_i_gfs_ipc_resource_cb_t      callback;
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *) user_arg;
    callback = (globus_i_gfs_ipc_resource_cb_t) bounce_info->callback1;
    
    callback(instance, result, stat_info, stat_count, bounce_info->user_arg);
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_ipc_resource_request(
    globus_i_gfs_server_instance_t *    instance,
    const char *                        pathname,
    globus_bool_t                       file_only,
    globus_i_gfs_ipc_resource_cb_t      callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_resource_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_resource_request(
        instance,
        pathname,
        file_only,
        globus_l_gfs_data_resource_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_resource_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_command_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_i_gfs_ipc_command_cb_t      callback;
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *) user_arg;
    callback = (globus_i_gfs_ipc_command_cb_t) bounce_info->callback1;

    callback(instance, result, cmd_attr, bounce_info->user_arg);
    
    globus_free(bounce_info);    
}

globus_result_t
globus_i_gfs_ipc_command_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    globus_i_gfs_ipc_command_cb_t       callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_command_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_command_request(
        instance,
        cmd_attr,
        globus_l_gfs_data_command_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_command_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_transfer_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_i_gfs_ipc_transfer_cb_t      callback;
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *) user_arg;
    callback = (globus_i_gfs_ipc_transfer_cb_t) bounce_info->callback1;
    
    callback(instance, result, bounce_info->user_arg);
    globus_free(bounce_info);
}

static
void
globus_l_gfs_data_event_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_event_t                type,
    void *                              data,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_i_gfs_ipc_transfer_event_cb_t callback;
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *) user_arg;
    callback = (globus_i_gfs_ipc_transfer_event_cb_t) bounce_info->callback2;
    
    /* XXX disconnected event sends data handle, not ipc_data_handle */
    callback(instance, type, data, bounce_info->user_arg);
}

globus_result_t
globus_i_gfs_ipc_recv_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_op_attr_t *    op_attr,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_ipc_transfer_cb_t      callback,
    globus_i_gfs_ipc_transfer_event_cb_t event_callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_recv_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->callback2 = event_callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_recv_request(
        instance,
        op_attr,
        &data_handle->data,
        pathname,
        module_name,
        module_args,
        globus_l_gfs_data_transfer_cb,
        globus_l_gfs_data_event_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_recv_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

globus_result_t
globus_i_gfs_ipc_send_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_op_attr_t *    op_attr,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_ipc_transfer_cb_t      callback,
    globus_i_gfs_ipc_transfer_event_cb_t event_callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_send_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->callback2 = event_callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_send_request(
        instance,
        op_attr,
        &data_handle->data,
        pathname,
        module_name,
        module_args,
        globus_l_gfs_data_transfer_cb,
        globus_l_gfs_data_event_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_send_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

globus_result_t
globus_i_gfs_ipc_list_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    const char *                        pathname,
    globus_i_gfs_ipc_transfer_cb_t      callback,
    globus_i_gfs_ipc_transfer_event_cb_t event_callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_list_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->callback2 = event_callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_list_request(
        instance,
        &data_handle->data,
        pathname,
        globus_l_gfs_data_transfer_cb,
        globus_l_gfs_data_event_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_list_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_passive_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_data_handle_t *        data_handle,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_i_gfs_ipc_passive_data_cb_t  callback;
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *) user_arg;
    callback = (globus_i_gfs_ipc_passive_data_cb_t) bounce_info->callback1;
    
    callback(
        instance,
        result,
        (globus_i_gfs_ipc_data_handle_t *) data_handle, 
        bi_directional, 
        contact_strings,
        cs_count, 
        bounce_info->user_arg);
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_ipc_passive_data_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    globus_i_gfs_ipc_passive_data_cb_t  callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_passive_data_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_passive_request(
        instance,
        attr,
        globus_l_gfs_data_passive_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_passive_data_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_active_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_data_handle_t *        data_handle,
    globus_bool_t                       bi_directional,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_i_gfs_ipc_active_data_cb_t   callback;
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *) user_arg;
    callback = bounce_info->callback1;
    
    callback(
        instance,
        result,
        (globus_i_gfs_ipc_data_handle_t *) data_handle,
        bi_directional,
        bounce_info->user_arg);
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_ipc_active_data_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    const char **                       contact_strings,
    int                                 cs_count,
    globus_i_gfs_ipc_active_data_cb_t   callback,
    void *                              user_arg)
{
    globus_l_gfs_ipc_bounce_t *         bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_ipc_active_data_request);
    
    bounce_info = (globus_l_gfs_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->callback1 = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_i_gfs_data_active_request(
        instance,
        attr,
        contact_strings,
        cs_count,
        globus_l_gfs_data_active_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_active_data_request", result);
        goto error_data;
    }
    
    return GLOBUS_SUCCESS;

error_data:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

void
globus_i_gfs_ipc_data_destroy(
    globus_i_gfs_ipc_data_handle_t *    data_handle)
{
    globus_i_gfs_data_handle_destroy(&data_handle->data);
}

void
globus_i_gfs_ipc_transfer_event(
    globus_i_gfs_server_instance_t *    instance,
    int                                 event_type)
{
    globus_i_gfs_data_transfer_event(instance, event_type);
    
    return;
}


#if 1

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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
            call_entry->id,,
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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
            call_entry->id,,
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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
            call_entry->id,,
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
    globus_result_t                     result;
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
    call_entry->id = (int) call_entry;
    call_entry->cb = cb;
    call_entry->user_arg = user_arg;

    globus_hashtable_insert(
        &ipc_handle->call_table,
        call_entry->id,
        (void *) call_entry);
    
    if(ipc_handle->xio_handle == GLOBUS_NULL)
    {
        result = ipc_handle->iface->command_func(
            ipc_handle,
            call_entry->id,,
            cmd_state);
    }
    else
    {
        /* i like wires */
    }
    
    return result;
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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
            call_entry->id,,
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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
    globus_gfs_ipc_call_entry_t         call_entry;

    call_entry = (globus_gfs_ipc_call_entry_t *) 
        globus_calloc(1, sizeof(globus_gfs_ipc_call_entry_t);
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
);





#endif