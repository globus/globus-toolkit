
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
