#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server.h"

static
void
globus_l_gfs_channel_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_server_instance_t *    instance;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO,
        "Closed connection from %s\n",
        instance->remote_contact);
    
    globus_free(instance->remote_contact);
    globus_free(instance);
}

static
void
globus_l_gfs_done_cb(
    globus_gridftp_server_control_t     server,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_server_instance_t *    instance;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
    globus_gridftp_server_control_destroy(instance->u.control.server);
    globus_xio_register_close(
        instance->xio_handle,
        GLOBUS_NULL,
        globus_l_gfs_channel_close_cb,
        instance);
}

static
void
globus_l_gfs_auth_request(
    globus_gridftp_server_control_op_t  op,
    const char *                        user_name,
    const char *                        pw,
    gss_cred_id_t                       cred,
    gss_cred_id_t                       del_cred)
{
    globus_gridftp_server_control_finished_auth(
        op, GLOBUS_SUCCESS, getuid());
}

static
void
globus_l_gfs_ipc_resource_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    globus_gridftp_server_control_finished_resource(
        op, result, stat_info, stat_count);
}

static
void
globus_l_gfs_resource_request(
    globus_gridftp_server_control_op_t              op,
    const char *                                    path,
    globus_gridftp_server_control_resource_mask_t   mask)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_resource_request);
    
    result = globus_i_gfs_ipc_resource_request(
        instance,
        path,
        mask & GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_FILE_ONLY
            ? GLOBUS_TRUE
            : GLOBUS_FALSE,
        globus_l_gfs_ipc_resource_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_resource_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_resource(
        op, result, GLOBUS_NULL, 0);
}

static
void
globus_l_gfs_ipc_event_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_event_t                type,
    void *                              data,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    switch(type)
    {
      case GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN:
        globus_gridftp_server_control_begin_transfer(op);
        break;
      
      case GLOBUS_I_GFS_EVENT_DISCONNECTED:
        /* globus_gridftp_server_control_disconnected(data); */
        break;
        
      default:
        globus_assert(0 && "Unexpected event type");
        break;
    }
}

static
void
globus_l_gfs_ipc_transfer_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    globus_gridftp_server_control_finished_transfer(op, result);
}

static
void
globus_l_gfs_send_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        local_target,
    const char *                        mod_name,
    const char *                        mod_parms)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_ipc_data_handle_t *    data;
    GlobusGFSName(globus_l_gfs_send_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;
    
    result = globus_i_gfs_ipc_send_request(
        instance,
        data,
        local_target,
        mod_name,
        mod_parms,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_send_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_transfer(op, result);
}

static
void
globus_l_gfs_recv_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        local_target,
    const char *                        mod_name,
    const char *                        mod_parms)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_ipc_data_handle_t *    data;
    GlobusGFSName(globus_l_gfs_recv_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;
    
    result = globus_i_gfs_ipc_recv_request(
        instance,
        data,
        local_target,
        mod_name,
        mod_parms,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_recv_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_transfer(op, result);
}

static
void
globus_l_gfs_ipc_passive_data_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    globus_gridftp_server_control_finished_passive_connect(
        op,
        data_handle,
        result,
        bi_directional 
            ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
            : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_STOR,
        contact_strings,
        cs_count);
}

static
void
globus_l_gfs_op_to_attr(
    globus_gridftp_server_control_op_t               op,
    globus_i_gfs_data_attr_t *                       attr,
    globus_gridftp_server_control_network_protocol_t net_prt)
{
    globus_result_t                     result;
    int                                 buf_size;
    
    *attr = globus_i_gfs_data_attr_defaults;
    if(net_prt == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
    {
        attr->ipv6 = GLOBUS_TRUE;
    }
    else
    {
        attr->ipv6 = GLOBUS_FALSE;
    }
    
    result = globus_gridftp_server_control_get_mode(op, &attr->mode);
    globus_assert(result == GLOBUS_SUCCESS);
    
    result = globus_gridftp_server_control_get_type(op, &attr->type);
    globus_assert(result == GLOBUS_SUCCESS);
    
    result = globus_gridftp_server_control_get_buffer_size(
        op, &attr->tcp_bufsize, &buf_size);
    globus_assert(result == GLOBUS_SUCCESS);
    
    if(buf_size > attr->tcp_bufsize)
    {
        attr->tcp_bufsize = buf_size;
    }

    result = globus_gridftp_server_control_get_parallelism(
        op, &attr->nstreams);
    globus_assert(result == GLOBUS_SUCCESS);
}

static
void
globus_l_gfs_passive_data_connect(
    globus_gridftp_server_control_op_t               op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    int                                              max)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_attr_t            attr;
    GlobusGFSName(globus_l_gfs_passive_data_connect);
    
    globus_l_gfs_op_to_attr(op, &attr, net_prt);
    /* attr.nstreams = max; */
    /* XXX how do I know how many streams to 
     * optimize for when receiving data in mode E? 
     */
    
    result = globus_i_gfs_ipc_passive_data_request(
        instance,
        &attr,
        globus_l_gfs_ipc_passive_data_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_passive_data_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_passive_connect(
        op, GLOBUS_NULL, result, 0, GLOBUS_NULL, 0);
}

static
void
globus_l_gfs_ipc_active_data_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    globus_bool_t                       bi_directional,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    globus_gridftp_server_control_finished_active_connect(
        op,
        data_handle,
        result,
        bi_directional 
            ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
            : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_RETR);
}

static
void
globus_l_gfs_active_data_connect(
    globus_gridftp_server_control_op_t               op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    const char **                                    cs,
    int                                              cs_count)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_attr_t            attr;
    GlobusGFSName(globus_l_gfs_active_data_connect);
    
    globus_l_gfs_op_to_attr(op, &attr, net_prt);
    
    result = globus_i_gfs_ipc_active_data_request(
        instance,
        &attr,
        cs,
        cs_count,
        globus_l_gfs_ipc_active_data_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_active_data_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_active_connect(
        op, GLOBUS_NULL, result, 0);
}

static
void
globus_l_gfs_data_destroy(
    void *                              user_data_handle)
{
    globus_i_gfs_ipc_data_handle_t *    data_handle;
    
    data_handle = (globus_i_gfs_ipc_data_handle_t *) user_data_handle;
    
    globus_i_gfs_ipc_data_destroy(data_handle);
}

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    const char *                        remote_contact)
{
    globus_result_t                     result;
    globus_gridftp_server_control_attr_t attr;
    globus_i_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_i_gfs_control_start);
    
    instance = (globus_i_gfs_server_instance_t *)
        globus_malloc(sizeof(globus_i_gfs_server_instance_t));
    if(!instance)
    {
        result = GlobusGFSErrorMemory("instance");
        goto error_malloc;
    }
    
    instance->xio_handle = handle;
    instance->remote_contact = globus_libc_strdup(remote_contact);
    if(!instance->remote_contact)
    {
        result = GlobusGFSErrorMemory("remote_contact");
        goto error_strdup;
    }
    
    result = globus_gridftp_server_control_attr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
/*MMM    
    result = globus_gridftp_server_control_attr_set_done(
        attr, globus_l_gfs_done_cb);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
*/    
    result = globus_gridftp_server_control_attr_set_resource(
        attr, globus_l_gfs_resource_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_set_auth(
        attr, globus_l_gfs_auth_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_add_recv(
        attr, GLOBUS_NULL, globus_l_gfs_recv_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_add_send(
        attr, GLOBUS_NULL, globus_l_gfs_send_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_data_functions(
        attr,
        globus_l_gfs_active_data_connect,
        globus_l_gfs_passive_data_connect,
        globus_l_gfs_data_destroy);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_init(&instance->u.control.server);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    result = globus_gridftp_server_control_start(
        instance->u.control.server, attr, handle, globus_l_gfs_done_cb, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_start;
    }
    
    globus_gridftp_server_control_attr_destroy(attr);
    
    return GLOBUS_SUCCESS;

error_start:
    globus_gridftp_server_control_destroy(instance->u.control.server);
    
error_init:
error_attr_setup:
    globus_gridftp_server_control_attr_destroy(attr);
    
error_attr:
    globus_free(instance->remote_contact);
    
error_strdup:
    globus_free(instance);
    
error_malloc:
    return result;
}
