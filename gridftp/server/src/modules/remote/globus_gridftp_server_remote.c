#include "globus_gridftp_server_module.h"
#include "globus_i_gfs_ipc.h"


static
void
globus_l_gfs_ipc_resource_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
/*
    globus_gridftp_server_control_finished_stat(
        op,
        reply->result,
        reply->info.resource.stat_info, 
        reply->info.resource.stat_count);
*/
}

static
void
globus_l_gfs_ipc_command_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
       
}



static
void
globus_l_gfs_ipc_event_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_event_reply_t *      reply,
    void *                              user_arg)
{
}


static
void
globus_l_gfs_ipc_transfer_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
}


static
void
globus_l_gfs_ipc_passive_data_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
}


static
void
globus_l_gfs_ipc_active_data_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
}







static
globus_result_t
globus_l_gfs_remote_stat(
    globus_gridftp_server_operation_t   op,
    globus_gfs_stat_state_t *           stat_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_stat);
    
/*    globus_gfs_ipc_handle_obtain(
        NULL,
        NULL,
        NULL, 
        NULL,
        NULL,
        NULL,
        NULL);
*/
        
    result = globus_gfs_ipc_request_resource(
        ipc_handle,
        &request_id,
        stat_state,
        globus_l_gfs_ipc_resource_cb,
        user_arg);
                    
    return result;
}


static
globus_result_t
globus_l_gfs_remote_command(
    globus_gridftp_server_operation_t   op,
    globus_gfs_command_state_t *        command_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_command);

    result = globus_gfs_ipc_request_command(
        ipc_handle,
        &request_id,
        command_state,
        globus_l_gfs_ipc_command_cb,
        user_arg);

    return result;
}

static
globus_result_t
globus_l_gfs_remote_list(
    globus_gridftp_server_operation_t   op,
    globus_gfs_transfer_state_t *       transfer_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_list);
    
    result = globus_gfs_ipc_request_list(
        ipc_handle,
        &request_id,
        transfer_state,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        user_arg);

    return result;
}

static
globus_result_t
globus_l_gfs_remote_recv(
    globus_gridftp_server_operation_t   op,
    globus_gfs_transfer_state_t *       transfer_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_recv);

    result = globus_gfs_ipc_request_recv(
        ipc_handle,
        &request_id,
        transfer_state,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        user_arg);

    return result;
}

static
globus_result_t
globus_l_gfs_remote_send(
    globus_gridftp_server_operation_t   op,
    globus_gfs_transfer_state_t *       transfer_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_send);

    result = globus_gfs_ipc_request_send(
        ipc_handle,
        &request_id,
        transfer_state,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        user_arg);

    return result;
}

static
globus_result_t
globus_l_gfs_remote_active(
    globus_gridftp_server_operation_t   op,
    globus_gfs_data_state_t *           data_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_active);
    
    result = globus_gfs_ipc_request_active_data(
        ipc_handle,
        &request_id,
        data_state,
        globus_l_gfs_ipc_active_data_cb,
        user_arg);

    return result;
}

static
globus_result_t
globus_l_gfs_remote_passive(
    globus_gridftp_server_operation_t   op,
    globus_gfs_data_state_t *           data_state,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_passive);
        
    result = globus_gfs_ipc_request_passive_data(
        ipc_handle,
        &request_id,
        data_state,
        globus_l_gfs_ipc_passive_data_cb,
        user_arg);

    return result;
}

static
void
globus_l_gfs_remote_data_destroy(
    int                                 data_handle_id,
    void *                              user_arg)
{
    globus_gfs_ipc_handle_t             ipc_handle;
    GlobusGFSName(globus_l_gfs_remote_data_destroy);

    globus_gfs_ipc_request_data_destroy(ipc_handle, data_handle_id);

    return;
}


static
void
globus_l_gfs_remote_trev(
    int                                 transfer_id,
    int                                 event_type,
    void *                              user_arg)
{
    globus_gfs_ipc_handle_t             ipc_handle;
    GlobusGFSName(globus_l_gfs_remote_trev);

    globus_gfs_ipc_request_transfer_event(
        ipc_handle, transfer_id, event_type);

    return;
}


static
void
globus_l_gfs_remote_set_cred(
    globus_gridftp_server_operation_t   op,
    gss_cred_id_t                       cred_thing,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_remote_set_cred);
}


globus_result_t
globus_l_gfs_remote_init(
    const char *                        user_id,
    void **                             out_user_arg)
{
    globus_result_t                     result;
    
    
    return result;
}
                                                                                
void
globus_l_gfs_remote_destory(
    void *                              user_arg)
{
}


globus_gridftp_server_storage_iface_t   globus_gfs_remote_dsi_iface = 
{
    globus_l_gfs_remote_init,
    globus_l_gfs_remote_destory,
    globus_l_gfs_remote_list,
    globus_l_gfs_remote_send,
    globus_l_gfs_remote_recv,
    globus_l_gfs_remote_trev,
    globus_l_gfs_remote_active,
    globus_l_gfs_remote_passive,
    globus_l_gfs_remote_data_destroy,
    globus_l_gfs_remote_command, 
    globus_l_gfs_remote_stat,
    globus_l_gfs_remote_set_cred
};


