#ifndef GLOBUS_I_GFS_IPC_H
#define GLOBUS_I_GFS_IPC_H

typedef void
(*globus_i_gfs_ipc_command_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    void *                              user_arg);

typedef void
(*globus_i_gfs_ipc_resource_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_resource_request(
    globus_i_gfs_server_instance_t *    instance,
    const char *                        pathname,
    globus_bool_t                       file_only,
    globus_i_gfs_ipc_resource_cb_t      callback,
    void *                              user_arg);

typedef void
(*globus_i_gfs_ipc_transfer_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_i_gfs_ipc_transfer_event_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_event_t                type,
    void *                              data,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_recv_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_op_attr_t *            op_attr,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_ipc_transfer_cb_t      callback,
    globus_i_gfs_ipc_transfer_event_cb_t event_callback,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_send_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_op_attr_t *            op_attr,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_ipc_transfer_cb_t      callback,
    globus_i_gfs_ipc_transfer_event_cb_t event_callback,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_list_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    const char *                        pathname,
    globus_i_gfs_ipc_transfer_cb_t      callback,
    globus_i_gfs_ipc_transfer_event_cb_t event_callback,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_command_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    globus_i_gfs_ipc_command_cb_t       callback,
    void *                              user_arg);
    
typedef void
(*globus_i_gfs_ipc_passive_data_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_passive_data_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    globus_i_gfs_ipc_passive_data_cb_t  callback,
    void *                              user_arg);

typedef void
(*globus_i_gfs_ipc_active_data_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    globus_bool_t                       bi_directional,
    void *                              user_arg);

globus_result_t
globus_i_gfs_ipc_active_data_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    const char **                       contact_strings,
    int                                 cs_count,
    globus_i_gfs_ipc_active_data_cb_t   callback,
    void *                              user_arg);

void
globus_i_gfs_ipc_data_destroy(
    globus_i_gfs_ipc_data_handle_t *    data_handle);

void
globus_i_gfs_ipc_transfer_event(
    globus_i_gfs_server_instance_t *    instance,
    int                                 event_type);

#endif
