#ifndef GLOBUS_I_GFS_DATA_H
#define GLOBUS_I_GFS_DATA_H

#include "globus_i_gfs_ipc.h"

extern globus_i_gfs_data_attr_t         globus_i_gfs_data_attr_defaults;

typedef void
(*globus_i_gfs_data_command_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_resource_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_transfer_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_transfer_event_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_event_t                type,
    void *                              data,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_active_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_data_handle_t *        data_handle,
    globus_bool_t                       bi_directional,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_passive_cb_t)(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_data_handle_t *        data_handle,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count,
    void *                              user_arg);



globus_result_t
globus_i_gfs_data_resource_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_resource_state_t *       resource_state);

globus_result_t
globus_i_gfs_data_recv_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state);

globus_result_t
globus_i_gfs_data_send_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state);

globus_result_t
globus_i_gfs_data_list_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       list_state);

globus_result_t
globus_i_gfs_data_command_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_command_state_t *        command_state);

globus_result_t
globus_i_gfs_data_passive_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state);

globus_result_t
globus_i_gfs_data_active_request(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state);

void
globus_i_gfs_data_handle_destroy(
    globus_i_gfs_data_handle_t *        data_handle);

void
globus_i_gfs_data_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 transfer_id,
    int                                 event_type);
    
globus_result_t
globus_i_gfs_data_node_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact);


#endif
