#ifndef GLOBUS_I_GFS_DATA_H
#define GLOBUS_I_GFS_DATA_H

#include "globus_i_gridftp_server.h"

extern globus_i_gfs_data_attr_t         globus_i_gfs_data_attr_defaults;


typedef globus_gfs_ipc_reply_t          globus_gfs_data_reply_t;
typedef globus_gfs_ipc_event_reply_t    globus_gfs_data_event_reply_t;

typedef void
(*globus_i_gfs_data_callback_t)(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_event_callback_t)(
    globus_gfs_data_event_reply_t *     reply,
    void *                              user_arg);



globus_result_t
globus_i_gfs_data_request_resource(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_stat_state_t *       resource_state,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

globus_result_t
globus_i_gfs_data_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg);

globus_result_t
globus_i_gfs_data_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg);

globus_result_t
globus_i_gfs_data_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       list_state,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg);

globus_result_t
globus_i_gfs_data_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_command_state_t *        command_state,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

globus_result_t
globus_i_gfs_data_request_passive(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

globus_result_t
globus_i_gfs_data_request_active(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

void
globus_i_gfs_data_destroy_handle(
    globus_i_gfs_data_handle_t *        data_handle);

void
globus_i_gfs_data_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 transfer_id,
    int                                 event_type);
    
globus_result_t
globus_i_gfs_data_node_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact);


#endif
