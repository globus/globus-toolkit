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



#ifdef 0

/*
 *  replying
 *
 *  every comman requires a reply and comes with a reply id.  to reply
 *  the callee must fill in the globus_gfs_ipc_reply_t
 *  structure and then pass it
 *  to the function: globus_gfs_ipc_reply();  That call will result in
 *  the ipc communication that will untilimately call the callback
 *  on the callers side.
 */
typedef struct globus_gfs_ipc_passive_reply_s
{
} globus_gfs_ipc_passive_reply_t;

typedef struct globus_gfs_ipc_command_reply_s
{
} globus_gfs_ipc_command_reply_t;

typedef struct globus_gfs_ipc_resource_reply_s
{
} globus_gfs_ipc_resource_reply_t;

typedef struct globus_gfs_ipc_reply_s
{
    /* what command is being replied to */
    int                                 id;
    int                                 errno;
    int                                 reply_code;
    char *                              reply_msg;

    union
    {
        globus_gfs_ipc_passive_reply_t  passive_reply;
        globus_gfs_ipc_command_reply_t  command_reply;
        globus_gfs_ipc_resource_reply_t resource_reply;
    } reply_type;

} globus_gfs_ipc_reply_t;

globus_result_t
globus_gfs_ipc_reply(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply);

/*
 *  callbacks
 *
 *  all functions have the same callback, they examine the
 *  globus_gfs_ipc_reply_t() structure for their specific info
 */
typedef void
(*globus_gfs_ipc_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t              reply,
    void *                              user_arg);

/*
 *  sending
 *
 *  every command has a corresponding iface function.  A call to a
 *  command function results in a call to the correspoding iface
 *  function on the other side of the channel.
 *
 *  all parmeters are wrapped in a structure corresponding to
 *  each function call type.  those structures are defined below
 */
typedef struct globus_gfs_server_state_s
{
} globus_gfs_server_state_t;

typedef struct globus_gfs_server_state_s
{
} globus_gfs_server_state_t;

typedef struct globus_gfs_command_state_s
{
} globus_gfs_command_state_t;

typedef struct globus_gfs_data_state_s
{
} globus_gfs_data_state_t;

typedef struct globus_gfs_resource_state_s
{
} globus_gfs_resource_state_t;
/*
 *  interface to the function that gets called on the remote side when
 *  globus_gfs_ipc_call_state() is called
 */
typedef void
(*globus_gfs_ipc_iface_state_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_server_state_t *         server_state);

/*
 *  call the remote function
 */
globus_result_t
globus_gfs_ipc_call_state(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_server_state_t *         server_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  receive
 *
 *  tell the remote process to receive a file
 */
typedef void
(*globus_gfs_ipc_iface_recv_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state);

globus_result_t
globus_gfs_ipc_call_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_state_t *       recv_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg);

/*
 *  send
 *  
 *  tell remote process to send a file
 */
typedef void
(*globus_gfs_ipc_iface_send_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state);

globus_result_t
globus_gfs_ipc_call_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg);

/*
 *  command
 *
 *  tell remote side to execute the given command
 */
typedef void
(*globus_gfs_ipc_iface_command_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_command_state_t *        cmd_state);

globus_result_t
globus_gfs_ipc_call_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_command_state_t *        cmd_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  active data
 *
 *  tell remote side to create an active data connection
 */
typedef void
(*globus_gfs_ipc_iface_active_data_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state);

globus_result_t
globus_gfs_ipc_call_active_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  passive data
 *
 *  tell remote side to do passive data connection
 */
typedef void
(*globus_gfs_ipc_iface_passive_data_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state);

globus_result_t
globus_gfs_ipc_call_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  destroy a data connection associated with the given ID
 */
typedef void
(*globus_gfs_ipc_iface_data_destroy_t)(
    int                                 data_connection_id);

void
globus_gfs_ipc_call_data_destroy(
    int                                 data_connection_id);

/*
 *  send resource request
 */
typedef void
(*globus_gfs_ipc_iface_resource_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_resource_state_t *       resource_state);

globus_result_t
globus_gfs_ipc_call_resource(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_resource_state_t *       resource_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/* 
 *  tell remote side to provide list info
 */
typedef void
(*globus_gfs_ipc_iface_list_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state);

globus_result_t
globus_gfs_ipc_call_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg);

#endif
