#ifndef GLOBUS_I_GFS_IPC_H
#define GLOBUS_I_GFS_IPC_H

typedef struct globus_i_gfs_ipc_handle_s * globus_gfs_ipc_handle_t;
typedef struct globus_i_gfs_ipc_reply_s *  globus_gfs_ipc_reply_t;
typedef struct globus_i_gfs_ipc_iface_s *  globus_gfs_ipc_iface_t;


/*
 *  callbacks
 *
 *  all functions have the same callback, they examine the
 *  globus_gfs_ipc_reply_t() structure for their specific info
 *
 *  error_cb
 *  can be called at anytime.  typically means the ipc connection broke
 *  in an irrecoverable way.  Even tho this is called all outstanding
 *  callbacks will still be called (but with an error)
 */
typedef void
(*globus_gfs_ipc_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_ipc_reply_t              reply,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_event_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t              reply,
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_open_close_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_error_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg);


/*
 *  replying
 *
 *  every comman requires a reply and comes with a reply id.  to reply
 *  the requested side must fill in the globus_gfs_ipc_reply_t
 *  structure and then pass it
 *  to the function: globus_gfs_ipc_reply();  That call will result in
 *  the ipc communication that will untilimately call the callback
 *  on the callers side.
 */
typedef struct globus_gfs_ipc_passive_reply_s
{
    const char **                       contact_strings;
    int                                 cs_count;
    globus_bool_t                       bi_directional;
    globus_gridftp_server_control_network_protocol_t net_prt; /* gag */
} globus_gfs_ipc_passive_reply_t;

typedef struct globus_gfs_ipc_command_reply_s
{
    /* XXX not too sure bout these yet */
    globus_i_gfs_command_t              command;
    char *                              checksum;
    char *                              created_dir;
} globus_gfs_ipc_command_reply_t;

typedef struct globus_gfs_ipc_resource_reply_s
{
    globus_gridftp_server_stat_t *      stat_info;
    int                                 stat_count;
} globus_gfs_ipc_resource_reply_t;

struct globus_i_gfs_ipc_reply_s
{
    /* what command is being replied to */
    int                                 id;
    int                                 reply_code;
    char *                              reply_msg;
    globus_result_t                     result;

    union
    {
        globus_gfs_ipc_data_reply_t     data_reply;
        globus_gfs_ipc_command_reply_t  command_reply;
        globus_gfs_ipc_resource_reply_t resource_reply;
    } reply_type;

} globus_gfs_i_ipc_reply_t;


/* callback and id relation */
typedef struct globus_gfs_ipc_call_entry_s
{
    int                                 id;
    globus_gfs_ipc_callback_t           cb;
    globus_gfs_ipc_callback_t           event_cb;
    void *                              user_arg;
} globus_gfs_ipc_call_entry_t;

globus_result_t
globus_gfs_ipc_finished_reply(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply);

globus_result_t
globus_gfs_ipc_event_reply(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply);

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

typedef struct globus_gfs_transfer_state_s
{
    char *                              pathname;    
    char *                              module_name;
    char *                              module_args;
    
    globus_off_t                        partial_offset;
    globus_off_t                        partial_length;
    globus_range_list_t                 range_list;

    /* yeah yeah, this don't belong, need it for list and events (for now) */    
    globus_gridftp_server_control_op_t  control_op;
} globus_gfs_transfer_state_t;

typedef struct globus_gfs_command_state_s
{
    globus_i_gfs_command_t              command; 
    char *                              pathname;

    globus_off_t                        cksm_offset;
    globus_off_t                        cksm_length;
    char *                              cksm_alg;
    char *                              cksm_response;
    
    mode_t                              chmod_mode;
    
    char *                              rnfr_pathname;    
} globus_gfs_command_state_t;

typedef struct globus_gfs_data_state_s
{
    globus_bool_t                       ipv6;
    int                                 nstreams;
    char                                mode;
    char                                type;
    int                                 tcp_bufsize;
    globus_size_t                       blocksize;
        
    globus_ftp_control_protection_t     prot;
    globus_ftp_control_dcau_t           dcau;
    const char **                       contact_strings;
    int                                 cs_count;
    globus_gridftp_server_control_network_protocol_t net_prt; /* gag */
} globus_gfs_data_state_t;

typedef struct globus_gfs_resource_state_s
{
    char *                              pathname;
    /* maybe just a bool file_only here? 
        (tells me to return info on dir contents or dir itself) */
    globus_gridftp_server_control_resource_mask_t mask;
} globus_gfs_resource_state_t;

typedef void
(*globus_gfs_ipc_iface_set_user)(
    globus_gfs_ipc_handle_t             ipc_handle,
    const char *                        user_dn,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state);

globus_result_t
globus_gfs_ipc_set_user(
    globus_gfs_ipc_handle_t             ipc_handle,
    const char *                        user_dn,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_iface_set_cred)(
    globus_gfs_ipc_handle_t             ipc_handle,
    const char *                        user_dn,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state);

globus_result_t
globus_gfs_ipc_set_cred(
    globus_gfs_ipc_handle_t             ipc_handle,
    cred_thing,
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
globus_gfs_ipc_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
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
globus_gfs_ipc_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_callback_t           event_cb,
    void *                              user_arg);


typedef void
(*globus_gfs_ipc_iface_list_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state);

globus_result_t
globus_gfs_ipc_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
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
globus_gfs_ipc_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
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
globus_gfs_ipc_request_active_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
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
globus_gfs_ipc_request_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  send resource request
 */
typedef void
(*globus_gfs_ipc_iface_resource_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_resource_state_t *       resource_state);

globus_result_t
globus_gfs_ipc_resource_query(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_resource_state_t *       resource_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  destroy a data connection associated with the given ID
 */
typedef void
(*globus_gfs_ipc_iface_data_destroy_t)(
    int                                 data_connection_id);

void
globus_gfs_ipc_data_destroy(
    int                                 data_connection_id);

globus_result_t
globus_gfs_ipc_open(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t *            iface,
    const char *                        contact_string,
    globus_gfs_ipc_callback_t           open_cb,
    void *                              open_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg);

globus_result_t
globus_gfs_ipc_handle_create(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_handle_t                 xio_handle,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg);

globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg);

typedef struct globus_i_gfs_ipc_iface_s
{
    globus_gfs_ipc_iface_state_t        state_func;
    globus_gfs_ipc_iface_recv_t         recv_func;
    globus_gfs_ipc_iface_send_t         send_func;
    globus_gfs_ipc_iface_command_t      command_func;
    globus_gfs_ipc_iface_active_data_t  active_func;
    globus_gfs_ipc_iface_passive_data_t passive_func;
    globus_gfs_ipc_iface_data_destroy_t data_destory_func;
    globus_gfs_ipc_iface_resource_t     resource_func;
    globus_gfs_ipc_iface_list_t         list_func;
} globus_i_gfs_ipc_iface_t;

#endif

