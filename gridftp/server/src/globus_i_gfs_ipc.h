#ifndef GLOBUS_I_GFS_IPC_H
#define GLOBUS_I_GFS_IPC_H

#include "globus_i_gridftp_server.h"

// stuck in globus_i_gridftp_server.h for now so ipc_handle can be in instance
// will be outa there when ipc_handle handling shit is in control.c
// after local version / single stripe is working i guess.
// typedef struct globus_i_gfs_ipc_handle_s * globus_gfs_ipc_handle_t;

typedef enum
{
    GLOBUS_GFS_IPC_STATE_OPENING,
    GLOBUS_GFS_IPC_STATE_OPEN,
    GLOBUS_GFS_IPC_STATE_AUTHENTICATING,
    GLOBUS_GFS_IPC_STATE_CLOSING,
    GLOBUS_GFS_IPC_STATE_ERROR, 
} globus_gfs_ipc_state_t;

typedef enum
{
    GLOBUS_GFS_IPC_TYPE_FINAL_REPLY,
    GLOBUS_GFS_IPC_TYPE_EVENT_REPLY,
    GLOBUS_GFS_IPC_TYPE_EVENT,    
    GLOBUS_GFS_IPC_TYPE_AUTH,
    GLOBUS_GFS_IPC_TYPE_USER,
    GLOBUS_GFS_IPC_TYPE_RECV,
    GLOBUS_GFS_IPC_TYPE_SEND,
    GLOBUS_GFS_IPC_TYPE_LIST,
    GLOBUS_GFS_IPC_TYPE_COMMAND,
    GLOBUS_GFS_IPC_TYPE_PASSIVE,
    GLOBUS_GFS_IPC_TYPE_ACTIVE,
    GLOBUS_GFS_IPC_TYPE_DESTROY,
    GLOBUS_GFS_IPC_TYPE_TRANSFER,
    GLOBUS_GFS_IPC_TYPE_STAT
} globus_gfs_ipc_request_type_t;

typedef enum
{
    GLOBUS_GFS_IPC_USER_TYPE_INT32,
    GLOBUS_GFS_IPC_USER_TYPE_INT64,
    GLOBUS_GFS_IPC_USER_TYPE_CHAR,
    GLOBUS_GFS_IPC_USER_TYPE_STRING
} globus_gfs_ipc_user_type_t;

typedef struct globus_i_gfs_community_s
{
    char *                              root;
    char *                              name;
    int                                 cs_count;
    char **                             cs;
} globus_i_gfs_community_t;

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

typedef struct globus_gfs_ipc_data_reply_s
{
    int                                 data_handle_id;
    int                                 cs_count;
    const char **                       contact_strings;
    globus_bool_t                       bi_directional;
    globus_gridftp_server_control_network_protocol_t net_prt; /* gag */
} globus_gfs_ipc_data_reply_t;

typedef struct globus_gfs_ipc_command_reply_s
{
    /* XXX not too sure bout these yet */
    globus_i_gfs_command_t              command;
    char *                              checksum;
    char *                              created_dir;
} globus_gfs_ipc_command_reply_t;

typedef struct globus_gfs_ipc_stat_reply_s
{
    globus_gridftp_server_stat_t *      stat_info;
    int                                 stat_count;
    uid_t                               uid;
} globus_gfs_ipc_stat_reply_t;

typedef struct globus_i_gfs_ipc_reply_s
{
    /* what command is being replied to */
    int                                 type;
    int                                 id;
    int                                 code;
    char *                              msg;
    globus_result_t                     result;

    /* prolly a different struct for event stuff */
    globus_i_gfs_event_t                event;

    union
    {
        globus_gfs_ipc_data_reply_t     data;
        globus_gfs_ipc_command_reply_t  command;
        globus_gfs_ipc_stat_reply_t stat;
    } info;

} globus_gfs_ipc_reply_t;

typedef struct globus_i_gfs_ipc_event_reply_s
{
    /* what event is this */
    int                                 type;
    int                                 stripe_ndx;
    int                                 id;
    int                                 transfer_id;
    globus_off_t                        recvd_bytes;
    globus_range_list_t                 recvd_ranges;
} globus_gfs_ipc_event_reply_t;



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
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_event_callback_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_ipc_event_reply_t *      reply,
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

globus_result_t
globus_gfs_ipc_reply_finished(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_reply_t *            reply);

globus_result_t
globus_gfs_ipc_reply_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_event_reply_t *      reply);

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
    const char *                        list_type;
    
    globus_off_t                        partial_offset;
    globus_off_t                        partial_length;
    globus_range_list_t                 range_list;
    
    int                                 data_handle_id;
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

    char                                prot;
    char                                dcau;
    char *                              subject;

    globus_gridftp_server_control_network_protocol_t net_prt; /* gag */

    int                                 cs_count;
    const char **                       contact_strings;
} globus_gfs_data_state_t;

typedef struct globus_gfs_stat_state_s
{
    globus_bool_t                       file_only;
    char *                              pathname;
} globus_gfs_stat_state_t;


typedef void
(*globus_i_gfs_ipc_data_callback_t)(
    globus_gfs_ipc_reply_t *           reply,
    void *                              user_arg);

typedef void
(*globus_i_gfs_ipc_data_event_callback_t)(
    globus_gfs_ipc_event_reply_t *     reply,
    void *                              user_arg);



typedef void
(*globus_gfs_ipc_iface_set_user_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    const char *                        user_dn,
    globus_i_gfs_ipc_data_callback_t          cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_set_user(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    const char *                        user_dn,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

typedef void
(*globus_gfs_ipc_iface_set_cred_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    gss_cred_id_t                       cred_thing,
    globus_i_gfs_ipc_data_callback_t          cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_set_cred(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    gss_cred_id_t                       cred_thing,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  receive
 *
 *  tell the remote process to receive a file
 */
typedef globus_result_t
(*globus_gfs_ipc_iface_recv_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       recv_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    globus_i_gfs_ipc_data_event_callback_t    event_cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       recv_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg);

/*
 *  send
 *  
 *  tell remote process to send a file
 */
typedef globus_result_t
(*globus_gfs_ipc_iface_send_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       send_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    globus_i_gfs_ipc_data_event_callback_t    event_cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       send_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg);


typedef globus_result_t
(*globus_gfs_ipc_iface_list_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_transfer_state_t *       list_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    globus_i_gfs_ipc_data_event_callback_t    event_cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_transfer_state_t *       list_state,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg);


/*
 *  command
 *
 *  tell remote side to execute the given command
 */
typedef globus_result_t
(*globus_gfs_ipc_iface_command_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_command_state_t *        cmd_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    void *                              user_arg);

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
typedef globus_result_t
(*globus_gfs_ipc_iface_active_data_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    void *                              user_arg);

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
typedef globus_result_t
(*globus_gfs_ipc_iface_passive_data_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_data_state_t *           data_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_data_state_t *           data_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);

/*
 *  send stat request
 */
typedef globus_result_t
(*globus_gfs_ipc_iface_stat_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 id,
    globus_gfs_stat_state_t *       stat_state,
    globus_i_gfs_ipc_data_callback_t          cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               id,
    globus_gfs_stat_state_t *       stat_state,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg);


/*
 * poke transfer event request
 */
typedef void
(*globus_gfs_ipc_iface_transfer_event_t)(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 transfer_id,
    int                                 event_type);


globus_result_t
globus_gfs_ipc_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 transfer_id,
    int                                 event_type);


/*
 *  destroy a data connection associated with the given ID
 */
typedef void
(*globus_gfs_ipc_iface_data_destroy_t)(
    int                                 data_connection_id);

globus_result_t
globus_gfs_ipc_request_data_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,
    int                                 data_connection_id);

typedef struct globus_i_gfs_ipc_iface_s
{
    globus_gfs_ipc_iface_recv_t         recv_func;
    globus_gfs_ipc_iface_send_t         send_func;
    globus_gfs_ipc_iface_command_t      command_func;
    globus_gfs_ipc_iface_active_data_t  active_func;
    globus_gfs_ipc_iface_passive_data_t passive_func;
    globus_gfs_ipc_iface_data_destroy_t data_destroy_func;
    globus_gfs_ipc_iface_stat_t     stat_func;
    globus_gfs_ipc_iface_list_t         list_func;
    globus_gfs_ipc_iface_transfer_event_t transfer_event_func;
    globus_gfs_ipc_iface_set_cred_t     set_cred;
    globus_gfs_ipc_iface_set_user_t     set_user;
} globus_gfs_ipc_iface_t;

/* 
 *  getting an IPC handle
 */

/* 
 *  create an IPC handle from a xio system handle, can be used
 *  imediately, is not in handle table
 */
globus_result_t
globus_gfs_ipc_handle_create(
    globus_gfs_ipc_handle_t *           ipc_handle,
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_system_handle_t          system_handle,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg);

/*
 *  actually close the handle
 */
globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg);

globus_result_t
globus_gfs_ipc_handle_release(
    globus_gfs_ipc_handle_t             ipc_handle);

globus_result_t
globus_gfs_ipc_handle_get(
    const char *                        user_id,
    const char *                        pathname,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg);

globus_result_t
globus_gfs_ipc_handle_get_by_contact(
    const char *                        user_id,
    const char *                        contact_string,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg);

void
globus_gfs_ipc_init();

/* 
 *   community functions
 */
globus_result_t
globus_gfs_community_get_nodes(
    const char *                        pathname,
    char **                             contact_strings,
    int *                               count);

extern globus_gfs_ipc_iface_t  globus_gfs_ipc_default_iface;

#endif
