#if !defined(GLOBUS_GRIDFTP_SERVER_PROTO_H)
#define GLOBUS_GRIDFTP_SERVER_PROTO_H

#include "globus_gridftp_server_control.h"

/*********************************************************************
 *                  protocol module interface
 *                  -------------------------
 *  There is an abstraction for the protocol module interface.
 ********************************************************************/
/*
 *  the callback signature the protocol module calls to notify the
 *  library that it has finished.  Once the protocol module calls this
 *  it is signifiny that it will preform no more action with the handle.
 */
typedef void
(*globus_gridftp_server_control_stopped_cb_t)(
    globus_gridftp_server_control_t                 server);

/*
 *  called on module activate
 */
typedef globus_result_t
(*globus_gridftp_server_control_pmod_init_t)();

/*
 *  called on module deactivate
 */
typedef globus_result_t
(*globus_gridftp_server_control_pmod_destroy_t)();

/*
 *  called when a new server handle is to start
 */
typedef globus_result_t
(*globus_gridftp_server_control_pmod_start_t)(
    globus_gridftp_server_control_t                 server,
    globus_xio_handle_t                             xio_handle,
    void **                                         user_arg);

typedef globus_result_t
(*globus_gridftp_server_control_pmod_stop_t)(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_stopped_cb_t      cb,
    void *                                          user_arg);

typedef void
(*globus_gridftp_server_control_pmod_auth_callback_t)(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    void *                                          user_arg);

typedef void
(*globus_gridftp_server_control_pmod_stat_callback_t)(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    globus_gridftp_server_control_stat_t *          stat_buf,
    int                                             stat_count,
    void *                                          user_arg);

typedef void
(*globus_gridftp_server_control_pmod_passive_callback_t)(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    const char  **                                  cs,
    int                                             cs_count,
    void *                                          user_arg);

typedef void
(*globus_gridftp_server_control_pmod_port_callback_t)(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    void *                                          user_arg);

/*
 *  TODO:
 *
 *  event infor will come in here too.  not sure how yet
 */
typedef void
(*globus_gridftp_server_control_data_callback_t)(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    void *                                          user_arg);

typedef void
(*globus_gridftp_server_control_event_callback_t)(
    globus_gridftp_server_control_t                 server,
    unsigned int                                    code,
    const char *                                    msg,
    void *                                          user_arg);

/*
 *  This structure ties all the protocol module interface functions
 *  together.
 */
typedef struct globus_i_gridftp_server_control_pmod_s
{
    globus_gridftp_server_control_pmod_init_t       init_func;
    globus_gridftp_server_control_pmod_destroy_t    destroy_func;
    globus_gridftp_server_control_pmod_start_t      start_func;
    globus_gridftp_server_control_pmod_stop_t       stop_func;
} globus_i_gridftp_server_control_pmod_t;

globus_result_t
globus_gridftp_server_control_pmod_authenticate(
    globus_gridftp_server_control_t                 server,
    const char *                                    username,
    const char *                                    password,
    gss_cred_id_t                                   cred,
    gss_cred_id_t                                   del_cred,
    globus_gridftp_server_control_pmod_auth_callback_t cb,
    void *                                          user_arg);

globus_result_t
globus_gridftp_server_control_pmod_stat(
    globus_gridftp_server_control_t                 server,
    const char *                                    path,
    globus_gridftp_server_control_resource_mask_t   mask,
    globus_gridftp_server_control_pmod_stat_callback_t cb,
    void *                                          user_arg);

globus_result_t
globus_gridftp_server_control_pmod_passive(
    globus_gridftp_server_control_t                 server,
    int                                             max,
    int                                             net_prt,
    globus_gridftp_server_control_pmod_passive_callback_t cb,
    void *                                          user_arg);

globus_result_t
globus_gridftp_server_control_pmod_port(
    globus_gridftp_server_control_t                 server,
    const char **                                   cs,
    int                                             cs_count,
    int                                             net_prt,
    globus_gridftp_server_control_pmod_port_callback_t cb,
    void *                                          user_arg);

globus_result_t
globus_gridftp_server_control_pmod_send(
    globus_gridftp_server_control_t                 server,
    const char *                                    src_path,
    const char *                                    mod_name,
    const char *                                    mod_parms,
    globus_gridftp_server_control_data_callback_t   data_cb,
    globus_gridftp_server_control_event_callback_t  event_cb,
    void *                                          user_arg);

globus_result_t
globus_gridftp_server_control_pmod_receive(
    globus_gridftp_server_control_t                 server,
    const char *                                    dest_path,
    const char *                                    mod_name,
    const char *                                    mod_parms,
    globus_gridftp_server_control_data_callback_t   data_cb,
    globus_gridftp_server_control_event_callback_t  event_cb,
    void *                                          user_arg);

/*
 *  cancel all outstanding commands
 *
 *  TODO:  implement this
 */
globus_result_t
globus_gridftp_server_control_pmod_command_cancel(
    globus_gridftp_server_control_t                 server);

/*
 *  notify the library that the protocol module encountered and error.
 *  This is usually followed up with by a call to the stop interface
 *  function.
 */
globus_result_t
globus_gridftp_server_control_pmod_done(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res);

#endif
