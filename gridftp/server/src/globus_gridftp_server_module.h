#ifndef GLOBUS_GRIDFTP_SERVER_MODULE_H
#define GLOBUS_GRIDFTP_SERVER_MODULE_H


#include "globus_gridftp_server.h"
#include "globus_i_gridftp_server.h"

typedef globus_gfs_ipc_reply_t          globus_gridftp_server_finished_t;
typedef globus_gfs_ipc_event_reply_t    globus_gridftp_server_event_t;
typedef struct globus_l_gfs_data_operation_s * globus_gfs_operation_t;


/* notification funcs */

void
globus_gridftp_server_operation_finished(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_gridftp_server_finished_t    finished_state);

void
globus_gridftp_server_operation_event(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_gridftp_server_event_t       event_state);

void
globus_gridftp_server_begin_transfer(
    globus_gfs_operation_t   op);

void
globus_gridftp_server_finished_transfer(
    globus_gfs_operation_t   op, 
    globus_result_t                     result);

void
globus_gridftp_server_finished_command(
    globus_gfs_operation_t   op, 
    globus_result_t                     result,
    char *                              command_response);
    
void
globus_gridftp_server_finished_stat(
    globus_gfs_operation_t   op, 
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count);



/* data read and write */

typedef void
(*globus_gridftp_server_write_cb_t)(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);
    
globus_result_t
globus_gridftp_server_register_write(
    globus_gfs_operation_t   op,
    globus_byte_t *                     buffer,  
    globus_size_t                       length,  
    globus_off_t                        offset,  
    int                                 stripe_ndx,  
    globus_gridftp_server_write_cb_t    callback,  
    void *                              user_arg);

typedef void
(*globus_gridftp_server_read_cb_t)(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg);
 
globus_result_t
globus_gridftp_server_register_read(
    globus_gfs_operation_t   op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,  
    void *                              user_arg);


/* helper funcs */

void
globus_gridftp_server_flush_queue(
    globus_gfs_operation_t   op);
    
void
globus_gridftp_server_update_bytes_written(
    globus_gfs_operation_t   op,
    int                                 stripe_ndx,
    globus_off_t                        offset,
    globus_off_t                        length);

void
globus_gridftp_server_get_optimal_concurrency(
    globus_gfs_operation_t   op,
    int *                               count);

void
globus_gridftp_server_get_block_size(
    globus_gfs_operation_t   op,
    globus_size_t *                     block_size);

void
globus_gridftp_server_get_read_range(
    globus_gfs_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta);

void
globus_gridftp_server_get_write_range(
    globus_gfs_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta,
    globus_off_t *                      transfer_delta);



/* interface sigs */

typedef globus_result_t
(*globus_gridftp_server_storage_transfer_t)(
    globus_gfs_operation_t   op,
    globus_gfs_transfer_state_t *       transfer_state,
    void *                              user_arg);

typedef globus_result_t
(*globus_gridftp_server_storage_command_t)(
    globus_gfs_operation_t   op,
    globus_gfs_command_state_t *        command_state,
    void *                              user_arg);

typedef globus_result_t
(*globus_gridftp_server_storage_stat_t)(
    globus_gfs_operation_t   op,
    globus_gfs_stat_state_t *           stat_state,
    void *                              user_arg);

typedef globus_result_t
(*globus_gridftp_server_storage_data_t)(
    globus_gfs_operation_t   op,
    globus_gfs_data_state_t *           data_state,
    void *                              user_arg);

typedef void
(*globus_gridftp_server_storage_data_destroy_t)(
    int                                 data_handle_id,
    void *                              user_arg);

typedef void
(*globus_gridftp_server_storage_trev_t)(
    int                                 transfer_id,
    int                                 event_type,
    void *                              user_arg);

typedef void
(*globus_gridftp_server_storage_set_cred_t)(
    globus_gfs_operation_t   op,
    gss_cred_id_t                       cred_thing,
    void *                              user_arg);

typedef globus_result_t
(*globus_gridftp_server_storage_init_t)(
    const char *                        user_id,
    void **                             out_user_arg);

typedef void
(*globus_gridftp_server_storage_destroy_t)(
    void *                              user_arg);




typedef struct globus_gridftp_server_storage_iface_s
{
    /* session initiating functions */
    globus_gridftp_server_storage_init_t        init_func;
    globus_gridftp_server_storage_destroy_t     destroy_func;

    /* transfer functions */
    globus_gridftp_server_storage_transfer_t    list_func;
    globus_gridftp_server_storage_transfer_t    send_func;
    globus_gridftp_server_storage_transfer_t    recv_func;
    globus_gridftp_server_storage_trev_t        trev_func;

    /* data conn funcs */
    globus_gridftp_server_storage_data_t        active_func;
    globus_gridftp_server_storage_data_t        passive_func;
    globus_gridftp_server_storage_data_destroy_t data_destroy_func;

    globus_gridftp_server_storage_command_t     command_func;
    globus_gridftp_server_storage_stat_t        stat_func;

    globus_gridftp_server_storage_set_cred_t    set_cred_func;
} globus_gridftp_server_storage_iface_t;


extern globus_gridftp_server_storage_iface_t   globus_gfs_file_dsi_iface;
extern globus_gridftp_server_storage_iface_t   globus_gfs_remote_dsi_iface;



#endif
