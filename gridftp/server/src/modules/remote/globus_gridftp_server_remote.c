#include "globus_gridftp_server_module.h"
#include "globus_i_gfs_ipc.h"

static
globus_result_t
globus_l_gfs_remote_stat(
    globus_gridftp_server_operation_t   op,
    globus_gfs_stat_state_t *           stat_state,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_remote_stat);

globus_gfs_ipc_handle_obtain(
    const char *                        user_id,
    globus_gfs_ipc_iface_t *            iface,
    const char *                        contact_string,
    globus_gfs_ipc_open_close_callback_t cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg);

}

static
globus_result_t
globus_l_gfs_remote_mkdir(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname)
{
    GlobusGFSName(globus_l_gfs_remote_mkdir);
}

static
globus_result_t
globus_l_gfs_remote_rmdir(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname)
{
    GlobusGFSName(globus_l_gfs_remote_rmdir);
}

static
globus_result_t
globus_l_gfs_remote_delete(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname)
{
    GlobusGFSName(globus_l_gfs_remote_delete);
}

static
globus_result_t
globus_l_gfs_remote_rename(
    globus_gridftp_server_operation_t   op,
    const char *                        from_pathname,
    const char *                        to_pathname)
{
    GlobusGFSName(globus_l_gfs_remote_rename);
}

static
globus_result_t
globus_l_gfs_remote_chmod(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    mode_t                              mode)
{
    GlobusGFSName(globus_l_gfs_remote_chmod);
}

static
globus_result_t
globus_l_gfs_remote_cksm(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    const char *                        algorithm,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    GlobusGFSName(globus_l_gfs_remote_cksm);
}

static
globus_result_t
globus_l_gfs_remote_command(
    globus_gridftp_server_operation_t   op,
    globus_gfs_command_state_t *        cmd_state,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_remote_command);
}

static
globus_result_t
globus_l_gfs_remote_recv(
    globus_gridftp_server_operation_t   op,
    globus_gfs_transfer_state_t *       transfer_state,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_remote_command);
}

static
globus_result_t
globus_l_gfs_remote_send(
    globus_gridftp_server_operation_t   op,
    globus_gfs_transfer_state_t *       transfer_state,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_remote_send);
}

globus_result_t
globus_l_gfs_remote_init(
    const char *                        user_id,
    void **                             out_user_arg)
{
}
                                                                                
void
globus_l_gfs_remote_destory(
    void *                              user_arg)
{
}


globus_gridftp_server_storage_iface_t   globus_gfs_remote_dsi_iface = 
{
    NULL,
    NULL,
    NULL,
    globus_l_gfs_remote_send,
    globus_l_gfs_remote_recv,
    NULL, /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    globus_l_gfs_remote_command, 
    globus_l_gfs_remote_stat,
    NULL
};
