#include "globus_i_gridftp_server_control.h"
#include "version.h"
#include <sys/utsname.h>

/*************************************************************************
 *                      get functions
 *                      -------------
 ************************************************************************/
globus_bool_t
globus_gridftp_server_control_authenticated(
    globus_gridftp_server_control_t         server)
{
    globus_bool_t                           rc;
    globus_i_gsc_server_handle_t *          i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_authenticated);

    i_server = (globus_i_gsc_server_handle_t *) server;

    if(server == NULL)
    {
        return GLOBUS_FALSE;
    }

    return rc;
}

globus_result_t
globus_gridftp_server_control_get_buffer_size(
    globus_gridftp_server_control_op_t      op,
    globus_size_t *                         out_recv_bs,
    globus_size_t *                         out_send_bs)
{
    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_recv_bs = op->server_handle->receive_buf;
        *out_send_bs = op->server_handle->send_buf;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_parallelism(
    globus_gridftp_server_control_op_t      op,
    int *                                   out_parallelism)
{
    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_parallelism = op->server_handle->parallelism;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_mode(
    globus_gridftp_server_control_op_t      op,
    char *                                  out_mode)
{
    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_mode = op->server_handle->mode;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_type(
    globus_gridftp_server_control_op_t      op,
    char *                                  out_type)
{
    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_type = op->server_handle->type;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_cwd(
    globus_gridftp_server_control_t         server,
    char **                                 cwd_string)
{
    if(server == NULL)
    {
    }

    globus_mutex_lock(&server->mutex);
    {
        *cwd_string = globus_libc_strdup(server->cwd);
    }
    globus_mutex_unlock(&server->mutex);

    return GLOBUS_SUCCESS;
}

