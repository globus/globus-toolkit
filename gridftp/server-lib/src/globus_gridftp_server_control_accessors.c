/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */


/*
 * This file or a portion of this file is licensed under the terms of the
 * Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without modifications,
 * you must include this notice in the file.
 */

#include "globus_i_gridftp_server_control.h"
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
    GlobusGridFTPServerName(globus_gridftp_server_control_get_buffer_size);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_recv_bs = op->server_handle->opts.receive_buf;
        *out_send_bs = op->server_handle->opts.send_buf;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_layout(
    globus_gridftp_server_control_op_t      op,
    globus_gsc_layout_t *                   layout_type,
    globus_size_t *                         block_size)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_layout);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *layout_type = op->server_handle->opts.layout;
        *block_size = op->server_handle->opts.block_size;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_allocated(
    globus_gridftp_server_control_op_t      op,
    globus_off_t *                          out_allo)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_parallelism);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_allo = op->server_handle->allocated_bytes;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_parallelism(
    globus_gridftp_server_control_op_t      op,
    int *                                   out_parallelism)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_parallelism);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_parallelism = op->server_handle->opts.parallelism;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_mode(
    globus_gridftp_server_control_op_t      op,
    char *                                  out_mode)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_mode);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
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
    GlobusGridFTPServerName(globus_gridftp_server_control_get_type);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_type = op->server_handle->type;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_list_type(
    globus_gridftp_server_control_op_t      op,
    int *                                   out_type)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_list_type);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        *out_type = op->type;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_get_cwd(
    globus_gridftp_server_control_t         server,
    char **                                 cwd_string)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_cwd);

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }

    globus_mutex_lock(&server->mutex);
    {
        *cwd_string = globus_libc_strdup(server->cwd);
    }
    globus_mutex_unlock(&server->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_set_cwd(
    globus_gridftp_server_control_t         server,
    const char *                            cwd_string)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_cwd);

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }

    globus_mutex_lock(&server->mutex);
    {
        if(server->cwd)
        {
            globus_free(server->cwd);
        }
        server->cwd = strdup(cwd_string);
    }
    globus_mutex_unlock(&server->mutex);

    return GLOBUS_SUCCESS;
}


globus_result_t
globus_gridftp_server_control_get_data_auth(
    globus_gridftp_server_control_op_t      op,
    char **                                 subject,
    char *                                  dcau,
    char *                                  prot,
    gss_cred_id_t *                         del_cred)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_get_data_auth);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(subject != NULL)
        {
            if(op->server_handle->dcau_subject != NULL)
            {
                *subject = globus_libc_strdup(op->server_handle->dcau_subject);
            }
            else
            {
                *subject = NULL;
            }
        }
        if(dcau != NULL)
        {
            *dcau = op->server_handle->dcau;
        }
        if(prot != NULL)
        {
            *prot = op->server_handle->prot;
        }
        if(del_cred != NULL)
        {
            *del_cred = op->server_handle->del_cred;
        }        
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}
