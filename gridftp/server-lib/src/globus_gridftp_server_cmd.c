#include "globus_i_gridftp_server.h"

#include <stdarg.h>

/*************************************************************************
 *      Authentication functions
 *      ------------------------
 ************************************************************************/
typedef struct globus_l_gs_auth_info_s
{
    char *                                  username;
    char *                                  pw;
    gss_cred_id_t                           cred;
    gss_cred_id_t                           del_cred;
} globus_l_gs_auth_info_t;

void
globus_gridftp_server_finished_auth(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         res)
{
    globus_gridftp_server_t                 server;
    globus_l_gs_auth_info_t *               auth_info;

    server = (globus_gridftp_server_t)GlobusGridFTPServerOpGetServer(op);
    auth_info = (globus_l_gs_auth_info_t *)
        GlobusGridFTPServerOpGetUserArg(op);

    if(res == GLOBUS_SUCCESS)
    {
        res = globus_gridftp_server_set_authentication(
                server,
                auth_info->username,
                auth_info->pw,
                auth_info->cred,
                auth_info->del_cred);
    }

    if(auth_info->username != NULL)
    {
        globus_free(auth_info->username);
    }
    if(auth_info->pw != NULL)
    {
        globus_free(auth_info->pw);
    }
    globus_free(auth_info);

    globus_gridftp_server_finished_cmd(op, res, GLOBUS_TRUE);
}
/*
 *  SInce these commands are internal they can look at the 
 */
globus_result_t
globus_l_gs_cmd_auth(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    globus_list_t *                         list)
{
    globus_result_t                         res;
    globus_l_gs_auth_info_t *               auth_info;
    globus_gridftp_server_auth_callback_t   auth_cb;
    GlobusGridFTPServerName(globus_l_gs_cmd_auth);

    /*  
     *  if already authenticated simply return an error
     */
    if(globus_gridftp_server_authenticated(server))
    {
        res = GlobusGridFTPServerNotAuthenticated();
        return res;
    }

    /* this is slightly ugle, but if it doens't happen too often i would
        like to preserve this boundry */
    res = globus_gridftp_server_get_auth_cb(server, &auth_cb);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    auth_info = (globus_l_gs_auth_info_t *) globus_malloc(
        sizeof(globus_l_gs_auth_info_t));
    auth_info->username = (char *) globus_list_first(list);
    if(auth_info->username != NULL)
    {
        auth_info->username = globus_libc_strdup(auth_info->username);
    }
    list = globus_list_rest(list);

    auth_info->pw = globus_list_first(list);
    if(auth_info->pw != NULL)
    {
        auth_info->pw = globus_libc_strdup(auth_info->pw);
    }
    list = globus_list_rest(list);

    auth_info->cred = (gss_cred_id_t) globus_list_first(list);
    list = globus_list_rest(list);
    auth_info->del_cred = (gss_cred_id_t) globus_list_first(list);

    GlobusGridFTPServerOpSetUserArg(op, auth_info);
    if(auth_cb != NULL)
    {
        /* call user callback */
        auth_cb(
            op, 
            auth_info->username, 
            auth_info->pw, 
            auth_info->cred, 
            auth_info->del_cred);
    }
    else
    {
        globus_gridftp_server_finished_auth(op, GLOBUS_SUCCESS);
    }

    return GLOBUS_SUCCESS;
}

/*
 *  These are the commands that do not make calls to the user.
 *
 *  MODE
 *  TYPE
 * 
 *  Since we have unlocked we have to recheck the state.
 */
globus_result_t
globus_l_gs_simple_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    globus_list_t *                         list)
{
    globus_i_gs_server_t *                  i_server;
    int                                     ch;
    globus_i_gs_op_t *                      i_op;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gs_simple_cmd);

    i_op = (globus_i_gs_op_t *) op;
    i_server = (globus_i_gs_server_t *) server;

    ch = (int) globus_list_first(list);
    if(strcmp(command_name, "MODE") == 0)
    {
        if(ch != 'E' && ch != 'S')
        {
            res = GlobusGridFTPServerErrorParameter(command_name);
        }
        else
        {
            res = globus_gridftp_server_set_mode(server, ch);
        }
    }
    else if(strcmp(command_name, "TYPE") == 0)
    {
        if(ch != 'I' && ch != 'A')
        {
            res = GlobusGridFTPServerErrorParameter(command_name);
        }
        else
        {
            res = globus_gridftp_server_set_type(server, ch);
        }
    }
    else
    {
        globus_assert(0 && "possible memory curroption");
    }

    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_gridftp_server_finished_cmd(op, GLOBUS_SUCCESS, GLOBUS_TRUE);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/**************************************************************************
 *                  directory listing functions
 *
 *************************************************************************/
/*
 *  CWD 
 *
 *  no need to check state, we simply pass this down to user.
 */
globus_result_t
globus_l_gs_directory_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    globus_list_t *                         list)
{
    globus_i_gs_server_t *                  i_server;
    globus_result_t                         res;
    globus_i_gs_op_t *                      i_op;

    i_server = (globus_i_gs_server_t *) server;
    i_op = (globus_i_gs_op_t *) op;

    i_op->mask = (int) globus_list_first(list);
    list = globus_list_rest(list);
    i_op->str_arg = (char *) globus_list_first(list);
    globus_assert(i_op->str_arg == NULL
        && "This should not be allowed to be NULL");
    i_op->str_arg = globus_libc_strdup(i_op->str_arg);

    /*
     *  call out to user
     */
    res = i_server->resource_func(op, i_op->str_arg, i_op->mask);

    return res;
}

globus_result_t
globus_l_gs_port_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    globus_list_t *                         list)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_gs_noop_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    globus_list_t *                         list)
{
    globus_result_t                         res;

    res = globus_gridftp_server_ping(server);

    globus_gridftp_server_finished_cmd(op, res, GLOBUS_TRUE);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gs_cmd_add_builtins(
    globus_gridftp_server_attr_t            attr)
{
    globus_result_t                         res;

    res = globus_gridftp_server_attr_command_add(
            attr,
            "NOOP",
            globus_l_gs_noop_cmd,
            NULL,
            GLOBUS_FALSE,
            GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "MODE",
            globus_l_gs_simple_cmd,
            NULL,
            GLOBUS_TRUE,
            GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "TYPE",
            globus_l_gs_simple_cmd,
            NULL,
            GLOBUS_TRUE,
            GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "CWD",
            globus_l_gs_directory_cmd,
            NULL,
            GLOBUS_TRUE,
            GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "AUTH",
            globus_l_gs_cmd_auth,
            NULL,
            GLOBUS_FALSE,
            GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    return GLOBUS_SUCCESS;
}
