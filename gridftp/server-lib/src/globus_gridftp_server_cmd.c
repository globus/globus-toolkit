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

    globus_gridftp_server_finished_cmd(op, res, NULL, 0, GLOBUS_TRUE);
}
/*
 *  SInce these commands are internal they can look at the 
 */
globus_result_t
globus_l_gs_cmd_auth(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    void **                                 argv,
    int                                     argc)
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
    auth_info->username = (char *) argv[0];
    if(auth_info->username != NULL)
    {
        auth_info->username = globus_libc_strdup(auth_info->username);
    }

    auth_info->pw = argv[1];
    if(auth_info->pw != NULL)
    {
        auth_info->pw = globus_libc_strdup(auth_info->pw);
    }

    auth_info->cred = (gss_cred_id_t) argv[2];
    auth_info->del_cred = (gss_cred_id_t) argv[3];

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
    void **                                 argv,
    int                                     argc)
{
    globus_i_gs_server_t *                  i_server;
    int                                     ch;
    globus_i_gs_op_t *                      i_op;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gs_simple_cmd);

    i_op = (globus_i_gs_op_t *) op;
    i_server = (globus_i_gs_server_t *) server;

    ch = (int) argv[0];
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

    globus_gridftp_server_finished_cmd(
        op, GLOBUS_SUCCESS, NULL, 0, GLOBUS_TRUE);

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
    void **                                 argv,
    int                                     argc)
{
    globus_i_gs_server_t *                  i_server;
    globus_result_t                         res;
    globus_i_gs_op_t *                      i_op;

    i_server = (globus_i_gs_server_t *) server;
    i_op = (globus_i_gs_op_t *) op;

    i_op->mask = (int) argv[0];
    i_op->str_arg = (char *) argv[1];
    globus_assert(i_op->str_arg == NULL
        && "This should not be allowed to be NULL");
    i_op->str_arg = globus_libc_strdup(i_op->str_arg);

    /*
     *  call out to user
     */
    res = i_server->resource_func(op, i_op->str_arg, i_op->mask);

    return res;
}

/*
 *  stat a file
 */
void
globus_gridftp_server_finished_resource(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         result,
    globus_gridftp_server_stat_t *          stat_info_array,
    int                                     stat_count)
{
    void *                                  argv[2];

    argv[0] = stat_info_array;
    argv[1] = stat_count;

    globus_gridftp_server_finished_cmd(op, result, argv, 2, GLOBUS_TRUE);
}

globus_result_t
globus_l_gs_stat_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    void **                                 argv,
    int                                     argc)
{
    globus_i_gs_server_t *                  i_server;
    char *                                  filename;
    int                                     mask;
    globus_gridftp_server_resource_func_t   resource_cb;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gs_stat_cmd);

    i_server = (globus_i_gs_server_t *) server;

    filename = (char *) argv[0];
    mask = (int) argv[1];

    globus_gridftp_server_get_resource_cb(server, &resource_cb);

    if(resource_cb != NULL)
    {
        resource_cb(op, filename, mask);
    }
    else
    {
        res = GlobusGridFTPServerNotACommand();
        globus_gridftp_server_finished_cmd(op, res, NULL, 0, GLOBUS_TRUE);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_gs_port_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    void **                                 argv,
    int                                     argc)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_gs_noop_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    void **                                 argv,
    int                                     argc)
{
    globus_result_t                         res;

    res = globus_gridftp_server_ping(server);

    globus_gridftp_server_finished_cmd(op, res, NULL, 0, GLOBUS_TRUE);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_gs_quit_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    void **                                 argv,
    int                                     argc)
{
    globus_gridftp_server_finished_cmd(
        op, GLOBUS_SUCCESS, NULL, 0, GLOBUS_TRUE);

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
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "MODE",
            globus_l_gs_simple_cmd,
            NULL,
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "STAT",
            globus_l_gs_stat_cmd,
            NULL,
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "TYPE",
            globus_l_gs_simple_cmd,
            NULL,
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "CWD",
            globus_l_gs_directory_cmd,
            NULL,
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_gridftp_server_attr_command_add(
            attr,
            "AUTH",
            globus_l_gs_cmd_auth,
            NULL,
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_PRE_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    res = globus_gridftp_server_attr_command_add(
            attr,
            "QUIT",
            globus_l_gs_quit_cmd,
            NULL,
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_PRE_AUTH |
            GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH |
                GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    return GLOBUS_SUCCESS;
}
