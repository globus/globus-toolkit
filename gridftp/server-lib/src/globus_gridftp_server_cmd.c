#include "globus_i_gridftp_server.h"

#include <stdarg.h>

/*
 *  local command types.  Set in command structure to make decisions on
 *  that commadn is what easier.
 */
enum
{
    GLOBUS_L_GS_COMMAND_MODE,
    GLOBUS_L_GS_COMMAND_TYPE,
    GLOBUS_L_GS_COMMAND_CWD,
};


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
    va_list                                 ap)
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
    auth_info->username = va_arg(ap, char *);
    if(auth_info->username != NULL)
    {
        auth_info->username = globus_libc_strdup(auth_info->username);
    }
    auth_info->pw = va_arg(ap, char *);
    if(auth_info->pw != NULL)
    {
        auth_info->pw = globus_libc_strdup(auth_info->pw);
    }

    auth_info->cred = (gss_cred_id_t) va_arg(ap, gss_cred_id_t);
    auth_info->del_cred = (gss_cred_id_t) va_arg(ap, gss_cred_id_t);

    GlobusGridFTPServerOpSetUserArg(op, auth_info);
    /* call user callback */
    auth_cb(
        op, 
        auth_info->username, 
        auth_info->pw, 
        auth_info->cred, 
        auth_info->del_cred);

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
    va_list                                 ap)
{
    globus_i_gs_server_t *                  i_server;
    globus_i_gs_cmd_ent_t *                 cmd_ent;
    int                                     ch;
    globus_i_gs_op_t *                      i_op;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gs_simple_cmd);

    i_op = (globus_i_gs_op_t *) op;
    i_server = (globus_i_gs_server_t *) server;
    cmd_ent = i_op->cmd_ent;

    switch(cmd_ent->type)
    {
        case GLOBUS_L_GS_COMMAND_MODE:
            ch = (int) va_arg(ap, int);
            if(ch != 'E' && ch != 'S')
            {
                res = GlobusGridFTPServerErrorParameter("mode");
            }
            else
            {
                res = globus_gridftp_server_set_mode(server, ch);
            }

            break;

        case GLOBUS_L_GS_COMMAND_TYPE:
            ch = (int) va_arg(ap, int);
            if(ch != 'A' && ch != 'I')
            {
                res = GlobusGridFTPServerErrorParameter("type");
            }
            else
            {
                res = globus_gridftp_server_set_type(server, ch);
            }
            break;

        default:
            globus_assert(0 && "possible memory corrupiton");
            break;
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
    va_list                                 ap)
{
    globus_i_gs_server_t *                  i_server;
    globus_result_t                         res;
    globus_i_gs_op_t *                      i_op;

    i_server = (globus_i_gs_server_t *) server;
    i_op = (globus_i_gs_op_t *) op;

    i_op->mask = (int) va_arg(ap, int);
    i_op->str_arg = (char *) va_arg(ap, char *);
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
 *  user calls back in when stat is finished.
 */
void
globus_gridftp_server_finished_resource(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         result,
    globus_gridftp_server_stat_t *          stat_info_array,
    int                                     stat_count)
{
    globus_result_t                         res;
    va_list                                 ap;
    globus_i_gs_server_t *                  i_server;
    globus_i_gs_cmd_ent_t *                 cmd_ent;
    char *                                  tmp_s;
    char **                                 out_string;
    globus_i_gs_op_t *                      i_op;
    GlobusGridFTPServerName(globus_gridftp_server_finished_resource);

    i_op = (globus_i_gs_op_t *) op;
    i_server = i_op->server;
    cmd_ent = i_op->cmd_ent;

    switch(cmd_ent->type)
    {
        case GLOBUS_L_GS_COMMAND_CWD:
            if(result != GLOBUS_SUCCESS || stat_count < 1)
            {
                res = GlobusGridFTPServerErrorParameter("out_string");
            }
            else
            {
                out_string = (char **) va_arg(ap, char **);
                /* allow the user to get away with pushing in multiple
                    stats by only looking at the first one */
                if(!S_ISDIR(stat_info_array[0].st_rdev))
                {
                    *out_string = NULL;
                    res = GlobusGridFTPServerErrorParameter("out_string");
                }
                else
                {
                    tmp_s = i_server->pwd;
                    i_server->pwd = 
                        globus_common_create_string(
                            "%s/%s", tmp_s, i_op->str_arg);
                    globus_free(tmp_s);
                    *out_string = i_server->pwd;
                }
            }
            break;

        default:
            globus_assert(0 && "Possible memory cooruption.");
            break;
    }
    globus_gridftp_server_finished_cmd(op, res, GLOBUS_TRUE);
}

globus_result_t
globus_l_gs_noop_cmd(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    va_list                                 ap)
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
            GLOBUS_TRUE,
            GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    return GLOBUS_SUCCESS;
}
