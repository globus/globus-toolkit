#include "globus_gridftp_server_control_pmod_959.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server_control.h"
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 *  These commands will only come in one at a time
 */

typedef struct globus_l_gsc_pmod_959_cmd_handle_s
{
    char *                                          username;
    globus_gsc_pmod_959_handle_t                    handle_959;
    globus_size_t                                   send_window;
    globus_size_t                                   receive_window;
    globus_size_t                                   packet_size;
    int                                             parallelism;

    int                                             opts_dc_parsing_alg;

    globus_bool_t                                   delayed_passive;
    globus_bool_t                                   opts_delayed_passive;
    globus_bool_t                                   passive_only;
    int                                             opts_pasv_max;
    globus_gridftp_server_control_network_protocol_t opts_pasv_prt;

    int                                             opts_port_max;
    globus_gridftp_server_control_network_protocol_t opts_port_prt;

} globus_l_gsc_pmod_959_cmd_handle_t;


typedef struct globus_l_gsc_pmod_959_cmd_wrapper_s
{
    globus_gridftp_server_control_t                 server;
    globus_gsc_pmod_959_op_t                        op;
    char *                                          strarg;
    char *                                          mod_name;
    char *                                          mod_parms;
    char *                                          path;
    char                                            cmd[8]; /* only need 5 */
    globus_l_gsc_pmod_959_cmd_handle_t *            handle;
    int                                             cmd_ndx;

    globus_bool_t                                   transfer_flag;
    int                                             dc_parsing_alg;
    int                                             max;
    globus_gridftp_server_control_network_protocol_t prt;

    char **                                         cs;
    int                                             cs_count;
    int                                             reply_code;
} globus_l_gsc_pmod_959_cmd_wrapper_t;

char *
globus_l_gs_pmod_959_ls_line(
    globus_gridftp_server_control_stat_t *          stat_info,
    char *                                          path);


static void
globus_l_gsc_pmod_959_transfer(
    globus_l_gsc_pmod_959_cmd_wrapper_t *           wrapper);

/*
 *  only used with send and receive, aborts a transfer
 */
static void
globus_l_gsc_pmod_959_cmd_abort_cb(
    globus_gsc_pmod_959_op_t                        op,
    void *                                          user_arg)
{
}

/*************************************************************************
 *                      simple commands
 *                      ---------------
 ************************************************************************/
/*
 *  simply pings the control channel
 */
static void
globus_l_gsc_pmod_959_cmd_noop(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_gridftp_server_control_ping(server);

    globus_gsc_pmod_959_finished_op(op, "200 NOOP command successful.\r\n");
}

/*
 *  mode
 */
static void
globus_l_gsc_pmod_959_cmd_mode(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    char *                                  msg;
    globus_result_t                         res;
    char                                    ch;
    int                                     sc;

    sc = sscanf(full_command, "%*s %c", &ch);

    if(sc != 1)
    {
        msg = globus_common_create_string(
            "500 '%s' unrecognized command.\r\n", full_command);
    }
    else
    {
        res = globus_gridftp_server_control_set_mode(server, ch);
        if(res == GLOBUS_SUCCESS)
        {
            msg = globus_common_create_string("200 Mode set to %c.\r\n", ch);
        }
        else
        {
            msg = globus_common_create_string(
                "501 '%s' unrecognized transfer mode.\r\n", full_command);
        }
    }
    globus_gsc_pmod_959_finished_op(op, msg);

    globus_free(msg);
}

/*
 *  type
 */
static void
globus_l_gsc_pmod_959_cmd_type(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    char                                    ch;
    int                                     sc;
    char *                                  msg;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_type);

    sc = sscanf(full_command, "%*s %c", &ch);

    if(sc != 1)
    {
        msg = globus_common_create_string(
            "500 '%s' unrecognized command.\r\n", full_command);
    }
    else
    {
        res = globus_gridftp_server_control_set_type(server, ch);
        if(res == GLOBUS_SUCCESS)
        {
            msg = globus_common_create_string("200 Type set to %c.\r\n", ch);
        }
        else
        {
            msg = globus_common_create_string(
                "501 '%s' unrecognized type.\r\n", full_command);
        }
    }
    if(msg == NULL)
    {
        goto err;
    }

    globus_gsc_pmod_959_finished_op(op, msg);

    globus_free(msg);

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*************************************************************************
 *                      directory functions
 *                      -------------------
 ************************************************************************/
/*
 *  PWD
 */
static void
globus_l_gsc_pmod_959_cmd_pwd(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    char *                                  msg;
    char *                                  pwd;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_pwd);

    res = globus_gridftp_server_control_get_cwd(server, &pwd);
    if(res == GLOBUS_SUCCESS)
    {
        msg = globus_common_create_string(
            "257 \"%s\" is current directory.\r\n", pwd);
    }
    else
    {
        msg = globus_common_create_string("550 Error getting pwd.\r\n");
    }
    if(msg == NULL)
    {
        goto err;
    }

    globus_gsc_pmod_959_finished_op(op, msg);

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 *  CWD
 */
static void
globus_l_gsc_pmod_959_cmd_cwd_cb(
    globus_gridftp_server_control_t         server,
    globus_result_t                         result,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count,
    void *                                  user_arg)
{
    globus_result_t                         res;
    char *                                  path;
    char *                                  msg;
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper;
    uid_t                                   uid;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_cwd_cb);

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    /*
     *  decide what message to send
     */
    if(result != GLOBUS_SUCCESS || stat_count < 1)
    {
        msg = globus_common_create_string(
            "550 %s: Could not change directory.\r\n",
            path);
    }
    else if(!S_ISDIR(stat_info->mode))
    {
        msg = globus_common_create_string(
            "550 %s: Not a directory.\r\n",
            path);
    }
    else
    {
        res = globus_gridftp_server_control_get_client_id(server, &uid);
        if(res != GLOBUS_SUCCESS)
        {
            msg = globus_common_create_string(
                "550 %s: Could not change directory.\r\n",
                path);
        }
        /* TODO: deal with groups */
        else if(
            !(S_IXOTH & stat_info->mode && S_IROTH & stat_info->mode) &&
            !(stat_info->uid == uid && 
                S_IXUSR & stat_info->mode && S_IRUSR & stat_info->mode))
        {
            msg = globus_common_create_string(
                "550 %s: Permission denied\r\n",
                path);
        }
        else
        {
            path = wrapper->strarg;
            res = globus_gridftp_server_control_set_cwd(server, path);
            if(res != GLOBUS_SUCCESS)
            {
                msg = globus_common_create_string(
                    "550 %s: Could not change directory.\r\n",
                    path);
            }
            else
            {
                msg = globus_libc_strdup("250 CWD command successful.\r\n");
            }
        }
    }
    if(msg == NULL)
    {
        goto err;
    }

    globus_gsc_pmod_959_finished_op(wrapper->op, msg);
    globus_free(wrapper);
    globus_free(wrapper->strarg);
    globus_free(msg);

    return;

  err:
    globus_gsc_959_panic(
        wrapper->op, GlobusGridFTPServerErrorMemory("message"));

    if(wrapper->strarg != NULL)
    {
        globus_free(wrapper->strarg);
    }
    if(msg != NULL)
    {
        globus_free(msg);
    }
    globus_free(wrapper);
}

static void
globus_l_gsc_pmod_959_cmd_cwd(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    globus_result_t                         res;
    int                                     sc;
    int                                     mask = 0;
    char *                                  path = NULL;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_cwd);

    if(strcmp(command_name, "CDUP") == 0)
    {
        path = globus_libc_strdup("..");
        if(path == NULL)
        {
            goto err;
        }
    }
    else
    {
        path = globus_malloc(strlen(full_command));
        if(path == NULL)
        {
            goto err;
        }
        sc = sscanf(full_command, "%*s %s", path);
        if(sc != 1)
        {
            globus_gsc_pmod_959_finished_op(wrapper->op, 
                "501 Syntax error in parameters or arguments.\r\n");
            globus_free(path);
            return;
        }
    }

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
    if(wrapper == NULL)
    {
        goto err;
    }
    wrapper->op = op;
    wrapper->strarg = path;

    res = globus_gridftp_server_control_pmod_stat(
            server,
            path,
            mask,
            globus_l_gsc_pmod_959_cmd_cwd_cb,
            wrapper);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
    if(path != NULL)
    {
        globus_free(path);
    }
    if(wrapper != NULL)
    {
        globus_free(wrapper);
    }
}

/*
 *  STAT
 */
static void
globus_l_gsc_pmod_959_cmd_stat_cb(
    globus_gridftp_server_control_t         server,
    globus_result_t                         result,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count,
    void *                                  user_arg)
{
    char *                                  path;
    globus_size_t                           msg_size;
    globus_size_t                           msg_ndx = 0;
    char *                                  msg;
    char *                                  tmp_ptr;
    char *                                  tmp_ptr2;
    int                                     ctr;
    char *                                  end_tok = "213 End of Status\r\n";
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_stat_cb);

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        msg = globus_libc_strdup("500 Command failed\r\n");
    }
    else
    {
        path = wrapper->strarg;

        msg_size = (stat_count + 2) * 80;
        msg = globus_malloc(msg_size);
        if(msg == NULL)
        {
            goto err;
        }

        sprintf(msg, "213-status of %s\r\n", path);

        for(ctr = 0; ctr < stat_count; ctr++)
        {
            tmp_ptr = globus_l_gs_pmod_959_ls_line(&stat_info[ctr], path);
            if(msg_ndx + strlen(tmp_ptr) > msg_size)
            {
                msg_size = (msg_size + strlen(tmp_ptr)) * 2;
                tmp_ptr2 = globus_libc_realloc(msg, msg_size);
                if(tmp_ptr2 == NULL)
                {
                    goto err;
                }
                msg = tmp_ptr2;
            }

            strcat(msg, tmp_ptr);
            msg_ndx += strlen(tmp_ptr);
            globus_free(tmp_ptr);
        }

        if(msg_ndx + sizeof(end_tok) > msg_size)
        {
            msg_size *= 2;
            msg = globus_libc_realloc(msg, msg_size);
            if(tmp_ptr2 == NULL)
            {
                goto err;
            }
            msg = tmp_ptr2;
        } 
        strcat(msg, end_tok);
    }

    globus_gsc_pmod_959_finished_op(wrapper->op, msg);
    if(stat_info != NULL)
    {
        globus_free(stat_info);
    }
    globus_free(wrapper);
    globus_free(wrapper->strarg);
    globus_free(msg);

    return;

  err:
    globus_gsc_959_panic(
        wrapper->op, GlobusGridFTPServerErrorMemory("message"));
    if(stat_info != NULL)
    {
        globus_free(stat_info);
    }
    globus_free(wrapper);
    globus_free(wrapper->strarg);
    if(msg != NULL)
    {
        globus_free(msg);
    }
}

static void
globus_l_gsc_pmod_959_cmd_stat(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    /* these are really just place holders in the list */
    char *                                  path = NULL;
    int                                     mask = 0;
    int                                     sc;
    char *                                  status;
    char *                                  msg = NULL;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_stat);

    path = (char *) globus_malloc(strlen(full_command));
    if(path == NULL)
    {
        goto err;
    }

    sc = sscanf(full_command, "%*s %s", path);
    if(sc < 1)
    {
        globus_free(path);
        path = NULL;
    }
    if(path == NULL)
    {
        res = globus_gridftp_server_control_get_status(server, &status);
        if(res != GLOBUS_SUCCESS)
        {
            msg = globus_libc_strdup("550 Command Failed.\r\n");
        }
        else
        {
            msg = globus_common_create_string(
                    "212 %s\r\n",
                    status);
        }
        if(msg == NULL)
        {
            goto err;
        }
        globus_gsc_pmod_959_finished_op(wrapper->op, msg);
        globus_free(msg);
    }
    else
    {
        wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
            sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
        if(wrapper == NULL)
        {
            goto err;
        }
        wrapper->op = op;
        wrapper->strarg = path;

        res = globus_gridftp_server_control_pmod_stat(
                server,
                path,
                mask,
                globus_l_gsc_pmod_959_cmd_stat_cb,
                wrapper);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    return;

  err:
    if(wrapper != NULL)
    {
        globus_free(wrapper);
    }
    if(path != NULL)
    {
        globus_free(path);
    }
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 *  size and mdtm
 */
static void
globus_l_gsc_pmod_959_cmd_size_cb(
    globus_gridftp_server_control_t         server,
    globus_result_t                         result,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper;
    char *                                  path = NULL;
    char *                                  msg = NULL;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_size_cb);

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    if(result != GLOBUS_SUCCESS || stat_info == NULL)
    {
        msg = globus_libc_strdup("550 Command failed\r\n");
    }
    else
    {
        path = wrapper->strarg;

        /* stat count should only be 1, but this is hard to insist upon */
        if(strcmp(wrapper->cmd, "SIZE") == 0)
        {
            msg = globus_common_create_string("213 %d\r\n", stat_info->size);
        }
        else if(strcmp(wrapper->cmd, "MDTM") == 0)
        {
            if(!S_ISREG(stat_info->mode))
            {
                msg = globus_common_create_string(
                    "550 %s is not retrievable.\r\n", path);
            }
            else
            {
                msg = globus_common_create_string(
                    "213 %ld\r\n", stat_info->mtime);
            }
        }
        else
        {
            globus_assert(GLOBUS_FALSE);
        }
    }
    if(msg == NULL)
    {
        goto err;
    }
    globus_gsc_pmod_959_finished_op(wrapper->op, msg);

    globus_free(wrapper);
    globus_free(wrapper->strarg);
    globus_free(msg);

  err:
    globus_gsc_959_panic(
        wrapper->op, GlobusGridFTPServerErrorMemory("message"));
    globus_free(wrapper->strarg);
    globus_free(wrapper);
    if(msg != NULL)
    {
        globus_free(msg);
    }
}

static void
globus_l_gsc_pmod_959_cmd_size(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    /* these are really just place holders in the list */
    char *                                  path = NULL;
    int                                     mask = 0;
    int                                     sc;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_size);

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
    if(wrapper == NULL)
    {
        goto err;
    }
    path = (char *) globus_malloc(strlen(full_command));
    if(path == NULL)
    {
        goto err;
    }
    sc = sscanf(full_command, "%s %s", wrapper->cmd, path);
    if(sc < 2)
    {
        goto err;
    }
    wrapper->op = op;
    wrapper->strarg = path;

    res = globus_gridftp_server_control_pmod_stat(
            server,
            path,
            mask,
            globus_l_gsc_pmod_959_cmd_size_cb,
            wrapper);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return;

  err:
    if(wrapper != NULL)
    {
        globus_free(wrapper);
    }
    if(path != NULL)
    {
        globus_free(path);
    }
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 *  quit
 */
static void
globus_l_gsc_pmod_959_cmd_quit(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_gsc_pmod_959_finished_op(op, "221 Goodbye\r\n");

    globus_gridftp_server_control_pmod_done(
        server,
        GLOBUS_SUCCESS);
}

/*************************************************************************
 *                      authentication commands
 *                      -----------------------
 ************************************************************************/
/*
 *   USER
 */
static void
globus_l_gsc_pmod_959_cmd_user(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    char *                                  msg;
    int                                     sc;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_user);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    if(cmd_handle->username != NULL)
    {
        globus_free(cmd_handle->username);
    }
    cmd_handle->username = globus_malloc(strlen(full_command));
    if(cmd_handle->username == NULL)
    {
        goto err;
    }
    sc = sscanf(full_command, "%*s %s", cmd_handle->username);
    if(sc == 1)
    {
        msg = globus_common_create_string(
            "331 Password required for %s.\r\n", cmd_handle->username);
    }
    else
    {
        globus_free(cmd_handle->username);
        cmd_handle->username = NULL;
        msg = globus_common_create_string(
            "500 \'USER\': command requires a parameter.\r\n");
    }

    globus_gsc_pmod_959_finished_op(op, msg);
    globus_free(msg);

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

static void
globus_l_gsc_pmod_959_auth_cb(
    globus_gridftp_server_control_t         server,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper;
    char *                                  msg;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    if(result == GLOBUS_SUCCESS)
    {
        msg = globus_common_create_string(
            "230 User %s logged in, proceed.\r\n", wrapper->handle->username);
        globus_free(wrapper->handle->username);
        wrapper->handle->username = NULL;
    }
    else
    {
        msg = globus_common_create_string("530 Login incorrect.\r\n");
    }
    globus_gsc_pmod_959_finished_op(wrapper->op, msg);

    globus_free(msg);
    globus_free(wrapper);
}

/*
 *  pass
 */
static void
globus_l_gsc_pmod_959_cmd_pass(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    char *                                  pass = NULL;
    char *                                  msg = NULL;
    gss_cred_id_t                           cred;
    gss_cred_id_t                           del_cred;
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    int                                     sc;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_pass);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    /*
     *  if user name has not yet been supplied return error message
     */
    if(cmd_handle->username == NULL)
    {
        msg = "503 Login with USER first.\r\n";
        globus_gsc_pmod_959_finished_op(wrapper->op, msg);
    }
    else
    {
        res = globus_gsc_pmod_959_get_cred(op, &cred, &del_cred);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }

        pass = globus_malloc(strlen(full_command));
        if(pass == NULL)
        {
            goto err;
        }
        sc = sscanf(full_command, "%*s %s", pass);
        if(sc != 1)
        {
            msg = "503 Login with USER first.\r\n";
            globus_gsc_pmod_959_finished_op(wrapper->op, msg);
        }
        else
        {
            wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
                sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
            if(wrapper == NULL)
            {
                goto err;
            }
            wrapper->op = op;
            wrapper->handle = cmd_handle;

            res = globus_gridftp_server_control_pmod_authenticate(
                server,
                cmd_handle->username,
                pass,
                cred,
                del_cred,
                globus_l_gsc_pmod_959_auth_cb,
                wrapper);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
        globus_free(pass);
    }

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
    if(pass != NULL)
    {
        globus_free(pass);
    }
    if(wrapper != NULL)
    {
        globus_free(wrapper);
    }
}

/*
 *  syst
 */
static void
globus_l_gsc_pmod_959_cmd_syst(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_result_t                         res;
    char *                                  msg;
    char *                                  tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_syst);

    res = globus_gridftp_server_control_get_system(
        server,
        &tmp_ptr);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    msg = globus_common_create_string("215 %s\r\n", tmp_ptr);
    if(msg == NULL)
    {
        goto err;
    }
    globus_gsc_pmod_959_finished_op(op, msg);
    globus_free(tmp_ptr);
    globus_free(msg);

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 *  help
 */
static void
globus_l_gsc_pmod_959_cmd_help(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    int                                     sc;
    int                                     ctr;
    char *                                  arg;
    char *                                  msg;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_help);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    arg = globus_malloc(strlen(full_command));
    sc = sscanf(full_command, "%*s %s", arg);
    /* general help */
    if(sc < 1)
    {
        globus_free(arg);
        arg = NULL;
    }
    else
    {
        for(ctr = 0; ctr < strlen(arg); ctr++)
        {
            arg[ctr] = toupper(arg[ctr]);
        }
    }

    msg = globus_gsc_pmod_959_get_help(cmd_handle->handle_959, arg);
    if(msg == NULL)
    {
        goto err;
    }

    globus_gsc_pmod_959_finished_op(op, msg);
    globus_free(msg);

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 * opts
 */
static void
globus_l_gsc_pmod_959_cmd_opts(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    char *                                  opts_type = NULL;
    int                                     tmp_i;
    int                                     sc;
    char *                                  msg;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_opts);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    opts_type = globus_malloc(strlen(full_command));
    if(opts_type == NULL)
    {
        goto err;
    }
    sc = sscanf(full_command, "%*s %s", opts_type);
    if(sc != 1)
    {
        msg = "500 OPTS failed.\r\n";
    }
    else if(strcmp("RETR", opts_type) == 0)
    {
        msg = "200 OPTS Command Successful.\r\n";
        if(sscanf(full_command, "%*s %*s Parallelism=%d,%*d,%*d;", &tmp_i)==1)
        {
            cmd_handle->parallelism = tmp_i;
        }
        else if(
            sscanf(full_command, "%*s %*s PacketSize=%d;", &tmp_i) == 1)
        {
            cmd_handle->packet_size = tmp_i;
        }
        else if(
            sscanf(full_command, "%*s %*s WindowSize=%d;", &tmp_i) == 1)
        {
            cmd_handle->send_window = tmp_i;
        }
        else
        {
            msg = "500 OPTS failed.\r\n";
        }
    }
    else if(strcmp("PASV", opts_type) == 0 || strcmp("SPAS", opts_type) == 0)
    {
        msg = "200 OPTS Command Successful.\r\n";
        sc = sscanf(full_command, "%*s %*s AllowDelayed=%d", &tmp_i);
        if(sscanf(full_command, "%*s %*s AllowDelayed=%d", &tmp_i) == 1)
        {
            /* of coures i realize this could be optimized, but i am try
               to use the proper abstractions */
            if(tmp_i == 0)
            {
                cmd_handle->opts_delayed_passive = GLOBUS_FALSE;
            }
            else
            {
                cmd_handle->opts_delayed_passive = GLOBUS_TRUE;
            }
        }
        else if(sscanf(full_command, "%*s %*s DefaultProto=%d", &tmp_i) == 1)
        {
            if(tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4 ||
                tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
            {
                cmd_handle->opts_pasv_prt = tmp_i;
            }
            else
            {
                msg = "500 OPTS failed.\r\n";
            }
            
        }
        else if(sscanf(full_command, "%*s %*s DefaultStripes=%d", &tmp_i) == 1)
        {
            cmd_handle->opts_pasv_max = tmp_i;
        }
        else if(sscanf(full_command, "%*s %*s ParsingAlgrythm=%d", &tmp_i) == 1)
        {
            if(tmp_i == 0 || tmp_i == 1)
            {
                cmd_handle->opts_dc_parsing_alg = tmp_i;
            }
            else
            {
                msg = "500 OPTS failed.\r\n";
            }
        }
        else
        {
            msg = "500 OPTS failed.\r\n";
        }
    }
    else if(strcmp("PORT", opts_type) == 0 || strcmp("SPOR", opts_type) == 0)
    {
        msg = "200 OPTS Command Successful.\r\n";
        if(sscanf(full_command, "%*s %*s DefaultProto=%d", &tmp_i) == 1)
        {
            if(tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4 ||
                tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
            {
                cmd_handle->opts_port_prt = tmp_i;
            }
            else
            {
                msg = "500 OPTS failed.\r\n";
            }
            
        }
        else if(sscanf(full_command, "%*s %*s DefaultStripes=%d", &tmp_i) == 1)
        {
            cmd_handle->opts_port_max = tmp_i;
        }
        else if(sscanf(full_command, "%*s %*s ParsingAlgrythm=%d", &tmp_i) == 1)
        {
            if(tmp_i == 0 || tmp_i == 1)
            {
                cmd_handle->opts_dc_parsing_alg = tmp_i;
            }
            else
            {
                msg = "500 OPTS failed.\r\n";
            }
        }
        else
        {
            msg = "500 OPTS failed.\r\n";
        }
    }

    globus_gsc_pmod_959_finished_op(op, msg);
    globus_free(opts_type);

    return;

  err:
    if(opts_type != NULL)
    {
        globus_free(opts_type);
    }

    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 *
 */
static void
globus_l_gsc_pmod_959_cmd_sbuf(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    int                                     sc;
    int                                     tmp_i;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_sbuf);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    sc = sscanf(full_command, "%*s %d", &tmp_i);
    if(sc != 1)
    {
        goto err;
    }
    cmd_handle->send_window = tmp_i;
    cmd_handle->receive_window = tmp_i;

    globus_gsc_pmod_959_finished_op(op, "200 SBUF Command Successful.\r\n");

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*
 *
 */
static void
globus_l_gsc_pmod_959_cmd_site(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    char *                                  site_type = NULL;
    char *                                  msg;
    int                                     tmp_i;
    int                                     sc;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_site);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    site_type = (char *) globus_malloc(strlen(full_command));
    if(site_type == NULL)
    {
        goto err;
    }

    msg = "200 Site Command Successful.\r\n";
    sc = sscanf(full_command, "%*s %s %d", site_type, &tmp_i);
    if(sc != 2)
    {
        msg = "500 Invalid Command.\r\n";
    }
    else if(strcmp(site_type, "BUFSIZE") == 0 ||
       strcmp(site_type, "SBUF") == 0)
    {
        cmd_handle->send_window = tmp_i;
        cmd_handle->receive_window = tmp_i;
    }
    else if(strcmp(site_type, "RETRBUFSIZE") == 0 ||
            strcmp(site_type, "RBUFSZ") == 0 ||
            strcmp(site_type, "RBUFSIZ") == 0)
    {
        cmd_handle->receive_window = tmp_i;
    }
    else if(strcmp(site_type, "STORBUFSIZE") == 0 ||
            strcmp(site_type, "SBUFSZ") == 0 ||
            strcmp(site_type, "SBUFSIZ") == 0)
    {
        cmd_handle->send_window = tmp_i;
    }
    else
    {
        msg = "500 Invalid Command.\r\n";
    }

    globus_gsc_pmod_959_finished_op(op, msg);
    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*************************************************************************
 *                  data connection esstablishement
 *                  -------------------------------
 ************************************************************************/
static void
globus_l_gsc_pmod_959_cmd_pasv_cb(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    const char **                                   cs,
    int                                             addr_count,
    void *                                          user_arg)
{
    int                                             ctr;
    char *                                          tmp_ptr;
    char *                                          host;
    int                                             host_ip[4];
    int                                             port;
    int                                             sc;
    int                                             hi;
    int                                             low;
    char *                                          msg = NULL;
    globus_l_gsc_pmod_959_cmd_handle_t *            cmd_handle;
    globus_l_gsc_pmod_959_cmd_wrapper_t *           wrapper;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_pasv_cb);

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    cmd_handle = wrapper->handle;

    if(res != GLOBUS_SUCCESS)
    {
        globus_gsc_pmod_959_finished_op(wrapper->op, "500 Command failed.\r\n");
    }
    else if(addr_count > wrapper->max && wrapper->max != -1)
    {
        globus_gsc_pmod_959_finished_op(wrapper->op, "500 Command failed.\r\n");
    }
    else
    {
        if(wrapper->dc_parsing_alg == 0)
        {
            if(wrapper->cmd_ndx == 1)
            {
                sc = sscanf(cs[0], " %d.%d.%d.%d:%d",
                    &host_ip[0],
                    &host_ip[1],
                    &host_ip[2],
                    &host_ip[3],
                    &port);
                globus_assert(sc == 5);
                hi = port / 256;
                low = port % 256;

                msg = globus_common_create_string(
                    "%d Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
                        wrapper->reply_code,
                        host_ip[0],
                        host_ip[1],
                        host_ip[2],
                        host_ip[3],
                        hi,
                        low);
            }
            else
            {
                msg =  globus_common_create_string(
                    "%d-Entering Striped Passive Mode.\r\n", 
                    wrapper->reply_code);
                for(ctr = 0; ctr < addr_count; ctr++)
                {
                    sc = sscanf(cs[ctr], " %d.%d.%d.%d:%d",
                        &host_ip[0],
                        &host_ip[1],
                        &host_ip[2],
                        &host_ip[3],
                        &port);
                    globus_assert(sc == 5);
                    hi = port / 256;
                    low = port % 256;

                    tmp_ptr = globus_common_create_string(
                        "%s %d,%d,%d,%d,%d,%d\r\n",
                        msg,
                        host_ip[0],
                        host_ip[1],
                        host_ip[2],
                        host_ip[3],
                        hi,
                        low);
                    if(tmp_ptr == NULL)
                    {
                        goto err;
                    }
                    globus_free(msg);
                    msg = tmp_ptr;
                }
                tmp_ptr = globus_common_create_string("%s%d End\r\n", 
                    wrapper->reply_code, msg);
                if(tmp_ptr == NULL)
                {
                    goto err;
                }
                globus_free(msg);
                msg = tmp_ptr;
            }
        }
        else if(wrapper->dc_parsing_alg == 1)
        {
            msg =  globus_common_create_string(
                "%d-Entering Striped Passive Mode.\r\n", wrapper->reply_code);
            for(ctr = 0; ctr < addr_count; ctr++)
            {
                switch(wrapper->prt)
                {
                    case GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4:
                        sc = sscanf(cs[ctr], "%d.%d.%d.%d:%d",
                            &host_ip[0], &host_ip[1], &host_ip[2], &host_ip[3],
                            &port);
                        globus_assert(sc == 5);
                        tmp_ptr = globus_common_create_string(
                            "%s |%d|%d.%d.%d.%d|%d|\r\n", msg,
                            wrapper->prt, 
                            host_ip[0], host_ip[1], host_ip[2], host_ip[3],
                            port);
                        msg = tmp_ptr;
                        break;
                
                    case GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6:
                        host = globus_malloc(strlen(cs[ctr]));
                        sc = sscanf(cs[ctr], "[%s]:%d", host, &port);
                        globus_assert(sc == 2);

                        tmp_ptr = globus_common_create_string(
                            " |%s|%d|%s|%d|\r\n", msg,
                            wrapper->prt, host, port);
                        globus_free(host);
                        globus_free(msg);
                        msg = tmp_ptr;
                        break;
                
                    default:
                        globus_assert(GLOBUS_FALSE);
                        break;
                }
                if(tmp_ptr == NULL)
                {
                    goto err;
                }
            }
            tmp_ptr = globus_common_create_string(
                "%s%d End\r\n", msg, wrapper->reply_code);
            if(tmp_ptr == NULL)
            {
                goto err;
            }
            globus_free(msg);
            msg = tmp_ptr;
        }
        else
        {
            globus_assert(GLOBUS_FALSE);
        }
    }

    /* if we were in delayed passive mode we start transfer now */
    if(wrapper->transfer_flag)
    {
        globus_gsc_pmod_959_intermediate_reply(wrapper->op, msg);
        globus_l_gsc_pmod_959_transfer(wrapper);
    }
    else
    {
        globus_gsc_pmod_959_finished_op(wrapper->op, msg);
        globus_free(msg);
        globus_free(wrapper);
    }

    return;

  err:

    if(msg != NULL)
    {
        globus_free(msg);
    }
    globus_free(wrapper);
}

/*
 *  passive
 */
static void
globus_l_gsc_pmod_959_cmd_pasv(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    int                                     sc;
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    char *                                  msg = NULL;
    globus_bool_t                           reply_flag;
    globus_bool_t                           dp;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_pasv);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
    if(wrapper == NULL)
    {
        goto err;
    }
    wrapper->op = op;
    wrapper->transfer_flag = GLOBUS_FALSE;
    wrapper->handle = cmd_handle;

    sc = sscanf(full_command, "%s", wrapper->cmd);
    globus_assert(sc == 1);

    dp = cmd_handle->opts_delayed_passive;
    reply_flag = cmd_handle->opts_delayed_passive;

    if(strcasecmp(wrapper->cmd, "PASV") == 0)
    {
        wrapper->dc_parsing_alg = cmd_handle->opts_dc_parsing_alg;
        wrapper->max = cmd_handle->opts_pasv_max;
        wrapper->prt = cmd_handle->opts_pasv_prt;
        msg = "227 Passive delayed.\r\n";
        wrapper->cmd_ndx = 1;
        wrapper->reply_code = 227;
    }
    else if(strcmp(wrapper->cmd, "EPSV") == 0)
    {
        wrapper->dc_parsing_alg = 1;
        msg = "229 Passive delayed.\r\n";
        if(strstr(&full_command[5], "ALL") != NULL)
        {
            reply_flag = GLOBUS_TRUE;
            cmd_handle->passive_only = GLOBUS_TRUE;
            msg = "229 EPSV ALL Successful.\r\n";
            dp = cmd_handle->delayed_passive;
        }
        else
        {
            sc = sscanf(full_command, "EPSV %d", &wrapper->prt);
            if(sc != 1)
            {
                dp = cmd_handle->delayed_passive;
                reply_flag = GLOBUS_TRUE;
                msg = "501 Invalid network command.\r\n";
            }
            else if(wrapper->prt != GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4
                && wrapper->prt != GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
            {
                dp = cmd_handle->delayed_passive;
                reply_flag = GLOBUS_TRUE;
                msg = "501 Invalid protocol.\r\n";
            }
            else
            {
                wrapper->max = cmd_handle->opts_pasv_max;
            }
        }
        wrapper->reply_code = 229;
        wrapper->cmd_ndx = 2;
    }
    else if(strcmp(wrapper->cmd, "SPAS") == 0)
    {
        wrapper->dc_parsing_alg = cmd_handle->opts_dc_parsing_alg;
        msg = "229 Passive delayed.\r\n";
        wrapper->max = -1;
        wrapper->prt = cmd_handle->opts_pasv_prt;
        wrapper->cmd_ndx = 3;
        wrapper->reply_code = 229;
    }
    else
    {
        globus_assert(GLOBUS_FALSE);
    }

    /*
     *  if delayed just wait for it
     */
    if(!reply_flag)
    {
        res = globus_gridftp_server_control_pmod_passive(
            server,
            wrapper->max,
            wrapper->prt,
            globus_l_gsc_pmod_959_cmd_pasv_cb,
            wrapper);
        if(res != GLOBUS_SUCCESS)
        {
            globus_gsc_pmod_959_finished_op(op, "500 command failed.\r\n");
        }
    }
    else
    {
        cmd_handle->delayed_passive = dp;
        globus_gsc_pmod_959_finished_op(op, msg);
        globus_free(wrapper);
    }

    return;

  err:
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
    if(wrapper != NULL)
    {
        globus_free(wrapper);
    }
}

/*
 *  port
 */
static void
globus_l_gsc_pmod_959_cmd_port_cb(
    globus_gridftp_server_control_t         server,
    globus_result_t                         res,
    void *                                  user_arg)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper;
    int                                     ctr;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;
    cmd_handle = wrapper->handle;

    if(res != GLOBUS_SUCCESS)
    {
        globus_gsc_pmod_959_finished_op(
            wrapper->op, "500 PORT Command failed.\r\n");
    }
    else
    {
        /* if port is successful we know that we are not delaying the pasv */
        cmd_handle->delayed_passive = GLOBUS_FALSE;
        cmd_handle->opts_port_prt = wrapper->prt;
        globus_gsc_pmod_959_finished_op(
            wrapper->op, "200 PORT Command successful.\r\n");
    }

    for(ctr = 0; ctr < wrapper->cs_count; ctr++)
    {
        globus_free(wrapper->cs[ctr]);
    }
    globus_free(wrapper);
}

static void
globus_l_gsc_pmod_959_cmd_port(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    int                                     host_ip[4];
    int                                     hi;
    int                                     low;
    int                                     port;
    int                                     sc;
    int                                     pc;
    int                                     stripe_count;
    char                                    del;
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    char *                                  msg = NULL;
    char                                    scan_str[64];
    char *                                  host_str;
    char *                                  tmp_ptr;
    char **                                 tmp_ptr2;
    char **                                 contact_strings = NULL;
    int                                     cs_sz = 64;
    globus_bool_t                           done;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_port);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
    if(wrapper == NULL)
    {
        goto err;
    }
    wrapper->op = op;
    wrapper->handle = cmd_handle;

    sc = sscanf(full_command, "%s", wrapper->cmd);
    globus_assert(sc == 1);

    if(strcasecmp(wrapper->cmd, "PORT") == 0)
    {
        wrapper->dc_parsing_alg = cmd_handle->opts_dc_parsing_alg;
        wrapper->prt = cmd_handle->opts_port_prt;
        wrapper->max = cmd_handle->opts_port_max;
    }
    else if(strcasecmp(wrapper->cmd, "SPOR") == 0)
    {
        wrapper->dc_parsing_alg = cmd_handle->opts_dc_parsing_alg;
        wrapper->prt = cmd_handle->opts_port_prt;
        wrapper->max = -1;
    }
    else if(strcasecmp(wrapper->cmd, "EPRT") == 0)
    {
        wrapper->dc_parsing_alg = 1;
        wrapper->prt = cmd_handle->opts_port_prt;
        wrapper->max = cmd_handle->opts_port_max;
    }
    else
    {
        globus_assert(GLOBUS_FALSE);
    }
    

    /* 
     *  parse in the traditional rfc959 ftp way
     */
    if(wrapper->dc_parsing_alg == 0)
    {
        /* move to the first command argument */
        tmp_ptr = strstr(full_command, wrapper->cmd);
        globus_assert(tmp_ptr != NULL);
        tmp_ptr += strlen(wrapper->cmd);

        contact_strings = globus_malloc(sizeof(char **) * cs_sz);
        if(contact_strings == NULL)
        {
            goto err;
        }
        /* parse out all the arguments */
        stripe_count = 0;
        done = GLOBUS_FALSE;
        while(!done && *tmp_ptr != '\0')
        {
            /* move past all the leading spaces */
            while(isspace(*tmp_ptr)) tmp_ptr++;

            sc = sscanf(tmp_ptr, "%d,%d,%d,%d,%d,%d",
                &host_ip[0],
                &host_ip[1],
                &host_ip[2],
                &host_ip[3],
                &hi,
                &low);
            port = hi * 256 + low;
            /* if string improperly parsed */
            if(sc != 6)
            {
                /* if nothing could be read it implies the string was ok */
                if(sc != 0)
                {
                    msg = "501 Illegal PORT command.\r\n";
                }
                done = GLOBUS_TRUE;
            }
            /* if received port is not valid */
            else if(host_ip[0] > 255 ||
                    host_ip[1] > 255 ||
                    host_ip[2] > 255 ||
                    host_ip[3] > 255 ||
                    port > 65535)
            {
                msg = "501 Illegal PORT command.\r\n";
                done = GLOBUS_TRUE;
            }
            /* all is well with the client string */
            else
            {
                if(stripe_count >= cs_sz)
                {
                    cs_sz *= 2;
                    tmp_ptr2 = globus_libc_realloc(
                        contact_strings, sizeof(char **)*cs_sz);
                    if(contact_strings == NULL)
                    {
                        goto err;
                    }
                    contact_strings = tmp_ptr2;
                }
                /* create teh stripe count string */
                contact_strings[stripe_count] = globus_malloc(32); /* 22 max */
                pc = sprintf(contact_strings[stripe_count], "%d.%d.%d.%d:%d",
                    host_ip[0], host_ip[1], host_ip[2], host_ip[3], port);
                globus_assert(pc < 32);

                stripe_count++;
                /* move to next space */
                while(!isspace(*tmp_ptr) && *tmp_ptr != '\0') tmp_ptr++;
            }
        }
    }
    /* 
     *  parse in the new eprt way, ipv6 respected
     */
    else if(wrapper->dc_parsing_alg == 1)
    {
        /* move past the initial command and read the first character */
        tmp_ptr = strstr(full_command, wrapper->cmd);
        globus_assert(tmp_ptr != NULL);
        tmp_ptr += strlen(wrapper->cmd);

        done = GLOBUS_FALSE;
        sc = sscanf(tmp_ptr, " %c%d", &del, &wrapper->prt);
        if(sc != 2)
        {
            done = GLOBUS_TRUE;
            msg = "501 Malformed argument.\r\n";
        }
        else if(wrapper->prt != GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4 && 
            wrapper->prt != GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
        {
            msg = "501 Invalid network protocol.\r\n";
            done = GLOBUS_TRUE;
        }
        else if(!isascii(del))
        {
            msg = "501 Invalid delimiter.\r\n";
            done = GLOBUS_TRUE;
        }

        while(!done)
        {
            /* move past all the leading spaces */
            while(isspace(*tmp_ptr)) tmp_ptr++;

            if(stripe_count >= cs_sz)
            {
                cs_sz *= 2;
                tmp_ptr2 = globus_libc_realloc(
                    contact_strings, sizeof(char **)*cs_sz);
                if(contact_strings == NULL)
                {
                    goto err;
                }
                contact_strings = tmp_ptr2;
            }

            switch(wrapper->prt)
            {
                case GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4:
                    /* build the scan string */
                    sprintf(scan_str, "%c%d%c%%d.%%d.%%d.%%d%c%%d%c",
                        del, wrapper->prt, del, del, del);

                    sc = sscanf(full_command, scan_str, 
                        &host_ip[0],
                        &host_ip[1],
                        &host_ip[2],
                        &host_ip[3],
                        &port);
                    if(sc != 5)
                    {
                        if(sc != 0)
                        {
                            msg = "501 Bad parameters to EPRT\r\n";
                        }
                        done = GLOBUS_TRUE;
                    }
                    else
                    {
                        contact_strings[stripe_count] = globus_malloc(32);
                        pc = sprintf(contact_strings[stripe_count], 
                            "%d.%d.%d.%d:%d",
                            host_ip[0], host_ip[1], host_ip[2], host_ip[3], 
                            port);
                        globus_assert(pc < 32);

                        stripe_count++;
                    }
                    break;

                case GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6:
                    /* build the scan string */
                    sprintf(scan_str, "%c%d%c%%s%c%%d%c",
                        del, wrapper->prt, del, del, del);
                    host_str = globus_malloc(strlen(full_command));                          
                    sc = sscanf(full_command, scan_str,
                        host_str,
                        &port);
                    if(sc != 2)
                    {
                        if(sc != 0)
                        {
                            msg = "501 Bad parameters to EPRT\r\n";
                        }
                        done = GLOBUS_TRUE;
                    }
                    else
                    {
                        contact_strings[stripe_count] = globus_malloc(
                            strlen(host_str) + 9);
                        sprintf(contact_strings[stripe_count], "[%s]:%d",
                            host_str, port);
                        stripe_count++;
                    }
                    break;

                default:
                    globus_assert(GLOBUS_FALSE);
                    break;
            }
            while(!isspace(*tmp_ptr) && *tmp_ptr != '\0') tmp_ptr++;
        }
    }

    if((stripe_count > wrapper->max && wrapper->max != -1) || stripe_count == 0)
    {
        msg = "501 Illegal PORT command.\r\n";
    }
    if(msg != NULL)
    {
        globus_gsc_pmod_959_finished_op(op, msg);
        globus_free(wrapper);
        globus_free(contact_strings);
    }
    else
    {
        wrapper->cs = contact_strings;
        wrapper->cs_count = stripe_count;
        res = globus_gridftp_server_control_pmod_port(
                server,
                (const char **)contact_strings,
                stripe_count,
                wrapper->prt,
                globus_l_gsc_pmod_959_cmd_port_cb,
                wrapper);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    return;

  err:
    if(contact_strings != NULL)
    {
        globus_free(contact_strings);
    }
    if(wrapper != NULL)
    {
        globus_free(wrapper);
    }
    globus_gsc_959_panic(op, GlobusGridFTPServerErrorMemory("message"));
}

/*************************************************************************
 *                          transfer functions
 *                          ------------------
 ************************************************************************/
static void
globus_l_gsc_pmod_959_event_cb(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_event_type_t      event,
    const char *                                    msg,
    void *                                          user_arg)
{
    globus_result_t                                 res;
    globus_l_gsc_pmod_959_cmd_wrapper_t *           wrapper;
    char *                                          l_msg;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    l_msg = globus_common_create_string("%d %s\r\n", event, msg);
    res = globus_gsc_pmod_959_intermediate_reply(wrapper->op, l_msg);
    if(res != GLOBUS_SUCCESS)
    {
    }
    globus_free(l_msg);
}

static void 
globus_l_gsc_pmod_959_data_cb(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    void *                                          user_arg)
{
    globus_l_gsc_pmod_959_cmd_wrapper_t *           wrapper;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) user_arg;

    if(res != GLOBUS_SUCCESS)
    {
        globus_gsc_pmod_959_finished_op(wrapper->op, "500 Command failed\r\n");
    }
    else
    {
        globus_gsc_pmod_959_finished_op(
            wrapper->op, "226 Transfer Complete.\r\n");
    }
}

static void
globus_l_gsc_pmod_959_transfer(
    globus_l_gsc_pmod_959_cmd_wrapper_t *           wrapper)
{
    globus_result_t                                 res;

    if(strcasecmp(wrapper->cmd, "RETR") == 0 ||
        strcasecmp(wrapper->cmd, "ERET") == 0)
    {
        res = globus_gridftp_server_control_pmod_send(
            wrapper->server,
            wrapper->path,
            wrapper->mod_name,
            wrapper->mod_parms,
            globus_l_gsc_pmod_959_data_cb,
            globus_l_gsc_pmod_959_event_cb,
            wrapper);
    }
    else if(strcasecmp(wrapper->cmd, "STOR") == 0 ||
        strcasecmp(wrapper->cmd, "ESTO") == 0)
    {
        res = globus_gridftp_server_control_pmod_receive(
            wrapper->server,
            wrapper->path,
            wrapper->mod_name,
            wrapper->mod_parms,
            globus_l_gsc_pmod_959_data_cb,
            globus_l_gsc_pmod_959_event_cb,
            wrapper);
    }
    else
    {
        globus_assert(GLOBUS_FALSE);
    }

    if(res != GLOBUS_SUCCESS)
    {
        globus_gsc_pmod_959_finished_op(wrapper->op, "500 Command failed\r\n");
    }
}

/*
 *  stor
 */
static void
globus_l_gsc_pmod_959_cmd_stor_retr(
    globus_gsc_pmod_959_op_t                op,
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    int                                     sc;
    globus_result_t                         res;
    char *                                  path = NULL;
    char *                                  mod_name = NULL;
    char *                                  mod_parm = NULL;
    char *                                  tmp_ptr = NULL;
    globus_l_gsc_pmod_959_cmd_wrapper_t *   wrapper = NULL;
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;
    GlobusGridFTPServerName(globus_l_gsc_pmod_959_cmd_stor);

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) user_arg;

    wrapper = (globus_l_gsc_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gsc_pmod_959_cmd_wrapper_t));
    if(wrapper == NULL)
    {
        goto err;
    }
    wrapper->op = op;
    wrapper->handle = cmd_handle;

    sc = sscanf(full_command, "%s", wrapper->cmd);
    globus_assert(sc == 1);

    if(strcasecmp(wrapper->cmd, "STOR") == 0 ||
        strcasecmp(wrapper->cmd, "RETR") == 0)
    {
        tmp_ptr = strstr(full_command, wrapper->cmd);
        globus_assert(tmp_ptr);
        tmp_ptr = tmp_ptr + strlen(wrapper->cmd);
        while(isspace(*tmp_ptr)) tmp_ptr++;

        /* error */
        if(tmp_ptr == '\0')
        {
        }

        path = globus_libc_strdup(tmp_ptr);
        mod_name = NULL;
        mod_parm = NULL;
    }
    else if(strcasecmp(wrapper->cmd, "ESTO") == 0 ||
        strcasecmp(wrapper->cmd, "ERET") == 0)
    {
        mod_name = globus_malloc(strlen(full_command));
        mod_parm = globus_malloc(strlen(full_command));
        sc = sscanf(full_command, "%*s %s",
            mod_name);
        if(sc != 1)
        {
        }

        tmp_ptr = strstr(mod_name, "=\"");
        if(tmp_ptr == NULL)
        {
        }

        *tmp_ptr = '\0';
        tmp_ptr += 2;
        mod_parm = globus_libc_strdup(tmp_ptr);
        tmp_ptr = strchr(mod_parm, '\"');
        *tmp_ptr = '\0';

        tmp_ptr = strstr(full_command, mod_parm);
        globus_assert(tmp_ptr != NULL);
        tmp_ptr += strlen(mod_parm);
        tmp_ptr++; /* move past the " */
        while(isspace(*tmp_ptr)) tmp_ptr++;
        path = globus_libc_strdup(tmp_ptr);
    }
    else
    {
        globus_assert(GLOBUS_FALSE);
    }

    wrapper->mod_name = mod_name;
    wrapper->mod_parms = mod_parm;
    wrapper->path = path;
    wrapper->reply_code = 129;
    wrapper->server = server;
    /* if in delayed passive tell library to go passive */
    if(cmd_handle->delayed_passive)
    {
        res = globus_gridftp_server_control_pmod_passive(
            server,
            wrapper->max,
            wrapper->prt,
            globus_l_gsc_pmod_959_cmd_pasv_cb,
            wrapper);
        if(res != GLOBUS_SUCCESS)
        {
            globus_gsc_pmod_959_finished_op(op, "500 command failed.\r\n");
        }
    }
    else
    {
        globus_l_gsc_pmod_959_transfer(wrapper);
    }

    return;

  err:
}

/*************************************************************************
 *                          helpers
 *                          -------
 ************************************************************************/
/*
 *  turn a stat struct into a string
 */
char *
globus_l_gs_pmod_959_ls_line(
    globus_gridftp_server_control_stat_t *  stat_info,
    char *                                  path)
{
    struct passwd *                         pw;
    struct group *                          gr;
    struct tm *                             tm;
    char                                    perms[11];
    char *                                  tmp_ptr;
    char *                                  month_lookup[12] = 
        {"Jan", "Feb", "Mar", "April", "May", "June", "July", "Aug", 
        "Sept", "Oct", "Nov", "Dec" };

    strcpy(perms, "----------");

    tm = localtime(&stat_info->mtime);
    pw = getpwuid(stat_info->uid);
    gr = getgrgid(stat_info->gid);

    if(S_ISDIR(stat_info->mode))
    {
        perms[0] = 'd';
    }
    else if(S_ISLNK(stat_info->mode))
    {
        perms[0] = 'l';
    }
    else if(S_ISFIFO(stat_info->mode))
    {
        perms[0] = 'x';
    }
    else if(S_ISCHR(stat_info->mode))
    {
        perms[0] = 'c';
    }
    else if(S_ISBLK(stat_info->mode))
    {
        perms[0] = 'b';
    }

    if(S_IRUSR & stat_info->mode)
    {
        perms[1] = 'r';
    }
    if(S_IWUSR & stat_info->mode)
    {
        perms[2] = 'w';
    }
    if(S_IXUSR & stat_info->mode)
    {
        perms[3] = 'x';
    }
    if(S_IRGRP & stat_info->mode)
    {
        perms[4] = 'r';
    }
    if(S_IWGRP & stat_info->mode)
    {
        perms[5] = 'w';
    }
    if(S_IXGRP & stat_info->mode)
    {
        perms[6] = 'x';
    }
    if(S_IROTH & stat_info->mode)
    {
        perms[7] = 'r';
    }
    if(S_IWOTH & stat_info->mode)
    {
        perms[8] = 'w';
    }
    if(S_IXOTH & stat_info->mode)
    {
        perms[9] = 'x';
    }

    tmp_ptr = globus_common_create_string(
        " %s %d %s %s %ld %s %2d %02d:%02d %s\r\n",
        perms,
        stat_info->nlink,
        pw->pw_name,
        gr->gr_name,
        stat_info->size,
        month_lookup[tm->tm_mon],
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        path);

    return tmp_ptr;
}

void
globus_i_gsc_pmod_959_add_commands(
    globus_gsc_pmod_959_handle_t            handle)
{
    globus_l_gsc_pmod_959_cmd_handle_t *    cmd_handle;

    cmd_handle = (globus_l_gsc_pmod_959_cmd_handle_t *) globus_malloc(
        sizeof(globus_l_gsc_pmod_959_cmd_handle_t));
    memset(cmd_handle, '\0', sizeof(globus_l_gsc_pmod_959_cmd_handle_t));

    cmd_handle->handle_959 = handle;
    cmd_handle->send_window = 65536;
    cmd_handle->receive_window = 65536;
    cmd_handle->packet_size = 65536;
    cmd_handle->parallelism = 4;

    cmd_handle->opts_pasv_max = 1;
    cmd_handle->opts_pasv_prt = GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4;

    cmd_handle->opts_port_max = 1;
    cmd_handle->opts_port_prt = GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4;

    globus_gsc_pmod_959_command_add(
        handle,
        "CWD", 
        globus_l_gsc_pmod_959_cmd_cwd,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: CWD <sp> pathname\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "CDUP", 
        globus_l_gsc_pmod_959_cmd_cwd,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: CDUP (up one directory)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "EPSV", 
        globus_l_gsc_pmod_959_cmd_pasv,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: EPSV [<sp> ALL]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "ERET", 
        globus_l_gsc_pmod_959_cmd_stor_retr,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: ERET <sp> mod_name=\"mod_parms\" <sp> pathname\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "ESTO", 
        globus_l_gsc_pmod_959_cmd_stor_retr,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: ESTO <sp> mod_name=\"mod_parms\" <sp> pathname\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "HELP", 
        globus_l_gsc_pmod_959_cmd_help,
        GLOBUS_GSC_959_COMMAND_PRE_AUTH | 
            GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: HELP [<sp> command]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "MDTM", 
        globus_l_gsc_pmod_959_cmd_size,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: MDTM <sp> pathname\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "MODE", 
        globus_l_gsc_pmod_959_cmd_mode,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: MODE <sp> mode-code\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "NOOP", 
        globus_l_gsc_pmod_959_cmd_noop,
        GLOBUS_GSC_959_COMMAND_PRE_AUTH | 
            GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: NOOP (no operation)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "OPTS", 
        globus_l_gsc_pmod_959_cmd_opts,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: OPTS <sp> opt-type [paramters]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "PASS", 
        globus_l_gsc_pmod_959_cmd_pass,
        GLOBUS_GSC_959_COMMAND_PRE_AUTH,
        "214 Syntax: PASS <sp> password\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "PASV", 
        globus_l_gsc_pmod_959_cmd_pasv,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: PASS <sp> password\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "PORT", 
        globus_l_gsc_pmod_959_cmd_port,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: PWD (returns current working directory)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "EPRT", 
        globus_l_gsc_pmod_959_cmd_port,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: PWD (returns current working directory)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "SPOR", 
        globus_l_gsc_pmod_959_cmd_port,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: PWD (returns current working directory)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "PWD", 
        globus_l_gsc_pmod_959_cmd_pwd,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: PWD (returns current working directory)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "QUIT", 
        globus_l_gsc_pmod_959_cmd_quit,
        GLOBUS_GSC_959_COMMAND_PRE_AUTH | 
            GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: QUIT (close control connection)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "RETR", 
        globus_l_gsc_pmod_959_cmd_stor_retr,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: RETR [<sp> pathname]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "SBUF", 
        globus_l_gsc_pmod_959_cmd_sbuf,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: SBUF <sp> window-size\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "SITE", 
        globus_l_gsc_pmod_959_cmd_site,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: SITE <sp> site-command [parameters]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "SIZE", 
        globus_l_gsc_pmod_959_cmd_size,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: SIZE <sp> pathname\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "SPAS", 
        globus_l_gsc_pmod_959_cmd_pasv,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: SPAS\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "STAT", 
        globus_l_gsc_pmod_959_cmd_stat,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: STAT [<sp> pathname]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "STOR", 
        globus_l_gsc_pmod_959_cmd_stor_retr,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: STOR [<sp> pathname]\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "SYST", 
        globus_l_gsc_pmod_959_cmd_syst,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: SYST (returns system type)\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "TYPE", 
        globus_l_gsc_pmod_959_cmd_type,
        GLOBUS_GSC_959_COMMAND_POST_AUTH,
        "214 Syntax: TYPE <sp> type-code\r\n",
        cmd_handle);

    globus_gsc_pmod_959_command_add(
        handle,
        "USER", 
        globus_l_gsc_pmod_959_cmd_user,
        GLOBUS_GSC_959_COMMAND_PRE_AUTH,
        "214 Syntax: USER <sp> username\r\n",
        cmd_handle);
}
