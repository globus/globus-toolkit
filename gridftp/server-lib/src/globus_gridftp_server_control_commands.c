#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server_control.h"
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/utsname.h>

/*
 *  These commands will only come in one at a time
 */

typedef struct globus_l_gsc_cmd_wrapper_s
{
    globus_i_gsc_op_t *                     op;
    char *                                  strarg;
    char *                                  mod_name;
    char *                                  mod_parms;
    char *                                  path;

    globus_bool_t                           transfer_flag;
    int                                     dc_parsing_alg;
    int                                     max;
    globus_gridftp_server_control_network_protocol_t prt;

    char                                    cmd[8];
    int                                     cmd_ndx;

    char **                                 cs;
    int                                     cs_count;
    int                                     reply_code;
} globus_l_gsc_cmd_wrapper_t;

char *
globus_l_gsc_ls_line(
    globus_gridftp_server_control_stat_t *  stat_info,
    char *                                  path);

static void
globus_l_gsc_cmd_transfer(
    globus_l_gsc_cmd_wrapper_t *            wrapper);

/*************************************************************************
 *                      simple commands
 *                      ---------------
 ************************************************************************/
/*
 *  simply pings the control channel
 */
static void
globus_l_gsc_cmd_noop(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    op->server_handle->refresh = GLOBUS_TRUE;
    globus_i_gsc_finished_command(op, "200 NOOP command successful.\r\n");
}

/*
 *  mode
 */
static void
globus_l_gsc_cmd_mode(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  msg;
    char                                    ch;

    ch = (char)toupper((int)cmd_a[1][0]);
    if(strchr(op->server_handle->modes, ch) == NULL)
    {
        msg = globus_common_create_string(
            "501 '%s' unrecognized transfer mode.\r\n", full_command);
    }
    else
    {
        msg = globus_common_create_string("200 Mode set to %c.\r\n", ch);
    }
    if(msg == NULL)
    {
        globus_i_gsc_command_panic(op);
    }
    else
    {
        globus_i_gsc_finished_command(op, msg);
        globus_free(msg);
    }
}

/*
 *  type
 */
static void
globus_l_gsc_cmd_type(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    char                                    ch;
    char *                                  msg;
    GlobusGridFTPServerName(globus_l_gsc_cmd_type);

    ch = (char)toupper((int)cmd_a[1][0]);
    if(strchr(op->server_handle->types, ch) == NULL)
    {
        msg = globus_common_create_string(
            "501 '%s' unrecognized type.\r\n", full_command);
    }
    else
    {
        msg = globus_common_create_string("200 Type set to %c.\r\n", ch);
    }
    if(msg == NULL)
    {
        globus_i_gsc_command_panic(op);
    }
    else
    {
        globus_i_gsc_finished_command(op, msg);
        globus_free(msg);
    }
}

/*************************************************************************
 *                      directory functions
 *                      -------------------
 ************************************************************************/
/*
 *  PWD
 */
static void
globus_l_gsc_cmd_pwd(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  msg;
    GlobusGridFTPServerName(globus_l_gsc_cmd_pwd);

    msg = globus_common_create_string(
        "257 \"%s\" is current directory.\r\n", op->server_handle->cwd);
    if(msg == NULL)
    {
        globus_i_gsc_command_panic(op);
    }
    else
    {
        globus_i_gsc_finished_command(op, msg);
        globus_free(msg);
    }
}

/*
 *  CWD
 */
static void
globus_l_gsc_cmd_cwd_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         result,
    char *                                  path,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count,
    void *                                  user_arg)
{
    char *                                  l_path;
    char *                                  msg = NULL;
    GlobusGridFTPServerName(globus_l_gsc_cmd_cwd_cb);

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
        if(!(S_IXOTH & stat_info->mode && S_IROTH & stat_info->mode) &&
            !(stat_info->uid == op->server_handle->uid && 
                S_IXUSR & stat_info->mode && S_IRUSR & stat_info->mode))
        {
            msg = globus_common_create_string(
                "550 %s: Permission denied\r\n",
                path);
        }
        else
        {
            l_path = globus_i_gsc_concat_path(op->server_handle, path);
            if(l_path == NULL)
            {
                globus_i_gsc_command_panic(op);
                goto err;
            }
            if(op->server_handle->cwd != NULL)
            {
                globus_free(op->server_handle->cwd);
            }
            op->server_handle->cwd = path;
            msg = globus_libc_strdup("250 CWD command successful.\r\n");
        }
    }
    if(msg == NULL)
    {
        globus_i_gsc_command_panic(op);
        goto err;
    }

    globus_i_gsc_finished_command(op, msg);
    globus_free(msg);
    globus_free(path);

    return;

  err:

    if(l_path != NULL)
    {
        globus_free(l_path);
    }
    if(msg != NULL)
    {
        globus_free(msg);
    }
    globus_free(path);
}

static void
globus_l_gsc_cmd_cwd(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    globus_result_t                         res;
    int                                     mask = 0;
    char *                                  path = NULL;
    GlobusGridFTPServerName(globus_l_gsc_cmd_cwd);

    if(strcmp(cmd_a[0], "CDUP") == 0 && argc == 1)
    {
        path = globus_libc_strdup("..");
        if(path == NULL)
        {
            globus_i_gsc_command_panic(op);
            goto err;
        }
    }
    else if(argc == 2)
    {
        path = strdup(cmd_a[1]);
    }
    else
    {
        globus_i_gsc_finished_command(op,
            "501 Syntax error in parameters or arguments.\r\n");
        goto err;
    }

    res = globus_i_gsc_resource_query(
            op,
            path,
            mask,
            globus_l_gsc_cmd_cwd_cb,
            NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return;

  err:
    if(path != NULL)
    {
        globus_free(path);
    }
}

/*
 *  STAT
 */
static void
globus_l_gsc_cmd_stat_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         result,
    char *                                  path,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count,
    void *                                  user_arg)
{
    globus_size_t                           msg_size;
    globus_size_t                           msg_ndx = 0;
    char *                                  msg;
    char *                                  tmp_ptr;
    char *                                  tmp_ptr2;
    int                                     ctr;
    char *                                  end_tok = "213 End of Status\r\n";
    GlobusGridFTPServerName(globus_l_gsc_cmd_stat_cb);

    if(result != GLOBUS_SUCCESS)
    {
        msg = globus_libc_strdup("500 Command failed\r\n");
    }
    else
    {
        msg_size = (stat_count + 2) * 80;
        msg = globus_malloc(msg_size);
        if(msg == NULL)
        {
            globus_i_gsc_command_panic(op);
            goto err;
        }

        sprintf(msg, "213-status of %s\r\n", op->path);

        for(ctr = 0; ctr < stat_count; ctr++)
        {
            tmp_ptr = globus_l_gsc_ls_line(&stat_info[ctr], path);
            if(msg_ndx + strlen(tmp_ptr) > msg_size)
            {
                msg_size = (msg_size + strlen(tmp_ptr)) * 2;
                tmp_ptr2 = globus_libc_realloc(msg, msg_size);
                if(tmp_ptr2 == NULL)
                {
                    globus_i_gsc_command_panic(op);
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
                globus_i_gsc_command_panic(op);
                goto err;
            }
            msg = tmp_ptr2;
        } 
        strcat(msg, end_tok);
    }

    globus_i_gsc_finished_command(op, msg);
    if(stat_info != NULL)
    {
        globus_free(stat_info);
    }
    globus_free(msg);

    return;

  err:
    if(stat_info != NULL)
    {
        globus_free(stat_info);
    }

    if(msg != NULL)
    {
        globus_free(msg);
    }
}

static void
globus_l_gsc_cmd_stat(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    /* these are really just place holders in the list */
    int                                     mask = 0;
    char *                                  msg = NULL;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_cmd_stat);

    if(argc == 1)
    {
        msg = globus_common_create_string(
                "212 GridFTP server status.\r\n");
        if(msg == NULL)
        {
            globus_i_gsc_command_panic(op);
            goto err;
        }
        globus_i_gsc_finished_command(op, msg);
        globus_free(msg);
    }
    else if(argc == 2)
    {
        res = globus_i_gsc_resource_query(
                op,
                cmd_a[1],
                mask,
                globus_l_gsc_cmd_stat_cb,
                NULL);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gsc_finished_command(op, "500 Command not supported.\r\n");
        }
    }

    return;

  err:
    return;
}

/*
 *  size and mdtm
 */
static void
globus_l_gsc_cmd_size_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         result,
    char *                                  path,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count,
    void *                                  user_arg)
{
    char *                                  msg = NULL;
    GlobusGridFTPServerName(globus_l_gsc_cmd_size_cb);

    globus_free(path);
    if(result != GLOBUS_SUCCESS || stat_count < 1)
    {
        msg = globus_libc_strdup("550 Command failed.\r\n");
    }
    else
    {
        msg = globus_common_create_string("213 %d.\r\n", stat_info->size);
    }
    if(msg == NULL)
    {
        globus_i_gsc_command_panic(op);
        goto err;
    }
    globus_i_gsc_finished_command(op, msg);
    
    globus_free(msg);
    
    return;
    
  err:
    if(msg != NULL)
    {
        globus_free(msg);
    }
}

static void
globus_l_gsc_cmd_size(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    /* these are really just place holders in the list */
    char *                                  path = NULL;
    int                                     mask = 0;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_cmd_size);

    path = strdup(cmd_a[1]);
    if(path == NULL)
    {
        globus_i_gsc_command_panic(op);
        goto err;
    }
    res = globus_i_gsc_resource_query(
        op,
        path,
        mask,
        globus_l_gsc_cmd_size_cb,
        NULL);
    if(res != GLOBUS_SUCCESS)
    {
        globus_i_gsc_command_panic(op);
        goto err;
    }

    return;

  err:
    if(path != NULL)
    {
        globus_free(path);
    }
}

/*
 *  quit
 */
static void
globus_l_gsc_cmd_quit(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    globus_i_gsc_server_handle_t *          server_handle;

    server_handle = op->server_handle;

    globus_i_gsc_finished_command(op, "221 Goodbye.\r\n");

    globus_i_gsc_terminate(server_handle, 1);
}

/*************************************************************************
 *                      authentication commands
 *                      -----------------------
 ************************************************************************/
/*
 *   USER
 */
static void
globus_l_gsc_cmd_user(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  msg;
    GlobusGridFTPServerName(globus_l_gsc_cmd_user);

    if(op->server_handle->username != NULL)
    {
        globus_free(op->server_handle->username);
        op->server_handle->username = NULL;
    }
    op->server_handle->username = globus_libc_strdup(cmd_a[1]);
    msg = globus_common_create_string(
        "331 Password required for %s.\r\n", op->server_handle->username);
    if(msg == NULL)
    {
        goto err;
    }
    globus_i_gsc_finished_command(op, msg);
    globus_free(msg);
    return;

  err:
    if(op->server_handle->username != NULL)
    {
        globus_free(op->server_handle->username);
    }
    globus_i_gsc_command_panic(op);
}

static void
globus_l_gsc_auth_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    char *                                  msg;

    if(result == GLOBUS_SUCCESS)
    {
        msg = globus_common_create_string(
            "230 User %s logged in, proceed.\r\n", op->server_handle->username);
    }
    else
    {
        msg = globus_common_create_string("530 Login incorrect.\r\n");
    }
    globus_i_gsc_finished_command(op, msg);

    globus_free(msg);
}

/*
 *  pass
 */
static void
globus_l_gsc_cmd_pass(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  pass = NULL;
    char *                                  msg = NULL;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_cmd_pass);

    /*
     *  if user name has not yet been supplied return error message
     */
    if(op->server_handle->username == NULL)
    {
        msg = "503 Login with USER first.\r\n";
        if(msg == NULL)
        {
            goto err;
        }
        globus_i_gsc_finished_command(op, msg);
    }
    else
    {
        pass = globus_libc_strdup(cmd_a[1]);
        if(pass == NULL)
        {
            goto err;
        }
        res = globus_i_gsc_authenticate(
            op,
            op->server_handle->username,
            pass,
            op->server_handle->cred,
            op->server_handle->del_cred,
            globus_l_gsc_auth_cb,
            NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        globus_free(pass);
    }

    return;

  err:
    globus_i_gsc_command_panic(op);
    if(pass != NULL)
    {
        globus_free(pass);
    }
}

/*
 *  syst
 */
static void
globus_l_gsc_cmd_syst(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  msg;
    struct utsname                          uname_info;
    GlobusGridFTPServerName(globus_l_gsc_cmd_syst);

    uname(&uname_info);

    msg = globus_common_create_string("215 %s.\r\n", uname_info.sysname);
    if(msg == NULL)
    {
        goto err;
    }
    globus_i_gsc_finished_command(op, msg);
    globus_free(msg);

    return;

  err:
    globus_i_gsc_command_panic(op);
}

/*
 *  help
 */
static void
globus_l_gsc_cmd_help(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    int                                     ctr;
    char *                                  msg;
    char *                                  arg;
    GlobusGridFTPServerName(globus_l_gsc_cmd_help);

    /* general help */
    if(argc == 1)
    {
        arg = NULL;
    }
    else
    {
        arg = globus_libc_strdup(cmd_a[0]);
        for(ctr = 0; ctr < strlen(arg); ctr++)
        {
            arg[ctr] = toupper(arg[ctr]);
        }
    }

    msg = globus_i_gsc_get_help(op->server_handle, arg);
    if(arg != NULL)
    {
        globus_free(arg);
    }
    if(msg == NULL)
    {
        goto err;
    }

    globus_i_gsc_finished_command(op, msg);
    globus_free(msg);

    return;

  err:
    globus_i_gsc_command_panic(op);
}

/*
 * opts
 */
static void
globus_l_gsc_cmd_opts(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    int                                     tmp_i;
    char *                                  msg;
    GlobusGridFTPServerName(globus_l_gsc_cmd_opts);

    if(argc != 3)
    {
        msg = "500 OPTS failed.\r\n";
    }
    else if(strcmp("RETR", cmd_a[1]) == 0)
    {
        msg = "200 OPTS Command Successful.\r\n";
        if(sscanf(cmd_a[2], "Parallelism=%d,%*d,%*d;", &tmp_i)==1)
        {
            op->server_handle->parallelism = tmp_i;
        }
        else if(sscanf(cmd_a[2], "PacketSize=%d;", &tmp_i) == 1)
        {
            op->server_handle->packet_size = tmp_i;
        }
        else if(sscanf(cmd_a[2], "WindowSize=%d;", &tmp_i) == 1)
        {
            op->server_handle->send_buf = tmp_i;
        }
        else
        {
            msg = "500 OPTS failed.\r\n";
        }
    }
    else if(strcmp("PASV", cmd_a[1]) == 0 || strcmp("SPAS", cmd_a[1]) == 0)
    {
        msg = "200 OPTS Command Successful.\r\n";
        if(sscanf(cmd_a[2], "AllowDelayed=%d", &tmp_i) == 1)
        {
            /* of coures i realize this could be optimized, but i am try
               to use the proper abstractions */
            if(tmp_i == 0)
            {
                op->server_handle->delayed_passive = GLOBUS_FALSE;
            }
            else
            {
                op->server_handle->delayed_passive = GLOBUS_TRUE;
            }
        }
        else if(sscanf(cmd_a[2], "DefaultProto=%d", &tmp_i) == 1)
        {
            if(tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4 ||
                tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
            {
                op->server_handle->pasv_prt = tmp_i;
            }
            else
            {
                msg = "500 OPTS failed.\r\n";
            }
            
        }
        else if(sscanf(cmd_a[2], "DefaultStripes=%d", &tmp_i) == 1)
        {
            op->server_handle->pasv_max = tmp_i;
        }
        else if(sscanf(cmd_a[2], "ParsingAlgrythm=%d", &tmp_i) == 1)
        {
            if(tmp_i == 0 || tmp_i == 1)
            {
                op->server_handle->dc_parsing_alg = tmp_i;
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
    else if(strcmp("PORT", cmd_a[1]) == 0 || strcmp("SPOR", cmd_a[1]) == 0)
    {
        msg = "200 OPTS Command Successful.\r\n";
        if(sscanf(cmd_a[2], "DefaultProto=%d", &tmp_i) == 1)
        {
            if(tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4 ||
                tmp_i == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
            {
                op->server_handle->port_prt = tmp_i;
            }
            else
            {
                msg = "500 OPTS failed.\r\n";
            }
            
        }
        else if(sscanf(cmd_a[2], "DefaultStripes=%d", &tmp_i) == 1)
        {
            op->server_handle->port_max = tmp_i;
        }
        else if(sscanf(cmd_a[2], "ParsingAlgrythm=%d", &tmp_i) == 1)
        {
            if(tmp_i == 0 || tmp_i == 1)
            {
                op->server_handle->dc_parsing_alg = tmp_i;
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

    globus_i_gsc_finished_command(op, msg);

    return;
}

/*
 *
 */
static void
globus_l_gsc_cmd_sbuf(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    int                                     sc;
    int                                     tmp_i;
    GlobusGridFTPServerName(globus_l_gsc_cmd_sbuf);

    if(argc != 2)
    {
        globus_i_gsc_finished_command(op, "502 Invalid Parameter.\r\n");
    }
    else
    {
        sc = sscanf(cmd_a[1], "%d", &tmp_i);
        if(sc != 1)
        {
            globus_i_gsc_finished_command(
                op, "502 Invalid Parameter.\r\n");
        }
        else
        {
            op->server_handle->send_buf = tmp_i;
            op->server_handle->receive_buf = tmp_i;

            globus_i_gsc_finished_command(
                op, "200 SBUF Command Successful.\r\n");
        }
    }
}

/*
 *
 */
static void
globus_l_gsc_cmd_site(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    int                                     sc;
    char *                                  msg = NULL;
    int                                     tmp_i;
    GlobusGridFTPServerName(globus_l_gsc_cmd_site);

    msg = globus_libc_strdup("500 Invalid Command.\r\n");

    switch(argc)
    {
        case 3:
            sc = sscanf(cmd_a[2], "%d", &tmp_i);
            if(strcmp(cmd_a[1], "HELP") == 0)
            {
                msg = globus_i_gsc_get_help(op->server_handle, cmd_a[2]);
            }
            else if(sc != 1)
            {
            }
            else if(strcmp(cmd_a[1], "BUFSIZE") == 0 ||
                    strcmp(cmd_a[1], "SBUF") == 0)
            {
                msg = globus_libc_strdup("200 Site Command Successful.\r\n");
                op->server_handle->send_buf = tmp_i;
                op->server_handle->receive_buf = tmp_i;
            }
            else if(strcmp(cmd_a[1], "RETRBUFSIZE") == 0 ||
                    strcmp(cmd_a[1], "RBUFSZ") == 0 ||
                    strcmp(cmd_a[1], "RBUFSIZ") == 0)
            {
                msg = globus_libc_strdup("200 Site Command Successful.\r\n");
                op->server_handle->send_buf = tmp_i;
            }
            else if(strcmp(cmd_a[1], "STORBUFSIZE") == 0 ||
                    strcmp(cmd_a[1], "SBUFSZ") == 0 ||
                    strcmp(cmd_a[1], "SBUFSIZ") == 0)
            {
                msg = globus_libc_strdup("200 Site Command Successful.\r\n");
                op->server_handle->receive_buf = tmp_i;
            }
            break;

        case 2:
            if(strcmp(cmd_a[1], "HELP") == 0)
            {
                msg = globus_i_gsc_get_help(op->server_handle, NULL);
            }
            break;

        default:
            break;
    }

    if(msg == NULL)
    {
        goto err;
    }
    globus_i_gsc_finished_command(op, msg);
    globus_free(msg);
    
    return;

  err:
    
    globus_i_gsc_command_panic(op);
}

/*************************************************************************
 *                  data connection esstablishement
 *                  -------------------------------
 ************************************************************************/
static void
globus_l_gsc_cmd_pasv_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         res,
    const char **                           cs,
    int                                     addr_count,
    void *                                  user_arg)
{
    int                                     ctr;
    char *                                  tmp_ptr;
    char *                                  host;
    int                                     host_ip[4];
    int                                     port;
    int                                     sc;
    int                                     hi;
    int                                     low;
    char *                                  msg = NULL;
    globus_l_gsc_cmd_wrapper_t *            wrapper = NULL;
    GlobusGridFTPServerName(globus_l_gsc_cmd_pasv_cb);

    wrapper = (globus_l_gsc_cmd_wrapper_t *) user_arg;
    wrapper->op = op;

    if(res != GLOBUS_SUCCESS)
    {
        globus_i_gsc_finished_command(op, "500 Command failed.\r\n");
        goto err;
    }
    else if(addr_count > wrapper->max && wrapper->max != -1)
    {
        globus_i_gsc_finished_command(wrapper->op, "500 Command failed.\r\n");
        goto err;
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
        globus_i_gsc_intermediate_reply(op, msg);
        globus_l_gsc_cmd_transfer(wrapper);
        globus_free(msg);
    }
    else
    {
        globus_i_gsc_finished_command(op, msg);
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
globus_l_gsc_cmd_pasv(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    int                                     sc;
    globus_l_gsc_cmd_wrapper_t *            wrapper = NULL;
    char *                                  msg = NULL;
    globus_bool_t                           reply_flag;
    globus_bool_t                           dp;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_cmd_pasv);

    wrapper = (globus_l_gsc_cmd_wrapper_t *)
        globus_calloc(sizeof(globus_l_gsc_cmd_wrapper_t), 1);

    dp = op->server_handle->delayed_passive;
    reply_flag = op->server_handle->delayed_passive;

    if(strcasecmp(cmd_a[0], "PASV") == 0)
    {
        wrapper->dc_parsing_alg = op->server_handle->dc_parsing_alg;
        wrapper->max = op->server_handle->pasv_max;
        wrapper->prt = op->server_handle->pasv_prt;
        msg = "227 Passive delayed.\r\n";
        wrapper->cmd_ndx = 1;
        wrapper->reply_code = 227;
    }
    else if(strcmp(cmd_a[0], "EPSV") == 0 && argc == 2)
    {
        wrapper->dc_parsing_alg = 1;
        msg = "229 Passive delayed.\r\n";
        if(strstr(cmd_a[1], "ALL") != NULL)
        {
            reply_flag = GLOBUS_TRUE;
            op->server_handle->passive_only = GLOBUS_TRUE;
            msg = "229 EPSV ALL Successful.\r\n";
            dp = op->server_handle->delayed_passive;
        }
        else
        {
            sc = sscanf(cmd_a[1], "%d", (int*)&wrapper->prt);
            if(sc != 1)
            {
                dp = op->server_handle->delayed_passive;
                reply_flag = GLOBUS_TRUE;
                msg = "501 Invalid network command.\r\n";
            }
            else if(wrapper->prt != GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4
                && wrapper->prt != GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
            {
                dp = op->server_handle->delayed_passive;
                reply_flag = GLOBUS_TRUE;
                msg = "501 Invalid protocol.\r\n";
            }
            else
            {
                wrapper->max = op->server_handle->pasv_max;
            }
        }
        wrapper->reply_code = 229;
        wrapper->cmd_ndx = 2;
    }
    else if(strcmp(cmd_a[0], "SPAS") == 0)
    {
        wrapper->dc_parsing_alg = op->server_handle->dc_parsing_alg;
        msg = "229 Passive delayed.\r\n";
        wrapper->max = -1;
        wrapper->prt = op->server_handle->pasv_prt;
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
        res = globus_i_gsc_passive(
            op,
            wrapper->max,
            wrapper->prt,
            globus_l_gsc_cmd_pasv_cb,
            wrapper);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gsc_finished_command(op, "500 command failed.\r\n");
        }
    }
    else
    {
        op->server_handle->delayed_passive = dp;
        globus_i_gsc_finished_command(op, msg);
        globus_free(wrapper);
    }

    return;
}

/*
 *  port
 */
static void
globus_l_gsc_cmd_port_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         res,
    void *                                  user_arg)
{

    if(res != GLOBUS_SUCCESS)
    {
        globus_i_gsc_finished_command(
            op, "500 PORT Command failed.\r\n");
    }
    else
    {
        /* if port is successful we know that we are not delaying the pasv */
        op->server_handle->delayed_passive = GLOBUS_FALSE;
        globus_i_gsc_finished_command(
            op, "200 PORT Command successful.\r\n");
    }
}

static void
globus_l_gsc_cmd_port(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
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
    globus_l_gsc_cmd_wrapper_t *            wrapper = NULL;
    char *                                  msg = NULL;
    char                                    scan_str[64];
    char *                                  host_str;
    char *                                  tmp_ptr;
    char **                                 tmp_ptr2;
    char **                                 contact_strings = NULL;
    int                                     cs_sz = 64;
    globus_bool_t                           done;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_cmd_port);

    wrapper = (globus_l_gsc_cmd_wrapper_t *) globus_calloc(
        sizeof(globus_l_gsc_cmd_wrapper_t), 1);
    if(wrapper == NULL)
    {
        goto err;
    }
    wrapper->op = op;
    strcpy(wrapper->cmd, cmd_a[0]);

    if(strcasecmp(wrapper->cmd, "PORT") == 0)
    {
        wrapper->dc_parsing_alg = op->server_handle->dc_parsing_alg;
        wrapper->prt = op->server_handle->port_prt;
        wrapper->max = op->server_handle->port_max;
    }
    else if(strcasecmp(wrapper->cmd, "SPOR") == 0)
    {
        wrapper->dc_parsing_alg = op->server_handle->dc_parsing_alg;
        wrapper->prt = op->server_handle->port_prt;
        wrapper->max = -1;
    }
    else if(strcasecmp(wrapper->cmd, "EPRT") == 0)
    {
        wrapper->dc_parsing_alg = 1;
        wrapper->prt = op->server_handle->port_prt;
        wrapper->max = op->server_handle->port_max;
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
        tmp_ptr = cmd_a[1];
        globus_assert(tmp_ptr != NULL);

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
        tmp_ptr = cmd_a[1];
        globus_assert(tmp_ptr != NULL);
        tmp_ptr += strlen(wrapper->cmd);

        done = GLOBUS_FALSE;
        sc = sscanf(tmp_ptr, " %c%d", &del, (int *)&wrapper->prt);
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
        globus_i_gsc_finished_command(op, msg);
        globus_free(wrapper);
        globus_free(contact_strings);
    }
    else
    {
        wrapper->cs = contact_strings;
        wrapper->cs_count = stripe_count;
        res = globus_i_gsc_port(
                op,
                (const char **)contact_strings,
                stripe_count,
                wrapper->prt,
                globus_l_gsc_cmd_port_cb,
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
    globus_i_gsc_command_panic(op);
}

/*************************************************************************
 *                          transfer functions
 *                          ------------------
 ************************************************************************/

static void 
globus_l_gsc_event_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         res,
    void *                                  user_arg)
{
}

static void 
globus_l_gsc_data_cb(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         res,
    void *                                  user_arg)
{
    globus_l_gsc_cmd_wrapper_t *            wrapper;

    wrapper = (globus_l_gsc_cmd_wrapper_t *) user_arg;

    if(res != GLOBUS_SUCCESS)
    {
        globus_i_gsc_finished_command(wrapper->op, "500 Command failed\r\n");
    }
    else
    {
        globus_i_gsc_finished_command(
            wrapper->op, "226 Transfer Complete.\r\n");
    }

    if(wrapper->mod_name)
    {
        globus_free(wrapper->mod_name);
    }
    if(wrapper->mod_parms)
    {
        globus_free(wrapper->mod_parms);
    }
    globus_free(wrapper->path);
    globus_free(wrapper);
}

static void
globus_l_gsc_cmd_transfer(
    globus_l_gsc_cmd_wrapper_t *            wrapper)
{
    globus_result_t                         res;

    if(strcasecmp(wrapper->cmd, "RETR") == 0 ||
        strcasecmp(wrapper->cmd, "ERET") == 0)
    {
        res = globus_i_gsc_send(
            wrapper->op,
            wrapper->path,
            wrapper->mod_name,
            wrapper->mod_parms,
            globus_l_gsc_data_cb,
            globus_l_gsc_event_cb,
            wrapper);
    }
    else if(strcasecmp(wrapper->cmd, "STOR") == 0 ||
        strcasecmp(wrapper->cmd, "ESTO") == 0)
    {
        res = globus_i_gsc_recv(
            wrapper->op,
            wrapper->path,
            wrapper->mod_name,
            wrapper->mod_parms,
            globus_l_gsc_data_cb,
            globus_l_gsc_event_cb,
            wrapper);
    }
    else
    {
        globus_assert(GLOBUS_FALSE);
    }

    if(res != GLOBUS_SUCCESS)
    {
        globus_i_gsc_finished_command(wrapper->op, "500 Command failed\r\n");
    }
}

/*
 *  stor
 */
static void
globus_l_gsc_cmd_stor_retr(
    globus_i_gsc_op_t *                     op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    globus_result_t                         res;
    char *                                  path = NULL;
    char *                                  mod_name = NULL;
    char *                                  mod_parm = NULL;
    char *                                  tmp_ptr = NULL;
    globus_l_gsc_cmd_wrapper_t *            wrapper = NULL;
    GlobusGridFTPServerName(globus_l_gsc_cmd_stor);

    wrapper = (globus_l_gsc_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gsc_cmd_wrapper_t));
    if(wrapper == NULL)
    {
        goto err;
    }
    wrapper->op = op;

    strcpy(wrapper->cmd, cmd_a[0]);
    if(strcasecmp(cmd_a[0], "STOR") == 0 ||
            strcasecmp(cmd_a[0], "RETR") == 0)
    {
        if(argc != 2)
        {
            globus_free(wrapper);
            globus_i_gsc_finished_command(op, "500 command failed.\r\n");
            return;
        }
        path = globus_libc_strdup(cmd_a[1]);
        mod_name = NULL;
        mod_parm = NULL;
    }
    else if(strcasecmp(cmd_a[0], "ESTO") == 0 ||
        strcasecmp(cmd_a[0], "ERET") == 0)
    {
        if(argc != 3)
        {
            globus_free(wrapper);
            globus_i_gsc_finished_command(op, "500 command failed.\r\n");
            return;
        }
        mod_name = globus_libc_strdup(cmd_a[1]);
        if(mod_name == NULL)
        {
            globus_free(wrapper);
            globus_i_gsc_command_panic(op);
            return;
        }

        tmp_ptr = strstr(mod_name, "=\"");
        if(tmp_ptr == NULL)
        {
            globus_free(mod_name);
            globus_free(wrapper);
            globus_i_gsc_finished_command(op, "500 command failed.\r\n");
            return;
        }

        *tmp_ptr = '\0';
        tmp_ptr += 2;
        mod_parm = globus_libc_strdup(tmp_ptr);
        tmp_ptr = strchr(mod_parm, '\"');
        *tmp_ptr = '\0';

        path = globus_libc_strdup(cmd_a[2]);
    }
    else
    {
        globus_assert(GLOBUS_FALSE);
    }

    wrapper->mod_name = mod_name;
    wrapper->mod_parms = mod_parm;
    wrapper->path = path;
    wrapper->reply_code = 129;
    /* if in delayed passive tell library to go passive */
    if(op->server_handle->delayed_passive)
    {
        res = globus_i_gsc_passive(
            wrapper->op,
            wrapper->max,
            wrapper->prt,
            globus_l_gsc_cmd_pasv_cb,
            wrapper);
        if(res != GLOBUS_SUCCESS)
        {
            globus_free(wrapper);
            globus_i_gsc_finished_command(op, "500 command failed.\r\n");
        }
    }
    else
    {
        globus_l_gsc_cmd_transfer(wrapper);
    }

    return;

  err:
    return;
}

/*************************************************************************
 *                          helpers
 *                          -------
 ************************************************************************/
/*
 *  turn a stat struct into a string
 */
char *
globus_l_gsc_ls_line(
    globus_gridftp_server_control_stat_t *  stat_info,
    char *                                  path)
{
    char *                                  username;
    char *                                  grpname;
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
    if(pw == NULL)
    {
        username = "(null)";
    }
    else
    {
        username = pw->pw_name;
    }
    gr = getgrgid(stat_info->gid);
    if(pw == NULL)
    {
        grpname = "(null)";
    }
    else
    {
        grpname = gr->gr_name;
    }

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
        username,
        grpname,
        stat_info->size,
        month_lookup[tm->tm_mon],
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        path);

    return tmp_ptr;
}

void
globus_i_gsc_add_commands(
    globus_i_gsc_server_handle_t *          server_handle)
{
    globus_i_gsc_command_add(
        server_handle,
        "CWD", 
        globus_l_gsc_cmd_cwd,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: CWD <sp> pathname\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "CDUP", 
        globus_l_gsc_cmd_cwd,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: CDUP (up one directory)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "EPSV", 
        globus_l_gsc_cmd_pasv,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        2,
        "214 Syntax: EPSV [<sp> ALL]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "ERET", 
        globus_l_gsc_cmd_stor_retr,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        3,
        3,
        "214 Syntax: ERET <sp> mod_name=\"mod_parms\" <sp> pathname\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "ESTO", 
        globus_l_gsc_cmd_stor_retr,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        3,
        3,
        "214 Syntax: ESTO <sp> mod_name=\"mod_parms\" <sp> pathname\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "HELP", 
        globus_l_gsc_cmd_help,
        GLOBUS_GSC_COMMAND_PRE_AUTH | 
            GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        2,
        "214 Syntax: HELP [<sp> command]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "MODE", 
        globus_l_gsc_cmd_mode,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: MODE <sp> mode-code\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "NOOP", 
        globus_l_gsc_cmd_noop,
        GLOBUS_GSC_COMMAND_PRE_AUTH | 
            GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: NOOP (no operation)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "OPTS", 
        globus_l_gsc_cmd_opts,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        3,
        "214 Syntax: OPTS <sp> opt-type [paramters]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "PASS", 
        globus_l_gsc_cmd_pass,
        GLOBUS_GSC_COMMAND_PRE_AUTH,
        2,
        2,
        "214 Syntax: PASS <sp> password\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "PASV", 
        globus_l_gsc_cmd_pasv,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: PASS <sp> password\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "PORT", 
        globus_l_gsc_cmd_port,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: PWD (returns current working directory)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "EPRT", 
        globus_l_gsc_cmd_port,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: PWD (returns current working directory)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "SPOR", 
        globus_l_gsc_cmd_port,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: PWD (returns current working directory)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "PWD", 
        globus_l_gsc_cmd_pwd,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: PWD (returns current working directory)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "QUIT", 
        globus_l_gsc_cmd_quit,
        GLOBUS_GSC_COMMAND_PRE_AUTH | 
            GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: QUIT (close control connection)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "RETR", 
        globus_l_gsc_cmd_stor_retr,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: RETR [<sp> pathname]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "SBUF", 
        globus_l_gsc_cmd_sbuf,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: SBUF <sp> window-size\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "SITE", 
        globus_l_gsc_cmd_site,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: SITE <sp> site-command [parameters]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "SIZE", 
        globus_l_gsc_cmd_size,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: SIZE <sp> pathname\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "SPAS", 
        globus_l_gsc_cmd_pasv,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: SPAS\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "STAT", 
        globus_l_gsc_cmd_stat,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        2,
        "214 Syntax: STAT [<sp> pathname]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "STOR", 
        globus_l_gsc_cmd_stor_retr,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: STOR [<sp> pathname]\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "SYST", 
        globus_l_gsc_cmd_syst,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        1,
        1,
        "214 Syntax: SYST (returns system type)\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "TYPE", 
        globus_l_gsc_cmd_type,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: TYPE <sp> type-code\r\n",
        NULL);

    globus_i_gsc_command_add(
        server_handle,
        "USER", 
        globus_l_gsc_cmd_user,
        GLOBUS_GSC_COMMAND_PRE_AUTH,
        2,
        2,
        "214 Syntax: USER <sp> username\r\n",
        NULL);
}

