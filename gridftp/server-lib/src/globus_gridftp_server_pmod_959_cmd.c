#include "globus_gridftp_server_pmod_959.h"
#include "globus_i_gridftp_server.h"
#include "globus_gridftp_server.h"
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 *  These commands will only come in one at a time
 */

typedef struct globus_l_gs_pmod_959_cmd_handle_s
{
    char *                                  username;
} globus_l_gs_pmod_959_cmd_handle_t;


typedef struct globus_l_gs_pmod_959_cmd_wrapper_s
{
    globus_gs_pmod_959_op_t                 op;
    char *                                  success_msg;
    char *                                  fail_msg;
    char *                                  strarg;
} globus_l_gs_pmod_959_cmd_wrapper_t;


static void
globus_l_gs_pmod_959_cmd_noop_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg)
{
    globus_gs_pmod_959_op_t                 op;

    op = (globus_gs_pmod_959_op_t) user_arg;

    globus_gs_pmod_959_finished_op(op, "200 NOOP command successful.\r\n");
}

static void
globus_l_gs_pmod_959_cmd_noop(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_gridftp_server_t                 server;

    globus_gs_pmod_959_get_server(&server, handle);

    globus_gridftp_server_pmod_command(
        server,
        "NOOP",
        globus_l_gs_pmod_959_cmd_noop_cb,
        NULL,
        0,
        op);
}

static void
globus_l_gs_pmod_959_cmd_basic_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    char *                                  msg;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) user_arg;

    if(result == GLOBUS_SUCCESS)
    {
        msg = wrapper->success_msg;
    }
    else
    {
        if(globus_error_match(
            globus_error_peek(result), 
            GLOBUS_GRIDFTP_SERVER_MODULE, GLOBUS_GRIDFTP_SERVER_NO_AUTH))
        {
            msg = "530 Please login with USER and PASS.\r\n";
        }   
        else if(globus_error_match(
            globus_error_peek(result), 
            GLOBUS_GRIDFTP_SERVER_MODULE, GLOBUS_GRIDFTP_SERVER_POST_AUTH))
        {
            msg = "503 You are already logged in!\r\n";
        }
        else
        {
            msg = wrapper->fail_msg;
        }
    }
    globus_gs_pmod_959_finished_op(wrapper->op, msg);

    globus_free(wrapper->fail_msg);
    globus_free(wrapper->success_msg);
    globus_free(wrapper);
}

static void
globus_l_gs_pmod_959_cmd_mode(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_gridftp_server_t                 server;
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    char                                    ch;
    void *                                  list[1];

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    globus_gs_pmod_959_get_server(&server, handle);

    sscanf(full_command, "%*s %c", &ch);

    wrapper->fail_msg = globus_common_create_string(
        "501 '%s' unrecognized transfer mode.\r\n", full_command);
    wrapper->success_msg = globus_common_create_string(
        "200 Mode set to %c.\r\n", ch);

    list[0] = (void *) ch;

    globus_gridftp_server_pmod_command(
        server,
        "MODE",
        globus_l_gs_pmod_959_cmd_basic_cb,
        list,
        1,
        wrapper);
}

static void
globus_l_gs_pmod_959_cmd_type(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_gridftp_server_t                 server;
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    char                                    ch;
    void *                                  list[1];

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    globus_gs_pmod_959_get_server(&server, handle);

    sscanf(full_command, "%*s %c", &ch);

    wrapper->fail_msg = globus_common_create_string(
        "500 '%s' not understood.\r\n", full_command);
    wrapper->success_msg = globus_common_create_string(
        "200 Type set to %c.\r\n", ch);

    list[0] = (void *) ch;
    globus_gridftp_server_pmod_command(
        server,
        "TYPE",
        globus_l_gs_pmod_959_cmd_basic_cb,
        list,
        1,
        wrapper);
}

char *
globus_l_gs_pmod_959_ls_line(
    globus_gridftp_server_stat_t *          stat_info,
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
    pw = getpwuid(stat_info->st_uid);
    gr = getgrgid(stat_info->st_gid);

    if(S_ISDIR(stat_info->st_mode))
    {
        perms[0] = 'd';
    }
    else if(S_ISLNK(stat_info->st_mode))
    {
        perms[0] = 'l';
    }
    else if(S_ISFIFO(stat_info->st_mode))
    {
        perms[0] = 'x';
    }
    else if(S_ISCHR(stat_info->st_mode))
    {
        perms[0] = 'c';
    }
    else if(S_ISBLK(stat_info->st_mode))
    {
        perms[0] = 'b';
    }

    if(S_IRUSR & stat_info->st_mode)
    {
        perms[1] = 'r';
    }
    if(S_IWUSR & stat_info->st_mode)
    {
        perms[2] = 'w';
    }
    if(S_IXUSR & stat_info->st_mode)
    {
        perms[3] = 'x';
    }
    if(S_IRGRP & stat_info->st_mode)
    {
        perms[4] = 'r';
    }
    if(S_IWGRP & stat_info->st_mode)
    {
        perms[5] = 'w';
    }
    if(S_IXGRP & stat_info->st_mode)
    {
        perms[6] = 'x';
    }
    if(S_IROTH & stat_info->st_mode)
    {
        perms[7] = 'r';
    }
    if(S_IWOTH & stat_info->st_mode)
    {
        perms[8] = 'w';
    }
    if(S_IXOTH & stat_info->st_mode)
    {
        perms[9] = 'x';
    }

    tmp_ptr = globus_common_create_string(
        " %s %d %s %s %ld %s %2d %02d:%02d %s\r\n",
        perms,
        stat_info->st_nlink,
        pw->pw_name,
        gr->gr_name,
        stat_info->st_size,
        month_lookup[tm->tm_mon],
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        path);

    return tmp_ptr;
}

/*
 *  stat 
 */
static void
globus_l_gs_pmod_959_cmd_stat_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  path;
    globus_size_t                           msg_size;
    globus_size_t                           msg_ndx = 0;
    char *                                  msg;
    char *                                  tmp_ptr;
    globus_gridftp_server_stat_t *          stat_info;
    int                                     ctr;
    int                                     stat_count;
    char *                                  end_tok = "213 End of Status\r\n";
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        globus_gs_pmod_959_finished_op(wrapper->op, "500 Command failed\r\n");

        return;
    }
    stat_info = (globus_gridftp_server_stat_t *) argv[0];
    stat_count = argv[1];
    path = wrapper->strarg;

    msg_size = (stat_count + 2) * 80;
    msg = globus_malloc(msg_size);

    sprintf(msg, "213-status of %s\r\n", path);

    for(ctr = 0; ctr < stat_count; ctr++)
    {
        tmp_ptr = globus_l_gs_pmod_959_ls_line(&stat_info[ctr], path);
        if(msg_ndx + strlen(tmp_ptr) > msg_size)
        {
            msg_size = (msg_size + strlen(tmp_ptr)) * 2;
            msg = globus_libc_realloc(msg, msg_size);
        }

        strcat(msg, tmp_ptr);
        msg_ndx += strlen(tmp_ptr);
        globus_free(tmp_ptr);
    }

    if(msg_ndx + sizeof(end_tok) > msg_size)
    {
        msg_size *= 2;
        msg = globus_libc_realloc(msg, msg_size);
    } 
    strcat(msg, end_tok);

    globus_free(wrapper->strarg);
    /* build the reply */
    globus_gs_pmod_959_finished_op(wrapper->op, msg);
}

static void
globus_l_gs_pmod_959_cmd_stat(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    globus_gridftp_server_t                 server;
    /* these are really just place holders in the list */
    char *                                  path;
    int                                     mask = 0;
    int                                     sc;
    void *                                  argv[2];
    char *                                  status;
    char *                                  msg;
    globus_result_t                         res;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    path = (char *) globus_malloc(strlen(full_command));
    sc = sscanf(full_command, "%*s %s", path);
    wrapper->strarg = path;

    if(sc < 1)
    {
        globus_free(path);
        path = NULL;
    }

    argv[0] = path;
    argv[1] = mask;

    globus_gs_pmod_959_get_server(&server, handle);
    if(path == NULL)
    {
        res = globus_gridftp_server_get_status(server, &status);
        if(res != GLOBUS_SUCCESS)
        {
            msg = "500 Command Failed\r\n";
        }
        else
        {
            msg = globus_common_create_string(
                    "212 %s\r\n",
                    status);
        }
        globus_gs_pmod_959_finished_op(wrapper->op, msg);
    }
    else
    {
        globus_gridftp_server_pmod_command(
            server,
            "STAT",
            globus_l_gs_pmod_959_cmd_stat_cb,
            argv,
            2,
            wrapper);
    }
}

/*
 *  size
 */
static void
globus_l_gs_pmod_959_cmd_size_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    globus_gridftp_server_stat_t *          stat_info;
    int                                     ctr;
    int                                     stat_count;
    char *                                  path;
    char *                                  msg;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) user_arg;
                                                                                
    if(result != GLOBUS_SUCCESS)
    {
        globus_gs_pmod_959_finished_op(wrapper->op, "500 Command failed\r\n");
                                                                                
        return;
    }
    stat_info = (globus_gridftp_server_stat_t *) argv[0];
    stat_count = argv[1];
    path = wrapper->strarg;

    /* stat count should only be 1, but this is hard to insist upon */

    msg = globus_common_create_string("213 %d\r\n", stat_info->st_size);

    globus_gs_pmod_959_finished_op(wrapper->op, msg);

    globus_free(msg);
}

static void
globus_l_gs_pmod_959_cmd_size(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    globus_gridftp_server_t                 server;
    /* these are really just place holders in the list */
    char *                                  path;
    int                                     mask = 0;
    int                                     sc;
    void *                                  argv[2];
    char *                                  status;
    char *                                  msg;
    globus_result_t                         res;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    path = (char *) globus_malloc(strlen(full_command));
    sc = sscanf(full_command, "%*s %s", path);
    wrapper->strarg = path;

    if(sc < 1)
    {
        globus_free(path);
        path = NULL;
    }

    argv[0] = path;
    argv[1] = mask;

    globus_gs_pmod_959_get_server(&server, handle);
    if(path == NULL)
    {
        globus_gs_pmod_959_finished_op(wrapper->op, "500 Command Failed\r\n");
    }
    else
    {
        globus_gridftp_server_pmod_command(
            server,
            "STAT",
            globus_l_gs_pmod_959_cmd_size_cb,
            argv,
            2,
            wrapper);
    }
}

/*
 *  quit
 */
static void
globus_l_gs_pmod_959_cmd_quit_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg)
{
    char *                                  msg;
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) user_arg;

    globus_gridftp_server_pmod_done(
        server,
        result);

    if(result == GLOBUS_SUCCESS)
    {
        msg = globus_libc_strdup("221 Goodbye\r\n");
    }
    else
    {
        msg = globus_libc_strdup("221 Say goodbye next time.\r\n");
    }

    globus_gs_pmod_959_finished_op(wrapper->op, msg);
}

static void
globus_l_gs_pmod_959_cmd_quit(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    globus_gridftp_server_t                 server;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    globus_gs_pmod_959_get_server(&server, handle);

    globus_gridftp_server_pmod_command(
        server,
        "QUIT",
        globus_l_gs_pmod_959_cmd_quit_cb,
        NULL,
        0,
        wrapper);
}

/*
 *  authentication commands
 *
 *   USER and PASS
 */
static void
globus_l_gs_pmod_959_cmd_user(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_handle_t *     cmd_handle;
    char *                                  msg;
    int                                     sc;

    cmd_handle = (globus_l_gs_pmod_959_cmd_handle_t *) user_arg;

    if(cmd_handle->username != NULL)
    {
        globus_free(cmd_handle->username);
    }

    cmd_handle->username = globus_malloc(strlen(full_command));
    sc = sscanf(full_command, "%*s %s", cmd_handle->username);

    if(sc == 1)
    {
        msg = globus_common_create_string(
            "331 Password required for %s.\r\n", cmd_handle->username);
        globus_gs_pmod_959_finished_op(op, msg);
    }
    else
    {
        globus_free(cmd_handle->username);
        cmd_handle->username = NULL;
        msg = globus_common_create_string(
            "500 \'USER\': command requires a parameter.\r\n");
        globus_gs_pmod_959_finished_op(op, msg);
    }

    globus_free(msg);
}

static void
globus_l_gs_pmod_959_cmd_pass(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_gridftp_server_t                 server;
    globus_l_gs_pmod_959_cmd_handle_t *     cmd_handle;
    char *                                  pass;
    gss_cred_id_t                           cred;
    gss_cred_id_t                           del_cred;
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    void *                                  argv[4];

    cmd_handle = (globus_l_gs_pmod_959_cmd_handle_t *) user_arg;

    /*
     *  if user name has not yet been supplied return error message
     */
    if(cmd_handle->username == NULL)
    {
        globus_gs_pmod_959_finished_op(op, "503 Login with USER first.\r\n");
        return;
    }

    globus_gs_pmod_959_get_server(&server, handle);
    globus_gs_pmod_959_get_cred(handle, &cred, &del_cred);

    pass = globus_malloc(strlen(full_command));
    sscanf(full_command, "%*s %s", pass);

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;
    wrapper->fail_msg = globus_common_create_string("530 Login incorrect.\r\n");
    wrapper->success_msg = globus_common_create_string(
        "230 User logged in, proceed.\r\n");

    argv[0] = cmd_handle->username;
    argv[1] = pass;
    argv[2] = cred;
    argv[3] = del_cred;

    globus_gridftp_server_pmod_command(
        server,
        "AUTH",
        globus_l_gs_pmod_959_cmd_basic_cb,
        argv,
        4,
        wrapper);
}

void
globus_i_gs_pmod_959_add_commands(
    globus_gs_pmod_959_handle_t             handle)
{
    globus_l_gs_pmod_959_cmd_handle_t *     cmd_handle;

    cmd_handle = (globus_l_gs_pmod_959_cmd_handle_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_handle_t));
    cmd_handle->username = NULL;

    globus_gs_pmod_959_command_add(
        handle,
        "NOOP", 
        globus_l_gs_pmod_959_cmd_noop,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "MODE", 
        globus_l_gs_pmod_959_cmd_mode,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "TYPE", 
        globus_l_gs_pmod_959_cmd_type,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "QUIT", 
        globus_l_gs_pmod_959_cmd_quit,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "STAT", 
        globus_l_gs_pmod_959_cmd_stat,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "SIZE", 
        globus_l_gs_pmod_959_cmd_size,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "USER", 
        globus_l_gs_pmod_959_cmd_user,
        cmd_handle);

    globus_gs_pmod_959_command_add(
        handle,
        "PASS", 
        globus_l_gs_pmod_959_cmd_pass,
        cmd_handle);
}
