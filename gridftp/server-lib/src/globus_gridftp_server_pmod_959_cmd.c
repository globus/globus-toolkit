#include "globus_gridftp_server_pmod_959.h"
#include "globus_i_gridftp_server.h"

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
    int                                     success_code;
    char *                                  fail_msg;
    int                                     fail_code;
} globus_l_gs_pmod_959_cmd_wrapper_t;


static void
globus_l_gs_pmod_959_cmd_noop_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    globus_list_t *                         list,
    void *                                  user_arg)
{
    globus_gs_pmod_959_op_t                 op;

    op = (globus_gs_pmod_959_op_t) user_arg;

    globus_gs_pmod_959_finished_op(op, 200, "NOOP command successful.");
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
        op);
}

static void
globus_l_gs_pmod_959_cmd_basic_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    globus_list_t *                         list,
    void *                                  user_arg)
{
    globus_l_gs_pmod_959_cmd_wrapper_t *    wrapper;
    int                                     code;
    char *                                  msg;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) user_arg;

    if(result == GLOBUS_SUCCESS)
    {
        msg = wrapper->success_msg;
        code = wrapper->success_code;
    }
    else
    {
        if(globus_error_match(
            globus_error_peek(result), 
            GLOBUS_GRIDFTP_SERVER_MODULE, GLOBUS_GRIDFTP_SERVER_NO_AUTH))
        {
            code = 530;
            msg = "Please login with USER and PASS.";
        }   
        else if(globus_error_match(
            globus_error_peek(result), 
            GLOBUS_GRIDFTP_SERVER_MODULE, GLOBUS_GRIDFTP_SERVER_POST_AUTH))
        {
            code = 503;
            msg = "You are already logged in!";
        }
        else
        {
            msg = wrapper->fail_msg;
            code = wrapper->fail_code;
        }
    }
    globus_gs_pmod_959_finished_op(wrapper->op, code, msg);

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
    globus_list_t *                         list = NULL;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    globus_gs_pmod_959_get_server(&server, handle);

    sscanf(full_command, "%*s %c", &ch);

    wrapper->fail_msg = globus_common_create_string(
        "'%s' unrecognized transfer mode.", full_command);
    wrapper->fail_code = 501;
    wrapper->success_msg = globus_common_create_string(
        "Mode set to %c.", ch);
    wrapper->success_code = 200;

    globus_list_insert(&list, (void *)ch);

    globus_gridftp_server_pmod_command(
        server,
        "MODE",
        globus_l_gs_pmod_959_cmd_basic_cb,
        list,
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
    globus_list_t *                         list = NULL;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    globus_gs_pmod_959_get_server(&server, handle);

    sscanf(full_command, "%*s %c", &ch);

    wrapper->fail_msg = globus_common_create_string(
        "'%s' not understood.", full_command);
    wrapper->fail_code = 500;
    wrapper->success_msg = globus_common_create_string(
        "Type set to %c.", ch);
    wrapper->success_code = 200;

    globus_list_insert(&list, (void *)ch);
    globus_gridftp_server_pmod_command(
        server,
        "TYPE",
        globus_l_gs_pmod_959_cmd_basic_cb,
        list,
        wrapper);
}

/*
 *  stat and size
 */
static void
globus_l_gs_pmod_959_cmd_stat_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    globus_list_t *                         list,
    void *                                  user_arg)
{
    globus_gridftp_server_stat_t *          stat_info;
    int                                     stat_count;
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
    globus_list_t *                         list = NULL;
    /* these are really just place holders in the list */
    globus_gridftp_server_stat_t *          stat_info;
    int                                     stat_count;

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;

    globus_list_insert(&list, stat_count);
    globus_list_insert(&list, stat_info);

    globus_gridftp_server_pmod_command(
        server,
        "STAT",
        globus_l_gs_pmod_959_cmd_stat_cb,
        list,
        wrapper);
}

/*
 *  quit
 */
static void
globus_l_gs_pmod_959_cmd_quit_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    globus_list_t *                         list,
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
        msg = globus_libc_strdup("Goodbye");
    }
    else
    {
        msg = globus_libc_strdup("Say goodbye next time.");
    }

    globus_gs_pmod_959_finished_op(wrapper->op, 221, msg);
}

static void
globus_l_gs_pmod_959_cmd_quit(
    globus_gs_pmod_959_handle_t             handle,
    globus_gs_pmod_959_op_t                 op,
    const char *                            command_name,
    const char *                            full_command,
    void *                                  user_arg)
{
    globus_result_t                         res;
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

    cmd_handle = (globus_l_gs_pmod_959_cmd_handle_t *) user_arg;

    if(cmd_handle->username != NULL)
    {
        globus_free(cmd_handle->username);
    }

    cmd_handle->username = globus_malloc(strlen(full_command));
    sscanf(full_command, "%*s %s", cmd_handle->username);

    msg = globus_common_create_string(
        "Password required for %s.", cmd_handle->username);

    globus_gs_pmod_959_finished_op(op, 331, msg);

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
    globus_list_t *                         list = NULL;

    cmd_handle = (globus_l_gs_pmod_959_cmd_handle_t *) user_arg;

    /*
     *  if user name has not yet been supplied return error message
     */
    if(cmd_handle->username == NULL)
    {
        globus_gs_pmod_959_finished_op(op, 503, "Login with USER first.");
        return;
    }

    globus_gs_pmod_959_get_server(&server, handle);
    globus_gs_pmod_959_get_cred(handle, &cred, &del_cred);

    pass = globus_malloc(strlen(full_command));
    sscanf(full_command, "%*s %s", pass);

    wrapper = (globus_l_gs_pmod_959_cmd_wrapper_t *) globus_malloc(
        sizeof(globus_l_gs_pmod_959_cmd_wrapper_t));
    wrapper->op = op;
    wrapper->fail_msg = globus_common_create_string("Login incorrect.");
    wrapper->fail_code = 530;
    wrapper->success_msg = globus_common_create_string(
        "User logged in, proceed.");
    wrapper->success_code = 230;

    globus_list_insert(&list, del_cred);
    globus_list_insert(&list, cred);
    globus_list_insert(&list, pass);
    globus_list_insert(&list, cmd_handle->username);

    globus_gridftp_server_pmod_command(
        server,
        "AUTH",
        globus_l_gs_pmod_959_cmd_basic_cb,
        list,
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
        globus_l_gs_pmod_959_cmd_stat,
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
