#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server.h"
#include <grp.h>

typedef struct
{
    globus_xio_handle_t                 xio_handle;
    char *                              remote_contact;
    char *                              local_contact;

    char *                              rnfr_pathname;

    globus_i_gfs_server_close_cb_t      close_func;
    void *                              close_arg;

    void *                              session_arg;

    globus_gridftp_server_control_t     server_handle;
} globus_l_gfs_server_instance_t;

typedef struct
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gridftp_server_control_op_t  control_op;
    void *                              event_arg;
    void *                              info;
    globus_bool_t                       transfer_events;
} globus_l_gfs_request_info_t;

typedef struct globus_l_gfs_auth_info_s
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gridftp_server_control_op_t  control_op;
    globus_gfs_session_info_t *         session_info;
} globus_l_gfs_auth_info_t;

static globus_bool_t                    globus_l_gfs_control_active = GLOBUS_FALSE;
static globus_list_t *                  globus_l_gfs_server_handle_list;
static globus_mutex_t                   globus_l_gfs_control_mutex;

char *
globus_i_gsc_string_to_959(
    int                                 code,
    const char *                        in_str, 
    const char *                        preline);

void
globus_i_gfs_control_init()
{
    globus_l_gfs_server_handle_list = NULL;
    globus_mutex_init(&globus_l_gfs_control_mutex, NULL);
    globus_l_gfs_control_active = GLOBUS_TRUE;
}

void
globus_i_gfs_control_stop()
{
    globus_list_t *                     list;
    globus_l_gfs_server_instance_t *    instance;

    globus_mutex_lock(&globus_l_gfs_control_mutex);
    {
        globus_l_gfs_control_active = GLOBUS_FALSE;

        for(list = globus_l_gfs_server_handle_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            instance = (globus_l_gfs_server_instance_t *) 
                globus_list_first(list);

            globus_gridftp_server_control_stop(instance->server_handle);
        }
    }
    globus_mutex_unlock(&globus_l_gfs_control_mutex);
}

static
globus_result_t
globus_l_gfs_request_info_init(
    globus_l_gfs_request_info_t **      u_request,
    globus_l_gfs_server_instance_t *    instance,
    globus_gridftp_server_control_op_t  control_op,
    void *                              info_struct)
{
    globus_result_t                     result;
    globus_l_gfs_request_info_t *       request;
    GlobusGFSName(globus_l_gfs_request_info_init);

    request = (globus_l_gfs_request_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_request_info_t));
    if(request == NULL)
    {
        result = GlobusGFSErrorMemory("request");
        goto error;
    }
    
    request->control_op = control_op;
    request->instance = instance;
    request->info = info_struct;
    request->transfer_events = GLOBUS_FALSE;

    *u_request = request;
    return GLOBUS_SUCCESS;

error:
    return result;
}

static
void
globus_l_gfs_request_info_destroy(
    globus_l_gfs_request_info_t *       request)
{
    globus_free(request);
}

static
globus_result_t
globus_l_gfs_get_full_path(
    globus_l_gfs_server_instance_t *        instance,
    const char *                            in_path,
    char **                                 out_path)
{
    GlobusGFSName(globus_l_gfs_get_full_path);
    globus_result_t                         result;
    char                                    path[MAXPATHLEN];
    char *                                  cwd = GLOBUS_NULL;
    int                                     cwd_len;

    if(!in_path)
    {
        result = GlobusGFSErrorGeneric("invalid pathname");
        goto done;
    }
    if(*in_path == '/')
    {
        strncpy(path, in_path, sizeof(path));
    }
    else
    {
        result = globus_gridftp_server_control_get_cwd(
            instance->server_handle, &cwd);
        if(result != GLOBUS_SUCCESS || cwd == GLOBUS_NULL)
        {
            result = GlobusGFSErrorGeneric("invalid cwd");
            goto done;
        }
        cwd_len = strlen(cwd);
        if(cwd[cwd_len - 1] == '/')
        {
            cwd[--cwd_len] = '\0';
        }
        snprintf(path, sizeof(path), "%s/%s", cwd, in_path);
        globus_free(cwd);
    }
    path[MAXPATHLEN - 1] = '\0';

    *out_path = globus_libc_strdup(path);

    return GLOBUS_SUCCESS;

done:
    return result;
}

static
void
globus_l_gfs_channel_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;


    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO,
        "Closed connection from %s\n",
        instance->remote_contact);

    globus_i_gfs_data_session_stop(NULL, instance->session_arg);
    if(instance->close_func)
    {
        instance->close_func(instance->close_arg);
    }
    globus_free(instance->local_contact);
    globus_free(instance->remote_contact);
    globus_free(instance);
}

static
void
globus_l_gfs_done_cb(
    globus_gridftp_server_control_t     server,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_done_cb);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_gridftp_server_control_destroy(instance->server_handle);

    globus_mutex_lock(&globus_l_gfs_control_mutex);
    {
        globus_list_remove(&globus_l_gfs_server_handle_list,
            globus_list_search(globus_l_gfs_server_handle_list, instance));
    }
    globus_mutex_unlock(&globus_l_gfs_control_mutex);

    if(result != GLOBUS_SUCCESS)
    {
        char *                          tmp_str;

        tmp_str = globus_error_print_friendly(globus_error_peek(result));
        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "Control connection closed with error: %s\n",
             tmp_str);
        globus_free(tmp_str);
    }
    else
    {
        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "Control connection closed\n");
    }
    result = globus_xio_register_close(
        instance->xio_handle,
        GLOBUS_NULL,
        globus_l_gfs_channel_close_cb,
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_channel_close_cb(
            instance->xio_handle,
            GLOBUS_SUCCESS,
            instance);
    }
}


static
void
globus_l_gfs_auth_session_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_l_gfs_auth_info_t *          auth_info;
    char *                              tmp_str;
    GlobusGFSName(globus_l_gfs_auth_session_cb);

    auth_info = (globus_l_gfs_auth_info_t *) user_arg;

    auth_info->instance->session_arg = reply->session_arg;
    if(reply->result != GLOBUS_SUCCESS)
    {
        tmp_str = globus_error_print_friendly(
            globus_error_peek(reply->result));
        globus_gridftp_server_control_finished_auth(
            auth_info->control_op,
            NULL,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            tmp_str);
        globus_free(tmp_str);
    }
    else
    {
        globus_gridftp_server_control_finished_auth(
            auth_info->control_op,
            auth_info->session_info->username,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            NULL);
    }
    globus_free(auth_info->session_info->username);
    if(auth_info->session_info->password != NULL)
    {
        globus_free(auth_info->session_info->password);
    }
    if(auth_info->session_info->subject != NULL)
    {
        globus_free(auth_info->session_info->subject);
    }
    globus_free(auth_info->session_info);
    globus_free(auth_info);
}


static
void
globus_l_gfs_request_auth(
    globus_gridftp_server_control_op_t  control_op,
    globus_gridftp_server_control_security_type_t secure_type,
    gss_ctx_id_t                        context,
    const char *                        subject,
    const char *                        user_name,
    const char *                        pw,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_session_info_t *         session_info;
    globus_l_gfs_auth_info_t *          auth_info;
    globus_l_gfs_server_instance_t *    instance;

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    session_info = (globus_gfs_session_info_t *)
        calloc(1, sizeof(globus_gfs_session_info_t));
    if(session_info == NULL)
    {
        goto session_error;
    }

    result = globus_gridftp_server_control_get_data_auth(
        control_op,
        NULL,
        NULL,
        NULL,
        &session_info->del_cred);
    if(result != GLOBUS_SUCCESS)
    {
        goto del_error;
    }
    session_info->username = strdup(user_name);
    if(session_info->username == NULL)
    {
        goto del_error;
    }
    if(pw != NULL)
    {
        session_info->password = strdup(pw);
        if(session_info->password == NULL)
        {
            goto user_error;
        }
    }
    if(subject != NULL)
    {
        session_info->subject = strdup(subject);
        if(session_info->password == NULL)
        {
            goto user_error;
        }
    }

    auth_info = (globus_l_gfs_auth_info_t *) calloc(1,
        sizeof(globus_l_gfs_auth_info_t));
    if(auth_info == NULL)
    {
        goto pw_error;
    }
    auth_info->instance = instance;
    auth_info->control_op = control_op;
    auth_info->session_info = session_info;

    globus_i_gfs_data_session_start(
        NULL,
        context,
        session_info,
        globus_l_gfs_auth_session_cb,
        auth_info);

    return;

pw_error:
    globus_free(session_info->password);
user_error:
    globus_free(session_info->username);
del_error:
    globus_free(session_info);
session_error:
    globus_gridftp_server_control_finished_auth(
        control_op,
        NULL,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_PANIC,
        "internal error: session_cb");
}

static
void
globus_l_gfs_data_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    char *                              tmp_str;
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    globus_gfs_stat_info_t *            info;
    GlobusGFSName(globus_l_gfs_data_stat_cb);
    
    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    globus_assert(op != NULL);
    if(reply->result != GLOBUS_SUCCESS)
    {
        tmp_str = globus_error_print_friendly(globus_error_peek(reply->result));
        globus_gridftp_server_control_finished_resource(
            op,
            reply->info.stat.stat_array,
            reply->info.stat.stat_count,
            reply->info.stat.uid,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            tmp_str);
        globus_free(tmp_str);
    }
    else
    {
        globus_gridftp_server_control_finished_resource(
            op,
            reply->info.stat.stat_array,
            reply->info.stat.stat_count,
            reply->info.stat.uid,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
    }
    
    info = (globus_gfs_stat_info_t *) request->info;
    if(info)
    {
        if(info->pathname)
        {
            globus_free(info->pathname);
        }
        globus_free(info);
    }
    globus_l_gfs_request_info_destroy(request);
}

static
void
globus_l_gfs_request_stat(
    globus_gridftp_server_control_op_t  op,
    const char *                        path,
    globus_gridftp_server_control_resource_mask_t mask,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_stat_info_t *            stat_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_stat);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    stat_info = (globus_gfs_stat_info_t *) 
        globus_calloc(1, sizeof(globus_gfs_stat_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, stat_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    globus_l_gfs_get_full_path(instance, path, &stat_info->pathname);
    stat_info->file_only =
        (mask & GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_FILE_ONLY) ?
            GLOBUS_TRUE : GLOBUS_FALSE;

    globus_i_gfs_data_request_stat(
        NULL,
        instance->session_arg,
        0,
        stat_info,
        globus_l_gfs_data_stat_cb,
        request);

    return;
    
error_init:
    /* finish here */
    return;
}

static
void
globus_l_gfs_data_command_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    char *                              msg;
    char *                              tmp_msg;
    globus_l_gfs_request_info_t *       request;
    globus_gfs_command_info_t *         info;
    GlobusGFSName(globus_l_gfs_data_command_cb);

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result == GLOBUS_SUCCESS)
    {
        switch(reply->info.command.command)
        {
          case GLOBUS_GFS_CMD_RMD:
          case GLOBUS_GFS_CMD_DELE:
          case GLOBUS_GFS_CMD_RNTO:
          case GLOBUS_GFS_CMD_SITE_CHMOD:
            globus_gsc_959_finished_command(op, "250 OK.\r\n");
            break;
          case GLOBUS_GFS_CMD_MKD:
            msg = globus_common_create_string(
                "257 Directory \"%s\" created successfully.\r\n",
                reply->info.command.created_dir);
            globus_gsc_959_finished_command(op, msg);
            globus_free(msg);
            break;
          case GLOBUS_GFS_CMD_RNFR:
            globus_gsc_959_finished_command(op, "350 Waiting for RNTO.\r\n");
            break;
          case GLOBUS_GFS_CMD_CKSM:
            msg = globus_common_create_string(
                "213 %s\r\n", reply->info.command.checksum);
            globus_gsc_959_finished_command(op, msg);
            globus_free(msg);
            break;

          default:
            globus_gsc_959_finished_command(op, "500 Unknown error.\r\n");
            break;
        }
    }
    else
    {
        msg = globus_error_print_friendly(
            globus_error_peek(reply->result));
        tmp_msg = globus_common_create_string("Command failed : %s", msg);
        globus_free(msg);
        msg = globus_i_gsc_string_to_959(500, tmp_msg, NULL);
        globus_gsc_959_finished_command(op, msg);
        globus_free(tmp_msg);
        globus_free(msg);
    }
    
    info = (globus_gfs_command_info_t *) request->info;
    if(info)
    {
        if(info->pathname)
        {
            globus_free(info->pathname);
        }
        if(info->cksm_alg)
        {
            globus_free(info->cksm_alg);
        }
        if(info->rnfr_pathname)
        {
            globus_free(info->rnfr_pathname);
        }
        globus_free(info);
    }
    globus_l_gfs_request_info_destroy(request);
}

static
void
globus_l_gfs_request_command(
    globus_gsc_959_op_t                 op,
    const char *                        full_command,
    char **                             cmd_array,
    int                                 argc,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_command_info_t *         command_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_command);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    command_info = (globus_gfs_command_info_t *) 
        globus_calloc(1, sizeof(globus_gfs_command_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, command_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    if(strcmp(cmd_array[0], "MKD") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_MKD;
        globus_l_gfs_get_full_path(
            instance, cmd_array[1], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
    }
    else if(strcmp(cmd_array[0], "RMD") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_RMD;
        globus_l_gfs_get_full_path(
            instance, cmd_array[1], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
    }
    else if(strcmp(cmd_array[0], "DELE") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_DELE;
        globus_l_gfs_get_full_path(
            instance, cmd_array[1], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
    }
    else if(strcmp(cmd_array[0], "RNFR") == 0)
    {
        /* XXX */
        command_info->command = GLOBUS_GFS_CMD_RNFR;
        globus_l_gfs_get_full_path(
            instance, cmd_array[1], &command_info->pathname);
        instance->rnfr_pathname = globus_libc_strdup(command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
        globus_gsc_959_finished_command(op,
            "200 OK.\r\n");
        return;
    }
    else if(strcmp(cmd_array[0], "RNTO") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_RNTO;
        globus_l_gfs_get_full_path(
            instance, cmd_array[1], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
        if(instance->rnfr_pathname == GLOBUS_NULL)
        {
            goto err;
        }
        command_info->rnfr_pathname = instance->rnfr_pathname;
        instance->rnfr_pathname = GLOBUS_NULL;
    }
    else if(strcmp(cmd_array[0], "CKSM") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_CKSM;
        globus_l_gfs_get_full_path(
            instance, cmd_array[4], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
        command_info->cksm_alg = globus_libc_strdup(cmd_array[1]);
        globus_libc_scan_off_t(
            cmd_array[2],
            &command_info->cksm_offset,
            GLOBUS_NULL);
        globus_libc_scan_off_t(
            cmd_array[3],
            &command_info->cksm_length,
            GLOBUS_NULL);

    }
    else if(strcmp(cmd_array[0], "SITE") == 0 &&
        strcmp(cmd_array[1], "CHMOD") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_SITE_CHMOD;
        globus_l_gfs_get_full_path(
            instance, cmd_array[3], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
        command_info->chmod_mode = strtol(cmd_array[2], NULL, 8);
    }
    else if(strcmp(cmd_array[0], "SITE") == 0 &&
        strcmp(cmd_array[1], "DSI") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_SITE_DSI;
        command_info->pathname = strdup(cmd_array[2]);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
    }
    else
    {
        goto err;
    }

    globus_i_gfs_data_request_command(
        NULL,
        instance->session_arg,
        0,
        command_info,
        globus_l_gfs_data_command_cb,
        request);

    return;

err:   
error_init:
    globus_gsc_959_finished_command(op,
        "501 Invalid command arguments.\r\n");

    return;
}

static
void
globus_l_gfs_request_transfer_event(
    globus_gridftp_server_control_op_t  op,
    int                                 event_type,
    void *                              user_arg)
{
    globus_l_gfs_request_info_t *       request;
    globus_gfs_event_info_t             event_info;
    GlobusGFSName(globus_l_gfs_request_transfer_event);

    request = (globus_l_gfs_request_info_t *) user_arg;

    memset(&event_info, '\0', sizeof(globus_gfs_event_info_t));
    event_info.event_arg = request->event_arg;

    switch(event_type)
    {
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF:
            event_info.type = GLOBUS_GFS_EVENT_BYTES_RECVD;
            break;
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART:
            event_info.type = GLOBUS_GFS_EVENT_RANGES_RECVD;
            break;
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT:
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_ABORT;
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO,
                "Requesting abort...\n");
            break;
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_TRANSFER_COMPLETE:
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
            break;
        default:
            goto error;
            break;
    }

    globus_i_gfs_data_request_transfer_event(
        NULL,
        request->instance->session_arg,
        &event_info);

    if(event_info.type == GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
    {
        globus_gfs_transfer_info_t *    info;
        info = (globus_gfs_transfer_info_t *) request->info;
        if(info)
        {
            if(info->pathname)
            {
                globus_free(info->pathname);
            }
            if(info->list_type)
            {
                globus_free(info->list_type);
            }
            if(info->module_name)
            {
                globus_free(info->module_name);
            }
            if(info->module_args)
            {
                globus_free(info->module_args);
            }
            globus_free(info);
        }
        globus_l_gfs_request_info_destroy(request);
    }

    return;

error:
    return;
}


static
void
globus_l_gfs_data_event_cb(
    globus_gfs_data_event_reply_t *     reply,
    void *                              user_arg)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    GlobusGFSName(globus_l_gfs_data_event_cb);

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            request->event_arg = reply->event_arg;
            
            request->transfer_events = GLOBUS_TRUE;
            result = globus_gridftp_server_control_events_enable(
                op,
                GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF |
                GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART |
                GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT,
                globus_l_gfs_request_transfer_event,
                request);
            if(result != GLOBUS_SUCCESS)
            {
                request->transfer_events = GLOBUS_FALSE;
                /* TODO: can we ignore this */
            }
            break;
        
        case GLOBUS_GFS_EVENT_TRANSFER_CONNECTED:
            globus_gridftp_server_control_begin_transfer(op);
            break;
        
        case GLOBUS_GFS_EVENT_DISCONNECTED:
            globus_gridftp_server_control_disconnected(
                request->instance->server_handle, 
                reply->data_arg);
            break;
        
        case GLOBUS_GFS_EVENT_BYTES_RECVD:
            globus_gridftp_server_control_event_send_perf(
                op, reply->node_ndx, reply->recvd_bytes);
            break;
        
        case GLOBUS_GFS_EVENT_RANGES_RECVD:
            globus_gridftp_server_control_event_send_restart(
               op, reply->recvd_ranges);
            break;
        
        default:
            globus_assert(0 && "Unexpected event type");
            break;
    }
}

static
void
globus_l_gfs_data_transfer_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    char *                              tmp_str;
    GlobusGFSName(globus_l_gfs_data_transfer_cb);

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result != GLOBUS_SUCCESS)
    {
        tmp_str = globus_error_print_friendly(
            globus_error_peek(reply->result));
        globus_gridftp_server_control_finished_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            tmp_str);
        globus_free(tmp_str);
    }
    else
    {
        globus_gridftp_server_control_finished_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
    }
    if(!request->transfer_events)
    {
        globus_gfs_transfer_info_t *    info;
        info = (globus_gfs_transfer_info_t *) request->info;
        if(info)
        {
            if(info->pathname)
            {
                globus_free(info->pathname);
            }
            if(info->list_type)
            {
                globus_free(info->list_type);
            }
            if(info->module_name)
            {
                globus_free(info->module_name);
            }
            if(info->module_args)
            {
                globus_free(info->module_args);
            }
            globus_free(info);
        }
        globus_l_gfs_request_info_destroy(request);
    }
}

static
void
globus_l_gfs_request_send(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        path,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_range_list_t                 range_list,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_transfer_info_t *        send_info;
    int                                 args;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_send);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    send_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, send_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    if(mod_name && strcmp("P", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT" %"GLOBUS_OFF_T_FORMAT,
            &send_info->partial_offset,
            &send_info->partial_length);

        globus_assert(args == 2);
    }
    else
    {
        send_info->partial_offset = 0;
        send_info->partial_length = -1;
        if(mod_name != NULL)
        {
            send_info->module_name = globus_libc_strdup(mod_name);
        }
        if(mod_parms != NULL)
        {
            send_info->module_args = globus_libc_strdup(mod_parms);
        }
    }

    globus_l_gfs_get_full_path(instance, path, &send_info->pathname);
    send_info->range_list = range_list;
    send_info->stripe_count = 1;
    send_info->node_count = 1;
    send_info->data_arg = data_handle;

    globus_i_gfs_data_request_send(
        NULL,
        instance->session_arg,
        0,
        send_info,
        globus_l_gfs_data_transfer_cb,
        globus_l_gfs_data_event_cb,
        request);

    return;
    
error_init:
    /* finish here */
    return;
}

static
void
globus_l_gfs_request_recv(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        path,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_range_list_t                 range_list,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    int                                 args;
    globus_gfs_transfer_info_t *        recv_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_off_t                        length = GLOBUS_RANGE_LIST_MAX;
    globus_off_t                        offset = 0;
    GlobusGFSName(globus_l_gfs_request_recv);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    recv_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, recv_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    /* if restart range is anything but 0-MAX then we don't trunc the file */
    if(globus_range_list_size(range_list))
    {
        globus_range_list_at(range_list, 0, &offset, &length);
    }
    if(offset == 0 && length == GLOBUS_RANGE_LIST_MAX)
    {
        recv_info->truncate = GLOBUS_TRUE;
    }

    if(mod_name && strcmp("A", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT,
            &recv_info->partial_offset);
        recv_info->partial_length = -1;
        
        /*  ESTO A 0 /file is not the same as STOR /file
            ESTO doesn't truncate the file. 
        */
        recv_info->truncate = GLOBUS_FALSE;

        globus_assert(args == 1);
    }
    else
    {
        recv_info->partial_offset = 0;
        recv_info->partial_length = -1;
        
        if(mod_name != NULL)
        {
            recv_info->module_name = globus_libc_strdup(mod_name);
        }
        if(mod_parms != NULL)
        {
            recv_info->module_args = globus_libc_strdup(mod_parms);
        }
    }
        
    globus_l_gfs_get_full_path(instance, path, &recv_info->pathname);
    recv_info->range_list = range_list;
    recv_info->stripe_count = 1;
    recv_info->node_count = 1;
    recv_info->data_arg = data_handle;

    globus_i_gfs_data_request_recv(
        NULL,
        instance->session_arg,
        0,
        recv_info,
        globus_l_gfs_data_transfer_cb,
        globus_l_gfs_data_event_cb,
        request);

    return;
    
error_init:
    /* finish here */
    return;
}

static
void
globus_l_gfs_request_list(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        path,
    const char *                        list_type,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_transfer_info_t *        list_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_list);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    list_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, list_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    globus_l_gfs_get_full_path(instance, path, &list_info->pathname);
    list_info->list_type = globus_libc_strdup(list_type);
    list_info->data_arg = data_handle;
    list_info->stripe_count = 1;
    list_info->node_count = 1;

    globus_i_gfs_data_request_list(
        NULL,
        instance->session_arg,
        0,
        list_info,
        globus_l_gfs_data_transfer_cb,
        globus_l_gfs_data_event_cb,
        request);

    return;
    
error_init:
    /* finish here */
    return;
}

static
void
globus_l_gfs_data_passive_data_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    globus_gfs_data_info_t *            info;
    char *                              tmp_str;
    GlobusGFSName(globus_l_gfs_data_passive_data_cb);

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result != GLOBUS_SUCCESS)
    {
        tmp_str = globus_error_print_friendly(
            globus_error_peek(reply->result));
        globus_gridftp_server_control_finished_passive_connect(
            op,
            reply->info.data.data_arg,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            reply->info.data.contact_strings,
            reply->info.data.cs_count,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            tmp_str);
        globus_free(tmp_str);
    }
    else
    {
        globus_gridftp_server_control_finished_passive_connect(
            op,
            reply->info.data.data_arg,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            reply->info.data.contact_strings,
            reply->info.data.cs_count,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
    }

    info = (globus_gfs_data_info_t *) request->info;
    if(info)
    {
        if(info->interface)
        {
            globus_free(info->interface);
        }
        if(info->pathname)
        {
            globus_free(info->pathname);
        }
        globus_free(info);
    }
    globus_l_gfs_request_info_destroy(request);
}

static
void
globus_l_gfs_get_data_info(
    globus_gridftp_server_control_op_t  op,
    globus_gfs_data_info_t *            data_info,
    globus_gridftp_server_control_network_protocol_t net_prt)
{
    globus_result_t                     result;
    globus_size_t                       buf_size;

    if(net_prt == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
    {
        data_info->ipv6 = GLOBUS_TRUE;
    }
    else
    {
        data_info->ipv6 = GLOBUS_FALSE;
    }

    result = globus_gridftp_server_control_get_mode(op, &data_info->mode);
    globus_assert(result == GLOBUS_SUCCESS);

    result = globus_gridftp_server_control_get_type(op, &data_info->type);
    globus_assert(result == GLOBUS_SUCCESS);

    result = globus_gridftp_server_control_get_buffer_size(
        op, &data_info->tcp_bufsize, &buf_size);
    globus_assert(result == GLOBUS_SUCCESS);

    if(buf_size > data_info->tcp_bufsize)
    {
        data_info->tcp_bufsize = buf_size;
    }

    result = globus_gridftp_server_control_get_parallelism(
        op, &data_info->nstreams);
    globus_assert(result == GLOBUS_SUCCESS);

    result = globus_gridftp_server_control_get_data_auth(
        op,
        &data_info->subject,
        &data_info->dcau,
        &data_info->prot,
        NULL);
    globus_assert(result == GLOBUS_SUCCESS);

    data_info->blocksize = globus_i_gfs_config_int("blocksize");
    data_info->stripe_blocksize =
        globus_i_gfs_config_int("stripe_blocksize") * data_info->blocksize;

}

static
void
globus_l_gfs_request_passive_data(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    int                                 max,
    const char *                        pathname,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_data_info_t *            data_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_xio_contact_t                parsed_contact;
    GlobusGFSName(globus_l_gfs_passive_data_connect);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    data_info = (globus_gfs_data_info_t *)
        globus_calloc(1, sizeof(globus_gfs_data_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, data_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    globus_l_gfs_get_data_info(op, data_info, net_prt);

    if(pathname)
    {
        globus_l_gfs_get_full_path(instance, pathname, &data_info->pathname);
    }
    globus_xio_contact_parse(&parsed_contact, instance->local_contact);
    data_info->max_cs = max;
    data_info->interface = globus_libc_strdup(parsed_contact.host);
    
    globus_xio_contact_destroy(&parsed_contact);

    globus_i_gfs_data_request_passive(
        NULL,
        instance->session_arg,
        0,
        data_info,
        globus_l_gfs_data_passive_data_cb,
        request);

    return;
    
error_init:
    /* finish here */
    return;
}

static
void
globus_l_gfs_data_active_data_cb(
    globus_gfs_data_reply_t *            reply,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    globus_gfs_data_info_t *            info;
    char *                              tmp_str;
    GlobusGFSName(globus_l_gfs_data_active_data_cb);

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result != GLOBUS_SUCCESS)
    {
        tmp_str = globus_error_print_friendly(
            globus_error_peek(reply->result));
        globus_gridftp_server_control_finished_active_connect(
            op,
            reply->info.data.data_arg,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            tmp_str);
        globus_free(tmp_str);
    }
    else
    {
        globus_gridftp_server_control_finished_active_connect(
            op,
            reply->info.data.data_arg,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
    }

    info = (globus_gfs_data_info_t *) request->info;
    if(info)
    {
        if(info->interface)
        {
            globus_free(info->interface);
        }
        if(info->pathname)
        {
            globus_free(info->pathname);
        }
        globus_free(info);
    }
    globus_l_gfs_request_info_destroy(request);
}

static
void
globus_l_gfs_request_active_data(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    const char **                       cs,
    int                                 cs_count,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_data_info_t *            data_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_xio_contact_t                parsed_contact;
    GlobusGFSName(globus_l_gfs_active_data_connect);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    data_info = (globus_gfs_data_info_t *)
        globus_calloc(1, sizeof(globus_gfs_data_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, data_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    globus_l_gfs_get_data_info(op, data_info, net_prt);
    globus_xio_contact_parse(&parsed_contact, instance->local_contact);

    data_info->contact_strings = cs;
    data_info->cs_count = cs_count;
    data_info->interface = globus_libc_strdup(parsed_contact.host);
    
    globus_xio_contact_destroy(&parsed_contact);
    
    globus_i_gfs_data_request_active(
        NULL,
        instance->session_arg,
        0,
        data_info,
        globus_l_gfs_data_active_data_cb,
        request);

    return;
    
error_init:
    /* finish here */
    return;
}

static
void
globus_l_gfs_request_data_destroy(
    void *                              user_data_arg,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_request_data_destroy);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_i_gfs_data_request_handle_destroy(
        NULL, instance->session_arg, user_data_arg);
}

static
void
globus_l_gfs_control_log(
    globus_gridftp_server_control_t     server_handle,
    const char *                        message,
    int                                 type,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    globus_i_gfs_log_type_t             log_type;

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    if(instance == GLOBUS_NULL)
    {
        return;
    }

    switch(type)
    {
      case GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_REPLY:
        log_type = GLOBUS_I_GFS_LOG_CONTROL;
        globus_i_gfs_log_message(log_type, "%s: [SERVER]: %s",
            instance->remote_contact, message);
        break;
      case GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_ERROR:
        log_type = GLOBUS_I_GFS_LOG_ERR;
        globus_i_gfs_log_message(log_type, "%s: [CLIENT ERROR]: %s",
            instance->remote_contact, message);
         break;
      default:
        log_type = GLOBUS_I_GFS_LOG_CONTROL;
        globus_i_gfs_log_message(log_type, "%s: [CLIENT]: %s",
            instance->remote_contact, message);
         break;
    }

    return;
}


static
globus_result_t
globus_l_gfs_add_commands(
    globus_l_gfs_server_instance_t *    instance,
    globus_gridftp_server_control_t     control_handle)
{
    globus_result_t                     result;

    result = globus_gsc_959_command_add(
        control_handle,
        "MKD",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "MKD <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "RMD",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "RMD <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "DELE",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "DELE <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "SITE CHMOD",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        4,
        4,
        "SITE CHMOD <sp> mode <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "CKSM",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        5,
        5,
        "CKSM <sp> algorithm <sp> offset <sp> length <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "RNFR",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "RNFR <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "RNTO",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "RNTO <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gsc_959_command_add(
        control_handle,
        "SITE DSI",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        3,
        3,
        "SITE DSI <sp> dsi name",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return GLOBUS_SUCCESS;

error:
    return result;
}

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact,
    const char *                        local_contact,
    globus_i_gfs_server_close_cb_t      close_func,
    void *                              close_arg)
{
    GlobusGFSName(globus_i_gfs_control_start);
    globus_result_t                     result;
    globus_gridftp_server_control_attr_t attr;
    globus_l_gfs_server_instance_t *    instance;
    int                                 idle_timeout;
    char *                              banner;
    char *                              login_msg;

    instance = (globus_l_gfs_server_instance_t *)
        globus_calloc(1, sizeof(globus_l_gfs_server_instance_t));
    if(!instance)
    {
        result = GlobusGFSErrorMemory("instance");
        goto error_malloc;
    }

    instance->close_func = close_func;
    instance->close_arg = close_arg;
    instance->xio_handle = handle;
    instance->rnfr_pathname = GLOBUS_NULL;
    instance->remote_contact = globus_libc_strdup(remote_contact);
    if(!instance->remote_contact)
    {
        result = GlobusGFSErrorMemory("remote_contact");
        goto error_strdup;
    }
    instance->local_contact = globus_libc_strdup(local_contact);
    if(!instance->local_contact)
    {
        result = GlobusGFSErrorMemory("local_contact");
        goto error_strdup;
    }

    result = globus_gridftp_server_control_attr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }

    result = globus_gridftp_server_control_attr_set_security(
        attr,
        (globus_i_gfs_config_bool("no_security")) ?
        GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE :
        GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI |
        ((globus_i_gfs_config_bool("allow_anonymous")) ?
        GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE : 0));
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    idle_timeout = globus_i_gfs_config_int("idle_timeout");
    if(idle_timeout)
    {
        result = globus_gridftp_server_control_attr_set_idle_time(
            attr, idle_timeout);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_attr_setup;
        }
    }

    banner = globus_i_gfs_config_string("banner");
    if(banner)
    {
        result = globus_gridftp_server_control_attr_set_banner(
            attr, banner);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_attr_setup;
        }
    }

    login_msg = globus_i_gfs_config_string("login_msg");
    if(login_msg)
    {
        result = globus_gridftp_server_control_attr_set_message(
            attr, login_msg);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_attr_setup;
        }
    }

    result = globus_gridftp_server_control_attr_set_auth(
        attr, globus_l_gfs_request_auth, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_set_resource(
        attr, globus_l_gfs_request_stat, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_recv(
        attr, GLOBUS_NULL, globus_l_gfs_request_recv, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_recv(
        attr, "A", globus_l_gfs_request_recv, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_send(
        attr, GLOBUS_NULL, globus_l_gfs_request_send, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_send(
        attr, "P", globus_l_gfs_request_send, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_set_list(
        attr, globus_l_gfs_request_list, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_data_functions(
        attr,
        globus_l_gfs_request_active_data,
        instance,
        globus_l_gfs_request_passive_data,
        instance,
        globus_l_gfs_request_data_destroy,
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_set_log(
        attr,
        globus_l_gfs_control_log,
        GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_ALL, /* XXX config what-to-log */
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_init(&instance->server_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    result = globus_l_gfs_add_commands(instance, instance->server_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_add_commands;
    }

    globus_mutex_lock(&globus_l_gfs_control_mutex);
    {
        if(!globus_l_gfs_control_active)
        {
            goto error_start;
        }
        result = globus_gridftp_server_control_start(
            instance->server_handle,
            attr,
            system_handle,
            globus_l_gfs_done_cb,
            instance);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_start;
        }
        globus_list_insert(&globus_l_gfs_server_handle_list, instance);
    }
    globus_mutex_unlock(&globus_l_gfs_control_mutex);

    globus_gridftp_server_control_attr_destroy(attr);

    return GLOBUS_SUCCESS;

error_start:
    globus_mutex_unlock(&globus_l_gfs_control_mutex);
error_add_commands:
error_init:
    globus_gridftp_server_control_destroy(instance->server_handle);
error_attr_setup:
    globus_gridftp_server_control_attr_destroy(attr);

error_attr:
    globus_free(instance->remote_contact);
    globus_free(instance->local_contact);

error_strdup:
    globus_free(instance);
error_malloc:
    return result;
}
