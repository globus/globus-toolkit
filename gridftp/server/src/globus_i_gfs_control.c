#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server.h"
#include <grp.h>

#define FTP_SERVICE_NAME "file"

typedef struct
{
    globus_xio_handle_t                 xio_handle;
    char *                              remote_contact;

    char *                              rnfr_pathname;

    globus_i_gfs_server_close_cb_t      close_func;
    void *                              close_arg;

    globus_i_gfs_acl_handle_t           acl_handle;
    int                                 session_id;

    globus_gridftp_server_control_t     server_handle;
} globus_l_gfs_server_instance_t;

typedef struct
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gridftp_server_control_op_t  control_op;
    int                                 transfer_id;
} globus_l_gfs_request_info_t;


static
globus_result_t
globus_l_gfs_request_info_init(
    globus_l_gfs_request_info_t **      u_request,
    globus_l_gfs_server_instance_t *    instance,
    globus_gridftp_server_control_op_t  control_op)
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
    if(request != NULL)
    {
        globus_free(request);
    }
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

    globus_i_gfs_data_session_stop(NULL, instance->session_id);
    if(instance->close_func)
    {
        instance->close_func(instance->close_arg);
    }
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

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_gridftp_server_control_destroy(instance->server_handle);

    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "Control connection closed with error: %s\n",
             globus_object_printable_to_string(globus_error_get(result)));
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

typedef struct globus_l_gfs_auth_info_s
{
    uid_t                               uid;
    const char *                        username;
    const char *                        password;
    const char *                        subject;
    globus_gridftp_server_control_op_t  control_op;
    globus_gridftp_server_control_response_t response;
    char *                              msg;
    globus_l_gfs_server_instance_t *    instance;
    int                                 id;
} globus_l_gfs_auth_info_t;

static
void
globus_l_gfs_auth_session_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_l_gfs_auth_info_t *          auth_info;

    auth_info = (globus_l_gfs_auth_info_t *) user_arg;

    auth_info->instance->session_id = reply->session_id;
    if(reply->result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_auth(
            auth_info->control_op,
            NULL,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_PANIC,
            "internal error: session_cb");
    }
    else
    {
        globus_gridftp_server_control_finished_auth(
            auth_info->control_op,
            auth_info->username,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            NULL);
    }

}

static
void
globus_l_gfs_auth_data_cb(
    const char *                        resource_id,
    void *                              user_arg,
    globus_result_t                     result)
{
    globus_l_gfs_auth_info_t *          auth_info;
    gss_cred_id_t                       delegated_cred;
    auth_info = (globus_l_gfs_auth_info_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto err;
    }

    result = globus_gridftp_server_control_get_data_auth(
        auth_info->control_op,
        NULL,
        NULL,
        NULL,
        &delegated_cred);
    if(result != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_i_gfs_data_session_start(
        NULL,
        0,
        auth_info->username,
        delegated_cred,
        globus_l_gfs_auth_session_cb,
        auth_info);

    return;

  err:
    globus_gridftp_server_control_finished_auth(
        auth_info->control_op,
        NULL,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_PANIC,
        "internal error");
}

static
void
globus_l_gfs_request_auth(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_security_type_t secure_type,
    gss_ctx_id_t                        context,
    const char *                        subject,
    const char *                        user_name,
    const char *                        pw,
    void *                              user_arg)
{
    int                                 rc;
    char *                              local_name;
    struct passwd *                     pwent;
    struct group *                      group;
    char *                              anon_usr;
    char *                              anon_grp;
    uid_t                               current_uid;
    gid_t                               gid;
    char *                              err_msg = GLOBUS_NULL;
    globus_result_t                     res;
    globus_l_gfs_auth_info_t *          auth_info;
    globus_l_gfs_server_instance_t *    instance;
    char *                              remote_cs;

/* XXX add error responses */

    instance = (globus_l_gfs_server_instance_t *) user_arg;
    current_uid = getuid();
    auth_info = (globus_l_gfs_auth_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_auth_info_t));

    auth_info->control_op = op;
    auth_info->instance = instance;
    auth_info->subject = globus_libc_strdup(subject);
    auth_info->password = globus_libc_strdup(pw);

    remote_cs = globus_i_gfs_config_string("remote");

    if(secure_type == GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI)
    {
        rc = globus_gss_assist_gridmap((char *) subject, &local_name);
        if(rc != 0)
        {
            err_msg = globus_common_create_string(
                "No local mapping for Globus ID");
            goto error;
        }

        pwent = getpwnam(local_name);
        if(pwent == NULL)
        {
            err_msg = globus_common_create_string(
                "Local user %s not found", local_name);
            globus_free(local_name);
            goto error;
        }
        globus_free(local_name);

        if(globus_i_gfs_config_bool("inetd") ||
            globus_i_gfs_config_bool("daemon"))
        {
            rc = setgid(pwent->pw_gid);
            if(rc != 0)
            {
                err_msg = globus_common_create_string(
                    "Could not set user or group");
                goto error;
            }
            rc = setuid(pwent->pw_uid);
            if(rc != 0)
            {
                err_msg = globus_common_create_string(
                    "Could not set user or group");
                goto error;
            }
        }
        auth_info->username = globus_libc_strdup(pwent->pw_name);
    }
    else if(globus_i_gfs_config_bool("allow_anonymous") && current_uid == 0)
    {
        if(globus_i_gfs_config_bool("inetd") ||
            globus_i_gfs_config_bool("daemon"))
        {
            anon_usr = globus_i_gfs_config_string("anonymous_user");
            anon_grp = globus_i_gfs_config_string("anonymous_group");
            if(anon_usr)
            {
                pwent = getpwnam(anon_usr);
                if(pwent == NULL)
                {
                    err_msg = globus_common_create_string(
                        "Anonymous user not found");
                    goto error;
                }
            }
            else
            {
                err_msg = globus_common_create_string(
                    "Anonymous user not found");
                goto error;
            }
            if(anon_grp)
            {
                group = getgrnam(anon_grp);
                if(group == NULL)
                {
                    err_msg = globus_common_create_string(
                        "Anonymous group not found");
                    goto error;
                }
                gid = group->gr_gid;
            }
            else
            {
                gid = pwent->pw_gid;
            }

        rc = setgid(gid);
            if(rc != 0)
            {
               err_msg = globus_common_create_string(
                    "Could not set anonymous user or group");
                goto error;
            }
            rc = setuid(pwent->pw_uid);
            if(rc != 0)
            {
               err_msg = globus_common_create_string(
                    "Could not set anonymous user or group");
                goto error;
            }
        }
        else
        {
           err_msg = globus_common_create_string(
                "Invalid authentication method");
            goto error;
        }

    }

    auth_info->response =
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS;

    rc = globus_i_gfs_acl_init(
        &instance->acl_handle,
        context,
        FTP_SERVICE_NAME,
        user_name,
        &res,
        globus_l_gfs_auth_data_cb,
        auth_info);
    if(rc < 0)
    {
        err_msg = globus_common_create_string("acl init failed");
        goto error;
    }
    else if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        globus_l_gfs_auth_data_cb(NULL, auth_info, res);
    }

    return;

error:
    globus_gridftp_server_control_finished_auth(
        op,
        NULL,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        err_msg);
    if(err_msg != NULL)
    {
        globus_free(err_msg);
    }

}

static
void
globus_l_gfs_data_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_resource(
            op,
            reply->info.stat.stat_array,
            reply->info.stat.stat_count,
            reply->info.stat.uid,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            globus_error_print_friendly(globus_error_peek(reply->result)));
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

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    stat_info = (globus_gfs_stat_info_t *)
        globus_calloc(1, sizeof(globus_gfs_stat_info_t));

    globus_l_gfs_get_full_path(instance, path, &stat_info->pathname);
    stat_info->file_only =
        (mask & GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_FILE_ONLY) ?
            GLOBUS_TRUE : GLOBUS_FALSE;

    globus_i_gfs_data_request_stat(
        NULL,
        instance->session_id,
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
    globus_l_gfs_request_info_t *       request;
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
        globus_gsc_959_finished_command(op, "500 Unknown error.\r\n");
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

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    command_info = (globus_gfs_command_info_t *)
        globus_calloc(1, sizeof(globus_gfs_command_info_t));

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
    else
    {
        goto err;
    }

    globus_i_gfs_data_request_command(
        NULL,
        instance->session_id,
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
    globus_gfs_event_type_t             event;
    GlobusGFSName(globus_l_gfs_request_transfer_event);

    request = (globus_l_gfs_request_info_t *) user_arg;

    switch(event_type)
    {
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF:
            event = GLOBUS_GFS_EVENT_BYTES_RECVD;
            break;
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART:
            event = GLOBUS_GFS_EVENT_RANGES_RECVD;
            break;
        case GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT:
            event = GLOBUS_GFS_EVENT_TRANSFER_ABORT;
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO,
                "Requesting abort...\n");
            break;
        default:
            goto error;
            break;
    }

    globus_i_gfs_data_request_transfer_event(
        NULL,
        request->instance->session_id,
        request->transfer_id,
        event);

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
    globus_result_t                     result;
    globus_gridftp_server_control_op_t  op;
    globus_l_gfs_request_info_t *       request;
    GlobusGFSName(globus_l_gfs_data_event_cb);

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;
    switch(reply->type)
    {
      case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
        request->transfer_id = reply->transfer_id;
        
        result = globus_gridftp_server_control_events_enable(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF |
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART |
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT,
            globus_l_gfs_request_transfer_event,
            request);
        if(result != GLOBUS_SUCCESS)
        {
            /* TODO: can we ignore this */
        }
        break;

        case GLOBUS_GFS_EVENT_TRANSFER_CONNECTED:
            globus_gridftp_server_control_begin_transfer(op);
            break;

      case GLOBUS_GFS_EVENT_DISCONNECTED:
         globus_gridftp_server_control_disconnected(
            request->instance->server_handle, (void *) reply->data_handle_id);
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
    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    /* no more events once this returns */
    globus_gridftp_server_control_events_disable(op);

    /* if we ddi not yet get a begin don't send the complete.  perhaps 
        this should be moved into the server library */
    if(request->transfer_id != NULL)
    {
        globus_i_gfs_data_request_transfer_event(
            NULL,
            request->instance->session_id,
            request->transfer_id,
            GLOBUS_GFS_EVENT_TRANSFER_COMPLETE);
    }

    if(reply->result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            globus_error_print_friendly(globus_error_peek(reply->result)));
    }
    else
    {
        globus_gridftp_server_control_finished_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
    }


   /* still getting events after this?
   globus_l_gfs_request_info_destroy(request);
   
==11527== Invalid read of size 4
==11527==    at 0x40236757: globus_l_gfs_request_transfer_event (globus_i_gfs_control.c:756)
==11527==    by 0x4027B376: globus_i_gsc_terminate (globus_gridftp_server_control.c:644)
==11527==    by 0x4027B221: globus_l_gsc_read_cb (globus_gridftp_server_control.c:565)
==11527==    by 0x40299AA6: globus_l_xio_read_write_callback_kickout (globus_xio_handle.c:1127)
==11527==    by 0x402999B4: globus_i_xio_read_write_callback (globus_xio_handle.c:1095)
==11527==    by 0x402A05C4: globus_l_xio_driver_op_read_kickout (globus_xio_driver.c:574)
==11527==    by 0x402ABF11: globus_xio_driver_finished_read (globus_xio_pass.c:1216)
==11527==    by 0x402BD97C: globus_l_xio_gssapi_ftp_server_read_cb (globus_xio_gssapi_ftp.c:1343)
==11527==    by 0x402A0669: globus_l_xio_driver_op_read_kickout (globus_xio_driver.c:589)
==11527==    by 0x402ABF11: globus_xio_driver_finished_read (globus_xio_pass.c:1216)
==11527==    Address 0x44767C7C is 8 bytes inside a block of size 12 free'd
==11527==    at 0x40026E8B: free (vg_replace_malloc.c:231)
==11527==    by 0x402358F5: globus_l_gfs_request_info_destroy (globus_i_gfs_control.c:68)
==11527==    by 0x4023690F: globus_l_gfs_data_transfer_cb (globus_i_gfs_control.c:857)
==11527==    by 0x40229C31: globus_l_gfs_data_end_transfer_kickout (globus_i_gfs_data.c:1382)
==11527==    by 0x40229D99: globus_l_gfs_data_end_read_kickout (globus_i_gfs_data.c:1459)
==11527==    by 0x403881A4: globus_callback_space_poll (globus_callback_nothreads.c:1341)
==11527==    by 0x804BA58: main (globus_gridftp_server.c:735)
==11527==    by 0x410037F6: __libc_start_main (in /lib/i686/libc-2.3.1.so)
==11527==    by 0x804ACD0: (within /sandbox/mlink/gridftp-server3-branch/INSTALL/sbin/globus-gridftp-server)
     */
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

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    send_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

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
    }

    globus_l_gfs_get_full_path(instance, path, &send_info->pathname);
    send_info->range_list = range_list;
    send_info->stripe_count = 1;
    send_info->node_count = 1;
    send_info->data_handle_id = (int) data_handle;

    globus_i_gfs_data_request_send(
        NULL,
        instance->session_id,
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
    GlobusGFSName(globus_l_gfs_request_recv);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    recv_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

    if(mod_name && strcmp("A", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT,
            &recv_info->partial_offset);

        globus_assert(args == 1);
    }
    else
    {
        recv_info->partial_offset = 0;
        recv_info->partial_length = -1;
    }

    globus_l_gfs_get_full_path(instance, path, &recv_info->pathname);
    recv_info->range_list = range_list;
    recv_info->stripe_count = 1;
    recv_info->node_count = 1;
    recv_info->data_handle_id = (int) data_handle;

    globus_i_gfs_data_request_recv(
        NULL,
        instance->session_id,
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

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    list_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

    globus_l_gfs_get_full_path(instance, path, &list_info->pathname);
    list_info->list_type = globus_libc_strdup(list_type);
    list_info->data_handle_id = (int) data_handle;
    list_info->stripe_count = 1;
    list_info->node_count = 1;

    globus_i_gfs_data_request_list(
        NULL,
        instance->session_id,
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
    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_passive_connect(
            op,
            (void *) reply->info.data.data_handle_id,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            reply->info.data.contact_strings,
            reply->info.data.cs_count,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            globus_error_print_friendly(globus_error_peek(reply->result)));
    }
    else
    {
        globus_gridftp_server_control_finished_passive_connect(
            op,
            (void *) reply->info.data.data_handle_id,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            reply->info.data.contact_strings,
            reply->info.data.cs_count,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
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
    int                                 buf_size;

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
        &data_info->del_cred);
    globus_assert(result == GLOBUS_SUCCESS);

    data_info->blocksize = globus_i_gfs_config_int("blocksize");

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
    GlobusGFSName(globus_l_gfs_passive_data_connect);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    data_info = (globus_gfs_data_info_t *)
        globus_calloc(1, sizeof(globus_gfs_data_info_t));

    globus_l_gfs_get_data_info(op, data_info, net_prt);

    data_info->pathname = globus_libc_strdup(pathname);
    data_info->max_cs = max;

    globus_i_gfs_data_request_passive(
        NULL,
        instance->session_id,
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
    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    if(reply->result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_active_connect(
            op,
            (void *) reply->info.data.data_handle_id,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
            globus_error_print_friendly(globus_error_peek(reply->result)));
    }
    else
    {
        globus_gridftp_server_control_finished_active_connect(
            op,
            (void *) reply->info.data.data_handle_id,
            reply->info.data.bi_directional
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS,
            GLOBUS_NULL);
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
    GlobusGFSName(globus_l_gfs_active_data_connect);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    result = globus_l_gfs_request_info_init(
        &request, instance, op);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }
    
    data_info = (globus_gfs_data_info_t *)
        globus_calloc(1, sizeof(globus_gfs_data_info_t));

    globus_l_gfs_get_data_info(op, data_info, net_prt);

    data_info->contact_strings = cs;
    data_info->cs_count = cs_count;

    globus_i_gfs_data_request_active(
        NULL,
        instance->session_id,
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
    void *                              user_data_handle,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_request_data_destroy);

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_i_gfs_data_destroy_handle(
        NULL, instance->session_id, (int) user_data_handle);
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

    return GLOBUS_SUCCESS;

error:
    return result;
}

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact,
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

    result = globus_gridftp_server_control_start(
        instance->server_handle,
        attr,
        system_handle,
        globus_l_gfs_done_cb,
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_done_cb(instance->server_handle, result, instance);
        globus_gridftp_server_control_attr_destroy(attr);
        goto error_start;
    }

    globus_gridftp_server_control_attr_destroy(attr);

    return GLOBUS_SUCCESS;

error_add_commands:
error_init:
error_attr_setup:
    globus_gridftp_server_control_attr_destroy(attr);

error_attr:
    globus_free(instance->remote_contact);

error_strdup:
    globus_free(instance);
error_start:
error_malloc:
    return result;
}
