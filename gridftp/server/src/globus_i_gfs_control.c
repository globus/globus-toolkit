#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server.h"
#include <grp.h>

globus_result_t
globus_l_gfs_op_attr_init(
    globus_i_gfs_op_attr_t **   u_attr)
{
    globus_i_gfs_op_attr_t *    attr;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_op_attr_init);
    
    attr = (globus_i_gfs_op_attr_t *) 
        globus_malloc(sizeof(globus_i_gfs_op_attr_t));
    if(!attr)
    {
        result = GlobusGFSErrorMemory("attr");
        goto error_alloc;
    }
    attr->control_op = GLOBUS_NULL;
    attr->partial_offset = 0;
    attr->partial_length = -1;
    attr->range_list = GLOBUS_NULL;
    
    *u_attr = attr;
    return GLOBUS_SUCCESS;
    
error_alloc:
    return result;
}

void
globus_i_gfs_op_attr_destroy(
    globus_i_gfs_op_attr_t *            attr)
{
    globus_free(attr);
}

void
globus_i_gfs_op_attr_copy(
    globus_i_gfs_op_attr_t *            out_attr,
    globus_i_gfs_op_attr_t *            in_attr)
{
    out_attr->partial_offset = in_attr->partial_offset;
    out_attr->partial_length = in_attr->partial_length;
    out_attr->range_list = in_attr->range_list;
}

static
globus_result_t
globus_l_gfs_get_full_path(
    globus_i_gfs_server_instance_t *        instance,
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
            instance->u.control.server, &cwd);
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
    globus_i_gfs_server_instance_t *    instance;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO,
        "Closed connection from %s\n",
        instance->remote_contact);
    
    globus_free(instance->remote_contact);
    globus_free(instance);
    globus_i_gfs_server_closed();
}

static
void
globus_l_gfs_abort_cb(
    globus_gridftp_server_control_op_t      op,
    void *                                  user_arg)
{
    globus_i_gfs_server_instance_t *    instance;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
            
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR,
        "Aborting \n");
    return;   
}

static
void
globus_l_gfs_done_cb(
    globus_gridftp_server_control_t     server,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_server_instance_t *    instance;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
    globus_gridftp_server_control_destroy(instance->u.control.server);
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
globus_l_gfs_auth_request(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_security_type_t secure_type,
    const char *                        subject,
    const char *                        user_name,
    const char *                        pw,
    void *                              user_arg)
{
    globus_result_t                     result; 
    int                                 rc;
    char *                              local_name;
    struct passwd *                     pwent;
    struct group *                      group;
    char *                              anon_usr;
    char *                              anon_grp;
    uid_t                               current_uid;
    gid_t                               gid;
    char *                              err_msg = GLOBUS_NULL;

/* XXX add error responses */
    result = GLOBUS_FAILURE;
    
    current_uid = getuid();
    
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
    }
    else if(globus_i_gfs_config_bool("allow_anonymous"))
    {   
        if(current_uid != 0)
        {
            globus_gridftp_server_control_finished_auth(
                op, 
                current_uid, 
                GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS, 
                GLOBUS_NULL);
            return;    
        }
        else if(globus_i_gfs_config_bool("inetd") || 
            globus_i_gfs_config_bool("daemon"))
        {            
            anon_usr = globus_i_gfs_config_string("anonymous_user");
            anon_grp = globus_i_gfs_config_string("anonymous_group");
            if(anon_usr)
            {   
                pwent = getpwnam(anon_usr);
                globus_free(anon_usr);
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
                globus_free(anon_grp);
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
                      
    globus_gridftp_server_control_finished_auth(
        op, 
        pwent->pw_uid, 
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS, 
        GLOBUS_NULL);

    return;

error:
    globus_gridftp_server_control_finished_auth(
        op, 
        0, 
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        err_msg);
}

static
void
globus_l_gfs_ipc_resource_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info,
    int                                 stat_count,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;

    op = (globus_gridftp_server_control_op_t) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_resource(
            op,
            stat_info, 
            stat_count, 
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
            globus_error_print_friendly(globus_error_peek(result)));
    }
    else
    {
        globus_gridftp_server_control_finished_resource(
            op,
            stat_info, 
            stat_count, 
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS, 
            GLOBUS_NULL);
    }    
}

static
void
globus_l_gfs_resource_request(
    globus_gridftp_server_control_op_t  op,
    const char *                        path,
    globus_gridftp_server_control_resource_mask_t mask,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    char *                              fullpath;
    GlobusGFSName(globus_l_gfs_resource_request);
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;

    globus_l_gfs_get_full_path(instance, path, &fullpath);

    result = globus_i_gfs_ipc_resource_request(
        instance,
        fullpath,
        mask & GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_FILE_ONLY
            ? GLOBUS_TRUE
            : GLOBUS_FALSE,
        globus_l_gfs_ipc_resource_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_resource_request", result);
        goto error_ipc;
    }
    
    return;
error_ipc:     
    globus_gridftp_server_control_finished_resource(
        op, 
        GLOBUS_NULL, 
        0, 
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        globus_error_print_friendly(globus_error_peek(result)));
}

static
void
globus_l_gfs_ipc_command_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_cmd_attr_t *           cmd_attr,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    char *                              msg;
    
    op = (globus_gridftp_server_control_op_t) user_arg;

    switch(cmd_attr->command)
    {
      case GLOBUS_I_GFS_CMD_RMD:
      case GLOBUS_I_GFS_CMD_DELE:
      case GLOBUS_I_GFS_CMD_RNTO:
      case GLOBUS_I_GFS_CMD_SITE_CHMOD:
        globus_gsc_959_finished_command(op, "250 OK.\r\n"); 
        break;
      case GLOBUS_I_GFS_CMD_MKD:
        msg = globus_common_create_string(
            "257 Directory \"%s\" created successfully.\r\n", 
            cmd_attr->pathname);
        globus_gsc_959_finished_command(op, msg);
        globus_free(msg);
        break;      
      case GLOBUS_I_GFS_CMD_RNFR:
        globus_gsc_959_finished_command(op, "350 Waiting for RNTO.\r\n"); 
        break;
      case GLOBUS_I_GFS_CMD_CKSM:
        msg = globus_common_create_string(
            "213 %s\r\n", cmd_attr->cksm_response);
        globus_gsc_959_finished_command(op, msg); 
        globus_free(msg);
        break;
      
      default:
        globus_gsc_959_finished_command(op, "500 Unknown error.\r\n"); 
        break;
    }
       
}

static
void
globus_l_gfs_command_request(
    globus_gsc_959_op_t                 op,
    const char *                        full_command,
    char **                             cmd_array,
    int                                 argc,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_cmd_attr_t             cmd_attr;
    GlobusGFSName(globus_l_gfs_command_request);
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
    if(strcmp(cmd_array[0], "MKD") == 0)
    {
        cmd_attr.command = GLOBUS_I_GFS_CMD_MKD;
        globus_l_gfs_get_full_path(instance, cmd_array[1], &cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
    }
    else if(strcmp(cmd_array[0], "RMD") == 0)
    {
        cmd_attr.command = GLOBUS_I_GFS_CMD_RMD;
        globus_l_gfs_get_full_path(instance, cmd_array[1], &cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
    }
    else if(strcmp(cmd_array[0], "DELE") == 0)
    {
        cmd_attr.command = GLOBUS_I_GFS_CMD_DELE;
        globus_l_gfs_get_full_path(instance, cmd_array[1], &cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
    }
    else if(strcmp(cmd_array[0], "RNFR") == 0)
    {
        /* XXX */
        cmd_attr.command = GLOBUS_I_GFS_CMD_RNFR;
        globus_l_gfs_get_full_path(instance, cmd_array[1], &cmd_attr.pathname);
        instance->rnfr_pathname = globus_libc_strdup(cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
        globus_gsc_959_finished_command(op,
            "200 OK.\r\n");
        return;
    }
    else if(strcmp(cmd_array[0], "RNTO") == 0)
    {
        cmd_attr.command = GLOBUS_I_GFS_CMD_RNTO;
        globus_l_gfs_get_full_path(instance, cmd_array[1], &cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
        if(instance->rnfr_pathname == GLOBUS_NULL)
        {
            goto err;
        }
        cmd_attr.rnfr_pathname = instance->rnfr_pathname;
        instance->rnfr_pathname = GLOBUS_NULL;
    }
    else if(strcmp(cmd_array[0], "CKSM") == 0)
    {
        cmd_attr.command = GLOBUS_I_GFS_CMD_CKSM;
        globus_l_gfs_get_full_path(instance, cmd_array[4], &cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
        cmd_attr.cksm_alg = globus_libc_strdup(cmd_array[1]);
        globus_libc_scan_off_t(
            cmd_array[2],
            &cmd_attr.cksm_offset,
            GLOBUS_NULL);
        globus_libc_scan_off_t(
            cmd_array[3],
            &cmd_attr.cksm_length,
            GLOBUS_NULL);
   
    }
    else if(strcmp(cmd_array[0], "SITE") == 0 && 
        strcmp(cmd_array[1], "CHMOD") == 0)
    {
        cmd_attr.command = GLOBUS_I_GFS_CMD_SITE_CHMOD;
        globus_l_gfs_get_full_path(instance, cmd_array[3], &cmd_attr.pathname);
        if(cmd_attr.pathname == NULL)
        {
            goto err;
        }
        cmd_attr.chmod_mode = strtol(cmd_array[2], NULL, 8);
    }
    else
    {
        goto err;
    }

    result = globus_i_gfs_ipc_command_request(
        instance,
        &cmd_attr,
        globus_l_gfs_ipc_command_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_command_request", result);
        goto error_ipc;
    }
    
    return;
err:
error_ipc:  
    globus_gsc_959_finished_command(op,
        "501 Invalid command arguments.\r\n");

}

static
void
globus_l_gfs_transfer_event(
    globus_gridftp_server_control_op_t      op,
    int                                     event_type,
    void *                                  user_arg)
{
    globus_i_gfs_server_instance_t *        instance;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
    globus_i_gfs_ipc_transfer_event(instance, event_type);
    
    return;
}


static
void
globus_l_gfs_ipc_event_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_event_t                type,
    void *                              data,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    char                                mode;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    switch(type)
    {
      case GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN:
        globus_gridftp_server_control_begin_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF | 
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART,
            globus_l_gfs_transfer_event,
            instance);
        break;
      
      case GLOBUS_I_GFS_EVENT_DISCONNECTED:
        globus_gridftp_server_control_get_mode(op, &mode);
        if(mode != 'E')
        {
            globus_gridftp_server_control_disconnected(
                instance->u.control.server, data);
        }
        break;
        
      default:
        globus_assert(0 && "Unexpected event type");
        break;
    }
}

static
void
globus_l_gfs_ipc_transfer_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
            globus_error_print_friendly(globus_error_peek(result)));
    }
    else
    {
        globus_gridftp_server_control_finished_transfer(
            op,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS, 
            GLOBUS_NULL);
    }    
}

static
void
globus_l_gfs_send_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        path,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_range_list_t                 range_list,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_op_attr_t *            op_attr;            
    globus_i_gfs_ipc_data_handle_t *    data;
    int                                 args;
    char *                              fullpath;
    GlobusGFSName(globus_l_gfs_send_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;

    result = globus_gridftp_server_abort_enable(
        op, globus_l_gfs_abort_cb, instance);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_gridftp_server_abort_enable", result);
        goto error_attr;
    }
    
    globus_l_gfs_get_full_path(instance, path, &fullpath);

    result = globus_l_gfs_op_attr_init(&op_attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_op_attr_init", result);
        goto error_attr;
    }
    
    op_attr->control_op = op;
    op_attr->range_list = range_list;
    if(mod_name && strcmp("P", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT" %"GLOBUS_OFF_T_FORMAT,
            &op_attr->partial_offset,
            &op_attr->partial_length);
            
        globus_assert(args == 2);
    }
     
    {
    globus_gfs_transfer_state_t *       send_state;
    
    send_state = (globus_gfs_transfer_state_t *) 
        globus_calloc(1, sizeof(globus_gfs_transfer_state_t));
    
    send_state->partial_offset = op_attr->partial_offset;
    send_state->partial_length = op_attr->partial_length;
    send_state->range_list = range_list;
    send_state->control_op = op;

    result = globus_gfs_ipc_send(
        instance->ipc_handle,
        send_state,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    }
    /*
    result = globus_i_gfs_ipc_send_request(
        instance,
        op_attr,
        data,
        fullpath,
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    */    
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_send_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:
    globus_i_gfs_op_attr_destroy(op_attr);
error_attr:
    globus_gridftp_server_control_finished_transfer(
        op,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        globus_error_print_friendly(globus_error_peek(result)));
}

static
void
globus_l_gfs_recv_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        path,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_range_list_t                 range_list,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_op_attr_t *            op_attr;            
    globus_i_gfs_ipc_data_handle_t *    data;
    int                                 args;
    char *                              fullpath;
    GlobusGFSName(globus_l_gfs_recv_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;

    result = globus_gridftp_server_abort_enable(
        op, globus_l_gfs_abort_cb, instance);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_gridftp_server_abort_enable", result);
        goto error_attr;
    }
    
    globus_l_gfs_get_full_path(instance, path, &fullpath);

    result = globus_l_gfs_op_attr_init(&op_attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_op_attr_init", result);
        goto error_attr;
    }

    op_attr->control_op = op;
    op_attr->range_list = range_list;
    if(mod_name && strcmp("A", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT,
            &op_attr->partial_offset);
            
        globus_assert(args == 1);
    }            
    {
    globus_gfs_transfer_state_t *       recv_state;
    
    recv_state = (globus_gfs_transfer_state_t *) 
        globus_calloc(1, sizeof(globus_gfs_transfer_state_t));
    
    send_state->partial_offset = op_attr->partial_offset;
    send_state->range_list = range_list;
    send_state->control_op = op;

    result = globus_gfs_ipc_recv(
        instance->ipc_handle,
        recv_state,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    }
    /*
    result = globus_i_gfs_ipc_recv_request(
        instance,
        op_attr,
        data,
        fullpath,
        mod_name,
        mod_parms,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    */
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_recv_request", result);
        goto error_ipc;
    }
    
    return;
    
error_ipc:
    globus_i_gfs_op_attr_destroy(op_attr);
error_attr:
    globus_gridftp_server_control_finished_transfer(
        op,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        globus_error_print_friendly(globus_error_peek(result)));
}

static
void
globus_l_gfs_list_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        path,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_ipc_data_handle_t *    data;
    char *                              fullpath;
    GlobusGFSName(globus_l_gfs_list_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;

    instance = (globus_i_gfs_server_instance_t *) user_arg;

    result = globus_gridftp_server_abort_enable(
        op, globus_l_gfs_abort_cb, instance);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_gridftp_server_abort_enable", result);
        goto error_ipc;
    }
    
    globus_l_gfs_get_full_path(instance, path, &fullpath);

    result = globus_i_gfs_ipc_list_request(
        instance,
        data,
        fullpath,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_list_request", result);
        goto error_ipc;
    }
    return;
error_ipc:     
    globus_gridftp_server_control_finished_transfer(
        op,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        globus_error_print_friendly(globus_error_peek(result)));
}

static
void
globus_l_gfs_ipc_passive_data_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_passive_connect(
            op,
            data_handle,
            bi_directional 
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            contact_strings,
            cs_count,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
            globus_error_print_friendly(globus_error_peek(result)));
    }
    else
    {
        globus_gridftp_server_control_finished_passive_connect(
            op,
            data_handle,
            bi_directional 
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            contact_strings,
            cs_count,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS, 
            GLOBUS_NULL);
    }    
}

static
void
globus_l_gfs_op_to_attr(
    globus_gridftp_server_control_op_t  op,
    globus_i_gfs_data_attr_t *          attr,
    globus_gridftp_server_control_network_protocol_t net_prt)
{
    globus_result_t                     result;
    int                                 buf_size;
        
    *attr = globus_i_gfs_data_attr_defaults;
    if(net_prt == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
    {
        attr->ipv6 = GLOBUS_TRUE;
    }
    else
    {
        attr->ipv6 = GLOBUS_FALSE;
    }
    
    result = globus_gridftp_server_control_get_mode(op, &attr->mode);
    globus_assert(result == GLOBUS_SUCCESS);
    
    result = globus_gridftp_server_control_get_type(op, &attr->type);
    globus_assert(result == GLOBUS_SUCCESS);
    
    result = globus_gridftp_server_control_get_buffer_size(
        op, &attr->tcp_bufsize, &buf_size);
    globus_assert(result == GLOBUS_SUCCESS);
    
    if(buf_size > attr->tcp_bufsize)
    {
        attr->tcp_bufsize = buf_size;
    }

    result = globus_gridftp_server_control_get_parallelism(
        op, &attr->nstreams);
    globus_assert(result == GLOBUS_SUCCESS);

    result = globus_gridftp_server_control_get_data_auth(
        op, 
        &attr->dcau.subject.subject, 
        (char *) &attr->dcau.mode,
        (char *) &attr->prot, 
        &attr->delegated_cred);
    globus_assert(result == GLOBUS_SUCCESS);
                
}

static
void
globus_l_gfs_passive_data_connect(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    int                                 max,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_attr_t            attr;
    GlobusGFSName(globus_l_gfs_passive_data_connect);
    
    globus_l_gfs_op_to_attr(op, &attr, net_prt);
    /* attr.nstreams = max; */
    /* XXX how do I know how many streams to 
     * optimize for when receiving data in mode E? 
     */
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;

    {
    globus_gfs_data_state_t *               data_state;
    
    data_state = (globus_gfs_data_state_t *) 
        globus_calloc(1, sizeof(globus_gfs_data_state_t));
    
    /* XXX current data attr stuff will be set with set_state */
    
    result = globus_gfs_ipc_passive_data(
        instance->ipc_handle,
        data_state,
        globus_l_gfs_ipc_passive_data_cb,
        op);
    }
    /*
    result = globus_i_gfs_ipc_passive_data_request(
        instance,
        &attr,
        globus_l_gfs_ipc_passive_data_cb,
        op);
    */
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_passive_data_request", result);
        goto error_ipc;
    }
    
    return;
error_ipc:     
    globus_gridftp_server_control_finished_passive_connect(
        op,
        GLOBUS_NULL,
        0,
        GLOBUS_NULL,
        0,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        globus_error_print_friendly(globus_error_peek(result)));
}

static
void
globus_l_gfs_ipc_active_data_cb(
    globus_i_gfs_server_instance_t *    instance,
    globus_result_t                     result,
    globus_i_gfs_ipc_data_handle_t *    data_handle,
    globus_bool_t                       bi_directional,
    void *                              user_arg)
{
    globus_gridftp_server_control_op_t  op;
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
        globus_gridftp_server_control_finished_active_connect(
            op,
            data_handle,
            bi_directional 
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
            globus_error_print_friendly(globus_error_peek(result)));
    }
    else
    {
        globus_gridftp_server_control_finished_active_connect(
            op,
            data_handle,
            bi_directional 
                ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
                : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
            GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS, 
            GLOBUS_NULL);
    }    
}

static
void
globus_l_gfs_active_data_connect(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    const char **                       cs,
    int                                 cs_count,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_attr_t            attr;
    GlobusGFSName(globus_l_gfs_active_data_connect);
    
    globus_l_gfs_op_to_attr(op, &attr, net_prt);

    instance = (globus_i_gfs_server_instance_t *) user_arg;
    {
    globus_gfs_data_state_t *               data_state;
    
    data_state = (globus_gfs_data_state_t *) 
        globus_calloc(1, sizeof(globus_gfs_data_state_t));
    
    /* XXX current data attr stuff will be set with set_state */
    data_state->cs = cs;
    data_state->cs_count = cs_count;
    
    result = globus_gfs_ipc_active_data(
        instance->ipc_handle,
        data_state,
        globus_l_gfs_ipc_active_data_cb,
        op);
    }
    /*
    result = globus_i_gfs_ipc_active_data_request(
        instance,
        &attr,
        cs,
        cs_count,
        globus_l_gfs_ipc_active_data_cb,
        op);
    */
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_active_data_request", result);
        goto error_ipc;
    }
    
    return;
error_ipc:     
    globus_gridftp_server_control_finished_active_connect(
        op,
        GLOBUS_NULL,
        0,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED, 
        globus_error_print_friendly(globus_error_peek(result)));
}

static
void
globus_l_gfs_data_destroy(
    void *                              user_data_handle,
    void *                              user_arg)
{
    globus_i_gfs_ipc_data_handle_t *    data_handle;
    
    data_handle = (globus_i_gfs_ipc_data_handle_t *) user_data_handle;
    
    globus_i_gfs_ipc_data_destroy(data_handle);
}

static
void
globus_l_gfs_control_log(
    globus_gridftp_server_control_t     server_handle,
    const char *                        message,
    int                                 type,
    void *                              user_arg)
{
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_log_type_t             log_type;
    
    instance = (globus_i_gfs_server_instance_t *) user_arg;
    
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
    globus_i_gfs_server_instance_t *    instance,
    globus_gridftp_server_control_t     control_handle)
{
    globus_result_t                     result;
    
    result = globus_gsc_959_command_add(
        control_handle,
        "MKD",
        globus_l_gfs_command_request,
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
        globus_l_gfs_command_request,
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
        globus_l_gfs_command_request,
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
        globus_l_gfs_command_request,
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
        globus_l_gfs_command_request,
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
        globus_l_gfs_command_request,
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
        globus_l_gfs_command_request,
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
    const char *                        remote_contact)
{
    GlobusGFSName(globus_i_gfs_control_start);
    globus_result_t                     result;
    globus_gridftp_server_control_attr_t attr;
    globus_i_gfs_server_instance_t *    instance;
    int                                 idle_timeout;
    char *                              banner;
    char *                              login_msg;
    
    
    instance = (globus_i_gfs_server_instance_t *)
        globus_calloc(1, sizeof(globus_i_gfs_server_instance_t));
    if(!instance)
    {
        result = GlobusGFSErrorMemory("instance");
        goto error_malloc;
    }
    
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
        globus_free(banner);
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
        globus_free(login_msg);
    }

    result = globus_gridftp_server_control_attr_set_auth(
        attr, globus_l_gfs_auth_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_set_resource(
        attr, globus_l_gfs_resource_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }    
    
    result = globus_gridftp_server_control_attr_add_recv(
        attr, GLOBUS_NULL, globus_l_gfs_recv_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_recv(
        attr, "A", globus_l_gfs_recv_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_add_send(
        attr, GLOBUS_NULL, globus_l_gfs_send_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_send(
        attr, "P", globus_l_gfs_send_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_set_list(
        attr, globus_l_gfs_list_request, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_data_functions(
        attr,
        globus_l_gfs_active_data_connect,
        instance,
        globus_l_gfs_passive_data_connect,
        instance,
        globus_l_gfs_data_destroy,
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

    result = globus_gridftp_server_control_init(&instance->u.control.server);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    result = globus_l_gfs_add_commands(instance, instance->u.control.server);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_add_commands;
    }

    result = globus_gridftp_server_control_start(
        instance->u.control.server, 
        attr, 
        system_handle, 
        globus_l_gfs_done_cb, 
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_done_cb(instance->u.control.server, result, instance);
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
