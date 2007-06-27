/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_i_gridftp_server.h"
#include "version.h"

GlobusDebugDefine(GLOBUS_GRIDFTP_SERVER);

typedef struct
{
    globus_xio_handle_t                 xio_handle;
    char *                              remote_contact;
    char *                              local_contact;

    char *                              rnfr_pathname;

    globus_i_gfs_server_close_cb_t      close_func;
    void *                              close_arg;

    void *                              session_arg;
    char *                              home_dir;
    char *                              username;
    globus_gridftp_server_control_t     server_handle;
    globus_object_t *                   close_error;
} globus_l_gfs_server_instance_t;

typedef struct
{
    globus_l_gfs_server_instance_t *    instance;
    globus_gridftp_server_control_op_t  control_op;
    void *                              event_arg;
    void *                              info;
    globus_bool_t                       transfer_events;

    globus_gfs_operation_type_t         bounce_type;
    globus_i_gfs_data_callback_t        bounce_cb;
    void *                              bounce_info; 
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

static
void
globus_l_gfs_control_log(
    globus_gridftp_server_control_t     server_handle,
    const char *                        message,
    int                                 type,
    void *                              user_arg);

static int
globus_l_gfs_activate()
{
    int                                 rc = 0;
        
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    rc = globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    rc = globus_module_activate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    rc = globus_module_activate(GLOBUS_GSI_AUTHZ_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    rc = globus_module_activate(GLOBUS_USAGE_MODULE);
    if(rc != 0)
    {
        return rc;
    }
    
    GlobusDebugInit(GLOBUS_GRIDFTP_SERVER,
        ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);

    return rc;
}

static int
globus_l_gfs_deactivate()
{
    int                                 rc;

    rc = globus_module_deactivate_all();

    return rc;
}

globus_module_descriptor_t              globus_i_gfs_module =
{
    "globus_gridftp_server",
    globus_l_gfs_activate,
    globus_l_gfs_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
void
globus_l_gfs_conn_max_change_cb(
    const char *                        opt_name,
    int                                 val,
    void *                              user_arg)
{
    int                                 i;
    int                                 kill_count;
    globus_list_t *                     list;
    globus_l_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_conn_max_change_cb);
    GlobusGFSDebugEnter();

    /* if set to mac value there is nothing to do */
    if(val <= 0)
    {
        return;
    }
    globus_mutex_lock(&globus_l_gfs_control_mutex);
    {
        kill_count = globus_list_size(globus_l_gfs_server_handle_list) - val;

        for(i = 0, list = globus_l_gfs_server_handle_list;
            i < kill_count && !globus_list_empty(list);
            i++, list = globus_list_rest(list))
        {
            instance = (globus_l_gfs_server_instance_t *)
                globus_list_first(list);
            globus_gridftp_server_control_stop(instance->server_handle);
        }
    }
    globus_mutex_unlock(&globus_l_gfs_control_mutex);

    GlobusGFSDebugExit();
}


void
globus_i_gfs_control_init()
{
    globus_i_gfs_config_option_cb_ent_t * cb_handle;
    GlobusGFSName(globus_i_gfs_control_init);
    GlobusGFSDebugEnter();

    globus_l_gfs_server_handle_list = NULL;
    globus_mutex_init(&globus_l_gfs_control_mutex, NULL);
    globus_l_gfs_control_active = GLOBUS_TRUE;

    globus_gfs_config_add_cb(
        &cb_handle,
        "connections_max",
        globus_l_gfs_conn_max_change_cb,
        NULL);
    
    GlobusGFSDebugExit();
}

void
globus_i_gfs_control_stop()
{
    globus_list_t *                     list;
    globus_l_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_i_gfs_control_stop);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
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
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusGFSDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_request_info_destroy(
    globus_l_gfs_request_info_t *       request)
{
    GlobusGFSName(globus_l_gfs_request_info_destroy);
    GlobusGFSDebugEnter();

    globus_free(request);

    GlobusGFSDebugExit();
}

static
globus_result_t
globus_l_gfs_get_full_path(
    globus_l_gfs_server_instance_t *        instance,
    const char *                            in_path,
    char **                                 out_path)
{
    globus_result_t                         result;
    char                                    path[MAXPATHLEN];
    char *                                  cwd = GLOBUS_NULL;
    int                                     cwd_len;
    char *                                  slash = "/";
    GlobusGFSName(globus_l_gfs_get_full_path);
    GlobusGFSDebugEnter();

    if(!in_path)
    {
        result = GlobusGFSErrorGeneric("invalid pathname");
        goto done;
    }
    if(*in_path == '/')
    {
        strncpy(path, in_path, sizeof(path));
    }
    else if(*in_path == '~')
    {
        if(instance->home_dir == NULL)
        {
            result = GlobusGFSErrorGeneric(
                "No home directory, cannot expand ~");
            goto done;            
        }
        in_path++;
        if(*in_path == '/')
        {
            in_path++;
        }
        else if(*in_path == '\0')
        {
            slash = "";
        }
        else
        {
            /* XXX expand other usernames here */
            result = GlobusGFSErrorGeneric(
                "Cannot expand ~");
            goto done;            
        } 
        cwd = globus_libc_strdup(instance->home_dir);
        cwd_len = strlen(cwd);
        if(cwd[cwd_len - 1] == '/')
        {
            cwd[--cwd_len] = '\0';
        }
        snprintf(path, sizeof(path), "%s%s%s", cwd, slash, in_path);
        globus_free(cwd);
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

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

done:
    GlobusGFSDebugExitWithError();
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
    GlobusGFSName(globus_l_gfs_channel_close_cb);
    GlobusGFSDebugEnter();

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO,
        _FSSL("Closed connection from %s\n",NULL),
        instance->remote_contact);

    if(instance->session_arg != NULL)
    {
        globus_i_gfs_data_session_stop(NULL, instance->session_arg);
    }
    if(instance->close_func)
    {
        instance->close_func(instance->close_arg, instance->close_error);
    }
    
    if(instance->home_dir)
    {
        globus_free(instance->home_dir);
    }
    if(instance->username)
    {
        globus_free(instance->username);
    }
    globus_free(instance->local_contact);
    globus_free(instance->remote_contact);
    globus_free(instance);

    GlobusGFSDebugExit();
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
    GlobusGFSDebugEnter();

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_gridftp_server_control_destroy(instance->server_handle);

    globus_mutex_lock(&globus_l_gfs_control_mutex);
    {
        globus_list_remove(&globus_l_gfs_server_handle_list,
            globus_list_search(globus_l_gfs_server_handle_list, instance));
    }
    globus_mutex_unlock(&globus_l_gfs_control_mutex);

    instance->close_error = 
        (result == GLOBUS_SUCCESS ? NULL :globus_error_get(result));
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

    GlobusGFSDebugExit();
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
    GlobusGFSDebugEnter();

    auth_info = (globus_l_gfs_auth_info_t *) user_arg;

    auth_info->instance->session_arg = reply->info.session.session_arg;
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
        if(auth_info->session_info->subject != NULL)
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO,
                "DN %s successfully authorized.\n",
                auth_info->session_info->subject);
        }

        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "User %s successfully authorized.\n",
            reply->info.session.username);

        if(reply->info.session.home_dir != NULL && 
            globus_i_gfs_config_bool("use_home_dirs"))
        {
            globus_gridftp_server_control_set_cwd(
                auth_info->instance->server_handle,
                reply->info.session.home_dir);
        }
        
        auth_info->instance->home_dir = 
            globus_libc_strdup(reply->info.session.home_dir);
        auth_info->instance->username = 
            globus_libc_strdup(reply->info.session.username);
        
        globus_gridftp_server_control_finished_auth(
            auth_info->control_op,
            reply->info.session.username,
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
    if(auth_info->session_info->host_id != NULL)
    {
        globus_free(auth_info->session_info->host_id);
    }
    globus_free(auth_info->session_info);
    globus_free(auth_info);

    GlobusGFSDebugExit();
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
    GlobusGFSName(globus_l_gfs_request_auth);
    GlobusGFSDebugEnter();

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
    if(strcmp(session_info->username, GLOBUS_MAPPING_STRING) == 0)
    {
        session_info->map_user = GLOBUS_TRUE;
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
        if(session_info->subject == NULL)
        {
            goto user_error;
        }
    }
    if(instance->remote_contact != NULL)
    {
        session_info->host_id = strdup(instance->remote_contact);
        if(session_info->host_id == NULL)
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

    GlobusGFSDebugExit();
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
        _FSSL("internal error: session_cb",NULL));

    GlobusGFSDebugExitWithError();
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
    GlobusGFSDebugEnter();

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    globus_assert(op != NULL);
    if(reply->result != GLOBUS_SUCCESS)
    {
        tmp_str = globus_error_print_friendly(globus_error_peek(reply->result));
        globus_gridftp_server_control_finished_resource(
            op,
            NULL,
            0,
            0,
            0,
            NULL,
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
            reply->info.stat.gid_count,
            reply->info.stat.gid_array,
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

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_request_stat(
    globus_gridftp_server_control_op_t  op,
    const char *                        path,
    globus_gridftp_server_control_resource_mask_t mask,
    void *                              user_arg)
{
    char *                              tmp_str;
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_stat_info_t *            stat_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_stat);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return;
    
error_init:
    tmp_str = globus_error_print_friendly(globus_error_peek(result));
    globus_gridftp_server_control_finished_resource(
        op,
        NULL,
        0,
        0,
        0,
        NULL,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        tmp_str);
    globus_free(tmp_str);

    GlobusGFSDebugExitWithError();
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
    GlobusGFSDebugEnter();

    request = (globus_l_gfs_request_info_t *) user_arg;
    info = (globus_gfs_command_info_t *) request->info;
    op = request->control_op;

    if(reply->result == GLOBUS_SUCCESS)
    {
        switch(reply->info.command.command)
        {
          case GLOBUS_GFS_CMD_MKD:
            msg = globus_common_create_string(
                "257 Directory \"%s\" created successfully.\r\n",
                reply->info.command.created_dir);
            globus_gsc_959_finished_command(op, msg);
            globus_free(msg);
            break;
          case GLOBUS_GFS_CMD_RNFR:
            request->instance->rnfr_pathname = info->pathname;
            info->pathname = NULL;
            globus_gsc_959_finished_command(op,
                "350 OK. Send RNTO with destination name.\r\n");
            break;
          case GLOBUS_GFS_CMD_CKSM:
            msg = globus_common_create_string(
                "213 %s\r\n", reply->info.command.checksum);
            globus_gsc_959_finished_command(op, msg);
            globus_free(msg);
            break;

          default:
            globus_gsc_959_finished_command(op, "250 OK.\r\n");
            break;
        }
    }
    else
    {
        msg = globus_error_print_friendly(
            globus_error_peek(reply->result));
        tmp_msg = globus_common_create_string("Command failed : %s", msg);
        globus_free(msg);
        msg = globus_gsc_string_to_959(500, tmp_msg, NULL);
        globus_gsc_959_finished_command(op, msg);
        globus_free(tmp_msg);
        globus_free(msg);
    }
    
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

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_internal_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_l_gfs_request_info_t *       request;
    globus_gfs_stat_info_t *            info;
    GlobusGFSName(globus_l_gfs_data_internal_stat_cb);
    GlobusGFSDebugEnter();

    request = (globus_l_gfs_request_info_t *) user_arg;

    globus_assert(request->bounce_cb && "Invalid internal stat");

    info = (globus_gfs_stat_info_t *) request->bounce_info;
    if(info)
    {
        if(info->pathname)
        {
            globus_free(info->pathname);
        }
        globus_free(info);
    }
    request->bounce_info = NULL;

    switch(request->bounce_type)
    {
        case GLOBUS_GFS_OP_COMMAND:
            {
                globus_gfs_command_info_t * command_info;
                globus_gfs_data_reply_t     command_reply;
                
                memset(&command_reply, 0, sizeof(globus_gfs_data_reply_t));
                command_info = (globus_gfs_command_info_t *) request->info;
                command_reply.info.command.command = command_info->command;
                command_reply.result = reply->result;
                
                request->bounce_cb(&command_reply, request);
            }
            break;
            
        default:
            break;
    }
    
    GlobusGFSDebugExit();
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
    int                                 type;
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_command_info_t *         command_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_bool_t                       done = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_request_command);
    GlobusGFSDebugEnter();

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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_FILE_COMMANDS;
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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_FILE_COMMANDS;
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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_FILE_COMMANDS;
    }
    else if(strcmp(cmd_array[0], "RNFR") == 0)
    {
        globus_gfs_stat_info_t *            stat_info;
    
        command_info->command = GLOBUS_GFS_CMD_RNFR;
        globus_l_gfs_get_full_path(
            instance, cmd_array[1], &command_info->pathname);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
        
        stat_info = (globus_gfs_stat_info_t *) 
            globus_calloc(1, sizeof(globus_gfs_stat_info_t));

        stat_info->file_only = GLOBUS_TRUE;
        stat_info->pathname = globus_libc_strdup(command_info->pathname);
        request->bounce_info = stat_info;
        request->bounce_type = GLOBUS_GFS_OP_COMMAND;
        request->bounce_cb = globus_l_gfs_data_command_cb;
        globus_i_gfs_data_request_stat(
            NULL,
            instance->session_arg,
            0,
            stat_info,
            globus_l_gfs_data_internal_stat_cb,
            request);
        done = GLOBUS_TRUE;
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_FILE_COMMANDS;
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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_FILE_COMMANDS;
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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_FILE_COMMANDS;

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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_SITE;
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
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_SITE;
    }
    else if(strcmp(cmd_array[0], "SITE") == 0 &&
        strcmp(cmd_array[1], "AUTHZ_ASSERT") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_SITE_AUTHZ_ASSERT;
        command_info->authz_assert = strdup(cmd_array[2]);
        if(command_info->authz_assert == NULL)
        {
            goto err;
        }
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_SITE;
    }
    else if(strcmp(cmd_array[0], "SITE") == 0 &&
        strcmp(cmd_array[1], "RDEL") == 0)
    {
        command_info->command = GLOBUS_GFS_CMD_SITE_RDEL;
        command_info->pathname = strdup(cmd_array[2]);
        if(command_info->pathname == NULL)
        {
            goto err;
        }
        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_SITE;
    }
    else if(strcmp(cmd_array[0], "SITE") == 0 &&
        strcmp(cmd_array[1], "VERSION") == 0)
    {
        char                            version_string[1024];

        type = GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_SITE;
        snprintf(version_string, sizeof(version_string),
            "200 %s\r\n", globus_i_gfs_config_string("version_string"));
        globus_gsc_959_finished_command(op, version_string);
        done = GLOBUS_TRUE;
    }
    else
    {
        goto err;
    }

    if(!done)
    {
        globus_i_gfs_data_request_command(
            NULL,
            instance->session_arg,
            0,
            command_info,
            globus_l_gfs_data_command_cb,
            request);
    }
    globus_l_gfs_control_log(instance->server_handle, full_command,
        type, instance);
    
    GlobusGFSDebugExit();
    return;

err:   
error_init:

    globus_l_gfs_control_log(instance->server_handle, full_command,
        GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_ERROR, instance);
    globus_gsc_959_finished_command(op,
        "501 Invalid command arguments.\r\n");

    GlobusGFSDebugExitWithError();
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
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return;

error:
    GlobusGFSDebugExitWithError();
}

static
int
globus_l_gfs_get_event_mask(
    int                                 in_event_mask)
{
    int                                 out_event_mask = 0;
    GlobusGFSName(globus_l_gfs_get_event_mask);
    GlobusGFSDebugEnter();

    if(in_event_mask & GLOBUS_GFS_EVENT_BYTES_RECVD)
    {
        out_event_mask |= GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF;
    }
    if(in_event_mask & GLOBUS_GFS_EVENT_RANGES_RECVD)
    {
        out_event_mask |= GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART;
    }
    if(in_event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT)
    {
        out_event_mask |= GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT;
    }
    if(in_event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
    {
        out_event_mask |= 
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_TRANSFER_COMPLETE;
    }

    GlobusGFSDebugExit();
    return out_event_mask;
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
    int                                 event_mask;
    GlobusGFSName(globus_l_gfs_data_event_cb);
    GlobusGFSDebugEnter();

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            request->event_arg = reply->event_arg;
            
            request->transfer_events = GLOBUS_TRUE;
            event_mask = globus_l_gfs_get_event_mask(reply->event_mask);
            result = globus_gridftp_server_control_events_enable(
                op,
                event_mask,
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

    GlobusGFSDebugExit();
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
    globus_bool_t                       destroy_req;
    GlobusGFSName(globus_l_gfs_data_transfer_cb);
    GlobusGFSDebugEnter();

    request = (globus_l_gfs_request_info_t *) user_arg;
    op = request->control_op;

    destroy_req = !request->transfer_events;
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
    if(destroy_req)
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

    GlobusGFSDebugExit();
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
    char *                              tmp_str;
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_transfer_info_t *        send_info;
    int                                 args;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_send);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return;
    
error_init:
    tmp_str = globus_error_print_friendly(globus_error_peek(result));
    globus_gridftp_server_control_finished_transfer(
        op,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        tmp_str);
    globus_free(tmp_str);
    GlobusGFSDebugExitWithError();
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
    char *                              tmp_str;
    globus_l_gfs_server_instance_t *    instance;
    int                                 args;
    globus_gfs_transfer_info_t *        recv_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_off_t                        length = GLOBUS_RANGE_LIST_MAX;
    globus_off_t                        offset = 0;
    GlobusGFSName(globus_l_gfs_request_recv);
    GlobusGFSDebugEnter();

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    recv_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));

    result = globus_l_gfs_request_info_init(
        &request, instance, op, recv_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    result = globus_gridftp_server_control_get_allocated(
        op, &recv_info->alloc_size);
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

    GlobusGFSDebugExit();
    return;
    
error_init:
    tmp_str = globus_error_print_friendly(globus_error_peek(result));
    globus_gridftp_server_control_finished_transfer(
        op,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        tmp_str);
    globus_free(tmp_str);

    GlobusGFSDebugExitWithError();
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
    char *                              tmp_str;
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_transfer_info_t *        list_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_request_list);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return;
    
error_init:
    tmp_str = globus_error_print_friendly(globus_error_peek(result));
    globus_gridftp_server_control_finished_transfer(
        op,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        tmp_str);
    globus_free(tmp_str);
    GlobusGFSDebugExitWithError();
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
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
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
    GlobusGFSName(globus_l_gfs_get_data_info);
    GlobusGFSDebugEnter();

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

    result = globus_gridftp_server_control_get_layout(                                       
        op,
        (globus_gsc_layout_t *) &data_info->stripe_layout,
        &data_info->stripe_blocksize);
    globus_assert(result == GLOBUS_SUCCESS);
    
    if(data_info->stripe_blocksize == 0 || 
        globus_i_gfs_config_bool("stripe_blocksize_locked"))
    {
        data_info->stripe_blocksize = 
            globus_i_gfs_config_int("stripe_blocksize");
    }
    if(globus_i_gfs_config_int("stripe_layout_locked"))
    {
        data_info->stripe_layout = 
            globus_i_gfs_config_int("stripe_layout");
    }
    else
    {        
        switch(data_info->stripe_layout)
        {
            case GLOBUS_GSC_LAYOUT_TYPE_PARTITIONED:
                data_info->stripe_layout = GLOBUS_GFS_LAYOUT_PARTITIONED;
                break;
            case GLOBUS_GSC_LAYOUT_TYPE_BLOCKED:
                data_info->stripe_layout = GLOBUS_GFS_LAYOUT_BLOCKED;
                break;
            case GLOBUS_GSC_LAYOUT_TYPE_NONE:
            default:
                data_info->stripe_layout = 
                    globus_i_gfs_config_int("stripe_layout");
                break;
        }
    }
    
    data_info->blocksize = globus_i_gfs_config_int("blocksize");

    GlobusGFSDebugExit();
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
    char *                              tmp_str;
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_data_info_t *            data_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_xio_contact_t                parsed_contact;
    GlobusGFSName(globus_l_gfs_request_passive_data);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return;
    
error_init:
    tmp_str = globus_error_print_friendly(globus_error_peek(result));
    globus_gridftp_server_control_finished_passive_connect(
        op,
        NULL,
        0,
        NULL,
        0,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        tmp_str);
    globus_free(tmp_str);
    GlobusGFSDebugExitWithError();
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
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
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
    char *                              tmp_str;
    globus_l_gfs_server_instance_t *    instance;
    globus_gfs_data_info_t *            data_info;
    globus_l_gfs_request_info_t *       request;
    globus_result_t                     result;
    globus_xio_contact_t                parsed_contact;
    GlobusGFSName(globus_l_gfs_request_active_data);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return;
    
error_init:
    tmp_str = globus_error_print_friendly(globus_error_peek(result));
    globus_gridftp_server_control_finished_active_connect(
        op,
        NULL,
        0,
        GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_ACTION_FAILED,
        tmp_str);
    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_request_data_destroy(
    void *                              user_data_arg,
    void *                              user_arg)
{
    globus_l_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_request_data_destroy);
    GlobusGFSDebugEnter();

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    globus_i_gfs_data_request_handle_destroy(
        NULL, instance->session_arg, user_data_arg);

    GlobusGFSDebugExit();
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
    GlobusGFSName(globus_l_gfs_control_log);
    GlobusGFSDebugEnter();

    instance = (globus_l_gfs_server_instance_t *) user_arg;

    if(instance == GLOBUS_NULL)
    {
        goto error;
    }

    switch(type)
    {
      case GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_REPLY:
        log_type = GLOBUS_I_GFS_LOG_DUMP;
        globus_i_gfs_log_message(log_type, "%s: [SERVER]: %s",
            instance->remote_contact, message);
        break;
      case GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_ERROR:
        log_type = GLOBUS_I_GFS_LOG_WARN;
        globus_i_gfs_log_message(log_type, "%s: [CLIENT ERROR]: %s",
            instance->remote_contact, message);
         break;
      default:
        log_type = GLOBUS_I_GFS_LOG_DUMP;
        globus_i_gfs_log_message(log_type, "%s: [CLIENT]: %s",
            instance->remote_contact, message);
         break;
    }


    GlobusGFSDebugExit();
    return;

error:
    GlobusGFSDebugExitWithError();
}


static
globus_result_t
globus_l_gfs_add_commands(
    globus_l_gfs_server_instance_t *    instance,
    globus_gridftp_server_control_t     control_handle)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_add_commands);
    GlobusGFSDebugEnter();

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
        "SITE AUTHZ_ASSERT",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        3,
        3,
        "SITE AUTHZ_ASSERT <sp> pathname",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gridftp_server_control_add_feature(
                                        control_handle, "AUTHZ_ASSERT");
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_gsc_959_command_add(
        control_handle,
        "SITE RDEL",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        3,
        3,
        "SITE RDEL <sp> pathname",
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
    result = globus_gsc_959_command_add(
        control_handle,
        "SITE VERSION",
        globus_l_gfs_request_command,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "SITE VERSION",
        instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusGFSDebugExitWithError();
    return result;
}

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_socket_t          system_handle,
    const char *                        remote_contact,
    const char *                        local_contact,
    globus_i_gfs_server_close_cb_t      close_func,
    void *                              close_arg)
{
    globus_result_t                     result;
    globus_gridftp_server_control_attr_t attr;
    globus_l_gfs_server_instance_t *    instance;
    int                                 idle_timeout;
    int                                 preauth_timeout;
    char *                              banner;
    char *                              login_msg;
    globus_list_t *                     module_list;
    globus_list_t *                     list;
    char *                              alias;
    char *                              module;    
    GlobusGFSName(globus_i_gfs_control_start);
    GlobusGFSDebugEnter();

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
        GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI |
         ((globus_i_gfs_config_bool("allow_anonymous") ||
            globus_i_gfs_config_string("pw_file")!=NULL) ?
         GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE : 0));
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    idle_timeout = globus_i_gfs_config_int("control_idle_timeout");
    preauth_timeout = globus_i_gfs_config_int("control_preauth_timeout");
    
    result = globus_gridftp_server_control_attr_set_idle_time(
        attr, idle_timeout, preauth_timeout);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
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

    module_list = (globus_list_t *) globus_i_gfs_config_get("module_list");  
    for(list = module_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        /* parse out alias name from <alias> or <alias>:<module> */
        alias = globus_libc_strdup((char *) globus_list_first(list));
        module = strchr(alias, ':');
        if(module != NULL)
        {
            *module = '\0';
        }
        result = globus_gridftp_server_control_attr_add_recv(
            attr, alias, globus_l_gfs_request_recv, instance);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_attr_setup;
        }
        result = globus_gridftp_server_control_attr_add_send(
            attr, alias, globus_l_gfs_request_send, instance);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_attr_setup;
        }
        globus_free(alias);
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

    GlobusGFSDebugExit();
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
    GlobusGFSDebugExitWithError();
    return result;
}
