#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gridftp_server.h"

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
    
    attr->partial_offset = 0;
    attr->partial_length = -1;
    attr->restart_marker = GLOBUS_NULL;
    
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
    out_attr->restart_marker = in_attr->restart_marker;
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
    const char *                        user_name,
    const char *                        pw,
    const char *                        subject)
{

    globus_result_t                     result; 
    int                                 rc;
    char *                              local_name;
    struct passwd *                     pwent;

/* XXX add error responses */
    rc = globus_gss_assist_gridmap((char *) subject, &local_name);
    if(rc != 0)
    {
        goto error_gridmap;
    }
    
    pwent = getpwnam(local_name);
    if(pwent == NULL)
    {
        goto error_getpwnam;
    }
    globus_free(local_name);
                      
    globus_gridftp_server_control_finished_auth(
        op, GLOBUS_SUCCESS, pwent->pw_uid);

    return;
   
error_getpwnam:
    globus_free(local_name);
error_gridmap:
    globus_gridftp_server_control_finished_auth(
        op, result, 0);
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
    
    globus_gridftp_server_control_finished_resource(
        op, result, stat_info, stat_count);
}

static
void
globus_l_gfs_resource_request(
    globus_gridftp_server_control_op_t              op,
    const char *                                    path,
    globus_gridftp_server_control_resource_mask_t   mask)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_l_gfs_resource_request);
    
    result = globus_i_gfs_ipc_resource_request(
        instance,
        path,
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
        op, result, GLOBUS_NULL, 0);
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
    
    op = (globus_gridftp_server_control_op_t) user_arg;
    
    switch(type)
    {
      case GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN:
        globus_gridftp_server_control_begin_transfer(
            op,
            //GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF | 
            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART);
        break;
      
      case GLOBUS_I_GFS_EVENT_DISCONNECTED:
        /* globus_gridftp_server_control_disconnected(data); */
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
    
    globus_gridftp_server_control_finished_transfer(op, result);
}

static
void
globus_l_gfs_send_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        local_target,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_gridftp_server_control_restart_t restart_marker)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_op_attr_t *    op_attr;            
    globus_i_gfs_ipc_data_handle_t *    data;
    int                                 args;
    GlobusGFSName(globus_l_gfs_send_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;

    result = globus_l_gfs_op_attr_init(&op_attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_op_attr_init", result);
        goto error_attr;
    }

    if(mod_name && strcmp("P", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT" %"GLOBUS_OFF_T_FORMAT,
            &op_attr->partial_offset,
            &op_attr->partial_length);
            
        globus_assert(args == 2);
    } 
    
    op_attr->restart_marker = restart_marker;
    
    result = globus_i_gfs_ipc_send_request(
        instance,
        op_attr,
        data,
        local_target,
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
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
    globus_gridftp_server_control_finished_transfer(op, result);
}

static
void
globus_l_gfs_recv_request(
    globus_gridftp_server_control_op_t  op,
    void *                              data_handle,
    const char *                        local_target,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_gridftp_server_control_restart_t restart_marker)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_op_attr_t *    op_attr;            
    globus_i_gfs_ipc_data_handle_t *    data;
    int                                 args;
    GlobusGFSName(globus_l_gfs_recv_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;
    
    result = globus_l_gfs_op_attr_init(&op_attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_op_attr_init", result);
        goto error_attr;
    }

    if(mod_name && strcmp("A", mod_name) == 0)
    {
        args = sscanf(
            mod_parms,
            "%"GLOBUS_OFF_T_FORMAT,
            &op_attr->partial_offset);
            
        globus_assert(args == 1);
    }            

    op_attr->restart_marker = restart_marker;

    result = globus_i_gfs_ipc_recv_request(
        instance,
        op_attr,
        data,
        local_target,
        mod_name,
        mod_parms,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        op);
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
    globus_gridftp_server_control_finished_transfer(op, result);
}

static
void
globus_l_gfs_list_request(
    globus_gridftp_server_control_op_t              op,
    void *                                          data_handle,
    const char *                                    path)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_ipc_data_handle_t *    data;
    GlobusGFSName(globus_l_gfs_list_request);
    
    data = (globus_i_gfs_ipc_data_handle_t *) data_handle;
        
    result = globus_i_gfs_ipc_list_request(
        instance,
        data,
        path,
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
    globus_gridftp_server_control_finished_resource(
        op, result, GLOBUS_NULL, 0);
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
    
    globus_gridftp_server_control_finished_passive_connect(
        op,
        data_handle,
        result,
        bi_directional 
            ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
            : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND,
        contact_strings,
        cs_count);
}

static
void
globus_l_gfs_op_to_attr(
    globus_gridftp_server_control_op_t               op,
    globus_i_gfs_data_attr_t *                       attr,
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
}

static
void
globus_l_gfs_passive_data_connect(
    globus_gridftp_server_control_op_t               op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    int                                              max)
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
    
    result = globus_i_gfs_ipc_passive_data_request(
        instance,
        &attr,
        globus_l_gfs_ipc_passive_data_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_passive_data_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_passive_connect(
        op, GLOBUS_NULL, result, 0, GLOBUS_NULL, 0);
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
    
    globus_gridftp_server_control_finished_active_connect(
        op,
        data_handle,
        result,
        bi_directional 
            ? GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI
            : GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_RECV);
}

static
void
globus_l_gfs_active_data_connect(
    globus_gridftp_server_control_op_t               op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    const char **                                    cs,
    int                                              cs_count)
{
    globus_result_t                     result;
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_attr_t            attr;
    GlobusGFSName(globus_l_gfs_active_data_connect);
    
    globus_l_gfs_op_to_attr(op, &attr, net_prt);
    
    result = globus_i_gfs_ipc_active_data_request(
        instance,
        &attr,
        cs,
        cs_count,
        globus_l_gfs_ipc_active_data_cb,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_ipc_active_data_request", result);
        goto error_ipc;
    }
    
    return;

error_ipc:     
    globus_gridftp_server_control_finished_active_connect(
        op, GLOBUS_NULL, result, 0);
}

static
void
globus_l_gfs_data_destroy(
    void *                              user_data_handle)
{
    globus_i_gfs_ipc_data_handle_t *    data_handle;
    
    data_handle = (globus_i_gfs_ipc_data_handle_t *) user_data_handle;
    
    globus_i_gfs_ipc_data_destroy(data_handle);
}

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact)
{
    globus_result_t                     result;
    globus_gridftp_server_control_attr_t attr;
    globus_i_gfs_server_instance_t *    instance;
    GlobusGFSName(globus_i_gfs_control_start);
    
    instance = (globus_i_gfs_server_instance_t *)
        globus_malloc(sizeof(globus_i_gfs_server_instance_t));
    if(!instance)
    {
        result = GlobusGFSErrorMemory("instance");
        goto error_malloc;
    }
    
    instance->xio_handle = handle;
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
/*MMM    
    result = globus_gridftp_server_control_attr_set_done(
        attr, globus_l_gfs_done_cb);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
*/    
    result = globus_gridftp_server_control_attr_set_resource(
        attr, globus_l_gfs_resource_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_set_auth(
        attr, globus_l_gfs_auth_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_add_recv(
        attr, GLOBUS_NULL, globus_l_gfs_recv_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_recv(
        attr, "A", globus_l_gfs_recv_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_add_send(
        attr, GLOBUS_NULL, globus_l_gfs_send_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_add_send(
        attr, "P", globus_l_gfs_send_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_attr_set_list(
        attr, globus_l_gfs_list_request);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }
    
    result = globus_gridftp_server_control_attr_data_functions(
        attr,
        globus_l_gfs_active_data_connect,
        globus_l_gfs_passive_data_connect,
        globus_l_gfs_data_destroy);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_setup;
    }

    result = globus_gridftp_server_control_init(&instance->u.control.server);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_init;
    }

    result = globus_gridftp_server_control_start(
        instance->u.control.server, attr, handle, globus_l_gfs_done_cb, instance);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_start;
    }
    
    globus_gridftp_server_control_attr_destroy(attr);
    
    return GLOBUS_SUCCESS;

error_start:
    globus_gridftp_server_control_destroy(instance->u.control.server);
    
error_init:
error_attr_setup:
    globus_gridftp_server_control_attr_destroy(attr);
    
error_attr:
    globus_free(instance->remote_contact);
    
error_strdup:
    globus_free(instance);
    
error_malloc:
    return result;
}



/*

typedef enum globus_gsc_959_command_desc_e
{
    GLOBUS_GSC_COMMAND_POST_AUTH = 0x01,
    GLOBUS_GSC_COMMAND_PRE_AUTH = 0x02
} globus_gsc_959_command_desc_t;


typedef void
(*globus_gsc_959_command_cb_t)(
    globus_gsc_959_op_t                     op,
    const char *                            full_command,
    char **                                 cmd_array,
    int                                     argc,
    void *                                  user_arg);

                                                                                
globus_result_t
globus_gsc_959_command_add(
    globus_gridftp_server_control_t         server,
    const char *                            command_name,
    globus_gsc_959_command_cb_t             command_cb,
    globus_gsc_959_command_desc_t           desc,
    int                                     min_argc,
    int                                     max_argc,
    const char *                            help,
    void *                                  user_arg);
 
                                                                                
void
globus_gsc_959_finished_command(
    globus_gsc_959_op_t                     op,
    char *                                  reply_msg);
    
*/    

