
#include "globus_i_gridftp_server.h"

typedef enum
{
    GLOBUS_L_GFS_DATA_REQUESTING,
    GLOBUS_L_GFS_DATA_PENDING,
    GLOBUS_L_GFS_DATA_COMPLETE,
    GLOBUS_L_GFS_DATA_ERROR,
    GLOBUS_L_GFS_DATA_ERROR_COMPLETE
} globus_l_gfs_data_state_t;

typedef struct globus_l_gfs_data_operation_s
{
    globus_i_gfs_server_instance_t *    instance;
    globus_l_gfs_data_state_t           state;
    globus_mutex_t                      lock;
    globus_i_gfs_data_handle_t *        data_handle;
    globus_bool_t                       sending;
    
    union
    {
        globus_i_gfs_data_resource_cb_t resource;
        globus_i_gfs_data_transfer_cb_t transfer;
    } callback;
    
    globus_i_gfs_data_transfer_event_cb_t event_callback;
    void *                              user_arg;
} globus_l_gfs_data_operation_t;

globus_i_gfs_data_attr_t                globus_i_gfs_data_attr_defaults = 
{
    GLOBUS_FALSE,                       /* ipv6 */
    1,                                  /* nstreams */
    'S',                                /* mode */
    'A',                                /* type */
    0,                                  /* tcp_bufsize (sysdefault) */
    256 * 1024                          /* blocksize */
};

static
globus_result_t
globus_l_gfs_data_operation_init(
    globus_l_gfs_data_operation_t **    u_op,
    globus_i_gfs_server_instance_t *    instance)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_operation_init);
    
    op = (globus_l_gfs_data_operation_t *) 
        globus_malloc(sizeof(globus_l_gfs_data_operation_t));
    if(!op)
    {
        result = GlobusGFSErrorMemory("op");
        goto error_alloc;
    }
    
    op->instance = instance;
    globus_mutex_init(&op->lock, GLOBUS_NULL);
    
    *u_op = op;
    return GLOBUS_SUCCESS;
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_operation_destroy(
    globus_l_gfs_data_operation_t *     op)
{
    globus_mutex_destroy(&op->lock);
    globus_free(op);
}

/* XXX */
globus_result_t
globus_l_gfs_file_resource(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    int                                 mask);
    
globus_result_t
globus_i_gfs_data_resource_request(
    globus_i_gfs_server_instance_t *    instance,
    const char *                        pathname,
    globus_bool_t                       file_only,
    globus_i_gfs_data_resource_cb_t     callback,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_resource_request);
    
    result = globus_l_gfs_data_operation_init(&op, instance);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->callback.resource = callback;
    op->user_arg = user_arg;
    
    /* XXX */
    result = globus_l_gfs_file_resource(
        op, pathname, file_only ? GLOBUS_GFS_FILE_ONLY : 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(op);
    
error_op:
    return result;
}

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    globus_object_t *                   error;
    int                                 stat_count;
    globus_gridftp_server_stat_t        stat_info_array[1];
} globus_l_gfs_data_resource_bounce_t;

static
void
globus_l_gfs_data_resource_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_resource_bounce_t * bounce_info;
    
    bounce_info = (globus_l_gfs_data_resource_bounce_t *) user_arg;
    
    bounce_info->op->callback.resource(
        bounce_info->op->instance,
        bounce_info->error
            ? globus_error_put(bounce_info->error) : GLOBUS_SUCCESS,
        bounce_info->stat_info_array,
        bounce_info->stat_count,
        bounce_info->op->user_arg);
            
    globus_l_gfs_data_operation_destroy(bounce_info->op);
    globus_free(bounce_info);
}

void
globus_gridftp_server_finished_resource(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info_array,
    int                                 stat_count)
{
    globus_bool_t                       delay;
    globus_l_gfs_data_resource_bounce_t * bounce_info;
    GlobusGFSName(globus_gridftp_server_finished_resource);
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            delay = GLOBUS_TRUE;
        }
        else
        {
            delay = GLOBUS_FALSE;
        }
        
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
    }
    globus_mutex_unlock(&op->lock);
    
    if(delay)
    {
        bounce_info = (globus_l_gfs_data_resource_bounce_t *)
            globus_malloc(
                sizeof(globus_l_gfs_data_resource_bounce_t) + 
                (sizeof(globus_gridftp_server_stat_t) * (stat_count - 1)));
        if(!bounce_info)
        {
            result = GlobusGFSErrorMemory("bounce_info");
            goto error_alloc;
        }
        
        bounce_info->op = op;
        bounce_info->error = result == GLOBUS_SUCCESS 
            ? GLOBUS_NULL : globus_error_get(result);
        bounce_info->stat_count = stat_count;
        memcpy(
            bounce_info->stat_info_array,
            stat_info_array,
            sizeof(globus_gridftp_server_stat_t) * stat_count);
        
        result = globus_callback_register_oneshot(
            GLOBUS_NULL,
            GLOBUS_NULL,
            globus_l_gfs_data_resource_kickout,
            bounce_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_callback_register_oneshot", result);
            goto error_oneshot;
        }
    }
    else
    {
        op->callback.resource(
            op->instance,
            result,
            stat_info_array,
            stat_count,
            op->user_arg);
            
        globus_l_gfs_data_operation_destroy(op);
    }
    
    return;

error_oneshot:
error_alloc:
    globus_panic(
        GLOBUS_NULL,
        result,
        "[%s:%d] Unrecoverable error",
        _gfs_name,
        __LINE__);
}

static
globus_result_t
globus_l_gfs_data_handle_init(
    globus_i_gfs_data_handle_t **       u_handle,
    globus_i_gfs_data_attr_t *          attr)
{
    globus_i_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_data_handle_init);
    
    handle = (globus_i_gfs_data_handle_t *) 
        globus_malloc(sizeof(globus_i_gfs_data_handle_t));
    if(!handle)
    {
        result = GlobusGFSErrorMemory("handle");
        goto error_alloc;
    }
    
    if(!attr)
    {
        attr = &globus_i_gfs_data_attr_defaults;
    }

    memcpy(&handle->attr, attr, sizeof(globus_i_gfs_data_attr_t));
    
    result = globus_ftp_control_handle_init(&handle->data_channel);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_handle_init", result);
        goto error_data;
    }
    
    result = globus_ftp_control_local_mode(
        &handle->data_channel, handle->attr.mode);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_mode", result);
        goto error_control;
    }
    
    result = globus_ftp_control_local_type(
        &handle->data_channel, handle->attr.type, 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_type", result);
        goto error_control;
    }
    
    if(handle->attr.tcp_bufsize > 0)
    {
        globus_ftp_control_tcpbuffer_t  tcpbuffer;
        
        tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
        tcpbuffer.fixed.size = handle->attr.tcp_bufsize;
        
        result = globus_ftp_control_local_tcp_buffer(
            &handle->data_channel, &tcpbuffer);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_tcp_buffer", result);
            goto error_control;
        }
    }
    
    if(handle->attr.mode == 'S')
    {
        handle->attr.nstreams = 1;
    }
    else
    {
        globus_ftp_control_parallelism_t  parallelism;
        
        globus_assert(handle->attr.mode == 'E');
        
        parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
        parallelism.fixed.size = handle->attr.nstreams;
        
        result = globus_ftp_control_local_parallelism(
            &handle->data_channel, &parallelism);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_parallelism", result);
            goto error_control;
        }
    }
    
    handle->ref = 1;
    handle->closed = GLOBUS_FALSE;
    globus_mutex_init(&handle->lock, GLOBUS_NULL);
    
    *u_handle = handle;
    return GLOBUS_SUCCESS;

error_control:
    globus_ftp_control_handle_destroy(&handle->data_channel);
    
error_data:
    globus_free(handle);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_close_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *			error)
{
    globus_i_gfs_data_handle_t *        handle;
    
    handle = (globus_i_gfs_data_handle_t *) callback_arg;
    
    globus_i_gfs_data_handle_destroy(handle);
}

static
globus_result_t
globus_i_gfs_data_handle_close(
    globus_i_gfs_data_handle_t *        handle)
{
    globus_result_t                     result;
    
    globus_mutex_lock(&handle->lock);
    {
        if(!handle->closed)
        {
            result = globus_ftp_control_data_force_close(
                &handle->data_channel, globus_l_gfs_data_close_cb, handle);
            if(result == GLOBUS_SUCCESS)
            {
                handle->ref++;
            }
            
            handle->closed = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->lock);
    
    return result;
}

void
globus_i_gfs_data_handle_destroy(
    globus_i_gfs_data_handle_t *        handle)
{
    globus_bool_t                       destroy;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_handle_destroy);
    
    globus_mutex_lock(&handle->lock);
    {
        if(--handle->ref == 0)
        {
            destroy = GLOBUS_TRUE;
        }
        else
        {
            destroy = GLOBUS_FALSE;
        }
    }
    globus_mutex_unlock(&handle->lock);
    
    if(destroy)
    {
        if(!handle->closed)
        {
            result = globus_i_gfs_data_handle_close(handle);
            if(result == GLOBUS_SUCCESS)
            {
                destroy = GLOBUS_FALSE;
            }
        }
        
        if(destroy)
        {
            globus_mutex_destroy(&handle->lock);
            globus_ftp_control_handle_destroy(&handle->data_channel);
            globus_free(handle);
        }
    }
}

typedef struct
{
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    char *                              contact_string;
    globus_i_gfs_data_passive_cb_t      callback;
    void *                              user_arg;
} globus_l_gfs_data_passive_bounce_t;

static
void
globus_l_gfs_data_passive_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    
    bounce_info = (globus_l_gfs_data_passive_bounce_t *) user_arg;
    
    bounce_info->callback(
        bounce_info->instance,
        GLOBUS_SUCCESS,
        bounce_info->handle,
        bounce_info->bi_directional,
        (const char **) &bounce_info->contact_string,
        1,
        bounce_info->user_arg);
    
    globus_free(bounce_info->contact_string);
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_data_passive_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    globus_i_gfs_data_passive_cb_t      callback,
    void *                              user_arg)
{
    globus_i_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t      address;
    globus_sockaddr_t                   addr;
    char *                              cs;
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    GlobusGFSName(globus_i_gfs_data_passive_request);
    
    result = globus_l_gfs_data_handle_init(&handle, attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_handle_init", result);
        goto error_handle;
    }
    
    address.host[0] = 1; /* prevent address lookup */
    address.port = 0;
    result = globus_ftp_control_local_pasv(&handle->data_channel, &address);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_pasv", result);
        goto error_control;
    }
    
    GlobusLibcSockaddrSetFamily(addr, AF_INET);
    GlobusLibcSockaddrSetPort(addr, address.port);
    result = globus_libc_addr_to_contact_string(
        &addr, GLOBUS_LIBC_ADDR_LOCAL | GLOBUS_LIBC_ADDR_NUMERIC, &cs);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_libc_addr_to_contact_string", result);
        goto error_control;
    }
    
    bounce_info = (globus_l_gfs_data_passive_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_passive_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->instance = instance;
    bounce_info->handle = handle;
    bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
    bounce_info->contact_string = cs;
    bounce_info->callback = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_data_passive_kickout,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        goto error_oneshot;
    }
    
    return GLOBUS_SUCCESS;

error_oneshot:
    globus_free(bounce_info);
    
error_alloc:
    globus_free(cs);
    
error_control:
    globus_i_gfs_data_handle_destroy(handle);
    
error_handle:
    return result;
}

typedef struct
{
    globus_i_gfs_server_instance_t *    instance;
    globus_i_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    globus_i_gfs_data_active_cb_t       callback;
    void *                              user_arg;
} globus_l_gfs_data_active_bounce_t;

static
void
globus_l_gfs_data_active_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_active_bounce_t * bounce_info;
    
    bounce_info = (globus_l_gfs_data_active_bounce_t *) user_arg;
    
    bounce_info->callback(
        bounce_info->instance,
        GLOBUS_SUCCESS,
        bounce_info->handle,
        bounce_info->bi_directional,
        bounce_info->user_arg);
    
    globus_free(bounce_info);
}

globus_result_t
globus_i_gfs_data_active_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_attr_t *          attr,
    const char **                       contact_strings,
    int                                 cs_count,
    globus_i_gfs_data_active_cb_t       callback,
    void *                              user_arg)
{
    globus_i_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t *    addresses;
    int                                 i;
    globus_l_gfs_data_active_bounce_t * bounce_info;
    GlobusGFSName(globus_i_gfs_data_active_request);
    
    result = globus_l_gfs_data_handle_init(&handle, attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_handle_init", result);
        goto error_handle;
    }
    
    addresses = (globus_ftp_control_host_port_t *)
        globus_malloc(sizeof(globus_ftp_control_host_port_t) * cs_count);
    if(!addresses)
    {
        result = GlobusGFSErrorMemory("addresses");
        goto error_addresses;
    }
    
    for(i = 0; i < cs_count; i++)
    {
        int                             rc;
        
        rc = sscanf(
            contact_strings[i],
            "%d.%d.%d.%d:%hu",
            &addresses[i].host[0],
            &addresses[i].host[1],
            &addresses[i].host[2], 
            &addresses[i].host[3], 
            &addresses[i].port);
        if(rc < 5)
        {
            result = GlobusGFSErrorGeneric("Bad contact string");
            goto error_format;
        }
    }
    
    
    if(cs_count == 1)
    {
        result = globus_ftp_control_local_port(
            &handle->data_channel, addresses);
    }
    else
    {
        result = globus_ftp_control_local_spor(
            &handle->data_channel, addresses, cs_count);
    }
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_port/spor", result);
        goto error_control;
    }
    
    bounce_info = (globus_l_gfs_data_active_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_active_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->instance = instance;
    bounce_info->handle = handle;
    bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
    bounce_info->callback = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_data_active_kickout,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        goto error_oneshot;
    }
    
    globus_free(addresses);
    
    return GLOBUS_SUCCESS;

error_oneshot:
    globus_free(bounce_info);
    
error_alloc:
error_control:
error_format:
    globus_free(addresses);
    
error_addresses:
    globus_i_gfs_data_handle_destroy(handle);
    
error_handle:
    return result;
}

/* XXX */
globus_result_t
globus_l_gfs_file_recv(
    globus_gridftp_server_operation_t   op,
    const char *                        arguments,
    const char *                        pathname);
    
globus_result_t
globus_i_gfs_data_recv_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_handle_t *        data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_data_transfer_cb_t     callback,
    globus_i_gfs_data_transfer_event_cb_t event_callback,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_recv_request);
    
    if(data_handle->closed)
    {
        result = GlobusGFSErrorData("Data handle has been closed");
        goto error_handle;
    }
    
    result = globus_l_gfs_data_operation_init(&op, instance);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->data_handle = data_handle;
    op->sending = GLOBUS_FALSE;
    op->callback.transfer = callback;
    op->event_callback = event_callback;
    op->user_arg = user_arg;
    
    /* XXX */
    result = globus_l_gfs_file_recv(op, module_args, pathname);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("recv_hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(op);

error_op:
error_handle:
    return result;
}

/* XXX */
globus_result_t
globus_l_gfs_file_send(
    globus_gridftp_server_operation_t   op,
    const char *                        arguments,
    const char *                        pathname);
    
globus_result_t
globus_i_gfs_data_send_request(
    globus_i_gfs_server_instance_t *    instance,
    globus_i_gfs_data_handle_t *        data_handle,
    const char *                        pathname,
    const char *                        module_name,
    const char *                        module_args,
    globus_i_gfs_data_transfer_cb_t     callback,
    globus_i_gfs_data_transfer_event_cb_t event_callback,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_data_send_request);
    
    if(data_handle->closed)
    {
        result = GlobusGFSErrorData("Data handle has been closed");
        goto error_handle;
    }
    
    result = globus_l_gfs_data_operation_init(&op, instance);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->data_handle = data_handle;
    op->sending = GLOBUS_TRUE;
    op->callback.transfer = callback;
    op->event_callback = event_callback;
    op->user_arg = user_arg;
    
    /* XXX */
    result = globus_l_gfs_file_send(op, module_args, pathname);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("send_hook", result);
        goto error_hook;
    }
    
    globus_mutex_lock(&op->lock);
    {
        if(op->state == GLOBUS_L_GFS_DATA_REQUESTING)
        {
            op->state = GLOBUS_L_GFS_DATA_PENDING;
        }
    }
    globus_mutex_unlock(&op->lock);
    
    return GLOBUS_SUCCESS;

error_hook:
    globus_l_gfs_data_operation_destroy(op);

error_op:
error_handle:
    return result;
}

void
globus_gridftp_server_begin_transfer(
    globus_gridftp_server_operation_t   op)
{
    globus_result_t                     result;
    GlobusGFSName(globus_gridftp_server_begin_transfer);
    
    if(op->sending)
    {
        result = globus_ftp_control_data_connect_write(
            &op->data_handle->data_channel, GLOBUS_NULL, GLOBUS_NULL);
    }
    else
    {
        result = globus_ftp_control_data_connect_read(
            &op->data_handle->data_channel, GLOBUS_NULL, GLOBUS_NULL);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_connect;
    }
    
    op->event_callback(
        op->instance,
        GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN,
        GLOBUS_NULL,
        op->user_arg);
    
    return;
    
error_connect:
    op->state = GLOBUS_L_GFS_DATA_ERROR;
    globus_gridftp_server_finished_transfer(op, result);
}

static
void
globus_l_gfs_data_write_eof_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    globus_gridftp_server_operation_t   op;
    GlobusGFSName(globus_l_gfs_data_write_eof_cb);
    
    op = (globus_gridftp_server_operation_t) user_arg;
    
    /* XXX mode s only */
    op->event_callback(
        op->instance,
        GLOBUS_I_GFS_EVENT_DISCONNECTED,
        op->data_handle,
        op->user_arg);
        
    op->callback.transfer(
        op->instance,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        op->user_arg);

    globus_l_gfs_data_operation_destroy(op);
}

void
globus_gridftp_server_finished_transfer(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result)
{
    GlobusGFSName(globus_gridftp_server_finished_transfer);
    
    switch(op->state)
    {
      case GLOBUS_L_GFS_DATA_PENDING:
      case GLOBUS_L_GFS_DATA_REQUESTING:
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
        
        if(result == GLOBUS_SUCCESS && op->sending)
        {
            result = globus_ftp_control_data_write(
                &op->data_handle->data_channel,
                "",
                0,
                0,
                GLOBUS_TRUE,
                globus_l_gfs_data_write_eof_cb,
                op);
        }
        
        if(result != GLOBUS_SUCCESS || !op->sending)
        {
            /* XXX mode s only */
            op->event_callback(
                op->instance,
                GLOBUS_I_GFS_EVENT_DISCONNECTED,
                op->data_handle,
                op->user_arg);
                
            op->callback.transfer(
                op->instance,
                result,
                op->user_arg);
        
            globus_l_gfs_data_operation_destroy(op);
        }
        break;
        
      case GLOBUS_L_GFS_DATA_ERROR_COMPLETE:
        op->state = GLOBUS_L_GFS_DATA_COMPLETE;
        
        globus_l_gfs_data_operation_destroy(op);
        break;
      
      /* this state always means this was called internally */
      case GLOBUS_L_GFS_DATA_ERROR:
        globus_i_gfs_data_handle_close(op->data_handle);
        op->event_callback(
            op->instance,
            GLOBUS_I_GFS_EVENT_DISCONNECTED,
            op->data_handle,
            op->user_arg);
        
        op->callback.transfer(
            op->instance,
            result,
            op->user_arg);
        
        op->state = GLOBUS_L_GFS_DATA_ERROR_COMPLETE;
        break;
      
      default:
        globus_assert(0 && "Invalid state");
        break;
    }
}

typedef struct
{
    globus_gridftp_server_operation_t   op;
    
    union
    {
        globus_gridftp_server_write_cb_t write;
        globus_gridftp_server_read_cb_t  read;
    } callback;
    void *                              user_arg;
} globus_l_gfs_data_bounce_t;

static
void
globus_l_gfs_data_write_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_l_gfs_data_write_cb);
    
    bounce_info = (globus_l_gfs_data_bounce_t *) user_arg;
    
    bounce_info->callback.write(
        bounce_info->op,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        buffer,
        length,
        bounce_info->user_arg);
        
    globus_free(bounce_info);
}

globus_result_t
globus_gridftp_server_register_write(
    globus_gridftp_server_operation_t   op,
    globus_byte_t *                     buffer,  
    globus_size_t                       length,  
    globus_off_t                        offset,  
    int                                 stripe_ndx,  
    globus_gridftp_server_write_cb_t    callback,  
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_gridftp_server_register_write);
    
    bounce_info = (globus_l_gfs_data_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = op;
    bounce_info->callback.write = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_ftp_control_data_write(
        &op->data_handle->data_channel,
        buffer,
        length,
        offset,
        GLOBUS_FALSE,
        globus_l_gfs_data_write_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_data_write", result);
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

static
void
globus_l_gfs_data_read_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof)
{
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_l_gfs_data_read_cb);
    
    bounce_info = (globus_l_gfs_data_bounce_t *) user_arg;
    
    bounce_info->callback.read(
        bounce_info->op,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        buffer,
        length,
        offset,
        eof,
        bounce_info->user_arg);
    
    globus_free(bounce_info);
}
    
globus_result_t
globus_gridftp_server_register_read(
    globus_gridftp_server_operation_t   op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,  
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_gridftp_server_register_read);
    
    bounce_info = (globus_l_gfs_data_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = op;
    bounce_info->callback.read = callback;
    bounce_info->user_arg = user_arg;
    
    result = globus_ftp_control_data_read(
        &op->data_handle->data_channel,
        buffer,
        length,
        globus_l_gfs_data_read_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_data_read", result);
        goto error_register;
    }
    
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);
    
error_alloc:
    return result;
}

/* aborts all pending operations and calls callbacks */
void
globus_gridftp_server_flush_queue(
    globus_gridftp_server_operation_t   op)
{
    GlobusGFSName(globus_gridftp_server_flush_queue);
    
    globus_i_gfs_data_handle_close(op->data_handle);
    op->event_callback(
        op->instance,
        GLOBUS_I_GFS_EVENT_DISCONNECTED,
        op->data_handle,
        op->user_arg);
}

void
globus_gridftp_server_update_bytes_written(
    globus_gridftp_server_operation_t   op,
    globus_size_t                       nbytes)
{
    GlobusGFSName(globus_gridftp_server_update_bytes_written);
}

void
globus_gridftp_server_optimal_concurrency(
    globus_gridftp_server_operation_t   op,
    int *                               count)
{
    GlobusGFSName(globus_gridftp_server_optimal_concurrency);
    
    *count = op->data_handle->attr.nstreams * 2;
}

void
globus_gridftp_server_block_size(
    globus_gridftp_server_operation_t   op,
    globus_size_t *                     block_size)
{
    GlobusGFSName(globus_gridftp_server_block_size);
    
    *block_size = op->data_handle->attr.blocksize;
}
