#include "globus_gridftp_server.h"
#include "globus_i_gfs_ipc.h"
#include "version.h"

typedef struct globus_l_gfs_remote_handle_s
{
    const char *                        user_id;
    globus_gfs_ipc_handle_t             ipc_handle;
} globus_l_gfs_remote_handle_t;


typedef struct globus_l_gfs_remote_ipc_bounce_s
{
    globus_gfs_operation_t              op;
    void *                              state;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 stripes_pending;
    int                                 event_pending;
    globus_list_t *                     stripe_list;
} globus_l_gfs_remote_ipc_bounce_t;

static
void
globus_l_gfs_remote_ipc_error_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_log_result(
        "IPC ERROR", result);
            
    return;
}

#define GlobusGFSErrorOpFinished(_op, _result)                              \
do                                                                          \
{                                                                           \
    globus_gfs_finished_info_t *    _finished_info;                         \
                                                                            \
    _finished_info = (globus_gfs_finished_info_t *)                         \
        globus_calloc(1, sizeof(globus_gfs_finished_info_t));               \
                                                                            \
    _finished_info->type = GLOBUS_GFS_OP_FINAL_REPLY;                       \
    _finished_info->code = 0;                                               \
    _finished_info->msg =                                                   \
        globus_error_print_friendly(globus_error_peek(_result));            \
    _finished_info->result = _result;                                       \
                                                                            \
    globus_gridftp_server_operation_finished(                               \
        _op,                                                                \
        _result,                                                            \
        _finished_info);                                                    \
} while(0)                                                                  



static
void
globus_l_gfs_ipc_finished_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_ipc_finished_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    globus_gridftp_server_operation_finished(
        bounce_info->op,
        reply->result,
        reply);
   
   result = globus_gfs_ipc_handle_release(ipc_handle);
   if(result != GLOBUS_SUCCESS)
   {
       globus_i_gfs_log_result("IPC ERROR", result);
   }
   bounce_info->my_handle->ipc_handle = NULL;
    
   return;
}

typedef struct globus_l_gfs_remote_stripe_info_s
{
    globus_gfs_ipc_handle_t             ipc_handle;
    char *                              cs;
    int                                 data_handle_id;
    int                                 transfer_id;
    int                                 event_mask;
} globus_l_gfs_remote_stripe_info_t;


static
void
globus_l_gfs_ipc_passive_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    int                                 rc;
    globus_list_t *                     list;
    int                                 ndx;
    GlobusGFSName(globus_l_gfs_ipc_data_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    stripe_info = (globus_l_gfs_remote_stripe_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_stripe_info_t));
    stripe_info->ipc_handle = ipc_handle;
    stripe_info->cs = globus_libc_strdup(reply->info.data.contact_strings[0]);
    stripe_info->data_handle_id = reply->info.data.data_handle_id;
    
    bounce_info->stripes_pending--;
    
    rc = globus_list_insert(&bounce_info->stripe_list, stripe_info);
    
    if(!bounce_info->stripes_pending)
    {
        globus_gfs_finished_info_t *    finished_info;
        
        finished_info = (globus_gfs_finished_info_t *)
            globus_calloc(1, sizeof(globus_gfs_finished_info_t));
        memcpy(finished_info, reply, sizeof(globus_gfs_finished_info_t));

        finished_info->info.data.data_handle_id = 
            (int) bounce_info->stripe_list;        
        finished_info->info.data.cs_count = 
            globus_list_size(bounce_info->stripe_list);

        finished_info->info.data.contact_strings = (const char **)
            globus_malloc(sizeof(char *) * finished_info->info.data.cs_count);
        for(list = bounce_info->stripe_list, ndx = 0;
            !globus_list_empty(list);
            list = globus_list_rest(list), ndx++)
        {
            stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
                globus_list_first(list);
            /* XXX handle case where cs_count from a single stripe > 1 */
            finished_info->info.data.contact_strings[ndx] =
                globus_libc_strdup(stripe_info->cs);
        }        
        globus_gridftp_server_operation_finished(
            bounce_info->op,
            finished_info->result,
            finished_info);           
    }
       
   return;
}

static
void
globus_l_gfs_ipc_active_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_ipc_data_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    stripe_info = (globus_l_gfs_remote_stripe_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_stripe_info_t));
    stripe_info->ipc_handle = ipc_handle;
    stripe_info->data_handle_id = reply->info.data.data_handle_id;
    
    bounce_info->stripes_pending--;
    
    rc = globus_list_insert(&bounce_info->stripe_list, stripe_info);
    
    if(!bounce_info->stripes_pending)
    {
        globus_gfs_finished_info_t *    finished_info;
        
        finished_info = (globus_gfs_finished_info_t *)
            globus_calloc(1, sizeof(globus_gfs_finished_info_t));
        memcpy(finished_info, reply, sizeof(globus_gfs_finished_info_t));

        finished_info->info.data.data_handle_id = 
            (int) bounce_info->stripe_list;        
 
        globus_gridftp_server_operation_finished(
            bounce_info->op,
            finished_info->result,
            finished_info);           
    }
       
   return;
}

static
void
globus_l_gfs_ipc_transfer_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_ipc_transfer_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    bounce_info->stripes_pending--;
        
    if(!bounce_info->stripes_pending)
    {
        globus_gfs_finished_info_t *    finished_info;
        
        finished_info = (globus_gfs_finished_info_t *)
            globus_calloc(1, sizeof(globus_gfs_finished_info_t));

        finished_info->type = reply->type;
        finished_info->id = reply->id;
        finished_info->code = reply->code;
        finished_info->msg = reply->msg;
        finished_info->result = reply->result;
        
        globus_gridftp_server_operation_finished(
            bounce_info->op,
            finished_info->result,
            finished_info);           
    }
       
   return;
}

static
void
globus_l_gfs_ipc_event_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_event_reply_t *      reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_list_t *                     list;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    GlobusGFSName(globus_l_gfs_ipc_event_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;    
    
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            bounce_info->event_pending--;
            for(list = bounce_info->stripe_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
                    globus_list_first(list);
                if(stripe_info->ipc_handle == ipc_handle)
                {
                    stripe_info->transfer_id = reply->transfer_id;
                    stripe_info->event_mask = reply->event_mask;
                }
            }        
            break;
        default:
            break;
    }        
    if(!bounce_info->event_pending)
    {        
        reply->transfer_id = (int) bounce_info->stripe_list;
        reply->event_mask = 
            GLOBUS_GFS_EVENT_TRANSFER_ABORT | 
            GLOBUS_GFS_EVENT_TRANSFER_COMPLETE |
            GLOBUS_GFS_EVENT_BYTES_RECVD |
            GLOBUS_GFS_EVENT_RANGES_RECVD;

        globus_gridftp_server_operation_event(
            bounce_info->op,
            GLOBUS_SUCCESS,
            reply);
    }
       
   return;
}



static
globus_result_t
globus_l_gfs_remote_init_bounce_info(
    globus_l_gfs_remote_ipc_bounce_t ** bounce,
    globus_gfs_operation_t              op,
    void *                              state,
    globus_l_gfs_remote_handle_t *      my_handle)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_remote_init_bounce_info);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_remote_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = op;
    bounce_info->state = state;
    bounce_info->my_handle = my_handle;
    bounce_info->stripe_list = NULL;
    bounce_info->stripes_pending = 0;
    bounce_info->event_pending = 0;

    *bounce = bounce_info;
    
    return GLOBUS_SUCCESS;

error_alloc:
    return result;
}
    

static
void
globus_l_gfs_remote_stat_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_stat_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    result = globus_gfs_ipc_request_stat(
        ipc_handle,
        0,
        &request_id,
        (globus_gfs_stat_info_t *) bounce_info->state,
        globus_l_gfs_ipc_finished_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    return;
}



static
globus_result_t
globus_l_gfs_remote_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_stripes;
    GlobusGFSName(globus_l_gfs_remote_stat);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, stat_info, my_handle);
    num_stripes = 1;            
    result = globus_gfs_ipc_handle_get(
        &num_stripes,
        my_handle->user_id,
        stat_info->pathname,
        &globus_gfs_ipc_default_iface,
        globus_l_gfs_remote_stat_kickout,
        bounce_info,
        globus_l_gfs_remote_ipc_error_cb,
        bounce_info);        
                    
    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    return result;
}

static
void
globus_l_gfs_remote_command_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_command_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    result = globus_gfs_ipc_request_command(
        ipc_handle,
        0,
        &request_id,
        (globus_gfs_command_info_t *) bounce_info->state,
        globus_l_gfs_ipc_finished_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return;
}

static
globus_result_t
globus_l_gfs_remote_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         command_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_stripes;
    GlobusGFSName(globus_l_gfs_remote_command);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, command_info, my_handle);
            
    num_stripes = 1;            
    result = globus_gfs_ipc_handle_get(
        &num_stripes,
        my_handle->user_id,
        command_info->pathname,
        &globus_gfs_ipc_default_iface,
        globus_l_gfs_remote_command_kickout,
        bounce_info,
        globus_l_gfs_remote_ipc_error_cb,
        bounce_info);        
                    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return result;
}

static
globus_result_t
globus_l_gfs_remote_list(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    int                                 request_id;
    int                                 stripe_count;
    GlobusGFSName(globus_l_gfs_remote_list);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
            
    bounce_info->stripe_list = (globus_list_t *) transfer_info->data_handle_id;
    
    stripe_count = globus_list_size(bounce_info->stripe_list);
        
    stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
        globus_list_first(bounce_info->stripe_list);
        
    transfer_info->data_handle_id = stripe_info->data_handle_id;
    transfer_info->stripe_count = stripe_count;
    transfer_info->node_ndx = 0;
    transfer_info->node_count = 1;
    bounce_info->event_pending = 1;
    bounce_info->stripes_pending = 1;
    
    result = globus_gfs_ipc_request_list(
        stripe_info->ipc_handle,
        0,
        &request_id,
        transfer_info,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        bounce_info); 
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    return result;    
}


static
globus_result_t
globus_l_gfs_remote_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    int                                 request_id;
    globus_list_t *                     list;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 stripe_count;
    GlobusGFSName(globus_l_gfs_remote_recv);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    
    bounce_info->stripe_list = (globus_list_t *) transfer_info->data_handle_id;
    
    stripe_count = globus_list_size(bounce_info->stripe_list);
        
    for(list = bounce_info->stripe_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
            globus_list_first(list);
        
        new_transfer_info = (globus_gfs_transfer_info_t *)
            globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
        memcpy(new_transfer_info, transfer_info, sizeof(globus_gfs_transfer_info_t));

        new_transfer_info->data_handle_id = stripe_info->data_handle_id;
        new_transfer_info->node_count = stripe_count;
        new_transfer_info->stripe_count = stripe_count;
        new_transfer_info->node_ndx = bounce_info->stripes_pending;

        bounce_info->stripes_pending++;
        bounce_info->event_pending++;
        
        result = globus_gfs_ipc_request_recv(
            stripe_info->ipc_handle,
            0,
            &request_id,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            bounce_info); 
    }

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return result;
}


static
globus_result_t
globus_l_gfs_remote_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    int                                 request_id;
    globus_list_t *                     list;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 stripe_count;
    GlobusGFSName(globus_l_gfs_remote_send);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    
    bounce_info->stripe_list = (globus_list_t *) transfer_info->data_handle_id;

    stripe_count = globus_list_size(bounce_info->stripe_list);

    for(list = bounce_info->stripe_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
            globus_list_first(list);
        
        new_transfer_info = (globus_gfs_transfer_info_t *)
            globus_malloc(sizeof(globus_gfs_transfer_info_t));
        memcpy(new_transfer_info, transfer_info, sizeof(globus_gfs_transfer_info_t));
            
        new_transfer_info->data_handle_id = stripe_info->data_handle_id;
        new_transfer_info->node_count = stripe_count;
        new_transfer_info->stripe_count = stripe_count;
        new_transfer_info->node_ndx = bounce_info->stripes_pending;
                            
        bounce_info->stripes_pending++;
        bounce_info->event_pending++;
        
        result = globus_gfs_ipc_request_send(
            stripe_info->ipc_handle,
            0,
            &request_id,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            bounce_info); 
    }
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return result;
}

static
void
globus_l_gfs_remote_active_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    int                                 request_id;
    globus_gfs_data_info_t *            tmp_data_info;
    GlobusGFSName(globus_l_gfs_remote_active_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    if(bounce_info->stripes_pending == 0)
    {
        tmp_data_info = (globus_gfs_data_info_t *)
            globus_calloc(1, sizeof(globus_gfs_data_info_t));
        
        memcpy(tmp_data_info, bounce_info->state, sizeof(globus_gfs_data_info_t));
    }
    else
    {
        tmp_data_info = (globus_gfs_data_info_t *) bounce_info->state;
    }
    
    bounce_info->stripes_pending++;
    
    result = globus_gfs_ipc_request_active_data(
        ipc_handle,
        0,
        &request_id,
        tmp_data_info,
        globus_l_gfs_ipc_active_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return;
}

static
globus_result_t
globus_l_gfs_remote_active(
    globus_gfs_operation_t              op,
    globus_gfs_data_info_t *            data_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_stripes;
    GlobusGFSName(globus_l_gfs_remote_active);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, data_info, my_handle);
            
    num_stripes = data_info->cs_count;
    result = globus_gfs_ipc_handle_get(
        &num_stripes,
        my_handle->user_id,
        NULL,
        &globus_gfs_ipc_default_iface,
        globus_l_gfs_remote_active_kickout,
        bounce_info,
        globus_l_gfs_remote_ipc_error_cb,
        bounce_info);        
                    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(op, result);
    }
    return result;
}

static
void
globus_l_gfs_remote_passive_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    int                                 request_id;
    GlobusGFSName(globus_l_gfs_remote_passive_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    bounce_info->stripes_pending++;

    result = globus_gfs_ipc_request_passive_data(
        ipc_handle,
        0,
        &request_id,
        (globus_gfs_data_info_t *) bounce_info->state,
        globus_l_gfs_ipc_passive_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return;
}

static
globus_result_t
globus_l_gfs_remote_passive(
    globus_gfs_operation_t              op,
    globus_gfs_data_info_t *            data_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_stripes;
    GlobusGFSName(globus_l_gfs_remote_passive);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, data_info, my_handle);
                
    num_stripes = (data_info->max_cs == -1) ? 0 : data_info->max_cs;

    result = globus_gfs_ipc_handle_get(
        &num_stripes,
        my_handle->user_id,
        data_info->pathname,
        &globus_gfs_ipc_default_iface,
        globus_l_gfs_remote_passive_kickout,
        bounce_info,
        globus_l_gfs_remote_ipc_error_cb,
        bounce_info); 
               

    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(op, result);
    }
    return result;
}

static
void
globus_l_gfs_remote_data_destroy(
    int                                 data_handle_id,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    globus_list_t *                     stripe_list;
    globus_list_t *                     list;
    int                                 stripe_count;
    GlobusGFSName(globus_l_gfs_remote_data_destroy);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
       
    stripe_list = (globus_list_t *) data_handle_id;

    stripe_count = globus_list_size(stripe_list);

    for(list = stripe_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
            globus_list_first(list);
                
        result = globus_gfs_ipc_request_data_destroy(
            stripe_info->ipc_handle,
            0,
            stripe_info->data_handle_id); 
        if(result != GLOBUS_SUCCESS)
        {
           globus_i_gfs_log_result("IPC ERROR: remote_data_destroy: ipc call", result);
        }
        result = globus_gfs_ipc_handle_release(stripe_info->ipc_handle);
        if(result != GLOBUS_SUCCESS)
        {
           globus_i_gfs_log_result("IPC ERROR: remote_data_destroy: handle_release", result);
        }
    }
                    
    return;
}


static
void
globus_l_gfs_remote_trev(
    int                                 transfer_id,
    int                                 event_type,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_stripe_info_t * stripe_info;
    globus_list_t *                     stripe_list;
    globus_list_t *                     list;
    GlobusGFSName(globus_l_gfs_remote_trev);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    stripe_list = (globus_list_t *) transfer_id;

    for(list = stripe_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        stripe_info = (globus_l_gfs_remote_stripe_info_t *) 
            globus_list_first(list);
        
        result = globus_gfs_ipc_request_transfer_event(
            stripe_info->ipc_handle,
            (int) my_handle,
            stripe_info->transfer_id,
            event_type);
    }                              
    return;
}


static
void
globus_l_gfs_remote_set_cred(
    globus_gfs_operation_t              op,
    gss_cred_id_t                       cred_thing,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_remote_set_cred);
}


static
globus_result_t
globus_l_gfs_remote_init(
    globus_gfs_operation_t              op,
    const char *                        user_id,
    gss_cred_id_t                       del_cred)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_gfs_finished_info_t *        finished_info;            
    GlobusGFSName(globus_l_gfs_remote_init);
    
    my_handle = (globus_l_gfs_remote_handle_t *) 
        globus_calloc(1, sizeof(globus_l_gfs_remote_handle_t));
        
    my_handle->user_id = globus_libc_strdup(user_id);
    my_handle->ipc_handle = NULL;
                                                              
    finished_info = (globus_gfs_finished_info_t *)            
        globus_calloc(1, sizeof(globus_gfs_finished_info_t)); 
                                                              
    finished_info->type = GLOBUS_GFS_OP_SESSION_START;          
    finished_info->session_id = (int) my_handle;                          
                                                              
    globus_gridftp_server_operation_finished(                 
        op,                                                   
        result,                                               
        finished_info);                                       
    
    return result;
}

static
void
globus_l_gfs_remote_destory(
    void *                              user_arg)
{
}

static
int
globus_l_gfs_remote_activate(void);

static
int
globus_l_gfs_remote_deactivate(void);

static globus_gfs_storage_iface_t       globus_l_gfs_remote_dsi_iface = 
{
    globus_l_gfs_remote_init,
    globus_l_gfs_remote_destory,
    globus_l_gfs_remote_list,
    globus_l_gfs_remote_send,
    globus_l_gfs_remote_recv,
    globus_l_gfs_remote_trev,
    globus_l_gfs_remote_active,
    globus_l_gfs_remote_passive,
    globus_l_gfs_remote_data_destroy,
    globus_l_gfs_remote_command, 
    globus_l_gfs_remote_stat,
    globus_l_gfs_remote_set_cred
};

GlobusExtensionDefineModule(globus_gridftp_server_remote) =
{
    "globus_gridftp_server_remote",
    globus_l_gfs_remote_activate,
    globus_l_gfs_remote_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
int
globus_l_gfs_remote_activate(void)
{
    int                                 rc;
    
    GlobusGFSName(globus_l_gfs_remote_activate);
    
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }
    
    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "remote",
        GlobusExtensionMyModule(globus_gridftp_server_remote),
        &globus_l_gfs_remote_dsi_iface);
    
    return GLOBUS_SUCCESS;
}

static
int
globus_l_gfs_remote_deactivate(void)
{
    GlobusGFSName(globus_l_gfs_remote_deactivate);
    
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "remote");
        
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    
    return GLOBUS_SUCCESS;
}
