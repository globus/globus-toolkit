#include "globus_gridftp_server.h"
#include "globus_i_gfs_ipc.h"
#include "version.h"

typedef struct globus_l_gfs_remote_handle_s
{
    void *                              state;
    globus_gfs_session_info_t           session_info;
    globus_list_t *                     cached_node_list;
} globus_l_gfs_remote_handle_t;

typedef struct globus_l_gfs_remote_ipc_bounce_s
{
    globus_gfs_operation_t              op;
    void *                              state;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 nodes_pending;
    int                                 begin_event_pending;
    int                                 event_pending;
    int *                               eof_count;
    globus_list_t *                     node_list;
    int                                 partial_eof_counts;
    globus_bool_t                       recv_pending;
    int                                 nodes_requesting;
    int                                 node_count;
    int                                 finished;
    int                                 final_eof;
    int                                 cached_result;
} globus_l_gfs_remote_ipc_bounce_t;

typedef struct globus_l_gfs_remote_node_info_s
{
    globus_gfs_ipc_handle_t             ipc_handle;
    char *                              cs;
    int                                 data_handle_id;
    int                                 transfer_id;
    int                                 event_mask;
    int                                 node_ndx;
} globus_l_gfs_remote_node_info_t;

typedef void
(*globus_l_gfs_remote_node_cb)(
    globus_l_gfs_remote_node_info_t * node_info,
    globus_result_t                     result,
    void *                              user_arg);

typedef struct globus_l_gfs_remote_request_s
{
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_cb       callback;
    void *                              user_arg;
    int                                 nodes_created;
    void *                              state;
} globus_l_gfs_remote_request_t;
              
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
globus_l_gfs_remote_recv_next(
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info);


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

static
globus_result_t
globus_l_gfs_remote_node_release(
    globus_l_gfs_remote_handle_t *      my_handle,
    globus_l_gfs_remote_node_info_t * node_info)
{
    globus_list_insert(&my_handle->cached_node_list, node_info);
    
    return GLOBUS_SUCCESS;
}  

static
void
globus_l_gfs_remote_node_request_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_request_t *     bounce_info;
    globus_l_gfs_remote_node_info_t * node_info;
    GlobusGFSName(globus_l_gfs_ipc_node_request_cb);
    
    bounce_info = (globus_l_gfs_remote_request_t *)  user_arg;

    node_info = (globus_l_gfs_remote_node_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_node_info_t));
    node_info->ipc_handle = ipc_handle;

    bounce_info->callback(
        node_info,
        result,
        bounce_info->user_arg);
        
    return;    
}
                
static
globus_result_t                    
globus_l_gfs_remote_node_request(
    globus_l_gfs_remote_handle_t *      my_handle,
    int *                               num_nodes,
    char *                              pathname,
    globus_l_gfs_remote_node_cb       callback,
    void *                              user_arg)
{
    globus_l_gfs_remote_request_t *     bounce_info;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 current_node_count;
    globus_l_gfs_remote_node_info_t * node_info;
    int                                 nodes;
    GlobusGFSName(globus_l_gfs_remote_create_nodes);
        
    bounce_info = (globus_l_gfs_remote_request_t *) 
        globus_calloc(1, sizeof(globus_l_gfs_remote_request_t));
    
    bounce_info->callback = callback;
    bounce_info->user_arg = user_arg;
    bounce_info->my_handle = my_handle;
    
    current_node_count = globus_list_size(my_handle->cached_node_list);
    nodes = *num_nodes;
    if(nodes == 0)
    {
        globus_gfs_ipc_handle_get_max_available_count(
            my_handle->session_info.username, pathname, &nodes);
        bounce_info->nodes_created = nodes;
    }
    *num_nodes = nodes;
    bounce_info->nodes_created = nodes;

    if(current_node_count >= nodes)
    {
        while(nodes--)
        {
            node_info = (globus_l_gfs_remote_node_info_t *)
                globus_list_first(my_handle->cached_node_list);
            my_handle->cached_node_list = 
                globus_list_rest(my_handle->cached_node_list);
    
            bounce_info->callback(
                node_info,
                GLOBUS_SUCCESS,
                bounce_info->user_arg);
        }
    }
    else
    {            
        result = globus_gfs_ipc_handle_obtain_by_path(
            &bounce_info->nodes_created,
            pathname,
            &my_handle->session_info,
            &globus_gfs_ipc_default_iface,
            globus_l_gfs_remote_node_request_kickout,
            bounce_info,
            globus_l_gfs_remote_ipc_error_cb,
            bounce_info); 
        if(result != GLOBUS_SUCCESS)
        {
    //        GlobusGFSErrorOpFinished(op, result);
        }
    }
    return result;
}    

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
    
    result = globus_l_gfs_remote_node_release(
        bounce_info->my_handle,
        globus_list_first(bounce_info->node_list));
        
    globus_free(bounce_info);
    return;
}

static
void
globus_l_gfs_ipc_passive_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_reply_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_node_info_t * node_info;
    int                                 rc;
    globus_list_t *                     list;
    int                                 ndx;
    GlobusGFSName(globus_l_gfs_ipc_data_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    node_info = (globus_l_gfs_remote_node_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_node_info_t));
    node_info->ipc_handle = ipc_handle;
    node_info->cs = globus_libc_strdup(reply->info.data.contact_strings[0]);
    node_info->data_handle_id = reply->info.data.data_handle_id;
    
    bounce_info->nodes_pending--;
    
    rc = globus_list_insert(&bounce_info->node_list, node_info);
    
    if(!bounce_info->nodes_pending && !bounce_info->nodes_requesting)
    {
        globus_gfs_finished_info_t *    finished_info;
        
        finished_info = (globus_gfs_finished_info_t *)
            globus_calloc(1, sizeof(globus_gfs_finished_info_t));
        memcpy(finished_info, reply, sizeof(globus_gfs_finished_info_t));

        finished_info->info.data.data_handle_id = 
            (int) bounce_info->node_list;        
        finished_info->info.data.cs_count = 
            globus_list_size(bounce_info->node_list);

        finished_info->info.data.contact_strings = (const char **)
            globus_malloc(sizeof(char *) * finished_info->info.data.cs_count);
        for(list = bounce_info->node_list, ndx = 0;
            !globus_list_empty(list);
            list = globus_list_rest(list), ndx++)
        {
            node_info = (globus_l_gfs_remote_node_info_t *) 
                globus_list_first(list);
            /* XXX handle case where cs_count from a single node > 1 */
            finished_info->info.data.contact_strings[ndx] =
                globus_libc_strdup(node_info->cs);
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
    globus_l_gfs_remote_node_info_t * node_info;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_ipc_data_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    node_info = (globus_l_gfs_remote_node_info_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_node_info_t));
    node_info->ipc_handle = ipc_handle;
    node_info->data_handle_id = reply->info.data.data_handle_id;
    
    bounce_info->nodes_pending--;
    
    rc = globus_list_insert(&bounce_info->node_list, node_info);
    
    if(!bounce_info->nodes_pending && !bounce_info->nodes_requesting)
    {
        globus_gfs_finished_info_t *    finished_info;
        
        finished_info = (globus_gfs_finished_info_t *)
            globus_calloc(1, sizeof(globus_gfs_finished_info_t));
        memcpy(finished_info, reply, sizeof(globus_gfs_finished_info_t));

        finished_info->info.data.data_handle_id = 
            (int) bounce_info->node_list;        
 
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
    
    bounce_info->nodes_pending--;
    if(reply->result != 0)
    {
        bounce_info->cached_result = reply->result;
    }
    if(!bounce_info->nodes_pending && !bounce_info->nodes_requesting)
    {
        globus_gfs_finished_info_t *    finished_info;
        
        finished_info = (globus_gfs_finished_info_t *)
            globus_calloc(1, sizeof(globus_gfs_finished_info_t));

        finished_info->type = reply->type;
        finished_info->id = reply->id;
        finished_info->code = reply->code;
        finished_info->msg = reply->msg;
        finished_info->result = reply->result;
        
        if(bounce_info->final_eof==0 && bounce_info->node_count > 1)
        {
            globus_libc_printf("**finishing transfer before final_eof!\n");
            if(bounce_info->cached_result != GLOBUS_SUCCESS)
            {
                printf("with error!!\n");
            }
            bounce_info->finished = GLOBUS_TRUE;
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
globus_l_gfs_ipc_event_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_ipc_event_reply_t *      reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_list_t *                     list;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_l_gfs_remote_node_info_t *   current_node;
    globus_l_gfs_remote_node_info_t *   master_node;
    globus_l_gfs_remote_node_info_t *   node_info;    
    globus_gfs_event_info_t             event_info;
    globus_result_t                     result;
    int                                 ctr;
    GlobusGFSName(globus_l_gfs_ipc_event_cb);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;    
    
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            bounce_info->begin_event_pending--;
            for(list = bounce_info->node_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                node_info = (globus_l_gfs_remote_node_info_t *) 
                    globus_list_first(list);
                if(node_info->ipc_handle == ipc_handle)
                {
                    node_info->transfer_id = reply->transfer_id;
                    node_info->event_mask = reply->event_mask;
                }
            }        
            if(!bounce_info->begin_event_pending)
            {
                if(bounce_info->recv_pending)
                {
                    globus_l_gfs_remote_recv_next(bounce_info);
                }
                else if(!bounce_info->nodes_requesting)
                {
                    reply->transfer_id = (int) bounce_info->node_list;
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
            }
            break;
        case GLOBUS_GFS_EVENT_TRANSFER_CONNECTED:
            bounce_info->event_pending--;
            if(!bounce_info->event_pending && 
                !bounce_info->recv_pending &&
                !bounce_info->nodes_requesting)
            {
                finish = GLOBUS_TRUE;
            }
            break;
        case GLOBUS_GFS_EVENT_PARTIAL_EOF_COUNT:
            for(list = bounce_info->node_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                node_info = (globus_l_gfs_remote_node_info_t *) 
                    globus_list_first(list);
                if(node_info->ipc_handle == ipc_handle)
                {
                    current_node = node_info;
                    globus_assert(node_info->node_ndx != 0);
                }
                if(node_info->node_ndx == 0)
                {
                    master_node = node_info;
                }
            }
            for(ctr = 0; ctr < reply->node_count; ctr++)
            { 
                bounce_info->eof_count[ctr] += reply->eof_count[ctr];
            }
            bounce_info->partial_eof_counts++;
            if(bounce_info->partial_eof_counts + 1 == 
                bounce_info->node_count && !bounce_info->finished)
            {
                memset(&event_info, '\0', sizeof(globus_gfs_event_info_t));
                event_info.type = GLOBUS_GFS_EVENT_FINAL_EOF_COUNT;
                event_info.eof_count = bounce_info->eof_count;
                event_info.node_count = bounce_info->partial_eof_counts + 1;
                result = globus_gfs_ipc_request_transfer_event(
                    master_node->ipc_handle,
                    master_node->transfer_id,
                    &event_info);
                bounce_info->final_eof++;
            }   
            break;
        default:
            if(!bounce_info->event_pending)
            {
                finish = GLOBUS_TRUE;
            }
            break;
    }       
    if(finish)
    {        
        reply->transfer_id = (int) bounce_info->node_list;
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
        globus_calloc(1, sizeof(globus_l_gfs_remote_ipc_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }
    
    bounce_info->op = op;
    bounce_info->state = state;
    bounce_info->my_handle = my_handle;

    *bounce = bounce_info;
    
    return GLOBUS_SUCCESS;

error_alloc:
    return result;
}

static
void
globus_l_gfs_remote_stat_kickout(
    globus_l_gfs_remote_node_info_t * node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_stat_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    globus_list_insert(&bounce_info->node_list, node_info);

    result = globus_gfs_ipc_request_stat(
        node_info->ipc_handle,
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
void
globus_l_gfs_remote_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_nodes;
    GlobusGFSName(globus_l_gfs_remote_stat);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, stat_info, my_handle);

    num_nodes = 1;

    result = globus_l_gfs_remote_node_request(
        my_handle,
        &num_nodes,
        stat_info->pathname,
        globus_l_gfs_remote_stat_kickout,
        bounce_info);                    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    return;
}

static
void
globus_l_gfs_remote_command_kickout(
    globus_l_gfs_remote_node_info_t * node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_command_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    globus_list_insert(&bounce_info->node_list, node_info);

    result = globus_gfs_ipc_request_command(
        node_info->ipc_handle,
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
void
globus_l_gfs_remote_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         command_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_nodes;
    GlobusGFSName(globus_l_gfs_remote_command);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, command_info, my_handle);
            
    num_nodes = 1;            
    result = globus_l_gfs_remote_node_request(
        my_handle,
        &num_nodes,
        command_info->pathname,
        globus_l_gfs_remote_command_kickout,
        bounce_info);                    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    
    return;
}

static
void
globus_l_gfs_remote_list(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t * node_info;
    GlobusGFSName(globus_l_gfs_remote_list);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
            
    bounce_info->node_list = (globus_list_t *) transfer_info->data_handle_id;
            
    node_info = (globus_l_gfs_remote_node_info_t *) 
        globus_list_first(bounce_info->node_list);
        
    transfer_info->data_handle_id = node_info->data_handle_id;
    transfer_info->stripe_count = 1;
    transfer_info->node_ndx = 0;
    transfer_info->node_count = 1;
    bounce_info->event_pending = 1;
    bounce_info->begin_event_pending = 1;
    bounce_info->nodes_pending = 1;
    bounce_info->node_count = 1;
    
    result = globus_gfs_ipc_request_list(
        node_info->ipc_handle,
        transfer_info,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        bounce_info); 
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    return;    
}

static
void
globus_l_gfs_remote_recv_next(
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info)
{
    globus_result_t                     result;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_list_t *                     list;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 node_count;
    int                                 node_index = 1;
    globus_gfs_transfer_info_t *        transfer_info;
    GlobusGFSName(globus_l_gfs_remote_recv_next);
               
    /* already sent recv to node 0, now send the rest */
    transfer_info = (globus_gfs_transfer_info_t *) bounce_info->state;
    
    node_count = globus_list_size(bounce_info->node_list);
    
    for(list = globus_list_rest(bounce_info->node_list);
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
        
        new_transfer_info = (globus_gfs_transfer_info_t *)
            globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
        memcpy(new_transfer_info, transfer_info, 
            sizeof(globus_gfs_transfer_info_t));
        
        new_transfer_info->truncate = GLOBUS_FALSE;
        new_transfer_info->data_handle_id = node_info->data_handle_id;
        new_transfer_info->node_count = node_count;
        new_transfer_info->stripe_count = node_count;
        new_transfer_info->node_ndx = node_index++;
        node_info->node_ndx = new_transfer_info->node_ndx;

        bounce_info->nodes_pending++;
        bounce_info->event_pending++;
        bounce_info->begin_event_pending++;
        bounce_info->nodes_requesting--;
        
        result = globus_gfs_ipc_request_recv(
            node_info->ipc_handle,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            bounce_info); 
        if(result != GLOBUS_SUCCESS)
        {
            GlobusGFSErrorOpFinished(bounce_info->op, result);
        }
    }
    
    bounce_info->recv_pending = GLOBUS_FALSE;
    
    return;     
}

static
void
globus_l_gfs_remote_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 node_count;
    GlobusGFSName(globus_l_gfs_remote_recv);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    
    bounce_info->node_list = (globus_list_t *) transfer_info->data_handle_id;

    /* only going to do the first recv request here, the others
       will be sent after this one responds with the begin event 
    
       we need to do this primarily to make sure the file is opened 
       in TRUNC mode only the first time */
       
    node_count = globus_list_size(bounce_info->node_list);
    if(node_count > 1)
    {
        bounce_info->recv_pending = GLOBUS_TRUE;
    }
    bounce_info->nodes_requesting = node_count;
    bounce_info->node_count = node_count;

            
    node_info = (globus_l_gfs_remote_node_info_t *) 
        globus_list_first(bounce_info->node_list);
    
    new_transfer_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
    memcpy(new_transfer_info, transfer_info, sizeof(globus_gfs_transfer_info_t));

    new_transfer_info->data_handle_id = node_info->data_handle_id;
    new_transfer_info->node_count = node_count;
    new_transfer_info->stripe_count = node_count;
    new_transfer_info->node_ndx = 0;
    node_info->node_ndx = new_transfer_info->node_ndx;

    bounce_info->nodes_pending++;
    bounce_info->event_pending++;
    bounce_info->begin_event_pending++;
    bounce_info->nodes_requesting--;
    
    result = globus_gfs_ipc_request_recv(
        node_info->ipc_handle,
        new_transfer_info,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return;
}


static
void
globus_l_gfs_remote_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t * node_info;
    globus_list_t *                     list;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 node_count;
    int                                 node_index = 0;
    GlobusGFSName(globus_l_gfs_remote_send);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    
    bounce_info->node_list = (globus_list_t *) transfer_info->data_handle_id;

    node_count = globus_list_size(bounce_info->node_list);

    bounce_info->eof_count = (int *) 
        globus_calloc(1, node_count * sizeof(int) + 1);

    bounce_info->nodes_requesting = node_count;
    bounce_info->node_count = node_count;
        
    for(list = bounce_info->node_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
        
        new_transfer_info = (globus_gfs_transfer_info_t *)
            globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
        memcpy(new_transfer_info, transfer_info, sizeof(globus_gfs_transfer_info_t));
            
        new_transfer_info->data_handle_id = node_info->data_handle_id;
        new_transfer_info->node_count = node_count;
        new_transfer_info->stripe_count = node_count;
        new_transfer_info->node_ndx = node_index++;
        node_info->node_ndx = new_transfer_info->node_ndx;
                                    
        bounce_info->nodes_pending++;
        bounce_info->event_pending++;
        bounce_info->begin_event_pending++;

        bounce_info->nodes_requesting--;
        
        result = globus_gfs_ipc_request_send(
            node_info->ipc_handle,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            bounce_info); 
    }
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }
    return;
}

static
void
globus_l_gfs_remote_active_kickout(
    globus_l_gfs_remote_node_info_t * node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_gfs_data_info_t *            tmp_data_info;
    GlobusGFSName(globus_l_gfs_remote_active_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    if(bounce_info->nodes_pending == 0)
    {
        tmp_data_info = (globus_gfs_data_info_t *)
            globus_calloc(1, sizeof(globus_gfs_data_info_t));
        
        memcpy(
            tmp_data_info, bounce_info->state, sizeof(globus_gfs_data_info_t));
    }
    else
    {
        tmp_data_info = (globus_gfs_data_info_t *) bounce_info->state;
    }
    
    bounce_info->nodes_pending++;
    bounce_info->nodes_requesting--;
    
    result = globus_gfs_ipc_request_active_data(
        node_info->ipc_handle,
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
void
globus_l_gfs_remote_active(
    globus_gfs_operation_t              op,
    globus_gfs_data_info_t *            data_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_nodes;
    GlobusGFSName(globus_l_gfs_remote_active);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, data_info, my_handle);
            
    num_nodes = data_info->cs_count;
    bounce_info->nodes_requesting = num_nodes;
    result = globus_l_gfs_remote_node_request(
        my_handle,
        &num_nodes,
        data_info->pathname,
        globus_l_gfs_remote_active_kickout,
        bounce_info);                    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(op, result);
    }
    
    return;
}

static
void
globus_l_gfs_remote_passive_kickout(
    globus_l_gfs_remote_node_info_t * node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_passive_kickout);
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    bounce_info->nodes_pending++;
    bounce_info->nodes_requesting--;

    result = globus_gfs_ipc_request_passive_data(
        node_info->ipc_handle,
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
void
globus_l_gfs_remote_passive(
    globus_gfs_operation_t              op,
    globus_gfs_data_info_t *            data_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_nodes;
    GlobusGFSName(globus_l_gfs_remote_passive);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, data_info, my_handle);
                
    num_nodes = (data_info->max_cs == -1) ? 0 : data_info->max_cs;
    
    bounce_info->nodes_requesting = num_nodes;

    result = globus_l_gfs_remote_node_request(
        my_handle,
        &bounce_info->nodes_requesting,
        data_info->pathname,
        globus_l_gfs_remote_passive_kickout,
        bounce_info);                    
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(op, result);
    }
    
    return;
}

static
void
globus_l_gfs_remote_data_destroy(
    int                                 data_handle_id,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t * node_info;
    globus_list_t *                     node_list;
    globus_list_t *                     list;
    int                                 node_count;
    GlobusGFSName(globus_l_gfs_remote_data_destroy);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    node_list = (globus_list_t *) data_handle_id;

    node_count = globus_list_size(node_list);

    for(list = node_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
                
        result = globus_gfs_ipc_request_data_destroy(
            node_info->ipc_handle,
            node_info->data_handle_id); 
        if(result != GLOBUS_SUCCESS)
        {
           globus_i_gfs_log_result("IPC ERROR: remote_data_destroy: ipc call", result);
        }

        globus_l_gfs_remote_node_release(my_handle, node_info);
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
    globus_l_gfs_remote_node_info_t * node_info;
    globus_list_t *                     node_list;
    globus_list_t *                     list;
    globus_gfs_event_info_t             event_info;
    GlobusGFSName(globus_l_gfs_remote_trev);
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    node_list = (globus_list_t *) transfer_id;
    
    memset(&event_info, '\0', sizeof(globus_gfs_event_info_t));
    event_info.type = event_type;

    
    for(list = node_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
        
        result = globus_gfs_ipc_request_transfer_event(
            node_info->ipc_handle,
            node_info->transfer_id,
            &event_info);
    }                              
    return;
}

static
void
globus_l_gfs_remote_session_start_kickout(
    globus_l_gfs_remote_node_info_t * node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_gfs_finished_info_t *        finished_info;                         
    GlobusGFSName(globus_l_gfs_remote_session_start_kickout);

    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    globus_l_gfs_remote_node_release(
        bounce_info->my_handle, node_info);
                                                                 
    finished_info = (globus_gfs_finished_info_t *)            
        globus_calloc(1, sizeof(globus_gfs_finished_info_t)); 
    finished_info->type = GLOBUS_GFS_OP_SESSION_START;          
    finished_info->result = result;          
    finished_info->session_arg = bounce_info->my_handle;                          
                                                              
    globus_gridftp_server_operation_finished(                 
        bounce_info->op,                                                   
        result,                                               
        finished_info);
        
    return;
}   

static
void
globus_l_gfs_remote_session_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 num_nodes;
    GlobusGFSName(globus_l_gfs_remote_session_start);
    
    my_handle = (globus_l_gfs_remote_handle_t *) 
        globus_calloc(1, sizeof(globus_l_gfs_remote_handle_t));

    if(session_info->username != NULL)
    {
        my_handle->session_info.username = strdup(session_info->username);
    }
    if(session_info->password != NULL)
    {
        my_handle->session_info.password = strdup(session_info->password);
    }
    if(session_info->subject != NULL)
    {
        my_handle->session_info.subject = strdup(session_info->subject);
    }
    my_handle->session_info.del_cred = session_info->del_cred;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, &my_handle->session_info, my_handle);
                
    num_nodes = 1;

    result = globus_l_gfs_remote_node_request(
        my_handle,
        &num_nodes,
        NULL,
        globus_l_gfs_remote_session_start_kickout,
        bounce_info);                       
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(op, result);
    }
    
    return;
}

static
void
globus_l_gfs_remote_session_end(
    void *                              user_arg)
{
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_list_t *                     list;
    globus_result_t                     result;
    globus_l_gfs_remote_node_info_t * node_info;
    GlobusGFSName(globus_l_gfs_remote_session_end);

    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    for(list = my_handle->cached_node_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
                
        result = globus_gfs_ipc_handle_release(node_info->ipc_handle);
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result(
                "ERROR: remote_data_destroy: handle_release", result);
        }
    }                              
   
    return;
}

static
int
globus_l_gfs_remote_activate(void);

static
int
globus_l_gfs_remote_deactivate(void);

static globus_gfs_storage_iface_t       globus_l_gfs_remote_dsi_iface = 
{
    0,
    globus_l_gfs_remote_session_start,
    globus_l_gfs_remote_session_end,
    globus_l_gfs_remote_list,
    globus_l_gfs_remote_send,
    globus_l_gfs_remote_recv,
    globus_l_gfs_remote_trev,
    globus_l_gfs_remote_active,
    globus_l_gfs_remote_passive,
    globus_l_gfs_remote_data_destroy,
    globus_l_gfs_remote_command, 
    globus_l_gfs_remote_stat,
    NULL,
    NULL
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
