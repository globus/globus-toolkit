/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_gridftp_server.h"
#include "version.h"


GlobusDebugDeclare(GLOBUS_GRIDFTP_SERVER_REMOTE);

#define GlobusGFSRemoteDebugPrintf(level, message)                          \
    GlobusDebugPrintf(GLOBUS_GRIDFTP_SERVER_REMOTE, level, message)          
                                                                             
#define GlobusGFSRemoteDebugEnter()                                         \
    GlobusGFSRemoteDebugPrintf(                                             \
        GLOBUS_GFS_DEBUG_TRACE,                                             \
        ("[%s] Entering\n", _gfs_name))                                      
                                                                             
#define GlobusGFSRemoteDebugExit()                                          \
    GlobusGFSRemoteDebugPrintf(                                             \
        GLOBUS_GFS_DEBUG_TRACE,                                             \
        ("[%s] Exiting\n", _gfs_name))                                       
                                                                             
#define GlobusGFSRemoteDebugExitWithError()                                 \
    GlobusGFSRemoteDebugPrintf(                                             \
        GLOBUS_GFS_DEBUG_TRACE,                                             \
        ("[%s] Exiting with error\n", _gfs_name))

GlobusDebugDefine(GLOBUS_GRIDFTP_SERVER_REMOTE);


typedef struct globus_l_gfs_remote_handle_s
{
    void *                              state;
    globus_gfs_session_info_t           session_info;
    globus_priority_q_t                 cached_node_q;
    int *                               nodes_connected;
    int                                 max_nodes;
    int                                 striped_mode;
} globus_l_gfs_remote_handle_t;

typedef struct globus_l_gfs_remote_node_handle_s
{
    globus_list_t *                     node_list;
} globus_l_gfs_remote_node_handle_t;

typedef struct globus_l_gfs_remote_ipc_bounce_s
{
    globus_gfs_operation_t              op;
    void *                              state;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 nodes_pending;
    int                                 begin_event_pending;
    int                                 event_pending;
    int *                               eof_count;
    globus_l_gfs_remote_node_handle_t * node_handle;  
    int                                 partial_eof_counts;
    globus_bool_t                       recv_pending;
    int                                 nodes_requesting;
    int                                 node_ndx;
    int                                 node_count;
    int                                 finished;
    int                                 final_eof;
    int                                 cached_result;
    int                                 sending;
    int                                 events_enabled;
    globus_object_t *                   cached_error;
} globus_l_gfs_remote_ipc_bounce_t;

typedef struct globus_l_gfs_remote_node_info_s
{
    globus_gfs_ipc_handle_t             ipc_handle;
    char *                              cs;
    void *                              data_arg;
    void *                              event_arg;
    int                                 event_mask;
    int                                 node_ndx;
    int                                 stripe_count;
    char *                              username;
    char *                              home_dir;
    int                                 info_needs_free;
    void *                              info;
} globus_l_gfs_remote_node_info_t;

typedef void
(*globus_l_gfs_remote_node_cb)(
    globus_l_gfs_remote_node_info_t *   node_info,
    globus_result_t                     result,
    void *                              user_arg);

typedef struct globus_l_gfs_remote_request_s
{
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_cb         callback;
    void *                              user_arg;
    int                                 nodes_created;
    void *                              state;
} globus_l_gfs_remote_request_t;

typedef enum
{
    GLOBUS_L_GFS_REMOTE_STRIPED_ONE_TO_ONE = 1,
    GLOBUS_L_GFS_REMOTE_STRIPED_ALL_TO_ALL
} globus_l_gfs_remote_striped_mode_t;
    
              
#define GlobusGFSErrorOpFinished(_op, _result)                              \
do                                                                          \
{                                                                           \
    globus_gfs_finished_info_t          _finished_info;                     \
                                                                            \
     memset(&_finished_info, '\0', sizeof(globus_gfs_finished_info_t));     \
    _finished_info.type = GLOBUS_GFS_OP_FINAL_REPLY;                        \
    _finished_info.code = 0;                                                \
    _finished_info.msg =                                                    \
        globus_error_print_friendly(globus_error_peek(_result));            \
    _finished_info.result = _result;                                        \
                                                                            \
    globus_gridftp_server_operation_finished(                               \
        _op,                                                                \
        _result,                                                            \
        &_finished_info);                                                   \
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
    GlobusGFSName(globus_l_gfs_remote_ipc_error_cb);
    GlobusGFSRemoteDebugEnter();
    
    globus_gfs_log_result(
        GLOBUS_GFS_LOG_ERR, "IPC ERROR", result);
            
    GlobusGFSRemoteDebugExit();
}

int
globus_l_gfs_remote_node_list_compare(
    void *                              low_datum, 
    void *                              high_datum,
    void *                              ignored)
{
    globus_l_gfs_remote_node_info_t *   node1;
    globus_l_gfs_remote_node_info_t *   node2;
    int                                 rc = 0;
    GlobusGFSName(globus_l_gfs_remote_node_list_compare);
    GlobusGFSRemoteDebugEnter();

    node1 = (globus_l_gfs_remote_node_info_t *) low_datum;
    node2 = (globus_l_gfs_remote_node_info_t *) high_datum;
    
    rc = (node1->node_ndx < node2->node_ndx);
    
    GlobusGFSRemoteDebugExit();
    return rc;
}

static
int
globus_l_gfs_remote_node_queue_compare(
    void *                              priority_1,
    void *                              priority_2)
{
    globus_l_gfs_remote_node_info_t *   node1;
    globus_l_gfs_remote_node_info_t *   node2;
    int                                 rc = 0;
    GlobusGFSName(globus_l_gfs_remote_node_queue_compare);
    GlobusGFSRemoteDebugEnter();

    node1 = (globus_l_gfs_remote_node_info_t *) priority_1;
    node2 = (globus_l_gfs_remote_node_info_t *) priority_2;
    
    if(node1->node_ndx > node2->node_ndx)
    {
        rc = 1;
    }
    if(node1->node_ndx < node2->node_ndx)
    {
        rc = -1;
    }
    
    GlobusGFSRemoteDebugExit();
    return rc;
}

static
globus_l_gfs_remote_node_info_t *
globus_l_gfs_remote_get_current_node(
    globus_list_t *                     node_list,
    globus_gfs_ipc_handle_t             ipc_handle)
{
    globus_list_t *                     list;
    globus_bool_t                       found = GLOBUS_FALSE;
    globus_l_gfs_remote_node_info_t *   node_info = NULL;
    GlobusGFSName(globus_l_gfs_remote_get_current_node);
    GlobusGFSRemoteDebugEnter();
    
    for(list = node_list;
        !globus_list_empty(list) && !found;
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
        if(node_info->ipc_handle == ipc_handle)
        {
            found = GLOBUS_TRUE;
        }
    }

    GlobusGFSRemoteDebugExit();
    return node_info;    
}

static
globus_result_t
globus_l_gfs_remote_node_release(
    globus_l_gfs_remote_handle_t *      my_handle,
    globus_l_gfs_remote_node_info_t *   node_info)
{
    globus_result_t                     result;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_remote_node_release);
    GlobusGFSRemoteDebugEnter();
    
    rc = globus_priority_q_enqueue(
        &my_handle->cached_node_q, node_info, node_info);
    if(rc != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorGeneric(
            "globus_priority_q_enqueue failed");
        goto error_enqueue;
    }

    GlobusGFSRemoteDebugExit();
    return GLOBUS_SUCCESS;
    
error_enqueue:
    GlobusGFSRemoteDebugExitWithError();
    return result;
}  

static
void
globus_l_gfs_remote_node_request_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_finished_info_t *        reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_request_t *     bounce_info;
    globus_l_gfs_remote_node_info_t *   node_info;
    int                                 ndx;
    GlobusGFSName(globus_l_gfs_remote_node_request_kickout);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_request_t *)  user_arg;

    if(result == GLOBUS_SUCCESS)
    {
        node_info = (globus_l_gfs_remote_node_info_t *)
            globus_calloc(1, sizeof(globus_l_gfs_remote_node_info_t));
        node_info->ipc_handle = ipc_handle;
        if(reply->info.session.username)
        {
            node_info->username = strdup(reply->info.session.username);
        }
        if(reply->info.session.home_dir)
        {
            node_info->home_dir = strdup(reply->info.session.home_dir);
        }
        globus_gfs_ipc_handle_get_index(ipc_handle, &ndx);
        
        node_info->node_ndx = (bounce_info->my_handle->nodes_connected[ndx] *
            bounce_info->my_handle->max_nodes) + ndx;
        bounce_info->my_handle->nodes_connected[ndx]++;
    }
    
    bounce_info->callback(
        node_info,
        result,
        bounce_info->user_arg);
    bounce_info->nodes_created--;
    
    if(!bounce_info->nodes_created)
    {
        globus_free(bounce_info);
    }

    GlobusGFSRemoteDebugExit();
}
                
static
globus_result_t                    
globus_l_gfs_remote_node_request(
    globus_l_gfs_remote_handle_t *      my_handle,
    int *                               num_nodes,
    char *                              pathname,
    globus_l_gfs_remote_node_cb         callback,
    void *                              user_arg)
{
    globus_l_gfs_remote_request_t *     bounce_info;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 current_node_count;
    globus_l_gfs_remote_node_info_t *   node_info;
    int                                 nodes_requested;
    int                                 new_nodes_needed;
    GlobusGFSName(globus_l_gfs_remote_node_request);
    GlobusGFSRemoteDebugEnter();
            
    current_node_count = globus_priority_q_size(&my_handle->cached_node_q);
    nodes_requested = *num_nodes;
    if(nodes_requested == 0)
    {
        nodes_requested = my_handle->max_nodes;
    }
    *num_nodes = nodes_requested;

    new_nodes_needed = nodes_requested - current_node_count;

    if(new_nodes_needed > 0)
    {  
        bounce_info = (globus_l_gfs_remote_request_t *) 
            globus_calloc(1, sizeof(globus_l_gfs_remote_request_t));

        bounce_info->nodes_created = new_nodes_needed;
        bounce_info->callback = callback;
        bounce_info->user_arg = user_arg;
        bounce_info->my_handle = my_handle;
          
        result = globus_gfs_ipc_handle_obtain_by_path(
            &bounce_info->nodes_created,
            pathname,
            &my_handle->session_info,
            &globus_gfs_ipc_default_iface,
            globus_l_gfs_remote_node_request_kickout,
            bounce_info,
            globus_l_gfs_remote_ipc_error_cb,
            my_handle); 
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    while(current_node_count-- && nodes_requested--)
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_priority_q_dequeue(&my_handle->cached_node_q);

        callback(
            node_info,
            GLOBUS_SUCCESS,
            user_arg);
    }
    GlobusGFSRemoteDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusGFSRemoteDebugExitWithError();
    return result;
}    

static
void
globus_l_gfs_ipc_finished_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_finished_info_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_node_info_t *   node_info;    
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_ipc_finished_cb);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    node_info = globus_list_remove(
        &bounce_info->node_handle->node_list, 
        bounce_info->node_handle->node_list);

    if(node_info->info && node_info->info_needs_free)
    {
        globus_free(node_info->info);
        node_info->info = NULL;
        node_info->info_needs_free = GLOBUS_FALSE;
    }

    result = globus_l_gfs_remote_node_release(
        bounce_info->my_handle,
        node_info);

    globus_gridftp_server_operation_finished(
        bounce_info->op,
        reply->result,
        reply);
    
    globus_free(bounce_info->node_handle);
    globus_free(bounce_info);

    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_ipc_passive_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_finished_info_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_list_t *                     list;
    int                                 ndx;
    GlobusGFSName(globus_l_gfs_ipc_passive_cb);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    node_info = globus_l_gfs_remote_get_current_node(
        bounce_info->node_handle->node_list, ipc_handle);
    node_info->cs = globus_libc_strdup(reply->info.data.contact_strings[0]);
    node_info->data_arg = reply->info.data.data_arg;
        
    bounce_info->nodes_pending--;
        
    if(!bounce_info->nodes_pending && !bounce_info->nodes_requesting)
    {
        globus_gfs_finished_info_t      finished_info;
                
        memcpy(&finished_info, reply, sizeof(globus_gfs_finished_info_t));

        bounce_info->node_handle->node_list = 
            globus_list_sort_destructive(
                bounce_info->node_handle->node_list, 
                globus_l_gfs_remote_node_list_compare, 
                NULL);

        finished_info.info.data.data_arg = bounce_info->node_handle;        
        finished_info.info.data.cs_count = 
            globus_list_size(bounce_info->node_handle->node_list);

        finished_info.info.data.contact_strings = (const char **)
            globus_malloc(sizeof(char *) * finished_info.info.data.cs_count);
        for(list = bounce_info->node_handle->node_list, ndx = 0;
            !globus_list_empty(list);
            list = globus_list_rest(list), ndx++)
        {
            node_info = (globus_l_gfs_remote_node_info_t *) 
                globus_list_first(list);
            if(bounce_info->my_handle->striped_mode == 
                GLOBUS_L_GFS_REMOTE_STRIPED_ONE_TO_ONE)
            {
                node_info->stripe_count = 1;
            }
            else
            {
                node_info->stripe_count = finished_info.info.data.cs_count;
            }

            /* XXX handle case where cs_count from a single node > 1 */
            finished_info.info.data.contact_strings[ndx] = node_info->cs;
            node_info->cs = NULL;
        
            if(node_info->info && node_info->info_needs_free)
            {
                globus_free(node_info->info);
                node_info->info = NULL;
                node_info->info_needs_free = GLOBUS_FALSE;
            }
            globus_l_gfs_remote_node_release(
                bounce_info->my_handle,
                node_info);   
        }        
        globus_gridftp_server_operation_finished(
            bounce_info->op,
            finished_info.result,
            &finished_info);
        
        for(ndx = 0; ndx < finished_info.info.data.cs_count; ndx++)
        {
            globus_free((void *) finished_info.info.data.contact_strings[ndx]);
        }
        globus_free(finished_info.info.data.contact_strings);
            
        globus_free(bounce_info);
    }
       
    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_ipc_active_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_finished_info_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_node_info_t *   node_info;
    GlobusGFSName(globus_l_gfs_ipc_active_cb);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    node_info = globus_l_gfs_remote_get_current_node(
        bounce_info->node_handle->node_list, ipc_handle);
    node_info->data_arg = reply->info.data.data_arg;

    if(bounce_info->my_handle->striped_mode == 
        GLOBUS_L_GFS_REMOTE_STRIPED_ONE_TO_ONE)
    {
        node_info->stripe_count = 1;
    }
    else
    {
        node_info->stripe_count = 
            ((globus_gfs_data_info_t *) bounce_info->state)->cs_count;
    }

    bounce_info->nodes_pending--;
        
    if(!bounce_info->nodes_pending && !bounce_info->nodes_requesting)
    {
        globus_gfs_finished_info_t      finished_info;
        globus_list_t *                 list;
                
        memcpy(&finished_info, reply, sizeof(globus_gfs_finished_info_t));

        bounce_info->node_handle->node_list = 
            globus_list_sort_destructive(
                bounce_info->node_handle->node_list, 
                globus_l_gfs_remote_node_list_compare, 
                NULL);

        finished_info.info.data.data_arg = bounce_info->node_handle;        
 
        for(list = bounce_info->node_handle->node_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            globus_gfs_data_info_t *    info;
            node_info = (globus_l_gfs_remote_node_info_t *) 
                globus_list_first(list);
            
            if(node_info->info && node_info->info_needs_free)
            {
                int                     i;
                info = (globus_gfs_data_info_t *) node_info->info;
                for(i = 0; i < info->cs_count; i++)
                {
                    globus_free((void *) info->contact_strings[i]);
                }
                globus_free(info->contact_strings);
                globus_free(node_info->info);
                node_info->info = NULL;
                node_info->info_needs_free = GLOBUS_FALSE;
            }   
            globus_l_gfs_remote_node_release(
                bounce_info->my_handle,
                node_info);   
        }

        globus_gridftp_server_operation_finished(
            bounce_info->op,
            finished_info.result,
            &finished_info);           

        globus_free(bounce_info);
    }
       
    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_ipc_transfer_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_finished_info_t *            reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_gfs_finished_info_t          finished_info;
    globus_gfs_operation_t              op;
    globus_bool_t                       finish = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_ipc_transfer_cb);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    bounce_info->nodes_pending--;
    if(reply->result != 0)
    {
        bounce_info->cached_result = reply->result;
    }
    
    /* wait for all the nodes to return, or if recving and we get an error
        before the first begin_cb we quit right now */    
    if((!bounce_info->nodes_pending && !bounce_info->nodes_requesting) || 
        (reply->result != GLOBUS_SUCCESS && bounce_info->recv_pending))
    {        
        memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
        finished_info.type = reply->type;
        finished_info.id = reply->id;
        finished_info.code = reply->code;
        finished_info.msg = reply->msg;
        finished_info.result = bounce_info->cached_result;
        finish = GLOBUS_TRUE;
        op = bounce_info->op;
        
        if(!bounce_info->events_enabled)
        {
            globus_list_t *             list;
            globus_l_gfs_remote_node_info_t * node_info;
            
            for(list = bounce_info->node_handle->node_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                node_info = (globus_l_gfs_remote_node_info_t *) 
                    globus_list_first(list);
                
                if(node_info->info && node_info->info_needs_free)
                {
                    globus_free(node_info->info);
                    node_info->info = NULL;
                    node_info->info_needs_free = GLOBUS_FALSE;
                }
            }
            if(bounce_info->eof_count != NULL)
            {
                globus_free(bounce_info->eof_count);
            }
            globus_free(bounce_info);
        }        
    }
    
    if(finish)
    {
        globus_gridftp_server_operation_finished(
            op,
            finished_info.result,
            &finished_info); 
    }

    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_ipc_event_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     ipc_result,
    globus_gfs_event_info_t *      reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_list_t *                     list;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_l_gfs_remote_node_info_t *   current_node = NULL;
    globus_l_gfs_remote_node_info_t *   master_node = NULL;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_gfs_transfer_info_t *        info;
    globus_gfs_event_info_t             event_info;
    globus_result_t                     result;
    int                                 ctr;
    GlobusGFSName(globus_l_gfs_ipc_event_cb);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;    
    
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            node_info = globus_l_gfs_remote_get_current_node(
                bounce_info->node_handle->node_list, ipc_handle);
            node_info->event_arg = reply->event_arg;
            node_info->event_mask = reply->event_mask;

            bounce_info->begin_event_pending--;
            if(!bounce_info->begin_event_pending)
            {
                if(bounce_info->recv_pending)
                {
                    globus_l_gfs_remote_recv_next(bounce_info);
                }
                else if(!bounce_info->nodes_requesting)
                {
                    bounce_info->events_enabled = GLOBUS_TRUE;
                    reply->event_arg = bounce_info;
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
            for(list = bounce_info->node_handle->node_list;
                !globus_list_empty(list);
                list = globus_list_rest(list))
            {
                node_info = (globus_l_gfs_remote_node_info_t *) 
                    globus_list_first(list);
                info = (globus_gfs_transfer_info_t *) node_info->info;
                
                if(node_info->ipc_handle == ipc_handle)
                {
                    globus_assert(
                        info->node_ndx != 0 && current_node == NULL);
                    current_node = node_info;
                }
                if(info->node_ndx == 0)
                {
                    globus_assert(master_node == NULL);
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
                event_info.event_arg = master_node->event_arg;
                event_info.eof_count = bounce_info->eof_count;
                event_info.node_count = bounce_info->partial_eof_counts + 1;
                result = globus_gfs_ipc_request_transfer_event(
                    master_node->ipc_handle,
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
        reply->event_arg = bounce_info;
        globus_gridftp_server_operation_event(
            bounce_info->op,
            GLOBUS_SUCCESS,
            reply);
    }
       
    GlobusGFSRemoteDebugExit();
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
    GlobusGFSRemoteDebugEnter();
    
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
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *) 
        globus_malloc(sizeof(globus_l_gfs_remote_node_handle_t));
    bounce_info->node_handle->node_list = NULL;
    *bounce = bounce_info;
    
    GlobusGFSRemoteDebugExit();
    return GLOBUS_SUCCESS;

error_alloc:
    GlobusGFSRemoteDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_remote_stat_kickout(
    globus_l_gfs_remote_node_info_t *   node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_stat_kickout);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
    globus_list_insert(&bounce_info->node_handle->node_list, node_info);

    result = globus_gfs_ipc_request_stat(
        node_info->ipc_handle,
        (globus_gfs_stat_info_t *) bounce_info->state,
        globus_l_gfs_ipc_finished_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    GlobusGFSRemoteDebugExit();
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
    GlobusGFSRemoteDebugEnter();
    
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

    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_remote_command_kickout(
    globus_l_gfs_remote_node_info_t *   node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_command_kickout);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;

    globus_list_insert(&bounce_info->node_handle->node_list, node_info);

    result = globus_gfs_ipc_request_command(
        node_info->ipc_handle,
        (globus_gfs_command_info_t *) bounce_info->state,
        globus_l_gfs_ipc_finished_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    GlobusGFSRemoteDebugExit();
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
    GlobusGFSRemoteDebugEnter();
    
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
    
    GlobusGFSRemoteDebugExit();
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
    globus_l_gfs_remote_node_info_t *   node_info;
    GlobusGFSName(globus_l_gfs_remote_list);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    globus_free(bounce_info->node_handle);   
         
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *) 
        transfer_info->data_arg;
                 
    node_info = (globus_l_gfs_remote_node_info_t *) 
        globus_list_first(bounce_info->node_handle->node_list);
        
    transfer_info->data_arg = node_info->data_arg;
    transfer_info->stripe_count = 1;
    transfer_info->node_ndx = 0;
    transfer_info->node_count = 1;
    bounce_info->event_pending = 1;
    bounce_info->begin_event_pending = 1;
    bounce_info->nodes_pending = 1;
    bounce_info->node_count = 1;
    node_info->info = NULL;
    node_info->info_needs_free = GLOBUS_FALSE;
    
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

    GlobusGFSRemoteDebugExit();
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
    globus_gfs_transfer_info_t *        transfer_info;
    int                                 ndx = 1;
    GlobusGFSName(globus_l_gfs_remote_recv_next);
    GlobusGFSRemoteDebugEnter();
               
    /* already sent recv to node 0, now send the rest */
    transfer_info = (globus_gfs_transfer_info_t *) bounce_info->state;
    
    node_count = globus_list_size(bounce_info->node_handle->node_list);
    
    for(list = globus_list_rest(bounce_info->node_handle->node_list);
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
        new_transfer_info->data_arg = node_info->data_arg;
        new_transfer_info->node_count = node_count;
        new_transfer_info->stripe_count = node_info->stripe_count;
        new_transfer_info->node_ndx = ndx++;
        node_info->info = new_transfer_info;
        node_info->info_needs_free = GLOBUS_TRUE;

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
    
    GlobusGFSRemoteDebugExit();
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
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    globus_free(bounce_info->node_handle);        
    
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *) 
        transfer_info->data_arg;

    /* only going to do the first recv request here, the others
       will be sent after this one responds with the begin event 
    
       we need to do this primarily to make sure the file is opened 
       in TRUNC mode only the first time */
       
    node_count = globus_list_size(bounce_info->node_handle->node_list);
    if(node_count > 1)
    {
        bounce_info->recv_pending = GLOBUS_TRUE;
    }
    bounce_info->nodes_requesting = node_count;
    bounce_info->node_count = node_count;

            
    node_info = (globus_l_gfs_remote_node_info_t *) 
        globus_list_first(bounce_info->node_handle->node_list);
    
    new_transfer_info = (globus_gfs_transfer_info_t *)
        globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
    memcpy(new_transfer_info, transfer_info, sizeof(globus_gfs_transfer_info_t));

    new_transfer_info->data_arg = node_info->data_arg;
    new_transfer_info->node_count = node_count;
    new_transfer_info->stripe_count = node_info->stripe_count;
    new_transfer_info->node_ndx = 0;
    node_info->info = new_transfer_info;
    node_info->info_needs_free = GLOBUS_TRUE;

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

    GlobusGFSRemoteDebugExit();
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
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_list_t *                     list;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 node_count;
    int                                 ndx = 0;
    GlobusGFSName(globus_l_gfs_remote_send);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    globus_free(bounce_info->node_handle);        
    
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *)
        transfer_info->data_arg;

    node_count = globus_list_size(bounce_info->node_handle->node_list);

    bounce_info->eof_count = (int *) 
        globus_calloc(1, node_count * sizeof(int) + 1);

    bounce_info->nodes_requesting = node_count;
    bounce_info->node_count = node_count;
    bounce_info->sending = GLOBUS_TRUE;
    for(list = bounce_info->node_handle->node_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
        
        new_transfer_info = (globus_gfs_transfer_info_t *)
            globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
        memcpy(new_transfer_info, transfer_info, sizeof(globus_gfs_transfer_info_t));
            
        new_transfer_info->data_arg = node_info->data_arg;
        new_transfer_info->node_count = node_count;
        new_transfer_info->stripe_count = node_info->stripe_count;
        new_transfer_info->node_ndx = ndx++;
        node_info->info = new_transfer_info;
        node_info->info_needs_free = GLOBUS_TRUE;
                                    
        bounce_info->nodes_pending++;
        bounce_info->event_pending++;
        bounce_info->begin_event_pending++;
        
        result = globus_gfs_ipc_request_send(
            node_info->ipc_handle,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            bounce_info); 

        bounce_info->nodes_requesting--;
    }
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_remote_active_kickout(
    globus_l_gfs_remote_node_info_t *   node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_gfs_data_info_t *            data_info;
    globus_gfs_data_info_t *            new_data_info;
    GlobusGFSName(globus_l_gfs_remote_active_kickout);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    data_info = (globus_gfs_data_info_t *) bounce_info->state;
    globus_list_insert(&bounce_info->node_handle->node_list, node_info);
    
    new_data_info = (globus_gfs_data_info_t *)
        globus_calloc(1, sizeof(globus_gfs_data_info_t));
    
    memcpy(
        new_data_info, bounce_info->state, sizeof(globus_gfs_data_info_t));

    if(bounce_info->my_handle->striped_mode == 
        GLOBUS_L_GFS_REMOTE_STRIPED_ONE_TO_ONE)
    {
        new_data_info->cs_count = 1;
        new_data_info->contact_strings = (const char **) malloc(sizeof(char *));
        new_data_info->contact_strings[0] = 
            globus_libc_strdup(
            data_info->contact_strings[bounce_info->node_ndx]);
    }

    bounce_info->node_ndx++;

    bounce_info->nodes_pending++;
    bounce_info->nodes_requesting--;
    
    node_info->info = new_data_info;
    node_info->info_needs_free = GLOBUS_TRUE;
    result = globus_gfs_ipc_request_active_data(
        node_info->ipc_handle,
        new_data_info,
        globus_l_gfs_ipc_active_cb,
        bounce_info); 

    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(bounce_info->op, result);
    }

    GlobusGFSRemoteDebugExit();
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
    GlobusGFSRemoteDebugEnter();
    
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
    
    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_remote_passive_kickout(
    globus_l_gfs_remote_node_info_t *   node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_passive_kickout);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    globus_list_insert(&bounce_info->node_handle->node_list, node_info);
    
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

    GlobusGFSRemoteDebugExit();
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
    GlobusGFSRemoteDebugEnter();
    
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
    
    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_remote_data_destroy(
    void *                              data_arg,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_list_t *                     list;
    globus_l_gfs_remote_node_handle_t * node_handle;
    GlobusGFSName(globus_l_gfs_remote_data_destroy);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    node_handle = (globus_l_gfs_remote_node_handle_t *) data_arg;
    list = node_handle->node_list;
    while(!globus_list_empty(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_remove(&list, list);
                
        result = globus_gfs_ipc_request_data_destroy(
            node_info->ipc_handle,
            node_info->data_arg); 
        if(result != GLOBUS_SUCCESS)
        {
            globus_gfs_log_result(
                GLOBUS_GFS_LOG_ERR, 
                "IPC ERROR: remote_data_destroy: ipc call", result);
        }
        if(node_info->cs != NULL)
        {
            globus_free(node_info->cs);
        }
        node_info->data_arg = NULL;
        node_info->stripe_count = 0;
    }
    node_handle->node_list = NULL;
    globus_free(node_handle);
                        
    GlobusGFSRemoteDebugExit();
}


static
void
globus_l_gfs_remote_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_list_t *                     list;
    globus_gfs_event_info_t             new_event_info;
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_trev);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *) event_info->event_arg;
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
        
    memset(&new_event_info, '\0', sizeof(globus_gfs_event_info_t));
    new_event_info.type = event_info->type;

    if(bounce_info->node_handle->node_list == NULL)
    {
        /* will have to do some ref counting on the node_handle if server-lib
        can't prevent this */
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, 
            "data_destroy before transfer_complete\n");
    }
    for(list = bounce_info->node_handle->node_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_list_first(list);
        
        new_event_info.event_arg = node_info->event_arg;
        result = globus_gfs_ipc_request_transfer_event(
            node_info->ipc_handle,
            &new_event_info);
    }
            
    if(event_info->type == GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
    {
        for(list = bounce_info->node_handle->node_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            node_info = (globus_l_gfs_remote_node_info_t *) 
                globus_list_first(list);
            
            if(node_info->info && node_info->info_needs_free)
            {
                globus_free(node_info->info);
                node_info->info = NULL;
                node_info->info_needs_free = GLOBUS_FALSE;
            }
            node_info->event_arg = NULL;
            node_info->event_mask = 0;
        }
        if(bounce_info->eof_count != NULL)
        {
            globus_free(bounce_info->eof_count);
        }
        globus_free(bounce_info);
    }

    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_remote_session_start_kickout(
    globus_l_gfs_remote_node_info_t *   node_info,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_gfs_finished_info_t          finished_info;                         
    GlobusGFSName(globus_l_gfs_remote_session_start_kickout);
    GlobusGFSRemoteDebugEnter();

    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
                                                                    
    bounce_info->nodes_requesting--;

    if(bounce_info->cached_error)
    {
        goto error;
    }
    if(result != GLOBUS_SUCCESS)
    {
        bounce_info->cached_error = globus_error_get(result);
        goto error;
    }
        
    if(bounce_info->nodes_requesting)
    {
        globus_l_gfs_remote_node_release(
            bounce_info->my_handle, node_info);
    }
    else
    {
        memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
        finished_info.type = GLOBUS_GFS_OP_SESSION_START;          
        finished_info.result = result;          
        finished_info.info.session.session_arg = bounce_info->my_handle;                          
        finished_info.info.session.username = node_info->username;                          
        finished_info.info.session.home_dir = node_info->home_dir;                          
                                                                      
        globus_l_gfs_remote_node_release(
            bounce_info->my_handle, node_info);
        
        globus_gridftp_server_operation_finished(                 
            bounce_info->op,                                                   
            result,                                               
            &finished_info);

        globus_free(bounce_info->node_handle);        
        globus_free(bounce_info);        
    }
    
    GlobusGFSRemoteDebugExit();
    return;
    
error:                                                              
    if(!bounce_info->nodes_requesting)
    {
        memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
        finished_info.type = GLOBUS_GFS_OP_SESSION_START;          
        finished_info.result = globus_error_put(bounce_info->cached_error);          
        globus_gridftp_server_operation_finished(                 
            bounce_info->op,                                                   
            finished_info.result,                                               
            &finished_info);
    
        globus_free(bounce_info->node_handle);        
        globus_free(bounce_info);  
    }
    
    GlobusGFSRemoteDebugExitWithError();
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
    GlobusGFSName(globus_l_gfs_remote_session_start);
    GlobusGFSRemoteDebugEnter();
    
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
    my_handle->session_info.map_user = session_info->map_user;
    my_handle->session_info.del_cred = session_info->del_cred;
    my_handle->striped_mode = 1;
    
    globus_priority_q_init(
        &my_handle->cached_node_q, globus_l_gfs_remote_node_queue_compare);

    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, &my_handle->session_info, my_handle);
                
    bounce_info->nodes_requesting = 0;
    
    globus_gfs_ipc_handle_get_max_available_count(
        NULL, NULL, &my_handle->max_nodes);
    
    my_handle->nodes_connected = 
        (int *) globus_calloc(1, my_handle->max_nodes * sizeof(int));

    result = globus_l_gfs_remote_node_request(
        my_handle,
        &bounce_info->nodes_requesting,
        NULL,
        globus_l_gfs_remote_session_start_kickout,
        bounce_info);                       
    if(result != GLOBUS_SUCCESS)
    {
        GlobusGFSErrorOpFinished(op, result);
    }
    
    GlobusGFSRemoteDebugExit();
}

static
void
globus_l_gfs_remote_session_end(
    void *                              user_arg)
{
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_result_t                     result;
    globus_l_gfs_remote_node_info_t *   node_info;
    GlobusGFSName(globus_l_gfs_remote_session_end);
    GlobusGFSRemoteDebugEnter();

    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    if(my_handle == NULL)
    {
        goto error;
    }
    while(!globus_priority_q_empty(&my_handle->cached_node_q))
    {
        node_info = (globus_l_gfs_remote_node_info_t *) 
            globus_priority_q_dequeue(&my_handle->cached_node_q);

        result = globus_gfs_ipc_handle_release(node_info->ipc_handle);
        if(result != GLOBUS_SUCCESS)
        {
            globus_gfs_log_result(
                GLOBUS_GFS_LOG_ERR, 
                "ERROR: remote_data_destroy: handle_release", result);
        }
        if(node_info->info && node_info->info_needs_free)
        {
            globus_free(node_info->info);
        }
        if(node_info->username)
        {
            globus_free(node_info->username);
        }
        if(node_info->home_dir)
        {
            globus_free(node_info->home_dir);
        }
        globus_free(node_info);
    } 
    globus_priority_q_destroy(&my_handle->cached_node_q);
    
    if(my_handle->session_info.username != NULL)
    {
        globus_free(my_handle->session_info.username);
    }
    if( my_handle->session_info.password != NULL)
    {
        globus_free(my_handle->session_info.password);
    }
    if(my_handle->session_info.subject != NULL)
    {
        globus_free(my_handle->session_info.subject);
    }
    if(my_handle->nodes_connected != NULL)
    {
        globus_free(my_handle->nodes_connected);
    }
    globus_free(my_handle);
    
    GlobusGFSRemoteDebugExit();
    return;
    
error:
    GlobusGFSRemoteDebugExitWithError();
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
        goto error;
    }
    
    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "remote",
        GlobusExtensionMyModule(globus_gridftp_server_remote),
        &globus_l_gfs_remote_dsi_iface);

    GlobusDebugInit(GLOBUS_GRIDFTP_SERVER_REMOTE,
        ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);
    
    return GLOBUS_SUCCESS;

error:
    return rc;
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
