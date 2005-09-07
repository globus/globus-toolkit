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

struct globus_l_gfs_remote_node_info_s;

typedef struct globus_l_gfs_remote_handle_s
{
    globus_mutex_t                      mutex;
    globus_gfs_operation_t              op;
    struct globus_l_gfs_remote_node_info_s *   control_node;
    void *                              state;
    globus_gfs_session_info_t           session_info;
    int                                 max_nodes;
    int                                 striped_mode;
} globus_l_gfs_remote_handle_t;

typedef struct globus_l_gfs_remote_node_handle_s
{
    struct globus_l_gfs_remote_node_info_s ** nodes;
    int                                 count;
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
} globus_l_gfs_remote_ipc_bounce_t;

typedef void
(*globus_l_gfs_remote_node_cb)(
    struct globus_l_gfs_remote_node_info_s *   node_info,
    globus_result_t                     result,
    void *                              user_arg);

typedef struct globus_l_gfs_remote_node_info_s
{
    globus_gfs_ipc_handle_t             ipc_handle;
    globus_l_gfs_remote_node_handle_t * node_handle;  
    struct globus_l_gfs_remote_ipc_bounce_s * bounce;
    char *                              host_cs;
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
    globus_l_gfs_remote_node_cb         callback;
    void *                              user_arg;
} globus_l_gfs_remote_node_info_t;

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

static
globus_result_t
globus_l_gfs_remote_node_release(
    globus_l_gfs_remote_node_info_t *   node_info)
{
    GlobusGFSName(globus_l_gfs_remote_node_release);
    GlobusGFSRemoteDebugEnter();

    globus_gfs_ipc_handle_release(node_info->ipc_handle);
    globus_free(node_info);

    GlobusGFSRemoteDebugExit();
    return GLOBUS_SUCCESS;
}  

static
void
globus_l_gfs_remote_node_request_kickout(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_finished_info_t *        reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_node_info_t *   node_info;
    GlobusGFSName(globus_l_gfs_remote_node_request_kickout);
    GlobusGFSRemoteDebugEnter();
    
    node_info = (globus_l_gfs_remote_node_info_t *) user_arg;

    if(result == GLOBUS_SUCCESS)
    {
        node_info->ipc_handle = ipc_handle;
        if(reply->info.session.username)
        {
            node_info->username = strdup(reply->info.session.username);
        }
        if(reply->info.session.home_dir)
        {
            node_info->home_dir = strdup(reply->info.session.home_dir);
        }
    }
    
    node_info->callback(
        node_info,
        result,
        node_info->user_arg);

    GlobusGFSRemoteDebugExit();
}

static
globus_result_t                    
globus_l_gfs_remote_node_request(
    globus_l_gfs_remote_handle_t *      my_handle,
    int *                               num_nodes,
    char *                              repo_name,
    globus_l_gfs_remote_node_cb         callback,
    void *                              user_arg)
{
    int                                 i;
    char **                             cs;
    int                                 cs_len;
    int                                 nodes_created;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_result_t                     tmp_res;
    globus_l_gfs_remote_node_info_t *   node_info;
    int                                 nodes_requested;
    char **                             new_node_array;
    GlobusGFSName(globus_l_gfs_remote_node_request);
    GlobusGFSRemoteDebugEnter();

    nodes_requested = *num_nodes;
    if(nodes_requested == 0)
    {
        nodes_requested = my_handle->max_nodes;
    }

    /* select a new set of nodes */
    result = globus_gfs_brain_select_nodes(
        &cs,
        &cs_len,
        repo_name,
        -1,
        1,
        nodes_requested);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    nodes_created = 0;
    result = GLOBUS_SUCCESS;
    for(i = 0; i < cs_len; i++)
    {
        node_info = (globus_l_gfs_remote_node_info_t *)
            globus_calloc(1, sizeof(globus_l_gfs_remote_node_info_t));
        node_info->host_cs = globus_libc_strdup(cs[i]);
        node_info->node_ndx = i;
        node_info->callback = callback;
        node_info->user_arg = user_arg;

        my_handle->session_info.host_id = node_info->host_cs;
        tmp_res = globus_gfs_ipc_handle_obtain(
            &my_handle->session_info,
            repo_name,
            &globus_gfs_ipc_default_iface,
            globus_l_gfs_remote_node_request_kickout,
            node_info,
            globus_l_gfs_remote_ipc_error_cb,
            my_handle);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            result = tmp_res;
            /* TODO: log a warning that on eof the guys didn't work,
                and tell the brain about it */
            globus_gfs_brain_release_node(
                node_info->host_cs,
                repo_name,
                GLOBUS_GFS_BRAIN_REASON_ERROR);
        }
        else
        {
            nodes_created++;
        }
    }
    /* if any succeed use them */
    if(result != GLOBUS_SUCCESS && nodes_created == 0)
    {
        goto error_connect;
    }
    *num_nodes = nodes_created;

    GlobusGFSRemoteDebugExit();
    return GLOBUS_SUCCESS;

error_connect:
    globus_free(new_node_array);
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
    GlobusGFSName(globus_l_gfs_ipc_finished_cb);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *)  user_arg;
    
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
    int                                 i;
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_node_info_t *   node_info;
    GlobusGFSName(globus_l_gfs_ipc_passive_cb);
    GlobusGFSRemoteDebugEnter();

    node_info = (globus_l_gfs_remote_node_info_t *) user_arg;    
    bounce_info = node_info->bounce;

    /* XXX this is suspect if we chain DSIs another step */
    node_info->cs = globus_libc_strdup(reply->info.data.contact_strings[0]);
    node_info->data_arg = reply->info.data.data_arg;

    /* XXX need to lock this */ 
    bounce_info->nodes_pending--;

    /* if we got 'em all */ 
    if(!bounce_info->nodes_pending && !bounce_info->nodes_requesting)
    {
        globus_gfs_finished_info_t      finished_info;
                
        memcpy(&finished_info, reply, sizeof(globus_gfs_finished_info_t));

        finished_info.info.data.data_arg = bounce_info->node_handle;        
        finished_info.info.data.cs_count = bounce_info->node_handle->count;

        finished_info.info.data.contact_strings = (const char **)
            globus_malloc(sizeof(char *) * finished_info.info.data.cs_count);
        for(i = 0; i < bounce_info->node_handle->count; i++)
        {
            node_info = (globus_l_gfs_remote_node_info_t *) 
                bounce_info->node_handle->nodes[i];
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
            finished_info.info.data.contact_strings[i] = node_info->cs;
            node_info->cs = NULL;
        
            if(node_info->info && node_info->info_needs_free)
            {
                globus_free(node_info->info);
                node_info->info = NULL;
                node_info->info_needs_free = GLOBUS_FALSE;
            }
        }        
        globus_gridftp_server_operation_finished(
            bounce_info->op,
            finished_info.result,
            &finished_info);
        
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
    globus_gfs_finished_info_t *        reply,
    void *                              user_arg)
{
    int                                 i;
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_l_gfs_remote_node_info_t *   node_info;
    GlobusGFSName(globus_l_gfs_ipc_active_cb);
    GlobusGFSRemoteDebugEnter();
    
    node_info = (globus_l_gfs_remote_node_info_t *) user_arg;    
    bounce_info = node_info->bounce;
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
                
        memcpy(&finished_info, reply, sizeof(globus_gfs_finished_info_t));

        finished_info.info.data.data_arg = bounce_info->node_handle;        
 
        for(i = 0; i < bounce_info->node_handle->count; i++)
        {
            globus_gfs_data_info_t *    info;
            node_info = bounce_info->node_handle->nodes[i];

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
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t *   node_info;
    int                                 i;
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_gfs_finished_info_t          finished_info;
    globus_gfs_operation_t              op;
    globus_bool_t                       finish = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_ipc_transfer_cb);
    GlobusGFSRemoteDebugEnter();

    node_info = (globus_l_gfs_remote_node_info_t *) user_arg;
    bounce_info = node_info->bounce;
    my_handle = bounce_info->my_handle;
    
    globus_mutex_lock(&my_handle->mutex);
    {
        bounce_info->nodes_pending--;
        if(reply->result != 0)
        {
            bounce_info->cached_result = reply->result;
        }
    
        /* wait for all the nodes to return, or if recving and we get an error
            before the first begin_cb we quit right now */    
        if((!bounce_info->nodes_pending && !bounce_info->nodes_requesting) || 
            (bounce_info->cached_result != GLOBUS_SUCCESS &&
                bounce_info->recv_pending))
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
                globus_l_gfs_remote_node_info_t * node_info;
            
                for(i = 0; i < bounce_info->node_handle->count; i++)
                {
                    node_info = bounce_info->node_handle->nodes[i];
 
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
    }
    globus_mutex_unlock(&my_handle->mutex);
    
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
    globus_gfs_event_info_t *           reply,
    void *                              user_arg)
{
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 i;
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
    
    node_info = (globus_l_gfs_remote_node_info_t *) user_arg;    
    bounce_info = node_info->bounce;
    my_handle = bounce_info->my_handle;

    globus_mutex_lock(&my_handle->mutex);
    {
        switch(reply->type)
        {
            case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
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

                for(i = 0; i < bounce_info->node_handle->count; i++)
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
    }
    globus_mutex_unlock(&my_handle->mutex);

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
    *bounce = bounce_info;
    
    GlobusGFSRemoteDebugExit();
    return GLOBUS_SUCCESS;

error_alloc:
    GlobusGFSRemoteDebugExitWithError();
    return result;
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
    GlobusGFSName(globus_l_gfs_remote_stat);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, stat_info, my_handle);

    result = globus_gfs_ipc_request_stat(
        my_handle->control_node->ipc_handle,
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
globus_l_gfs_remote_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         command_info,
    void *                              user_arg)
{
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    GlobusGFSName(globus_l_gfs_remote_command);
    GlobusGFSRemoteDebugEnter();

    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, command_info, my_handle);

    result = globus_gfs_ipc_request_command(
        my_handle->control_node->ipc_handle,
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

    /* XXX it appears no lock is needed here */ 
    result = globus_l_gfs_remote_init_bounce_info(
        &bounce_info, op, transfer_info, my_handle);
    globus_free(bounce_info->node_handle);   
         
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *) 
        transfer_info->data_arg;
                 
    node_info = bounce_info->node_handle->nodes[0];
        
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
    node_info->bounce = bounce_info;
    
    result = globus_gfs_ipc_request_list(
        node_info->ipc_handle,
        transfer_info,
        globus_l_gfs_ipc_transfer_cb,
        globus_l_gfs_ipc_event_cb,
        node_info); 
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
    int                                 i;
    globus_result_t                     result;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 node_count;
    globus_gfs_transfer_info_t *        transfer_info;
    int                                 ndx = 1;
    GlobusGFSName(globus_l_gfs_remote_recv_next);
    GlobusGFSRemoteDebugEnter();
               
    /* already sent recv to node 0, now send the rest */
    transfer_info = (globus_gfs_transfer_info_t *) bounce_info->state;
    
    node_count = bounce_info->node_handle->count;
    
    for(i = 1; i < bounce_info->node_handle->count; i++)
    {
        node_info = bounce_info->node_handle->nodes[i];
        
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
        node_info->bounce = bounce_info;

        bounce_info->nodes_requesting--;

        result = globus_gfs_ipc_request_recv(
            node_info->ipc_handle,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            node_info); 
        if(result != GLOBUS_SUCCESS)
        {
            if(bounce_info->nodes_pending > 0)
            {
                bounce_info->cached_result = result;
            }
            else
            {
                GlobusGFSErrorOpFinished(bounce_info->op, result);
            }
            goto error;
        }
        bounce_info->nodes_pending++;
        bounce_info->event_pending++;
        bounce_info->begin_event_pending++;
    }
    
    bounce_info->recv_pending = GLOBUS_FALSE;

    GlobusGFSRemoteDebugExit();
    return;
error:
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
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    globus_mutex_lock(&my_handle->mutex);
    {
        result = globus_l_gfs_remote_init_bounce_info(
            &bounce_info, op, transfer_info, my_handle);
    
        bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *) 
            transfer_info->data_arg;

        /* only going to do the first recv request here, the others
           will be sent after this one responds with the begin event 
    
           we need to do this primarily to make sure the file is opened 
           in TRUNC mode only the first time */
       
        node_count = bounce_info->node_handle->count;
        if(node_count > 1)
        {
            bounce_info->recv_pending = GLOBUS_TRUE;
        }
        bounce_info->nodes_requesting = node_count;
        bounce_info->node_count = node_count;
            
        node_info = bounce_info->node_handle->nodes[0];
    
        new_transfer_info = (globus_gfs_transfer_info_t *)
            globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
        memcpy(new_transfer_info,transfer_info,
            sizeof(globus_gfs_transfer_info_t));

        new_transfer_info->data_arg = node_info->data_arg;
        new_transfer_info->node_count = node_count;
        new_transfer_info->stripe_count = node_info->stripe_count;
        new_transfer_info->node_ndx = 0;
        node_info->info = new_transfer_info;
        node_info->info_needs_free = GLOBUS_TRUE;
        node_info->bounce = bounce_info;

        result = globus_gfs_ipc_request_recv(
            node_info->ipc_handle,
            new_transfer_info,
            globus_l_gfs_ipc_transfer_cb,
            globus_l_gfs_ipc_event_cb,
            node_info); 
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        /* could maybe get away with no lock if we moved the next few lines
            above the request.  we would have to then assume that the 
            values were meaningless under error.  This way is more 
            consistant and the lock is not very costly */
        bounce_info->nodes_pending++;
        bounce_info->event_pending++;
        bounce_info->begin_event_pending++;
        bounce_info->nodes_requesting--;
    }
    globus_mutex_unlock(&my_handle->mutex);

    GlobusGFSRemoteDebugExit();
    return;
error:
    globus_mutex_unlock(&my_handle->mutex);
    GlobusGFSErrorOpFinished(bounce_info->op, result);
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
    globus_gfs_transfer_info_t *        new_transfer_info;
    int                                 node_count;
    int                                 ndx = 0;
    int                                 i;
    GlobusGFSName(globus_l_gfs_remote_send);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;

    globus_mutex_lock(&my_handle->mutex);
    {
        result = globus_l_gfs_remote_init_bounce_info(
            &bounce_info, op, transfer_info, my_handle);
    
        bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *)
            transfer_info->data_arg;

        node_count = bounce_info->node_handle->count;

        bounce_info->eof_count = (int *) 
            globus_calloc(1, node_count * sizeof(int) + 1);

        bounce_info->nodes_requesting = node_count;
        bounce_info->node_count = node_count;
        bounce_info->sending = GLOBUS_TRUE;
        for(i = 0; i < bounce_info->node_handle->count; i++)
        {
            node_info = bounce_info->node_handle->nodes[i];
        
            new_transfer_info = (globus_gfs_transfer_info_t *)
                globus_calloc(1, sizeof(globus_gfs_transfer_info_t));
            memcpy(new_transfer_info,
                transfer_info, sizeof(globus_gfs_transfer_info_t));
            
            new_transfer_info->data_arg = node_info->data_arg;
            new_transfer_info->node_count = node_count;
            new_transfer_info->stripe_count = node_info->stripe_count;
            new_transfer_info->node_ndx = ndx++;
            node_info->info = new_transfer_info;
            node_info->info_needs_free = GLOBUS_TRUE;
            node_info->bounce = bounce_info;
                                    
            bounce_info->nodes_pending++;
            bounce_info->event_pending++;
            bounce_info->begin_event_pending++;
        
            result = globus_gfs_ipc_request_send(
                node_info->ipc_handle,
                new_transfer_info,
                globus_l_gfs_ipc_transfer_cb,
                globus_l_gfs_ipc_event_cb,
                node_info); 
            if(result != GLOBUS_SUCCESS)
            {
                /* if some callbacks are pending we need to wait for the
                    callbacks */
                if(i > 0)
                {
                    bounce_info->cached_result = result;
                }
                else
                {
                    GlobusGFSErrorOpFinished(bounce_info->op, result);
                }
                goto error;
            }

            bounce_info->nodes_requesting--;
        }
    }
    globus_mutex_unlock(&my_handle->mutex);

    GlobusGFSRemoteDebugExit();
    return;
error:
    globus_mutex_unlock(&my_handle->mutex);
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

    node_info->bounce = bounce_info;
    bounce_info->node_handle->nodes[node_info->node_ndx] = node_info;

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

    /* XXX gotta protect this stuff with a mutex */
    bounce_info->node_ndx++;

    bounce_info->nodes_pending++;
    bounce_info->nodes_requesting--;
    
    node_info->info = new_data_info;
    node_info->info_needs_free = GLOBUS_TRUE;
    result = globus_gfs_ipc_request_active_data(
        node_info->ipc_handle,
        new_data_info,
        globus_l_gfs_ipc_active_cb,
        node_info); 

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
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_node_handle_t));
    bounce_info->node_handle->nodes = (globus_l_gfs_remote_node_info_t **)
        globus_calloc(bounce_info->nodes_requesting,
            sizeof(globus_l_gfs_remote_node_info_t *));
    bounce_info->node_handle->count = bounce_info->nodes_requesting;

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

    /* XXX these need to be mutex protected */    
    bounce_info->nodes_pending++;
    bounce_info->nodes_requesting--;
    node_info->bounce = bounce_info;
    bounce_info->node_handle->nodes[node_info->node_ndx] = node_info;

    result = globus_gfs_ipc_request_passive_data(
        node_info->ipc_handle,
        (globus_gfs_data_info_t *) bounce_info->state,
        globus_l_gfs_ipc_passive_cb,
        node_info);

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
        goto error;
    }
    /* XXX need a lock for this */
    bounce_info->node_handle = (globus_l_gfs_remote_node_handle_t *)
        globus_calloc(1, sizeof(globus_l_gfs_remote_node_handle_t));
    bounce_info->node_handle->nodes = (globus_l_gfs_remote_node_info_t **)
        globus_calloc(bounce_info->nodes_requesting,
            sizeof(globus_l_gfs_remote_node_info_t));
    bounce_info->node_handle->count = bounce_info->nodes_requesting;

    GlobusGFSRemoteDebugExit();
    return;
error:
    GlobusGFSErrorOpFinished(op, result);
}

static
void
globus_l_gfs_remote_data_destroy(
    void *                              data_arg,
    void *                              user_arg)
{
    int                                 i;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_l_gfs_remote_node_handle_t * node_handle;
    GlobusGFSName(globus_l_gfs_remote_data_destroy);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    node_handle = (globus_l_gfs_remote_node_handle_t *) data_arg;

    for(i = 0; i < node_handle->count; i++)
    {
        node_info = (globus_l_gfs_remote_node_info_t *) node_handle->nodes[i];
  
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
        result = globus_l_gfs_remote_node_release(node_info);
        if(result != GLOBUS_SUCCESS)
        {
            globus_gfs_log_result(
                GLOBUS_GFS_LOG_ERR,
                "ERROR: remote_data_destroy: handle_release", result);
        }
    }
    globus_free(node_handle->nodes);
    globus_free(node_handle);
                        
    GlobusGFSRemoteDebugExit();
}


static
void
globus_l_gfs_remote_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg)
{
    int                                 i;
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_l_gfs_remote_node_info_t *   node_info;
    globus_gfs_event_info_t             new_event_info;
    globus_l_gfs_remote_ipc_bounce_t *  bounce_info;
    GlobusGFSName(globus_l_gfs_remote_trev);
    GlobusGFSRemoteDebugEnter();
    
    bounce_info = (globus_l_gfs_remote_ipc_bounce_t *) event_info->event_arg;
    
    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
        
    memset(&new_event_info, '\0', sizeof(globus_gfs_event_info_t));
    new_event_info.type = event_info->type;

    for(i = 0; i < bounce_info->node_handle->count; i++)
    {
        node_info = bounce_info->node_handle->nodes[i];

        new_event_info.event_arg = node_info->event_arg;
        result = globus_gfs_ipc_request_transfer_event(
            node_info->ipc_handle,
            &new_event_info);
    }
            
    if(event_info->type == GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
    {
        for(i = 0; i < bounce_info->node_handle->count; i++)
        {
            node_info = bounce_info->node_handle->nodes[i];

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
    globus_l_gfs_remote_handle_t *      my_handle;
    globus_gfs_finished_info_t          finished_info;                         
    GlobusGFSName(globus_l_gfs_remote_session_start_kickout);
    GlobusGFSRemoteDebugEnter();

    /* no locking needed here since no other callbacks can occur
        with this handle until we signal it has started */

    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
                                                                    
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;          
    finished_info.result = result;          
    finished_info.info.session.session_arg = my_handle;
    finished_info.info.session.username = node_info->username;                          
    finished_info.info.session.home_dir = node_info->home_dir;                          
    my_handle->control_node = node_info;

    globus_gridftp_server_operation_finished(                 
        my_handle->op,                                                   
        result,                                               
        &finished_info);

    GlobusGFSRemoteDebugExit();
    return;
    
error:                                                              
    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = result;

    globus_gridftp_server_operation_finished(                 
        my_handle->op,                                                   
        finished_info.result,                                               
        &finished_info);
    
    GlobusGFSRemoteDebugExitWithError();
}   

static
void
globus_l_gfs_remote_session_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    globus_result_t                     result;
    globus_l_gfs_remote_handle_t *      my_handle;
    int                                 nodes_requesting = 1;
    GlobusGFSName(globus_l_gfs_remote_session_start);
    GlobusGFSRemoteDebugEnter();
    
    my_handle = (globus_l_gfs_remote_handle_t *) 
        globus_calloc(1, sizeof(globus_l_gfs_remote_handle_t));
    globus_mutex_init(&my_handle->mutex, NULL);

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
    my_handle->op = op;

    globus_gfs_ipc_handle_get_max_available_count(
        NULL, NULL, &my_handle->max_nodes);
    
    result = globus_l_gfs_remote_node_request(
        my_handle,
        &nodes_requesting,
        NULL,
        globus_l_gfs_remote_session_start_kickout,
        my_handle);
    if(result != GLOBUS_SUCCESS || nodes_requesting != 1)
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
    GlobusGFSName(globus_l_gfs_remote_session_end);
    GlobusGFSRemoteDebugEnter();

    my_handle = (globus_l_gfs_remote_handle_t *) user_arg;
    
    if(my_handle == NULL)
    {
        goto error;
    }

    if(my_handle->control_node->username)
    {
        globus_free(my_handle->control_node->username);
    }
    if(my_handle->control_node->home_dir)
    {
        globus_free(my_handle->control_node->home_dir);
    }
    result = globus_l_gfs_remote_node_release(
        my_handle->control_node);
    if(result != GLOBUS_SUCCESS)
    {
        globus_gfs_log_result(
            GLOBUS_GFS_LOG_ERR, 
            "ERROR: remote_data_destroy: handle_release", result);
    }
    
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
    globus_mutex_destroy(&my_handle->mutex);
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
