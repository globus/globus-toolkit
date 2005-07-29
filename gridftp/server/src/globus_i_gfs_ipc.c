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

/*
 *  connector will send a 'connection info'.  Tihs includes username 
 *  (of the remote process, this may be meaningless), grid dn (this 
 *  should mean more) host_id, and contach_string.
 *
 *  subject dn
 *     -- the DN of the running process on the other end of 
 *        the connection.  If this is NULL and username is NULL
 *        it means that this can be set with a set_session_info 
 *        command.
 *
 *  username
 *    -- This is only meaning full if subject is NULL.  If so, and user 
 *        name is NULL it means that the remote process has not yet
 *        been set.  It it is not NULL then it represents the username
 *        of the remotely running process.  This really only helps if the
 *        forntend and backend have the same users.
 *
 *  cookie
 *    -- if this is not NULL it is the only value that is hashed upon.
 *       The point of this is to allow a backend to be started up with
 *       some UUID, then for a client to connect and provide that UUID
 *       allowing the 2 to be matched.
 *
 *  host_id
 *    -- a string representing the host.  This will need to be the same as
 *       the url used to conect to this host.
 *
 *  community
 *    -- the string that represents the community they are a part of
 *
 *  If the connector is a backend process:
 *    All setuid() type things are done before the connection.  If
 *    a password file is being used the process will need to read it and
 *    store the hash for later authentication.
 *
 *  If the connector is a frontend process
 *    The information is sent to the backend.  The backend reads the
 *    password file and stores the hash.  It then sets the uid.
 *
 *  Once an ipc connection is esstablished it can be used.  A user calls
 *  handle_obtain() and that sends a session_start message across the wire.
 *  The session start has a new delegated credential (if there is one) the
 *  and the password if there is one.  Subject/user do not need to be sent
 *  since they do not change in the lifetime of the connection.  The
 *  backend will respond to the message with success or failure.  In either
 *  case the conection will remain open.  At anytime either side can close 
 *  the connection.
 */
#include "globus_i_gridftp_server.h"

static const char * globus_l_gfs_local_version = "IPC Version 0.1";

/* single mutex, assuming low contention, only used for handle tables,
   not ipc communication */
static globus_mutex_t                   globus_l_ipc_mutex;
static globus_hashtable_t               globus_l_ipc_handle_table;
static globus_hashtable_t               globus_l_ipc_request_table;
static globus_i_gfs_community_t *       globus_l_gfs_ipc_community_default;
static globus_list_t *                  globus_l_gfs_ipc_community_list = NULL;
static globus_xio_stack_t               globus_l_gfs_ipc_xio_stack;

typedef enum globus_l_gfs_ipc_state_s
{
    GLOBUS_GFS_IPC_STATE_SERVER_OPENING = 1,
    GLOBUS_GFS_IPC_STATE_CLIENT_OPENING,
    GLOBUS_GFS_IPC_STATE_OPEN,
    GLOBUS_GFS_IPC_STATE_IN_CB,
    GLOBUS_GFS_IPC_STATE_IN_USE,
    GLOBUS_GFS_IPC_STATE_GETTING,
    GLOBUS_GFS_IPC_STATE_STOPPING,
    GLOBUS_GFS_IPC_STATE_ERROR,
    GLOBUS_GFS_IPC_STATE_CLOSING,
    GLOBUS_GFS_IPC_STATE_CLOSED
} globus_l_gfs_ipc_state_t;

static globus_xio_driver_t              globus_l_gfs_tcp_driver = GLOBUS_NULL;
static globus_xio_driver_t              globus_l_gfs_queue_driver = GLOBUS_NULL;
static globus_xio_driver_t              globus_l_gfs_gsi_driver = GLOBUS_NULL;
static globus_xio_server_t              globus_l_gfs_ipc_server_handle;
static globus_bool_t                    globus_l_gfs_ipc_requester;
static globus_list_t *                  globus_l_ipc_handle_list = NULL;

/*
 *  header:
 *  type:    single charater representing type of message
 *  id:      4 bytes of message id
 *  size:    remaining size of message
 */
#define GFS_IPC_HEADER_SIZE         (sizeof(uint32_t)*2 + 1)
#define GFS_IPC_HEADER_SIZE_OFFSET  (sizeof(uint32_t)*1 + 1)
#define GFS_IPC_DEFAULT_BUFFER_SIZE 8 * 1024
#define GFS_IPC_VERSION             '\1'

globus_gfs_ipc_iface_t  globus_gfs_ipc_default_iface = 
{
    globus_i_gfs_data_session_start,
    globus_i_gfs_data_session_stop,
    globus_i_gfs_data_request_recv,
    globus_i_gfs_data_request_send,
    globus_i_gfs_data_request_command,
    globus_i_gfs_data_request_active,
    globus_i_gfs_data_request_passive,
    globus_i_gfs_data_request_handle_destroy,
    globus_i_gfs_data_request_stat,
    globus_i_gfs_data_request_list,
    globus_i_gfs_data_request_transfer_event,
    globus_i_gfs_data_request_set_cred,
    globus_i_gfs_data_request_buffer_send
};

/* callback and id relation */
typedef struct globus_gfs_ipc_request_s
{
    globus_gfs_ipc_handle_t             ipc;
    globus_gfs_operation_type_t       type;
    int                                 id;
    globus_gfs_ipc_callback_t           cb;
    globus_gfs_ipc_open_callback_t      open_cb;
    globus_gfs_ipc_event_callback_t     event_cb;
    void *                              user_arg;
    globus_gfs_finished_info_t *            reply;
    globus_gfs_event_info_t *      event_reply;
    void *                              info_struct;
} globus_gfs_ipc_request_t;

typedef struct globus_l_gfs_ipc_connection_s
{
    char *                              version;
    char *                              community;
    char *                              cookie;
    char *                              username;
    char *                              subject;
    char *                              host_id;
    globus_bool_t                       map_user;
    int                                 community_ndx;
} globus_l_gfs_ipc_connection_t;

typedef struct globus_i_gfs_ipc_handle_s
{
    uid_t                               uid;
    const char *                        contact_string;
    globus_xio_handle_t                 xio_handle;
    globus_bool_t                       local;

    globus_bool_t                       requester;
    globus_gfs_session_info_t *         session_info;
    globus_handle_table_t               call_table;
    globus_hashtable_t                  reply_table;
    globus_gfs_ipc_iface_t *            iface;

    globus_mutex_t                      mutex;
    globus_l_gfs_ipc_state_t            state;

    globus_gfs_ipc_open_callback_t      open_cb;
    globus_gfs_ipc_close_callback_t     close_cb;
    void *                              user_arg;
    globus_result_t                     cached_res;
    globus_gfs_ipc_error_callback_t     error_cb;
    globus_gfs_ipc_error_callback_t     reply_error_cb;
    void *                              error_arg;
                                                                                
    globus_size_t                       buffer_size;

    char *                              hash_str;
    char *                              user_id;

    globus_l_gfs_ipc_connection_t       connection_info;
    globus_byte_t                       byte;
} globus_i_gfs_ipc_handle_t;

static
void
globus_l_gfs_ipc_stop_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
globus_l_gfs_ipc_read_new_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
globus_l_gfs_ipc_reply_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
globus_l_gfs_ipc_request_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static void
globus_l_gfs_ipc_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
globus_i_gfs_community_t *
globus_l_gfs_ipc_find_community(
    const char *                        path);

static
void
globus_l_gfs_ipc_send_start_session(
    globus_i_gfs_ipc_handle_t *         ipc);

static
void
globus_l_gfs_session_info_free(
    globus_gfs_session_info_t *         session_info);

static
void
globus_l_gfs_ipc_error_close(
    globus_i_gfs_ipc_handle_t *         ipc);
/***************************************************************************
 *  connection bootstrap
 *  --------------------
 **************************************************************************/
static
int
globus_l_gfs_ipc_hashtable_session_hash(
    void *                              voidp,
    int                                 limit)
{
    int                                 rc;
    char *                              tmp_str;
    char *                              hash_str;
    globus_l_gfs_ipc_connection_t *     s;
    GlobusGFSName(globus_l_gfs_ipc_hashtable_session_hash);

    s = (globus_l_gfs_ipc_connection_t *) voidp;

    if(s->cookie != NULL)
    {
        return globus_hashtable_string_hash(s->cookie, limit);
    }
    hash_str = strdup("");
    if(s->username)
    {
        tmp_str = globus_common_create_string("%s::", s->username);
        globus_free(hash_str);
        hash_str = tmp_str;
    }
    if(s->subject)
    {
        tmp_str = globus_common_create_string("%s%s@", hash_str, s->subject);
        globus_free(hash_str);
        hash_str = tmp_str;
    }
    globus_assert(s->host_id);
    globus_assert(s->community);
    tmp_str = globus_common_create_string(
        "%s%s%s##", hash_str, s->host_id, s->community);
    globus_free(hash_str);
    hash_str = tmp_str;

    rc = globus_hashtable_string_hash(hash_str, limit);
    globus_free(hash_str);

    return rc;
}

static
int
globus_l_gfs_ipc_hashtable_session_keyeq(
    void *                              voidp1,
    void *                              voidp2)
{
    globus_l_gfs_ipc_connection_t *     s1;
    globus_l_gfs_ipc_connection_t *     s2;
    GlobusGFSName(globus_l_gfs_ipc_hashtable_session_keyeq);

    s1 = (globus_l_gfs_ipc_connection_t *) voidp1;
    s2 = (globus_l_gfs_ipc_connection_t *) voidp2;

    /* if the cookies are the same we are equal */
    if(s1->cookie != NULL && s2->cookie != NULL &&
        strcmp(s1->cookie, s2->cookie) == 0)
    {
        return GLOBUS_TRUE;
    }

    globus_assert(s1->community && s2->community);
    if(strcmp(s1->community, s2->community) != 0)
    {
        return GLOBUS_FALSE;
    }
    globus_assert(s1->host_id && s2->host_id);
    if(strcmp(s1->host_id, s2->host_id) != 0)
    {
        return GLOBUS_FALSE;
    }

    /* if either is NULL and both are not fail */
    if((s1->username == NULL || s2->username == NULL) &&
        (s1->username != NULL || s2->username != NULL))
    {
        return GLOBUS_FALSE;
    }
    /* if they are not NULL and are not the same fail */
    if(s1->username != NULL && 
        strcmp(s1->username, s2->username) != 0)
    {
        return GLOBUS_FALSE;
    }

    /* if either is NULL and both are not fail */
    if((s1->subject == NULL || s2->subject == NULL) &&
        (s1->subject != NULL || s2->subject != NULL))
    {
        return GLOBUS_FALSE;
    }
    /* if they are not NULL and are not the same fail */
    if(s1->subject != NULL && 
        strcmp(s1->subject, s2->subject) != 0)
    {
        return GLOBUS_FALSE;
    }

    return GLOBUS_TRUE;
}

static
void
globus_l_gfs_ipc_handle_destroy(
    globus_i_gfs_ipc_handle_t *         ipc)
{
    GlobusGFSName(globus_l_gfs_ipc_handle_destroy);
    GlobusGFSDebugEnter();

    if(ipc->connection_info.community)
    {
        globus_free(ipc->connection_info.community);
    }
    if(ipc->connection_info.version)
    {
        globus_free(ipc->connection_info.version);
    }
    if(ipc->connection_info.cookie)
    {
        globus_free(ipc->connection_info.cookie);
    }
    if(ipc->connection_info.username)
    {
        globus_free(ipc->connection_info.username);
    }
    if(ipc->connection_info.subject)
    {
        globus_free(ipc->connection_info.subject);
    }
    if(ipc->connection_info.host_id)
    {
        globus_free(ipc->connection_info.host_id);
    }

    globus_mutex_destroy(&ipc->mutex);
    globus_handle_table_destroy(&ipc->call_table);
    globus_hashtable_destroy(&ipc->reply_table);
    globus_l_gfs_session_info_free(ipc->session_info);
    globus_free(ipc);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_request_destroy(
    globus_gfs_ipc_request_t *          request)
{
    globus_gfs_data_finished_info_t *   data_reply;
    globus_gfs_cmd_finshed_info_t *     command_reply;
    globus_gfs_stat_finished_info_t *   stat_reply;
    globus_gfs_command_info_t *         cmd_info;
    globus_gfs_transfer_info_t *        trans_info;
    globus_gfs_data_info_t *            data_info;
    globus_gfs_stat_info_t *            stat_info;
    int                                 ctr;
    GlobusGFSName(globus_l_gfs_ipc_request_destroy);
    GlobusGFSDebugEnter();

    /* if there is a reply struch clean it up */
    if(request->reply != NULL)
    {
        switch(request->reply->type)
        {
            /* nothing to do for these */
            case GLOBUS_GFS_OP_RECV:
            case GLOBUS_GFS_OP_SEND:
            case GLOBUS_GFS_OP_LIST:
            case GLOBUS_GFS_OP_DESTROY:
            case GLOBUS_GFS_OP_ACTIVE:
            case GLOBUS_GFS_OP_TRANSFER:
            case GLOBUS_GFS_OP_SESSION_START:
                break;

            case GLOBUS_GFS_OP_STAT:
                stat_reply = (globus_gfs_stat_finished_info_t *)
                    &request->reply->info.stat;
                if(stat_reply->stat_array != NULL)
                {
                    for(ctr = 0; ctr < stat_reply->stat_count; ctr++)
                    {
                        if(stat_reply->stat_array[ctr].name != NULL)
                        {
                            globus_free(stat_reply->stat_array[ctr].name);
                        }        
                        if(stat_reply->stat_array[ctr].symlink_target != NULL)
                        {
                            globus_free(
                                stat_reply->stat_array[ctr].symlink_target);
                        }
                    }
                    globus_free(stat_reply->stat_array);
                }
                if(stat_reply->gid_array != NULL)
                {
                    globus_free(stat_reply->gid_array);
                }
                break;
            case GLOBUS_GFS_OP_COMMAND:
                command_reply = (globus_gfs_cmd_finshed_info_t *)
                    &request->reply->info.command;
                if(command_reply->created_dir != NULL)
                {
                    globus_free(command_reply->created_dir);
                }
                if(command_reply->checksum != NULL)
                {
                    globus_free(command_reply->checksum);
                }
                break;

            case GLOBUS_GFS_OP_PASSIVE:
                data_reply = (globus_gfs_data_finished_info_t *)
                    &request->reply->info.data;
                if(data_reply->contact_strings != NULL)
                {
                    for(ctr = 0; ctr < data_reply->cs_count; ctr++)
                    {
                        globus_free((char *)data_reply->contact_strings[ctr]);
                    }
                    globus_free(data_reply->contact_strings);
                }
                break;

            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
        globus_free(request->reply);
    }
    /* if there was an info structure clean it up */
    if(request->info_struct != NULL)
    {
        switch(request->type)
        {
            case GLOBUS_GFS_OP_STAT:
                stat_info =
                    (globus_gfs_stat_info_t *) request->info_struct;
                if(stat_info->pathname != NULL)
                {
                    globus_free(stat_info->pathname);
                }
                globus_free(stat_info);
                break;

            case GLOBUS_GFS_OP_RECV:
            case GLOBUS_GFS_OP_SEND:
            case GLOBUS_GFS_OP_LIST:
                trans_info =
                    (globus_gfs_transfer_info_t *) request->info_struct;
                if(trans_info->pathname != NULL)
                {
                    globus_free(trans_info->pathname);
                }
                if(trans_info->module_name != NULL)
                {
                    globus_free(trans_info->module_name);
                }
                if(trans_info->module_args != NULL)
                {
                    globus_free(trans_info->module_args);
                }
                if(trans_info->list_type != NULL)
                {
                    globus_free((char *)trans_info->list_type);
                }
                globus_range_list_destroy(trans_info->range_list);
                globus_free(trans_info);
                break;

            case GLOBUS_GFS_OP_COMMAND:
                cmd_info =
                    (globus_gfs_command_info_t *) request->info_struct;
                if(cmd_info->pathname != NULL)
                {
                    globus_free(cmd_info->pathname);
                }
                if(cmd_info->cksm_alg != NULL)
                {
                    globus_free(cmd_info->cksm_alg);
                }
                if(cmd_info->rnfr_pathname != NULL)
                {
                    globus_free(cmd_info->rnfr_pathname);
                }
                globus_free(cmd_info);
                break;

            case GLOBUS_GFS_OP_PASSIVE:
            case GLOBUS_GFS_OP_ACTIVE:
                data_info =
                    (globus_gfs_data_info_t *) request->info_struct;
                if(data_info->subject != NULL)
                {
                    globus_free(data_info->subject);
                }
                if(data_info->interface != NULL)
                {
                    globus_free(data_info->interface);
                }
                if(data_info->pathname != NULL)
                {
                    globus_free(data_info->pathname);
                }
                if(data_info->contact_strings != NULL)
                {
                    for(ctr = 0; ctr < data_info->cs_count; ctr++)
                    {
                        globus_free((char *)data_info->contact_strings[ctr]);
                    }
                    globus_free(data_info->contact_strings);
                }
                if(data_info->del_cred != NULL)
                {
                  /* XXX  //gss_release_cred(&min_rc, &data_info->del_cred); */
                }
                globus_free(data_info);
                break;

            case GLOBUS_GFS_OP_DESTROY:
                break;

            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
    }
    globus_free(request);

    GlobusGFSDebugExit();
}


static
globus_gfs_session_info_t *
globus_l_gfs_ipc_session_info_copy(
    globus_gfs_session_info_t *         session_info)
{
    globus_gfs_session_info_t *         cp;
    GlobusGFSName(globus_l_gfs_ipc_session_info_copy);
    GlobusGFSDebugEnter();

    cp = (globus_gfs_session_info_t *) calloc(1, 
        sizeof(globus_gfs_session_info_t));
    if(cp == NULL)
    {
        goto alloc_error;
    }
    cp->del_cred = session_info->del_cred;

    if(session_info->username)
    {
        cp->username = strdup(session_info->username);
        if(cp->username == NULL)
        {
            goto username_error;
        }
    }
    if(session_info->password)
    {
        cp->password = strdup(session_info->password);
        if(cp->password == NULL)
        {
            goto password_error;
        }
    }
    if(session_info->subject)
    {
        cp->subject = strdup(session_info->subject);
        if(cp->subject == NULL)
        {
            goto subject_error;
        }
    }
    if(session_info->cookie)
    {
        cp->cookie = strdup(session_info->cookie);
        if(cp->cookie == NULL)
        {
            goto cookie_error;
        }
    }
    if(session_info->host_id)
    {
        cp->host_id = strdup(session_info->host_id);
        if(cp->host_id == NULL)
        {
            goto host_id_error;
        }
    }

    GlobusGFSDebugExit();
    return cp;

host_id_error:
    globus_free(cp->host_id);
cookie_error:
    globus_free(cp->subject);
subject_error:
    globus_free(cp->password);
password_error:
    globus_free(cp->username);
username_error:
    globus_free(cp);
alloc_error:

    GlobusGFSDebugExitWithError();
    return NULL;
}

static
void
globus_l_gfs_session_info_free(
    globus_gfs_session_info_t *         session_info)
{
    OM_uint32                           min_rc;
    GlobusGFSName(globus_l_gfs_session_info_free);
    GlobusGFSDebugEnter();

    if(session_info)
    {
        if(session_info->username)
        {
            globus_free(session_info->username);
        }
        if(session_info->password)
        {
            globus_free(session_info->password);
        }
        if(session_info->subject)
        {
            globus_free(session_info->subject);
        }
        if(session_info->cookie)
        {
            globus_free(session_info->cookie);
        }
        if(session_info->host_id)
        {
            globus_free(session_info->host_id);
        }
        if(session_info->free_cred && session_info->del_cred != NULL)
        {
            gss_release_cred(&min_rc, &session_info->del_cred);
        }
        globus_free(session_info);
    }

    GlobusGFSDebugExit();
}

void
globus_i_gfs_ipc_stop()
{
    globus_list_t *                     list;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_i_gfs_ipc_stop);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        for(list = globus_l_ipc_handle_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            ipc = (globus_i_gfs_ipc_handle_t *) globus_list_first(list);

            globus_mutex_lock(&ipc->mutex);
            {
                globus_l_gfs_ipc_error_close(ipc);
            }
            globus_mutex_unlock(&ipc->mutex);
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_internal_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_internal_close_cb);
    GlobusGFSDebugEnter();
                                                                                
    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        globus_list_remove(&globus_l_ipc_handle_list, 
            globus_list_search(globus_l_ipc_handle_list, ipc));
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    globus_l_gfs_ipc_handle_destroy(ipc);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_read_request_fault_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     in_buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_list_t *                     list;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_read_request_fault_cb);
    GlobusGFSDebugEnter();
                                                                                
    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    /* if it is successful or not canceled we must shut this connection
        down */
    if(result != GLOBUS_SUCCESS &&
        !globus_error_match(
            globus_error_peek(result),
            GLOBUS_XIO_MODULE,
            GLOBUS_XIO_ERROR_TIMEOUT) &&
        globus_error_match(
            globus_error_peek(result),
            GLOBUS_XIO_MODULE,
            GLOBUS_XIO_ERROR_CANCELED))
    {
        globus_l_gfs_ipc_send_start_session(ipc);

        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "an IPC connection has been reused\n");
    }
    else
    {
        globus_mutex_lock(&globus_l_ipc_mutex);
        {
            list = (globus_list_t *) globus_hashtable_remove(
                &globus_l_ipc_handle_table, &ipc->connection_info);
            globus_list_remove(&list, globus_list_search(list, ipc));
            if(!globus_list_empty(list))
            {
                globus_i_gfs_ipc_handle_t * tmp_ipc;
                tmp_ipc = (globus_i_gfs_ipc_handle_t *)
                    globus_list_first(list);
                globus_hashtable_insert(
                    &globus_l_ipc_handle_table,
                    &tmp_ipc->connection_info, list);
            }
            res = globus_xio_register_close(
               ipc->xio_handle,
                NULL,
                globus_l_gfs_ipc_internal_close_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                globus_l_gfs_ipc_handle_destroy(ipc);
            }
        }
        globus_mutex_unlock(&globus_l_ipc_mutex);
        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "an IPC connection has been closed due to error or time out.\n");
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_error_close_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_error_callback_t     error_cb;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_error_close_kickout);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        globus_list_remove(&globus_l_ipc_handle_list, 
            globus_list_search(globus_l_ipc_handle_list, ipc));
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    if(ipc->error_cb)
    {
        error_cb = ipc->error_cb;
        ipc->error_cb = NULL;
        error_cb(ipc, ipc->cached_res, ipc->error_arg);
    }

    globus_l_gfs_ipc_handle_destroy(ipc);

    GlobusGFSDebugExit();
}
    
static
void
globus_l_gfs_ipc_error_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_error_close_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_l_gfs_ipc_error_close_kickout(ipc);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_error_close(
    globus_i_gfs_ipc_handle_t *         ipc)
{
    globus_list_t *                     tmp_list;
    globus_list_t *                     list;
    globus_result_t                     res;
    GlobusGFSName(globus_l_gfs_ipc_error_close);
    GlobusGFSDebugEnter();

    switch(ipc->state)
    {
        case GLOBUS_GFS_IPC_STATE_CLOSING:
        case GLOBUS_GFS_IPC_STATE_IN_CB:
            ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
            break;

        case GLOBUS_GFS_IPC_STATE_ERROR:
            break;

        case GLOBUS_GFS_IPC_STATE_OPEN:

            if(globus_l_gfs_ipc_requester)
            {
                list = (globus_list_t *) globus_hashtable_remove(
                    &globus_l_ipc_handle_table, &ipc->connection_info);
                tmp_list = globus_list_search(list, ipc);
                if(tmp_list)
                {
                    globus_list_remove(&list, tmp_list);
                    if(!globus_list_empty(list))
                    {
                        globus_hashtable_insert(
                            &globus_l_ipc_handle_table,
                            &ipc->connection_info,list);
                    }
                }
            }
            /* deliberate fall through */

        case GLOBUS_GFS_IPC_STATE_SERVER_OPENING:
        case GLOBUS_GFS_IPC_STATE_CLIENT_OPENING:
        case GLOBUS_GFS_IPC_STATE_GETTING:
        case GLOBUS_GFS_IPC_STATE_STOPPING:
        case GLOBUS_GFS_IPC_STATE_IN_USE:
            ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
            res = globus_xio_register_close(
               ipc->xio_handle,
                NULL,
                globus_l_gfs_ipc_error_close_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_ipc_error_close_kickout,
                    ipc);
            }
            break;

        case GLOBUS_GFS_IPC_STATE_CLOSED:
        default:
            globus_assert(0 && "bad state, possible memory corruption");
            break;
    }

    GlobusGFSDebugExit();
}

static int
globus_l_gfs_ipc_unpack_cred(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    gss_cred_id_t *                     out_cred)
{
    OM_uint32                           maj_rc;
    OM_uint32                           min_rc;
    OM_uint32                           time_rec;
    gss_buffer_desc                     gsi_buffer;
    gss_cred_id_t                       cred;
    GlobusGFSName(globus_l_gfs_ipc_unpack_cred);
    GlobusGFSDebugEnter();

    GFSDecodeUInt32(buffer, len, gsi_buffer.length);
    if(gsi_buffer.length > 0)
    {
        gsi_buffer.value = buffer;

        maj_rc = gss_import_cred(
            &min_rc, &cred, GSS_C_NO_OID, 0, &gsi_buffer, 0, &time_rec);
        if(maj_rc != GSS_S_COMPLETE)
        {
            goto decode_err;
        }

        *out_cred = cred;
    }
    else
    {
        *out_cred = NULL;
    }

    GlobusGFSDebugExit();
    return 0;

  decode_err:

    GlobusGFSDebugExitWithError();
    return -1;
}

static
void
globus_l_gfs_ipc_request_ss_body_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     start_buf;
    globus_list_t *                     list;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_finished_info_t              reply;
    GlobusGFSName(globus_l_gfs_ipc_request_ss_body_cb);
    GlobusGFSDebugEnter();

    start_buf = buffer;
    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));

    globus_assert(globus_l_gfs_ipc_requester);

    /* this has just read the reply to the session start */
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* safe because no one else has this yet */
    ipc->state = GLOBUS_GFS_IPC_STATE_IN_CB;
    GFSDecodeUInt32(buffer, len, reply.code);
    GFSDecodeUInt32(buffer, len, reply.result);
    GFSDecodeString(buffer, len, reply.msg);
    if(reply.result != GLOBUS_SUCCESS && reply.msg != NULL)
    {
        result = GlobusGFSErrorGeneric(reply.msg);
        globus_free(reply.msg);
        reply.msg = NULL;
    }
    GFSDecodeString(buffer, len, reply.info.session.username);
    GFSDecodeString(buffer, len, reply.info.session.home_dir);
          
    if(ipc->open_cb)
    {
        ipc->open_cb(ipc, result, &reply, ipc->user_arg);
    }
        
    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_IN_CB:
                if(result != GLOBUS_SUCCESS)
                {
                    /* this result is from the peer, if it rejected
                        just stuff it in the cache */
                    list = (globus_list_t *) globus_hashtable_remove(
                        &globus_l_ipc_handle_table,
                        &ipc->connection_info);
                    /* check for requests */
                    globus_list_insert(&list, ipc);
                    globus_hashtable_insert(
                        &globus_l_ipc_handle_table,
                        &ipc->connection_info,
                        list);
                }
                else
                {
                    ipc->state = GLOBUS_GFS_IPC_STATE_IN_USE;
                }
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR:
                globus_l_gfs_ipc_error_close(ipc);
                break;

            default:
                globus_assert(0);
                break;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_free(start_buf);
    if(reply.info.session.home_dir)
    {
        globus_free(reply.info.session.home_dir);
    }
    if(reply.info.session.username)
    {
        globus_free(reply.info.session.username);
    }
    GlobusGFSDebugExit();
    return;

error:
decode_err:
    globus_free(start_buf);
    if(reply.info.session.home_dir)
    {
        globus_free(reply.info.session.home_dir);
    }
    if(reply.info.session.username)
    {
        globus_free(reply.info.session.username);
    }
    reply.result = result;
    if(ipc->open_cb)
    {
        ipc->open_cb(ipc, result, &reply, ipc->user_arg);
    }
    /* ok to call this unlocked.  since we errored no one should touch ipc */
    globus_l_gfs_ipc_error_close(ipc);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_reply_ss_body_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     start_buf;
    globus_i_gfs_ipc_handle_t *         ipc;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_ipc_reply_ss_body_cb);
    GlobusGFSDebugEnter();

    start_buf = buffer;
    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;
    globus_assert(!globus_l_gfs_ipc_requester);

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    ipc->session_info = (globus_gfs_session_info_t *) 
        globus_calloc(1, sizeof(globus_gfs_session_info_t));
    if(ipc->session_info == NULL)
    {
        goto error;
    }
    ipc->session_info->username = 
        globus_libc_strdup(ipc->connection_info.username);
    ipc->session_info->subject = 
        globus_libc_strdup(ipc->connection_info.subject);
    ipc->session_info->cookie = 
        globus_libc_strdup(ipc->connection_info.cookie);
    ipc->session_info->host_id = 
        globus_libc_strdup(ipc->connection_info.host_id);
    ipc->session_info->map_user = ipc->connection_info.map_user;
    GFSDecodeString(buffer, len, ipc->session_info->password);
    
    rc = globus_l_gfs_ipc_unpack_cred(
        ipc, buffer, len, &ipc->session_info->del_cred);
    if(rc != 0)
    {
        goto decode_err;
    }
    ipc->session_info->free_cred = GLOBUS_TRUE;
        
    ipc->state = GLOBUS_GFS_IPC_STATE_IN_CB;
    ipc->error_cb = ipc->reply_error_cb;
    if(ipc->iface->session_start_func)
    {
        ipc->iface->session_start_func(
            ipc, NULL, ipc->session_info, NULL, NULL);
    }
    globus_free(start_buf);

    GlobusGFSDebugExit();
    return;

decode_err:
error:
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);
    globus_free(start_buf);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_ss_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    globus_byte_t *                     new_buf = NULL;
    int                                 reply_size;
    globus_size_t                       size;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_ss_header_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        size = len;
        ptr = buffer;
        GFSDecodeChar(ptr, size, type);
        GFSDecodeUInt32(ptr, size, id);
        GFSDecodeUInt32(ptr, size, reply_size);

        new_buf = globus_malloc(reply_size);
        if(new_buf == NULL)
        {
            result = GlobusGFSErrorMemory("new_buf");
            goto error;
        }

        if(globus_l_gfs_ipc_requester)
        {
            if(type != GLOBUS_GFS_OP_SESSION_START_REPLY)
            {
                result = GlobusGFSErrorIPC();
                goto mem_error;
            }
            result = globus_xio_register_read(
                handle,
                new_buf,
                reply_size - GFS_IPC_HEADER_SIZE,
                reply_size - GFS_IPC_HEADER_SIZE,
                NULL,
                globus_l_gfs_ipc_request_ss_body_cb,
                ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto mem_error;
            }
        }
        else
        {
            if(type != GLOBUS_GFS_OP_SESSION_START)
            {
                result = GlobusGFSErrorIPC();
                goto mem_error;
            }
            result = globus_xio_register_read(
                handle,
                new_buf,
                reply_size - GFS_IPC_HEADER_SIZE,
                reply_size - GFS_IPC_HEADER_SIZE,
                NULL,
                globus_l_gfs_ipc_reply_ss_body_cb,
                ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto mem_error;
            }
        }

        globus_free(buffer);
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(new_buf);
decode_err:
error:
    globus_free(buffer);
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_start_session_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_start_session_write_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;
    
    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
        if(new_buf == NULL)
        {
            result = GlobusGFSErrorIPC();
            goto error;
        }
        result = globus_xio_register_read(
            ipc->xio_handle,
            new_buf,
            GFS_IPC_HEADER_SIZE,
            GFS_IPC_HEADER_SIZE,
            NULL,
            globus_l_gfs_ipc_ss_header_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            goto mem_error;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(new_buf);
error:
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);
    globus_free(buffer);

    GlobusGFSDebugExitWithError();
}


static
void
globus_l_gfs_ipc_send_start_session(
    globus_i_gfs_ipc_handle_t *         ipc)
{
    OM_uint32                           maj_rc;
    OM_uint32                           min_rc;
    int                                 ndx;
    gss_buffer_desc                     gsi_buffer;
    globus_result_t                     res;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_l_gfs_ipc_send_start_session);
    GlobusGFSDebugEnter();

    /* pack the header */
    buffer = globus_malloc(ipc->buffer_size);
    if(buffer == NULL)
    {
        goto alloc_error;
    }
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_SESSION_START);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

    /* body */
    GFSEncodeString(
        buffer, ipc->buffer_size, ptr, ipc->session_info->password);
    if(ipc->session_info->del_cred == NULL)
    {
        GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, 0);
    }
    else
    {
        maj_rc = gss_export_cred(
            &min_rc, ipc->session_info->del_cred, NULL, 0, &gsi_buffer);
        if(maj_rc != GSS_S_COMPLETE)
        {
        }
        GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, gsi_buffer.length);
        if(gsi_buffer.length > 0)
        {
            if(ptr - buffer + gsi_buffer.length >= ipc->buffer_size)
            {
                ndx = ptr - buffer;
                ipc->buffer_size += gsi_buffer.length;
                buffer = globus_libc_realloc(buffer, ipc->buffer_size);
                ptr = buffer + ndx;
            }
            memcpy(ptr, gsi_buffer.value, gsi_buffer.length);
            ptr += gsi_buffer.length;
            gss_release_buffer(&min_rc, &gsi_buffer);
        }
    }

    msg_size = ptr - buffer;
    ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

    res = globus_xio_register_write(
        ipc->xio_handle,
        buffer,
        msg_size,
        msg_size,
        NULL,
        globus_l_gfs_ipc_start_session_write_cb,
        ipc);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusGFSDebugExit();
    return;

error:
    globus_free(buffer);
alloc_error:
    globus_l_gfs_ipc_error_close(ipc);

    GlobusGFSDebugExitWithError();
}

/*
 *  called by the acceptor to read the connection information
 */
static
void
globus_l_gfs_ipc_read_new_body_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     in_buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    int                                 size;
    globus_byte_t *                     ptr;
    globus_byte_t *                     new_buf;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_list_t *                     list;
    globus_i_gfs_ipc_handle_t *         tmp_ipc;
    GlobusGFSName(globus_l_gfs_ipc_read_new_body_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto error;
    }
    size = len;
    ptr = in_buffer;

    GFSDecodeString(ptr, size, ipc->connection_info.version);
    GFSDecodeString(ptr, size, ipc->connection_info.community);
    GFSDecodeString(ptr, size, ipc->connection_info.cookie);
    GFSDecodeString(ptr, size, ipc->connection_info.subject);
    GFSDecodeString(ptr, size, ipc->connection_info.username);
    GFSDecodeString(ptr, size, ipc->connection_info.host_id);
    GFSDecodeUInt32(ptr, size, ipc->connection_info.map_user);

    if(strcmp(ipc->connection_info.version, globus_l_gfs_local_version) != 0)
    {
        goto version_error;
    }

    /* if i am a requester */
    if(globus_l_gfs_ipc_requester)
    {
        globus_mutex_lock(&globus_l_ipc_mutex);
        {
            /* see if there is a request out there for this one */
            list = (globus_list_t *) globus_hashtable_remove(
                &globus_l_ipc_request_table,
                &ipc->connection_info);
            if(!globus_list_empty(list))
            {
                /* check for requests */
                globus_list_remove(&list, list);
                if(!globus_list_empty(list))
                {
                    tmp_ipc = (globus_i_gfs_ipc_handle_t *)
                        globus_list_first(list);
                    globus_hashtable_insert(
                        &globus_l_ipc_request_table,
                        &tmp_ipc->connection_info,
                        list);
                }

                globus_l_gfs_ipc_send_start_session(ipc);
            }
            /* if no one needs it now stick in table */
            else
            {
                list = (globus_list_t *) globus_hashtable_remove(
                    &globus_l_ipc_handle_table,
                    &ipc->connection_info);

                /* check for requests */
                globus_list_insert(&list, ipc);
                globus_hashtable_insert(
                    &globus_l_ipc_handle_table,
                    &ipc->connection_info,
                    list);
            }
        }
        globus_mutex_unlock(&globus_l_ipc_mutex);
    }
    else
    {
        new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
        if(new_buf == NULL)
        {
            result = GlobusGFSErrorIPC();
            ipc->cached_res = result;
            goto error;
        }
        result = globus_xio_register_read(
            ipc->xio_handle,
            new_buf,
            GFS_IPC_HEADER_SIZE,
            GFS_IPC_HEADER_SIZE,
            NULL,
            globus_l_gfs_ipc_ss_header_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            globus_free(new_buf);
            ipc->cached_res = result;
            goto error;
        }
    }

    globus_free(in_buffer);

    GlobusGFSDebugExit();
    return;

version_error:
decode_err:
error:
    globus_free(in_buffer);
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR, 
        "An accepted IPC connection failed during session body read.\n");

    globus_l_gfs_ipc_error_close_kickout(ipc);

    GlobusGFSDebugExitWithError();
}

globus_result_t
globus_gfs_ipc_reply_session(
    globus_gfs_ipc_handle_t             ipc,
    globus_gfs_finished_info_t *            reply)
{
    globus_byte_t *                     buffer;
    globus_byte_t *                     new_buf;
    globus_byte_t *                     ptr;
    int                                 msg_size;
    globus_result_t                     res;
    char *                              tmp_msg;
    GlobusGFSName(globus_gfs_ipc_reply_session);
    GlobusGFSDebugEnter();

    globus_assert(!globus_l_gfs_ipc_requester);
 
    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_IN_CB:
                /* pack the header */
                buffer = globus_malloc(ipc->buffer_size);
                if(buffer == NULL)
                {
                    res = GlobusGFSErrorMemory("new_buf");
                    goto error;
                }
                ptr = buffer;
                
                GFSEncodeChar(
                    buffer, ipc->buffer_size, ptr, 
                    GLOBUS_GFS_OP_SESSION_START_REPLY);
                GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
                GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
                GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->code);
                GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->result);
                if(reply->msg == NULL && reply->result != GLOBUS_SUCCESS)
                {
                    tmp_msg = globus_error_print_friendly(
                        globus_error_peek(reply->result));
                    GFSEncodeString(
                        buffer, ipc->buffer_size, ptr, tmp_msg);  
                    globus_free(tmp_msg);              
                }
                else
                {
                    GFSEncodeString(
                        buffer, ipc->buffer_size, ptr, reply->msg);
                }
                GFSEncodeString(
                    buffer, ipc->buffer_size, 
                    ptr, reply->info.session.username);
                GFSEncodeString(
                    buffer, ipc->buffer_size, 
                    ptr, reply->info.session.home_dir);
    
                msg_size = ptr - buffer;
                ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
                GFSEncodeUInt32(
                    buffer, ipc->buffer_size, ptr, msg_size);
                res = globus_xio_register_write(
                    ipc->xio_handle,
                    buffer,
                    msg_size,
                    msg_size,
                    NULL,
                    globus_l_gfs_ipc_reply_cb,
                    ipc);
                if(res != GLOBUS_SUCCESS)
                {
                    goto xio_error;
                }
                new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
                if(new_buf == NULL)
                {
                    res = GlobusGFSErrorMemory("new_buf");
                    goto xio_error;
                }
                res = globus_xio_register_read(
                    ipc->xio_handle,
                    new_buf,
                    GFS_IPC_HEADER_SIZE,
                    GFS_IPC_HEADER_SIZE,
                    NULL,
                    globus_l_gfs_ipc_reply_read_header_cb,
                    ipc);
                if(res != GLOBUS_SUCCESS)
                {
                    goto mem_error;
                }

                ipc->user_arg = reply->info.session.session_arg;
                ipc->state = GLOBUS_GFS_IPC_STATE_IN_USE;
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR:
                globus_l_gfs_ipc_error_close(ipc);
                break;

            case GLOBUS_GFS_IPC_STATE_IN_USE:
                break;

            default:
                globus_assert(0);
                break;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

mem_error:
    globus_free(new_buf);
xio_error:
    globus_free(buffer);
error:
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

static
void
globus_l_gfs_ipc_read_new_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    globus_byte_t *                     new_buf = NULL;
    int                                 reply_size;
    globus_result_t                     res;
    globus_size_t                       size;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_read_new_header_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto err;
    }

    size = len;
    ptr = buffer;
    GFSDecodeChar(ptr, size, type);
    GFSDecodeUInt32(ptr, size, id);
    GFSDecodeUInt32(ptr, size, reply_size);

    if(type != GLOBUS_GFS_OP_HANDSHAKE)
    {
        goto err;
    }

    new_buf = globus_malloc(reply_size);
    if(new_buf == NULL)
    {
        res = GlobusGFSErrorMemory("new_buf");
        ipc->cached_res = res;
        goto err;
    }

    result = globus_xio_register_read(
        handle,
        new_buf,
        reply_size - GFS_IPC_HEADER_SIZE,
        reply_size - GFS_IPC_HEADER_SIZE,
        NULL,
        globus_l_gfs_ipc_read_new_body_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto mem_err;
    }
    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

mem_err:
decode_err:
err:
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR,
        "An accepted IPC connection failed during session header read\n");
    globus_l_gfs_ipc_error_close_kickout(ipc);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_server_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_byte_t *                     buffer = NULL;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_server_open_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto error;
    }

    /* send other side our session_info */
    buffer = globus_malloc(GFS_IPC_HEADER_SIZE);
    if(buffer == NULL)
    {
        goto error;
    }
    result = globus_xio_register_read(
        ipc->xio_handle,
        buffer,
        GFS_IPC_HEADER_SIZE,
        GFS_IPC_HEADER_SIZE,
        NULL,
        globus_l_gfs_ipc_read_new_header_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto mem_error;
    }

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(buffer);
error:
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR, 
        "An accepted IPC connection failed during open\n");
    globus_l_gfs_ipc_error_close_kickout(ipc);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_add_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_add_server_accept_cb);
    GlobusGFSDebugEnter();

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        res = GlobusGFSErrorMemory("ipc");
        goto error;
    }
    ipc->state = GLOBUS_GFS_IPC_STATE_SERVER_OPENING;

/* XXX //    if(!globus_l_gfs_ipc_requester) */
    {
        ipc->iface = &globus_gfs_ipc_default_iface;
    }
    /* ipc->local = GLOBUS_FALSE; */
    /* ipc->cached_res = GLOBUS_SUCCESS; */
    /* ipc->error_cb = NULL; */
    /* ipc->error_arg = NULL; */
    /* ipc->user_handle = NULL; */
    /* ipc->session_info = NULL; */
    globus_mutex_init(&ipc->mutex, NULL);
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    ipc->xio_handle = handle;
    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        result = globus_xio_register_open(
            ipc->xio_handle,
            NULL,
            NULL,
            globus_l_gfs_ipc_server_open_cb,
            ipc);
        if(result == GLOBUS_SUCCESS)
        {
            goto ipc_error;
        }
        globus_list_insert(&globus_l_ipc_handle_list, ipc);
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
    return;

ipc_error:
    globus_mutex_unlock(&globus_l_ipc_mutex);
error:
    /* perhaps want to log that a session could not be opened */
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR, "An accepted IPC connection failed to open\n");

    GlobusGFSDebugExitWithError();
}

/************************************************************************
 * public connection bottstrap functions 
 ***********************************************************************/
 
/*
 *  create a ipc handle from an FD.  assumed this is server side,
 *  will start the server side hand shake
 */
globus_result_t
globus_gfs_ipc_handle_create(
    globus_gfs_ipc_iface_t *            iface,
    globus_xio_system_native_handle_t   system_handle,
    globus_gfs_ipc_open_callback_t      cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_arg)
{
    globus_xio_attr_t                   xio_attr;
    globus_result_t                     result;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_handle_create);
    GlobusGFSDebugEnter();

    if(iface == NULL)
    {
        result = GlobusGFSErrorParameter("iface");
        goto error;
    }
    result = globus_xio_attr_init(&xio_attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_xio_attr_cntl(xio_attr, globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_HANDLE, system_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }
    result = globus_xio_attr_cntl(xio_attr, globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_NODELAY, GLOBUS_TRUE);
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }
    if(globus_i_gfs_config_bool("secure_ipc"))
    {
        result = globus_xio_attr_cntl(xio_attr, globus_l_gfs_gsi_driver,
            GLOBUS_XIO_GSI_FORCE_SERVER_MODE, GLOBUS_TRUE);
        if(result != GLOBUS_SUCCESS)
        {
            goto attr_error;
        }
    }
    
    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        result = GlobusGFSErrorMemory("ipc");
        goto attr_error;
    }
    ipc->iface = iface;
    ipc->state = GLOBUS_GFS_IPC_STATE_SERVER_OPENING;
    ipc->cached_res = GLOBUS_SUCCESS;
    ipc->open_cb = cb;
    ipc->error_cb = error_cb;
    ipc->reply_error_cb = error_cb;
    ipc->error_arg = error_arg;
    ipc->user_arg = user_arg;
    globus_mutex_init(&ipc->mutex, NULL);
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    globus_handle_table_init(&ipc->call_table, NULL);
    globus_hashtable_init(
        &ipc->reply_table, 
        8,
        globus_hashtable_int_hash,
        globus_hashtable_int_keyeq);

    result = globus_xio_handle_create(
        &ipc->xio_handle, globus_l_gfs_ipc_xio_stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        result = globus_xio_register_open(
            ipc->xio_handle,
            NULL,
            xio_attr,
            globus_l_gfs_ipc_server_open_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            goto handle_error;
        }
        globus_list_insert(&globus_l_ipc_handle_list, ipc);
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

handle_error:
    globus_l_gfs_ipc_handle_destroy(ipc);
attr_error:
    globus_xio_attr_destroy(xio_attr);
error:
    GlobusGFSDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_ipc_handshake_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_handshake_write_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    /* if i am a requester */
    if(globus_l_gfs_ipc_requester)
    {
        globus_l_gfs_ipc_send_start_session(ipc);
    }
    else
    {
        globus_mutex_lock(&ipc->mutex);
        {
            /* post a read for the next request */
            new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
            if(new_buf == NULL)
            {
                goto alloc_error;
            }
            result = globus_xio_register_read(
                ipc->xio_handle,
                new_buf,
                GFS_IPC_HEADER_SIZE,
                GFS_IPC_HEADER_SIZE,
                NULL,
                globus_l_gfs_ipc_reply_read_header_cb,
                ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto read_error;
            }
        }
        globus_mutex_unlock(&ipc->mutex);
    }
    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

read_error:
    globus_free(new_buf);
alloc_error:
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);
    globus_free(buffer);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_client_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_byte_t *                     ptr;
    globus_byte_t *                     buffer;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_l_gfs_ipc_client_open_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    ipc->state = GLOBUS_GFS_IPC_STATE_IN_CB;
    
    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto error;
    }
    
    globus_mutex_lock(&ipc->mutex);
    {
        buffer = globus_malloc(ipc->buffer_size);
        if(buffer == NULL)
        {
            goto error;
        }
        ptr = buffer;

        GFSEncodeChar(buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_HANDSHAKE);
        GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
        GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.version);
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.community);
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.cookie);
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.subject);
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.username);
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.host_id);
        GFSEncodeUInt32(
            buffer, ipc->buffer_size, ptr, ipc->connection_info.map_user);
        msg_size = ptr - buffer;
        ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
        GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

        res = globus_xio_register_write(
            ipc->xio_handle,
            buffer,
            msg_size,
            msg_size,
            NULL,
            globus_l_gfs_ipc_handshake_write_cb,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            goto xio_error;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

xio_error:
    globus_free(buffer);
error:
    {
        globus_gfs_finished_info_t          reply;
        memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));          
        result = GlobusGFSErrorWrapFailed("IPC connection", result);
        if(ipc->open_cb)
        {
            ipc->open_cb(ipc, result, &reply, ipc->user_arg);
        }
    }    
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}

static 
globus_bool_t
globus_l_gfs_ipc_timeout_cb(
    globus_xio_handle_t                 handle,
    globus_xio_operation_type_t         type,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_bool_t                       rc;
    GlobusGFSName(globus_l_gfs_ipc_timeout_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    switch(type)
    {
        case GLOBUS_XIO_OPERATION_TYPE_OPEN:
            rc = GLOBUS_TRUE;
            break;
        case GLOBUS_XIO_OPERATION_TYPE_READ:
            globus_mutex_lock(&globus_l_ipc_mutex);
            {
                if(ipc->state == GLOBUS_GFS_IPC_STATE_OPEN)
                {
                    rc = GLOBUS_TRUE;
                }
                else
                {
                    rc = GLOBUS_FALSE;
                }
            }
            globus_mutex_unlock(&globus_l_ipc_mutex);
            /* close handle */
            break;
        default:
            rc = GLOBUS_FALSE;
            break;
    }

    GlobusGFSDebugExit();
    return rc;
}



/*
 *  get a handle with the given info.  perhaps it is cached,
 *  perhaps a connection needs to be made, perhaps we wait for
 *  someone to connect back.
 */
static
globus_result_t
globus_l_gfs_ipc_handle_connect(
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_iface_t *            iface,
    globus_i_gfs_community_t *          community,
    int                                 community_ndx,
    globus_gfs_ipc_open_callback_t      cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_bool_t                       allowed_to_connect = GLOBUS_TRUE;
    globus_result_t                     result;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_request_t *          request;
    globus_list_t *                     list;
    globus_xio_attr_t                   attr;
    int                                 time;
    globus_reltime_t                    timeout;
    GlobusGFSName(globus_l_gfs_ipc_handle_connect);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        result = GlobusGFSErrorMemory("ipc");
        goto ipc_error;
    }
    ipc->open_cb = cb;
    ipc->user_arg = user_arg;
    ipc->error_cb = error_cb;
    ipc->error_arg = error_user_arg;
    ipc->iface = iface;
    ipc->state = GLOBUS_GFS_IPC_STATE_CLIENT_OPENING;
    ipc->session_info = 
        globus_l_gfs_ipc_session_info_copy(session_info);
    globus_mutex_init(&ipc->mutex, NULL);
    ipc->buffer_size = GFS_IPC_DEFAULT_BUFFER_SIZE;
    globus_handle_table_init(&ipc->call_table, NULL);
    globus_hashtable_init(
        &ipc->reply_table, 
        8,
        globus_hashtable_int_hash,
        globus_hashtable_int_keyeq);

    ipc->connection_info.version = strdup(globus_l_gfs_local_version);
    ipc->connection_info.community = strdup(community->name);
    ipc->connection_info.cookie = NULL;
    ipc->connection_info.subject = 
        session_info->subject ? strdup(session_info->subject) : NULL;
    ipc->connection_info.username = 
        session_info->username ? strdup(session_info->username) : NULL;
    ipc->connection_info.host_id = strdup(session_info->host_id);
    ipc->connection_info.map_user = session_info->map_user;
    ipc->connection_info.community_ndx = community_ndx;

    if(allowed_to_connect)
    {
        globus_xio_attr_init(&attr);

        if(session_info->del_cred != NULL &&
            globus_i_gfs_config_bool("secure_ipc"))
        {
            globus_xio_gsi_authorization_mode_t      auth_mode;
            const char *                             auth_mode_str;
            globus_xio_attr_cntl(
                attr, globus_l_gfs_gsi_driver,
                GLOBUS_XIO_GSI_SET_CREDENTIAL, session_info->del_cred);

            globus_xio_attr_cntl(
                attr, globus_l_gfs_gsi_driver,
                GLOBUS_XIO_GSI_SET_PROTECTION_LEVEL,
                GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY);

            auth_mode_str = globus_i_gfs_config_string("ipc_auth_mode");
            if(auth_mode_str != NULL)
            {
                if(strcasecmp(auth_mode_str, "none") == 0)
                {
                    auth_mode = GLOBUS_XIO_GSI_NO_AUTHORIZATION;
                }
                else if(strcasecmp(auth_mode_str, "self") == 0)
                {
                    auth_mode = GLOBUS_XIO_GSI_SELF_AUTHORIZATION;
                }
                else if(strcasecmp(auth_mode_str, "host") == 0)
                {
                    auth_mode = GLOBUS_XIO_GSI_HOST_AUTHORIZATION;
                }
                else if(strncasecmp(auth_mode_str, "subject:", 8) == 0)
                {
                    gss_buffer_desc     send_tok;
                    OM_uint32           min_stat;
                    OM_uint32           maj_stat;
                    gss_name_t          target_name;
                    
                    auth_mode = GLOBUS_XIO_GSI_IDENTITY_AUTHORIZATION;                   
                    send_tok.value = (void *) (auth_mode_str + 8);
                    send_tok.length = strlen(auth_mode_str + 8) + 1;
                    maj_stat = gss_import_name(
                                    &min_stat,
                                    &send_tok,
                                    GSS_C_NT_USER_NAME,
                                    &target_name);
                    if(maj_stat != GSS_S_COMPLETE || 
                        target_name == GSS_C_NO_NAME)
                    {
                        goto ipc_error;
                    }

                    globus_xio_attr_cntl(
                        attr, globus_l_gfs_gsi_driver,
                        GLOBUS_XIO_GSI_SET_TARGET_NAME,
                        target_name);
                        
                    gss_release_name(&min_stat, &target_name);
                }
                else
                {
                    goto ipc_error;
                }
                  
                globus_xio_attr_cntl(
                    attr, globus_l_gfs_gsi_driver,
                    GLOBUS_XIO_GSI_SET_AUTHORIZATION_MODE,
                    auth_mode);
            }
        }
        time = globus_i_gfs_config_int("ipc_connect_timeout");
        if(time > 0)
        {
            GlobusTimeReltimeSet(timeout, time, 0);
            globus_xio_attr_cntl(
                attr,
                NULL,
                GLOBUS_XIO_ATTR_SET_TIMEOUT_OPEN,
                globus_l_gfs_ipc_timeout_cb,
                &timeout,
                ipc);
        }
        time = globus_i_gfs_config_int("ipc_idle_timeout");
        if(time > 0)
        {
            GlobusTimeReltimeSet(timeout, time, 0);
            globus_xio_attr_cntl(
                attr,
                NULL,
                GLOBUS_XIO_ATTR_SET_TIMEOUT_READ,
                globus_l_gfs_ipc_timeout_cb,
                &timeout,
                ipc);
        }
        result = globus_xio_handle_create(
            &ipc->xio_handle, globus_l_gfs_ipc_xio_stack);
        if(result != GLOBUS_SUCCESS)
        {
            goto handle_error;
        }
        result = globus_xio_register_open(
            ipc->xio_handle,
            session_info->host_id,
            attr,
            globus_l_gfs_ipc_client_open_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            goto open_error;
        }
        globus_xio_attr_destroy(attr);
    }
    else
    {
        list = (globus_list_t *) globus_hashtable_remove(
            &globus_l_ipc_request_table,
            &ipc->connection_info);
        /* check for requests */
        globus_list_insert(&list, ipc);
        globus_hashtable_insert(
            &globus_l_ipc_request_table,
            &ipc->connection_info,
            list);
    }
    globus_list_insert(&globus_l_ipc_handle_list, ipc);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

open_error:
handle_error:
ipc_error:
    globus_free(request);

    GlobusGFSDebugExitWithError();
    return result;
}


static
globus_i_gfs_ipc_handle_t *
globus_l_gfs_ipc_handle_lookup(
    globus_l_gfs_ipc_connection_t *     connection_info)
{
    globus_list_t *                     list;
    globus_i_gfs_ipc_handle_t *         ipc = NULL;
    globus_i_gfs_ipc_handle_t *         insert_ipc = NULL;
    GlobusGFSName(globus_l_gfs_ipc_handle_lookup);
    GlobusGFSDebugEnter();

    list = (globus_list_t *) globus_hashtable_remove(
        &globus_l_ipc_handle_table,
        connection_info);
    if(!globus_list_empty(list))
    {
        ipc = (globus_i_gfs_ipc_handle_t *) globus_list_remove(&list, list);
        if(!globus_list_empty(list))
        {
            insert_ipc = globus_list_first(list);
            globus_hashtable_insert(
                &globus_l_ipc_handle_table,
                &insert_ipc->connection_info,
                list);
        }
    }

    GlobusGFSDebugExit();
    return ipc;
}

globus_result_t
globus_gfs_ipc_handle_obtain_by_path(
    int *                               p_handle_count,
    const char *                        pathname,
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_callback_t      cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_l_gfs_ipc_connection_t       tmp_ci;
    int                                 i;
    globus_i_gfs_ipc_handle_t *         ipc;
    int                                 handle_count;
    globus_result_t                     res;
    globus_list_t *                     reserved_list = NULL;
    globus_list_t *                     reserved_ndx = NULL;
    int                                 tmp_ndx;
    globus_gfs_session_info_t           tmp_si;
    globus_i_gfs_community_t *          community;
    GlobusGFSName(globus_gfs_ipc_handle_obtain_by_path);
    GlobusGFSDebugEnter();

    handle_count = *p_handle_count;
    /* find the community */
    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        community = globus_l_gfs_ipc_find_community(pathname);
        if(community == NULL)
        {
            res = GlobusGFSErrorIPC();
            goto community_error;
        }

        memset(&tmp_ci, '\0', sizeof(globus_l_gfs_ipc_connection_t));
        tmp_ci.version = (char *) globus_l_gfs_local_version;
        tmp_ci.community = community->name;
        tmp_ci.cookie = session_info->cookie;
        tmp_ci.username = session_info->username;
        tmp_ci.subject = session_info->subject;
        tmp_ci.map_user = session_info->map_user;

        memcpy(&tmp_si, session_info, sizeof(globus_gfs_session_info_t));

        /* first get anything that is cached */
        for(i = 0; i < community->cs_count && handle_count > 0; i++)
        {
            tmp_si.host_id = community->cs[i];
            tmp_ci.host_id = community->cs[i];
            ipc = globus_l_gfs_ipc_handle_lookup(&tmp_ci);
            if(ipc != NULL)
            {
                /* i got it safely from the big lock, i have not given
                    a ref to a user yet so i can safely mess with ipc */
                ipc->state = GLOBUS_GFS_IPC_STATE_GETTING;
                ipc->open_cb = cb;
                ipc->user_arg = user_arg;
                ipc->error_cb = error_cb;
                ipc->error_arg = error_user_arg;
                globus_l_gfs_session_info_free(ipc->session_info);
                ipc->session_info =
                    globus_l_gfs_ipc_session_info_copy(&tmp_si);
                if(ipc->session_info == NULL)
                {
                    res = GlobusGFSErrorIPC();
                    goto open_error;
                }
                handle_count--;

                globus_xio_handle_cancel_operations(
                    ipc->xio_handle, GLOBUS_XIO_CANCEL_READ);
            }
            /* if unused add to list for connection */
            else
            {
                globus_list_insert(&reserved_list, community->cs[i]);
                globus_list_insert(&reserved_ndx, (void *) i);
            }
        }

        /* get all of the unused hosts that may not have been cached */
        while(handle_count > 0 && !globus_list_empty(reserved_list))
        {
            tmp_si.host_id = (char *) 
                globus_list_remove(&reserved_list, reserved_list);
            tmp_ndx = (int) globus_list_remove(&reserved_ndx, reserved_ndx);
            res = globus_l_gfs_ipc_handle_connect(
                &tmp_si,
                iface,
                community,
                tmp_ndx,
                cb,
                user_arg,
                error_cb,
                error_user_arg);
            if(res != GLOBUS_SUCCESS)
            {
                goto open_error;
            }
            handle_count--;
        }

        /* if handle count is still not statisfied repeat walking the list
           picking then up in order */
        i = 0;
        while(handle_count > 0)
        {
            tmp_si.host_id = community->cs[i];
            ipc = globus_l_gfs_ipc_handle_lookup(&tmp_ci);
            if(ipc == NULL)
            {
                res = globus_l_gfs_ipc_handle_connect(
                    &tmp_si,
                    iface,
                    community,
                    i,
                    cb,
                    user_arg,
                    error_cb,
                    error_user_arg);
                if(res != GLOBUS_SUCCESS)
                {
                    goto open_error;
                }
            }
            else
            {
                ipc->state = GLOBUS_GFS_IPC_STATE_GETTING;
                ipc->open_cb = cb;
                ipc->user_arg = user_arg;
                ipc->error_cb = error_cb;
                ipc->error_arg = error_user_arg;
                globus_l_gfs_session_info_free(ipc->session_info);
                ipc->session_info =
                    globus_l_gfs_ipc_session_info_copy(&tmp_si);
                globus_xio_handle_cancel_operations(
                    ipc->xio_handle, GLOBUS_XIO_CANCEL_READ);
            }
            handle_count--;

            i++;
            if(i == community->cs_count)
            {
                i = 0;
            }
        }
        globus_list_free(reserved_list);
        globus_list_free(reserved_ndx);
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

open_error:
    *p_handle_count = *p_handle_count - handle_count;
community_error:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

/*
 *  put ipc handle back into cache
 */
globus_result_t
globus_gfs_ipc_handle_release(
    globus_gfs_ipc_handle_t             ipc_handle)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       msg_size;
    globus_result_t                     result;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    GlobusGFSName(globus_gfs_ipc_handle_release);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            result = GlobusGFSErrorParameter("ipc_handle");
            goto err;
        }

        ipc->error_cb = NULL;
        ipc->state = GLOBUS_GFS_IPC_STATE_STOPPING;
        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            if(buffer == NULL)
            {
                goto err;
            }
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_SESSION_STOP);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            result = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_stop_write_cb,
                ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto xio_error;
            }
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

xio_error:
    globus_free(buffer);
err:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExitWithError();
    return result;
}

globus_result_t
globus_gfs_ipc_handle_get_contact_string(
    globus_gfs_ipc_handle_t             ipc_handle,
    char **                             contact_string)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_handle_get_contact_string);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    *contact_string = globus_libc_strdup(ipc->connection_info.host_id);
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gfs_ipc_handle_get_index(
    globus_gfs_ipc_handle_t             ipc_handle,
    int *                               index)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_handle_get_index);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    *index = ipc->connection_info.community_ndx;
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
}


/*
 *  close a handle, stopping it from being further cached
 */
static
void
globus_l_gfs_ipc_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_close_cb);
    GlobusGFSDebugEnter();
                                                                                
    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;
                                                                                
    if(ipc->close_cb)
    {
        ipc->close_cb(ipc, ipc->cached_res, ipc->error_arg);
    }
                                                                                
    globus_l_gfs_ipc_handle_destroy(ipc);

    GlobusGFSDebugExit();
}

globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_close_callback_t     cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_close);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&ipc_handle->mutex);
    {
        switch(ipc_handle->state)
        {
            case GLOBUS_GFS_IPC_STATE_SERVER_OPENING:
            case GLOBUS_GFS_IPC_STATE_CLIENT_OPENING:
            case GLOBUS_GFS_IPC_STATE_OPEN:
            case GLOBUS_GFS_IPC_STATE_GETTING:
            case GLOBUS_GFS_IPC_STATE_IN_USE:
                ipc_handle->close_cb = cb;
                ipc_handle->state = GLOBUS_GFS_IPC_STATE_CLOSING;
                ipc_handle->error_cb = NULL;
                res = globus_xio_register_close(
                    ipc_handle->xio_handle,
                    NULL,
                    globus_l_gfs_ipc_close_cb,
                    ipc_handle);
                break;
                                                                                
            default:
                res = GlobusGFSErrorParameter("ipc_handle");
                break;
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);
                                                                                
    GlobusGFSDebugExit();
    return res;
}

/*************************************************************************
 *   inbound messages
 *   ----------------
 ************************************************************************/
/* 
 *  unpack
 */
static 
globus_gfs_finished_info_t *
globus_l_gfs_ipc_unpack_reply(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    int                                 ctr;
    char                                ch;
    char *                              str;
    globus_gfs_finished_info_t *            reply;
    GlobusGFSName(globus_l_gfs_ipc_unpack_reply);
    GlobusGFSDebugEnter();

    reply = (globus_gfs_finished_info_t *)
        globus_calloc(1, sizeof(globus_gfs_finished_info_t));
    if(reply == NULL)
    {
        goto error;
    }

    /* pack the body--this part is like a reply header */
    GFSDecodeChar(buffer, len, reply->type);
    GFSDecodeUInt32(buffer, len, reply->code);
    GFSDecodeUInt32(buffer, len, reply->result);
    GFSDecodeString(buffer, len, reply->msg);
    if(reply->result != GLOBUS_SUCCESS)
    {
        if(reply->msg != NULL)
        {
            reply->result = GlobusGFSErrorGeneric(reply->msg);
            globus_free(reply->msg);
            reply->msg = NULL;
        }
        else    
        {
            reply->result = GlobusGFSErrorGeneric("unknown error");
        }
    }

    /* encode the specific types */
    switch(reply->type)
    {
        case GLOBUS_GFS_OP_RECV:
            break;

        case GLOBUS_GFS_OP_SEND:
            break;

        case GLOBUS_GFS_OP_LIST:
            break;

        case GLOBUS_GFS_OP_SESSION_START:
            break;

        case GLOBUS_GFS_OP_STAT:
            GFSDecodeUInt32(buffer, len, reply->info.stat.stat_count);
            if(reply->info.stat.stat_count > 0)
            {
                reply->info.stat.stat_array = (globus_gfs_stat_t *)
                    globus_calloc(1, 
                    sizeof(globus_gfs_stat_t) * reply->info.stat.stat_count);
                if(reply->info.stat.stat_array == NULL)
                {
                    goto decode_err;
                }
                for(ctr = 0; ctr < reply->info.stat.stat_count; ctr++)
                {
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].mode);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].nlink);
                    GFSDecodeString(buffer, len, str);
                    if(str != NULL)
                    {
                        reply->info.stat.stat_array[ctr].name = str;
                    }
                    GFSDecodeString(buffer, len, str);
                    if(str != NULL)
                    {
                        reply->info.stat.stat_array[ctr].symlink_target = str;
                    }
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].uid);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].gid);
                    GFSDecodeUInt64(
                        buffer, len, reply->info.stat.stat_array[ctr].size);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].atime);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].ctime);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].mtime);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].dev);
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.stat_array[ctr].ino);
                }
            }
            else
            {
                reply->info.stat.stat_array = NULL;
            }
            GFSDecodeUInt32(buffer, len, reply->info.stat.uid);
            GFSDecodeUInt32(buffer, len, reply->info.stat.gid_count);
            if(reply->info.stat.gid_count > 0)
            {
                reply->info.stat.gid_array = (int *) globus_malloc(
                    reply->info.stat.gid_count * sizeof(int));
                for(ctr = 0; ctr < reply->info.stat.gid_count; ctr++)
                {
                    GFSDecodeUInt32(
                        buffer, len, reply->info.stat.gid_array[ctr]);
                }                        
            }
            else
            {
                reply->info.stat.gid_array = NULL;
            }
            break;

        case GLOBUS_GFS_OP_COMMAND:
            GFSDecodeChar(
                buffer, len, reply->info.command.command);
            GFSDecodeString(
                buffer, len, reply->info.command.checksum);
            GFSDecodeString(
                buffer, len, reply->info.command.created_dir);
            break;

        case GLOBUS_GFS_OP_PASSIVE:
            GFSDecodeUInt32P(
                buffer, len, reply->info.data.data_arg);
            GFSDecodeUInt32(
                buffer, len, reply->info.data.cs_count);
            if(reply->info.data.cs_count > 0)
            {
                reply->info.data.contact_strings = (const char **)
                    globus_malloc(sizeof(char *) * reply->info.data.cs_count);
                for(ctr = 0; ctr < reply->info.data.cs_count; ctr++)
                {
                    char *                  tmp_cs;
                    GFSDecodeString(buffer, len, tmp_cs);
                    reply->info.data.contact_strings[ctr] = tmp_cs;
                }
            }
            else
            {
                reply->info.data.contact_strings = NULL;
            }
            GFSDecodeChar(buffer, len, ch);
            reply->info.data.ipv6 = (int)ch;
            GFSDecodeChar(buffer, len, ch);
            reply->info.data.bi_directional = (int)ch;
            break;

        case GLOBUS_GFS_OP_ACTIVE:
            GFSDecodeUInt32P(
                buffer, len, reply->info.data.data_arg);
            GFSDecodeChar(buffer, len, ch);
            reply->info.data.bi_directional = (int)ch;
            break;

        case GLOBUS_GFS_OP_DESTROY:
            break;

        default:
            break;
    }

    GlobusGFSDebugExit();
    return reply;

  decode_err:
    if(reply != NULL)
    {
        if(reply->info.stat.stat_array != NULL)
        {
            globus_free(reply->info.stat.stat_array);
        }
        if(reply->info.stat.gid_array != NULL)
        {
            globus_free(reply->info.stat.gid_array);
        }
        globus_free(reply);
    }
error:                                                                                
    GlobusGFSDebugExitWithError();
    return NULL;
}

static 
globus_gfs_event_info_t *
globus_l_gfs_ipc_unpack_event_reply(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    int                                 ctr;
    int                                 range_size;
    globus_gfs_event_info_t *      reply;
    globus_off_t                        offset;
    globus_off_t                        length;
    GlobusGFSName(globus_l_gfs_ipc_unpack_event_reply);
    GlobusGFSDebugEnter();
    
    reply = (globus_gfs_event_info_t *)
        globus_calloc(1, sizeof(globus_gfs_event_info_t));
    if(reply == NULL)
    {
        goto error;
    }

    GFSDecodeUInt32(buffer, len, reply->type);
    GFSDecodeUInt32(buffer, len, reply->node_ndx);

    /* encode the specific types */
    switch(reply->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            GFSDecodeUInt32P(buffer, len, reply->event_arg);
            GFSDecodeUInt32(buffer, len, reply->event_mask);
            break;
            
        case GLOBUS_GFS_EVENT_DISCONNECTED:
            GFSDecodeUInt32P(buffer, len, reply->data_arg);
            break;
            
        case GLOBUS_GFS_EVENT_BYTES_RECVD:
            GFSDecodeUInt64(buffer, len, reply->recvd_bytes);
            break;
            
        case GLOBUS_GFS_EVENT_RANGES_RECVD:
            globus_range_list_init(&reply->recvd_ranges);
            GFSDecodeUInt32(buffer, len, range_size);
            for(ctr = 0; ctr < range_size; ctr++)
            {
                GFSDecodeUInt64(buffer, len, offset);
                GFSDecodeUInt64(buffer, len, length);
                globus_range_list_insert(reply->recvd_ranges, offset, length);
            }
            break;
            
        case GLOBUS_GFS_EVENT_PARTIAL_EOF_COUNT:
            GFSDecodeUInt32(buffer, len, reply->node_count);
            reply->eof_count = (int *) 
                globus_calloc(1, sizeof(int) * (reply->node_count + 1));
            for(ctr = 0; ctr < reply->node_count; ctr++)
            {
                GFSDecodeUInt32(buffer, len, reply->eof_count[ctr]);
            }
            break;
        default:
            break;
    }

    GlobusGFSDebugExit();
    return reply;

decode_err:  /* label used in macros */
    if(reply != NULL)
    {
        globus_free(reply);
    }
error:                                                                                
    GlobusGFSDebugExitWithError();
    return NULL;
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
static
globus_gfs_command_info_t *
globus_l_gfs_ipc_unpack_command(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_command_info_t *        cmd_info;
    GlobusGFSName(globus_l_gfs_ipc_unpack_command);
    GlobusGFSDebugEnter();

    cmd_info = (globus_gfs_command_info_t *)
        globus_malloc(sizeof(globus_gfs_command_info_t));
    if(cmd_info == NULL)
    {
        goto error;
    }

    GFSDecodeUInt32(buffer, len, cmd_info->command);
    GFSDecodeString(buffer, len, cmd_info->pathname);
    GFSDecodeUInt64(buffer, len, cmd_info->cksm_offset);
    GFSDecodeUInt64(buffer, len, cmd_info->cksm_length);
    GFSDecodeString(buffer, len, cmd_info->cksm_alg);
    GFSDecodeUInt32(buffer, len, cmd_info->chmod_mode);
    GFSDecodeString(buffer, len, cmd_info->rnfr_pathname);

    GlobusGFSDebugExit();
    return cmd_info;

decode_err:
    globus_free(cmd_info);
error:
    GlobusGFSDebugExitWithError();
    return NULL;
}

static
globus_gfs_transfer_info_t *
globus_l_gfs_ipc_unpack_transfer(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_transfer_info_t *        trans_info;
    int                                 ctr;
    int                                 range_size;
    globus_off_t                        offset;
    globus_off_t                        length;
    char                                ch;
    GlobusGFSName(globus_l_gfs_ipc_unpack_transfer);
    GlobusGFSDebugEnter();

    trans_info = (globus_gfs_transfer_info_t *)
        globus_malloc(sizeof(globus_gfs_transfer_info_t));
    if(trans_info == NULL)
    {
        goto error;
    }
    globus_range_list_init(&trans_info->range_list);

    GFSDecodeString(buffer, len, trans_info->pathname);
    GFSDecodeString(buffer, len, trans_info->module_name);
    GFSDecodeString(buffer, len, trans_info->module_args);
    GFSDecodeString(buffer, len, trans_info->list_type);    
    GFSDecodeUInt64(buffer, len, trans_info->partial_offset);
    GFSDecodeUInt64(buffer, len, trans_info->partial_length);
    GFSDecodeUInt64(buffer, len, trans_info->alloc_size);
    GFSDecodeUInt32P(buffer, len, trans_info->data_arg);
    GFSDecodeUInt32(buffer, len, trans_info->eof_count);
    GFSDecodeUInt32(buffer, len, trans_info->stripe_count);
    GFSDecodeUInt32(buffer, len, trans_info->node_count);
    GFSDecodeUInt32(buffer, len, trans_info->node_ndx);
    GFSDecodeChar(buffer, len, ch);
    trans_info->truncate = (globus_bool_t) ch;

    /* unpack range list */
    GFSDecodeUInt32(buffer, len, range_size);
    for(ctr = 0; ctr < range_size; ctr++)
    {
        GFSDecodeUInt64(buffer, len, offset);
        GFSDecodeUInt64(buffer, len, length);
        globus_range_list_insert(trans_info->range_list, offset, length);
    }

    /* unpack op */

    GlobusGFSDebugExit();
    return trans_info;

decode_err:
    globus_range_list_destroy(trans_info->range_list);
    globus_free(trans_info);
error:
    GlobusGFSDebugExitWithError();
    return NULL;
}

static globus_gfs_data_info_t *
globus_l_gfs_ipc_unpack_data(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_data_info_t *            data_info;
    char                                ch;
    int                                 ctr;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_ipc_unpack_data);
    GlobusGFSDebugEnter();

    data_info = (globus_gfs_data_info_t *)
        globus_malloc(sizeof(globus_gfs_data_info_t));
    if(data_info == NULL)
    {
        goto error;
    }
    
    GFSDecodeChar(buffer, len, ch);
    data_info->ipv6 = (globus_bool_t) ch;
    GFSDecodeUInt32(buffer, len, data_info->nstreams);
    GFSDecodeChar(buffer, len, data_info->mode);
    GFSDecodeChar(buffer, len, data_info->type);
    GFSDecodeUInt32(buffer, len, data_info->tcp_bufsize);
    GFSDecodeUInt32(buffer, len, data_info->blocksize);
    GFSDecodeUInt32(buffer, len, data_info->stripe_blocksize);
    GFSDecodeUInt32(buffer, len, data_info->stripe_layout);
    GFSDecodeChar(buffer, len, data_info->prot);
    GFSDecodeChar(buffer, len, data_info->dcau);
    GFSDecodeString(buffer, len, data_info->subject);
    GFSDecodeUInt32(buffer, len, data_info->max_cs);

    GFSDecodeUInt32(buffer, len, data_info->cs_count);
    if(data_info->cs_count > 0)
    {
        data_info->contact_strings = (const char **) 
            globus_malloc(sizeof(char *) * data_info->cs_count);
        for(ctr = 0; ctr < data_info->cs_count; ctr++)
        {
            char *                          tmp_cs;
            GFSDecodeString(buffer, len, tmp_cs);
            data_info->contact_strings[ctr] = tmp_cs;
        }
    }
    else
    {
        data_info->contact_strings = NULL;
    }
    GFSDecodeString(buffer, len, data_info->pathname);
    GFSDecodeString(buffer, len, data_info->interface);
    rc = globus_l_gfs_ipc_unpack_cred(
        ipc, buffer, len, &data_info->del_cred);
    if(rc != 0)
    {
        goto decode_err;
    }
    
    GlobusGFSDebugExit();
    return data_info;

decode_err:
    globus_free(data_info);
error:
    GlobusGFSDebugExitWithError();
    return NULL;
}

static globus_gfs_stat_info_t *
globus_l_gfs_ipc_unpack_stat(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_gfs_stat_info_t *            stat_info;
    char                                ch;
    GlobusGFSName(globus_l_gfs_ipc_unpack_stat);
    GlobusGFSDebugEnter();

    stat_info = (globus_gfs_stat_info_t *)
        globus_malloc(sizeof(globus_gfs_stat_info_t));
    if(stat_info == NULL)
    {
        goto error;
    }

    GFSDecodeChar(buffer, len, ch);
    stat_info->file_only = (globus_bool_t) ch;
    GFSDecodeChar(buffer, len, ch);
    stat_info->internal = (globus_bool_t) ch;
    GFSDecodeString(buffer, len, stat_info->pathname);

    GlobusGFSDebugExit();
    return stat_info;

decode_err:
    globus_free(stat_info);
error:
    GlobusGFSDebugExitWithError();
    return NULL;
}

static int
globus_l_gfs_ipc_unpack_data_destroy(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    void **                             data_arg)
{
    GlobusGFSName(globus_l_gfs_ipc_unpack_data_destroy);
    GlobusGFSDebugEnter();

    GFSDecodeUInt32P(buffer, len, *data_arg);
    
    GlobusGFSDebugExit();
    return 0;

  decode_err:

    GlobusGFSDebugExitWithError();
    return -1;
}


static int
globus_l_gfs_ipc_unpack_event_request(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_gfs_event_info_t **          out_event_info)
{
    globus_gfs_event_info_t *           event_info;
    int                                 ctr;
    GlobusGFSName(globus_l_gfs_ipc_unpack_event_request);
    GlobusGFSDebugEnter();
    
    event_info = (globus_gfs_event_info_t *) 
        globus_calloc(1, sizeof(globus_gfs_event_info_t));

    GFSDecodeUInt32P(buffer, len, event_info->event_arg);
    GFSDecodeUInt32(buffer, len, event_info->type);

    switch(event_info->type)
    {
        case GLOBUS_GFS_EVENT_FINAL_EOF_COUNT:
            GFSDecodeUInt32(buffer, len, event_info->node_count);
            event_info->eof_count = (int *) 
                globus_calloc(1, sizeof(int) * (event_info->node_count + 1));
            for(ctr = 0; ctr < event_info->node_count; ctr++)
            {
                GFSDecodeUInt32(buffer, len, event_info->eof_count[ctr]);
            }
            break;
            
        default:
            break;
    }
    
    *out_event_info = event_info;
    
    GlobusGFSDebugExit();
    return 0;

  decode_err:

    GlobusGFSDebugExitWithError();
    return -1;
}

static int
globus_l_gfs_ipc_unpack_user_buffer(
    globus_i_gfs_ipc_handle_t *         ipc,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    int *                               out_type,
    globus_byte_t **                    out_buf,
    globus_size_t *                     out_len)
{
    globus_size_t                       buffer_length;
    int                                 buffer_type;
    GlobusGFSName(globus_l_gfs_ipc_unpack_user_buffer);
    GlobusGFSDebugEnter();
    
    GFSDecodeUInt32(buffer, len, buffer_type);
    GFSDecodeUInt32(buffer, len, buffer_length);
    *out_buf = buffer;
    *out_len = buffer_length;
    *out_type = buffer_type;
                                                                                    
    GlobusGFSDebugExit();
    return 0;
    
  decode_err:

    GlobusGFSDebugExitWithError();
    return -1;
}

static
void
globus_l_gfs_ipc_finished_reply_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_l_gfs_ipc_finished_reply_kickout);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;

    /* call the user callback */
    if(request->cb)
    {
        request->cb(
            request->ipc,
            GLOBUS_SUCCESS,
            request->reply,
            request->user_arg);
    }
    globus_l_gfs_ipc_request_destroy(request);

    GlobusGFSDebugExit();
}

static void
globus_l_gfs_ipc_event_reply_kickout(
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_l_gfs_ipc_event_reply_kickout);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;

    /* call the user callback */
    if(request->event_cb)
    {
        request->event_cb(
            request->ipc,
            GLOBUS_SUCCESS,
            request->event_reply,
            request->user_arg);
    }

    if(request->event_reply->eof_count)
    {
        globus_free(request->event_reply->eof_count);
    }
    if(request->event_reply->type == GLOBUS_GFS_EVENT_RANGES_RECVD)
    {
        globus_range_list_destroy(request->event_reply->recvd_ranges);
    }
    globus_free(request->event_reply);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_request_read_body_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_byte_t *                     start_buf;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_finished_info_t *            reply;
    globus_gfs_event_info_t *      event_reply;
    GlobusGFSName(globus_l_gfs_ipc_request_read_body_cb);
    GlobusGFSDebugEnter();

    start_buf = buffer;
    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* parse based on type
       callout on all types excet for reply, reply needs lock */
    switch(request->type)
    {
        case GLOBUS_GFS_OP_FINAL_REPLY:
            reply = globus_l_gfs_ipc_unpack_reply(ipc, buffer, len);
            if(reply == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto error;
            }
            reply->id = request->id;
            request->reply = reply;
            globus_l_gfs_ipc_finished_reply_kickout(request);
            break;

        case GLOBUS_GFS_OP_EVENT_REPLY:
            event_reply = 
                globus_l_gfs_ipc_unpack_event_reply(ipc, buffer, len);
            if(event_reply == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto error;
            }
            event_reply->id = request->id;
            request->event_reply = event_reply;
            globus_l_gfs_ipc_event_reply_kickout(request);

            new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
            if(new_buf == NULL)
            {
                goto error;
            }
            result = globus_xio_register_read(
                ipc->xio_handle,
                new_buf,
                GFS_IPC_HEADER_SIZE,
                GFS_IPC_HEADER_SIZE,
                NULL,
                globus_l_gfs_ipc_request_read_header_cb,
                ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto mem_error;
            }
            break;

        default:
            goto error;
            break;
    }
    globus_free(start_buf);

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(new_buf);
error:
    globus_free(start_buf);
    ipc->cached_res = result;
    globus_mutex_lock(&ipc->mutex);
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);
    globus_l_gfs_ipc_request_destroy(request);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_request_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_bool_t                       rc;
    globus_gfs_ipc_request_t *          request;
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    globus_byte_t *                     new_buf = NULL;
    int                                 reply_size;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       size;
    GlobusGFSName(globus_l_gfs_ipc_request_read_header_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        size = len;
        ptr = buffer;
        GFSDecodeChar(ptr, size, type);
        GFSDecodeUInt32(ptr, size, id);
        GFSDecodeUInt32(ptr, size, reply_size);

        switch(type)
        {
            case GLOBUS_GFS_OP_FINAL_REPLY:
                request = (globus_gfs_ipc_request_t *)
                    globus_handle_table_lookup(&ipc->call_table, id);
                if(request == NULL)
                {
                    result = GlobusGFSErrorIPC();
                    goto error;
                }
                rc = globus_handle_table_decrement_reference(
                    &ipc->call_table, id);
                globus_assert(!rc);
                request->type = type;
                break;
                
            case GLOBUS_GFS_OP_EVENT_REPLY:
                request = (globus_gfs_ipc_request_t *)
                    globus_handle_table_lookup(&ipc->call_table, id);
                if(request == NULL)
                {
                    result = GlobusGFSErrorIPC();
                    goto error;
                }
                request->type = type;                
                break;

            default:
                result = GlobusGFSErrorIPC();
                goto error;
                break;
        }

        new_buf = globus_malloc(reply_size);
        if(new_buf == NULL)
        {
            result = GlobusGFSErrorMemory("new_buf");
            goto error;
        }
        result = globus_xio_register_read(
            handle,
            new_buf,
            reply_size - GFS_IPC_HEADER_SIZE,
            reply_size - GFS_IPC_HEADER_SIZE,
            NULL,
            globus_l_gfs_ipc_request_read_body_cb,
            request);
        if(result != GLOBUS_SUCCESS)
        {
            goto mem_err;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

mem_err:
    globus_free(new_buf);
decode_err:
error:
    globus_free(buffer);
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_reply_read_body_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_command_info_t *         cmd_info;
    globus_gfs_transfer_info_t *        trans_info;
    globus_gfs_data_info_t *            data_info;
    globus_gfs_stat_info_t *            stat_info;
    globus_gfs_event_info_t *           event_info;
    globus_byte_t *                     user_buffer;
    globus_size_t                       user_buffer_length;
    int                                 user_buffer_type;
    int                                 rc;
    void *                              data_arg;
    GlobusGFSName(globus_l_gfs_ipc_reply_read_body_cb);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    if(result != GLOBUS_SUCCESS)
    {
        goto err;
    }

    /* parse based on type
       callout on all types excet for reply, reply needs lock */
    switch(request->type)
    {
        case GLOBUS_GFS_OP_SESSION_START:
            result = GlobusGFSErrorIPC();
            goto err;
            break;

        case GLOBUS_GFS_OP_BUFFER_SEND:
            rc = globus_l_gfs_ipc_unpack_user_buffer(
                ipc, buffer, len, 
                &user_buffer_type, &user_buffer, &user_buffer_length);
            if(rc != 0)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            ipc->iface->buffer_send(
                ipc, ipc->user_arg,
                user_buffer, user_buffer_type, user_buffer_length);
            globus_l_gfs_ipc_request_destroy(request);
            break;

        case GLOBUS_GFS_OP_STAT:
            stat_info = globus_l_gfs_ipc_unpack_stat(
                ipc, buffer, len);
            if(stat_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = stat_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->stat_func(
                ipc, ipc->user_arg, request->id, stat_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_RECV:
            trans_info = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = trans_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->recv_func(
                ipc, 
                ipc->user_arg,
                request->id, trans_info, NULL, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_SEND:
            trans_info = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = trans_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->send_func(
                ipc, 
                ipc->user_arg,
                request->id, trans_info, NULL, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_LIST:
            trans_info = globus_l_gfs_ipc_unpack_transfer(ipc, buffer, len);
            if(trans_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = trans_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->list_func(
                ipc,
                ipc->user_arg,
                request->id, trans_info, NULL, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_COMMAND:
            cmd_info = globus_l_gfs_ipc_unpack_command(ipc, buffer, len);
            if(cmd_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = cmd_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->command_func(
                ipc, ipc->user_arg, request->id, cmd_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_PASSIVE:
            data_info = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
            if(data_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = data_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->passive_func(
                ipc, ipc->user_arg, request->id, data_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_ACTIVE:
            data_info = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
            if(data_info == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            request->info_struct = data_info;
            globus_mutex_lock(&ipc->mutex);
            {
                globus_hashtable_insert(
                    &ipc->reply_table, (void *)request->id, request);
            }
            globus_mutex_unlock(&ipc->mutex);
            ipc->iface->active_func(
                ipc, ipc->user_arg, request->id, data_info, NULL, NULL);
            break;

        case GLOBUS_GFS_OP_DESTROY:
            rc = globus_l_gfs_ipc_unpack_data_destroy(
                ipc, buffer, len, &data_arg);
            if(rc != 0)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            ipc->iface->data_destroy_func(
                ipc, ipc->user_arg, data_arg);
            globus_l_gfs_ipc_request_destroy(request);
            break;
            
        case GLOBUS_GFS_OP_EVENT:            
            rc = globus_l_gfs_ipc_unpack_event_request(
                ipc, buffer, len, &event_info);
            if(rc != 0)
            {
                result = GlobusGFSErrorIPC();
                goto err;
            }
            ipc->iface->transfer_event_func(
                ipc, ipc->user_arg, event_info);
            globus_l_gfs_ipc_request_destroy(request);

            if(event_info->eof_count)
            {
                globus_free(event_info->eof_count);
            }
            globus_free(event_info);
            break;
            
        default:
            break;
    }
    new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
    if(new_buf == NULL)
    {
        goto err;
    }
    result = globus_xio_register_read(
        ipc->xio_handle,
        new_buf,
        GFS_IPC_HEADER_SIZE,
        GFS_IPC_HEADER_SIZE,
        NULL,
        globus_l_gfs_ipc_reply_read_header_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        goto mem_error;
    }
    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(new_buf);
err:
    globus_free(buffer);
    ipc->cached_res = result;
    globus_mutex_lock(&ipc->mutex);
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);
    globus_l_gfs_ipc_request_destroy(request);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_reply_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_gfs_ipc_request_t *          request;
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    int                                 reply_size;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       size;
    globus_bool_t                       stopping = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_ipc_reply_read_header_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        size = len;
        ptr = buffer;
        GFSDecodeChar(ptr, size, type);
        GFSDecodeUInt32(ptr, size, id);
        GFSDecodeUInt32(ptr, size, reply_size);

        switch(type)
        {
            case GLOBUS_GFS_OP_EVENT:
            case GLOBUS_GFS_OP_RECV:
            case GLOBUS_GFS_OP_SEND:
            case GLOBUS_GFS_OP_LIST:
            case GLOBUS_GFS_OP_COMMAND:
            case GLOBUS_GFS_OP_PASSIVE:
            case GLOBUS_GFS_OP_ACTIVE:
            case GLOBUS_GFS_OP_DESTROY:
            case GLOBUS_GFS_OP_STAT:
            case GLOBUS_GFS_OP_BUFFER_SEND:
                request = (globus_gfs_ipc_request_t *)
                    globus_calloc(sizeof(globus_gfs_ipc_request_t), 1);
                if(request == NULL)
                {
                    result = GlobusGFSErrorMemory("request");
                    goto error;
                }
                request->type = type;
                request->ipc = ipc;
                request->id = id;

                new_buf = globus_malloc(reply_size);
                if(new_buf == NULL)
                {
                    result = GlobusGFSErrorMemory("new_buf");
                    goto error;
                }
                result = globus_xio_register_read(
                    handle,
                    new_buf,
                    reply_size - GFS_IPC_HEADER_SIZE,
                    reply_size - GFS_IPC_HEADER_SIZE,
                    NULL,
                    globus_l_gfs_ipc_reply_read_body_cb,
                    request);
                if(result != GLOBUS_SUCCESS)
                {
                    goto mem_err;
                }
                break;

            case GLOBUS_GFS_OP_SESSION_STOP:
                globus_assert(!globus_l_gfs_ipc_requester);
                ipc->state = GLOBUS_GFS_IPC_STATE_STOPPING;
                /*ipc->error_cb = NULL;*/
                stopping = GLOBUS_TRUE;
                break;

            default:
                result = GlobusGFSErrorIPC();
                goto error;
                break;
        }

    }
    globus_mutex_unlock(&ipc->mutex);

    if(stopping)
    {
        ipc->iface->session_stop_func(ipc, ipc->user_arg);
        globus_l_gfs_session_info_free(ipc->session_info);
        ipc->session_info = NULL;
        globus_mutex_lock(&ipc->mutex);
        {
            switch(ipc->state)
            {
                /* this is the normal case */
                case GLOBUS_GFS_IPC_STATE_STOPPING:
                    new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
                    if(new_buf == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto error;
                    }
                    result = globus_xio_register_read(
                        handle,
                        new_buf,
                        GFS_IPC_HEADER_SIZE,
                        GFS_IPC_HEADER_SIZE,
                        NULL,
                        globus_l_gfs_ipc_ss_header_cb,
                        ipc);
                    if(result != GLOBUS_SUCCESS)
                    {
                        goto mem_err;
                    }
                    ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
                    break;

                default:
                    globus_assert(0 && "memory corruption");
                    break;
            }
        }
        globus_mutex_unlock(&ipc->mutex);
    }

    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

mem_err:
    globus_free(new_buf);
decode_err:
error:
    globus_free(buffer);
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}
/*************************************************************************
 *   inbound messages
 *   ----------------
 ************************************************************************/

/*
 *  Initialize this module of server
 */
globus_result_t
globus_gfs_ipc_init(
    globus_bool_t                       requester,
    char **                             in_out_listener)
{
    globus_list_t *                     community_list;
    globus_list_t *                     list;
    globus_result_t                     res;
    int                                 sc;
    int                                 port;
    globus_xio_attr_t                   attr;
    char *                              listener = NULL;
    GlobusGFSName(globus_gfs_ipc_init);
    GlobusGFSDebugEnter();

    if(in_out_listener != NULL)
    {
        listener = *in_out_listener;
    }

    res = globus_xio_driver_load("tcp", &globus_l_gfs_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto tcp_load_error;
    }
    res = globus_xio_driver_load("queue", &globus_l_gfs_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto queue_load_error;
    }
    
    res = globus_xio_stack_init(&globus_l_gfs_ipc_xio_stack, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto stack_init_error;
    }
    res = globus_xio_stack_push_driver(
        globus_l_gfs_ipc_xio_stack, globus_l_gfs_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto stack_push_error;
    }
    if(globus_i_gfs_config_bool("secure_ipc"))
    {
        res = globus_xio_driver_load("gsi", &globus_l_gfs_gsi_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto gsi_load_error;
        }

        res = globus_xio_stack_push_driver(
            globus_l_gfs_ipc_xio_stack, globus_l_gfs_gsi_driver);
        if(res != GLOBUS_SUCCESS)
        {
            globus_xio_driver_unload(globus_l_gfs_gsi_driver);
            goto stack_push_error;
        }
    }
    res = globus_xio_stack_push_driver(
        globus_l_gfs_ipc_xio_stack, globus_l_gfs_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto stack_push_error;
    }

    community_list = globus_i_gfs_config_list("community");

    globus_assert(!globus_list_empty(community_list) && 
        "i said it wouldnt be empty");

    globus_l_gfs_ipc_community_default = 
        (globus_i_gfs_community_t *) globus_list_first(community_list);

    list = globus_list_rest(community_list);
    if(list != NULL)
    {
        globus_l_gfs_ipc_community_list = 
            globus_list_copy(list);
    }
    else
    {
        globus_l_gfs_ipc_community_list = NULL;
    }

    globus_hashtable_init(
        &globus_l_ipc_handle_table,
        64,
        globus_l_gfs_ipc_hashtable_session_hash,
        globus_l_gfs_ipc_hashtable_session_keyeq);

    globus_hashtable_init(
        &globus_l_ipc_request_table,
        64,
        globus_l_gfs_ipc_hashtable_session_hash,
        globus_l_gfs_ipc_hashtable_session_keyeq);

    globus_mutex_init(&globus_l_ipc_mutex, NULL); 

    globus_l_gfs_ipc_requester = requester;

    if(listener != NULL)
    {
        sc = sscanf(listener, "%d", &port);
        if(sc != 1)
        {
            goto port_scan_error;
        }

        res = globus_xio_attr_init(&attr);
        if(res != GLOBUS_SUCCESS)
        {
            goto attr_init_error;
        }

        res = globus_xio_attr_cntl(
            attr,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_SET_PORT,
            port);
        if(res != GLOBUS_SUCCESS)
        {
            goto attr_error;
        }
        res = globus_xio_server_create(
            &globus_l_gfs_ipc_server_handle, attr, globus_l_gfs_ipc_xio_stack);
        if(res != GLOBUS_SUCCESS)
        {
            goto attr_error;
        }

        res = globus_xio_server_cntl(
            globus_l_gfs_ipc_server_handle,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
            in_out_listener);
        if(res != GLOBUS_SUCCESS)
        {
            goto server_error;
        }
        res = globus_xio_server_register_accept(
            globus_l_gfs_ipc_server_handle,
            globus_l_gfs_ipc_add_server_accept_cb,
            NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto accept_error;
        }
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

accept_error:
server_error:
    globus_xio_server_close(globus_l_gfs_ipc_server_handle);
attr_error:
    globus_xio_attr_destroy(attr);
attr_init_error:
port_scan_error:
stack_push_error:
    globus_xio_stack_destroy(globus_l_gfs_ipc_xio_stack);
stack_init_error:
gsi_load_error:
    globus_xio_driver_unload(globus_l_gfs_queue_driver);
queue_load_error:
    globus_xio_driver_unload(globus_l_gfs_tcp_driver);
tcp_load_error:

    GlobusGFSDebugExitWithError();
    return res;
}

void
globus_gfs_ipc_destroy()
{
    GlobusGFSName(globus_gfs_ipc_destroy);
    GlobusGFSDebugEnter();

    globus_hashtable_destroy(&globus_l_ipc_handle_table);
    globus_mutex_destroy(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
}

/*************************************************************************
 *   community stuff
 *   ---------------
 ************************************************************************/
static
globus_i_gfs_community_t *
globus_l_gfs_ipc_find_community(
    const char *                        path)
{
    int                                 root_len;
    int                                 last_len = 0;
    globus_list_t *                     list;
    globus_i_gfs_community_t *          community;
    globus_i_gfs_community_t *          found;
    GlobusGFSName(globus_l_gfs_ipc_find_community);
    GlobusGFSDebugEnter();

    found = globus_l_gfs_ipc_community_default;
    if(path != NULL)
    {
        for(list = globus_l_gfs_ipc_community_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            community = (globus_i_gfs_community_t *) globus_list_first(list);
            root_len = strlen(community->root);
            /* make sure the path is shorter */
            if(root_len > last_len && strlen(path) <= root_len)
            {
                if(strncmp(path, community->root, root_len) == 0)
                {
                    found = community;
                    last_len = root_len;
                }
            }
        }
    }

    GlobusGFSDebugExit();
    return found;
}

globus_result_t
globus_gfs_ipc_handle_get_max_available_count(
    const char *                        user_id,
    const char *                        pathname,
    int *                               count)
{
    GlobusGFSName(globus_gfs_ipc_handle_get_max_available_count);
    GlobusGFSDebugEnter();

    /* ignores other communities for now */    
    *count = globus_l_gfs_ipc_community_default->cs_count;

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
}

/*
 *  only interesting if it failed
 */
static
void
globus_l_gfs_ipc_event_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_event_reply_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_free(buffer);
    if(result != GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&ipc->mutex);
        {
            globus_l_gfs_ipc_error_close(ipc);
        }
        globus_mutex_unlock(&ipc->mutex);
    }

    GlobusGFSDebugExit();
}

static void
globus_l_gfs_ipc_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_reply_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_free(buffer);
    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

error:
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply_finished(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_finished_info_t *            reply)
{
    int                                 ctr;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       msg_size;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_gfs_ipc_request_t *          request;
    char                                ch;
    globus_result_t                     res;
    char *                              tmp_msg;
    GlobusGFSName(globus_gfs_ipc_reply_finished);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc_handle->mutex);
    {
        /* if local register one shot to get out of recurisve call stack
            troubles */
        request = (globus_gfs_ipc_request_t *) 
            globus_hashtable_remove(
            &ipc->reply_table,
            (void *)reply->id);
        if(request == NULL)
        {
            goto error;
        }

        if(ipc->local)
        {
            /* XXX can't kickout here without copying the reply 
            to request->reply */
            globus_assert(0 && "read comment");
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_finished_reply_kickout,
                request);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* don't need the request anymore */
            globus_l_gfs_ipc_request_destroy(request);

            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            if(buffer == NULL)
            {
                goto error;
            }
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_FINAL_REPLY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack the body--this part is like a reply header */
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, reply->type);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->code);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->result);
            if(reply->msg == NULL && reply->result != GLOBUS_SUCCESS)
            {
                tmp_msg = globus_error_print_friendly(
                    globus_error_peek(reply->result));
                GFSEncodeString(
                    buffer, ipc->buffer_size, ptr, tmp_msg);  
                globus_free(tmp_msg);              
            }
            else
            {
                GFSEncodeString(
                    buffer, ipc->buffer_size, ptr, reply->msg);
            }


            /* encode the specific types */
            switch(reply->type)
            {
                case GLOBUS_GFS_OP_SESSION_START:
                    break;

                case GLOBUS_GFS_OP_RECV:
                    break;

                case GLOBUS_GFS_OP_SEND:
                    break;

                case GLOBUS_GFS_OP_LIST:
                    break;

                case GLOBUS_GFS_OP_STAT:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.stat.stat_count);
                    for(ctr = 0; ctr < reply->info.stat.stat_count; ctr++)
                    {
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].mode);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].nlink);
                        GFSEncodeString(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].name);
                        GFSEncodeString(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].symlink_target);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].uid);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].gid);
                        GFSEncodeUInt64(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].size);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].atime);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].ctime);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].mtime);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].dev);
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.stat.stat_array[ctr].ino);
                    }
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, 
                        ptr, reply->info.stat.uid);
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size,
                        ptr, reply->info.stat.gid_count);
                    for(ctr = 0; ctr < reply->info.stat.gid_count; ctr++)
                    {
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size,
                            ptr, reply->info.stat.gid_array[ctr]);
                    }

                    break;

                case GLOBUS_GFS_OP_COMMAND:
                    GFSEncodeChar(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.command.command);
                    GFSEncodeString(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.command.checksum);
                    GFSEncodeString(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.command.created_dir);
                    break;

                case GLOBUS_GFS_OP_PASSIVE:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.data.data_arg);
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.data.cs_count);
                    for(ctr = 0; ctr < reply->info.data.cs_count; ctr++)
                    {
                        GFSEncodeString(
                            buffer, ipc->buffer_size, ptr, 
                            reply->info.data.contact_strings[ctr]);
                    }
                    ch = (char) reply->info.data.ipv6;
                    GFSEncodeChar(buffer, ipc->buffer_size, ptr, ch);
                    ch = (char) reply->info.data.bi_directional;
                    GFSEncodeChar(buffer, ipc->buffer_size, ptr, ch);
                    break;

                case GLOBUS_GFS_OP_ACTIVE:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.data.data_arg);
                    ch = (char) reply->info.data.bi_directional;
                    GFSEncodeChar(buffer, ipc->buffer_size, ptr, ch);
                    break;

                case GLOBUS_GFS_OP_DESTROY:
                    break;

                default:
                    break;
            }

            msg_size = ptr - buffer;
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, msg_size);
            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_reply_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                goto xio_error;
            }
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

xio_error:
    globus_free(buffer);
error:
    globus_mutex_unlock(&ipc_handle->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_event_info_t *      reply)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_ipc_request_t *          request;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_result_t                     res;
    globus_off_t                        offset;
    globus_off_t                        length;
    int                                 range_size;
    int                                 ctr;
    int                                 msg_size;
    GlobusGFSName(globus_gfs_ipc_reply_event);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc_handle->mutex);
    {
        /* if local register one shot to get out of recurisve call stack
            troubles */
        if(ipc->local)
        {
            request = (globus_gfs_ipc_request_t *) 
                globus_hashtable_lookup(
                    &ipc_handle->reply_table,
                    (void *)reply->id);
            if(request == NULL)
            {
                /* 
                 *  race condition
                 */
                res = GLOBUS_SUCCESS;
                goto error;
            }
            
            request->event_reply = reply;
            request->reply = NULL;
            
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_event_reply_kickout,
                request);
        }
        /* if on wire pack up reply and send it */
        else
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            if(buffer == NULL)
            {
                goto error;
            }
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_EVENT_REPLY);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, reply->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack the body--this part is like a reply header */
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, reply->type);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, reply->node_ndx);

            /* encode the specific types */
            switch(reply->type)
            {
                case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, reply->event_arg);
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, reply->event_mask);
                    break;
                    
                case GLOBUS_GFS_EVENT_DISCONNECTED:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, reply->data_arg);
                    break;
                    
                case GLOBUS_GFS_EVENT_BYTES_RECVD:
                    GFSEncodeUInt64(
                        buffer, ipc->buffer_size, ptr, reply->recvd_bytes);
                    break;
                    
                case GLOBUS_GFS_EVENT_RANGES_RECVD:
                    range_size = globus_range_list_size(reply->recvd_ranges);
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, range_size);
                    for(ctr = 0; ctr < range_size; ctr++)
                    {
                        globus_range_list_at(
                            reply->recvd_ranges, ctr, &offset, &length);
                        GFSEncodeUInt64(
                            buffer, ipc->buffer_size, ptr, offset);
                        GFSEncodeUInt64(
                            buffer, ipc->buffer_size, ptr, length);
                    }
                    break;
                case GLOBUS_GFS_EVENT_PARTIAL_EOF_COUNT:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, reply->node_count);
                    for(ctr = 0; ctr < reply->node_count; ctr++)
                    {
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, 
                            ptr, reply->eof_count[ctr]);
                    }
                    break;
                    
                default:
                    break;
            }

            msg_size = ptr - buffer;
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, msg_size);
            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_event_reply_cb,
                ipc);
            if(res != GLOBUS_SUCCESS)
            {
                goto xio_error;
            }
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

xio_error:
    globus_free(buffer);
error:
    globus_mutex_unlock(&ipc_handle->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

/************************************************************************
 *   remote function calls
 *
 *   local: call directly to iface function
 *
 *   remote: serialize all needed information into a buffer and
 *   send it.  any number can be sent at once due to the queung 
 *   buffer.  Callback is ignored unless it fails, in which case 
 *   the user error callback is called and the user is expected to 
 *   close
 ***********************************************************************/

static
void
globus_l_gfs_ipc_stop_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_list_t *                     list;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_stop_write_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_free(buffer);

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        /* have a read pending on the cached connection so that we can catch
            errant data or disconnections.
            XXX need to change gsi driver to handle 0 byte read with a pass
            instead of a finish.  possibly figure out a different way to 
            checkup on cached connections since this won't necessisarily work
            on every driver we might want to use */
        result = globus_xio_register_read(
            ipc->xio_handle,
            &ipc->byte, /* bogus parmeter */
            1,
            1,
            NULL,
            globus_l_gfs_ipc_read_request_fault_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
        /* get the list of handles for the user, insert this one and 
            put it back in table */
        list = (globus_list_t *) globus_hashtable_remove(
            &globus_l_ipc_handle_table, &ipc->connection_info);
        globus_list_insert(&list, ipc);
        globus_hashtable_insert(
            &globus_l_ipc_handle_table, &ipc->connection_info, list);
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
    return;

error:
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_no_read_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_no_read_write_cb);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    globus_free(buffer);

    if(result != GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&ipc->mutex);
        {
            ipc->cached_res = result;
            globus_l_gfs_ipc_error_close(ipc);
        }
        globus_mutex_unlock(&ipc->mutex);
    }
    else
    {
        switch(request->type)
        {
            case GLOBUS_GFS_OP_DESTROY:
            case GLOBUS_GFS_OP_EVENT:
            case GLOBUS_GFS_OP_BUFFER_SEND:
                globus_free(request);
                break;
            default:
                break;
        }
    }

    GlobusGFSDebugExit();
}

/*
 *  write callback
 */
static
void
globus_l_gfs_ipc_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     new_buf;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_write_cb);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    globus_free(buffer);

    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        /* post a read for the next request */
        new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
        if(new_buf == NULL)
        {
            goto error;
        }
        result = globus_xio_register_read(
            ipc->xio_handle,
            new_buf,
            GFS_IPC_HEADER_SIZE,
            GFS_IPC_HEADER_SIZE,
            NULL,
            globus_l_gfs_ipc_request_read_header_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            goto read_error;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

read_error:
    globus_free(new_buf);
error:
    ipc->cached_res = result;
    globus_l_gfs_ipc_error_close(ipc);
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
}

globus_result_t
globus_gfs_ipc_request_buffer_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_byte_t *                     user_buffer,
    int                                 buffer_type,
    globus_size_t                       buffer_len)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    globus_gfs_ipc_request_t *          request = NULL;
    GlobusGFSName(globus_gfs_ipc_request_buffer_send);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }
        
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            res = GlobusGFSErrorIPC();
            goto err;
        }
    
        request->ipc = ipc;
        request->type = GLOBUS_GFS_OP_BUFFER_SEND;
        request->id = -1;

        if(!ipc->local)
        {
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_BUFFER_SEND);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            /* body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, buffer_type);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, buffer_len);
            if((ptr - buffer + buffer_len) >= ipc->buffer_size)
            {
                globus_size_t           ndx;                
                ndx = ptr - buffer;
                ipc->buffer_size += buffer_len;
                buffer = globus_libc_realloc(buffer, ipc->buffer_size);
                ptr = buffer + ndx;
            }
            memcpy(ptr, user_buffer, buffer_len);            
            
            msg_size = ptr - buffer + buffer_len;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            res = globus_xio_register_write(
                ipc->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_no_read_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->buffer_send(
            ipc, ipc->user_arg, buffer, buffer_type, buffer_len);
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }

    GlobusGFSDebugExitWithError();
    return res;
}

/* pack and send function for list send and receive */
static
globus_result_t
globus_l_gfs_ipc_transfer_pack(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    globus_gfs_transfer_info_t *        trans_info,
    globus_gfs_ipc_request_t *          request)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    globus_result_t                     res;
    int                                 range_size;
    int                                 ctr;
    globus_off_t                        offset;
    globus_off_t                        length;
    GlobusGFSName(globus_l_gfs_ipc_transfer_pack);
    GlobusGFSDebugEnter();

    /* pack the header */
    buffer = globus_malloc(ipc->buffer_size);
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
    /* pack the body */
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->pathname);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->module_name);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->module_args);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, trans_info->list_type);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_info->partial_offset);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_info->partial_length);
    GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, trans_info->alloc_size);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_info->data_arg);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_info->eof_count);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_info->stripe_count);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_info->node_count);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, trans_info->node_ndx);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, trans_info->truncate);

    /* pack range list */
    range_size = globus_range_list_size(trans_info->range_list);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, range_size);
    for(ctr = 0; ctr < range_size; ctr++)
    {
        globus_range_list_at(trans_info->range_list, ctr, &offset, &length);
        GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, offset);
        GFSEncodeUInt64(buffer, ipc->buffer_size, ptr, length);
    }

    /* TODO: pack op */

    msg_size = ptr - buffer;
    /* now that we know size, add it in */
    ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

    res = globus_xio_register_write(
        ipc->xio_handle,
        buffer,
        msg_size,
        msg_size,
        NULL,
        globus_l_gfs_ipc_write_cb,
        request);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(buffer);
    }

    GlobusGFSDebugExit();
    return res;
}
/*
 *  receive
 *
 *  tell the remote process to receive a file
 */
globus_result_t
globus_gfs_ipc_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_info_t *        recv_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_recv);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_RECV;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_OP_RECV, recv_info, request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->recv_func(
            ipc_handle,
            request->user_arg, request->id, recv_info, NULL, NULL, NULL);
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

/*
 *  send
 *  
 *  tell remote process to send a file
 */
globus_result_t
globus_gfs_ipc_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_info_t *        send_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_send);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->cb = cb;
        request->event_cb = event_cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_SEND;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_OP_SEND, send_info, request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->send_func(
            ipc_handle, 
            ipc->user_arg, request->id, send_info, NULL, NULL, NULL);
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

globus_result_t
globus_gfs_ipc_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_transfer_info_t *        data_info,
    globus_gfs_ipc_callback_t           cb,
    globus_gfs_ipc_event_callback_t     event_cb,
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    GlobusGFSName(globus_gfs_ipc_request_list);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        request->cb = cb;
        request->ipc = ipc_handle;
        request->event_cb = event_cb;
        request->user_arg = user_arg;
        request->type = GLOBUS_GFS_OP_LIST;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_transfer_pack(
                ipc, GLOBUS_GFS_OP_LIST, data_info, request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->list_func(
            ipc_handle,
            ipc_handle->user_arg,
            request->id, data_info, NULL, NULL, NULL);
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}

/*
 *  command
 *
 *  tell remote side to execute the given command
 */
globus_result_t
globus_gfs_ipc_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_command_info_t *         cmd_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_size_t                       msg_size;
    globus_result_t                     result;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    GlobusGFSName(globus_gfs_ipc_request_command);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            result = GlobusGFSErrorParameter("ipc");
            goto error;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            result = GlobusGFSErrorIPC();
            goto error;
        }
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_COMMAND;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);

        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            if(buffer == NULL)
            {
                goto request_error;
            }
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_COMMAND);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, cmd_info->command);
            GFSEncodeString(buffer, ipc->buffer_size, ptr, cmd_info->pathname);
            GFSEncodeUInt64(
                buffer, ipc->buffer_size, ptr, cmd_info->cksm_offset);
            GFSEncodeUInt64(
                buffer, ipc->buffer_size, ptr, cmd_info->cksm_length);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_info->cksm_alg);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, cmd_info->chmod_mode);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, cmd_info->rnfr_pathname);

            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            result = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_write_cb,
                request);
            if(result != GLOBUS_SUCCESS)
            {
                goto xio_error;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->command_func(
            ipc, ipc->user_arg, request->id, cmd_info, NULL, NULL);
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

xio_error:
    globus_free(buffer);
request_error:
    globus_free(request);
error:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return result;
}


globus_result_t
globus_gfs_ipc_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_event_info_t *           event_info)
{
    globus_size_t                       msg_size;
    globus_result_t                     result;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_gfs_ipc_request_t *          request;
    int                                 ctr;
    GlobusGFSName(globus_gfs_ipc_request_transfer_event);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            result = GlobusGFSErrorIPC();
            goto error;
        }
    
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_EVENT;
        request->id = -1;
        
        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            if(buffer == NULL)
            {
                result = GlobusGFSErrorIPC();
                goto error;
            }
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_EVENT);
            /* no reply, no id */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1); 
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, event_info->event_arg);
            GFSEncodeUInt32(
                buffer, ipc->buffer_size, ptr, event_info->type);

            switch(event_info->type)
            {
                case GLOBUS_GFS_EVENT_FINAL_EOF_COUNT:
                    GFSEncodeUInt32(
                        buffer, ipc->buffer_size, ptr, event_info->node_count);
                    for(ctr = 0; ctr < event_info->node_count; ctr++)
                    {
                        GFSEncodeUInt32(
                            buffer, ipc->buffer_size, 
                            ptr, event_info->eof_count[ctr]);
                    }
                    break;
                
                default:
                    break;
            }
                      
            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            result = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_no_read_write_cb,
                request);
            if(result != GLOBUS_SUCCESS)
            {
                goto xio_error;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc->iface->transfer_event_func(
            ipc, ipc->user_arg, event_info);
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

xio_error:
    globus_free(buffer);
error:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return result;
}
    
     

static
globus_result_t
globus_l_gfs_ipc_pack_data(
    globus_i_gfs_ipc_handle_t *         ipc,
    char                                type,
    globus_gfs_data_info_t *            data_info,
    globus_gfs_ipc_request_t *          request)
{
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    globus_result_t                     res;
    int                                 ctr;
    OM_uint32                           maj_rc;
    OM_uint32                           min_rc;
    gss_buffer_desc                     gsi_buffer;
    globus_size_t                       ndx;
    GlobusGFSName(globus_l_gfs_ipc_pack_data);
    GlobusGFSDebugEnter();

    if(data_info->del_cred == NULL)
    {
        gsi_buffer.length = 0;
    }
    else
    {
        maj_rc = gss_export_cred(
            &min_rc, data_info->del_cred, NULL, 0, &gsi_buffer);
        if(maj_rc != GSS_S_COMPLETE)
        {
            res = GlobusGFSErrorParameter("del_cred");
            goto error;
        }
    }

    /* pack the header */
    buffer = globus_malloc(ipc->buffer_size);
    ptr = buffer;
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

    /* pack body */
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->ipv6);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->nstreams);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->mode);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->type);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, (int) data_info->tcp_bufsize);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, (int) data_info->blocksize);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, (int) data_info->stripe_blocksize);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->stripe_layout);

    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->prot);
    GFSEncodeChar(buffer, ipc->buffer_size, ptr, data_info->dcau);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, data_info->subject);
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->max_cs);

    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_info->cs_count);
    for(ctr = 0; ctr < data_info->cs_count; ctr++)
    {
        GFSEncodeString(
            buffer, ipc->buffer_size, ptr, data_info->contact_strings[ctr]);
    }
    GFSEncodeString(buffer, ipc->buffer_size, ptr, data_info->pathname);
    GFSEncodeString(buffer, ipc->buffer_size, ptr, data_info->interface);

    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, gsi_buffer.length);
    if(gsi_buffer.length > 0)
    {
        if(ptr - buffer + gsi_buffer.length >= ipc->buffer_size)
        {
            ndx = ptr - buffer;
            ipc->buffer_size += gsi_buffer.length;
            buffer = globus_libc_realloc(buffer, ipc->buffer_size);
            ptr = buffer + ndx;
        }
        memcpy(ptr, gsi_buffer.value, gsi_buffer.length);
        ptr += gsi_buffer.length;
        gss_release_buffer(&min_rc, &gsi_buffer);
    }
    msg_size = ptr - buffer;
    /* now that we know size, add it in */
    ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
    
    GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

    res = globus_xio_register_write(
        ipc->xio_handle,
        buffer,
        msg_size,
        msg_size,
        NULL,
        globus_l_gfs_ipc_write_cb,
        request);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(buffer);
        goto error;
    }

    GlobusGFSDebugExit();
    return res;

error:
    GlobusGFSDebugExitWithError();
    return res;
} 

/*
 *  active data
 *
 *  tell remote side to create an active data connection
 */
globus_result_t
globus_gfs_ipc_request_active_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_info_t *            data_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_request_active_data);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            res = GlobusGFSErrorMemory("request");
            goto err;
        }
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_ACTIVE;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);
        
        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_pack_data(
                ipc,
                GLOBUS_GFS_OP_ACTIVE,
                data_info,
                request); 
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->active_func(
            ipc_handle,
            ipc_handle->user_arg,
            request->id,
            data_info, 
            NULL, 
            NULL);
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}


/*
 *  passive data
 *
 *  tell remote side to do passive data connection
 */
globus_result_t
globus_gfs_ipc_request_passive_data(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_data_info_t *            data_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_gfs_ipc_request_passive_data);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    /* XXX parameter checlking */
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            res = GlobusGFSErrorMemory("request");
            goto err;
        }
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_PASSIVE;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);

        if(!ipc->local)
        {
            res = globus_l_gfs_ipc_pack_data(
                ipc,
                GLOBUS_GFS_OP_PASSIVE,
                data_info,
                request); 
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->passive_func(
            ipc_handle,
            ipc_handle->user_arg,
            request->id,
            data_info,
            NULL,
            NULL);
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExitWithError();
    return res;
}


/*
 *  send stat request
 */
globus_result_t
globus_gfs_ipc_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_stat_info_t *            stat_info,
    globus_gfs_ipc_callback_t           cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_request_stat);
    GlobusGFSDebugEnter();

    ipc = ipc_handle;
    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->cb = cb;
        request->user_arg = user_arg;
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_STAT;
        request->id = globus_handle_table_insert(
            &ipc_handle->call_table, request, 1);

        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_STAT);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, request->id);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, stat_info->file_only);
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, stat_info->internal);
            GFSEncodeString(
                buffer, ipc->buffer_size, ptr, stat_info->pathname);

            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->stat_func(
            ipc_handle,
            ipc_handle->user_arg,
            request->id,
            stat_info, 
            NULL, 
            NULL);
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:
    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }

    GlobusGFSDebugExitWithError();
    return res;
}


/* 
 *  tell remote side to provide list info
 */


/*
 *  destroy a data connection associated with the given ID
 */
globus_result_t
globus_gfs_ipc_request_data_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,   
    void *                              data_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_result_t                     res;
    globus_gfs_ipc_request_t *          request = NULL;
    globus_byte_t *                     buffer = NULL;
    globus_byte_t *                     ptr;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_gfs_ipc_request_data_destroy);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;

    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->state != GLOBUS_GFS_IPC_STATE_IN_USE &&
            ipc->state != GLOBUS_GFS_IPC_STATE_IN_CB)
        {
            res = GlobusGFSErrorParameter("ipc");
            goto err;
        }

        request = (globus_gfs_ipc_request_t *) 
            globus_calloc(1, sizeof(globus_gfs_ipc_request_t));
        if(request == NULL)
        {
            goto err;
        }
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_DESTROY;
        request->id = -1;

        if(!ipc->local)
        {
            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            ptr = buffer;
            GFSEncodeChar(
                buffer, ipc->buffer_size, ptr, GLOBUS_GFS_OP_DESTROY);
            /* no reply, no id */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, -1);

            /* pack body */
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, data_arg);
            
            msg_size = ptr - buffer;
            /* now that we know size, add it in */
            ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
            GFSEncodeUInt32(buffer, ipc->buffer_size, ptr, msg_size);

            res = globus_xio_register_write(
                ipc_handle->xio_handle,
                buffer,
                msg_size,
                msg_size,
                NULL,
                globus_l_gfs_ipc_no_read_write_cb,
                request);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->local)
    {
        ipc_handle->iface->data_destroy_func(
            ipc, ipc->user_arg, data_arg);
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

  err:

    globus_mutex_unlock(&ipc->mutex);
    if(buffer != NULL)
    {
        globus_free(buffer);
    }
    if(request != NULL)
    {
        globus_free(request);
    }

    GlobusGFSDebugExitWithError();
    return res;
}
