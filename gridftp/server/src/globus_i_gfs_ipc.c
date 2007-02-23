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

static const char * globus_l_gfs_local_version = "IPC Version 0.2";

/* single mutex, assuming low contention, only used for handle tables,
   not ipc communication */
static globus_mutex_t                   globus_l_ipc_mutex;
static globus_cond_t                    globus_l_ipc_cond;
static globus_hashtable_t               globus_l_ipc_request_table;

globus_xio_stack_t                      globus_i_gfs_ipc_xio_stack;
globus_xio_driver_t                     globus_i_gfs_tcp_driver = GLOBUS_NULL;

typedef enum globus_l_gfs_ipc_state_s
{
    GLOBUS_GFS_IPC_STATE_OPENING,
    GLOBUS_GFS_IPC_STATE_OPEN,
    GLOBUS_GFS_IPC_STATE_REPLY_WAIT,
    GLOBUS_GFS_IPC_STATE_ERROR,
    GLOBUS_GFS_IPC_STATE_CLOSED,

    /* requestor only */
    GLOBUS_GFS_IPC_STATE_CLOSING_ERROR,
    GLOBUS_GFS_IPC_STATE_CLOSING,

    /* reply only states */
    GLOBUS_GFS_IPC_STATE_SESSION_OPEN,
    GLOBUS_GFS_IPC_STATE_SESSION_REPLY,
    GLOBUS_GFS_IPC_STATE_SESSION_ERROR,
    GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT,
    GLOBUS_GFS_IPC_STATE_ERROR_OPENING,
    GLOBUS_GFS_IPC_STATE_ERROR_WAIT
} globus_l_gfs_ipc_state_t;

static globus_xio_driver_t              globus_l_gfs_queue_driver = GLOBUS_NULL;
static globus_xio_driver_t              globus_l_gfs_gsi_driver = GLOBUS_NULL;
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
    globus_gfs_operation_type_t         type;
    globus_gfs_operation_type_t         last_type;
    int                                 id;
    globus_gfs_ipc_callback_t           cb;
    globus_gfs_ipc_open_callback_t      open_cb;
    globus_gfs_ipc_event_callback_t     event_cb;
    void *                              user_arg;
    globus_gfs_finished_info_t *        reply;
    globus_gfs_event_info_t *           event_reply;
    void *                              info_struct;
} globus_gfs_ipc_request_t;

typedef struct globus_l_gfs_ipc_connection_s
{
    char *                              version;
    char *                              cookie;
    char *                              username;
    char *                              subject;
    char *                              host_id;
    globus_bool_t                       map_user;
} globus_l_gfs_ipc_connection_t;

typedef struct globus_i_gfs_ipc_handle_s
{
    uid_t                               uid;
    const char *                        contact_string;
    globus_xio_handle_t                 xio_handle;

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
    void *                              reply_arg;
    globus_result_t                     cached_res;
    globus_gfs_ipc_error_callback_t     error_cb;
    globus_gfs_ipc_error_callback_t     reply_error_cb;
    void *                              error_arg;
                                                                                
    globus_size_t                       buffer_size;

    char *                              hash_str;
    char *                              user_id;

    void *                              outstanding_event_arg;
    globus_bool_t                       transfer_complete;
    globus_bool_t                       close_postponed;
    globus_bool_t                       fake_abort_outstanding;

    globus_l_gfs_ipc_connection_t       connection_info;
    globus_byte_t                       byte;
    globus_i_gfs_ipc_done_callback_t    done_cb;
} globus_i_gfs_ipc_handle_t;

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
globus_result_t
globus_l_gfs_ipc_send_start_session(
    globus_i_gfs_ipc_handle_t *         ipc);

static
void
globus_l_gfs_session_info_free(
    globus_gfs_session_info_t *         session_info);

static
globus_result_t
globus_l_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_close_callback_t     cb,
    void *                              user_arg);

static
void
globus_l_gfs_ipc_error_kickout(
    void *                              user_arg);

static
void
globus_l_gfs_ipc_reply_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_l_gfs_ipc_reply_close_kickout(
    void *                              user_arg);

static
void
globus_l_gfs_ipc_reply_fake_abort(
    void *                              user_arg);
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
    tmp_str = globus_common_create_string(
        "%s%s##", hash_str, s->host_id);
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

    assert(ipc->state = GLOBUS_GFS_IPC_STATE_CLOSED);
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
            case GLOBUS_GFS_OP_EVENT_REPLY:
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

static
void
globus_l_gfs_ipc_stop_close_cb(
    globus_gfs_ipc_handle_t             ipc,
    globus_result_t                     result,
    void *                              user_arg)
{
}

void
globus_i_gfs_ipc_stop()
{
    globus_result_t                     result;
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
            if(!globus_l_gfs_ipc_requester)
            {
                globus_mutex_lock(&ipc->mutex);
                {
                    switch(ipc->state)
                    {
                        case GLOBUS_GFS_IPC_STATE_OPENING:
                            /* not sure what to do here */
                            break;

                        case GLOBUS_GFS_IPC_STATE_OPEN:
                        case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                        case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                        case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                            globus_gfs_ipc_reply_close(ipc);
                            break;

                        case GLOBUS_GFS_IPC_STATE_ERROR:
                        case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
                        case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
                        case GLOBUS_GFS_IPC_STATE_ERROR_OPENING:
                        case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                            /* error already flaged, will end soon enough */
                            break;

                        case GLOBUS_GFS_IPC_STATE_CLOSED:
                        case GLOBUS_GFS_IPC_STATE_CLOSING_ERROR:
                        case GLOBUS_GFS_IPC_STATE_CLOSING:
                            globus_assert(0 &&
                                "these states should not be possible");
                            break;
                    }
                }
                globus_mutex_unlock(&ipc->mutex);
            }
            else
            {
                globus_mutex_lock(&ipc->mutex);
                {
                    switch(ipc->state)
                    {
                        case GLOBUS_GFS_IPC_STATE_OPENING:
                        case GLOBUS_GFS_IPC_STATE_OPEN:
                        case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                        case GLOBUS_GFS_IPC_STATE_ERROR:
                            result = globus_l_gfs_ipc_close(
                                ipc, globus_l_gfs_ipc_stop_close_cb, NULL);
                            if(result != GLOBUS_SUCCESS)
                            {
                                /* XXX this isn't really list safe */
                                globus_list_remove(&globus_l_ipc_handle_list, 
                                    globus_list_search(
                                        globus_l_ipc_handle_list, ipc));
                                ipc->state = GLOBUS_GFS_IPC_STATE_CLOSED;
                                globus_l_gfs_ipc_handle_destroy(ipc);
                            }
                            break;

                        case GLOBUS_GFS_IPC_STATE_CLOSING_ERROR:
                        case GLOBUS_GFS_IPC_STATE_CLOSING:
                        case GLOBUS_GFS_IPC_STATE_CLOSED:
                            /* will be out soon enough */
                            break;

                        default:
                            globus_assert(0 && "corrupt memory");
                            break;
                    }
                }
            }
            globus_mutex_unlock(&ipc->mutex);
        }

        while(!globus_list_empty(globus_l_ipc_handle_list))
        {
            globus_cond_wait(&globus_l_ipc_cond, &globus_l_ipc_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_error_kickout(
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    ipc->error_cb(ipc, ipc->cached_res, ipc->error_arg);
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
    ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
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
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
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
        ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
        goto error;
    }
    ipc->session_info = (globus_gfs_session_info_t *) 
        globus_calloc(1, sizeof(globus_gfs_session_info_t));
    if(ipc->session_info == NULL)
    {
        ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
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
        ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
        goto decode_err;
    }
    ipc->session_info->free_cred = GLOBUS_TRUE;
        
    ipc->state = GLOBUS_GFS_IPC_STATE_SESSION_REPLY;
    ipc->error_cb = ipc->reply_error_cb;
    if(ipc->iface->session_start_func)
    {
        ipc->iface->session_start_func(
            ipc, NULL, ipc->session_info, NULL, NULL);
    }

    /* at this point we can start getting ipc_close calls */
    globus_free(start_buf);
    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                /* if the reply is sent after this callback returns */
                ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                /* this is the normal case, since we are back from the 
                    session_start just move to the open track */
                ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
                /* if an error occurs before we get back here and before
                    the reply is sent */
                result = ipc->cached_res;
                ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
                goto error_lock;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
                /* if an error occurs before we get back here and before
                    the reply is sent */
                ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                break;

            default:
                globus_assert(0 && "possible bad mem");
                break;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

error_lock:
    globus_mutex_unlock(&ipc->mutex);
decode_err:
error:
    ipc->cached_res = result;
    result = globus_xio_register_close(
        ipc->xio_handle,
        NULL,
        globus_l_gfs_ipc_reply_close_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "a close failed, can lead to a barrier race", result);
        globus_l_gfs_ipc_reply_close_kickout(ipc);
    }

    globus_free(start_buf);

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_request_ss_header_cb(
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
    GlobusGFSName(globus_l_gfs_ipc_request_ss_header_cb);
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
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->open_cb)
    {
        ipc->open_cb(ipc, result, NULL, ipc->user_arg);
    }

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_reply_ss_header_cb(
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
    GlobusGFSName(globus_l_gfs_ipc_reply_ss_header_cb);
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

    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
    ipc->cached_res = result;
    result = globus_xio_register_close(
        ipc->xio_handle,
        NULL,
        globus_l_gfs_ipc_reply_close_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "a close failed, can lead to a barrier race", result);
        globus_l_gfs_ipc_reply_close_kickout(ipc);
    }
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
            globus_l_gfs_ipc_request_ss_header_cb,
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
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->open_cb)
    {
        ipc->open_cb(ipc, result, NULL, ipc->user_arg);
    }

    GlobusGFSDebugExitWithError();
}


static
globus_result_t
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
            res = GlobusGFSErrorGeneric("failed to export cred");
            goto error;
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
    return GLOBUS_SUCCESS;

error:
    globus_free(buffer);
alloc_error:

    GlobusGFSDebugExitWithError();
    return res;
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
    GlobusGFSName(globus_l_gfs_ipc_read_new_body_cb);
    GlobusGFSDebugEnter();

    globus_assert(!globus_l_gfs_ipc_requester);

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        ipc->cached_res = result;
        goto error;
    }
    size = len;
    ptr = in_buffer;

    GFSDecodeString(ptr, size, ipc->connection_info.version);
    GFSDecodeString(ptr, size, ipc->connection_info.cookie);
    GFSDecodeString(ptr, size, ipc->connection_info.subject);
    GFSDecodeString(ptr, size, ipc->connection_info.username);
    GFSDecodeString(ptr, size, ipc->connection_info.host_id);
    GFSDecodeUInt32(ptr, size, ipc->connection_info.map_user);

    if(strcmp(ipc->connection_info.version, globus_l_gfs_local_version) != 0)
    {
        goto error;
    }

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
        globus_l_gfs_ipc_reply_ss_header_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_io;
    }

    globus_free(in_buffer);

    GlobusGFSDebugExit();
    return;

error_io:
    globus_free(new_buf);
decode_err:
error:
    globus_free(in_buffer);
    ipc->cached_res = result;
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
    result = globus_xio_register_close(
        ipc->xio_handle,
        NULL,
        globus_l_gfs_ipc_reply_close_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "a close failed, can lead to a barrier race", result);
        globus_l_gfs_ipc_reply_close_kickout(ipc);
    }

    GlobusGFSDebugExitWithError();
}

globus_result_t
globus_gfs_ipc_reply_session(
    globus_gfs_ipc_handle_t             ipc,
    globus_gfs_finished_info_t *        reply)
{
    int                                 error_state;
    globus_byte_t *                     new_buf;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    int                                 msg_size;
    globus_bool_t                       send_reply = GLOBUS_FALSE;
    globus_result_t                     res;
    char *                              tmp_msg;
    GlobusGFSName(globus_gfs_ipc_reply_session);
    GlobusGFSDebugEnter();

    globus_assert(!globus_l_gfs_ipc_requester);

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                ipc->state = GLOBUS_GFS_IPC_STATE_SESSION_OPEN;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                send_reply = GLOBUS_TRUE;
                break;

            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                send_reply = GLOBUS_TRUE;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
                ipc->state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                goto error;
                break;

            default:
                globus_assert(0 && "memory corruption?");
                break;
        }

        if(send_reply)
        {
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
                globus_free(buffer);
                goto error;
            }
            new_buf = globus_malloc(GFS_IPC_HEADER_SIZE);
            if(new_buf == NULL)
            {
                res = GlobusGFSErrorMemory("new_buf");
                goto error;
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
                goto error_mem;
            }
            ipc->reply_arg = reply->info.session.session_arg;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
error_mem:
    globus_free(new_buf);
error:
    ipc->state = error_state;
    ipc->cached_res = res;
    globus_mutex_unlock(&ipc->mutex);
    if(error_state == GLOBUS_GFS_IPC_STATE_ERROR)
    {
        res = globus_xio_register_close(
            ipc->xio_handle,
            NULL,
            globus_l_gfs_ipc_reply_close_cb,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", res);
            globus_l_gfs_ipc_reply_close_kickout(ipc);
        }
    }

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
        goto err;
    }

    size = len;
    ptr = buffer;
    GFSDecodeChar(ptr, size, type);
    GFSDecodeUInt32(ptr, size, id);
    GFSDecodeUInt32(ptr, size, reply_size);

    if(type != GLOBUS_GFS_OP_HANDSHAKE)
    {
        res = GlobusGFSErrorMemory("type not handshake");
        goto err;
    }

    new_buf = globus_malloc(reply_size);
    if(new_buf == NULL)
    {
        res = GlobusGFSErrorMemory("new_buf");
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
        goto mem_err;
    }
    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

mem_err:
decode_err:
err:
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
    ipc->cached_res = result;
    result = globus_xio_register_close(
        ipc->xio_handle,
        NULL,
        globus_l_gfs_ipc_reply_close_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "a close failed, can lead to a barrier race", result);
        globus_l_gfs_ipc_reply_close_kickout(ipc);
    }

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
        goto mem_error;
    }

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(buffer);
error:
    ipc->cached_res = result;
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR_OPENING;
    result = globus_xio_register_close(
        ipc->xio_handle,
        NULL,
        globus_l_gfs_ipc_reply_close_cb,
        ipc);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "a close failed, can lead to a barrier race", result);
        globus_l_gfs_ipc_reply_close_kickout(ipc);
    }

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_ipc_reply_close_kickout(
    void *                              user_arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_bool_t                       call_stop = GLOBUS_FALSE;
    globus_bool_t                       call_done = GLOBUS_FALSE;
    globus_bool_t                       transfer_complete = GLOBUS_TRUE;
    globus_gfs_event_info_t             event_info;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&ipc->mutex);
    {
        if(ipc->fake_abort_outstanding)
        {
            ipc->close_postponed = GLOBUS_TRUE;
        }
        else
        {
            switch(ipc->state)
            {
                case GLOBUS_GFS_IPC_STATE_ERROR_OPENING:
                    call_done = GLOBUS_TRUE;
                    break;

                case GLOBUS_GFS_IPC_STATE_ERROR:
                    call_done = GLOBUS_TRUE;
                    call_stop = GLOBUS_TRUE;
                    transfer_complete = ipc->transfer_complete;
                    break;

                default:
                    globus_assert(0 && "not propa state");
                    break;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    if(!transfer_complete)
    {
        memset(&event_info, '\0', sizeof(globus_gfs_event_info_t));
        event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
        event_info.event_arg = ipc->outstanding_event_arg;
        ipc->iface->transfer_event_func(ipc, ipc->reply_arg, &event_info);
    }
    if(call_stop && ipc->iface->session_stop_func)
    {
        ipc->iface->session_stop_func(ipc, ipc->reply_arg);
    }
    if(call_done)
    {
        globus_mutex_lock(&globus_l_ipc_mutex);
        {
            globus_list_remove(&globus_l_ipc_handle_list,
                globus_list_search(globus_l_ipc_handle_list, ipc));
            globus_cond_signal(&globus_l_ipc_cond);
        }
        globus_mutex_unlock(&globus_l_ipc_mutex);

        if(ipc->done_cb)
        {
            ipc->done_cb(ipc->user_arg, ipc->cached_res);
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_CLOSED;
        globus_l_gfs_ipc_handle_destroy(ipc);
    }
}

static
void
globus_l_gfs_ipc_reply_fake_abort(
    void *                              user_arg)
{
    globus_bool_t                       call_stop = GLOBUS_FALSE;
    globus_bool_t                       call_done = GLOBUS_FALSE;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_event_info_t             event_info;

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    memset(&event_info, '\0', sizeof(globus_gfs_event_info_t));
    event_info.type = GLOBUS_GFS_EVENT_TRANSFER_ABORT;
    event_info.event_arg = ipc->outstanding_event_arg;

    if(ipc->iface->transfer_event_func != NULL)
    {
        ipc->iface->transfer_event_func(ipc, ipc->reply_arg, &event_info);
    }
    globus_mutex_lock(&ipc->mutex);
    {
        ipc->fake_abort_outstanding = GLOBUS_FALSE;
        if(ipc->close_postponed)
        {
            call_done = GLOBUS_TRUE;
            if(ipc->state == GLOBUS_GFS_IPC_STATE_ERROR)
            {
                call_stop = GLOBUS_TRUE;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
    if(call_stop && ipc->iface->transfer_event_func != NULL)
    {
        ipc->iface->transfer_event_func(ipc, ipc->reply_arg, &event_info);
    }
    if(call_stop && ipc->iface->session_stop_func)
    {
        ipc->iface->session_stop_func(ipc, ipc->reply_arg);
    }
    if(call_done)
    {
        globus_mutex_lock(&globus_l_ipc_mutex);
        {
            globus_list_remove(&globus_l_ipc_handle_list,
                globus_list_search(globus_l_ipc_handle_list, ipc));
            globus_cond_signal(&globus_l_ipc_cond);
        }
        globus_mutex_unlock(&globus_l_ipc_mutex);
        if(ipc->done_cb)
        {
            ipc->done_cb(ipc->user_arg, ipc->cached_res);
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_CLOSED;
        globus_l_gfs_ipc_handle_destroy(ipc);
    }
}

static
void
globus_l_gfs_ipc_reply_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_ipc_reply_close_kickout(user_arg);
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
    globus_xio_system_socket_t          system_handle,
    globus_i_gfs_ipc_done_callback_t    done_cb,
    void *                              user_arg)
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
    result = globus_xio_attr_cntl(xio_attr, globus_i_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_HANDLE, system_handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }
    result = globus_xio_attr_cntl(xio_attr, globus_i_gfs_tcp_driver,
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
    ipc->outstanding_event_arg = NULL;
    ipc->transfer_complete = GLOBUS_TRUE;
    ipc->iface = iface;
    ipc->state = GLOBUS_GFS_IPC_STATE_OPENING;
    ipc->cached_res = GLOBUS_SUCCESS;
    ipc->done_cb = done_cb;
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
        &ipc->xio_handle, globus_i_gfs_ipc_xio_stack);
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

    globus_mutex_lock(&ipc->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        /* if i am a requester */
        if(globus_l_gfs_ipc_requester)
        {
            result = globus_l_gfs_ipc_send_start_session(ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        else
        {
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
                globus_l_gfs_ipc_reply_read_header_cb,
                ipc);
            if(result != GLOBUS_SUCCESS)
            {
                goto read_error;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_free(buffer);

    GlobusGFSDebugExit();
    return;

read_error:
    globus_free(new_buf);
error:
    ipc->cached_res = result;
    globus_free(buffer);
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->open_cb)
    {
        ipc->open_cb(ipc, result, NULL, ipc->user_arg);
    }


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
    ipc->cached_res = result;
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    globus_mutex_unlock(&ipc->mutex);

    if(ipc->open_cb)
    {
        ipc->open_cb(ipc, result, NULL, ipc->user_arg);
    }

    GlobusGFSDebugExitWithError();
}

static 
globus_bool_t
globus_l_gfs_ipc_timeout_cb(
    globus_xio_handle_t                 handle,
    globus_xio_operation_type_t         type,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_ipc_timeout_cb);
    GlobusGFSDebugEnter();

    GlobusGFSDebugExit();
    return GLOBUS_FALSE;
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
    globus_gfs_ipc_open_callback_t      cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_bool_t                       allowed_to_connect = GLOBUS_TRUE;
    globus_result_t                     result;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_xio_attr_t                   attr;
    int                                 time;
    globus_reltime_t                    timeout;
    GlobusGFSName(globus_l_gfs_ipc_handle_connect);
    GlobusGFSDebugEnter();

    if(!allowed_to_connect)
    {
        result = GlobusGFSErrorGeneric("IPC: Not allowed to connect.");
    }
    ipc = (globus_i_gfs_ipc_handle_t *)
        globus_calloc(1, sizeof(globus_i_gfs_ipc_handle_t));
    if(ipc == NULL)
    {
        result = GlobusGFSErrorMemory("ipc");
        goto ipc_error;
    }
    ipc->outstanding_event_arg = NULL;
    ipc->transfer_complete = GLOBUS_TRUE;
    ipc->open_cb = cb;
    ipc->user_arg = user_arg;
    ipc->error_cb = error_cb;
    ipc->error_arg = error_user_arg;
    ipc->iface = iface;
    ipc->state = GLOBUS_GFS_IPC_STATE_OPENING;
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
    ipc->connection_info.cookie = NULL;
    ipc->connection_info.subject = 
        session_info->subject ? strdup(session_info->subject) : NULL;
    ipc->connection_info.username = 
        session_info->username ? strdup(session_info->username) : NULL;
    ipc->connection_info.host_id = strdup(session_info->host_id);
    ipc->connection_info.map_user = session_info->map_user;

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
        &ipc->xio_handle, globus_i_gfs_ipc_xio_stack);
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

    globus_list_insert(&globus_l_ipc_handle_list, ipc);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

open_error:
handle_error:
ipc_error:

    GlobusGFSDebugExitWithError();
    return result;
}

globus_result_t
globus_gfs_ipc_handle_connect(
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_open_callback_t      cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_result_t                     res;

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        res = globus_l_gfs_ipc_handle_connect(
            session_info,
            &globus_gfs_ipc_default_iface,
            cb,
            user_arg,
            error_cb,
            error_user_arg);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return GLOBUS_SUCCESS;
error:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return res;
}

globus_result_t
globus_gfs_ipc_handle_obtain(
    globus_gfs_session_info_t *         session_info,
    globus_gfs_ipc_iface_t *            iface,
    globus_gfs_ipc_open_callback_t      cb,
    void *                              user_arg,
    globus_gfs_ipc_error_callback_t     error_cb,
    void *                              error_user_arg)
{
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_handle_obtain);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        res = globus_l_gfs_ipc_handle_connect(
            session_info,
            iface,
            cb,
            user_arg,
            error_cb,
            error_user_arg);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_open;
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_open:
    globus_mutex_unlock(&globus_l_ipc_mutex);

    return res;
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

/*
 *  close a handle, stopping it from being further cached
 */
static
void
globus_l_gfs_ipc_close_cb_kickout(
    void *                              arg)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_close_cb_kickout);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) arg;

    if(ipc->close_cb)
    {
        ipc->close_cb(ipc, ipc->cached_res, ipc->error_arg);
    }

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        globus_list_remove(&globus_l_ipc_handle_list, 
            globus_list_search(globus_l_ipc_handle_list, ipc));
        globus_cond_signal(&globus_l_ipc_cond);
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    globus_l_gfs_ipc_handle_destroy(ipc);
    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_gfs_ipc_close_cb_kickout(user_arg);
}

static
globus_result_t
globus_l_gfs_ipc_requestor_start_close(
    globus_gfs_ipc_handle_t             ipc_handle)
{
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_result_t                     res;
    globus_size_t                       msg_size;
    GlobusGFSName(globus_l_gfs_ipc_requestor_start_close);

    buffer = globus_malloc(ipc_handle->buffer_size);
    if(buffer == NULL)
    {
        res = GlobusGFSErrorGeneric("malloc failed");
        goto error;
    }
    ptr = buffer;
    GFSEncodeChar(
        buffer,
        ipc_handle->buffer_size, ptr, GLOBUS_GFS_OP_SESSION_STOP);
    GFSEncodeUInt32(buffer, ipc_handle->buffer_size, ptr, -1);
    GFSEncodeUInt32(buffer, ipc_handle->buffer_size, ptr, -1);

    msg_size = ptr - buffer;
    /* now that we know size, add it in */
    ptr = buffer + GFS_IPC_HEADER_SIZE_OFFSET;
    GFSEncodeUInt32(buffer, ipc_handle->buffer_size, ptr, msg_size);

    res = globus_xio_register_write(
        ipc_handle->xio_handle,
        buffer,
        msg_size,
        msg_size,
        NULL,
        globus_l_gfs_ipc_stop_write_cb,
        ipc_handle);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(buffer);
        res = globus_xio_register_close(
            ipc_handle->xio_handle,
            NULL,
            globus_l_gfs_ipc_close_cb,
            ipc_handle);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", res);
            goto error_xio;
        }
    }
    return GLOBUS_SUCCESS;
error_xio:
    globus_free(buffer);
error:
    return res;
}

static
globus_result_t
globus_l_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_close_callback_t     cb,
    void *                              user_arg)
{
    globus_bool_t                       start_close = GLOBUS_FALSE;
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_close);
    GlobusGFSDebugEnter();

    if(!globus_l_gfs_ipc_requester)
    {
        res = GlobusGFSErrorGeneric("only a requestor can use this function");
        goto error;
    }

    switch(ipc_handle->state)
    {
        case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
        case GLOBUS_GFS_IPC_STATE_OPEN:
            ipc_handle->state = GLOBUS_GFS_IPC_STATE_CLOSING;
            start_close = GLOBUS_TRUE;
            break;

        case GLOBUS_GFS_IPC_STATE_ERROR:
            ipc_handle->state = GLOBUS_GFS_IPC_STATE_CLOSING_ERROR;
            start_close = GLOBUS_TRUE;
            break;

        case GLOBUS_GFS_IPC_STATE_CLOSING_ERROR:
        case GLOBUS_GFS_IPC_STATE_CLOSING:
            globus_assert(
                0 && "You already closed this, dont call it again");
            break;

        case GLOBUS_GFS_IPC_STATE_OPENING:
        case GLOBUS_GFS_IPC_STATE_CLOSED:
        default:
            globus_assert(0 && "probably meory corruption");
            break;
    }

    ipc_handle->close_cb = cb;
    ipc_handle->error_cb = NULL;

    if(start_close)
    {
        res = globus_l_gfs_ipc_requestor_start_close(ipc_handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
error:
    return res;
}

globus_result_t
globus_gfs_ipc_close(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_ipc_close_callback_t     cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    GlobusGFSName(globus_gfs_ipc_close);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&ipc_handle->mutex);
    {
        result = globus_l_gfs_ipc_close(ipc_handle, cb, user_arg);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);
                                                                                
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
error:
    globus_mutex_unlock(&ipc_handle->mutex);
    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        globus_list_remove(&globus_l_ipc_handle_list, 
            globus_list_search(globus_l_ipc_handle_list, ipc_handle));
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);
    globus_l_gfs_ipc_handle_destroy(ipc_handle);

    return result;
}

globus_result_t
globus_gfs_ipc_reply_close(
    globus_gfs_ipc_handle_t             ipc_handle)
{
    globus_result_t                     result;
    GlobusGFSName(globus_gfs_ipc_reply_close);

    if(globus_l_gfs_ipc_requester)
    {
        result = GlobusGFSErrorGeneric("only a replier can use this function");
        goto error;
    }
    globus_mutex_lock(&ipc_handle->mutex);
    {
        switch(ipc_handle->state)
        {
            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                ipc_handle->state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                if(!ipc_handle->transfer_complete)
                {
                    ipc_handle->fake_abort_outstanding = GLOBUS_TRUE;
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_ipc_reply_fake_abort,
                        ipc_handle);
                }
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                ipc_handle->state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                ipc_handle->state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT;
                if(!ipc_handle->transfer_complete)
                {
                    ipc_handle->fake_abort_outstanding = GLOBUS_TRUE;
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_ipc_reply_fake_abort,
                        ipc_handle);
                }
                break;

            case GLOBUS_GFS_IPC_STATE_OPEN:
                ipc_handle->state = GLOBUS_GFS_IPC_STATE_ERROR;
                result = globus_xio_register_close(
                    ipc_handle->xio_handle,
                    NULL,
                    globus_l_gfs_ipc_reply_close_cb,
                    ipc_handle);
                if(result != GLOBUS_SUCCESS)
                {
                    globus_i_gfs_log_result_warn(
                        "a close failed, can lead to a barrier race", result);
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_ipc_reply_close_kickout,
                        ipc_handle);
                }
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
            case GLOBUS_GFS_IPC_STATE_ERROR_OPENING:
            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                /* don nothing for all of these because the
                    the wheels are already in motion */
                break;

            case GLOBUS_GFS_IPC_STATE_CLOSING_ERROR:
            case GLOBUS_GFS_IPC_STATE_CLOSING:
            case GLOBUS_GFS_IPC_STATE_CLOSED:
            case GLOBUS_GFS_IPC_STATE_OPENING:
            default:
                globus_assert(0 && 
                    "can't call close in this state, whats wrongs with you?");
                break;
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    return GLOBUS_SUCCESS;
error:
    return result;
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

        case GLOBUS_GFS_OP_TRANSFER:
/*            GFSDecodeUInt64(
                buffer, len, reply->info.transfer.bytes_transferred);
*/            break;
            
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
            request->ipc->cached_res,
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
    globus_bool_t                       reply_kickout = GLOBUS_FALSE;
    globus_byte_t *                     new_buf;
    globus_byte_t *                     start_buf;
    globus_gfs_ipc_request_t *          request;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_gfs_finished_info_t *        reply = NULL;
    globus_gfs_event_info_t *           event_reply;
    GlobusGFSName(globus_l_gfs_ipc_request_read_body_cb);
    GlobusGFSDebugEnter();

    start_buf = buffer;
    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_CLOSING:
                /* close process already started, just ride that out */
                break;

            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                if(result != GLOBUS_SUCCESS)
                {
                    goto error;
                }

                /* parse based on type
                   callout on all types excet for reply, reply needs lock */
                switch(request->last_type)
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
                        ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
                        reply_kickout = GLOBUS_TRUE;
                        break;

                    case GLOBUS_GFS_OP_EVENT_REPLY:
                        event_reply = globus_l_gfs_ipc_unpack_event_reply(
                            ipc, buffer, len);
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
                            request);
                        if(result != GLOBUS_SUCCESS)
                        {
                            goto mem_error;
                        }
                        break;

                    default:
                        goto error;
                        break;
                }
                break;

            default:
                globus_assert(0 && "not in a valid state");
        }
    }
    /* call use callback */
    globus_mutex_unlock(&ipc->mutex);

    if(reply_kickout)
    {
        globus_l_gfs_ipc_finished_reply_kickout(request);
    }
    globus_free(start_buf);

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(new_buf);
error:
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    ipc->cached_res = result;
    globus_mutex_unlock(&ipc->mutex);

    if(reply == NULL)
    {
        reply = (globus_gfs_finished_info_t *) globus_calloc(
            1, sizeof(globus_gfs_finished_info_t));
        reply->type = request->type;
        reply->id = request->id;
        reply->code = 500;
        reply->msg = "IPC failed while attempting to perform request";
        reply->result = GlobusGFSErrorData("IPC failed while attempting to perform request");
    }
    request->reply = reply;

    globus_l_gfs_ipc_finished_reply_kickout(request);
    globus_l_gfs_ipc_error_kickout(ipc);
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
    globus_gfs_finished_info_t *        reply;
    globus_bool_t                       rc;
    globus_gfs_ipc_request_t *          request;
    globus_gfs_ipc_request_t *          lu_request;
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    globus_byte_t *                     new_buf = NULL;
    int                                 reply_size;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       size;
    GlobusGFSName(globus_l_gfs_ipc_request_read_header_cb);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_CLOSING:
                /* close process already started, just ride that out */
                break;

            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
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
                        /* even tho there is only 1 outstanding request
                            we look it up in the table.  this is in
                            case we ever allow many outstanding requests 
                            at once. */
                        lu_request = (globus_gfs_ipc_request_t *)
                            globus_handle_table_lookup(&ipc->call_table, id);
                        if(lu_request == NULL || request != lu_request)
                        {
                            result = GlobusGFSErrorIPC();
                            goto error;
                        }
                        rc = globus_handle_table_decrement_reference(
                            &ipc->call_table, id);
                        globus_assert(!rc);
                        request->last_type = type;
                        break;
                
                    case GLOBUS_GFS_OP_EVENT_REPLY:
                        lu_request = (globus_gfs_ipc_request_t *)
                            globus_handle_table_lookup(&ipc->call_table, id);
                        if(request == NULL || request != lu_request)
                        {
                            result = GlobusGFSErrorIPC();
                            goto error;
                        }
                        request->last_type = type;
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
                break;

            default:
                globus_assert(0 && "not in a valid state");
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

    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    /* kickout error */
    globus_free(buffer);
    ipc->cached_res = result;
    globus_mutex_unlock(&ipc->mutex);
    reply = (globus_gfs_finished_info_t *) globus_calloc(
        1, sizeof(globus_gfs_finished_info_t));
    reply->type = request->type;
    reply->id = request->id;
    reply->code = 500;
    reply->result = GlobusGFSErrorData("IPC failed while attempting to perform request");
    request->reply = reply;
    globus_l_gfs_ipc_finished_reply_kickout(request);
    globus_l_gfs_ipc_error_kickout(ipc);

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
    globus_bool_t                       process = GLOBUS_FALSE;
    int                                 error_state;
    int                                 no_reply_state;
    GlobusGFSName(globus_l_gfs_ipc_reply_read_body_cb);
    GlobusGFSDebugEnter();

    request = (globus_gfs_ipc_request_t *) user_arg;
    ipc = request->ipc;

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_OPEN:
                process = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                no_reply_state = GLOBUS_GFS_IPC_STATE_OPEN;
                ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                process = GLOBUS_TRUE;
                no_reply_state = GLOBUS_GFS_IPC_STATE_SESSION_OPEN;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                ipc->state = GLOBUS_GFS_IPC_STATE_SESSION_REPLY;
                break;

            /* in the error cases either xio_close has been called or
                we are waiting for the session start to return so that
                we can call xio_close.  in either case we do nothing here
            */
            case GLOBUS_GFS_IPC_STATE_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
            case GLOBUS_GFS_IPC_STATE_ERROR_OPENING:
            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                goto error_already;
                break;

            /* events come in this state */
            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                process = GLOBUS_TRUE;
                no_reply_state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
                error_state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                break;

            /* events come in this state */
            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                process = GLOBUS_TRUE;
                no_reply_state = GLOBUS_GFS_IPC_STATE_SESSION_REPLY;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT;
                break;

            default:
                globus_assert(0 && "mem corruption");
                break;
        }

        if(result != GLOBUS_SUCCESS)
        {
            goto err;
        }

        if(process)
        {
            /* parse based on type
               callout on all types excet for reply, reply needs lock */
            switch(request->type)
            {
                case GLOBUS_GFS_OP_BUFFER_SEND:
                    rc = globus_l_gfs_ipc_unpack_user_buffer(
                        ipc, buffer, len, 
                        &user_buffer_type, &user_buffer, &user_buffer_length);
                    if(rc != 0)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    ipc->state = no_reply_state;
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
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_RECV:
                    trans_info = globus_l_gfs_ipc_unpack_transfer(
                        ipc, buffer, len);
                    if(trans_info == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    request->info_struct = trans_info;
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_SEND:
                    trans_info = globus_l_gfs_ipc_unpack_transfer(
                        ipc, buffer, len);
                    if(trans_info == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    request->info_struct = trans_info;
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_LIST:
                    trans_info = globus_l_gfs_ipc_unpack_transfer(
                        ipc, buffer, len);
                    if(trans_info == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    request->info_struct = trans_info;
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_COMMAND:
                    cmd_info = globus_l_gfs_ipc_unpack_command(
                        ipc, buffer, len);
                    if(cmd_info == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    request->info_struct = cmd_info;
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_PASSIVE:
                    data_info = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
                    if(data_info == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    request->info_struct = data_info;
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_ACTIVE:
                    data_info = globus_l_gfs_ipc_unpack_data(ipc, buffer, len);
                    if(data_info == NULL)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    request->info_struct = data_info;
                    globus_hashtable_insert(
                        &ipc->reply_table, (void *)request->id, request);
                    break;

                case GLOBUS_GFS_OP_DESTROY:
                    rc = globus_l_gfs_ipc_unpack_data_destroy(
                        ipc, buffer, len, &data_arg);
                    if(rc != 0)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }
                    ipc->state = no_reply_state;
                    break;
            
                case GLOBUS_GFS_OP_EVENT:            
                    rc = globus_l_gfs_ipc_unpack_event_request(
                        ipc, buffer, len, &event_info);
                    if(rc != 0)
                    {
                        result = GlobusGFSErrorIPC();
                        goto err;
                    }

                    if(event_info->type == GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
                    {
                        ipc->transfer_complete = GLOBUS_TRUE;
                        ipc->outstanding_event_arg = NULL;
                    }
                    ipc->state = no_reply_state;
                    break;
            
                case GLOBUS_GFS_OP_SESSION_START:
                    result = GlobusGFSErrorIPC();
                    goto err;
                    break;

                default:
                    break;
            }
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    globus_free(buffer);

    /* now that everything is set call the iface funcs */
    if(process)
    {
        switch(request->type)
        {
            case GLOBUS_GFS_OP_BUFFER_SEND:
                ipc->iface->buffer_send(
                    ipc, ipc->reply_arg,
                    user_buffer, user_buffer_type, user_buffer_length);
                globus_l_gfs_ipc_request_destroy(request);
                break;

            case GLOBUS_GFS_OP_STAT:
                ipc->iface->stat_func(
                    ipc, ipc->reply_arg, request->id, stat_info, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_RECV:
                ipc->iface->recv_func(
                    ipc, 
                    ipc->reply_arg,
                    request->id, trans_info, NULL, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_SEND:
                ipc->iface->send_func(
                    ipc, 
                    ipc->reply_arg,
                    request->id, trans_info, NULL, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_LIST:
                ipc->iface->list_func(
                    ipc,
                    ipc->reply_arg,
                    request->id, trans_info, NULL, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_COMMAND:
                ipc->iface->command_func(
                    ipc, ipc->reply_arg, request->id, cmd_info, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_PASSIVE:
                ipc->iface->passive_func(
                    ipc, ipc->reply_arg, request->id, data_info, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_ACTIVE:
                ipc->iface->active_func(
                    ipc, ipc->reply_arg, request->id, data_info, NULL, NULL);
                break;

            case GLOBUS_GFS_OP_DESTROY:
                ipc->iface->data_destroy_func(
                    ipc, ipc->reply_arg, data_arg);
                globus_l_gfs_ipc_request_destroy(request);
                break;
            
            case GLOBUS_GFS_OP_EVENT:            
                ipc->iface->transfer_event_func(
                    ipc, ipc->reply_arg, event_info);
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
    }

    /* relock and post read */
    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            /* if while waiting for the lock the user already
                replied to the event we would return to the open
                states, nothing needs to be done but post the
                next read */
            case GLOBUS_GFS_IPC_STATE_OPEN:
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                break;
            case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                /* if it actaully ever makes it here in this state
                    then you got yourself one crazy ass thread
                    implementation */
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
            case GLOBUS_GFS_IPC_STATE_ERROR_OPENING:
            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                goto error_already;
                break;

            /* events come in this state */
            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                error_state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                break;
            /* events come in this state */
            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT;
                break;

            default:
                globus_assert(0 && "mem corruption");
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
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

mem_error:
    globus_free(new_buf);
err:
    globus_l_gfs_ipc_request_destroy(request);
    ipc->state = error_state;
    ipc->cached_res = result;
    globus_mutex_unlock(&ipc->mutex);
    if(error_state == GLOBUS_GFS_IPC_STATE_ERROR)
    {
        result = globus_xio_register_close(
            ipc->xio_handle,
            NULL,
            globus_l_gfs_ipc_reply_close_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", result);
            /* XXX this is a problem because it doesn't respect
                the cloes barrier.  log an error */
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", result);
            globus_l_gfs_ipc_reply_close_kickout(ipc);
        }
    }
    else if(error_state == GLOBUS_GFS_IPC_STATE_ERROR_WAIT ||
        error_state == GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT)
    {
        if(!ipc->transfer_complete)
        {
            ipc->fake_abort_outstanding = GLOBUS_TRUE;
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_reply_fake_abort,
                ipc);
        }
    }
error_already:
    globus_free(buffer);

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
    int                                 error_state;
    globus_bool_t                       post_read = GLOBUS_FALSE;
    globus_byte_t *                     new_buf;
    globus_gfs_ipc_request_t *          request;
    char                                type;
    int                                 id;
    globus_byte_t *                     ptr;
    int                                 reply_size;
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_size_t                       size;
    GlobusGFSName(globus_l_gfs_ipc_reply_read_header_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_OPEN:
                post_read = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                post_read = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                break;

            /* in the error cases either xio_close has been called or
                we are waiting for the session start to return so that
                we can call xio_close.  in either case we do nothing here
            */
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
            case GLOBUS_GFS_IPC_STATE_ERROR_OPENING:
            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
            case GLOBUS_GFS_IPC_STATE_ERROR:
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
                goto error_already;
                break;

            /* events come in this state */
            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                post_read = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                break;

            /* events come in this state */
            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                post_read = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT;
                break;

            default:
                globus_assert(0 && "mem corruption");
                break;
        }
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        if(post_read)
        {
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
                    goto error;
                    break;

                default:
                    result = GlobusGFSErrorIPC();
                    goto error;
                    break;
            }
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
    ipc->state = error_state;
    ipc->cached_res = result;
    globus_mutex_unlock(&ipc->mutex);
    if(error_state == GLOBUS_GFS_IPC_STATE_ERROR)
    {
        result = globus_xio_register_close(
            ipc->xio_handle,
            NULL,
            globus_l_gfs_ipc_reply_close_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", result);
            globus_l_gfs_ipc_reply_close_kickout(ipc);
        }
    }
error_already:
    globus_free(buffer);

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
    globus_bool_t                       requester)
{
    globus_result_t                     res;
    GlobusGFSName(globus_gfs_ipc_init);
    GlobusGFSDebugEnter();

    res = globus_xio_driver_load("tcp", &globus_i_gfs_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto tcp_load_error;
    }
    res = globus_xio_driver_load("queue", &globus_l_gfs_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto queue_load_error;
    }
    
    res = globus_xio_stack_init(&globus_i_gfs_ipc_xio_stack, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto stack_init_error;
    }
    res = globus_xio_stack_push_driver(
        globus_i_gfs_ipc_xio_stack, globus_i_gfs_tcp_driver);
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
            globus_i_gfs_ipc_xio_stack, globus_l_gfs_gsi_driver);
        if(res != GLOBUS_SUCCESS)
        {
            globus_xio_driver_unload(globus_l_gfs_gsi_driver);
            goto stack_push_error;
        }
    }
    res = globus_xio_stack_push_driver(
        globus_i_gfs_ipc_xio_stack, globus_l_gfs_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto stack_push_error;
    }

    globus_hashtable_init(
        &globus_l_ipc_request_table,
        64,
        globus_l_gfs_ipc_hashtable_session_hash,
        globus_l_gfs_ipc_hashtable_session_keyeq);

    globus_mutex_init(&globus_l_ipc_mutex, NULL); 
    globus_cond_init(&globus_l_ipc_cond, NULL); 

    globus_l_gfs_ipc_requester = requester;

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

stack_push_error:
    globus_xio_stack_destroy(globus_i_gfs_ipc_xio_stack);
stack_init_error:
gsi_load_error:
    globus_xio_driver_unload(globus_l_gfs_queue_driver);
queue_load_error:
    globus_xio_driver_unload(globus_i_gfs_tcp_driver);
tcp_load_error:

    GlobusGFSDebugExitWithError();
    return res;
}

void
globus_gfs_ipc_destroy()
{
    GlobusGFSName(globus_gfs_ipc_destroy);
    GlobusGFSDebugEnter();

    globus_mutex_destroy(&globus_l_ipc_mutex);
    globus_cond_destroy(&globus_l_ipc_cond);

    GlobusGFSDebugExit();
}

/*
 *  entirely ignore this.  let something else pick up the error (i think)
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
    int                                 error_state;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_reply_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_free(buffer);

    globus_mutex_lock(&ipc->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_OPEN:
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                break;
            case GLOBUS_GFS_IPC_STATE_SESSION_OPEN:
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR:
                /* in this case xio_close has been called, we do
                    nothing and just wait for the close_cb */
                goto error_already;
                break;
            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR:
                /* here we are waiting for session_start to return before
                    calling close.  again we do nothing. */
                goto error_already;
                break;

            default:
                globus_assert(0 && "memory corruption?");
                break;
        }
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;
error:
    ipc->state = error_state;
    ipc->cached_res = result;
    globus_mutex_unlock(&ipc->mutex);
    if(error_state == GLOBUS_GFS_IPC_STATE_ERROR)
    {
        result = globus_xio_register_close(
            ipc->xio_handle,
            NULL,
            globus_l_gfs_ipc_reply_close_cb,
            ipc);
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", result);
            globus_l_gfs_ipc_reply_close_kickout(ipc);
        }
    }
error_already:
    return;
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply_finished(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_finished_info_t *        reply)
{
    globus_bool_t                       send_event = GLOBUS_FALSE;
    int                                 error_state;
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
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                send_event = GLOBUS_TRUE;
                /* error state is same since we are returning error
                    giving user to try again */
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                ipc->state = GLOBUS_GFS_IPC_STATE_OPEN;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                send_event = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                ipc->state = GLOBUS_GFS_IPC_STATE_SESSION_OPEN;
                break;

            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                error_state = GLOBUS_GFS_IPC_STATE_ERROR;
                goto error;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR;
                goto error;
                break;

            default:
                globus_assert(0 && "memory corruption or api misuse");
        }

        if(send_event)
        {
            /* if local register one shot to get out of recurisve call stack
                troubles */
            request = (globus_gfs_ipc_request_t *) 
                globus_hashtable_remove(
                &ipc->reply_table,
                (void *)reply->id);
            if(request == NULL)
            {
                res = GlobusGFSErrorGeneric("malloc failed");
                goto error;
            }
            /* don't need the request anymore */
            globus_l_gfs_ipc_request_destroy(request);

            /* pack the header */
            buffer = globus_malloc(ipc->buffer_size);
            if(buffer == NULL)
            {
                res = GlobusGFSErrorGeneric("malloc failed");
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

                case GLOBUS_GFS_OP_TRANSFER:
/*                    GFSEncodeUInt64(
                        buffer, ipc->buffer_size, ptr, 
                        reply->info.transfer.bytes_transferred);                    
*/                    break;

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
                goto error_mem;
            }
        }
    }
    globus_mutex_unlock(&ipc_handle->mutex);

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_mem:
    globus_free(buffer);
error:
    ipc->state = error_state;
    ipc->cached_res = res;
    globus_mutex_unlock(&ipc->mutex);
    if(error_state == GLOBUS_GFS_IPC_STATE_ERROR)
    {
        res = globus_xio_register_close(
            ipc->xio_handle,
            NULL,
            globus_l_gfs_ipc_reply_close_cb,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", res);
            globus_l_gfs_ipc_reply_close_kickout(ipc);
        }
    }

    GlobusGFSDebugExitWithError();
    return GLOBUS_SUCCESS; /* we should make this a void type function */
}

/*
 *  register callback in oneshot to avoid reenter woes.
 */
globus_result_t
globus_gfs_ipc_reply_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_gfs_event_info_t *           reply)
{
    globus_i_gfs_ipc_handle_t *         ipc;
    globus_byte_t *                     buffer;
    globus_byte_t *                     ptr;
    globus_result_t                     res;
    globus_off_t                        offset;
    globus_off_t                        length;
    int                                 range_size;
    int                                 ctr;
    int                                 msg_size;
    int                                 error_state;
    globus_bool_t                       send_event = GLOBUS_FALSE;
    GlobusGFSName(globus_gfs_ipc_reply_event);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) ipc_handle;
    globus_mutex_lock(&ipc_handle->mutex);
    {
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
                send_event = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_REPLY:
                send_event = GLOBUS_TRUE;
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT;
                break;

            /* in the error cases do nothing.. maybe return error, but for now
                nothing */
            case GLOBUS_GFS_IPC_STATE_ERROR_WAIT:
                error_state = GLOBUS_GFS_IPC_STATE_ERROR_WAIT;
                break;

            case GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT:
                error_state = GLOBUS_GFS_IPC_STATE_SESSION_ERROR_WAIT;
                break;

            default:
                globus_assert(0 && "memory corruption or api misuse");
        }

        if(send_event)
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
                    ipc->transfer_complete = GLOBUS_FALSE;
                    ipc->outstanding_event_arg = reply->event_arg;
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
    ipc->state = error_state;
    ipc->cached_res = res;
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
    globus_result_t                     res;
    globus_i_gfs_ipc_handle_t *         ipc;
    GlobusGFSName(globus_l_gfs_ipc_stop_write_cb);
    GlobusGFSDebugEnter();

    ipc = (globus_i_gfs_ipc_handle_t *) user_arg;

    globus_free(buffer);

    globus_mutex_lock(&globus_l_ipc_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            ipc->cached_res = result;
        }

        ipc->state = GLOBUS_GFS_IPC_STATE_CLOSING;
        res = globus_xio_register_close(
            ipc->xio_handle,
            NULL,
            globus_l_gfs_ipc_close_cb,
            ipc);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result_warn(
                "a close failed, can lead to a barrier race", res);
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_ipc_close_cb_kickout,
                NULL);
        }
    }
    globus_mutex_unlock(&globus_l_ipc_mutex);

    GlobusGFSDebugExit();
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
        ipc->cached_res = result;
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
    globus_gfs_finished_info_t *        reply;
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
        switch(ipc->state)
        {
            case GLOBUS_GFS_IPC_STATE_CLOSING:
                /* close process already started, just ride that out */
                break;

            case GLOBUS_GFS_IPC_STATE_REPLY_WAIT:
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
                    request);
                if(result != GLOBUS_SUCCESS)
                {
                    goto read_error;
                }
                break;

            default:
                globus_assert(0 && "not in a valid state");
        }
    }
    globus_mutex_unlock(&ipc->mutex);

    GlobusGFSDebugExit();
    return;

read_error:
    globus_free(new_buf);
error:
    ipc->state = GLOBUS_GFS_IPC_STATE_ERROR;
    globus_mutex_unlock(&ipc->mutex);
    /* call use callback */
    reply = (globus_gfs_finished_info_t *) globus_calloc(
        1, sizeof(globus_gfs_finished_info_t));
    reply->type = request->type;
    reply->id = request->id;
    reply->code = 500;
    reply->msg = "IPC failed while attempting to perform request";
    reply->result = GlobusGFSErrorData("IPC failed while attempting to perform request");
    request->reply = reply;

    globus_l_gfs_ipc_finished_reply_kickout(request);
    globus_l_gfs_ipc_error_kickout(ipc);
    globus_l_gfs_ipc_request_destroy(request);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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

        res = globus_l_gfs_ipc_transfer_pack(
            ipc, GLOBUS_GFS_OP_RECV, recv_info, request);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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

        res = globus_l_gfs_ipc_transfer_pack(
            ipc, GLOBUS_GFS_OP_SEND, send_info, request);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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

        res = globus_l_gfs_ipc_transfer_pack(
            ipc, GLOBUS_GFS_OP_LIST, data_info, request);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_REPLY_WAIT)
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
    
        request->ipc = ipc_handle;
        request->type = GLOBUS_GFS_OP_EVENT;
        request->id = -1;
        
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
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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
        
        res = globus_l_gfs_ipc_pack_data(
            ipc,
            GLOBUS_GFS_OP_ACTIVE,
            data_info,
            request); 
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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

        res = globus_l_gfs_ipc_pack_data(
            ipc,
            GLOBUS_GFS_OP_PASSIVE,
            data_info,
            request); 
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc_handle->state != GLOBUS_GFS_IPC_STATE_OPEN)
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
        ipc->state = GLOBUS_GFS_IPC_STATE_REPLY_WAIT;
    }
    globus_mutex_unlock(&ipc->mutex);

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
        if(ipc->state != GLOBUS_GFS_IPC_STATE_OPEN)
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
    globus_mutex_unlock(&ipc->mutex);

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
