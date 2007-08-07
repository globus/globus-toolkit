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
/* provides local_extensions */
#include "extensions.h"
#include <unistd.h>
#include <openssl/des.h>
#include <pwd.h>
#include <grp.h>
#include "globus_io.h"

#define FTP_SERVICE_NAME "file"
#define USER_NAME_MAX   64
#define GSC_GETPW_PWBUFSIZE        (USER_NAME_MAX*3)+(PATH_MAX*2)

#define GFSDataOpDec(_op, _d_op, _d_s)                                  \
do                                                                      \
{                                                                       \
    _op->ref--;                                                         \
    if(_op->ref == 0)                                                   \
    {                                                                   \
        _d_op = GLOBUS_TRUE;                                            \
        _op->session_handle->ref--;                                     \
        if(_op->session_handle->ref == 0)                               \
        {                                                               \
            _d_s = GLOBUS_TRUE;                                         \
        }                                                               \
    }                                                                   \
} while(0)

struct passwd *                         globus_l_gfs_data_pwent = NULL;
static globus_gfs_storage_iface_t *     globus_l_gfs_dsi = NULL;
globus_extension_registry_t             globus_i_gfs_dsi_registry;
globus_extension_handle_t               globus_i_gfs_active_dsi_handle;
static globus_bool_t                    globus_l_gfs_data_is_remote_node = GLOBUS_FALSE;
globus_off_t                            globus_l_gfs_bytes_transferred;
globus_mutex_t                          globus_l_gfs_global_counter_lock;
globus_extension_registry_t             globus_i_gfs_acl_registry;

typedef enum
{
    GLOBUS_L_GFS_DATA_REQUESTING = 1,
    GLOBUS_L_GFS_DATA_CONNECTING,
    GLOBUS_L_GFS_DATA_CONNECT_CB,
    GLOBUS_L_GFS_DATA_CONNECTED,
    GLOBUS_L_GFS_DATA_ABORTING,
    GLOBUS_L_GFS_DATA_ABORT_CLOSING,
    GLOBUS_L_GFS_DATA_FINISH,
    GLOBUS_L_GFS_DATA_FINISH_WITH_ERROR,
    GLOBUS_L_GFS_DATA_COMPLETING,
    GLOBUS_L_GFS_DATA_COMPLETE
} globus_l_gfs_data_state_t;

typedef enum
{
    GLOBUS_L_GFS_DATA_HANDLE_VALID = 1,
    GLOBUS_L_GFS_DATA_HANDLE_INUSE,
    GLOBUS_L_GFS_DATA_HANDLE_CLOSING,
    GLOBUS_L_GFS_DATA_HANDLE_TE_VALID,
    GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED,
    GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED,
    GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED,
    GLOBUS_L_GFS_DATA_HANDLE_CLOSED_AND_DESTROYED,
    GLOBUS_L_GFS_DATA_HANDLE_CLOSED
} globus_l_gfs_data_handle_state_t;

typedef enum
{
    GLOBUS_L_GFS_DATA_INFO_TYPE_COMMAND = 1,
    GLOBUS_L_GFS_DATA_INFO_TYPE_PASSIVE,
    GLOBUS_L_GFS_DATA_INFO_TYPE_ACTIVE,
    GLOBUS_L_GFS_DATA_INFO_TYPE_STAT,
    GLOBUS_L_GFS_DATA_INFO_TYPE_SEND,
    GLOBUS_L_GFS_DATA_INFO_TYPE_RECV,
    GLOBUS_L_GFS_DATA_INFO_TYPE_LIST
} globus_l_gfs_data_info_type_t;

typedef struct
{
    globus_gfs_operation_t   op;

    union
    {
        globus_gridftp_server_write_cb_t write;
        globus_gridftp_server_read_cb_t  read;
    } callback;
    void *                              user_arg;
    globus_gfs_finished_info_t *        finished_info;
    globus_byte_t *                     list_response;
    globus_bool_t                       free_buffer;
} globus_l_gfs_data_bounce_t;

typedef struct
{
    globus_i_gfs_acl_handle_t           acl_handle;

    gss_cred_id_t                       del_cred;
    char *                              username;
    char *                              real_username;
    char *                              home_dir;
    uid_t                               uid;
    int                                 gid_count;
    gid_t *                             gid_array;

    void *                              session_arg;
    void *                              data_handle;
    globus_mutex_t                      mutex;
    int                                 ref;
    globus_gfs_storage_iface_t *        dsi;
    globus_extension_handle_t           dsi_handle;

    char *                              mod_dsi_name;
    globus_gfs_storage_iface_t *        mod_dsi;
    globus_extension_handle_t           mod_dsi_handle;

    globus_handle_table_t               handle_table;
    int                                 node_ndx;
} globus_l_gfs_data_session_t;

typedef struct
{
    globus_l_gfs_data_session_t *       session_handle;
    globus_l_gfs_data_handle_state_t    state;
    globus_gfs_data_info_t              info;
    globus_ftp_control_handle_t         data_channel;
    void *                              remote_data_arg;
    globus_bool_t                       is_mine;
    globus_gfs_operation_t              outstanding_op;
    globus_bool_t                       destroy_requested;
    globus_bool_t                       use_interface;
    globus_xio_attr_t                   xio_attr;
} globus_l_gfs_data_handle_t;

typedef struct globus_l_gfs_data_operation_s
{
    globus_l_gfs_data_state_t           state;
    globus_bool_t                       writing;
    globus_l_gfs_data_handle_t *        data_handle;
    void *                              data_arg;
    struct timeval                      start_timeval;
    char *                              remote_ip;

    globus_l_gfs_data_session_t *       session_handle;
    void *                              info_struct;
    globus_l_gfs_data_info_type_t       type;

    int                                 id;
    globus_gfs_ipc_handle_t             ipc_handle;

    uid_t                               uid;
    /* transfer stuff */
    globus_range_list_t                 range_list;
    globus_off_t                        partial_offset;
    globus_off_t                        partial_length;
    const char *                        list_type;

    globus_off_t                        bytes_transferred;
    globus_off_t                        max_offset;
    globus_off_t                        recvd_bytes;
    globus_range_list_t                 recvd_ranges;

    int                                 nstreams;
    int                                 stripe_count;
    int *                               eof_count;
    globus_bool_t                       eof_ready;
    int                                 node_count;
    int                                 node_ndx;
    int                                 write_stripe;

    int                                 stripe_connections_pending;

    /* used to shift the offset from the dsi due to partial/restart */
    int                                 write_delta;
    /* used to shift the offset from the dsi due to partial/restart */
    int                                 transfer_delta;
    int                                 stripe_chunk;
    globus_range_list_t                 stripe_range_list;

    /* command stuff */
    globus_gfs_command_type_t           command;
    char *                              pathname;
    globus_off_t                        cksm_offset;
    globus_off_t                        cksm_length;
    char *                              cksm_alg;
    char *                              cksm_response;
    mode_t                              chmod_mode;
    char *                              rnfr_pathname;
    /**/

    void *                              event_arg;
    int                                 event_mask;

    globus_i_gfs_data_callback_t        callback;
    globus_i_gfs_data_event_callback_t  event_callback;
    void *                              user_arg;

    int                                 ref;
    globus_result_t                     cached_res;

    globus_gfs_storage_iface_t *        dsi;
    int                                 sent_partial_eof;

    void *                              stat_wrapper;

    /* sort of a state cheat.  for case where:
        start_abort
            -- connecting to abort_closing
            -- waiting on abort_cb
        globus_gridftp_server_finished_transfer
            -- connecting to finished
        begin_cb
            -- since in finished we kickout atransfer end
        abort_cb
            -- kicks out transfer end since in finished
    */
    globus_bool_t                       finished_delayed;
} globus_l_gfs_data_operation_t;

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    int                                 event_type;
} globus_l_gfs_data_trev_bounce_t;

typedef struct
{
    globus_result_t                     result;
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 id;
    globus_l_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    globus_i_gfs_data_callback_t        callback;
    void *                              user_arg;
} globus_l_gfs_data_active_bounce_t;

typedef struct
{
    globus_gfs_ipc_handle_t             ipc_handle;
    int                                 id;
    globus_l_gfs_data_handle_t *        handle;
    globus_bool_t                       bi_directional;
    char *                              contact_string;
    globus_i_gfs_data_callback_t        callback;
    void *                              user_arg;
    globus_result_t                     result;
} globus_l_gfs_data_passive_bounce_t;

typedef struct
{
    globus_l_gfs_data_operation_t *     op;
    globus_object_t *                   error;
    int                                 stat_count;
    globus_gfs_stat_t *                 stat_array;
    globus_byte_t *                     list_response;
    globus_bool_t                       free_buffer;
} globus_l_gfs_data_stat_bounce_t;

static
void
globus_l_gfs_data_end_transfer_kickout(
    void *                              user_arg);
    
static
void
globus_l_gfs_data_start_abort(
    globus_l_gfs_data_operation_t *     op);

static
void
globus_l_gfs_data_handle_free(
    globus_l_gfs_data_handle_t *    data_handle);
    
static
void
globus_l_gfs_free_session_handle(
    globus_l_gfs_data_session_t *       session_handle);

static
void
globus_l_gfs_data_write_eof_cb(
    void *                              user_arg,
    globus_ftp_control_handle_t *       handle,
    globus_object_t *                   error,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_off_t                        offset,
    globus_bool_t                       eof);

static
void
globus_l_gfs_data_end_read_kickout(
    void *                              user_arg);

static
void
globus_l_gfs_data_operation_destroy(
    globus_l_gfs_data_operation_t *     op);

static
globus_result_t
globus_l_gfs_set_stack(
    globus_l_gfs_data_handle_t *        handle);

static
void *
globus_l_gfs_data_check(
    globus_l_gfs_data_session_t *       session_handle,
    globus_l_gfs_data_handle_t *        data_handle)
{
    void *                              remote_data_arg = NULL;

    if(data_handle == NULL)
    {
        return NULL;
    }

    /* need to hold something to make sure that it is safe to even check
        so far we are setting to CLOSED too soon 

        XXX race debug note */

            /* there is a problem here.  if i dec the session_handle count
                and it DOES NOT reach 0, that means that once i unlock the
                session_stop call could happen.  this would bump it down to
                zero and destroy it, which is a big problem because i am
                going to use the mutex again later in this function.  

                in short the problem is that i am decing the count too early.
                however, i have to do it hear to get destroy_op and other
                values.  therefore to cheat i am going to just bump it back up.
                I know, i know.  ugly.  fixing it properly would involve 
                re-evaulating the GFSDataOpDec() macro everwhere.
            */

    switch(data_handle->state)
    {
        case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
        case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
        case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
        case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
            break;

        case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
            if(!data_handle->is_mine)
            {

                /* this provides the flag making it ok to destroy */
                remote_data_arg = data_handle->remote_data_arg;
            }
            if(remote_data_arg != NULL)
            {
                session_handle->ref++;
            }
            break;

        case GLOBUS_L_GFS_DATA_HANDLE_TE_VALID:
            break;
        case GLOBUS_L_GFS_DATA_HANDLE_VALID:
        default:
            /*globus_assert(0 && "possible memory corruption"); */
            break;
    }    

    return remote_data_arg;
}

static
void
globus_l_gfs_data_fire_cb(
    globus_l_gfs_data_operation_t *     op,
    void *                              remote_data_arg,
    globus_bool_t                       free_session)
{
    if(remote_data_arg != NULL)
    {
        /* if i have something to call i should not be freeing */
        globus_assert(!op->data_handle->is_mine);
        globus_assert(op->session_handle->ref > 0);
        globus_assert(!free_session);

        if(op->session_handle->dsi->data_destroy_func != NULL)
        {
            op->session_handle->dsi->data_destroy_func(
                remote_data_arg,
                op->session_handle->session_arg);
        }
        else
        {
            /* XXX dsi impl error, what to do? */
        }
        globus_l_gfs_data_handle_free(op->data_handle);

        globus_mutex_lock(&op->session_handle->mutex);
        {
            op->session_handle->ref--;
            if(op->session_handle->ref == 0)
            {
                free_session = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&op->session_handle->mutex);
    }

    if(free_session)
    {
        if(op->session_handle->dsi->destroy_func != NULL)
        {
            op->session_handle->dsi->destroy_func(
                op->session_handle->session_arg);
        }

        if(op->session_handle->dsi != globus_l_gfs_dsi)
        {
            globus_extension_release(op->session_handle->dsi_handle);
        }
        globus_l_gfs_free_session_handle(op->session_handle);
    }

}

static
void *
globus_l_gfs_data_post_transfer_event_cb(
    globus_l_gfs_data_session_t *       session_handle,
    globus_l_gfs_data_handle_t *        data_handle)
{
    void *                              remote_data_arg = NULL;

    if(data_handle == NULL)
    {
        return NULL;
    }

        switch(data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
                /* cant free until destroy cb, put in full closed state */
                data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_CLOSED;
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED:
                /* can free it */
                data_handle->state =
                    GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED;
                if(!data_handle->is_mine)
                {
                    remote_data_arg = data_handle->remote_data_arg;
                }
                if(remote_data_arg != NULL)
                {
                    session_handle->ref++;
                }
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_TE_VALID:
                data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
                /* this cant happen because TE_PRE state prevents */
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
                /* havent even gotten a close, how did this happen? */
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
            default:
                /* these shouldnt be possible */
                globus_assert(0);
                break;
        }

    return remote_data_arg;
}


static
void
globus_l_gfs_pw_free(
    struct passwd *                     pw)
{
    if(pw->pw_name != NULL)
    {
        free(pw->pw_name);
    }
    if(pw->pw_passwd != NULL)
    {
        free(pw->pw_passwd);
    }
    if(pw->pw_gecos != NULL)
    {
        free(pw->pw_gecos);
    }
    if(pw->pw_dir != NULL)
    {
        free(pw->pw_dir);
    }
    if(pw->pw_shell != NULL)
    {
        free(pw->pw_shell);
    }

    free(pw);
}

static
struct passwd *
globus_l_gfs_pw_copy(
    struct passwd *                     pw)
{
    struct passwd *                     out_pw;

    if(pw == NULL)
    {
        return NULL;
    }
    out_pw = (struct passwd *) malloc(sizeof(struct passwd));
    if(out_pw == NULL)
    {
        return NULL;
    }

    out_pw->pw_name = pw->pw_name == NULL ? NULL : strdup(pw->pw_name);
    out_pw->pw_passwd = pw->pw_passwd == NULL ? NULL : strdup(pw->pw_passwd);
    out_pw->pw_uid = pw->pw_uid;
    out_pw->pw_gid = pw->pw_gid;
    out_pw->pw_gecos = pw->pw_gecos == NULL ? NULL : strdup(pw->pw_gecos);
    out_pw->pw_dir = pw->pw_dir == NULL ? NULL : strdup(pw->pw_dir);
    out_pw->pw_shell = pw->pw_shell == NULL ? NULL : strdup(pw->pw_shell);

    return out_pw;
}

static
void
globus_l_gfs_gr_free(
    struct group *                      gr)
{
    int                                 i;

    if(gr->gr_name != NULL)
    {
        free(gr->gr_name);
    }
    if(gr->gr_passwd != NULL)
    {
        free(gr->gr_passwd);
    }
    if(gr->gr_mem != NULL)
    {
        for(i = 0; gr->gr_mem[i] != NULL; i++)
        {
            free(gr->gr_mem[i]);
        }
        free(gr->gr_mem);
    }

    free(gr);
}

static
void
globus_l_gfs_free_session_handle(
    globus_l_gfs_data_session_t *       session_handle)
{
    if(session_handle->dsi != globus_l_gfs_dsi)
    {
        globus_extension_release(session_handle->dsi_handle);
    }
    if(session_handle->username)
    {
        globus_free(session_handle->username);
    }
    if(session_handle->real_username)
    {
        globus_free(session_handle->real_username);
    }
    if(session_handle->home_dir)
    {
        globus_free(session_handle->home_dir);
    }
    if(session_handle->gid_array)
    {
        globus_free(session_handle->gid_array);
    }
    globus_handle_table_destroy(&session_handle->handle_table);
    globus_i_gfs_acl_destroy(&session_handle->acl_handle);
    globus_free(session_handle);
}

static
struct group *
globus_l_gfs_gr_copy(
    struct group *                      gr)
{
    int                                 i;
    int                                 count;
    struct group *                      gr_copy = NULL;

    gr_copy = (struct group *) malloc(sizeof(struct group));
    if(gr_copy == NULL)
    {
        return NULL;
    }
    gr_copy->gr_name = gr->gr_name == NULL ? NULL : strdup(gr->gr_name);
    gr_copy->gr_passwd = gr->gr_passwd == NULL ? NULL : strdup(gr->gr_passwd);
    gr_copy->gr_gid = gr->gr_gid;
    /* I don't think we use this one so we are better off not
        allocating memory for it */
    if(gr->gr_mem != NULL)
    {
        for(i = 0; gr->gr_mem[i] != NULL; i++)
        {
        }
        count = i+1;
        gr_copy->gr_mem = (char **)malloc(sizeof(char*)*count);
        for(i = 0; i < count-1; i++)
        {
            gr_copy->gr_mem[i] = strdup(gr->gr_mem[i]);
        }
        gr_copy->gr_mem[i] = NULL;
    }

    return gr_copy;
}

static
struct group *
globus_l_gfs_getgrnam(
    const char *                        name)
{
    struct group *                      grent;
    struct group *                      grent_copy = NULL;

    globus_libc_lock();
    grent = getgrnam(name);
    if(grent != NULL)
    {
        grent_copy = globus_l_gfs_gr_copy(grent);   
    }
    globus_libc_unlock();

    return grent_copy;
}

static
struct group *
globus_l_gfs_getgrgid(
    gid_t                               gid)
{
    struct group *                      grent;
    struct group *                      grent_copy = NULL;

    globus_libc_lock();
    grent = getgrgid(gid);
    if(grent != NULL)
    {
        grent_copy = globus_l_gfs_gr_copy(grent);   
    }
    globus_libc_unlock();

    return grent_copy;
}

static
struct passwd *
globus_l_gfs_getpwuid(
    uid_t                               uid)
{
    int                                 rc;
    char                                pw_buffer[GSC_GETPW_PWBUFSIZE];
    struct passwd                       pwent_mem;
    struct passwd *                     pw_result;
    struct passwd *                     pwent = NULL;

    rc = globus_libc_getpwuid_r(getuid(), &pwent_mem, pw_buffer,
                GSC_GETPW_PWBUFSIZE, &pw_result);
    if(rc != 0)
    {
        return NULL;
    }
    pwent = globus_l_gfs_pw_copy(&pwent_mem);

    return pwent;
}

static
struct passwd *
globus_l_gfs_getpwnam(
    const char *                        name)
{
    int                                 rc;
    char                                pw_buffer[GSC_GETPW_PWBUFSIZE];
    struct passwd                       pwent_mem;
    struct passwd *                     pw_result;
    struct passwd *                     pwent = NULL;

    rc = globus_libc_getpwnam_r(
        (char *)name, &pwent_mem, pw_buffer,GSC_GETPW_PWBUFSIZE, &pw_result);
    if(rc != 0)
    {
        return NULL;
    }

    pwent = globus_l_gfs_pw_copy(&pwent_mem);

    return pwent;
}

static
void
globus_l_gfs_blocking_dispatch_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_transfer_info_t *        transfer_info;
    globus_gfs_command_info_t *         cmd_info;
    globus_gfs_data_info_t *            data_info;
    globus_gfs_stat_info_t *            stat_info;
    GlobusGFSName(globus_l_gfs_blocking_dispatch_kickout);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;

    if(op->session_handle->dsi->descriptor & GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING)
    {
        globus_thread_blocking_will_block();
    }

    switch(op->type)
    {
        case GLOBUS_L_GFS_DATA_INFO_TYPE_COMMAND:
            cmd_info = (globus_gfs_command_info_t *) op->info_struct;
            if (cmd_info->command == GLOBUS_GFS_CMD_SITE_AUTHZ_ASSERT)
            {
                globus_gridftp_server_finished_command(
                                                op, GLOBUS_SUCCESS, NULL);
            }
            else
            {
                op->session_handle->dsi->command_func(
                    op, cmd_info, op->session_handle->session_arg);
            }
            break;

        case GLOBUS_L_GFS_DATA_INFO_TYPE_STAT:
            stat_info = op->info_struct;
            op->session_handle->dsi->stat_func(
                op, stat_info, op->session_handle->session_arg);
            break;

        case GLOBUS_L_GFS_DATA_INFO_TYPE_PASSIVE:
            data_info = (globus_gfs_data_info_t *) op->info_struct;
            op->session_handle->dsi->passive_func(
                op, data_info, op->session_handle->session_arg);
            break;

        case GLOBUS_L_GFS_DATA_INFO_TYPE_ACTIVE:
            data_info = (globus_gfs_data_info_t *) op->info_struct;
            op->session_handle->dsi->active_func(
                op, data_info, op->session_handle->session_arg);
            break;

        case GLOBUS_L_GFS_DATA_INFO_TYPE_SEND:
            transfer_info = (globus_gfs_transfer_info_t *) op->info_struct;
            op->dsi->send_func(
                op, transfer_info, op->session_handle->session_arg);
            break;

        case GLOBUS_L_GFS_DATA_INFO_TYPE_RECV:
            transfer_info = (globus_gfs_transfer_info_t *) op->info_struct;
            op->dsi->recv_func(
                op, transfer_info, op->session_handle->session_arg);
            break;

        case GLOBUS_L_GFS_DATA_INFO_TYPE_LIST:
            transfer_info = (globus_gfs_transfer_info_t *) op->info_struct;
            op->session_handle->dsi->list_func(
                op, transfer_info, op->session_handle->session_arg);
            break;

        default:
            globus_assert(0 && "possible memory corruption");
            break;
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_authorize_cb(
    globus_gfs_acl_object_desc_t *      object,
    globus_gfs_acl_action_t             action,
    void *                              user_arg,
    globus_result_t                     result)
{
    void *                              remote_data_arg = NULL;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_authorize_cb);
    GlobusGFSDebugEnter();

    if(result == GLOBUS_SUCCESS)
    {
        if(user_arg)
        {
            globus_l_gfs_blocking_dispatch_kickout(user_arg);
        }         
    }
    else
    {
        globus_gfs_finished_info_t      finished_info;
        globus_l_gfs_data_operation_t * op;

        op = (globus_l_gfs_data_operation_t *) user_arg;
        memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));

        result = GlobusGFSErrorWrapFailed(
            "authorization", result);
        finished_info.result = result;

        if(op->callback == NULL)
        {
            globus_gfs_ipc_reply_finished(
                op->ipc_handle, &finished_info);
        }
        else
        {
            op->callback(
                &finished_info,
                op->user_arg);
        }
        globus_mutex_lock(&op->session_handle->mutex);
        {
            if(op->data_handle != NULL)
            {
                switch(op->data_handle->state)
                {
                    case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                        op->data_handle->state = 
                            GLOBUS_L_GFS_DATA_HANDLE_VALID;
                        break;
        
                    case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
                        break;

                    case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
                    case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
                        if(!op->data_handle->is_mine)
                        {
                            remote_data_arg = op->data_handle->remote_data_arg;
                        }
                        break;
        
                    case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
                    case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED:
                    case GLOBUS_L_GFS_DATA_HANDLE_VALID:
                    default:
                        globus_assert(0 && "possible memory corruption");
                        break;
                }
            }
            GFSDataOpDec(op, destroy_op, destroy_session);
        }
        globus_mutex_unlock(&op->session_handle->mutex);
        globus_assert(destroy_op);

        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);

        globus_l_gfs_data_operation_destroy(op);
    }

    GlobusGFSDebugExit();
}

/*
 *  this is called when writing.  if file exists it is a write
 *  request, if it does not exists it is a create request
 */
static
void
globus_l_gfs_data_auth_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    void *                              stat_wrapper;
    globus_result_t                     res;
    globus_gfs_acl_action_t             action;
    int                                 rc;
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_transfer_info_t *        recv_info;
    globus_gfs_acl_object_desc_t        object;
    GlobusGFSName(globus_l_gfs_data_auth_stat_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;
    recv_info = (globus_gfs_transfer_info_t *) op->info_struct;

    /* if the file does not exist */
    if(reply->info.stat.stat_count == 0)
    {
        action = GFS_ACL_ACTION_CREATE;
    }
    /* if the file does exist */
    else
    {
        action = GFS_ACL_ACTION_WRITE;
    }
    object.name = recv_info->pathname;
    object.size = recv_info->alloc_size;
    stat_wrapper = op->stat_wrapper;
    rc = globus_gfs_acl_authorize(
        &op->session_handle->acl_handle,
        action,
        &object,
        &res,
        globus_l_gfs_authorize_cb,
        op);
    if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        globus_l_gfs_authorize_cb(&object, action, op, res);
    }
    globus_free(stat_wrapper);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_send_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    void *                              stat_wrapper;
    globus_result_t                     res;
    int                                 rc;
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_transfer_info_t *        send_info;
    globus_gfs_acl_object_desc_t        object;
    GlobusGFSName(globus_l_gfs_data_recv_stat_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;
    send_info = (globus_gfs_transfer_info_t *) op->info_struct;
    if(reply->info.stat.stat_count == 1)
    {
        send_info->alloc_size = reply->info.stat.stat_array[0].size;
    }

    object.name = send_info->pathname;

    stat_wrapper = op->stat_wrapper;
    rc = globus_gfs_acl_authorize(
        &op->session_handle->acl_handle,
        GFS_ACL_ACTION_READ,
        &object,
        &res,
        globus_l_gfs_authorize_cb,
        op);
    if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        globus_l_gfs_authorize_cb(
            &object, GFS_ACL_ACTION_READ, op, res);
    }
    globus_free(stat_wrapper);

    GlobusGFSDebugExit();
}

void
globus_i_gfs_monitor_init(
    globus_i_gfs_monitor_t *            monitor)
{
    GlobusGFSName(globus_i_gfs_monitor_init);
    GlobusGFSDebugEnter();

    globus_mutex_init(&monitor->mutex, NULL);
    globus_cond_init(&monitor->cond, NULL);
    monitor->done = GLOBUS_FALSE;

    GlobusGFSDebugExit();
}

static
globus_gfs_storage_iface_t *
globus_i_gfs_data_new_dsi(
    globus_extension_handle_t *         dsi_handle,
    const char *                        dsi_name)
{
    globus_gfs_storage_iface_t *        new_dsi;
    int                                 rc;
    GlobusGFSName(globus_i_gfs_data_new_dsi);
    GlobusGFSDebugEnter();

    /* see if we already have this name loaded, if so use it */
    new_dsi = (globus_gfs_storage_iface_t *) globus_extension_lookup(
        dsi_handle, GLOBUS_GFS_DSI_REGISTRY, (void *) dsi_name);
    if(new_dsi == NULL)
    {
        /* if not already load it, activate it */
        char                            buf[256];

        snprintf(buf, 256, "globus_gridftp_server_%s", dsi_name);
        buf[255] = 0;

        rc = globus_extension_activate(buf);
        if(rc != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_ERR, 
                "Unable to activate %s: %s\n", 
                buf,
                globus_error_print_friendly(
                    globus_error_peek((globus_result_t) rc)));
        }
        else
        {
            new_dsi = (globus_gfs_storage_iface_t *)
                globus_extension_lookup(
                    dsi_handle,
                    GLOBUS_GFS_DSI_REGISTRY,
                    (void *) dsi_name);
        }
    }

    GlobusGFSDebugExit();
    return new_dsi;
}

static
globus_gfs_storage_iface_t *
globus_l_gfs_data_new_dsi(
    globus_l_gfs_data_session_t *       session_handle,
    const char *                        in_module_name)
{
    const char *                        module_name;
    GlobusGFSName(globus_l_gfs_data_new_dsi);
    GlobusGFSDebugEnter();

    if(in_module_name == NULL || *in_module_name == '\0')
    {
        GlobusGFSDebugExit();
        return session_handle->dsi;
    }
    if(!(session_handle->dsi->descriptor & GLOBUS_GFS_DSI_DESCRIPTOR_SENDER))
    {
        goto type_error;
    }

    module_name = globus_i_gfs_config_get_module_name(in_module_name);
    if(module_name == NULL)
    {
        goto type_error;
    }
    /* if there was a prevous loaded module */
    if(session_handle->mod_dsi_name != NULL)
    {
        /* if there was a last module and it is this one use it */
        if(strcmp(module_name, session_handle->mod_dsi_name) != 0)
        {
            globus_free(session_handle->mod_dsi_name);
            globus_extension_release(session_handle->mod_dsi_handle);

            session_handle->mod_dsi_name = globus_libc_strdup(module_name);
            session_handle->mod_dsi = globus_i_gfs_data_new_dsi(
                &session_handle->mod_dsi_handle,
                session_handle->mod_dsi_name);
            if(session_handle->mod_dsi == NULL)
            {
                goto error;
            }
        }
    }
    else
    {
        session_handle->mod_dsi_name =  globus_libc_strdup(module_name);
        session_handle->mod_dsi = globus_i_gfs_data_new_dsi(
            &session_handle->mod_dsi_handle,
            session_handle->mod_dsi_name);
        if(session_handle->mod_dsi == NULL)
        {
            goto error;
        }
    }

    GlobusGFSDebugExit();
    return session_handle->mod_dsi;

error:
    globus_free(session_handle->mod_dsi_name);
type_error:
    GlobusGFSDebugExitWithError();
    return NULL;
}


static
void
globus_l_gfs_data_auth_init_cb(
    globus_gfs_acl_object_desc_t *      object,
    globus_gfs_acl_action_t             action,
    void *                              user_arg,
    globus_result_t                     result)
{
    void *                              remote_data_arg = NULL;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_session_info_t *         session_info;
    globus_gfs_finished_info_t          finished_info;
    GlobusGFSName(globus_l_gfs_data_auth_init_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;
    session_info = (globus_gfs_session_info_t *) op->info_struct;

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    op->session_handle->username = globus_libc_strdup(session_info->username);

    if(op->session_handle->dsi->init_func != NULL)
    {
        op->session_handle->dsi->init_func(op, session_info);
    }
    else
    {
        finished_info.result = GLOBUS_SUCCESS;
        finished_info.info.session.session_arg = op->session_handle;
        finished_info.info.session.username = session_info->username;
        finished_info.info.session.home_dir = op->session_handle->home_dir;

        if(op->callback == NULL)
        {
            globus_gfs_ipc_reply_session(
                op->ipc_handle, &finished_info);
        }
        else
        {

            op->callback(
                &finished_info,
                op->user_arg);
        }
        globus_mutex_lock(&op->session_handle->mutex);
        {
            GFSDataOpDec(op, destroy_op, destroy_session);

            remote_data_arg = globus_l_gfs_data_check(
                op->session_handle,
                op->data_handle);
        }
        globus_mutex_unlock(&op->session_handle->mutex);
        globus_assert(destroy_op);

        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);

        globus_l_gfs_data_operation_destroy(op);
    }

    GlobusGFSDebugExit();
    return;

error:
    finished_info.result = result;
    finished_info.info.session.session_arg = NULL;

    if(op->callback == NULL)
    {
        globus_gfs_ipc_reply_session(
            op->ipc_handle, &finished_info);
    }
    else
    {
        op->callback(
            &finished_info,
            op->user_arg);
    }
    globus_mutex_lock(&op->session_handle->mutex);
    {
        /* dec session handle now since we won't get a stop_session */
        op->session_handle->ref--;
        GFSDataOpDec(op, destroy_op, destroy_session);
        remote_data_arg = globus_l_gfs_data_check(
            op->session_handle, op->data_handle);
    }
    globus_mutex_unlock(&op->session_handle->mutex);
    globus_assert(destroy_op);
    globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
    globus_l_gfs_data_operation_destroy(op);
    GlobusGFSDebugExitWithError();
}


static
void
globus_l_gfs_data_authorize(
    globus_l_gfs_data_operation_t *     op,
    const gss_ctx_id_t                  context,
    globus_gfs_session_info_t *         session_info)
{
    void *                              remote_data_arg = NULL;
    int                                 rc;
    globus_result_t                     res;
    int                                 gid;
    char *                              pw_file;
    char *                              usr;
    char *                              grp;
    char *                              pw_hash;
    char                                authz_usr[USER_NAME_MAX];
    struct passwd *                     pwent = NULL;
    struct group *                      grent = NULL;
    int                                 auth_level;
    GlobusGFSName(globus_l_gfs_data_authorize);
    GlobusGFSDebugEnter();

    auth_level = globus_i_gfs_config_int("auth_level");
    pw_file = (char *) globus_i_gfs_config_string("pw_file");
    /* if there is a del cred we are using gsi, look it up in the gridmap */
    if(session_info->del_cred != NULL)
    {
        if(!(auth_level & GLOBUS_L_GFS_AUTH_NOGRIDMAP))
        {
            if(context != NULL)
            {
                if(session_info->map_user)
                {
                    usr = NULL;
                }
                else
                {
                    usr = session_info->username;
                }
    
                *authz_usr = '\0';            
                res = globus_gss_assist_map_and_authorize(
                    context,
                    FTP_SERVICE_NAME,
                    usr,
                    authz_usr,
                    USER_NAME_MAX);
                if(res != GLOBUS_SUCCESS)
                {
                    goto pwent_error;
                }
                /* if res=success and authz_usr is empty, assume usr is ok
                 * and some callout just didn't copy it to authz_usr */
                if(*authz_usr != '\0')
                {
                    usr = authz_usr;
                
                    if(session_info->username)
                    {
                        globus_free(session_info->username);
                    }
                    session_info->username = globus_libc_strdup(usr);
                }
            }
            else
            {
                if(session_info->map_user)
                {
                    rc = globus_gss_assist_gridmap(
                        (char *) session_info->subject, &usr);
                    if(rc != 0)
                    {
                        GlobusGFSErrorGenericStr(res, 
                            ("Gridmap lookup failure: unable to map '%s'.", 
                            session_info->subject));
                        goto pwent_error;
                    }
                }
                else
                {
                    rc = globus_gss_assist_userok(
                        session_info->subject, session_info->username);
                    usr = session_info->username;
                    if(rc != 0)
                    {
                        GlobusGFSErrorGenericStr(res,
                            ("Gridmap lookup failure: "
                            "unable to map '%s' to '%s'.", 
                            session_info->subject,
                            session_info->username));
                        goto pwent_error;
                    }
                }
                if(session_info->username)
                {
                    globus_free(session_info->username);
                }
                session_info->username = globus_libc_strdup(usr);
            }
        }
        else
        {
            if(session_info->map_user == GLOBUS_TRUE ||
                session_info->username == NULL)
            {
                pwent = globus_l_gfs_getpwuid(getuid());
                if(pwent == NULL)
                {
                    res = GlobusGFSErrorGeneric(
                        "Invalid passwd entry for current user.");
                    goto pwent_error;
                }
                if(session_info->username)
                {
                    globus_free(session_info->username);
                }
                session_info->username = globus_libc_strdup(pwent->pw_name);
            }
        }

        if(pwent == NULL)
        {            
            if(auth_level & GLOBUS_L_GFS_AUTH_NOSETUID)
            {
                pwent = globus_l_gfs_getpwuid(getuid());
                if(pwent == NULL)
                {
                    res = GlobusGFSErrorGeneric(
                        "Invalid passwd entry for current user.");
                    goto pwent_error;
                }
            }
            else
            {
                pwent = globus_l_gfs_getpwnam(session_info->username);
                if(pwent == NULL)
                {
                    GlobusGFSErrorGenericStr(res,
                        ("Mapped user '%s' is invalid.",
                        session_info->username));
                    goto pwent_error;
                }
            }
        }
        
        gid = pwent->pw_gid;
        grent = globus_l_gfs_getgrgid(gid);
        if(grent == NULL)
        {
            GlobusGFSErrorGenericStr(res,
                ("Invalid group id assigned to user '%s'.",
                session_info->username));
            goto pwent_error;
        }
    }
    /* if anonymous use and we are allowing it */
    else if(globus_i_gfs_config_bool("allow_anonymous") &&
        globus_i_gfs_config_is_anonymous(session_info->username))
    {
        /* if we are root, set to anon user */
        if(getuid() == 0)
        {
            usr = globus_i_gfs_config_string("anonymous_user");
            if(usr == NULL)
            {
                res = GlobusGFSErrorGeneric("No anonymous user set.");
                goto pwent_error;
            }
            pwent = globus_l_gfs_getpwnam(usr);
            if(pwent == NULL)
            {
                res = GlobusGFSErrorGeneric("Invalid anonymous user set.");
                goto pwent_error;
            }
            grp = globus_i_gfs_config_string("anonymous_group");
            if(grp == NULL)
            {
                grent = globus_l_gfs_getgrgid(pwent->pw_gid);
                if(grent == NULL)
                {
                    res = GlobusGFSErrorGeneric(
                        "Invalid group id assigned to anonymous user.");
                    goto pwent_error;
                }
            }
            else
            {
                grent = globus_l_gfs_getgrnam(grp);
                if(grent == NULL)
                {
                    res = GlobusGFSErrorGeneric(
                        "Invalid anonymous group set.");
                    goto pwent_error;
                }
            }
            gid = grent->gr_gid;
        }
        /* if not root, just run as is */
        else
        {
            pwent = globus_l_gfs_getpwuid(getuid());
            if(pwent == NULL)
            {
                res = GlobusGFSErrorGeneric(
                    "Invalid passwd entry for current user.");
                goto pwent_error;
            }
            gid = pwent->pw_gid;
            grent = globus_l_gfs_getgrgid(pwent->pw_gid);
            if(grent == NULL)
            {
                res = GlobusGFSErrorGeneric(
                    "Invalid group id assigned to current user.");
                goto pwent_error;
            }
        }

        /* since this is anonymous change the user name */
        op->session_handle->real_username = globus_libc_strdup(pwent->pw_name);
        if(pwent->pw_name != NULL)
        {
            globus_free(pwent->pw_name);
        }
        pwent->pw_name = strdup("anonymous");
        if(grent->gr_name != NULL)
        {
            globus_free(grent->gr_name);
        }
        grent->gr_name = strdup("anonymous");
    }
    else if(pw_file != NULL)
    {
        /* if we have not yet looked it up for this user */
        if(globus_l_gfs_data_pwent == NULL)
        {
#           ifdef HAVE_FGETPWENT
            {
                FILE * pw = fopen(pw_file, "r");
                if(pw == NULL)
                {
                    res = GlobusGFSErrorGeneric(
                        "Invalid passwd file set.");
                    goto pwent_error;
                }

                globus_libc_lock();
                do
                {
                    pwent = fgetpwent(pw);
                }
                while(pwent != NULL &&
                    strcmp(pwent->pw_name, session_info->username) != 0);
                fclose(pw);

                if(pwent == NULL)
                {
                    globus_libc_unlock();
                    res = GlobusGFSErrorGeneric("Invalid user.");
                    goto pwent_error;
                }
                globus_l_gfs_data_pwent = globus_l_gfs_pw_copy(pwent);
                globus_libc_unlock();
            }
#           else
            {
                res = GlobusGFSErrorGeneric("Passwd file not supported.");
                goto pwent_error;
            }
#endif
        }
        else
        {
            /* if already looked up (and setuid()) use global value */
            if(strcmp(pwent->pw_name, session_info->username) != 0)
            {
                res = GlobusGFSErrorGeneric(
                    "Invalid user for current session.");
                goto pwent_error;
            }
        }
        pwent = globus_l_gfs_pw_copy(globus_l_gfs_data_pwent);
        grent = globus_l_gfs_getgrgid(pwent->pw_gid);
        if(grent == NULL)
        {
            GlobusGFSErrorGenericStr(res,
                ("Invalid group id assigned to user '%s'.",
                session_info->username));
            goto pwent_error;
        }
        pw_hash = DES_crypt(session_info->password, pwent->pw_passwd);
        if(strcmp(pw_hash, pwent->pw_passwd) != 0)
        {
            res = GlobusGFSErrorGeneric("Invalid user.");
            goto pwent_error;
        }
        gid = pwent->pw_gid;
    }
    else
    {
        res = GlobusGFSErrorGeneric("Access denied by configuration.");
        goto pwent_error;
    }

    /* change process ids */
    if(!(auth_level & GLOBUS_L_GFS_AUTH_NOSETUID))
    {
        rc = setgid(gid);
        if(rc != 0)
        {
            res = GlobusGFSErrorGeneric(
                "Unable to set the gid of the server process.");
            goto uid_error;
        }
        if(getuid() == 0)
        {
            char *                          name;
            if(op->session_handle->real_username == NULL)
            {
                name = pwent->pw_name;
            }
            else
            {
                name = op->session_handle->real_username;
            }
            rc = initgroups(name, gid);
            if(rc != 0)
            {
                res = GlobusGFSErrorGeneric(
                    "Unable to set the supplemental groups of the server "
                    "process.");
                goto uid_error;
            }
        }
        rc = setuid(pwent->pw_uid);
        if(rc != 0)
        {
            res = GlobusGFSErrorGeneric(
                "Unable to set the uid of the server process.");
            goto uid_error;
        }
    }
    op->session_handle->uid = pwent->pw_uid;
    op->session_handle->gid_count = getgroups(0, NULL);
    op->session_handle->gid_array = (gid_t *) globus_malloc(
        op->session_handle->gid_count * sizeof(gid_t));
    getgroups(op->session_handle->gid_count, op->session_handle->gid_array);

    if(pwent->pw_dir != NULL)
    {
        op->session_handle->home_dir = strdup(pwent->pw_dir);
    }
    if(op->session_handle->real_username == NULL)
    {
        op->session_handle->real_username = globus_libc_strdup(pwent->pw_name);
    }
    
    rc = globus_i_gfs_acl_init(
        &op->session_handle->acl_handle,
        context,
        session_info->subject,
        session_info->username,
        session_info->password,
        session_info->host_id,
        &res,
        globus_l_gfs_data_auth_init_cb,
        op);
    if(rc < 0)
    {
        res = GlobusGFSErrorGeneric(
            "ACL initialization error.");
        goto acl_error;
    }
    else if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        globus_l_gfs_data_auth_init_cb(NULL, GFS_ACL_ACTION_INIT, op, res);
    }

    globus_l_gfs_pw_free(pwent);
    globus_l_gfs_gr_free(grent);

    GlobusGFSDebugExit();
    return;

acl_error:
uid_error:
pwent_error:
    if(pwent != NULL)
    {
        globus_l_gfs_pw_free(pwent);
    }
    if(grent)
    {
        globus_l_gfs_gr_free(grent);
    }
    {
        globus_bool_t                   destroy_session = GLOBUS_FALSE;
        globus_bool_t                   destroy_op = GLOBUS_FALSE;
        globus_gfs_finished_info_t      finished_info;
        memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));

        finished_info.result = res;
        finished_info.info.session.session_arg = NULL;

        if(op->callback == NULL)
        {
            globus_gfs_ipc_reply_session(
                op->ipc_handle, &finished_info);
        }
        else
        {
            op->callback(
                &finished_info,
                op->user_arg);
        }

        globus_mutex_lock(&op->session_handle->mutex);
        {
            /* dec session handle now since we won't get a stop_session */
            op->session_handle->ref--;
            GFSDataOpDec(op, destroy_op, destroy_session);
            remote_data_arg = globus_l_gfs_data_check(
                op->session_handle, op->data_handle);
        }
        globus_mutex_unlock(&op->session_handle->mutex);
        globus_assert(destroy_op);
        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
        globus_l_gfs_data_operation_destroy(op);
    }
    GlobusGFSDebugExitWithError();
}

void
globus_i_gfs_data_init()
{
    char *                              dsi_name;
    int                                 rc;
    GlobusGFSName(globus_i_gfs_data_init);
    GlobusGFSDebugEnter();

    dsi_name = globus_i_gfs_config_string("load_dsi_module");

    globus_extension_register_builtins(local_extensions);

    globus_l_gfs_dsi = (globus_gfs_storage_iface_t *) globus_extension_lookup(
        &globus_i_gfs_active_dsi_handle, GLOBUS_GFS_DSI_REGISTRY, dsi_name);
    if(!globus_l_gfs_dsi)
    {
        char                            buf[256];

        snprintf(buf, 256, "globus_gridftp_server_%s", dsi_name);
        buf[255] = 0;
        rc = globus_extension_activate(buf);
        if(rc != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_ERR, 
                "Unable to activate %s: %s\n", 
                buf,
                globus_error_print_friendly(
                    globus_error_peek((globus_result_t) rc)));
            exit(1);
        }

        globus_l_gfs_dsi = (globus_gfs_storage_iface_t *) globus_extension_lookup(
            &globus_i_gfs_active_dsi_handle, GLOBUS_GFS_DSI_REGISTRY, dsi_name);
    }

    if(!globus_l_gfs_dsi)
    {
        globus_i_gfs_log_message(
           GLOBUS_I_GFS_LOG_ERR, "Couldn't find the %s extension\n", dsi_name);
        exit(1);
    }

    /* XXX is this is how we want to know this? */
    globus_l_gfs_data_is_remote_node = globus_i_gfs_config_bool("data_node");
    
    {
        char *                          str_transferred;

        str_transferred = (char *) globus_calloc(1, 256);
        sprintf(str_transferred, "0 bytes");
        globus_mutex_init(&globus_l_gfs_global_counter_lock, NULL);
        globus_gfs_config_set_ptr("byte_transfer_count", str_transferred);
    }
    GlobusGFSDebugExit();
}

static
globus_result_t
globus_l_gfs_data_operation_init(
    globus_l_gfs_data_operation_t **    u_op,
    globus_l_gfs_data_session_t *       session_handle)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_data_operation_init);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *)
        globus_calloc(1, sizeof(globus_l_gfs_data_operation_t));
    if(!op)
    {
        result = GlobusGFSErrorMemory("op");
        goto error_alloc;
    }

    op->session_handle = session_handle;
    op->ref = 1;
    globus_mutex_lock(&op->session_handle->mutex);
    {
        op->session_handle->ref++;
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    globus_range_list_init(&op->recvd_ranges);
    globus_range_list_init(&op->stripe_range_list);
    op->recvd_bytes = 0;
    op->max_offset = -1;

    *u_op = op;

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_alloc:
    GlobusGFSDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_data_operation_destroy(
    globus_l_gfs_data_operation_t *     op)
{
    GlobusGFSName(globus_l_gfs_data_operation_destroy);
    GlobusGFSDebugEnter();

    globus_range_list_destroy(op->recvd_ranges);
    globus_range_list_destroy(op->stripe_range_list);
    if(op->pathname)
    {
        globus_free(op->pathname);
    }
    if(op->cksm_response)
    {
        globus_free(op->cksm_response);
    }
    if(op->remote_ip)
    {
        globus_free(op->remote_ip);
    }
    if(op->list_type)
    {
        globus_free((char *) op->list_type);
    }
    if(op->eof_count != NULL)
    {
        globus_free(op->eof_count);
    }

    globus_free(op);

    GlobusGFSDebugExit();
}


void
globus_i_gfs_data_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_stat_info_t *            stat_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    int                                 rc;
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_session_t *       session_handle;
    globus_gfs_acl_object_desc_t        object;
    GlobusGFSName(globus_i_gfs_data_request_stat);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    result = globus_l_gfs_data_operation_init(&op, session_handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }

    op->ipc_handle = ipc_handle;
    op->id = id;
    op->uid = getuid();

    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->callback = cb;
    op->user_arg = user_arg;
    op->session_handle = session_handle;
    op->info_struct = stat_info;
    op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_STAT;

    object.name = stat_info->pathname;
    
    if(stat_info->internal)
    {
        res = GLOBUS_SUCCESS;
        rc = GLOBUS_GFS_ACL_COMPLETE;
    }
    else
    {
        rc = globus_gfs_acl_authorize(
            &session_handle->acl_handle,
            GFS_ACL_ACTION_LOOKUP,
            &object,
            &res,
            globus_l_gfs_authorize_cb,
            op);
    }
    if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        /* this should possibly be a one shot */
        globus_l_gfs_authorize_cb(
            &object, GFS_ACL_ACTION_LOOKUP, op, res);
    }

    GlobusGFSDebugExit();
    return;

error_op:
    globus_l_gfs_authorize_cb(
        &object, GFS_ACL_ACTION_LOOKUP, op, result);
    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_data_stat_kickout(
    void *                              user_arg)
{
    void *                              remote_data_arg = NULL;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_l_gfs_data_stat_bounce_t *   bounce_info;
    globus_gfs_finished_info_t          reply;
    int                                 i;
    GlobusGFSName(globus_l_gfs_data_stat_kickout);
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_stat_bounce_t *) user_arg;

    memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));

    reply.type = GLOBUS_GFS_OP_STAT;
    reply.id = bounce_info->op->id;
    reply.result = bounce_info->error ?
        globus_error_put(bounce_info->error) : GLOBUS_SUCCESS;
    reply.info.stat.stat_array =  bounce_info->stat_array;
    reply.info.stat.stat_count =  bounce_info->stat_count;
    reply.info.stat.uid = bounce_info->op->session_handle->uid;
    reply.info.stat.gid_count = bounce_info->op->session_handle->gid_count;
    reply.info.stat.gid_array = bounce_info->op->session_handle->gid_array;

    if(bounce_info->op->callback != NULL)
    {
        bounce_info->op->callback(
            &reply,
            bounce_info->op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            bounce_info->op->ipc_handle,
            &reply);
    }

    globus_mutex_lock(&bounce_info->op->session_handle->mutex);
    {
        GFSDataOpDec(bounce_info->op, destroy_op, destroy_session);
        remote_data_arg = globus_l_gfs_data_check(
            bounce_info->op->session_handle, bounce_info->op->data_handle);
    }
    globus_mutex_unlock(&bounce_info->op->session_handle->mutex);

    globus_assert(destroy_op);
    globus_l_gfs_data_fire_cb(
        bounce_info->op, remote_data_arg, destroy_session);
    globus_l_gfs_data_operation_destroy(bounce_info->op);
    if(bounce_info->stat_array)
    {
        for(i = 0; i < bounce_info->stat_count; i++)
        {
            if(bounce_info->stat_array[i].name != NULL)
            {
                globus_free(bounce_info->stat_array[i].name);
            }        
            if(bounce_info->stat_array[i].symlink_target != NULL)
            {
                globus_free(bounce_info->stat_array[i].symlink_target);
            }
        }
        globus_free(bounce_info->stat_array);
    }
    globus_free(bounce_info);

    GlobusGFSDebugExit();
}

void
globus_i_gfs_data_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_command_info_t *         cmd_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    int                                 rc;
    globus_gfs_acl_action_t             action;
    globus_bool_t                       call = GLOBUS_TRUE;
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_extension_handle_t           new_dsi_handle;
    globus_gfs_storage_iface_t *        new_dsi;
    globus_l_gfs_data_session_t *       session_handle;
    char *                              dsi_name;
    globus_gfs_acl_object_desc_t        object;
    GlobusGFSName(globus_i_gfs_data_request_command);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    result = globus_l_gfs_data_operation_init(&op, session_handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    op->ipc_handle = ipc_handle;
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->command = cmd_info->command;
    op->pathname = globus_libc_strdup(cmd_info->pathname);
    op->callback = cb;
    op->user_arg = user_arg;
    op->info_struct = cmd_info;
    op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_COMMAND;
    dsi_name = cmd_info->pathname;
    object.name = op->pathname;
    
    switch(cmd_info->command)
    {
        case GLOBUS_GFS_CMD_SITE_DSI:
            if(session_handle->dsi->descriptor & GLOBUS_GFS_DSI_DESCRIPTOR_SENDER)
            {
                new_dsi = globus_i_gfs_data_new_dsi(&new_dsi_handle, dsi_name);

                /* if we couldn't load it, error */
                if(new_dsi == NULL)
                {
                    result = GlobusGFSErrorGeneric("no such DSI");
                }
                /* if it is the wrong type release and error */
                else if(
                    !(new_dsi->descriptor & GLOBUS_GFS_DSI_DESCRIPTOR_SENDER))
                {
                    result = GlobusGFSErrorGeneric("DSI isn't a sender.");
                }
                /* if all is well */
                else
                {
                    /* if not the global default release the reference */
                    if(session_handle->dsi != globus_l_gfs_dsi)
                    {
                        globus_extension_release(session_handle->dsi_handle);
                    }
                    /* set to new dsi */
                    session_handle->dsi_handle = new_dsi_handle;
                    op->session_handle->dsi = new_dsi;
                    result = GLOBUS_SUCCESS;
                }
                call = GLOBUS_FALSE;

                globus_gridftp_server_finished_command(op, result, NULL);
            }
            break;

        case GLOBUS_GFS_CMD_DELE:
        case GLOBUS_GFS_CMD_SITE_RDEL:
            action = GFS_ACL_ACTION_DELETE;
            break;

        case GLOBUS_GFS_CMD_RNTO:
            action = GFS_ACL_ACTION_WRITE;
            break;

        case GLOBUS_GFS_CMD_RMD:
            action = GFS_ACL_ACTION_DELETE;
            break;

        case GLOBUS_GFS_CMD_RNFR:
            action = GFS_ACL_ACTION_DELETE;
            break;

        case GLOBUS_GFS_CMD_CKSM:
            action = GFS_ACL_ACTION_READ;
            break;

        case GLOBUS_GFS_CMD_MKD:
            action = GFS_ACL_ACTION_CREATE;
            break;

        case GLOBUS_GFS_CMD_SITE_CHMOD:
            action = GFS_ACL_ACTION_WRITE;
            break;

        case GLOBUS_GFS_CMD_SITE_AUTHZ_ASSERT:
            /*
             * A new action to provide authorization assertions received
             * over the control channel to the authorization callout
             */
            object.name = cmd_info->authz_assert;
            action = GFS_ACL_ACTION_AUTHZ_ASSERT;
            rc = globus_gfs_acl_authorize(
                &session_handle->acl_handle,
                action,
                &object,
                &res,
                globus_l_gfs_authorize_cb,
                op);
            if(rc == GLOBUS_GFS_ACL_COMPLETE)
            {
                globus_l_gfs_authorize_cb(
                    &object, action, op, res);
            }
            call = GLOBUS_FALSE;
            break;

        default:
            break;
    }

    if(call)
    {
        rc = globus_gfs_acl_authorize(
            &session_handle->acl_handle,
            action,
            &object,
            &res,
            globus_l_gfs_authorize_cb,
            op);
        if(rc == GLOBUS_GFS_ACL_COMPLETE)
        {
            globus_l_gfs_authorize_cb(&object, action, op, res);
        }
    }

    GlobusGFSDebugExit();
    return;

error_op:
    globus_l_gfs_authorize_cb(&object, action, op, result);
    GlobusGFSDebugExitWithError();
}

static
globus_result_t
globus_l_gfs_data_handle_init(
    globus_l_gfs_data_handle_t **       u_handle,
    globus_gfs_data_info_t *            data_info)
{
    int                                 tcp_mem_limit;
    globus_l_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_dcau_t           dcau;
    char *                              interface;
    globus_bool_t                       use_interface = GLOBUS_FALSE;
    GlobusGFSName(globus_l_gfs_data_handle_init);
    GlobusGFSDebugEnter();

    handle = (globus_l_gfs_data_handle_t *)
        globus_calloc(1, sizeof(globus_l_gfs_data_handle_t));
    if(!handle)
    {
        result = GlobusGFSErrorMemory("handle");
        goto error_alloc;
    }

    if((interface = globus_i_gfs_config_string("data_interface")) != NULL)
    {
        if(data_info->interface != NULL)
        {
            globus_free(data_info->interface);
        }
        data_info->interface = globus_libc_strdup(interface);
        use_interface = GLOBUS_TRUE;
    }
    memcpy(&handle->info, data_info, sizeof(globus_gfs_data_info_t));

    result = globus_ftp_control_handle_init(&handle->data_channel);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_handle_init", result);
        goto error_data;
    }

    handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
    handle->outstanding_op = NULL;
    handle->use_interface = use_interface;

    if(0 && !globus_l_gfs_data_is_remote_node)
    {
        /* this is too restrictive... if they connect to the server via ipv6
         * doesnt mean they know about ipv6 servers... this ends up requiring
         * that they use ipv6 commands
         */
        result = globus_ftp_control_data_set_interface(
            &handle->data_channel, handle->info.interface);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_data_set_interface", result);
            goto error_control;
        }
    }

    result = globus_ftp_control_local_mode(
        &handle->data_channel, handle->info.mode);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_mode", result);
        goto error_control;
    }

    result = globus_ftp_control_local_type(
        &handle->data_channel, handle->info.type, 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_type", result);
        goto error_control;
    }

    if(handle->info.tcp_bufsize > 0)
    {
        globus_ftp_control_tcpbuffer_t  tcpbuffer;

        tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
        tcpbuffer.fixed.size = handle->info.tcp_bufsize;

        result = globus_ftp_control_local_tcp_buffer(
            &handle->data_channel, &tcpbuffer);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_tcp_buffer", result);
            goto error_control;
        }
    }

    if(handle->info.mode == 'S')
    {
        handle->info.nstreams = 1;
    }
    else
    {
        globus_ftp_control_parallelism_t  parallelism;

        globus_assert(handle->info.mode == 'E');

        parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
        parallelism.fixed.size = handle->info.nstreams;

        result = globus_ftp_control_local_parallelism(
            &handle->data_channel, &parallelism);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_parallelism", result);
            goto error_control;
        }

        result = globus_ftp_control_local_send_eof(
            &handle->data_channel, GLOBUS_FALSE);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_send_eof", result);
            goto error_control;
        }
    }

    tcp_mem_limit = globus_gfs_config_get_int("tcp_mem_limit");
    if(tcp_mem_limit > 0 && tcp_mem_limit < handle->info.tcp_bufsize)
    {
        globus_ftp_control_tcpbuffer_t  tcpbuffer;

        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_WARN,
            "Limiting TCP memory to: %d on %d\n",
            tcp_mem_limit, handle->info.nstreams);
        tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
        tcpbuffer.fixed.size = tcp_mem_limit / handle->info.nstreams;

        result = globus_ftp_control_local_tcp_buffer(
            &handle->data_channel, &tcpbuffer);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_tcp_buffer", result);
            goto error_control;
        }

    }

    dcau.mode = handle->info.dcau;
    dcau.subject.mode = handle->info.dcau;
    dcau.subject.subject = handle->info.subject;
    result = globus_ftp_control_local_dcau(
        &handle->data_channel, &dcau, handle->info.del_cred);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_local_dcau", result);
        goto error_control;
    }
    if(handle->info.dcau != 'N')
    {
        result = globus_ftp_control_local_prot(
            &handle->data_channel, handle->info.prot);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_prot", result);
            goto error_control;
        }
    }
    if(handle->info.ipv6)
    {
        result = globus_ftp_control_ipv6_allow(
            &handle->data_channel, GLOBUS_TRUE);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_ipv6_allow", result);
            goto error_control;
        }
    }
    {
        result = globus_l_gfs_set_stack(handle);
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_WARN,
                "set stack failed: %s\n",
                globus_error_print_friendly(globus_error_peek(result)));
        }
    }

    *u_handle = handle;

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_control:
    globus_ftp_control_handle_destroy(&handle->data_channel);

error_data:
    globus_free(handle);

error_alloc:
    GlobusGFSDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_data_abort_kickout(
    void *                              user_arg)
{
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_bool_t                       start_finish = GLOBUS_FALSE;
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_event_info_t             event_info;
    GlobusGFSName(globus_l_gfs_data_abort_kickout);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;

    if(op->session_handle->dsi->trev_func != NULL &&
        op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT
        /* && op->data_handle->is_mine XXX don't think this matters here */
        )
    {
        event_info.type = GLOBUS_GFS_EVENT_TRANSFER_ABORT;
        event_info.event_arg = op->event_arg;
        op->session_handle->dsi->trev_func(
            &event_info,
            op->session_handle->session_arg);
    }

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->state)
        {
            /* if finished was called while waiting for this */
            case GLOBUS_L_GFS_DATA_FINISH:
                start_finish = GLOBUS_TRUE;
                break;

            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                op->state = GLOBUS_L_GFS_DATA_ABORTING;
                break;

            case GLOBUS_L_GFS_DATA_CONNECTING:
            case GLOBUS_L_GFS_DATA_CONNECTED:
            case GLOBUS_L_GFS_DATA_REQUESTING:
            case GLOBUS_L_GFS_DATA_ABORTING:
            case GLOBUS_L_GFS_DATA_COMPLETING:
            case GLOBUS_L_GFS_DATA_COMPLETE:
            default:
                globus_assert(0 && "bad state, possible memory corruption");
                break;
        }
        GFSDataOpDec(op, destroy_op, destroy_session);
        globus_assert(!destroy_op && !destroy_session);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(start_finish)
    {
        globus_l_gfs_data_end_transfer_kickout(op);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_fc_return(
    globus_l_gfs_data_operation_t *     op)
{
    GlobusGFSName(globus_l_gfs_data_fc_return);

    GlobusGFSDebugEnter();

    switch(op->data_handle->state)
    {
        case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
            op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED;
            break;

        case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
            /* ok free it */
            globus_l_gfs_data_handle_free(op->data_handle);
            op->data_handle = NULL;
            break;

        case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
        case GLOBUS_L_GFS_DATA_HANDLE_VALID:
        case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
        case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
        default:
            globus_assert(0 && "possible memory corruption");
            break;
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_complete_fc_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    void *                              remote_data_arg = NULL;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_gfs_event_info_t             event_info;
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_complete_fc_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) callback_arg;

    memset(&event_info, '\0', sizeof(globus_gfs_event_info_t));

    globus_mutex_lock(&op->session_handle->mutex);
    {
        globus_l_gfs_data_fc_return(callback_arg);

        GFSDataOpDec(op, destroy_op, destroy_session);
        if(destroy_op)
        {
            globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING &&
                op->data_handle != NULL);
            remote_data_arg = globus_l_gfs_data_check(
                op->session_handle, op->data_handle);
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(destroy_op)
    {
        if(op->session_handle->dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {   /* XXX should make our own */

            /* AAAA */
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
            event_info.event_arg = op->event_arg;
            op->session_handle->dsi->trev_func(
                &event_info,
                op->session_handle->session_arg);

            globus_mutex_lock(&op->session_handle->mutex);
            {
                remote_data_arg = globus_l_gfs_data_post_transfer_event_cb(
                    op->session_handle, op->data_handle);
            }
            globus_mutex_unlock(&op->session_handle->mutex);
        }
        /* destroy the op */
        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
        globus_l_gfs_data_operation_destroy(op);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_finish_fc_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_finish_fc_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) callback_arg;

    globus_mutex_lock(&op->session_handle->mutex);
    {
        globus_l_gfs_data_fc_return(callback_arg);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    globus_l_gfs_data_end_transfer_kickout(callback_arg);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_abort_fc_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_abort_fc_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) callback_arg;

    globus_mutex_lock(&op->session_handle->mutex);
    {
        globus_l_gfs_data_fc_return(op);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    globus_l_gfs_data_abort_kickout(callback_arg);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_destroy_cb(
    void *                              callback_arg,
    globus_ftp_control_handle_t *       ftp_handle,
    globus_object_t *                   error)
{
    globus_bool_t                       free_session = GLOBUS_FALSE;
    globus_bool_t                       free_data = GLOBUS_FALSE;
    globus_l_gfs_data_session_t *       session_handle;
    globus_l_gfs_data_handle_t *        data_handle;
    GlobusGFSName(globus_l_gfs_data_destroy_cb);
    GlobusGFSDebugEnter();

    data_handle = (globus_l_gfs_data_handle_t *) callback_arg;
    session_handle = data_handle->session_handle;

    globus_mutex_lock(&session_handle->mutex);
    {
        session_handle->ref--;
        if(session_handle->ref == 0)
        {
            free_session = GLOBUS_TRUE;
        }
        switch(data_handle->state)
        {
            /* destroy did come from server-lib so clean it up */
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
                free_data = GLOBUS_TRUE;
                break;

            /* someone else got to it first */
            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
                break;

            /* none of these are possible */            
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }

    }
    globus_mutex_unlock(&session_handle->mutex);

    if(free_data)
    {
        globus_l_gfs_data_handle_free(data_handle);
    }
    if(free_session)
    {
        if(session_handle->dsi->destroy_func != NULL)
        {
            session_handle->dsi->destroy_func(
                session_handle->session_arg);
        }

        if(session_handle->dsi != globus_l_gfs_dsi)
        {
            globus_extension_release(session_handle->dsi_handle);
        }

        globus_l_gfs_free_session_handle(session_handle);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_handle_free(
    globus_l_gfs_data_handle_t *    data_handle)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusGFSName(globus_l_gfs_data_handle_free);
    GlobusGFSDebugEnter();

    globus_assert(
        data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_CLOSED_AND_DESTROYED ||
        data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED);

/*    if(data_handle->outstanding_op == NULL)
*/    {
        if(data_handle->is_mine && 
            data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED)
        {            
            result = globus_ftp_control_handle_destroy(
                &data_handle->data_channel);
            if(result != GLOBUS_SUCCESS)
            {
                /* assert maybe, this should never fail 
                 * we're probably leaking the data channel mem */
            }
        }    
        if(result == GLOBUS_SUCCESS)
        {
            globus_free(data_handle);
        }
    }

    GlobusGFSDebugExit();
}

/* don't pass unless requested */
/*
 */
void
globus_i_gfs_data_request_handle_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              in_session_arg,
    void *                              data_arg)
{
    globus_bool_t                       free_it = GLOBUS_FALSE;
    globus_bool_t                       rc;
    void *                              session_arg;
    globus_bool_t                       pass = GLOBUS_FALSE;
    globus_result_t                     result;
    globus_l_gfs_data_session_t *       session_handle;
    globus_l_gfs_data_handle_t *        data_handle;
    int                                 old_state_dbg;
    GlobusGFSName(globus_i_gfs_data_request_handle_destroy);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) in_session_arg;

    session_handle->data_handle = NULL;

    globus_mutex_lock(&session_handle->mutex);
    {
        data_handle = (globus_l_gfs_data_handle_t *) globus_handle_table_lookup(
            &session_handle->handle_table, (int) data_arg);
        if(data_handle == NULL)
        {
            globus_assert(0);
        }
        rc = globus_handle_table_decrement_reference(
            &session_handle->handle_table, (int) data_arg);
        globus_assert(!rc);

        data_handle->destroy_requested = GLOBUS_TRUE;

        old_state_dbg = data_handle->state;
        session_arg = session_handle->session_arg;
        switch(data_handle->state)
        {
            /* not being used in a transfer o jsut clean it up */
            case GLOBUS_L_GFS_DATA_HANDLE_TE_VALID:
            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
                if(!data_handle->is_mine)
                {
                    if(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_TE_VALID)
                    {
                        data_handle->state =
                            GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED;
                    }
                    else
                    { 
                        pass = GLOBUS_TRUE;
                        free_it = GLOBUS_TRUE;
                        data_handle->state =
                            GLOBUS_L_GFS_DATA_HANDLE_CLOSED_AND_DESTROYED;
                    }
                }
                else
                {
                    data_handle->state =
                        GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED;
                    session_handle->ref++;
                    /* set directly to closed so that when callback
                        returns we clean it up */
                    result = globus_ftp_control_data_force_close(
                        &data_handle->data_channel,
                        globus_l_gfs_data_destroy_cb,
                        data_handle);
                    if(result != GLOBUS_SUCCESS)
                    {
                        data_handle->state =
                            GLOBUS_L_GFS_DATA_HANDLE_CLOSED_AND_DESTROYED;
                        pass = GLOBUS_TRUE;
                        session_handle->ref--;

                        /* we should be able to set it to free here, however
                            due to inadequecies in the control_data lib we
                            must let it leak. The control_data lib has no 
                            way to know when it is safe to free the mem
                            associated with its handle unless force close
                            works, thus the leak.
                        free_it = GLOBUS_TRUE;
                        */
                    }
                }
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                globus_assert(data_handle->outstanding_op != NULL);
                globus_l_gfs_data_start_abort(data_handle->outstanding_op);
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
                data_handle->state =
                    GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED;
                break;


            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
                data_handle->state =
                    GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED;
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
                if(!data_handle->is_mine)
                {
                    pass = GLOBUS_TRUE;
                    data_handle->state =
                        GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED;
                }
                else
                {
                    data_handle->state =
                        GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED;
                    /* now i can free it */
                    free_it = GLOBUS_TRUE;
                }
                break;

            /* we shouldn't get this callback twice */
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
                globus_assert(0 && "got destroyed callback twice");
                break;
            default:
                globus_assert(0 && "likey memory corruption");
                break;
        }
    }
    globus_mutex_unlock(&session_handle->mutex);
    if(pass)
    {
        if(session_handle->dsi->data_destroy_func != NULL)
        {
            session_handle->dsi->data_destroy_func(
                data_handle->remote_data_arg, session_arg);
        }
        else
        {
            /* XXX dsi impl error, what to do? */
        }
    }
    if(free_it)
    {
        globus_l_gfs_data_handle_free(data_handle);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_passive_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    globus_gfs_finished_info_t              reply;
    GlobusGFSName(globus_l_gfs_data_passive_kickout);
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_passive_bounce_t *) user_arg;

    memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));
    reply.type = GLOBUS_GFS_OP_PASSIVE;
    reply.id = bounce_info->id;
    reply.result = bounce_info->result;
    reply.info.data.contact_strings = (const char **)
        globus_calloc(1, sizeof(char *));
    reply.info.data.contact_strings[0] = bounce_info->contact_string;
    reply.info.data.bi_directional = bounce_info->bi_directional;
    reply.info.data.cs_count = 1;

    /* as soon as we finish the data handle can be in play, set its
        state appropriately.  if not success then we never created a
        handle */
    if(bounce_info->result == GLOBUS_SUCCESS)
    {
        bounce_info->handle->is_mine = GLOBUS_TRUE;
        bounce_info->handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;

        reply.info.data.data_arg = (void *) globus_handle_table_insert(
            &bounce_info->handle->session_handle->handle_table,
            bounce_info->handle,
            1);
    }
    else
    {
        globus_assert(bounce_info->handle == NULL);
    }

    if(bounce_info->callback != NULL)
    {
        bounce_info->callback(
            &reply,
            bounce_info->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            bounce_info->ipc_handle,
            &reply);
    }

    globus_free(reply.info.data.contact_strings);
    /* could be null on error */
    if(bounce_info->contact_string != NULL)
    {
        globus_free(bounce_info->contact_string);
    }
    globus_free(bounce_info);

    GlobusGFSDebugExit();
}

/*
 *
 *  NOTE: if bounce struct can't be allocated we fail. This should be
 *        corrected at some point, possibly by preaalocating a bunch in
 *        in a globus_memory_t.
 */
void
globus_i_gfs_data_request_passive(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_handle_t *        handle = NULL;
    globus_result_t                     result;
    globus_ftp_control_host_port_t      address;
    globus_sockaddr_t                   addr;
    char *                              cs;
    globus_l_gfs_data_passive_bounce_t * bounce_info;
    globus_l_gfs_data_operation_t *     op;
    globus_l_gfs_data_session_t *       session_handle;
    globus_bool_t                       ipv6_addr = GLOBUS_FALSE;
    GlobusGFSName(globus_i_gfs_data_request_passive);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    if(session_handle->dsi->passive_func != NULL)
    {
        result = globus_l_gfs_data_operation_init(&op, session_handle);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_operation_init", result);
            goto error_op;
        }

        op->ipc_handle = ipc_handle;
        op->id = id;
        op->state = GLOBUS_L_GFS_DATA_REQUESTING;
        op->callback = cb;
        op->user_arg = user_arg;
        op->session_handle = session_handle;
        op->info_struct = data_info;
        op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_PASSIVE;
        if(session_handle->dsi->descriptor & GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING)
        {
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_blocking_dispatch_kickout,
                op);
        }
        else
        {
            session_handle->dsi->passive_func(
                op, data_info, session_handle->session_arg);
        }
    }
    else
    {
        if(data_info->del_cred == NULL)
        {
            data_info->del_cred = session_handle->del_cred;
        }
        result = globus_l_gfs_data_handle_init(&handle, data_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_handle_init", result);
            goto error_handle;
        }
        handle->session_handle = session_handle;
        
        handle->info.cs_count = 1;
        /* prevent address lookup, we know what we want */
        address.host[0] = 1; 
        address.port = 0;
        result = globus_ftp_control_local_pasv(&handle->data_channel, &address);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_ftp_control_local_pasv", result);
            goto error_control;
        }

        /* XXX This needs to be smarter.  The address should be the same one
         * the user is connected to on the control channel (at least when
         * operating as a normal standalone server)
         */
        /* its ok to use AF_INET here since we are requesting the LOCAL
         * address.  we just use AF_INET to store the port
         */
        if(handle->info.interface && 
            (!globus_l_gfs_data_is_remote_node || handle->use_interface))
        {
            ipv6_addr = (strchr(handle->info.interface, ':') != NULL);
        }

        if((globus_l_gfs_data_is_remote_node && !handle->use_interface) ||
            (ipv6_addr && !handle->info.ipv6) || 
            handle->info.interface == NULL)
        {
            GlobusLibcSockaddrSetFamily(addr, AF_INET);
            GlobusLibcSockaddrSetPort(addr, address.port);
            result = globus_libc_addr_to_contact_string(
                &addr,
                GLOBUS_LIBC_ADDR_LOCAL | GLOBUS_LIBC_ADDR_NUMERIC |
                    (handle->info.ipv6 ? 0 : GLOBUS_LIBC_ADDR_IPV4),
                &cs);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_libc_addr_to_contact_string", result);
                goto error_control;
            }
        }
        else
        {
            if(ipv6_addr)
            {
                cs = globus_common_create_string(
                    "[%s]:%d", handle->info.interface, (int) address.port);
            }
            else
            {
                cs = globus_common_create_string(
                    "%s:%d", handle->info.interface, (int) address.port);
            }
        }
        
        bounce_info = (globus_l_gfs_data_passive_bounce_t *)
            globus_calloc(1, sizeof(globus_l_gfs_data_passive_bounce_t));
        if(!bounce_info)
        {
            result = GlobusGFSErrorMemory("bounce_info");
            globus_panic(NULL, result, "small malloc failure, no recovery");
        }

        bounce_info->result = GLOBUS_SUCCESS;
        bounce_info->ipc_handle = ipc_handle;
        bounce_info->id = id;
        bounce_info->handle = handle;
        bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
        bounce_info->contact_string = cs;
        bounce_info->callback = cb;
        bounce_info->user_arg = user_arg;

        session_handle->data_handle = handle;

        result = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_data_passive_kickout,
            bounce_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_callback_register_oneshot", result);
            globus_panic(NULL, result, "small malloc failure, no recovery");
        }
    }

    GlobusGFSDebugExit();
    return;

error_control:
    globus_ftp_control_handle_destroy(&handle->data_channel);
    globus_free(handle);
    handle = NULL;

error_handle:
error_op:

    bounce_info = (globus_l_gfs_data_passive_bounce_t *)
        globus_calloc(1, sizeof(globus_l_gfs_data_passive_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        globus_panic(NULL, result, "small malloc failure, no recovery");
    }
    bounce_info->ipc_handle = ipc_handle;
    bounce_info->id = id;
    bounce_info->handle = handle;
    bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
    bounce_info->callback = cb;
    bounce_info->user_arg = user_arg;
    bounce_info->result = result;
    bounce_info->handle = NULL;
    result = globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_gfs_data_passive_kickout,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        globus_panic(NULL, result, "small malloc failure, no recovery");
    }

    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_data_active_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_active_bounce_t * bounce_info;
    globus_gfs_finished_info_t              reply;
    GlobusGFSName(globus_l_gfs_data_active_kickout);
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_active_bounce_t *) user_arg;

    memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));
    reply.type = GLOBUS_GFS_OP_ACTIVE;
    reply.id = bounce_info->id;
    reply.result = bounce_info->result;
    reply.info.data.bi_directional = bounce_info->bi_directional;

    /* as soon as we finish the data handle can be in play, set its
        state appropriately.  if not success then we never created a
        handle */
    if(bounce_info->result == GLOBUS_SUCCESS)
    {
        bounce_info->handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
        bounce_info->handle->is_mine = GLOBUS_TRUE;

        reply.info.data.data_arg = (void *) globus_handle_table_insert(
            &bounce_info->handle->session_handle->handle_table,
            bounce_info->handle,
            1);
    }
    else
    {
        globus_assert(bounce_info->handle == NULL);
    }

    if(bounce_info->callback != NULL)
    {
        bounce_info->callback(
            &reply,
            bounce_info->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            bounce_info->ipc_handle,
            &reply);
    }

    globus_free(bounce_info);

    GlobusGFSDebugExit();
}

void
globus_i_gfs_data_request_active(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_handle_t *        handle;
    globus_result_t                     result;
    globus_ftp_control_host_port_t *    addresses;
    int                                 i;
    globus_l_gfs_data_active_bounce_t * bounce_info;
    globus_l_gfs_data_operation_t *     op;
    globus_l_gfs_data_session_t *       session_handle;
    GlobusGFSName(globus_i_gfs_data_request_active);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    if(session_handle->dsi->active_func != NULL)
    {
        result = globus_l_gfs_data_operation_init(&op, session_handle);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_operation_init", result);
            goto error_op;
        }

        op->ipc_handle = ipc_handle;
        op->id = id;
        op->state = GLOBUS_L_GFS_DATA_REQUESTING;
        op->callback = cb;
        op->user_arg = user_arg;
        op->session_handle = session_handle;
        op->info_struct = data_info;
        op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_ACTIVE;
        if(session_handle->dsi->descriptor & GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING)
        {
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_blocking_dispatch_kickout,
                op);
        }
        else
        {
            session_handle->dsi->active_func(
                op, data_info, session_handle->session_arg);
        }
    }
    else
    {
        if(data_info->del_cred == NULL)
        {
            data_info->del_cred = session_handle->del_cred;
        }
        result = globus_l_gfs_data_handle_init(&handle, data_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_l_gfs_data_handle_init", result);
            goto error_handle;
        }
        handle->session_handle = session_handle;
        addresses = (globus_ftp_control_host_port_t *)
            globus_malloc(sizeof(globus_ftp_control_host_port_t) *
                data_info->cs_count);
        if(!addresses)
        {
            result = GlobusGFSErrorMemory("addresses");
            goto error_addresses;
        }

        for(i = 0; i < data_info->cs_count; i++)
        {
            result = globus_libc_contact_string_to_ints(
                data_info->contact_strings[i],
                addresses[i].host,  &addresses[i].hostlen, &addresses[i].port);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_libc_contact_string_to_ints", result);
                goto error_format;
            }
        }

        if(data_info->cs_count == 1)
        {
            result = globus_ftp_control_local_port(
                &handle->data_channel, addresses);
        }
        else
        {
            result = globus_ftp_control_local_spor(
                &handle->data_channel, addresses, data_info->cs_count);
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
            globus_panic(NULL, result, "small malloc failure, no recovery");
        }

        bounce_info->ipc_handle = ipc_handle;
        bounce_info->id = id;
        bounce_info->handle = handle;
        bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
        bounce_info->callback = cb;
        bounce_info->user_arg = user_arg;
        bounce_info->result = GLOBUS_SUCCESS;

        session_handle->data_handle = handle;

        result = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_data_active_kickout,
            bounce_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_callback_register_oneshot", result);
            globus_panic(NULL, result, "small malloc failure, no recovery");
        }

        globus_free(addresses);
    }

    GlobusGFSDebugExit();
    return;

error_control:
error_format:
    globus_free(addresses);
error_addresses:
    globus_ftp_control_handle_destroy(&handle->data_channel);
    globus_free(handle);
    handle = NULL;
error_handle:
error_op:
    bounce_info = (globus_l_gfs_data_active_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_active_bounce_t));
    if(!bounce_info)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        globus_panic(NULL, result, "small malloc failure, no recovery");
    }
    bounce_info->ipc_handle = ipc_handle;
    bounce_info->id = id;
    bounce_info->handle = handle;
    bounce_info->bi_directional = GLOBUS_TRUE; /* XXX MODE S only */
    bounce_info->callback = cb;
    bounce_info->user_arg = user_arg;
    bounce_info->result = result;
    bounce_info->handle = NULL;
    result = globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_gfs_data_active_kickout,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        globus_panic(NULL, result, "small malloc failure, no recovery");
    }

    GlobusGFSDebugExitWithError();
}


void
globus_i_gfs_data_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_transfer_info_t *        recv_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_gfs_stat_info_t *            stat_info;
    globus_l_gfs_data_session_t *       session_handle;
    GlobusGFSName(globus_i_gfs_data_request_recv);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    data_handle = (globus_l_gfs_data_handle_t *) globus_handle_table_lookup(
        &session_handle->handle_table, (int) recv_info->data_arg);
    if(data_handle == NULL)
    {
        result = GlobusGFSErrorData("Data handle not found");
        goto error_handle;
    }
    
    if(!data_handle->is_mine)
    {
        recv_info->data_arg = data_handle->remote_data_arg;
    }

    result = globus_l_gfs_data_operation_init(&op, session_handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    globus_assert(data_handle->outstanding_op == NULL);
    data_handle->outstanding_op = op;
    
    op->ipc_handle = ipc_handle;
    op->session_handle = session_handle;
    op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_RECV;
    op->info_struct = recv_info;
    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->writing = GLOBUS_FALSE;
    op->data_handle = data_handle;
    op->data_arg = recv_info->data_arg;
    op->range_list = recv_info->range_list;
    op->partial_offset = recv_info->partial_offset;
    op->callback = cb;
    op->event_callback = event_cb;
    op->user_arg = user_arg;
    op->node_ndx = recv_info->node_ndx;
    session_handle->node_ndx = recv_info->node_ndx;
    op->node_count = recv_info->node_count;
    op->stripe_count = recv_info->stripe_count;
    /* events and disconnects cannot happen while i am in this
        function */
    globus_assert(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID);
    data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INUSE;

    op->dsi = globus_l_gfs_data_new_dsi(session_handle, recv_info->module_name);
    if(op->dsi == NULL)
    {
        globus_gridftp_server_finished_transfer(
            op, GlobusGFSErrorGeneric("bad module"));
        goto error_module;
    }
    if(op->dsi->stat_func != NULL)
    {
    stat_info = (globus_gfs_stat_info_t *)
        globus_calloc(1, sizeof(globus_gfs_stat_info_t));

    stat_info->pathname = recv_info->pathname;
    stat_info->file_only = GLOBUS_TRUE;
    stat_info->internal = GLOBUS_TRUE;

    op->info_struct = recv_info;
    op->stat_wrapper = stat_info;

    globus_i_gfs_data_request_stat(
        ipc_handle,
        session_handle,
        id,
        stat_info,
        globus_l_gfs_data_auth_stat_cb,
        op);
    }
    else
    {
        globus_gfs_acl_object_desc_t    object;
        object.name = recv_info->pathname;
        object.size = recv_info->alloc_size;
        result = GLOBUS_SUCCESS;
        globus_l_gfs_authorize_cb(
            &object, GFS_ACL_ACTION_WRITE, op, result);
    }
    GlobusGFSDebugExit();
    return;

error_module:
error_op:
error_handle:
    globus_gridftp_server_finished_transfer(op, result);
    GlobusGFSDebugExitWithError();
}


void
globus_i_gfs_data_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_transfer_info_t *        send_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    int                                 rc;
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_l_gfs_data_session_t *       session_handle;
    globus_gfs_acl_object_desc_t        object;
    GlobusGFSName(globus_i_gfs_data_send_request);
    GlobusGFSDebugEnter();
    
    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    data_handle = (globus_l_gfs_data_handle_t *) globus_handle_table_lookup(
        &session_handle->handle_table, (int) send_info->data_arg);
    if(data_handle == NULL)
    {
        result = GlobusGFSErrorData(_FSSL("Data handle not found",NULL));
        goto error_handle;
    }
    if(!data_handle->is_mine)
    {
        send_info->data_arg = data_handle->remote_data_arg;
    }

    result = globus_l_gfs_data_operation_init(&op, session_handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    globus_assert(data_handle->outstanding_op == NULL);
    data_handle->outstanding_op = op;

    op->ipc_handle = ipc_handle;
    op->session_handle = session_handle;
    op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_SEND;
    op->info_struct = send_info;

    op->id = id;
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->writing = GLOBUS_TRUE;
    op->data_handle = data_handle;
    op->data_arg = send_info->data_arg;
    op->range_list = send_info->range_list;
    op->partial_length = send_info->partial_length;
    op->partial_offset = send_info->partial_offset;
    op->callback = cb;
    op->event_callback = event_cb;
    op->user_arg = user_arg;
    op->node_ndx = send_info->node_ndx;
    session_handle->node_ndx = send_info->node_ndx;
    op->write_stripe = 0;
    op->stripe_chunk = send_info->node_ndx;
    op->node_count = send_info->node_count;
    op->stripe_count = send_info->stripe_count;
    op->eof_count = (int *) globus_calloc(1, op->stripe_count * sizeof(int));

    /* events and disconnects cannot happen while i am in this
        function */
    globus_assert(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID);
    data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INUSE;

    op->dsi = globus_l_gfs_data_new_dsi(session_handle, send_info->module_name);
    if(op->dsi == NULL)
    {
        globus_gridftp_server_finished_transfer(
            op, GlobusGFSErrorGeneric("bad module"));
        goto error_module;
    }
    if(op->dsi->stat_func != NULL && 
        op->data_handle->info.stripe_layout == GLOBUS_GFS_LAYOUT_PARTITIONED)
    {
        globus_gfs_stat_info_t *        stat_info;
        
        stat_info = (globus_gfs_stat_info_t *)
            globus_calloc(1, sizeof(globus_gfs_stat_info_t));
    
        stat_info->pathname = send_info->pathname;
        stat_info->file_only = GLOBUS_TRUE;
        stat_info->internal = GLOBUS_TRUE;
    
        op->info_struct = send_info;
        op->stat_wrapper = stat_info;
    
        globus_i_gfs_data_request_stat(
            ipc_handle,
            session_handle,
            id,
            stat_info,
            globus_l_gfs_data_send_stat_cb,
            op);
    }
    else
    {
        object.name = send_info->pathname;
        rc = globus_gfs_acl_authorize(
            &session_handle->acl_handle,
            GFS_ACL_ACTION_READ,
            &object,
            &res,
            globus_l_gfs_authorize_cb,
            op);
        if(rc == GLOBUS_GFS_ACL_COMPLETE)
        {
            globus_l_gfs_authorize_cb(
                &object, GFS_ACL_ACTION_READ, op, res);
        }
    }
    GlobusGFSDebugExit();
    return;

error_module:
error_op:
error_handle:
    globus_gridftp_server_finished_transfer(op, result);
    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_data_list_write_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_gfs_data_stat_bounce_t *   bounce_info;

    GlobusGFSName(globus_l_gfs_data_list_write_cb);
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_stat_bounce_t *) user_arg;

    if(!bounce_info)
    {
        globus_gridftp_server_control_list_buffer_free(buffer);
    }
    else 
    {
        if(bounce_info->free_buffer)
        {
            globus_free(bounce_info->list_response);
        }
        globus_free(bounce_info);
    }
        
    globus_gridftp_server_finished_transfer(op, result);

    GlobusGFSDebugExit();
}



static
void
globus_l_gfs_data_list_stat_cb(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg)
{
    globus_gfs_operation_t   op;
    globus_byte_t *                     list_buffer;
    globus_size_t                       buffer_len;
    globus_l_gfs_data_bounce_t *        bounce_info;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_data_list_stat_cb);
    GlobusGFSDebugEnter();

    op = (globus_gfs_operation_t) user_arg;
    bounce_info = (globus_l_gfs_data_bounce_t *) op->user_arg;

    globus_free(op->stat_wrapper);
    if(reply->result != GLOBUS_SUCCESS)
    {
        result = reply->result;
        goto error;
    }

    result = globus_gridftp_server_control_list_buffer_alloc(
            op->list_type,
            op->uid,
            reply->info.stat.stat_array,
            reply->info.stat.stat_count,
            &list_buffer,
            &buffer_len);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
           "globus_gridftp_server_control_list_buffer_alloc", result);
        goto error;
    }

    globus_gridftp_server_begin_transfer(op, 0, NULL);

    result = globus_gridftp_server_register_write(
        op,
        list_buffer,
        buffer_len,
        0,
        -1,
        globus_l_gfs_data_list_write_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_gridftp_server_register_write", result);
        goto error;
    }

    GlobusGFSDebugExit();
    return;

error:
    globus_gridftp_server_finished_transfer(op, result);
    GlobusGFSDebugExitWithError();
}

void
globus_gridftp_server_finished_stat_custom_list(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     list_response,
    globus_size_t                       list_response_len,
    globus_bool_t                       free_buffer)
{
    globus_l_gfs_data_bounce_t *        bounce_info;
    globus_l_gfs_data_operation_t *     data_op;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    GlobusGFSName(globus_gridftp_server_finished_stat_custom_list);
    GlobusGFSDebugEnter();

    data_op = (globus_l_gfs_data_operation_t *) op->user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    bounce_info = (globus_l_gfs_data_stat_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_stat_bounce_t));
    if(bounce_info == NULL)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error;
    }

    bounce_info->free_buffer = free_buffer;
    if(free_buffer)
    {
        bounce_info->list_response = list_response;
    }
    else
    {
        bounce_info->list_response = globus_malloc(list_response_len);
        memcpy(bounce_info->list_response, list_response, list_response_len);
    }

    globus_gridftp_server_begin_transfer(data_op, 0, NULL);

    result = globus_gridftp_server_register_write(
        data_op,
        bounce_info->list_response,
        list_response_len,
        0,
        -1,
        globus_l_gfs_data_list_write_cb,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_gridftp_server_register_write", result);
        goto error;
    }

    globus_mutex_lock(&op->session_handle->mutex);
    {
        GFSDataOpDec(op, destroy_op, destroy_session);
    }
    globus_mutex_unlock(&op->session_handle->mutex);
    globus_assert(destroy_op);
    globus_l_gfs_data_operation_destroy(op, destroy_session);

    globus_free(data_op->stat_wrapper);

    GlobusGFSDebugExit();
    return;

error:
    globus_gridftp_server_finished_transfer(data_op, result);
    GlobusGFSDebugExitWithError();
}

void
globus_i_gfs_data_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_transfer_info_t *        list_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg)
{
    int                                 rc;
    globus_result_t                     res;
    globus_l_gfs_data_operation_t *     data_op;
    globus_result_t                     result;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_gfs_stat_info_t *            stat_info;
    globus_l_gfs_data_session_t *       session_handle;
    globus_gfs_acl_object_desc_t        object;
    GlobusGFSName(globus_i_gfs_data_request_list);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    data_handle = (globus_l_gfs_data_handle_t *) globus_handle_table_lookup(
        &session_handle->handle_table, (int) list_info->data_arg);
    if(data_handle == NULL)
    {
        result = GlobusGFSErrorData(_FSSL("Data handle not found",NULL));
        goto error_handle;
    }
    if(!data_handle->is_mine)
    {
        list_info->data_arg = data_handle->remote_data_arg;
    }

    result = globus_l_gfs_data_operation_init(&data_op, session_handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_data_operation_init", result);
        goto error_op;
    }
    globus_assert(data_handle->outstanding_op == NULL);
    data_handle->outstanding_op = data_op;

    data_op->ipc_handle = ipc_handle;
    data_op->session_handle = session_handle;
    data_op->type = GLOBUS_L_GFS_DATA_INFO_TYPE_LIST;
    data_op->info_struct = list_info;

    data_op->id = id;
    data_op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    data_op->writing = GLOBUS_TRUE;
    data_op->data_handle = data_handle;
    data_op->data_arg = list_info->data_arg;
    data_op->list_type = strdup(list_info->list_type);
    data_op->uid = getuid();
    /* XXX */
    data_op->callback = cb;
    data_op->event_callback = event_cb;
    data_op->user_arg = user_arg;
    data_op->node_ndx = list_info->node_ndx;
    data_op->write_stripe = 0;
    data_op->stripe_chunk = list_info->node_ndx;
    data_op->node_count = list_info->node_count;
    data_op->stripe_count = list_info->stripe_count;
    data_op->eof_count = (int *)
        globus_calloc(1, data_op->stripe_count * sizeof(int));

    /* events and disconnects cannot happen while i am in this
        function */
    globus_assert(data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID);
    data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_INUSE;

    if(session_handle->dsi->list_func != NULL)
    {
        object.name = list_info->pathname;
        rc = globus_gfs_acl_authorize(
            &session_handle->acl_handle,
            GFS_ACL_ACTION_LOOKUP,
            &object,
            &res,
            globus_l_gfs_authorize_cb,
            data_op);
        if(rc == GLOBUS_GFS_ACL_COMPLETE)
        {
            globus_l_gfs_authorize_cb(
                &object, GFS_ACL_ACTION_LOOKUP, data_op, res);
        }
    }
    else
    {
        stat_info = (globus_gfs_stat_info_t *)
            globus_calloc(1, sizeof(globus_gfs_stat_info_t));

        stat_info->pathname = list_info->pathname;
        stat_info->file_only = GLOBUS_FALSE;

        data_op->info_struct = list_info;
        data_op->stat_wrapper = stat_info;

        globus_i_gfs_data_request_stat(
            ipc_handle,
            session_handle,
            id,
            stat_info,
            globus_l_gfs_data_list_stat_cb,
            data_op);
    }

    GlobusGFSDebugExit();
    return;

error_handle:
error_op:
    globus_gridftp_server_finished_transfer(data_op, result);
    GlobusGFSDebugExitWithError();
}

/***********************************************************************
 *  finished transfer callbacks
 *  ---------------------------
 **********************************************************************/
static
void
globus_l_gfs_data_finish_connected(
    globus_l_gfs_data_operation_t *     op)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusGFSName(globus_l_gfs_data_finish_connected);
    GlobusGFSDebugEnter();

    if(op->data_handle->is_mine)
    {
        if(op->writing)
        {
            if(op->node_ndx != 0 ||
                op->stripe_count == 1 ||
                op->eof_ready)
            {
                result = globus_ftp_control_data_write(
                    &op->data_handle->data_channel,
                    "",
                    0,
                    0,
                    GLOBUS_TRUE,
                    globus_l_gfs_data_write_eof_cb,
                    op);
                if(result != GLOBUS_SUCCESS)
                {
                    globus_i_gfs_log_result_warn(
                        "write_eof error", result);
                    op->cached_res = result;
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_data_end_transfer_kickout,
                        op);
                }
            }
        }
        else
        {
            globus_callback_register_oneshot(
                NULL,
                NULL,
                globus_l_gfs_data_end_read_kickout,
                op);
        }
    }
    else
    {
                if(op->data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID)
                {
                    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_VALID;
                }
        globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gfs_data_end_transfer_kickout,
            op);
    }
    
    GlobusGFSDebugExit();
}


static
void
globus_l_gfs_data_begin_cb(
    void *                              callback_arg,
    struct globus_ftp_control_handle_s * handle,
    unsigned int                        stripe_ndx,
    globus_bool_t                       reused,
    globus_object_t *                   error)
{
    globus_result_t                     res;
    int                                 rcvbuf;
    int                                 sndbuf;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_bool_t                       dec_op = GLOBUS_FALSE;
    globus_bool_t                       connect_event = GLOBUS_FALSE;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_gfs_event_info_t        event_reply;
    globus_gfs_event_info_t             event_info;
    globus_l_gfs_data_operation_t *     op;
    globus_l_gfs_data_handle_state_t    last_state;
    void *                              remote_data_arg = NULL;
    GlobusGFSName(globus_l_gfs_data_begin_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) callback_arg;

    globus_mutex_lock(&op->session_handle->mutex);
    {
        last_state = op->state;
        switch(op->state)
        {
            case GLOBUS_L_GFS_DATA_CONNECTING:
                op->stripe_connections_pending--;
                globus_assert(op->ref > 0);

                if(error != NULL)
                {
                    /* something wrong, start the abort process */
                    op->cached_res =
                        globus_error_put(globus_object_copy(error));
                    goto err_lock;
                }
                if(!op->stripe_connections_pending)
                {
                    dec_op = GLOBUS_TRUE;
                    /* everything is well, send the begin event */
                    op->state = GLOBUS_L_GFS_DATA_CONNECT_CB;
                    connect_event = GLOBUS_TRUE;
                }
                break;
            /* this happens when a finished comes right after a begin,
                usually because 0 bytes were written.  we need to send
                the transfer_connected event and then finish. */
            case GLOBUS_L_GFS_DATA_FINISH_WITH_ERROR:
            case GLOBUS_L_GFS_DATA_FINISH:
                op->stripe_connections_pending--;
                if(!op->stripe_connections_pending)
                {
                    dec_op = GLOBUS_TRUE;
                    /* everything is well, send the begin event */
                    connect_event = GLOBUS_TRUE;

                    /* if the fished was delayed, and was not started
                        via abort process, the start the finish after
                        the unlock */
                    finish = op->finished_delayed;
                }

                globus_assert(op->ref > 1);

                break;

            /* this happens when a transfer is aborted before a connection
                is esstablished.  it could be in this state
                depending on how quickly the abort process happens.  */
            case GLOBUS_L_GFS_DATA_ABORTING:
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                dec_op = GLOBUS_TRUE;
                globus_assert(op->ref > 1);
                break;
                /* we need to dec the reference count and clean up if needed.
                also we ignore the error value here, it is likely canceled */
            case GLOBUS_L_GFS_DATA_COMPLETING:
                dec_op = GLOBUS_TRUE;
                if(op->ref == 1)
                {
                    op->state = GLOBUS_L_GFS_DATA_COMPLETE;
                }
                break;

            case GLOBUS_L_GFS_DATA_COMPLETE:
            case GLOBUS_L_GFS_DATA_CONNECTED:
            case GLOBUS_L_GFS_DATA_CONNECT_CB:
            case GLOBUS_L_GFS_DATA_REQUESTING:
            default:
                globus_assert(0 && "not possible state.  memory corruption");
                break;
        }
        if(connect_event && op->data_handle->is_mine)
        {
            res = globus_ftp_control_data_get_socket_buf(
                &op->data_handle->data_channel,
                &rcvbuf,
                &sndbuf);
            if(res != GLOBUS_SUCCESS)
            {
                char * tmp_err_str = 
                    globus_error_print_friendly(globus_error_peek(res));
                globus_i_gfs_log_message(
                    GLOBUS_I_GFS_LOG_WARN,
                    "Buffer size may not be properly set: %s\n",
                    tmp_err_str);
                free(tmp_err_str);
            }
            if(op->writing)
            {
                if(rcvbuf != op->data_handle->info.tcp_bufsize
                    && res == GLOBUS_SUCCESS)
                {
                    globus_i_gfs_log_message(
                        GLOBUS_I_GFS_LOG_WARN,
                        "RECV buffer size may not be properly set.  "
                        "Requested size = %d, actualy size = %d\n",
                        op->data_handle->info.tcp_bufsize, rcvbuf);
                }
                op->data_handle->info.tcp_bufsize = rcvbuf;
            }
            else
            {
                if(res != GLOBUS_SUCCESS)
                {
                    globus_i_gfs_log_message(
                        GLOBUS_I_GFS_LOG_WARN,
                        "Request to get socket buffer size failed\n");
                }
                else
                {
                    if(sndbuf != op->data_handle->info.tcp_bufsize)
                    {
                        globus_i_gfs_log_message(
                            GLOBUS_I_GFS_LOG_WARN,
                            "SEND buffer size may not be properly set.  "
                            "Requested size = %d, actualy size = %d\n",
                            op->data_handle->info.tcp_bufsize, sndbuf);
                    }
                    op->data_handle->info.tcp_bufsize = sndbuf;
                }
            }

            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO,
                "Starting to transfer \"%s\".\n", 
                    ((globus_gfs_transfer_info_t *) op->info_struct)->pathname);
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(connect_event && op->data_handle->is_mine)
    {
        globus_ftp_control_host_port_t  remote_addr;
        int                             remote_addr_count = 1;

        memset(&remote_addr, '\0', sizeof(globus_ftp_control_host_port_t));
        globus_ftp_control_data_get_remote_hosts(
              &op->data_handle->data_channel,
              &remote_addr,
              &remote_addr_count);
        op->remote_ip = globus_common_create_string(
            "%d.%d.%d.%d",
            remote_addr.host[0], remote_addr.host[1],
            remote_addr.host[2], remote_addr.host[3]);

        memset(&event_reply, '\0', sizeof(globus_gfs_event_info_t));
        event_reply.type = GLOBUS_GFS_EVENT_TRANSFER_CONNECTED;
        event_reply.id = op->id;
        event_reply.event_arg = op;
        if(op->event_callback != NULL)
        {
            op->event_callback(&event_reply, op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(op->ipc_handle, &event_reply);
        }

        if(!op->writing && op->data_handle->info.mode == 'E')
        {   
            /* send first 0 byte marker */
            event_reply.type = GLOBUS_GFS_EVENT_BYTES_RECVD;
            event_reply.recvd_bytes = op->recvd_bytes;
            event_reply.node_ndx = op->node_ndx;
            if(op->event_callback != NULL)
            {
                op->event_callback(&event_reply, op->user_arg);
            }
            else
            {
                globus_gfs_ipc_reply_event(op->ipc_handle, &event_reply);
            }
        }
    }
    globus_mutex_lock(&op->session_handle->mutex);
    {
        if(op->state == GLOBUS_L_GFS_DATA_CONNECT_CB)
        {
            op->state = GLOBUS_L_GFS_DATA_CONNECTED;
        }
        finish = op->finished_delayed;
        if(dec_op)
        {
            /* must delay decrement otherwise the callback could result in
                destroing the op once the lock is released */
            GFSDataOpDec(op, destroy_op, destroy_session);

            if(destroy_op)
            {
                globus_assert(op->data_handle != NULL);
                remote_data_arg = globus_l_gfs_data_check(
                    op->session_handle, op->data_handle);
            }
        }
        if(finish)
        {
            globus_l_gfs_data_finish_connected(op);
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);


    if(destroy_op)
    {
        /* pass the complete event */
        if(op->session_handle->dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            /* AAAA */
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
            event_info.event_arg = op->event_arg;
            op->session_handle->dsi->trev_func(
                &event_info,
                op->session_handle->session_arg);
            globus_mutex_lock(&op->session_handle->mutex);
            {
                remote_data_arg = globus_l_gfs_data_post_transfer_event_cb(
                    op->session_handle, op->data_handle);
            }
            globus_mutex_unlock(&op->session_handle->mutex);
        }

        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
        /* destroy the op */
        globus_l_gfs_data_operation_destroy(op);
    }

    GlobusGFSDebugExit();
    return;

  err_lock:
    /* start abort process */
    globus_l_gfs_data_start_abort(op);
    globus_mutex_unlock(&op->session_handle->mutex);
    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_data_begin_kickout(
    void *                              callback_arg)
{
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_begin_kickout);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) callback_arg;

    globus_l_gfs_data_begin_cb(
        callback_arg,
        &op->data_handle->data_channel,
        0,
        GLOBUS_TRUE,
        NULL);

    GlobusGFSDebugExit();
}


static
void
globus_l_gfs_data_end_transfer_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_gfs_event_info_t        event_reply;
    globus_gfs_finished_info_t              reply;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_bool_t                       disconnect = GLOBUS_FALSE;
    void *                              remote_data_arg = NULL;
    globus_gfs_event_info_t             event_info;
    GlobusGFSName(globus_l_gfs_data_end_transfer_kickout);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;

    memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));

    /* deal with the data handle */
    globus_mutex_lock(&op->session_handle->mutex);
    {
        globus_assert(op->data_handle != NULL);
        switch(op->data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_TE_VALID:
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_VALID;
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED:
                disconnect = GLOBUS_TRUE;
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO,
        "Finished transferring \"%s\".\n",
            ((globus_gfs_transfer_info_t *) op->info_struct)->pathname);

    /* XXX send final byte total to frontends if wasn't already sent */
    if(op->data_handle->is_mine && 
        (op->data_handle->info.mode != 'E' || op->writing))
    {
        globus_gfs_event_info_t        event_reply;
        memset(&event_reply, '\0', sizeof(globus_gfs_event_info_t));
        event_reply.id = op->id;
        event_reply.recvd_bytes = op->bytes_transferred;
        event_reply.node_ndx = op->node_ndx;

        event_reply.type = GLOBUS_GFS_EVENT_BYTES_RECVD;
        if(op->event_callback != NULL)
        {
            /* do nothing */
        }
        else
        {
            globus_gfs_ipc_reply_event(
                op->ipc_handle,
                &event_reply);
        }
    }

    if(disconnect && op->data_handle->is_mine)
    {
        memset(&event_reply, '\0', sizeof(globus_gfs_event_info_t));
        event_reply.id = op->id;
        event_reply.data_arg = op->data_arg;

        event_reply.type = GLOBUS_GFS_EVENT_DISCONNECTED;
        if(op->event_callback != NULL)
        {
            op->event_callback(
                &event_reply,
                op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(
                op->ipc_handle,
                &event_reply);
        }
    }

    /* log transfer */
    if(op->node_ndx == 0 && 
        op->cached_res == GLOBUS_SUCCESS &&
        (globus_i_gfs_config_string("log_transfer") || 
        (!globus_i_gfs_config_bool("disable_usage_stats") 
            && op->data_handle->is_mine)))
    {
        char *                          type;
        globus_gfs_transfer_info_t *    info;
        struct timeval                  end_timeval;

        info = (globus_gfs_transfer_info_t *) op->info_struct;

        if(op->writing)
        {
            if(info->list_type)
            {
                if(strncmp(info->list_type, "LIST:", 5) == 0)
                {
                    type = "LIST";
                }
                else if(strncmp(info->list_type, "NLST:", 5) == 0)
                {
                    type = "NLST";
                }
                else
                {
                    type = "MLSD";
                }
            }
            else if(info->module_name || info->partial_offset != 0 ||
                info->partial_length != -1)
            {
                type = "ERET";
            }
            else
            {
                type = "RETR";
            }
        }
        else
        {
            if(info->module_name || info->partial_offset != 0 ||
                 !info->truncate)
            {
                type = "ESTO";
            }
            else
            {
                type = "STOR";
            }
        }
        gettimeofday(&end_timeval, NULL);

        if(globus_i_gfs_config_string("log_transfer"))
        {
            globus_i_gfs_log_transfer(
                op->node_count,
                op->node_count * op->data_handle->info.nstreams,
                &op->start_timeval,
                &end_timeval,
                op->remote_ip ? op->remote_ip : "0.0.0.0",
                op->data_handle->info.blocksize,
                op->data_handle->info.tcp_bufsize,
                info->pathname,
                op->bytes_transferred,
                226,
                "/",
                type,
                op->session_handle->username);
        }
        if(!globus_i_gfs_config_string("disable_usage_stats")
            && op->data_handle->is_mine)
        {
            globus_i_gfs_log_usage_stats(
                op->node_count,
                op->node_count * op->data_handle->info.nstreams,
                &op->start_timeval,
                &end_timeval,
                op->remote_ip ? op->remote_ip : "0.0.0.0",
                op->data_handle->info.blocksize,
                op->data_handle->info.tcp_bufsize,
                info->pathname,
                op->bytes_transferred,
                226,
                "/",
                type,
                op->session_handle->username);
        }            
    }

    /* XXX sc process bytes transferred count */
    {
        char *                          names[5] = 
            {"bytes", "kilobytes", "megabytes", "gigabytes", "terabytes"}; 
        char *                          str_transferred;
        globus_off_t                    tmp_bytes;
        double                          remainder = 0.0;
        int                             i = 0;
        
        globus_mutex_lock(&globus_l_gfs_global_counter_lock);
        {
            globus_l_gfs_bytes_transferred += op->bytes_transferred;
            tmp_bytes = globus_l_gfs_bytes_transferred;
        }
        globus_mutex_unlock(&globus_l_gfs_global_counter_lock);
    
        while((i < 5) && (tmp_bytes > 1024))
        {
            remainder = ((tmp_bytes % 1024) / 1024.0) + (remainder / 1024.0);
            tmp_bytes /= 1024;
            i++;
        }
        str_transferred = globus_gfs_config_get_string("byte_transfer_count");
        if(str_transferred)
        {
            sprintf(
                str_transferred, 
                "%.2f %s", 
                (double) tmp_bytes + remainder,
                names[i]);
        }
        globus_gfs_config_set_ptr("byte_transfer_count", str_transferred);
    }

    reply.type = GLOBUS_GFS_OP_TRANSFER;
    reply.id = op->id;
    reply.result = op->cached_res;
    reply.info.transfer.bytes_transferred = op->bytes_transferred;

    globus_assert(!op->writing ||
        (op->sent_partial_eof == 1 || op->stripe_count == 1 ||
        (op->node_ndx == 0 && op->eof_ready)));
    /* tell the control side the finished was called */
    if(op->callback != NULL)
    {
        op->callback(&reply, op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            op->ipc_handle,
            &reply);
    }

    /* remove the refrence for this callback.  It is posible the before
        aquireing this lock the completing state occured and we are
        ready to finish */
    globus_mutex_lock(&op->session_handle->mutex);
    {
        GFSDataOpDec(op, destroy_op, destroy_session);

        if(destroy_op)
        {
            globus_assert(op->data_handle != NULL);
            remote_data_arg = globus_l_gfs_data_check(
                op->session_handle, op->data_handle);
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(destroy_op)
    {
        /* pass the complete event */
        if(op->session_handle->dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            /* AAAA */
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
            event_info.event_arg = op->event_arg;
            op->session_handle->dsi->trev_func(
                &event_info,
                op->session_handle->session_arg);
            globus_mutex_lock(&op->session_handle->mutex);
            {
                remote_data_arg = globus_l_gfs_data_post_transfer_event_cb(
                    op->session_handle, op->data_handle);
                if(op->data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_TE_VALID)
                {
                    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
                }
            }
            globus_mutex_unlock(&op->session_handle->mutex);
        }

        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
        globus_l_gfs_data_operation_destroy(op);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_end_read_kickout(
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_bool_t                       end = GLOBUS_FALSE;
    globus_l_gfs_data_operation_t *     op;

    globus_gfs_acl_action_t             action;
    int                                 rc;
    globus_result_t                     res;
    globus_gfs_transfer_info_t *        recv_info;
    globus_gfs_acl_object_desc_t        object;

    GlobusGFSName(globus_l_gfs_data_end_read_kickout);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;

    if(op->data_handle->info.mode == 'E')
    {
        globus_gfs_event_info_t        event_reply;
        memset(&event_reply, '\0', sizeof(globus_gfs_event_info_t));
        event_reply.id = op->id;
        event_reply.recvd_bytes = op->recvd_bytes;
        event_reply.recvd_ranges = op->recvd_ranges;
        event_reply.node_ndx = op->node_ndx;

        event_reply.type = GLOBUS_GFS_EVENT_BYTES_RECVD;
        if(op->event_callback != NULL)
        {
            op->event_callback(
                &event_reply,
                op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(
                op->ipc_handle,
                &event_reply);
        }

        event_reply.type = GLOBUS_GFS_EVENT_RANGES_RECVD;
        if(op->event_callback != NULL)
        {
            op->event_callback(
                &event_reply,
                op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(
                op->ipc_handle,
                &event_reply);
        }
    }

    recv_info = op->info_struct;
    object.name = recv_info->pathname;
    object.size = op->bytes_transferred;
    object.final = GLOBUS_TRUE;
    action = GFS_ACL_ACTION_COMMIT;
    rc = globus_gfs_acl_authorize(
        &op->session_handle->acl_handle,
        action,
        &object,
        &res,
        globus_l_gfs_authorize_cb,
        NULL);
    if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        globus_l_gfs_authorize_cb(&object, action, NULL, res);
    }

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                /* if not mode e we need to close it */
                if(op->data_handle->info.mode != 'E')
                {
                    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_CLOSING;
                    result = globus_ftp_control_data_force_close(
                        &op->data_handle->data_channel,
                        globus_l_gfs_data_finish_fc_cb,
                        op);
                    if(result != GLOBUS_SUCCESS)
                    {
                        op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED;
                        end = GLOBUS_TRUE;
                    }
                }
                else
                {
                    end = GLOBUS_TRUE;
                }
                break;

            default:
                break;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);
    if(end)
    {
        globus_l_gfs_data_end_transfer_kickout(op);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_cb_error(
    globus_l_gfs_data_handle_t *        data_handle)
{
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_cb_error);
    GlobusGFSDebugEnter();

    op = data_handle->outstanding_op;

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED;
                /* XXX free it here ??? */
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_send_eof_cb(
    void *                              callback_arg,
    struct globus_ftp_control_handle_s * handle,
    globus_object_t *			error)
{
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_send_eof_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) callback_arg;
    if(error != NULL)
    {
        /* XXX this should be thread safe see not in write_eof cb */
        globus_l_gfs_data_cb_error(op->data_handle);
        op->cached_res = globus_error_put(globus_object_copy(error));
    }
    globus_l_gfs_data_end_transfer_kickout(op);

    GlobusGFSDebugExit();
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
    globus_bool_t                       end = GLOBUS_FALSE;
    globus_result_t                     result;
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_data_write_eof_cb);
    GlobusGFSDebugEnter();

    op = (globus_l_gfs_data_operation_t *) user_arg;

    GlobusGFSDebugState(op->state);
    GlobusGFSDebugState(op->data_handle->state);
    if(error != NULL)
    {
        /* XXX this should be thread safe since we only get this
            callback after a finsihed_transfer() from the user.  we
            could still get events or disconnects, but the abort process
            does not touch the data_handle->state */
        op->cached_res = globus_error_put(globus_object_copy(error));
        globus_i_gfs_log_result_warn(
            "write_eof_cb error", op->cached_res);
        globus_l_gfs_data_cb_error(op->data_handle);
        end = GLOBUS_TRUE;
    }
    else
    {
        globus_mutex_lock(&op->session_handle->mutex);
        {
            switch(op->data_handle->state)
            {
                case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                /* if not mode e we need to close it */
                if(op->data_handle->info.mode == 'E')
                {
                    result = globus_ftp_control_data_send_eof(
                        &op->data_handle->data_channel,
                        op->eof_count,
                        op->stripe_count,
                        (op->node_ndx == 0 || op->stripe_count == 1) ?
                            GLOBUS_TRUE : GLOBUS_FALSE,
                        globus_l_gfs_data_send_eof_cb,
                        op);
                    if(op->node_ndx != 0 && op->stripe_count > 1)
                    {
                       /* I think we want the eof event to kick off even
                        though we may have an error here since someone is
                        expecting it.  The transfer should still error out
                        normally */
                        globus_gfs_event_info_t        event_reply;
                        memset(&event_reply, '\0',
                            sizeof(globus_gfs_event_info_t));
                        event_reply.id = op->id;
                        event_reply.eof_count = op->eof_count;
                        event_reply.type = GLOBUS_GFS_EVENT_PARTIAL_EOF_COUNT;
                        event_reply.node_count = op->node_count;
                        if(op->event_callback != NULL)
                        {
                                op->event_callback(
                                &event_reply,
                                op->user_arg);
                        }
                        else
                        {
                            globus_gfs_ipc_reply_event(
                                op->ipc_handle,
                                &event_reply);
                        }
                        op->sent_partial_eof++;
                    }
                    if(result != GLOBUS_SUCCESS)
                    {
                        globus_i_gfs_log_result_warn(
                            "ERROR", result);
                        op->cached_res = result;
                        end = GLOBUS_TRUE;
                    }
                }
                else
                {
                    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_CLOSING;
                    result = globus_ftp_control_data_force_close(
                        &op->data_handle->data_channel,
                        globus_l_gfs_data_finish_fc_cb,
                        op);
                    if(result != GLOBUS_SUCCESS)
                    {
                        op->data_handle->state =
                            GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED;
                        end = GLOBUS_TRUE;
                    }
                }

                default:
                    break;
            }
        }
        globus_mutex_unlock(&op->session_handle->mutex);
    }

    if(end)
    {
        globus_l_gfs_data_end_transfer_kickout(op);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_send_eof(
    globus_l_gfs_data_operation_t *     op)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_data_send_eof);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->state)
        {
            case GLOBUS_L_GFS_DATA_FINISH:
                op->eof_ready = GLOBUS_TRUE;
                result = globus_ftp_control_data_write(
                    &op->data_handle->data_channel,
                    "",
                    0,
                    0,
                    GLOBUS_TRUE,
                    globus_l_gfs_data_write_eof_cb,
                    op);
                if(result != GLOBUS_SUCCESS)
                {
                    globus_i_gfs_log_result_warn(
                        "send_eof error", result);
                    op->cached_res = result;

                if(op->data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID)
                {
                    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_VALID;
                }
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_data_end_transfer_kickout,
                        op);
                }
                break;
            case GLOBUS_L_GFS_DATA_CONNECTED:
                op->eof_ready = GLOBUS_TRUE;
                break;
            default:
                /* figure out what needs to happen in other states */
                break;
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    GlobusGFSDebugExit();
}

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
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_bounce_t *) user_arg;

    bounce_info->op->bytes_transferred += length;

    bounce_info->callback.write(
        bounce_info->op,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        buffer,
        length,
        bounce_info->user_arg);

    globus_free(bounce_info);

    GlobusGFSDebugExit();
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
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_bounce_t *) user_arg;

    bounce_info->op->bytes_transferred += length;

    bounce_info->callback.read(
        bounce_info->op,
        error ? globus_error_put(globus_object_copy(error)) : GLOBUS_SUCCESS,
        buffer,
        length,
        offset + bounce_info->op->write_delta,
        eof,
        bounce_info->user_arg);

    globus_free(bounce_info);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_trev_kickout(
    void *                              user_arg)
{
    globus_l_gfs_data_trev_bounce_t *   bounce_info;
    globus_gfs_event_info_t *      event_reply;
    void *                              remote_data_arg = NULL;
    globus_bool_t                       pass;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_gfs_event_info_t             event_info;

    globus_gfs_acl_action_t             action;
    int                                 rc;
    globus_result_t                     res;
    globus_gfs_transfer_info_t *        recv_info;
    globus_gfs_acl_object_desc_t        object;

    GlobusGFSName(globus_l_gfs_data_trev_kickout);
    GlobusGFSDebugEnter();

    bounce_info = (globus_l_gfs_data_trev_bounce_t *) user_arg;
    event_reply = (globus_gfs_event_info_t *)
        globus_calloc(1, sizeof(globus_gfs_event_info_t));

    event_reply->id = bounce_info->op->id;
    event_reply->node_ndx = bounce_info->op->node_ndx;
    globus_mutex_lock(&bounce_info->op->session_handle->mutex);
    {
        switch(bounce_info->op->state)
        {
            case GLOBUS_L_GFS_DATA_CONNECTING:
            case GLOBUS_L_GFS_DATA_CONNECTED:
            case GLOBUS_L_GFS_DATA_ABORTING:
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                pass = GLOBUS_TRUE;
                break;

            case GLOBUS_L_GFS_DATA_FINISH:
                pass = GLOBUS_FALSE;
                break;

            case GLOBUS_L_GFS_DATA_COMPLETING:
            case GLOBUS_L_GFS_DATA_COMPLETE:
            case GLOBUS_L_GFS_DATA_REQUESTING:
            default:
                globus_assert(0 && "possibly memory corruption");
                break;
        }
        switch(bounce_info->event_type)
        {
            case GLOBUS_GFS_EVENT_BYTES_RECVD:
                event_reply->recvd_bytes = bounce_info->op->recvd_bytes;
                bounce_info->op->recvd_bytes = 0;
                event_reply->type = GLOBUS_GFS_EVENT_BYTES_RECVD;
                break;

            case GLOBUS_GFS_EVENT_RANGES_RECVD:
                event_reply->type = GLOBUS_GFS_EVENT_RANGES_RECVD;
                globus_range_list_copy(
                    &event_reply->recvd_ranges,
                    bounce_info->op->recvd_ranges);
                globus_range_list_remove(
                    bounce_info->op->recvd_ranges, 0, GLOBUS_RANGE_LIST_MAX);
                break;

            default:
                globus_assert(0 && "invalid state, not possible");
                break;
        }
    }
    globus_mutex_unlock(&bounce_info->op->session_handle->mutex);

    if(globus_i_gfs_config_bool("sync_writes"))
    {
        sync();
    }
    
    recv_info = bounce_info->op->info_struct;
    object.name = recv_info->pathname;
    object.size = bounce_info->op->bytes_transferred;
    object.final = GLOBUS_FALSE;
    action = GFS_ACL_ACTION_COMMIT;
    rc = globus_gfs_acl_authorize(
        &bounce_info->op->session_handle->acl_handle,
        action,
        &object,
        &res,
        globus_l_gfs_authorize_cb,
        NULL);
    if(rc == GLOBUS_GFS_ACL_COMPLETE)
    {
        globus_l_gfs_authorize_cb(&object, action, NULL, res);
    }


    if(pass)
    {
        if(bounce_info->op->event_callback != NULL)
        {
            bounce_info->op->event_callback(
                event_reply,
                bounce_info->op->user_arg);
        }
        else
        {
            globus_gfs_ipc_reply_event(
                bounce_info->op->ipc_handle,
                event_reply);
        }
    }

    globus_mutex_lock(&bounce_info->op->session_handle->mutex);
    {
        GFSDataOpDec(bounce_info->op, destroy_op, destroy_session);
        if(destroy_op)
        {
            globus_assert(
                bounce_info->op->state == GLOBUS_L_GFS_DATA_COMPLETING);
            globus_assert(bounce_info->op->data_handle != NULL);
            remote_data_arg = globus_l_gfs_data_check(
                bounce_info->op->session_handle, bounce_info->op->data_handle);
        }
    }
    globus_mutex_unlock(&bounce_info->op->session_handle->mutex);

    if(destroy_op)
    {
        /* pass the complete event */
        if(bounce_info->op->session_handle->dsi->trev_func &&
            bounce_info->op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            /* AAAA */
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
            event_info.event_arg = bounce_info->op->event_arg;
            bounce_info->op->session_handle->dsi->trev_func(
                &event_info,
                bounce_info->op->session_handle->session_arg);
            globus_mutex_lock(&bounce_info->op->session_handle->mutex);
            {
                remote_data_arg = globus_l_gfs_data_post_transfer_event_cb(
                    bounce_info->op->session_handle, bounce_info->op->data_handle);
            }
            globus_mutex_unlock(&bounce_info->op->session_handle->mutex);
        }
        globus_l_gfs_data_fire_cb(
            bounce_info->op, remote_data_arg, destroy_session);
        globus_l_gfs_data_operation_destroy(bounce_info->op);
    }

    if(event_reply->recvd_ranges)
    {
        globus_range_list_destroy(event_reply->recvd_ranges);
    }
    globus_free(bounce_info);
    globus_free(event_reply);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_data_force_close(
    globus_l_gfs_data_operation_t *     op)
{
    GlobusGFSName(globus_l_gfs_data_force_close);
    GlobusGFSDebugEnter();

    /* handle the data_handle state machine */
    if(op->data_handle->is_mine)
    {
        switch(op->data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_CLOSING;

                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_data_end_transfer_kickout,
                    op);
                break;

            /* already started closing the handle */
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED:
            case GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_AND_DESTROYED:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
            default:
                globus_assert(0 && "only should be called when inuse");
                break;
        }
    }
    else
    {
        switch(op->data_handle->state)
        {
            case GLOBUS_L_GFS_DATA_HANDLE_INUSE:
                op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_PRE_CLOSED;
                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_data_end_transfer_kickout,
                    op);
                break;

            /* already started closing the handle */
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSED:
            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING:
                break;

            case GLOBUS_L_GFS_DATA_HANDLE_CLOSING_AND_DESTROYED:
            case GLOBUS_L_GFS_DATA_HANDLE_VALID:
            default:
                globus_assert(0 && "only should be called when inuse");
                break;
        }
    }

    GlobusGFSDebugExit();
}

/* must be called locked */
static
void
globus_l_gfs_data_start_abort(
    globus_l_gfs_data_operation_t *     op)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_data_start_abort);
    GlobusGFSDebugEnter();

    switch(op->state)
    {
        case GLOBUS_L_GFS_DATA_REQUESTING:
            op->state = GLOBUS_L_GFS_DATA_ABORTING;
            break;

        case GLOBUS_L_GFS_DATA_CONNECTING:
        case GLOBUS_L_GFS_DATA_CONNECTED:
            if(op->data_handle->is_mine)
            {
                globus_assert(op->data_handle->state ==
                    GLOBUS_L_GFS_DATA_HANDLE_INUSE);
                op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_CLOSING;

                GlobusGFSDebugInfo("globus_ftp_control_data_force_close");
                result = globus_ftp_control_data_force_close(
                    &op->data_handle->data_channel,
                    globus_l_gfs_data_abort_fc_cb,
                    op);
                if(result != GLOBUS_SUCCESS)
                {
                    GlobusGFSDebugInfo("force_close failed");                    
                    globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_data_abort_kickout,
                        op);
                }
            }
            else
            {
                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_data_abort_kickout,
                    op);
            }
            op->state = GLOBUS_L_GFS_DATA_ABORT_CLOSING;
            op->ref++;
            break;

        /* everything post finished can ignore abort, because dsi is already
            done and connections should be torn down, or in the process
            of tearing down */
        case GLOBUS_L_GFS_DATA_FINISH:
        case GLOBUS_L_GFS_DATA_COMPLETING:
        case GLOBUS_L_GFS_DATA_COMPLETE:
            break;

        case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
        case GLOBUS_L_GFS_DATA_ABORTING:
            /* do nothing cause it has already been done */
            break;

        default:
            break;
    }

    GlobusGFSDebugExit();
}

void
globus_i_gfs_data_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    globus_gfs_event_info_t *           event_info)
{
    void *                              remote_data_arg = NULL;
    globus_result_t                     result;
    globus_l_gfs_data_trev_bounce_t *   bounce_info;
    globus_l_gfs_data_session_t *       session_handle;
    globus_l_gfs_data_operation_t *     op;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_bool_t                       pass = GLOBUS_FALSE;
    GlobusGFSName(globus_i_gfs_data_request_transfer_event);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;
    op = (globus_l_gfs_data_operation_t *) globus_handle_table_lookup(
        &session_handle->handle_table, (int) event_info->event_arg);
    if(op == NULL)
    {
        globus_assert(0 && "i wanna know when this happens");
    }
    globus_mutex_lock(&op->session_handle->mutex);
    {
        globus_assert(op->data_handle != NULL);

        /* this is the final event.  dec reference */
        switch(event_info->type)
        {
            /* if this event has been received we SHOULD be in complete state
                if we are not it is a bad message and we ignore it */
            case GLOBUS_GFS_EVENT_TRANSFER_COMPLETE:
                switch(op->state)
                {
                    case GLOBUS_L_GFS_DATA_FINISH:
                        /* even tho we are passing do not up the ref because
                           this is the barrier message */
                        op->state = GLOBUS_L_GFS_DATA_COMPLETING;
                        pass = GLOBUS_TRUE;
                        break;

                    case GLOBUS_L_GFS_DATA_FINISH_WITH_ERROR:
                        if(op->data_handle->is_mine)
                        {
                            op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_CLOSING;

                            result = globus_ftp_control_data_force_close(
                                &op->data_handle->data_channel,
                                globus_l_gfs_data_complete_fc_cb,
                                op);
                            if(result != GLOBUS_SUCCESS)
                            {
                                globus_i_gfs_log_result_warn(
                                    "force_close", result);
                                globus_l_gfs_data_fc_return(op);
                                pass = GLOBUS_TRUE;
                            }
                        }
                        else
                        {
                            pass = GLOBUS_TRUE;
                        }
                        op->state = GLOBUS_L_GFS_DATA_COMPLETING;
                        break;

                    default:
                        /* XXX log a bad message */
                        globus_assert(0 && "for now we assert");
                        pass = GLOBUS_FALSE;
                        break;
                }
                break;

            case GLOBUS_GFS_EVENT_FINAL_EOF_COUNT:
                /* XXX check state here, move send_eof call out of lock */
                op->eof_count = event_info->eof_count;
                globus_l_gfs_data_send_eof(op);
                break;

            case GLOBUS_GFS_EVENT_BYTES_RECVD:
            case GLOBUS_GFS_EVENT_RANGES_RECVD:
                /* we ignore these 2 events for everything except the
                    connected state */
                /* if finished already happened ignore these completely */
                if(op->state != GLOBUS_L_GFS_DATA_CONNECTED)
                {
                    pass = GLOBUS_FALSE;
                }
                else
                {
                    /* if the DSI is handling these events */
                    if(session_handle->dsi->trev_func != NULL &&
                        event_info->type & op->event_mask)
                    {
                        op->ref++;
                        pass = GLOBUS_TRUE;
                    }
                    /* if DSI not handling, take care of for them */
                    else
                    {
                        pass = GLOBUS_FALSE;
                        /* since this will be put in a callback we must up
                            ref */
                        op->ref++;

                        bounce_info = (globus_l_gfs_data_trev_bounce_t *)
                            globus_malloc(
                                sizeof(globus_l_gfs_data_trev_bounce_t));
                        if(!bounce_info)
                        {
                            result = GlobusGFSErrorMemory("bounce_info");
                        }

                        bounce_info->event_type = event_info->type;
                        bounce_info->op = op;
                        globus_callback_register_oneshot(
                            NULL,
                            NULL,
                            globus_l_gfs_data_trev_kickout,
                            bounce_info);
                    }
                }
                break;

            case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
                /* start the abort process */
                globus_l_gfs_data_start_abort(op);
                break;

            /* only pass though if in connected state and the dsi wants
                the event */
            default:
                if(op->state != GLOBUS_L_GFS_DATA_CONNECTED ||
                    session_handle->dsi->trev_func == NULL ||
                    !(event_info->type & op->event_mask))
                {
                    pass = GLOBUS_FALSE;
                }
                else
                {
                    op->ref++;
                    pass = GLOBUS_TRUE;
                }
                break;
        }
        if(pass)
        {
            GFSDataOpDec(op, destroy_op, destroy_session);
            if(destroy_op)
            {
                globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING &&
                    op->data_handle != NULL);
                remote_data_arg = globus_l_gfs_data_check(
                    op->session_handle, op->data_handle);
            }
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    /* if is possible that events slip through here after setting to
        GLOBUS_L_GFS_DATA_COMPLETE.  This is ok because the only
        gauretee made is that none will come after
        GLOBUS_GFS_EVENT_TRANSFER_COMPLETE.  This is gaurenteed with
        the reference count. */
    if(pass)
    {
        /* if a TRANSFER_COMPLETE event we must respect the barrier */
        if(event_info->type != GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            /* XXX should copy here */
            event_info->event_arg = op->event_arg;
            session_handle->dsi->trev_func(
                event_info,
                session_handle->session_arg);
        }
        if(destroy_op)
        {
            if(session_handle->dsi->trev_func &&
                op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
            {   /* XXX should make our own */
                /* AAAA */
                event_info->type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
                event_info->event_arg = op->event_arg;
                session_handle->dsi->trev_func(
                    event_info,
                    op->session_handle->session_arg);
                globus_mutex_lock(&op->session_handle->mutex);
                {
                    remote_data_arg = globus_l_gfs_data_post_transfer_event_cb(
                        op->session_handle, op->data_handle);
                }
                globus_mutex_unlock(&op->session_handle->mutex);
            }
            globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
            /* destroy the op */
            globus_l_gfs_data_operation_destroy(op);
        }
    }

    GlobusGFSDebugExit();
}

void
globus_i_gfs_data_session_start(
    globus_gfs_ipc_handle_t             ipc_handle,
    const gss_ctx_id_t                  context,
    globus_gfs_session_info_t *         session_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg)
{
    globus_l_gfs_data_operation_t *     op;
    globus_result_t                     result;
    globus_l_gfs_data_session_t *       session_handle;
    GlobusGFSName(globus_i_gfs_data_session_start);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *)
        globus_calloc(1, sizeof(globus_l_gfs_data_session_t));
    if(session_handle == NULL)
    {
        /* XXX deal with this */
    }
    session_handle->dsi = globus_l_gfs_dsi;
    globus_handle_table_init(&session_handle->handle_table, NULL);
    globus_mutex_init(&session_handle->mutex, NULL);
    session_handle->ref = 1;
    session_handle->del_cred = session_info->del_cred;

    result = globus_l_gfs_data_operation_init(&op, session_handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_i_gfs_data_session_start", result);
        globus_assert(0);
    }
    op->session_handle = session_handle;
    op->ipc_handle = ipc_handle;
    op->uid = getuid();
    op->state = GLOBUS_L_GFS_DATA_REQUESTING;
    op->callback = cb;
    op->user_arg = user_arg;
    op->info_struct = session_info;

    if(globus_i_gfs_config_int("auth_level") & GLOBUS_L_GFS_AUTH_IDENTIFY)
    {
        globus_l_gfs_data_authorize(op, context, session_info);
    }
    else
    {
        struct passwd *                 pwent;

        op->session_handle->uid = getuid();
        op->session_handle->gid_count = getgroups(0, NULL);
        op->session_handle->gid_array = (gid_t *) globus_malloc(
            op->session_handle->gid_count * sizeof(gid_t));
        getgroups(op->session_handle->gid_count, op->session_handle->gid_array);

        pwent = getpwuid(op->session_handle->uid);
        if(pwent->pw_dir != NULL)
        {
            op->session_handle->home_dir = strdup(pwent->pw_dir);
        }
        globus_l_gfs_data_auth_init_cb(
            NULL, GFS_ACL_ACTION_INIT, op, GLOBUS_SUCCESS);
    }

    GlobusGFSDebugExit();
}

void
globus_i_gfs_data_session_stop(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg)
{
    globus_bool_t                       free_session = GLOBUS_FALSE;
    globus_l_gfs_data_session_t *       session_handle;
    GlobusGFSName(globus_i_gfs_data_session_stop);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;
    if(session_handle != NULL)
    {
        globus_mutex_lock(&session_handle->mutex);
        {
            session_handle->ref--;
            /* can't jsut free bcause we may be waiting on a force close */
            if(session_handle->ref == 0)
            {
                free_session = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&session_handle->mutex);

        if(free_session)
        {
            if(session_handle->dsi->destroy_func != NULL)
            {
                session_handle->dsi->destroy_func(session_handle->session_arg);
            }
            
            if(session_handle->dsi != globus_l_gfs_dsi)
            {
                globus_extension_release(session_handle->dsi_handle);
            }
            globus_l_gfs_free_session_handle(session_handle);
        }
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_finished_command_kickout(
    void *                              user_arg)
{
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_gfs_finished_info_t          reply;
    void *                              remote_data_arg = NULL;
    globus_l_gfs_data_operation_t *     op;

    op = (globus_l_gfs_data_operation_t *) user_arg;

    memset(&reply, '\0', sizeof(globus_gfs_finished_info_t));
    reply.type = GLOBUS_GFS_OP_COMMAND;
    reply.id = op->id;
    reply.result = op->cached_res;
    reply.info.command.command = op->command;
    reply.info.command.checksum = op->cksm_response;
    reply.info.command.created_dir = op->pathname;

    if(op->callback != NULL)
    {
        op->callback(
            &reply,
            op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_finished(
            op->ipc_handle,
            &reply);
    }

    globus_mutex_lock(&op->session_handle->mutex);
    {
        GFSDataOpDec(op, destroy_op, destroy_session);
        remote_data_arg = globus_l_gfs_data_check(
            op->session_handle, op->data_handle);
    }
    globus_mutex_unlock(&op->session_handle->mutex);
    globus_assert(destroy_op);
    globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
    globus_l_gfs_data_operation_destroy(op);
}


/************************************************************************
 *
 * Public functions
 *
 ***********************************************************************/

void
globus_gridftp_server_finished_command(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    char *                              command_data)
{
    GlobusGFSName(globus_gridftp_server_finished_command);
    GlobusGFSDebugEnter();

    /* XXX gotta do a oneshot */
    switch(op->command)
    {
      case GLOBUS_GFS_CMD_CKSM:
        op->cksm_response = globus_libc_strdup(command_data);
        break;
      case GLOBUS_GFS_CMD_MKD:
      case GLOBUS_GFS_CMD_RMD:
      case GLOBUS_GFS_CMD_DELE:
      case GLOBUS_GFS_CMD_RNTO:
      case GLOBUS_GFS_CMD_SITE_CHMOD:
      default:
        break;
    }
    op->cached_res = result;

    result = globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_gfs_finished_command_kickout,
        op);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        globus_panic(NULL, result, "oneshot failed, no recovery");
    }

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_finished_stat(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count)
{
    globus_l_gfs_data_stat_bounce_t *   bounce_info;
    globus_gfs_stat_t *                 stat_copy;
    int                                 i;
    GlobusGFSName(globus_gridftp_server_finished_stat);
    GlobusGFSDebugEnter();

    if(result == GLOBUS_SUCCESS)
    {
        stat_copy = (globus_gfs_stat_t *)
            globus_malloc(sizeof(globus_gfs_stat_t) * stat_count);
        if(stat_copy == NULL)
        {
            result = GlobusGFSErrorMemory("stat_copy");
            goto error_alloc;
        }
        memcpy(
            stat_copy,
            stat_array,
            sizeof(globus_gfs_stat_t) * stat_count);
        for(i = 0; i < stat_count; i++)
        {
            if(stat_array[i].name != NULL)
            { 
                stat_copy[i].name = globus_libc_strdup(stat_array[i].name);
            }
            else
            {
                /* XXX probably not acceptable to proceed */
                stat_copy[i].name = globus_libc_strdup("(null)");
            }
            stat_copy[i].symlink_target = 
                globus_libc_strdup(stat_array[i].symlink_target);
        }
    }
    else
    {
        stat_copy = NULL;
        stat_count = 0;
    }

    bounce_info = (globus_l_gfs_data_stat_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_stat_bounce_t));
    if(bounce_info == NULL)
    {
        result = GlobusGFSErrorMemory("bounce_info");
        goto error_alloc;
    }

    bounce_info->op = op;
    bounce_info->error = result == GLOBUS_SUCCESS
        ? GLOBUS_NULL : globus_error_get(result);
    bounce_info->stat_count = stat_count;
    bounce_info->stat_array = stat_copy;
    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_gfs_data_stat_kickout,
        bounce_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        goto error_oneshot;
    }

    GlobusGFSDebugExit();
    return;

error_oneshot:
error_alloc:
    globus_panic(
        GLOBUS_NULL,
        result,
        "[%s:%d] Unrecoverable error",
        _gfs_name,
        __LINE__);
    GlobusGFSDebugExitWithError();
}

void
globus_gridftp_server_begin_transfer(
    globus_gfs_operation_t              op,
    int                                 event_mask,
    void *                              event_arg)
{
    void *                              remote_data_arg = NULL;
    globus_bool_t                       pass_abort = GLOBUS_FALSE;
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_result_t                     result;
    globus_gfs_event_info_t             event_reply;
    globus_gfs_event_info_t             event_info;
    GlobusGFSName(globus_gridftp_server_begin_transfer);
    GlobusGFSDebugEnter();

    gettimeofday(&op->start_timeval, NULL);
    op->event_mask = event_mask;
    op->event_arg = event_arg;

    /* increase refrence count for the events.  This gets decreased when
        the COMPLETE event occurs.  it is safe to increment outside of a
        lock because until we enable events there should be no
        contention
       increase the reference count a second time for this function.
       It is possible that after enabling events but before getting the lock
        that we: 1) get an abort, 2) get a finished() from dsi,
        3) get a complete, 4) free the op.  if this happens there will
        be no memory at op->mutex. we get around this with an extra
        reference count */
    op->ref += 2;
    memset(&event_reply, '\0', sizeof(globus_gfs_event_info_t));
    event_reply.type = GLOBUS_GFS_EVENT_TRANSFER_BEGIN;
    event_reply.id = op->id;
    event_reply.event_mask =
        GLOBUS_GFS_EVENT_TRANSFER_ABORT | GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
    if(!op->data_handle->is_mine || op->data_handle->info.mode == 'E')
    {
        event_reply.event_mask |=
            GLOBUS_GFS_EVENT_BYTES_RECVD | GLOBUS_GFS_EVENT_RANGES_RECVD;
    }

    event_reply.event_arg = (void *) globus_handle_table_insert(
        &op->session_handle->handle_table, op, 1);
    if(op->event_callback != NULL)
    {
        op->event_callback(&event_reply, op->user_arg);
    }
    else
    {
        globus_gfs_ipc_reply_event(op->ipc_handle, &event_reply);
    }

    /* at this point events can happen that change the state before
        the lock is aquired */

    globus_mutex_lock(&op->session_handle->mutex);
    {
        switch(op->state)
        {
            /* if going according to plan */
            case GLOBUS_L_GFS_DATA_REQUESTING:
                op->state = GLOBUS_L_GFS_DATA_CONNECTING;
                if(op->data_handle->is_mine)
                {
                    if(op->writing)
                    {
                        GlobusGFSDebugInfo(
                            "globus_ftp_control_data_connect_write");
                        result = globus_ftp_control_data_connect_write(
                            &op->data_handle->data_channel,
                            globus_l_gfs_data_begin_cb,
                            op);
                    }
                    else
                    {
                        GlobusGFSDebugInfo(
                            "globus_ftp_control_data_connect_read");
                        result = globus_ftp_control_data_connect_read(
                            &op->data_handle->data_channel,
                            globus_l_gfs_data_begin_cb,
                            op);
                    }
                }
                else
                {
                    /* rarre case where we are willing to check return code
                        from oneshot, however, if it ever fail many many
                        other things are likely to break frist */
                    GlobusGFSDebugInfo(
                        "oneshot globus_l_gfs_data_begin_kickout");
                    result = globus_callback_register_oneshot(
                        NULL,
                        NULL,
                        globus_l_gfs_data_begin_kickout,
                        op);
                }
                if(result != GLOBUS_SUCCESS)
                {
                    GlobusGFSDebugInfo("Register failed");
                    op->state = GLOBUS_L_GFS_DATA_ABORTING;
                    /* if the connects fail tell the dsi to abort */
                    op->cached_res = result;
                    if(op->session_handle->dsi->trev_func != NULL &&
                        op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT &&
                        !op->data_handle->is_mine)
                    {
                        pass_abort = GLOBUS_TRUE;
                        op->ref++;
                    }
                }
                else
                {
                    GlobusGFSDebugInfo("Register successful");
                    /* for the begin callback on success */
                    if(op->writing && op->data_handle->is_mine)
                    {
                        op->ref++;
                        op->stripe_connections_pending =
                            op->data_handle->info.cs_count;
                    }
                    else
                    {
                        op->ref++;
                        op->stripe_connections_pending = 1;
                    }
                }
                break;

            /* if in this state we have delayed the pass to the dsi until
                after we know they have requested events */
            case GLOBUS_L_GFS_DATA_ABORTING:
                if(op->session_handle->dsi->trev_func != NULL &&
                    op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_ABORT &&
                    !op->data_handle->is_mine)
                {
                    pass_abort = GLOBUS_TRUE;
                    op->ref++;
                }
                break;

            /* we are waiting for the force close callback to return */
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                break;

            /* nothing to do here, finishing is in the works */
            case GLOBUS_L_GFS_DATA_FINISH:
                break;

            /* if this happens we went through all the step in the above
                doc box. */
            case GLOBUS_L_GFS_DATA_COMPLETING:
                break;

            /* the reference counting should make htis not possible */
            case GLOBUS_L_GFS_DATA_COMPLETE:
                globus_assert(0 &&
                    "reference counts are likely messed up");
                break;

            /* this could only happen if the dsi did something bad, like
                maybe call this function twice? */
            case GLOBUS_L_GFS_DATA_CONNECTING:
            case GLOBUS_L_GFS_DATA_CONNECTED:
                globus_assert(0 &&
                    "In connecting state before it should be possible");
                break;
            default:
                globus_assert(0 && "this should not be possible");
                break;
        }

        GFSDataOpDec(op, destroy_op, destroy_session);
        if(destroy_op)
        {
            globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING);
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    if(pass_abort)
    {
        event_info.type = GLOBUS_GFS_EVENT_TRANSFER_ABORT;
        event_info.event_arg = op->event_arg;
        op->session_handle->dsi->trev_func(
            &event_info,
            op->session_handle->session_arg);
        globus_mutex_lock(&op->session_handle->mutex);
        {
            GFSDataOpDec(op, destroy_op, destroy_session);
            if(destroy_op)
            {
                globus_assert(op->state == GLOBUS_L_GFS_DATA_COMPLETING &&
                    op->data_handle != NULL);
                op->data_handle->outstanding_op = NULL;
                remote_data_arg = globus_l_gfs_data_check(
                    op->session_handle, op->data_handle);
            }
        }
        globus_mutex_unlock(&op->session_handle->mutex);
    }

    if(destroy_op)
    {
        if(op->session_handle->dsi->trev_func &&
            op->event_mask & GLOBUS_GFS_EVENT_TRANSFER_COMPLETE)
        {
            /* XXX does this call need to be in a oneshot? */

            /* AAAA */
            event_info.type = GLOBUS_GFS_EVENT_TRANSFER_COMPLETE;
            event_info.event_arg = op->event_arg;
            op->session_handle->dsi->trev_func(
                &event_info,
                op->session_handle->session_arg);
            globus_mutex_lock(&op->session_handle->mutex);
            {
                remote_data_arg = globus_l_gfs_data_post_transfer_event_cb(
                    op->session_handle, op->data_handle);
            }
            globus_mutex_unlock(&op->session_handle->mutex);
        }
        /* destroy the op */
        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
        globus_l_gfs_data_operation_destroy(op);
    }

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_finished_transfer(
    globus_gfs_operation_t              op,
    globus_result_t                     result)
{
    GlobusGFSName(globus_gridftp_server_finished_transfer);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&op->session_handle->mutex);
    {
        /* move the data_handle state to VALID.  at first error if will
            be moved to invalid */
        switch(op->state)
        {
            /* this is the normal case */
            case GLOBUS_L_GFS_DATA_CONNECTED:
                if(result != GLOBUS_SUCCESS)
                {
                    GlobusGFSDebugInfo("passed error in CONNECTED state\n");
                    goto err_close;
                }
                globus_l_gfs_data_finish_connected(op);
                op->state = GLOBUS_L_GFS_DATA_FINISH;
                break;

            /* finishing in connecting state with no error likely means
                a zero byte transfer.  the finish will be kicked off in
                the connect_cb when it comes, here we just let it fall
                through and change state to finished
                XXX think we need another state here, what if we get
                an abort while waiting for connect_cb but we are finished */
            case GLOBUS_L_GFS_DATA_CONNECT_CB:
            case GLOBUS_L_GFS_DATA_CONNECTING:
                op->finished_delayed = GLOBUS_TRUE;
                op->state = GLOBUS_L_GFS_DATA_FINISH;
                if(result != GLOBUS_SUCCESS)
                {
                    GlobusGFSDebugInfo("passed error in CONNECTING state\n");
                    op->cached_res = result;
                    op->state = GLOBUS_L_GFS_DATA_FINISH_WITH_ERROR;
                }
                break;

            case GLOBUS_L_GFS_DATA_ABORTING:
            case GLOBUS_L_GFS_DATA_REQUESTING:
                if(result != GLOBUS_SUCCESS)
                {
                    op->cached_res = result;
                }
                op->state = GLOBUS_L_GFS_DATA_FINISH;

                /* XXX goto check the data handle state */
                if(op->data_handle->state == GLOBUS_L_GFS_DATA_HANDLE_VALID)
                {
                    op->data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_TE_VALID;
                }
                globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gfs_data_end_transfer_kickout,
                    op);
                break;

            /* waiting for a force close callback to return.  will switch
                to the finished state, when the force close callback comes
                back it will continue the finish process */
            case GLOBUS_L_GFS_DATA_ABORT_CLOSING:
                op->state = GLOBUS_L_GFS_DATA_FINISH;
                break;

            case GLOBUS_L_GFS_DATA_COMPLETING:
            case GLOBUS_L_GFS_DATA_COMPLETE:
            case GLOBUS_L_GFS_DATA_FINISH:
            default:
                globus_assert(0 && "Invalid state");
                break;
        }
        globus_gfs_config_inc_int("file_transfer_count", 1);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    GlobusGFSDebugExit();
    return;

err_close:
    globus_l_gfs_data_force_close(op);
    op->cached_res = result;
    op->state = GLOBUS_L_GFS_DATA_FINISH_WITH_ERROR;
    globus_mutex_unlock(&op->session_handle->mutex);
    GlobusGFSDebugExitWithError();
}

static
void
globus_l_gfs_operation_finished_kickout(
    void *                              user_arg)
{
    globus_bool_t                       destroy_session = GLOBUS_FALSE;
    globus_bool_t                       destroy_op = GLOBUS_FALSE;
    globus_l_gfs_data_bounce_t *        bounce;
    void *                              remote_data_arg = NULL;
    globus_l_gfs_data_operation_t *     op;
    GlobusGFSName(globus_l_gfs_operation_finished_kickout);
    GlobusGFSDebugEnter();

    bounce = (globus_l_gfs_data_bounce_t *) user_arg;
    op = bounce->op;

    if(op->callback != NULL)
    {
        op->callback(
            bounce->finished_info,
            op->user_arg);
    }
    else
    {
        if(bounce->finished_info->type == GLOBUS_GFS_OP_SESSION_START)
        {
            globus_gfs_ipc_reply_session(
                op->ipc_handle,
                bounce->finished_info);
        }
        else
        {
            globus_gfs_ipc_reply_finished(
                op->ipc_handle,
                bounce->finished_info);
        }
    }

    globus_mutex_lock(&op->session_handle->mutex);
    {
        GFSDataOpDec(op, destroy_op, destroy_session);
        if(destroy_op)
        {
            remote_data_arg = globus_l_gfs_data_check(
                op->session_handle, op->data_handle);
        }
    }
    globus_mutex_unlock(&op->session_handle->mutex);
 
     /* globus_assert(destroy_op); this was wrong, there could stull
        be an event out there */
    if(destroy_op)
    {
        globus_l_gfs_data_fire_cb(op, remote_data_arg, destroy_session);
        globus_l_gfs_data_operation_destroy(op);
    }

    globus_free(bounce);

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_operation_finished(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_finished_info_t *        finished_info)
{
    globus_l_gfs_data_bounce_t *        bounce;
    globus_l_gfs_data_handle_t *        data_handle;
    globus_bool_t                       kickout = GLOBUS_TRUE;
    GlobusGFSName(globus_gridftp_server_operation_finished);
    GlobusGFSDebugEnter();

    bounce = (globus_l_gfs_data_bounce_t *)
        globus_malloc(sizeof(globus_l_gfs_data_bounce_t));
    if(bounce == NULL)
    {
        globus_panic(NULL, result, "small malloc failure, no recovery");
    }
    bounce->op = op;
    bounce->finished_info = finished_info;

    finished_info->id = op->id;
    finished_info->result = result;

    switch(finished_info->type)
    {
        case GLOBUS_GFS_OP_RECV:
        case GLOBUS_GFS_OP_SEND:
        case GLOBUS_GFS_OP_TRANSFER:
            if(!op->data_handle->is_mine)
            {
                op->bytes_transferred += 
                    finished_info->info.transfer.bytes_transferred;
            }
            globus_gridftp_server_finished_transfer(
                op, finished_info->result);
            kickout = GLOBUS_FALSE;
            break;

        case GLOBUS_GFS_OP_SESSION_START:
            op->session_handle->session_arg =
                (void *) finished_info->info.session.session_arg;
            finished_info->info.session.session_arg = op->session_handle;
            if(finished_info->info.session.username == NULL)
            {
                finished_info->info.session.username = 
                    op->session_handle->username;
            }
            if(finished_info->info.session.home_dir == NULL)
            {
                finished_info->info.session.home_dir = 
                    op->session_handle->home_dir;
            }
            if(result != GLOBUS_SUCCESS)
            {
            }
            break;

        case GLOBUS_GFS_OP_PASSIVE:
        case GLOBUS_GFS_OP_ACTIVE:
            data_handle = (globus_l_gfs_data_handle_t *)
                globus_calloc(1, sizeof(globus_l_gfs_data_handle_t));
            if(data_handle == NULL)
            {
                globus_panic(NULL, result, "small malloc failure, no recovery");
            }
            data_handle->session_handle = op->session_handle;
            data_handle->remote_data_arg = finished_info->info.data.data_arg;
            data_handle->is_mine = GLOBUS_FALSE;
            data_handle->info.mode  = 
                ((globus_gfs_data_info_t *)op->info_struct)->mode;
            data_handle->state = GLOBUS_L_GFS_DATA_HANDLE_VALID;
            finished_info->info.data.data_arg =
                (void *) globus_handle_table_insert(
                    &data_handle->session_handle->handle_table,
                    data_handle,
                    1);
            break;

        default:
            break;
    }
    if(kickout)
    {
        globus_l_gfs_operation_finished_kickout(bounce);
    }
    else
    {
        globus_free(bounce);
    }
/*
    result = globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_gfs_operation_finished_kickout,
        bounce);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        globus_panic(NULL, result, "small malloc failure, no recovery");
    }
*/
    GlobusGFSDebugExit();
}

void
globus_gridftp_server_operation_event(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_event_info_t *           event_info)
{
    GlobusGFSName(globus_gridftp_server_operation_event);
    GlobusGFSDebugEnter();

    event_info->id = op->id;

    /* XXX gotta do a onesot here ?? */
    switch(event_info->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_BEGIN:
            globus_gridftp_server_begin_transfer(
                op, event_info->event_mask, event_info->event_arg);
            break;
        case GLOBUS_GFS_EVENT_BYTES_RECVD:
            if(!op->data_handle->is_mine)
            {
                op->bytes_transferred = event_info->recvd_bytes;
            }
            if(op->writing || op->data_handle->info.mode != 'E')
            {
                break;
            }
        default:
            if(op->event_callback != NULL)
            {
                op->event_callback(
                    event_info,
                    op->user_arg);
            }
            else
            {
                globus_gfs_ipc_reply_event(
                    op->ipc_handle,
                    event_info);
            }
            break;
    }

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_update_bytes_written(
    globus_gfs_operation_t              op,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    GlobusGFSName(globus_gridftp_server_update_bytes_written);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&op->session_handle->mutex);
    {
        op->recvd_bytes += length;
        globus_range_list_insert(
            op->recvd_ranges, offset + op->transfer_delta, length);
    }
    globus_mutex_unlock(&op->session_handle->mutex);

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_optimal_concurrency(
    globus_gfs_operation_t              op,
    int *                               count)
{
    GlobusGFSName(globus_gridftp_server_get_optimal_concurrency);
    GlobusGFSDebugEnter();

    if(!op->writing)
    {
        /* query number of currently connected streams and update
            data_info (only if recieving) */
        globus_ftp_control_data_query_channels(
            &op->data_handle->data_channel,
            &op->data_handle->info.nstreams,
            0);

        if(op->data_handle->info.nstreams == 0)
        {
            op->data_handle->info.nstreams = 1;
        }
    }

    *count = op->data_handle->info.nstreams * op->stripe_count * 2;

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_block_size(
    globus_gfs_operation_t              op,
    globus_size_t *                     block_size)
{
    GlobusGFSName(globus_gridftp_server_get_block_size);
    GlobusGFSDebugEnter();
    if(op->data_handle != NULL && op->data_handle->is_mine)
    {
        *block_size = op->data_handle->info.blocksize;
    }
    else
    {
        *block_size = (globus_size_t) globus_i_gfs_config_int("blocksize");
    }
    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_stripe_block_size(
    globus_gfs_operation_t              op,
    globus_size_t *                     stripe_block_size)
{
    GlobusGFSName(globus_gridftp_server_get_stripe_block_size);
    GlobusGFSDebugEnter();
    if(op->data_handle != NULL && op->data_handle->is_mine)
    {
        *stripe_block_size = op->data_handle->info.stripe_blocksize;
    }
    else
    {
        *stripe_block_size = 
            (globus_size_t) globus_i_gfs_config_int("stripe_blocksize");
    }
    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_session_uid(
    globus_gfs_operation_t              op,
    uid_t *                             uid)
{
    GlobusGFSName(globus_gridftp_server_get_session_uid);
    GlobusGFSDebugEnter();

    *uid = op->session_handle->uid;

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_session_username(
    globus_gfs_operation_t              op,
    char **                             username)
{
    GlobusGFSName(globus_gridftp_server_get_session_username);
    GlobusGFSDebugEnter();

    *username = globus_libc_strdup(op->session_handle->real_username);

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_config_string(
    globus_gfs_operation_t              op,
    char **                             config_string)
{
    GlobusGFSName(globus_gridftp_server_get_config_string);
    GlobusGFSDebugEnter();

    *config_string = globus_libc_strdup(
        globus_i_gfs_config_string("dsi_options"));

    GlobusGFSDebugExit();
}


/* this is used to translate the restart and partial offset/lengths into
    a sets of ranges to transfer... storage interface shouldn't know about
    partial or restart semantics, it only needs to know which offsets to
    read from the data source, and what offset to write to data sink
    (dest offset only matters for mode e, but again, storage interface
    doesn't know about modes)
*/
void
globus_gridftp_server_get_write_range(
    globus_gfs_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length)
{
    globus_off_t                        tmp_off = 0;
    globus_off_t                        tmp_len = -1;
    globus_off_t                        tmp_write = 0;
    globus_off_t                        tmp_transfer = 0;
    int                                 rc;
    GlobusGFSName(globus_gridftp_server_get_write_range);
    GlobusGFSDebugEnter();

    if(globus_range_list_size(op->range_list))
    {
        rc = globus_range_list_remove_at(
            op->range_list,
            0,
            &tmp_off,
            &tmp_len);
    }
    if(op->data_handle->info.mode == 'S')
    {
        tmp_write = tmp_off;
    }
    if(op->partial_offset > 0)
    {
        tmp_off += op->partial_offset;
        tmp_write += op->partial_offset;
        tmp_transfer = 0 - op->partial_offset;
    }
    if(offset)
    {
        *offset = tmp_off;
    }
    if(length)
    {
        *length = tmp_len;
    }
    op->write_delta = tmp_write;
    op->transfer_delta = tmp_transfer;

    GlobusGFSDebugExit();
}

void
globus_gridftp_server_get_read_range(
    globus_gfs_operation_t              op,
    globus_off_t *                      offset,
    globus_off_t *                      length)
{
    globus_off_t                        tmp_off = 0;
    globus_off_t                        tmp_len = -1;
    globus_off_t                        tmp_write = 0;
    int                                 rc;
    globus_off_t                        start_offset;
    globus_off_t                        end_offset;
    globus_off_t                        stripe_block_size;
    int                                 size;
    int                                 i;
    globus_gfs_transfer_info_t *        info;
    globus_off_t                        part_size;
    GlobusGFSName(globus_gridftp_server_get_read_range);
    GlobusGFSDebugEnter();

    /* this whole function is crazy ugly and inneffiecient...
       needs rethinking */
    globus_mutex_lock(&op->session_handle->mutex);
    {
        if(op->node_count > 1)
        {
            switch(op->data_handle->info.stripe_layout)
            {
                case GLOBUS_GFS_LAYOUT_PARTITIONED:
                    info = (globus_gfs_transfer_info_t *) op->info_struct;
                    if(op->partial_length > 0)
                    {
                        part_size = op->partial_length;
                    }
                    else
                    {
                        part_size = info->alloc_size;
                    }
                    stripe_block_size = part_size / op->node_count;
                    if(part_size <= 0)
                    {
                        stripe_block_size =
                            op->data_handle->info.stripe_blocksize;                        
                    }
                    else if(part_size % op->node_count)
                    {
                        stripe_block_size++;
                    }
                    break;
                    
                case GLOBUS_GFS_LAYOUT_BLOCKED:
                default:
                    stripe_block_size = op->data_handle->info.stripe_blocksize;
                    break;
            }
            start_offset = op->stripe_chunk * stripe_block_size;
            end_offset = start_offset + stripe_block_size;

            if(globus_range_list_size(op->stripe_range_list))
            {
                rc = globus_range_list_remove_at(
                    op->stripe_range_list,
                    0,
                    &tmp_off,
                    &tmp_len);

                tmp_write = op->write_delta;
            }
            else if((size = globus_range_list_size(op->range_list)) != 0)
            {
                for(i = 0; i < size; i++)
                {
                    rc = globus_range_list_at(
                        op->range_list,
                        i,
                        &tmp_off,
                        &tmp_len);

                    if(op->partial_length != -1)
                    {
                        if(tmp_len == -1)
                        {
                            tmp_len = op->partial_length;
                        }
                        if(tmp_off + tmp_len > op->partial_length)
                        {
                            tmp_len = op->partial_length - tmp_off;
                            if(tmp_len < 0)
                            {
                                tmp_len = 0;
                            }
                        }
                    }

                    if(op->partial_offset > 0)
                    {
                        tmp_off += op->partial_offset;
                        tmp_write = 0 - op->partial_offset;
                    }

                    globus_range_list_insert(
                        op->stripe_range_list, tmp_off, tmp_len);
                    op->write_delta = tmp_write;
                }
                globus_range_list_remove(
                    op->stripe_range_list, 0, start_offset);
                globus_range_list_remove(
                    op->stripe_range_list, end_offset, GLOBUS_RANGE_LIST_MAX);
                op->stripe_chunk += op->node_count;

                if(globus_range_list_size(op->stripe_range_list))
                {
                    rc = globus_range_list_remove_at(
                        op->stripe_range_list,
                        0,
                        &tmp_off,
                        &tmp_len);

                    tmp_write = op->write_delta;
                }
                else
                {
                    tmp_len = 0;
                    tmp_off = 0;
                    tmp_write = 0;
                }
            }
            else
            {
                tmp_len = 0;
            }
        }
        else if(globus_range_list_size(op->range_list))
        {
            rc = globus_range_list_remove_at(
                op->range_list,
                0,
                &tmp_off,
                &tmp_len);

            if(op->partial_length != -1)
            {
                if(tmp_len == -1)
                {
                    tmp_len = op->partial_length;
                }
                if(tmp_off + tmp_len > op->partial_length)
                {
                    tmp_len = op->partial_length - tmp_off;
                    if(tmp_len < 0)
                    {
                        tmp_len = 0;
                    }
                }
            }

            if(op->partial_offset > 0)
            {
                tmp_off += op->partial_offset;
                if(op->data_handle->info.mode == 'E')
                {
                    tmp_write = 0 - op->partial_offset;
                }
            }
        }
        else
        {
            tmp_len = 0;
        }

    }
    globus_mutex_unlock(&op->session_handle->mutex);
    if(offset)
    {
        *offset = tmp_off;
    }
    if(length)
    {
        *length = tmp_len;
    }
    op->write_delta = tmp_write;
    
    GlobusGFSDebugExit();
}

globus_result_t
globus_gridftp_server_register_read(
    globus_gfs_operation_t   op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_gfs_data_bounce_t *        bounce_info;
    GlobusGFSName(globus_gridftp_server_register_read);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);

error_alloc:
    GlobusGFSDebugExitWithError();
    return result;
}


globus_result_t
globus_gridftp_server_register_write(
    globus_gfs_operation_t   op,
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
    GlobusGFSDebugEnter();

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

    if(op->data_handle->info.mode == 'E' && op->stripe_count > 1)
    {
        /* XXX not sure what this is all about */
        globus_mutex_lock(&op->session_handle->mutex);
        {
            if(stripe_ndx != -1)
            {
                op->write_stripe = stripe_ndx;
            }
            if(op->write_stripe >= op->stripe_count)
            {
                op->write_stripe %= op->stripe_count;
            }
            result = globus_ftp_control_data_write_stripe(
                &op->data_handle->data_channel,
                buffer,
                length,
                offset + op->write_delta,
                GLOBUS_FALSE,
                op->write_stripe,
                globus_l_gfs_data_write_cb,
                bounce_info);

            op->write_stripe++;
        }
        globus_mutex_unlock(&op->session_handle->mutex);
    }
    else
    {
        result = globus_ftp_control_data_write(
            &op->data_handle->data_channel,
            buffer,
            length,
            offset + op->write_delta,
            GLOBUS_FALSE,
            globus_l_gfs_data_write_cb,
            bounce_info);
    }
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_ftp_control_data_write", result);
        goto error_register;
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    globus_free(bounce_info);

error_alloc:
    GlobusGFSDebugExitWithError();
    return result;
}

void
globus_gridftp_server_finished_session_start(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    void *                              session_arg,
    char *                              username,
    char *                              home_dir)
{
    globus_gfs_finished_info_t          finished_info;                         
    GlobusGFSName(globus_gridftp_server_finished_session_start);
    GlobusGFSDebugEnter();

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;          
    finished_info.result = result;          
    finished_info.info.session.session_arg = session_arg;                          
    finished_info.info.session.username = username;                          
    finished_info.info.session.home_dir = home_dir;                          
                                                              
    globus_gridftp_server_operation_finished(                 
        op,                                                   
        result,                                               
        &finished_info);
   
    if(result != GLOBUS_SUCCESS)
    { 
        globus_l_gfs_free_session_handle(op->session_handle);
    } 
    GlobusGFSDebugExit();
}    

void
globus_gridftp_server_finished_active_data(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    void *                              data_arg,
    globus_bool_t                       bi_directional)
{
    globus_gfs_finished_info_t          finished_info;                         
    GlobusGFSName(globus_gridftp_server_finished_active_data);
    GlobusGFSDebugEnter();

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_ACTIVE;          
    finished_info.result = result;          
    finished_info.info.data.data_arg = data_arg;                          
    finished_info.info.data.bi_directional = bi_directional;                          
                                                              
    globus_gridftp_server_operation_finished(                 
        op,                                                   
        result,                                               
        &finished_info);
    
    GlobusGFSDebugExit();
}    

void
globus_gridftp_server_finished_passive_data(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    void *                              data_arg,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count)
{
    globus_gfs_finished_info_t          finished_info;                         
    GlobusGFSName(globus_gridftp_server_finished_passive_data);
    GlobusGFSDebugEnter();

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_PASSIVE;          
    finished_info.result = result;          
    finished_info.info.data.data_arg = data_arg;                          
    finished_info.info.data.bi_directional = bi_directional;                          
    finished_info.info.data.contact_strings = contact_strings;                          
    finished_info.info.data.cs_count = cs_count;                          
                                                              
    globus_gridftp_server_operation_finished(                 
        op,                                                   
        result,                                               
        &finished_info);
    
    GlobusGFSDebugExit();
}    

void
globus_i_gfs_data_request_set_cred(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    gss_cred_id_t                       del_cred)
{
    globus_l_gfs_data_session_t *       session_handle;
    GlobusGFSName(globus_i_gfs_data_request_set_cred);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    if(del_cred != NULL)
    {
        session_handle->del_cred = del_cred;
    }
    if(session_handle->dsi->set_cred_func != NULL)
    {
        session_handle->dsi->set_cred_func(
            del_cred, session_handle->session_arg);
    }

    GlobusGFSDebugExit();
    return;
}


/* this end receives the buffer */
void
globus_i_gfs_data_request_buffer_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    globus_byte_t *                     buffer,
    int                                 buffer_type,
    globus_size_t                       buffer_len)
{
    globus_l_gfs_data_session_t *       session_handle;
    GlobusGFSName(globus_i_gfs_data_request_buffer_send);
    GlobusGFSDebugEnter();

    session_handle = (globus_l_gfs_data_session_t *) session_arg;

    if(buffer_type & GLOBUS_GFS_BUFFER_SERVER_DEFINED)
    {
        switch(buffer_type)
        {
            case GLOBUS_GFS_BUFFER_EOF_INFO:
                break;
            default:
                break;
        }
    }

    if(session_handle->dsi->buffer_send_func != NULL)
    {
        session_handle->dsi->buffer_send_func(
            buffer_type, buffer, buffer_len, session_handle->session_arg);
    }

    GlobusGFSDebugExit();
    return;
}

static
globus_result_t
globus_l_gfs_set_stack(
    globus_l_gfs_data_handle_t *        handle)
{
    globus_result_t                     result;
    gfs_i_stack_entry_t *               stack_ent;
    globus_list_t *                     driver_list;
    globus_list_t *                     list;
    globus_xio_stack_t                  stack;

    globus_xio_stack_init(&stack, NULL);
    driver_list = (globus_list_t *) globus_i_gfs_config_list("net_stack_list");
    globus_i_ftp_control_data_get_attr(&handle->data_channel, &handle->xio_attr);
    for(list = driver_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        stack_ent = (gfs_i_stack_entry_t *) globus_list_first(list);

        result = GLOBUS_SUCCESS;
        if(strcmp(stack_ent->driver_name, "gsi") == 0)
        {
            if(handle->info.dcau != 'N')
            {
                result = globus_xio_stack_push_driver(
                    stack, stack_ent->driver);
            }
        }
        else
        {
            result=globus_xio_stack_push_driver(stack, stack_ent->driver);
        }
        if(result != GLOBUS_SUCCESS)
        {
            goto error_control;
        }
        /* this should go away after demo? */
        if(stack_ent->opts != NULL)
        {
            /* ignore error */
            globus_xio_attr_cntl(
                handle->xio_attr,
                stack_ent->driver,
                GLOBUS_XIO_SET_STRING_OPTIONS,
                stack_ent->opts);
        }
    }
    globus_i_ftp_control_data_set_stack(&handle->data_channel, stack);

    globus_xio_stack_destroy(stack);

    return GLOBUS_SUCCESS;
error_control:

    globus_xio_stack_destroy(stack);
    return result;
}
