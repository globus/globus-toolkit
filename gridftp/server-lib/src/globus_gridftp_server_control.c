#include "globus_i_gridftp_server_control.h"
#include "version.h"
#include "globus_gridftp_server_control_pmod_959.h"
#include <sys/utsname.h>

#define GlobusGSUserDoneKickout(_in_server)                             \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    if(_in_server->done_func != NULL)                                   \
    {                                                                   \
        _in_server->ref++;                                              \
        _res = globus_callback_space_register_oneshot(                  \
                    NULL,                                               \
                    NULL,                                               \
                    globus_l_gsc_user_done_kickout,                     \
                    (void *)_in_server,                                 \
                    GLOBUS_CALLBACK_GLOBAL_SPACE);                      \
        globus_assert(_res == GLOBUS_SUCCESS); /* don't do this */      \
    }                                                                   \
} while(0)

#define GlobusGSUserStopKickout(_in_server)                             \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    _res = globus_callback_space_register_oneshot(                      \
                NULL,                                                   \
                NULL,                                                   \
                globus_l_gsc_user_stop_kickout,                         \
                (void *)_in_server,                                     \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    globus_assert(_res == GLOBUS_SUCCESS); /* don't do this */          \
} while(0)

/**************************************************************************
 *                  funciton prototypes and typedefs
 *
 *************************************************************************/
static int
globus_l_gsc_activate();

static int
globus_l_gsc_deactivate();

static void
globus_l_gsc_user_op_kickout(
    void *                                          user_arg);

static void
globus_l_gsc_user_stop_kickout(
    void *                                          user_arg);

static void
globus_l_gsc_user_done_kickout(
    void *                                          user_arg);

void
globus_l_gsc_operation_destroy(
    globus_i_gsc_op_t *                             i_op);

static void
globus_l_gsc_protocol_stop_callback(
    globus_i_gsc_server_t *                         i_server);

static void
globus_l_gsc_callback_return(
    globus_i_gsc_server_t *                         i_server);

static globus_result_t
globus_l_gsc_perform_op(
    globus_i_gsc_op_t *                             i_op);

char *
globus_i_gsc_concat_path(
    globus_i_gsc_server_t *                         i_server,
    const char *                                    in_path);
/**************************************************************************
 *                         global data members 
 *
 *************************************************************************/
globus_module_descriptor_t      globus_i_gridftp_server_control_module =
{
    "globus_gridftp_server",
    globus_l_gsc_activate,
    globus_l_gsc_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static globus_gridftp_server_control_attr_t globus_l_gsc_default_attr;

GlobusDebugDefine(GLOBUS_GRIDFTP_SERVER_CONTROL);

static int
globus_l_gsc_activate()
{
    int                                     rc = 0;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != 0)
    {
        return rc;
    }

    /* add all the default command handlers */

    globus_gridftp_server_control_attr_init(&globus_l_gsc_default_attr);
    globus_l_gsc_959_init();

    return rc;
}

static int
globus_l_gsc_deactivate()
{
    int                                     rc;

    globus_gridftp_server_control_attr_destroy(globus_l_gsc_default_attr);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);

    return rc;
}

/**************************************************************************
 *                      user functions
 *                      --------------
 *
 *  init
 *
 *  start
 *
 *  stop
 *
 *  destroy
 *
 *************************************************************************/
globus_result_t
globus_gridftp_server_control_init(
    globus_gridftp_server_control_t *               server)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    struct utsname                                  uname_buf;
    GlobusGridFTPServerName(globus_gridftp_server_control_init);

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    i_server = (globus_i_gsc_server_t *) globus_malloc(
        sizeof(globus_i_gsc_server_t));
    if(i_server == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("i_server");
        goto err;
    }

    memset(i_server, '\0', sizeof(globus_i_gsc_server_t));
    globus_mutex_init(&i_server->mutex, NULL);
    i_server->state = GLOBUS_L_GS_STATE_STOPPED;
    i_server->banner = globus_libc_strdup("GridFTP server "__DATE__);
    i_server->cwd = globus_libc_strdup("/");

    uname(&uname_buf);
    i_server->syst = globus_libc_strdup(uname_buf.sysname);
    *server = i_server;

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gridftp_server_control_destroy(
    globus_gridftp_server_control_t                 server)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_destroy);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }
    if(i_server->state != GLOBUS_L_GS_STATE_STOPPED)
    {
        res = GlobusGridFTPServerErrorState(i_server->state);
        goto err;
    }

    /* if in stopped state we should be at a ref of 0 */
    globus_assert(i_server->ref == 0);

    globus_mutex_destroy(&i_server->mutex);
    globus_free(i_server->banner);
    globus_free(i_server->syst);
    globus_free(i_server);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gridftp_server_control_start(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_attr_t            attr,
    globus_xio_handle_t                             xio_handle,
    void *                                          user_arg)
{
    globus_i_gsc_server_t *                         i_server;
    globus_i_gsc_attr_t *                           i_attr;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_start);

    i_attr = (globus_i_gsc_attr_t *) attr;
    if(i_attr == NULL)
    {
        i_attr = globus_l_gsc_default_attr;
    }

    i_server = (globus_i_gsc_server_t *) server;

    globus_mutex_lock(&i_server->mutex);
    {
        if(i_server->state != GLOBUS_L_GS_STATE_STOPPED)
        {
            globus_mutex_unlock(&i_server->mutex);
            goto err;
        }

        i_server->pmod = i_attr->pmod;
        i_server->xio_handle = xio_handle;
        globus_hashtable_copy(
            &i_server->send_table, &i_attr->send_func_table, NULL);
        globus_hashtable_copy(
            &i_server->recv_table, &i_attr->recv_func_table, NULL);
        i_server->resource_func = i_attr->resource_func;
        i_server->auth_cb = i_attr->auth_func;
        i_server->done_func = i_attr->done_func;
        i_server->passive_func = i_attr->passive_func;
        i_server->active_func = i_attr->active_func;

        globus_fifo_init(&i_server->data_q);

        if(i_server->modes == NULL)
        {
            globus_free(i_server->modes);
        }
        if(i_server->types == NULL)
        {
            globus_free(i_server->types);
        }
        i_server->modes = globus_libc_strdup(i_attr->modes);
        i_server->types = globus_libc_strdup(i_attr->types);
        i_server->cwd = globus_libc_strdup(i_attr->base_dir);

        /* can bypass _AUTH state ad go directly to _OPEN */
        i_server->state = i_attr->start_state;
        i_server->user_arg = user_arg;
        i_server->ref = 1; /* reference until user tells it to stop */

        /* NOTE: This is called locked */
        res = i_server->pmod->start_func(
                server, 
                i_server->xio_handle, 
                &i_server->proto_arg);

        if(res != GLOBUS_SUCCESS)
        {
            i_server->ref = 0;
            globus_mutex_unlock(&i_server->mutex);
            goto err;
        }
    } 
    globus_mutex_unlock(&i_server->mutex);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gridftp_server_control_stop(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_callback_t        done_callback,
    void *                                          user_arg)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_stop);
   
    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    i_server = (globus_i_gsc_server_t *) server;

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* if already stooped set error and return it */
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_STOPPED:
                break;

            case GLOBUS_L_GS_STATE_OPEN:
            case GLOBUS_L_GS_STATE_AUTH:
            case GLOBUS_L_GS_STATE_ERROR:
                /* remove the referebce the server has to itself */
                i_server->ref--;
                i_server->state = GLOBUS_L_GS_STATE_STOPPING;
                /* if it is already done just kick it out */
                if(i_server->ref == 0)
                {
                    GlobusGSUserStopKickout(i_server);
                }
                break;

            default:
                globus_assert(0 && "possible memory currption");
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/*************************************************************************
 *                      operation functions
 *                      -------------------
 ************************************************************************/
/*
 *  This kicks out an operation to 
 */
static void
globus_l_gsc_user_op_kickout(
    void *                                  user_arg)
{
    globus_i_gsc_op_t *                      i_op;

    i_op = (globus_i_gsc_op_t *) user_arg;

    switch(i_op->type)
    {
        case GLOBUS_L_GSC_OP_TYPE_AUTH:
            i_op->server->auth_cb(
                i_op,
                i_op->username,
                i_op->password,
                i_op->cred,
                i_op->del_cred);
            break;

        case GLOBUS_L_GSC_OP_TYPE_RESOURCE:
            i_op->server->resource_func(
                i_op,
                i_op->path,
                i_op->mask);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PASV:
            i_op->server->passive_func(
                i_op,
                i_op->net_prt,
                i_op->max_cs);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PORT:
            i_op->server->active_func(
                i_op,
                i_op->net_prt,
                (const char **)i_op->cs,
                i_op->max_cs);
            break;

        default:
            globus_assert(0);
            break;
    }
}

static globus_result_t
globus_l_gsc_perform_op(
    globus_i_gsc_op_t *                             i_op)
{
    globus_result_t                                 res = GLOBUS_SUCCESS;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_l_gsc_perform_op);

    i_server = i_op->server;

    switch(i_server->state)
    {
        case GLOBUS_L_GS_STATE_AUTH:
        case GLOBUS_L_GS_STATE_OPEN:

            i_server->ref++;

            /* register callback */
            res = globus_callback_space_register_oneshot(
                NULL,
                NULL,
                globus_l_gsc_user_op_kickout,
                (void *)i_op,
                GLOBUS_CALLBACK_GLOBAL_SPACE);
            break;

        /*
         *  If stopping simply return an error to the proto mod
         */
        case GLOBUS_L_GS_STATE_STOPPED:
        case GLOBUS_L_GS_STATE_STOPPING:
        case GLOBUS_L_GS_STATE_ERROR:
            res = GlobusGridFTPServerErrorState(i_server->state);
            break;

        default:
            globus_assert(0 && "bad state, likely mem corruption.");
            break;
    }

    return res;
}

globus_result_t
globus_gridftp_server_control_pmod_command_cancel(
    globus_gridftp_server_control_t                 server)
{
    return GLOBUS_SUCCESS;
}

/*************************************************************************
 *                      get functions
 *                      -------------
 ************************************************************************/
globus_bool_t
globus_gridftp_server_control_authenticated(
    globus_gridftp_server_control_t                 server)
{
    globus_bool_t                                   rc;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_authenticated);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GLOBUS_FALSE;
    }
    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_OPEN:
                rc = GLOBUS_TRUE;
                break;

            default:
                rc = GLOBUS_FALSE;
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return rc;
}

globus_result_t
globus_gridftp_server_control_get_banner(
    globus_gridftp_server_control_t                 server,
    char **                                         banner)
{
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_banner);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(banner == NULL)
    {
        return GlobusGridFTPServerErrorParameter("mode");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                *banner = i_server->banner;
                res = GLOBUS_SUCCESS;
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_get_mode(
    globus_gridftp_server_control_t                 server,
    char *                                          mode)
{
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_mode);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(mode == NULL)
    {
        return GlobusGridFTPServerErrorParameter("mode");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                *mode = i_server->mode;
                res = GLOBUS_SUCCESS;
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_get_type(
    globus_gridftp_server_control_t                 server,
    char *                                          type)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_type);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(type == NULL)
    {
        return GlobusGridFTPServerErrorParameter("type");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                *type = i_server->type;
                res = GLOBUS_SUCCESS;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_get_client_id(
    globus_gridftp_server_control_t                 server,
    uid_t *                                         uid)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_client_id);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(uid == NULL)
    {
        return GlobusGridFTPServerErrorParameter("uid");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                *uid = i_server->uid;
                res = GLOBUS_SUCCESS;
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}
                                                                                
globus_result_t
globus_gridftp_server_control_get_cwd(
    globus_gridftp_server_control_t                 server,
    char **                                         cwd_string)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_cwd);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(cwd_string == NULL)
    {
        return GlobusGridFTPServerErrorParameter("cwd_string");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                *cwd_string = globus_libc_strdup(i_server->cwd);
                res = GLOBUS_SUCCESS;
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_set_cwd(
    globus_gridftp_server_control_t                 server,
    char *                                          dir)
{
    char *                                          tmp_str;
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_set_cwd);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(dir == NULL)
    {
        return GlobusGridFTPServerErrorParameter("dir");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                res = GLOBUS_SUCCESS;
                tmp_str = globus_i_gsc_concat_path(i_server, dir);
                if(tmp_str == NULL)
                {
                    res = GlobusGridFTPServerErrorParameter("dir");
                }
                else
                {
                    globus_free(i_server->cwd);
                    i_server->cwd = tmp_str;
                }
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_get_system(
    globus_gridftp_server_control_t                 server,
    char **                                         syst_string)
{
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_system);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(syst_string == NULL)
    {
        return GlobusGridFTPServerErrorParameter("syst_string");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            /* all others are ok */
            default:
                *syst_string = globus_libc_strdup(i_server->syst);
                res = GLOBUS_SUCCESS;
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

/*
 *  set functions
 */
globus_result_t
globus_gridftp_server_control_ping(
    globus_gridftp_server_control_t                 server)
{
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_ping);

    i_server = (globus_i_gsc_server_t *) server;
    globus_mutex_lock(&i_server->mutex);
    {
        i_server->refresh = GLOBUS_TRUE;
    }
    globus_mutex_unlock(&i_server->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_set_mode(
    globus_gridftp_server_control_t                 server,
    char                                            mode)
{
    char                                            ch;
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_set_mode);

    i_server = (globus_i_gsc_server_t *) server;
    
    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;
                                                                                
            /* all others are ok */
            default:
                ch = toupper(mode);
                if(strchr(i_server->modes, ch) == NULL)
                {
                    res = GlobusGridFTPServerErrorParameter("mode");
                }
                else
                {
                    i_server->mode = mode;
                    res = GLOBUS_SUCCESS;
                }
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}
                                                                                
globus_result_t
globus_gridftp_server_control_set_type(
    globus_gridftp_server_control_t                 server,
    char                                            type)
{
    char                                            ch;
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_set_type);

    i_server = (globus_i_gsc_server_t *) server;
    
    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /* invalid states */
            case GLOBUS_L_GS_STATE_NONE:
            case GLOBUS_L_GS_STATE_STOPPED:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_ERROR:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;
                                                                                
            /* all others are ok */
            default:
                ch = toupper(type);
                if(strchr(i_server->types, ch) == NULL)
                {
                    res = GlobusGridFTPServerErrorParameter("type");
                }
                else
                {
                    i_server->type = type;
                    res = GLOBUS_SUCCESS;
                }
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_get_status(
    globus_gridftp_server_control_t                 server,
    char **                                         status)
{
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_resource_cb);

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(status == NULL)
    {
        return GlobusGridFTPServerErrorParameter("status");
    }

    i_server = (globus_i_gsc_server_t *) server;

    /* TODO, make this some sort of real status message */
    *status = globus_libc_strdup("GridFTP server status");

    return GLOBUS_SUCCESS;
}

/*************************************************************************
 *                      internal commands
 *
 ************************************************************************/

/*
 *  called after all user or protocol callbacks have returned.
 *
 *  decrement the reference count, then check the state.  If stopping
 *  Then we kickout the stop callback when the reference count goes to xero.
 */
static void
globus_l_gsc_callback_return(
    globus_i_gsc_server_t *                         i_server)
{
    GlobusGridFTPServerName(globus_l_gsc_callback_return);

    i_server->ref--;
                                                                                
    switch(i_server->state)
    {
        /* nothing to do in this  state */
        case GLOBUS_L_GS_STATE_OPEN:
        case GLOBUS_L_GS_STATE_AUTH:
        case GLOBUS_L_GS_STATE_ERROR:
            break;
                                                                                
        /* in error or stoping we may have to tell the protocol
           module that we are finished */
        case GLOBUS_L_GS_STATE_STOPPING:
            if(i_server->ref == 0)
            {
                GlobusGSUserStopKickout(i_server);
            }
            break;
                                                                                
        /* no other state is valid */
        default:
            globus_assert(0 && "possible memory curroption");
            break;
    }
}

/*
 *  When this is called the protocol module is telling us they are finished
 *  with the xio_handle.  
 */
static void
globus_l_gsc_protocol_stop_callback(
    globus_i_gsc_server_t *                         i_server)
{
    /* this call will remove the reference that the protcol module held. */
    if(i_server->user_stop_func != NULL)
    {
        i_server->user_stop_func(
            i_server, 
            i_server->cached_res, i_server->user_arg);
    }
    i_server->state = GLOBUS_L_GS_STATE_STOPPED;
}

static void
globus_l_gsc_user_done_kickout(
    void *                                          user_arg)
{
    globus_i_gsc_server_t *                         i_server;

    i_server = (globus_i_gsc_server_t *) user_arg;

    globus_assert(i_server->done_func != NULL &&
        "should not have been registered if null");
    /* call the users callback.  They will call back in when done stoping */
    i_server->done_func(
        i_server,
        i_server->cached_res,
        i_server->user_arg);

    globus_mutex_lock(&i_server->mutex);
    {
        globus_l_gsc_callback_return(i_server);
    }
    globus_mutex_unlock(&i_server->mutex);
}

/* 
 *  have to call into protocol module
 */
static void
globus_l_gsc_user_stop_kickout(
    void *                                          user_arg)
{
    globus_result_t                                 res;
    globus_i_gsc_server_t *                         i_server;

    i_server = (globus_i_gsc_server_t *) user_arg;

    globus_assert(i_server->ref == 0);
    if(i_server->pmod->stop_func != NULL)
    {
        res = i_server->pmod->stop_func(
            i_server,
            globus_l_gsc_protocol_stop_callback,
            i_server->proto_arg);
        if(res != GLOBUS_SUCCESS)
        {
            globus_l_gsc_protocol_stop_callback(i_server);
        }
    }
    else
    {
        globus_l_gsc_protocol_stop_callback(i_server);
    }
}

/************************************************************************
 *                  pmod commands
 *                  -------------
 ***********************************************************************/
static void
globus_l_gsc_op_destroy(
    globus_i_gsc_op_t *                             i_op)
{
    if(i_op->username != NULL)
    {
        globus_free(i_op->username);
    }
    if(i_op->password != NULL)
    {
        globus_free(i_op->password);
    }
    if(i_op->path != NULL)
    {
        globus_free(i_op->path);
    }
    globus_free(i_op);
}

globus_result_t
globus_l_gridftp_server_control_connect(
    globus_i_gsc_op_t *                             i_op,
    void *                                          user_data_handle,
    globus_result_t                                 res,
    const char **                                   cs,
    int                                             cs_count)
{
    void *                                          tmp_ptr;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_resource);

    if(i_op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    i_server = i_op->server;
    if(i_op->type == GLOBUS_L_GSC_OP_TYPE_CREATE_PASV)
    {
        i_op->passive_cb(
            i_server,
            res,
            cs,
            cs_count,
            i_op->user_arg);
    }
    else if(i_op->type == GLOBUS_L_GSC_OP_TYPE_CREATE_PORT)
    {
        i_op->port_cb(
            i_server,
            res,
            i_op->user_arg);
        globus_free(i_op->cs);
    }
    else
    {
        return GlobusGridFTPServerErrorParameter("op");
    }


    globus_mutex_lock(&i_server->mutex);
    {
        tmp_ptr = globus_fifo_dequeue(&i_server->data_q);
        globus_assert(tmp_ptr == i_op);

        if(globus_fifo_empty(&i_server->data_q))
        {
            globus_l_gsc_callback_return(i_server);
        }
        else
        {
            tmp_ptr = globus_fifo_peek(&i_server->data_q);

            globus_callback_space_register_oneshot(
                NULL,
                NULL,
                globus_l_gsc_user_op_kickout,
                tmp_ptr,
                GLOBUS_CALLBACK_GLOBAL_SPACE);
        }
        globus_free(i_op);
    }
    globus_mutex_unlock(&i_server->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_passive_connect(
    globus_gridftp_server_control_operation_t       op,
    void *                                          user_data_handle,
    globus_result_t                                 res,
    const char **                                   cs,
    int                                             cs_count)
{
    return globus_l_gridftp_server_control_connect(
        op,
        user_data_handle,
        res,
        cs,
        cs_count);
}

globus_result_t
globus_gridftp_server_control_finished_active_connect(
    globus_gridftp_server_control_operation_t       op,
    void *                                          user_data_handle,
    globus_result_t                                 res)
{
    return globus_l_gridftp_server_control_connect(
        op,
        user_data_handle,
        res,
        NULL,
        0);
}

globus_result_t
globus_gridftp_server_control_finished_resource(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 result,
    globus_gridftp_server_control_stat_t *          stat_info_array,
    int                                             stat_count)
{
    globus_i_gsc_server_t *                         i_server;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_resource);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    i_op = (globus_i_gsc_op_t *) op;
    if(i_op->type != GLOBUS_L_GSC_OP_TYPE_RESOURCE)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    i_server = i_op->server;

    i_op->stat_cb(
        i_server,
        result,
        stat_info_array,
        stat_count,
        i_op->user_arg);

    globus_l_gsc_op_destroy(i_op);
    globus_free(stat_info_array);

    globus_mutex_lock(&i_server->mutex);
    {
        globus_l_gsc_callback_return(i_server);
    }
    globus_mutex_unlock(&i_server->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_finished_auth(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 res,
    uid_t                                           uid)
{
    globus_i_gsc_server_t *                         i_server;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_auth);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    i_op = (globus_i_gsc_op_t *) op;
    if(i_op->type != GLOBUS_L_GSC_OP_TYPE_AUTH)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    i_server = i_op->server;

    if(res == GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&i_server->mutex);
        {
            /* if not in STATE_AUTH, we will deal with it in callback_return */
            if(i_server->state == GLOBUS_L_GS_STATE_AUTH)
            {
                i_server->state = GLOBUS_L_GS_STATE_OPEN;
            }
            i_server->uid = uid;
        }
        globus_mutex_unlock(&i_server->mutex);
    }
    i_op->auth_cb(
        i_server,
        res,
        i_op->user_arg);

    globus_l_gsc_op_destroy(i_op);

    globus_mutex_lock(&i_server->mutex);
    {
        globus_l_gsc_callback_return(i_server);
    }
    globus_mutex_unlock(&i_server->mutex);

    return GLOBUS_SUCCESS;
}


globus_result_t
globus_gridftp_server_control_pmod_stat(
    globus_gridftp_server_control_t                 server,
    const char *                                    path,
    globus_gridftp_server_control_resource_mask_t   mask,
    globus_gridftp_server_control_pmod_stat_callback_t   cb,
    void *                                          user_arg)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_pmod_authenticate);

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    i_server = server;
    if(path == NULL)
    {
        return GlobusGridFTPServerErrorParameter("path");
    }

    i_op = (globus_i_gsc_op_t *) globus_malloc(sizeof(globus_i_gsc_op_t));
    if(i_op == NULL)
    {
        return GlobusGridFTPServerErrorMemory("i_op");
    }
    memset(i_op, '\0', sizeof(globus_i_gsc_op_t));

    i_op->server = i_server;
    i_op->type = GLOBUS_L_GSC_OP_TYPE_RESOURCE;
    i_op->res = GLOBUS_SUCCESS;
    i_op->user_arg = user_arg;

    i_op->stat_cb = cb;
    i_op->mask = mask;

    i_op->path = globus_i_gsc_concat_path(i_server, path);
    if(i_op->path == NULL)
    {
        globus_free(i_op);
        res = GlobusGridFTPServerErrorParameter("path");
    }
    else
    {
        globus_mutex_lock(&i_server->mutex);
        {
            res = globus_l_gsc_perform_op(i_op);
        }
        globus_mutex_unlock(&i_server->mutex);
        if(res != GLOBUS_SUCCESS)
        {
            globus_free(i_op->path);
            globus_free(i_op);
        }
    }
    return res;
}

globus_result_t
globus_gridftp_server_control_pmod_authenticate(
    globus_gridftp_server_control_t                 server,
    const char *                                    username,
    const char *                                    password,
    gss_cred_id_t                                   cred,
    gss_cred_id_t                                   del_cred,
    globus_gridftp_server_control_pmod_auth_callback_t cb,
    void *                                          user_arg)
{
    globus_result_t                                 res;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_pmod_authenticate);

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }

    i_op = (globus_i_gsc_op_t *) globus_malloc(sizeof(globus_i_gsc_op_t));
    if(i_op == NULL)
    {
        return GlobusGridFTPServerErrorMemory("i_op");
    }
    memset(i_op, '\0', sizeof(globus_i_gsc_op_t));

    i_op->server = server;
    i_op->type = GLOBUS_L_GSC_OP_TYPE_AUTH;
    i_op->res = GLOBUS_SUCCESS;
    i_op->user_arg = user_arg;

    i_op->auth_cb = cb;
    if(username != NULL)
    {
        i_op->username = globus_libc_strdup(username);
    }
    if(password != NULL)
    {
        i_op->password = globus_libc_strdup(password);
    }
    i_op->cred = cred;
    i_op->del_cred = del_cred;

    globus_mutex_lock(&i_op->server->mutex);
    {
        res = globus_l_gsc_perform_op(i_op);
    }
    globus_mutex_unlock(&i_op->server->mutex);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(i_op);
    }

    return res;
}

/*
 *  called by the protocol module when an error occurs
 */
globus_result_t
globus_gridftp_server_control_pmod_done(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 result)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res = GLOBUS_SUCCESS;
    GlobusGridFTPServerName(globus_gridftp_server_control_protocol_error);
 
    i_server = (globus_i_gsc_server_t *) server;

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            case GLOBUS_L_GS_STATE_OPEN:
            case GLOBUS_L_GS_STATE_AUTH:
                i_server->cached_res = result;
                i_server->state = GLOBUS_L_GS_STATE_ERROR;
                /* start the stop process for protocol module */
                GlobusGSUserDoneKickout(i_server);
                res = GLOBUS_SUCCESS;
                break;


            case GLOBUS_L_GS_STATE_ERROR:
            case GLOBUS_L_GS_STATE_STOPPING:
            case GLOBUS_L_GS_STATE_STOPPED:
                res = GlobusGridFTPServerErrorState(i_server->state);
                break;

            default:
                globus_assert(0 && 
                    "Not a valid state, possible memory curroption");
                break;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_pmod_passive(
    globus_gridftp_server_control_t                 server,
    int                                             max,
    int                                             net_prt,
    globus_gridftp_server_control_pmod_passive_callback_t cb,
    void *                                          user_arg)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res = GLOBUS_SUCCESS;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_pmod_passive);
 
    i_server = (globus_i_gsc_server_t *) server;

    i_op = (globus_i_gsc_op_t *) globus_malloc(sizeof(globus_i_gsc_op_t));
    if(i_op == NULL)
    {
        return GlobusGridFTPServerErrorMemory("i_op");
    }
    memset(i_op, '\0', sizeof(globus_i_gsc_op_t));

    i_op->server = server;
    i_op->res = GLOBUS_SUCCESS;
    i_op->user_arg = user_arg;
    i_op->max_cs = max;
    i_op->net_prt = net_prt;
    i_op->passive_cb = cb;
    i_op->cs = NULL;
    i_op->type = GLOBUS_L_GSC_OP_TYPE_CREATE_PASV;

    globus_mutex_lock(&i_server->mutex);
    {
        if(!globus_fifo_empty(&i_server->data_q))
        {
            globus_fifo_enqueue(&i_server->data_q, i_op);
        }
        else
        {
            globus_fifo_enqueue(&i_server->data_q, i_op);
            res = globus_l_gsc_perform_op(i_op);

            if(res != GLOBUS_SUCCESS)
            {
                globus_fifo_dequeue(&i_server->data_q);
                globus_free(i_op);
            }
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_pmod_port(
    globus_gridftp_server_control_t                 server,
    const char **                                   cs,
    int                                             cs_count,
    int                                             net_prt,
    globus_gridftp_server_control_pmod_port_callback_t cb,
    void *                                          user_arg)
{
    int                                             ctr;
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res = GLOBUS_SUCCESS;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_pmod_port);
 
    i_server = (globus_i_gsc_server_t *) server;

    i_op = (globus_i_gsc_op_t *) globus_malloc(sizeof(globus_i_gsc_op_t));
    if(i_op == NULL)
    {
        return GlobusGridFTPServerErrorMemory("i_op");
    }
    memset(i_op, '\0', sizeof(globus_i_gsc_op_t));

    i_op->server = server;
    i_op->res = GLOBUS_SUCCESS;
    i_op->user_arg = user_arg;
    i_op->max_cs = cs_count;
    i_op->net_prt = net_prt;
    i_op->port_cb = cb;
    i_op->cs = globus_malloc(sizeof(char *) * cs_count);
    for(ctr = 0; ctr < cs_count; ctr++)
    {
        i_op->cs[ctr] = globus_libc_strdup(cs[ctr]);
    }
    i_op->type = GLOBUS_L_GSC_OP_TYPE_CREATE_PORT;

    globus_mutex_lock(&i_server->mutex);
    {
        if(!globus_fifo_empty(&i_server->data_q))
        {
            globus_fifo_enqueue(&i_server->data_q, i_op);
        }
        else
        {
            globus_fifo_enqueue(&i_server->data_q, i_op);
            res = globus_l_gsc_perform_op(i_op);

            if(res != GLOBUS_SUCCESS)
            {
                globus_fifo_dequeue(&i_server->data_q);
                globus_free(i_op);
            }
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

/************************************************************************
 *                      utility finctions
 *                      -----------------
 ***********************************************************************/
char *
globus_i_gsc_concat_path(
    globus_i_gsc_server_t *                         i_server,
    const char *                                    in_path)
{
    char *                                          tmp_path;
    char *                                          tmp_ptr;
    char *                                          tmp_ptr2;

    if(in_path[0] == '/')
    {
        tmp_path = globus_libc_strdup(in_path);
    }
    else
    {
        tmp_path = globus_common_create_string("%s/%s",
            i_server->cwd,
            in_path);
    }

    /*
     *  reduce it
     */

    /* remove all double slashes */
    tmp_ptr = strstr(tmp_path, "//");
    while(tmp_ptr != NULL)
    {
        memmove(tmp_ptr, &tmp_ptr[1], strlen(&tmp_ptr[1])+1);
        tmp_ptr = strstr(tmp_path, "//");
    }

    tmp_ptr = strstr(tmp_path, "/..");
    while(tmp_ptr != NULL)
    {
        /* if they try to trick past top return NULL */
        if(tmp_ptr == tmp_path)
        {
            return NULL;
        }
        tmp_ptr2 = tmp_ptr - 1;
        while(tmp_ptr2 != tmp_path && *tmp_ptr2 != '/')
        {
            tmp_ptr2--;
        }
        if(tmp_ptr2 == tmp_path)
        {
            return NULL;
        }
        memmove(tmp_ptr2, &tmp_ptr[3], strlen(&tmp_ptr[3])+1);
        tmp_ptr = strstr(tmp_path, "/..");
    }
    /* remove all dot slashes */
    tmp_ptr = strstr(tmp_path, "./");
    while(tmp_ptr != NULL)
    {
        memmove(tmp_ptr, &tmp_ptr[1], strlen(&tmp_ptr[1])+1);
        tmp_ptr = strstr(tmp_path, "./");
    }

    return tmp_path;
}
