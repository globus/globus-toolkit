#include "globus_i_gridftp_server_control.h"

#include "version.h"
#include "globus_gridftp_server_control_pmod_959.h"

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
                    globus_l_gsc_user_done_kickout,                      \
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
                globus_l_gsc_user_stop_kickout,                          \
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

/*
 *  default command lookup table
 */
globus_hashtable_t                      globus_i_gsc_default_attr_command_hash;
globus_gridftp_server_control_attr_t            globus_l_gsc_default_attr;

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

        default:
            globus_assert(0);
            break;
    }
}

void
globus_gridftp_server_control_finished_auth(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 res)
{
    globus_i_gsc_server_t *                         i_server;
    globus_i_gsc_op_t *                             i_op;
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_auth);

    if(op == NULL)
    {
        return;
    }
    i_op = (globus_i_gsc_op_t *) op;
    if(i_op->type != GLOBUS_L_GSC_OP_TYPE_AUTH)
    {
        return;
    }

    i_server = i_op->server;

    globus_mutex_lock(&i_server->mutex);
    {
        /* if not in STATE_AUTH, we will deal with it in callback_return */
        if(i_server->state == GLOBUS_L_GS_STATE_AUTH)
        {
            i_server->state = GLOBUS_L_GS_STATE_OPEN;
        }
    }
    globus_mutex_unlock(&i_server->mutex);

    i_op->auth_cb(
        i_server,
        res,
        i_op->user_arg);

    globus_l_gsc_callback_return(i_server);
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

    res = globus_l_gsc_perform_op(i_op);

    return res;
}

static globus_result_t
globus_l_gsc_perform_op(
    globus_i_gsc_op_t *                             i_op)
{
    globus_result_t                                 res = GLOBUS_SUCCESS;
    globus_i_gsc_server_t *                         i_server;
    GlobusGridFTPServerName(globus_l_gsc_perform_op);

    i_server = i_op->server;

    globus_mutex_lock(&i_server->mutex);
    {
        switch(i_server->state)
        {
            /*
             *  If we are trying to authenticate check to see if
             *  the command is ok pre auth.  If so fall through to
             *  open, otherwise send error reply and break switch
             */
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
    }
    globus_mutex_unlock(&i_server->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_pmod_stat(
    globus_gridftp_server_control_t                 server,
    const char *                                    path,
    globus_gridftp_server_control_resource_mask_t   mask,
    globus_gridftp_server_control_pmod_stat_callback_t   cb,
    void *                                          user_arg)
{
    return GLOBUS_SUCCESS;
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
globus_gridftp_server_control_get_pwd(
    globus_gridftp_server_control_t                 server,
    char **                                         pwd_string)
{
    globus_i_gsc_server_t *                         i_server;
    globus_result_t                                 res;
    GlobusGridFTPServerName(globus_gridftp_server_control_get_pwd);

    i_server = (globus_i_gsc_server_t *) server;

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(pwd_string == NULL)
    {
        return GlobusGridFTPServerErrorParameter("pwd_string");
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
                *pwd_string = globus_libc_strdup(i_server->pwd);
                res = GLOBUS_SUCCESS;
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
                i_server->mode = mode;
                res = GLOBUS_SUCCESS;
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
                i_server->type = type;
                res = GLOBUS_SUCCESS;
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

    globus_mutex_lock(&i_server->mutex);
    {
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
    globus_mutex_unlock(&i_server->mutex);
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

    globus_l_gsc_callback_return(i_server);
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
