#include "globus_i_gridftp_server_control.h"
#include <version.h>

#define GLOBUS_L_GSC_DEFAULT_220   "220 GridFTP Server.\r\n"
#define GLOBUS_XIO_CLOSE_NO_CANCEL 1

/*
 *  This File
 *  ---------
 *  This file reads 959 commands off the wire and kicks out callbacks to 
 *  the individual commands.
 */

/*
 *  reading
 *  -------
 *
 *  Commands are read and put into a queue.  Only 1 command is processed
 *  at a time.  That is commands are removed from the queue for processing
 *  only once the reply to the previous command is sent.  This allows the
 *  client to send commands while the previous command is outstanding,
 *  (potientially having the advanatage of hidding latency) while still
 *  maintaining command reply sementics.
 * 
 *  The ABOR command is an exception to this.  Abort should be preceded
 *  with some out of band messaging.  This protocol module reads all oob
 *  messages inline.  If a command is outstanging when an ABOR message 
 *  is received, the library function globus_i_gs_abort() is called
 *  to cancel it.  When the callback for _abort() which will cause the 
 *  outstanding command to end early.  When the abort callbcak returns
 *  all commands in the queue are replied to with "Aborted", and the 
 *  ABOR command is replied to with "Success"
 */

/* 
 *  parsing commands
 *  ----------------
 *
 *  This protocol module insists that the xio stack used has a driver
 *  that can be put into "super mode" (gssapi_ftp driveri or ftp_cmd).
 *  This mode gaurentees that each read callback will contain a 
 *  complete command.
 *
 *  On activate a table of commands is built.  This table can be index
 *  by the command name string.  Each entry in the table contains an
 *  integer representation of the command type (for faster decisions)
 *  and a parse function.  
 */

#define GlobusLRegisterDone(_h)                                      \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    _res = globus_callback_space_register_oneshot(                      \
                NULL,                                                   \
                NULL,                                                   \
                globus_l_gsc_user_close_kickout,                        \
                (void *)_h,                                             \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    if(_res != GLOBUS_SUCCESS)                                          \
    {                                                                   \
        globus_panic(                                                   \
            &globus_i_gsc_module,                                       \
            _res,                                                       \
            "one shot failed.");                                        \
    }                                                                   \
} while(0)

#define GlobusLGSCRegisterCmd(_op)                                       \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    _res = globus_callback_space_register_oneshot(                      \
                NULL,                                                   \
                NULL,                                                   \
                globus_l_gsc_command_callout,                           \
                (void *)_op,                                             \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    if(_res != GLOBUS_SUCCESS)                                          \
    {                                                                   \
        globus_panic(                                                   \
            &globus_i_gsc_module,                                       \
            _res,                                                       \
            "one shot failed.");                                        \
    }                                                                   \
} while(0)

#define GlobusLGSCRegisterInternalCB(_op)                               \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    _res = globus_callback_space_register_oneshot(                      \
                NULL,                                                   \
                NULL,                                                   \
                globus_l_gsc_internal_cb_kickout,                       \
                (void *)_op,                                            \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    if(_res != GLOBUS_SUCCESS)                                          \
    {                                                                   \
        globus_panic(                                                   \
            &globus_i_gsc_module,                                       \
            _res,                                                       \
            "one shot failed.");                                        \
    }                                                                   \
} while(0)



typedef struct globus_l_gsc_cmd_ent_s
{
    int                                     cmd;
    char                                    cmd_name[16]; /* only 5 needed */
    globus_gsc_command_cb_t                 cmd_cb;
    globus_gsc_command_desc_t               desc;
    char *                                  help;
    void *                                  user_arg;
    int                                     max_argc;
    int                                     min_argc;
} globus_l_gsc_cmd_ent_t;

typedef struct globus_l_gsc_reply_ent_s
{
    char *                                  msg;
    globus_bool_t                           final;
    globus_i_gsc_op_t *                     op;
} globus_l_gsc_reply_ent_t;

/*************************************************************************
 *              functions prototypes
 *
 ************************************************************************/

static void
globus_l_gsc_process_next_cmd(
    globus_i_gsc_server_handle_t *          server_handle);

static globus_result_t
globus_l_gsc_final_reply(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            message);

static void
globus_l_gsc_close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    void *                                  user_arg);

static void
globus_l_gsc_user_close_kickout(
    void *                                  user_arg);

static globus_result_t
globus_l_gsc_intermediate_reply(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            message);

static void
globus_l_gsc_finished_op(
    globus_i_gsc_op_t *                     op,
    char *                                  reply_msg);

static void
globus_l_gsc_internal_cb_kickout(
    void *                                  user_arg);

/*************************************************************************
 *              globals
 *
 ************************************************************************/

/*
 *  fake buffers.
 *
 *  this protocmodule insists that ftp_cmd is in the stack and that
 *  it is placed in a mode that will create buffers for the user.
 */
static globus_byte_t                        globus_l_gsc_fake_buffer[1];
static globus_size_t                        globus_l_gsc_fake_buffer_len 
    = 1;

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

/*
 *  module
 */
globus_module_descriptor_t                  globus_i_gsc_module =
{
    "globus_gridftp_server_control",
    globus_l_gsc_activate,
    globus_l_gsc_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static globus_i_gsc_op_t *
globus_l_gsc_op_create(
    globus_list_t *                         cmd_list,
    const char *                            command,
    globus_i_gsc_server_handle_t *          server_handle)
{
    globus_i_gsc_op_t *                     op;

    op = (globus_i_gsc_op_t *) globus_calloc(sizeof(globus_i_gsc_op_t), 1);
    if(op == NULL)
    {
        return NULL;
    }
    op->command = globus_libc_strdup(command);
    if(op->command == NULL)
    {
        globus_free(op);
        return NULL;
    }

    op->server_handle = server_handle;
    op->res = GLOBUS_SUCCESS;
    op->cmd_list = cmd_list;

    op->authenticated = GLOBUS_FALSE;
    op->username = NULL;
    op->password = NULL;
    op->cred = NULL;
    op->del_cred = NULL;
    op->auth_cb = NULL;
    op->stat_cb = NULL;

    op->uid = -1;

    op->path = NULL;

    op->cs = NULL;
    op->passive_cb = NULL;
    op->port_cb = NULL;

    op->mod_name = NULL;
    op->mod_parms = NULL;
    op->user_data_cb = NULL;
    op->transfer_started = GLOBUS_FALSE;

    op->user_arg = NULL;

    return op;
}

static void
globus_l_gsc_op_destroy(
    globus_i_gsc_op_t *                     op)
{
    /* clearly leaking here */
    globus_free(op);
}

/************************************************************************
 *                         callbacks
 *                         ---------
 *  Only function in this file where we need to lock.  The reason for
 *  this is it is the return from system land back to server-lib land. 
 *
 ***********************************************************************/

/*
 *  since the xio stack gaurentees 1 command per callback
 */
static void
globus_l_gsc_read_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_i_gsc_server_handle_t *          server_handle;
    globus_list_t *                         cmd_list;
    globus_i_gsc_op_t *                     op;
    /* largest know command is 4, but possible the user sent a huge one */
    char *                                  command_name;
    int                                     sc;
    int                                     ctr;
    GlobusGridFTPServerName(globus_l_gsc_read_cb);

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_mutex_lock(&server_handle->mutex);
    {
        /*  terminate will be called twice because of the canceled read
            this is safe, due to the state machine. */
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gsc_terminate(server_handle, 0);
            globus_mutex_unlock(&server_handle->mutex);
            goto exit;
        }

        switch(server_handle->state)
        {
            /* OPEN: we will process this command */
            case GLOBUS_L_GSC_STATE_OPEN:
            /* PROCESSING we will add this command to a q */
            case GLOBUS_L_GSC_STATE_PROCESSING:
                /*  parse out the command name */
                command_name = (char *) globus_malloc(len + 1);
                sc = sscanf(buffer, "%s", command_name);
                /* stack will make sure this never happens */
                globus_assert(sc > 0);
                /* convert to all upper for convience and such */
                for(ctr = 0; command_name[ctr] != '\0'; ctr++)
                {
                    command_name[ctr] = toupper(command_name[ctr]);
                }

                cmd_list = (globus_list_t *) globus_hashtable_lookup(
                                &server_handle->cmd_table, command_name);
                /*  This may be NULL, if so  we don't suport this command.
                 *  Just to the q anyway, it will be dealt with later. */

                /* if not an abort */
                if(strcmp(command_name, "ABOR") != 0)
                {
                    op = globus_l_gsc_op_create(
                        cmd_list, buffer, server_handle);
                    if(op == NULL)
                    {
                        globus_i_gsc_terminate(server_handle, 0);
                        globus_mutex_unlock(&server_handle->mutex);
                        goto exit;
                    }

                    globus_fifo_enqueue(&server_handle->read_q, op);
                    /* if no errors outstanding */
                    if(server_handle->state == GLOBUS_L_GSC_STATE_OPEN)
                    {
                        globus_l_gsc_process_next_cmd(server_handle);
                    }
                    /* allow outstanding commands, just queue them up */
                    res = globus_xio_register_read(
                            xio_handle,
                            globus_l_gsc_fake_buffer,
                            globus_l_gsc_fake_buffer_len,
                            globus_l_gsc_fake_buffer_len,
                            NULL,
                            globus_l_gsc_read_cb,
                            (void *) server_handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_i_gsc_terminate(server_handle, 0);
                        globus_mutex_unlock(&server_handle->mutex);
                        goto exit;
                    }
                }
                else
                {
                    /* if we are in the open state then there is no
                       outstanding operation to cancel and we can just
                       reply to the ABOR */
                    if(server_handle->state == GLOBUS_L_GSC_STATE_OPEN)
                    {
                        globus_assert(
                            globus_fifo_empty(&server_handle->read_q));

                        server_handle->state = GLOBUS_L_GSC_STATE_PROCESSING;
                        res = globus_l_gsc_final_reply(
                                server_handle,
                                "226 Abort successful\r\n");
                        if(res != GLOBUS_SUCCESS)
                        {
                            globus_i_gsc_terminate(server_handle, 0);
                            globus_mutex_unlock(&server_handle->mutex);
                            goto exit;
                        }
                    }
                    else
                    {
                        server_handle->state = GLOBUS_L_GSC_STATE_ABORTING;
                        /*
                         *  cancel the outstanding command.  In its callback
                         *  we flush the q and respond to the ABOR
                         */
                        globus_assert(server_handle->outstanding_op != NULL);

                        /*
                         *  noptify user that an abort is requested if they
                         *  are interested in hearing about it.
                         *  In any case  we will just wait for them to finish 
                         *  to respond to the abort.  Their notification cb
                         *  is simply a way to allow *them* to cancel what 
                         *  they are doing 
                         */
                        if(server_handle->abort_cb != NULL)
                        {
                            server_handle->abort_cb(
                                server_handle->outstanding_op,
                                server_handle->abort_arg);
                        }
                    }
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_i_gsc_terminate(server_handle, 0);
                        globus_mutex_unlock(&server_handle->mutex);
                        goto exit;
                    }
                }

                globus_free(command_name);
                break;

            /* these only happen if result cam back an error, in which case
                we will jump around this part */
            case GLOBUS_L_GSC_STATE_STOPPING:

            /* should never be in stopped state while a read is posted */
            case GLOBUS_L_GSC_STATE_STOPPED:
            /* we should not be in these states with a read posted
               ever.  When an abort is read we flush the queue and
               do not post another read until we are back in the open
               state */
            case GLOBUS_L_GSC_STATE_ABORTING:
            case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
            default:
                globus_assert(0 && "invalid state, likely memory curroption");
                break;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

  exit:

    return;
}

/*
 *  220 mesage write callback
 *
 *  This only happens once at the begining of the handle life cycle.
 */
static void 
globus_l_gsc_220_write_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res;
    globus_i_gsc_server_handle_t *          server_handle;
    GlobusGridFTPServerName(globus_l_gsc_220_write_cb);

    GlobusGridFTPServerDebugEnter();

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_free(buffer);

    globus_mutex_lock(&server_handle->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gsc_terminate(server_handle, 0);
            globus_mutex_unlock(&server_handle->mutex);
            goto err;
        }

        /*  post a read on the fake buffers
         *  TODO:  deal with it if they are not using the right stack  */
        res = globus_xio_register_read(
                xio_handle,
                globus_l_gsc_fake_buffer,
                globus_l_gsc_fake_buffer_len,
                globus_l_gsc_fake_buffer_len,
                NULL,
                globus_l_gsc_read_cb,
                (void *) server_handle);
        if(res != GLOBUS_SUCCESS)
        {
            globus_i_gsc_terminate(server_handle, 0);
            globus_mutex_unlock(&server_handle->mutex);
            goto err;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    GlobusGridFTPServerDebugExit();
    return;

  err:
    GlobusGridFTPServerDebugExitWithError();
}

/*
 *  callback for replies
 */
static void 
globus_l_gsc_final_reply_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_xio_attr_t                       close_attr;
    globus_result_t                         res;
    globus_i_gsc_server_handle_t *          server_handle;
    GlobusGridFTPServerName(globus_l_final_reply_cb);

    globus_free(buffer);

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_mutex_lock(&server_handle->mutex);
    {
        server_handle->reply_outstanding = GLOBUS_FALSE;
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gsc_terminate(server_handle, 0);
            globus_mutex_unlock(&server_handle->mutex);
            return;
        }

        switch(server_handle->state)
        {
            case GLOBUS_L_GSC_STATE_ABORTING:
                /* if all of the replies in response to the abort
                   have returned we can move back to the open state
                   and post another read */

                /* abort should have flushed the q and not posted
                   another read.  This must be empty */
                globus_assert(globus_fifo_empty(&server_handle->read_q));

                server_handle->abort_cnt--;
                if(server_handle->abort_cnt == 0)
                {
                    /* post a new read */
                    res = globus_xio_register_read(
                            server_handle->xio_handle,
                            globus_l_gsc_fake_buffer,
                            globus_l_gsc_fake_buffer_len,
                            1,
                            NULL,
                            globus_l_gsc_read_cb,
                            (void *) server_handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_i_gsc_terminate(server_handle, 0);
                    }
                }
                break;

            case GLOBUS_L_GSC_STATE_PROCESSING:
                server_handle->state = GLOBUS_L_GSC_STATE_OPEN;
                globus_l_gsc_process_next_cmd(server_handle);
                break;

            case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
            case GLOBUS_L_GSC_STATE_STOPPING:

                globus_xio_attr_init(&close_attr);
                globus_xio_attr_cntl(
                    close_attr, NULL, GLOBUS_XIO_CLOSE_NO_CANCEL);
                res = globus_xio_register_close(
                    server_handle->xio_handle,
                    close_attr,
                    globus_l_gsc_close_cb,
                    server_handle);
                globus_xio_attr_destroy(close_attr);
                if(res != GLOBUS_SUCCESS)
                {
                    GlobusLRegisterDone(server_handle);
                }

                break;

            /* in open state if intermediate message has been sent */
            case GLOBUS_L_GSC_STATE_OPEN:
                break;

            case GLOBUS_L_GSC_STATE_STOPPED:
            default:
                globus_assert(0 && "should never reach this state");
                break;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);
}

static void 
globus_l_gsc_intermediate_reply_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_l_gsc_reply_ent_t *              reply_ent;
    globus_result_t                         res;
    globus_i_gsc_server_handle_t *          server_handle;
    GlobusGridFTPServerName(globus_l_gsc_intermediate_reply_cb);

    globus_free(buffer);

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_mutex_lock(&server_handle->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gsc_terminate(server_handle, 0);
            globus_mutex_unlock(&server_handle->mutex);
            return;
        }

        if(!globus_fifo_empty(&server_handle->reply_q))
        {
            reply_ent = (globus_l_gsc_reply_ent_t *)
                globus_fifo_dequeue(&server_handle->reply_q);
            if(reply_ent->final)
            {
                globus_l_gsc_finished_op(
                    reply_ent->op, reply_ent->msg);
            }
            else
            {
                res = globus_l_gsc_intermediate_reply(
                            server_handle,
                            reply_ent->msg);
                if(res != GLOBUS_SUCCESS)
                {
                    server_handle->reply_outstanding = GLOBUS_FALSE;
                    globus_i_gsc_terminate(server_handle, 0);
                    globus_free(reply_ent->msg);
                }
            }
            globus_free(reply_ent);
        }
        else
        {
            server_handle->reply_outstanding = GLOBUS_FALSE;
        }
    }
    globus_mutex_lock(&server_handle->mutex);
}

static void
globus_l_gsc_user_close_kickout(
    void *                                  user_arg)
{
    globus_i_gsc_server_handle_t *          server_handle;

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_assert(
        server_handle->state == GLOBUS_L_GSC_STATE_ABORTING_STOPPING ||
        server_handle->state == GLOBUS_L_GSC_STATE_STOPPING);

    /* set state to stopped */
    if(server_handle->done_cb != NULL)
    {
        server_handle->done_cb(
            server_handle,
            server_handle->cached_res,
            server_handle->user_arg);
    }
}

/*
 *  close callback
 * 
 *  handle is not closed until user requests a close.
 */
static void
globus_l_gsc_close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_gsc_user_close_kickout(user_arg);
}

/************************************************************************
 *                         utility functions
 *                         -----------------
 *
 ***********************************************************************/
static globus_result_t
globus_l_gsc_parse_command(
    char *                                  command,
    char ***                                out_cmd_a,
    int                                     argc)
{
    char *                                  start_ptr;
    char **                                 cmd_a = NULL;
    int                                     ctr;
    int                                     ndx;
    globus_bool_t                           done = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_parse_command);

    *out_cmd_a = NULL;

    cmd_a = (char **) globus_malloc(sizeof(char *) * argc);
    if(cmd_a == NULL)
    {
        return -1;
    }

    start_ptr = command;
    for(ctr = 0; ctr < argc && !done; ctr++)
    {
        /* skip past all leading spaces */
        while(isspace(*start_ptr) && *start_ptr != '\r')
        {
            start_ptr++;
        }
        if(*start_ptr == '\r')
        {
            cmd_a[ctr] = NULL;
        }
        else
        {
            for(ndx = 0; 
                !isspace(start_ptr[ndx]) && start_ptr[ndx] != '\r' && 
                    start_ptr[ndx] != '\0'; 
                ndx++)
            {
                ndx++;
            }
            if(*start_ptr == '\0' || *start_ptr == '\r')
            {
                cmd_a[ctr] = NULL;
                ctr--;
                done = GLOBUS_TRUE;
            }
            else if(ctr == argc - 1)
            {
                cmd_a[ctr] = globus_libc_strdup(start_ptr);
            }
            else
            {
                cmd_a[ctr] = globus_libc_strndup(start_ptr, ndx);
            }
            start_ptr += ndx;
        }
    }
    cmd_a[ctr] = NULL;
    *out_cmd_a = cmd_a;

    return ctr;
}

static void 
globus_l_gsc_free_command_array(
    char **                                 cmd_a)
{
    int                                     ctr;

    for(ctr = 0; cmd_a[ctr] != NULL; ctr++)
    {
        globus_free(cmd_a[ctr]);
    }
    globus_free(cmd_a);
}

/*
 *  flush all reads in panic, abort, or early termination by the server.
 */
static globus_result_t
globus_l_gsc_flush_reads(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            reply_msg)
{
    globus_result_t                         res;
    globus_result_t                         tmp_res;
    globus_i_gsc_op_t *                     op;

    while(!globus_fifo_empty(&server_handle->read_q))
    {
        op = (globus_i_gsc_op_t *)
            globus_fifo_dequeue(&server_handle->read_q);
        globus_assert(op != NULL);
        globus_l_gsc_op_destroy(op);

        tmp_res = globus_l_gsc_final_reply(server_handle, reply_msg);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            res = tmp_res;
        }
    }

    return res;
}

char *
globus_i_gsc_concat_path(
    globus_i_gsc_server_handle_t *                  i_server,
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

globus_bool_t
globus_i_gridftp_server_control_cs_verify(
    const char *                                    cs,
    globus_gridftp_server_control_network_protocol_t net_prt)
{
    int                                             sc;
    int                                             ctr;
    unsigned int                                    ip[8];
    unsigned int                                    port;
    char *                                          host_str;

    if(cs == NULL)
    {
        return GLOBUS_FALSE;
    }

    if(net_prt == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4)
    {
        sc = sscanf(cs, " %d.%d.%d.%d:%d",
                &ip[0],
                &ip[1],
                &ip[2],
                &ip[3],
                &port);
        if(sc != 5)
        {
            return GLOBUS_FALSE;
        }

        if(ip[0] > 255 ||
           ip[1] > 255 ||
           ip[2] > 255 ||
           ip[3] > 255 ||
           port > 65536)
        {
            return GLOBUS_FALSE;
        }

        return GLOBUS_TRUE;
    }
    else if(net_prt == GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6)
    {
        host_str = globus_malloc(strlen(cs));
        sc = sscanf(cs, " [ %s ]:%d", host_str, &port);
        if(sc != 2)
        {
            globus_free(host_str);
            return GLOBUS_FALSE;
        }

        /* verify that the string contains nothing but numbers and ':' */
        for(ctr = 0; ctr < strlen(cs); ctr++)
        {
            if(cs[ctr] != ':' && !isdigit(cs[ctr]))
            {
                globus_free(host_str);
                return GLOBUS_FALSE;
            }
        }
        globus_free(host_str);
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

void
globus_i_gsc_stat_cp(
    globus_gridftp_server_control_stat_t *  dst,
    globus_gridftp_server_control_stat_t *  src)
{
    memcpy(dst, src, sizeof(globus_gridftp_server_control_stat_t));
}

/*
 *  callout into the command code
 */
static void
globus_l_gsc_command_callout(
    void *                                  user_arg)
{
    int                                     argc;
    globus_bool_t                           auth = GLOBUS_FALSE;
    char **                                 cmd_array;
    char *                                  msg;
    globus_result_t                         res;
    globus_l_gsc_cmd_ent_t *                cmd_ent;
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_i_gsc_op_t *                     op;
    globus_gsc_command_cb_t                 cmd_cb = NULL;

    op = (globus_i_gsc_op_t *) user_arg;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        globus_assert(
            op->server_handle->state == GLOBUS_L_GSC_STATE_PROCESSING);
        auth = op->server_handle->authenticated;

        msg = "500 Invalid command.\r\n";
        while(!done)
        {
            /* if we ran out of commands before finishing tell the client
                the command does not exist */
            if(op->cmd_list == NULL)
            {
                res = globus_l_gsc_final_reply(op->server_handle, msg);
                done = GLOBUS_TRUE;
                globus_free(op);
            }
            else
            {
                cmd_ent = (globus_l_gsc_cmd_ent_t *)
                    globus_list_first(op->cmd_list);
                /* must advance before calling the user callback */
                op->cmd_list = globus_list_rest(op->cmd_list);
                if(!auth && !(cmd_ent->desc & GLOBUS_GSC_COMMAND_PRE_AUTH))
                {
                    msg = "530 Please login with USER and PASS.\r\n";
                }
                else if(auth && 
                    !(cmd_ent->desc & GLOBUS_GSC_COMMAND_POST_AUTH))
                {
                    msg = "503 You are already logged in!\r\n";
                }
                else
                {
                    cmd_cb = cmd_ent->cmd_cb;
                    done = GLOBUS_TRUE;
                }
            }
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    if(cmd_cb != NULL)
    {
        argc = globus_l_gsc_parse_command(
            op->command, &cmd_array, cmd_ent->max_argc);
        if(argc < cmd_ent->min_argc)
        {
            globus_i_gsc_finished_command(op,
                "500 unrecognized command.\r\n");
        }
        else
        {
            cmd_ent->cmd_cb(
                op,
                op->command,
                cmd_array,
                argc,
                cmd_ent->user_arg);
        }
        globus_l_gsc_free_command_array(cmd_array);
    }
}

/*
 *  This pulls a command out of the read_q if there is one and processes
 *  it based on its type.  All callbacks for the commands are the same.
 *  This function should only be called in the PROCESSING state.
 *
 *  called locked
 */
static void
globus_l_gsc_process_next_cmd(
    globus_i_gsc_server_handle_t *          server_handle)
{
    globus_i_gsc_op_t *                     op;
    GlobusGridFTPServerName(globus_l_gsc_process_next_cmd);

    GlobusGridFTPServerDebugEnter();

    globus_assert(server_handle->state == GLOBUS_L_GSC_STATE_OPEN);

    if(!globus_fifo_empty(&server_handle->read_q))
    {
        server_handle->state = GLOBUS_L_GSC_STATE_PROCESSING;

        op = (globus_i_gsc_op_t *)
            globus_fifo_dequeue(&server_handle->read_q);

        server_handle->outstanding_op = op;

        GlobusLGSCRegisterCmd(op);
    }

    GlobusGridFTPServerDebugExit();
}

/*
 *  seperated from the exteranally visible function to allow for only
 *  1 write at a time.
 */
static void
globus_l_gsc_finished_op(
    globus_i_gsc_op_t *                     op,
    char *                                  reply_msg)
{
    globus_xio_attr_t                       close_attr;
    globus_i_gsc_server_handle_t *          server_handle;
    globus_result_t                         res;
    globus_bool_t                           stopping = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_finished_op);

    server_handle = op->server_handle;

    switch(server_handle->state)
    {
        /* after receiving the servers reply to the abor we 
           clear everything in the Q and respond */
        case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
            stopping = GLOBUS_TRUE;
        case GLOBUS_L_GSC_STATE_ABORTING:

            /* if user considers this command incomplete it does not
               matter, we are aborting anyway */
            if(reply_msg == NULL)
            {
                reply_msg = "426 Command Aborted\r\n";
            }

            server_handle->abort_cnt = globus_fifo_size(&server_handle->read_q);
            server_handle->abort_cnt += 2;

            /* reply to the outstanding message */
            res = globus_l_gsc_final_reply(
                    server_handle,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                globus_i_gsc_terminate(server_handle, 0);
                break;
            }
            res = globus_l_gsc_flush_reads(
                    server_handle,
                    "426 Command Aborted\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_i_gsc_terminate(server_handle, 0);
                break;
            }
            res = globus_l_gsc_final_reply(
                    server_handle,
                    "226 Abort successful\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_i_gsc_terminate(server_handle, 0);
                break;
            }
            break;

        case GLOBUS_L_GSC_STATE_PROCESSING:

            if(reply_msg == NULL && op->cmd_list == NULL)
            {
                reply_msg = "500 Command not supported\r\n";
            }

            if(reply_msg == NULL)
            {
                GlobusLGSCRegisterCmd(op);
            }
            else
            {
                res = globus_l_gsc_final_reply(
                        server_handle,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    globus_i_gsc_terminate(server_handle, 0);
                }
            }
            break;

        case GLOBUS_L_GSC_STATE_STOPPING:
            stopping = GLOBUS_TRUE;
            break;

        case GLOBUS_L_GSC_STATE_OPEN:
        case GLOBUS_L_GSC_STATE_STOPPED:
        default:
            globus_assert(0);
            break;
    }

    if(stopping)
    {
        globus_xio_attr_init(&close_attr);
        globus_xio_attr_cntl(
            close_attr, NULL, GLOBUS_XIO_CLOSE_NO_CANCEL);
        res = globus_xio_register_close(
            server_handle->xio_handle,
            close_attr,
            globus_l_gsc_close_cb,
            server_handle);
        globus_xio_attr_destroy(close_attr);
        if(res != GLOBUS_SUCCESS)
        {
            GlobusLRegisterDone(server_handle);
        }

    }

    globus_free(op->command);
    globus_free(op);
}

static globus_result_t
globus_l_gsc_final_reply(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            message)
{
    globus_result_t                         res;
    char *                                  tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_final_reply);

    globus_assert(globus_fifo_empty(&server_handle->reply_q));

    server_handle->reply_outstanding = GLOBUS_TRUE;
    tmp_ptr = globus_libc_strdup(message);
    /*TODO: check state */
    res = globus_xio_register_write(
            server_handle->xio_handle,
            tmp_ptr,
            strlen(tmp_ptr),
            strlen(tmp_ptr),
            NULL,
            globus_l_gsc_final_reply_cb,
            server_handle);
    if(res != GLOBUS_SUCCESS)
    {
        server_handle->reply_outstanding = GLOBUS_FALSE;
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/*
 *  only called when an intermediate command is not outstanding
 */
static globus_result_t
globus_l_gsc_intermediate_reply(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            message)
{
    globus_result_t                         res;
    char *                                  tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_intermediate_reply);

    globus_assert(globus_fifo_empty(&server_handle->reply_q));

    tmp_ptr = globus_libc_strdup(message);
    /*TODO: check state */
    res = globus_xio_register_write(
            server_handle->xio_handle,
            tmp_ptr,
            strlen(tmp_ptr),
            strlen(tmp_ptr),
            NULL,
            globus_l_gsc_intermediate_reply_cb,
            server_handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/************************************************************************
 *              externally visable functions
 *              ----------------------------
 *
 ***********************************************************************/
globus_result_t
globus_gridftp_server_control_init(
    globus_gridftp_server_control_t *       server)
{
    globus_i_gsc_server_handle_t *          server_handle;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_init);

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    server_handle = (globus_i_gsc_server_handle_t *) globus_malloc(
        sizeof(globus_i_gsc_server_handle_t));
    if(server_handle == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("server_handle");
        goto err;
    }

    memset(server_handle, '\0', sizeof(globus_i_gsc_server_handle_t));

    globus_mutex_init(&server_handle->mutex, NULL);

    server_handle->state = GLOBUS_L_GSC_STATE_OPEN;
    server_handle->reply_outstanding = GLOBUS_FALSE;
    server_handle->pre_auth_banner = 
        globus_libc_strdup(GLOBUS_L_GSC_DEFAULT_220);
    globus_fifo_init(&server_handle->read_q);
    globus_fifo_init(&server_handle->reply_q);
    globus_fifo_init(&server_handle->data_q);

    globus_hashtable_init(
        &server_handle->cmd_table,
        128,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    
    globus_i_gsc_add_commands(server_handle);

    *server = server_handle;

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gridftp_server_control_destroy(
    globus_gridftp_server_control_t         server)
{
    globus_i_gsc_server_handle_t *          server_handle;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_destroy);

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    server_handle = (globus_i_gsc_server_handle_t *) server;
    if(server_handle->state != GLOBUS_L_GSC_STATE_STOPPED)
    {
        res = GlobusGridFTPServerErrorState(server_handle->state);
        goto err;
    }

    globus_mutex_destroy(&server_handle->mutex);
    globus_hashtable_destroy(&server_handle->cmd_table);
    globus_fifo_destroy(&server_handle->read_q);
    globus_fifo_destroy(&server_handle->reply_q);
    globus_free(server_handle);

    return GLOBUS_SUCCESS;

  err:
    return res;
}

/*
 *  start
 *  ---------
 *  Write the 220 then start reading.
 */
globus_result_t
globus_gridftp_server_control_start(
    globus_gridftp_server_control_t         server,
    globus_gridftp_server_control_attr_t    attr,
    globus_xio_handle_t                     xio_handle,
    globus_gridftp_server_control_cb_t      done_cb,
    void *                                  user_arg)
{
    globus_result_t                         res;
    globus_i_gsc_server_handle_t *          server_handle;
    globus_i_gsc_attr_t *                   i_attr;
    GlobusGridFTPServerName(globus_gridftp_server_control_start);

    GlobusGridFTPServerDebugEnter();

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }
    if(xio_handle == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("xio_handle");
        goto err;
    }

    i_attr = (globus_i_gsc_attr_t *) attr;
    if(i_attr == NULL)
    {
        i_attr = globus_l_gsc_default_attr;
    }

    server_handle = (globus_i_gsc_server_handle_t *) server;

    globus_mutex_lock(&server_handle->mutex);
    {
        if(server_handle->state != GLOBUS_L_GSC_STATE_STOPPED &&
            server_handle->state != GLOBUS_L_GSC_STATE_OPEN)
        {
            globus_mutex_unlock(&server_handle->mutex);
            res = GlobusGridFTPServerErrorParameter("server");
            goto err;
        }

        server_handle->xio_handle = xio_handle;
        globus_hashtable_copy(
            &server_handle->send_cb_table, &i_attr->send_cb_table, NULL);
        globus_hashtable_copy(
            &server_handle->recv_cb_table, &i_attr->recv_cb_table, NULL);
        server_handle->resource_cb = i_attr->resource_cb;
        server_handle->auth_cb = i_attr->auth_cb;
        server_handle->done_cb = done_cb;
        server_handle->passive_cb = i_attr->passive_cb;
        server_handle->active_cb = i_attr->active_cb;
        server_handle->data_destroy_cb = i_attr->data_destroy_cb;
        server_handle->default_send_cb = i_attr->default_send_cb;
        server_handle->default_recv_cb = i_attr->default_recv_cb;

        if(server_handle->modes != NULL)
        {
            globus_free(server_handle->modes);
        }
        if(server_handle->types != NULL)
        {
            globus_free(server_handle->types);
        }
        server_handle->modes = globus_libc_strdup(i_attr->modes);
        server_handle->types = globus_libc_strdup(i_attr->types);
        /* set default */
        server_handle->send_buf = -1; 
        server_handle->receive_buf = -1;
        server_handle->parallelism = 1;
        server_handle->type = 'A';
        server_handle->mode = 'S';

        server_handle->parallelism = 1;
        server_handle->send_buf = -1;
        server_handle->receive_buf = -1;
        server_handle->packet_size = -1;
        server_handle->delayed_passive = GLOBUS_FALSE;
        server_handle->passive_only = GLOBUS_FALSE;
        server_handle->pasv_max = 1;
        server_handle->port_max = 1;
        server_handle->port_prt = GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4;
        server_handle->pasv_prt = GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4;
        server_handle->dc_parsing_alg = 0;;

        if(server_handle->cwd != NULL)
        {
            globus_free(server_handle->cwd);
        }
        server_handle->cwd = globus_libc_strdup(i_attr->base_dir);

        server_handle->user_arg = user_arg;

        res = globus_xio_register_write(
                server_handle->xio_handle,
                server_handle->pre_auth_banner,
                strlen(server_handle->pre_auth_banner),
                strlen(server_handle->pre_auth_banner),
                NULL, /* may need a DD here */
                globus_l_gsc_220_write_cb,
                server_handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_i_gsc_command_panic(
    globus_i_gsc_op_t *                     op)
{
    globus_result_t                         res;

    if(op->server_handle->state != GLOBUS_L_GSC_STATE_PROCESSING)
    {

    }

    globus_xio_handle_cancel_operations(
        op->server_handle->xio_handle,
        GLOBUS_XIO_CANCEL_READ);
    globus_l_gsc_flush_reads(
        op->server_handle,
        "421 Service not available, closing control connection.\r\n");
    op->server_handle->state = GLOBUS_L_GSC_STATE_STOPPING;

    /* not much can be done about an error here, we are terminating 
        anyway */
    res = globus_l_gsc_final_reply(
            op->server_handle,
            "421 Service not available, closing control connection.\r\n");

    return GLOBUS_SUCCESS;
}


/*
 *  terminate
 *  ---------
 *  This is called whenever an error occurs.  It attempts to nicely
 *  send a message to the user then changes to a stopping state.
 */
void
globus_i_gsc_terminate(
    globus_i_gsc_server_handle_t *          server_handle,
    globus_bool_t                           nice)
{
    globus_xio_attr_t                       close_attr;
    globus_bool_t                           close = GLOBUS_TRUE;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_i_gsc_terminate);

    switch(server_handle->state)
    {
        /* if already stopping, just punt. this is likely to happen */
        case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
        case GLOBUS_L_GSC_STATE_STOPPING:
            close = GLOBUS_FALSE;
            break;

        case GLOBUS_L_GSC_STATE_ABORTING:
            server_handle->state = GLOBUS_L_GSC_STATE_ABORTING_STOPPING;
            /* if aborting no read is posted, and there are no commands 
               to flush */
            break;

        /*  Clear out whatever commands we have if we can */
        case GLOBUS_L_GSC_STATE_PROCESSING:

            if(!nice)
            {
                /* start abort process */
                server_handle->state = GLOBUS_L_GSC_STATE_ABORTING_STOPPING;
                /*
                 *  cancel the outstanding command.  In its callback
                 *  we flush the q and respond to the ABOR
                 */
                globus_assert(server_handle->outstanding_op != NULL);

                if(server_handle->abort_cb != NULL)
                {
                    server_handle->abort_cb(
                        server_handle->outstanding_op,
                        server_handle->abort_arg);
                }

                globus_xio_handle_cancel_operations(
                    server_handle->xio_handle,
                    GLOBUS_XIO_CANCEL_READ);
                globus_l_gsc_flush_reads(
                    server_handle,
                "421 Service not available, closing control connection.\r\n");
            }
            else
            {
                server_handle->state = GLOBUS_L_GSC_STATE_STOPPING;
            }
            close = GLOBUS_FALSE;
            break;

        /*
         *  goto panic state and cancel the read
         */
        case GLOBUS_L_GSC_STATE_OPEN:
            server_handle->state = GLOBUS_L_GSC_STATE_STOPPING;
            globus_xio_handle_cancel_operations(
                server_handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            /* no commands to flush */
            break;

        /* shouldn't do anything once we hit the stopped state */
        case GLOBUS_L_GSC_STATE_STOPPED:
        /* no other states */
        default:
            globus_assert(0);
            break;
    }

    if(close)
    {
        globus_xio_attr_init(&close_attr);
        globus_xio_attr_cntl(
            close_attr, NULL, GLOBUS_XIO_CLOSE_NO_CANCEL);
        res = globus_xio_register_close(
            server_handle->xio_handle,
            close_attr,
            globus_l_gsc_close_cb,
            server_handle);
        globus_xio_attr_destroy(close_attr);
        if(res != GLOBUS_SUCCESS)
        {
            GlobusLRegisterDone(server_handle);
        }
    }
}

globus_result_t
globus_gridftp_server_control_stop(
    globus_gridftp_server_control_t         server)
{
    globus_i_gsc_server_handle_t *          server_handle;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_stop);

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }
    server_handle = (globus_i_gsc_server_handle_t *) server;

    globus_mutex_lock(&server_handle->mutex);
    {
        if(server_handle->state != GLOBUS_L_GSC_STATE_OPEN)
        {
            globus_mutex_unlock(&server_handle->mutex);
            res = GlobusGridFTPServerErrorParameter("server");
            goto err;
        }
        globus_i_gsc_terminate(server_handle, 0);
    }
    globus_mutex_unlock(&server_handle->mutex);


    return GLOBUS_SUCCESS;

  err:

    return res;
}

void
globus_i_gsc_finished_command(
    globus_i_gsc_op_t *                     op,
    char *                                  reply_msg)
{
    globus_i_gsc_server_handle_t *          server_handle;
    globus_l_gsc_reply_ent_t *              reply_ent;
    GlobusGridFTPServerName(globus_gsc_finished_op);

    server_handle = op->server_handle;

    if(server_handle->reply_outstanding)
    {
        reply_ent = (globus_l_gsc_reply_ent_t *)
            globus_malloc(sizeof(globus_l_gsc_reply_ent_t));
        reply_ent->msg = reply_msg;
        reply_ent->op = op;
        reply_ent->final = GLOBUS_TRUE;

        globus_fifo_enqueue(&server_handle->reply_q, reply_ent);
    }
    else
    {
        globus_l_gsc_finished_op(op, reply_msg);
    }
}

globus_result_t
globus_i_gsc_intermediate_reply(
    globus_i_gsc_op_t *                     op,
    char *                                  reply_msg)
{
    globus_l_gsc_reply_ent_t *              reply_ent;
    globus_i_gsc_server_handle_t *          server_handle;
    globus_result_t                         res;

    server_handle = op->server_handle;

    if(server_handle->reply_outstanding)
    {
        reply_ent = (globus_l_gsc_reply_ent_t *)
            globus_malloc(sizeof(globus_l_gsc_reply_ent_t));
        reply_ent->msg = reply_msg;
        reply_ent->op = op;
        reply_ent->final = GLOBUS_FALSE;

        globus_fifo_enqueue(&server_handle->reply_q, reply_ent);
    }
    else
    {
        server_handle->reply_outstanding = GLOBUS_TRUE;
        res = globus_l_gsc_intermediate_reply(
                server_handle,
                reply_msg);
        if(res != GLOBUS_SUCCESS)
        {
            server_handle->reply_outstanding = GLOBUS_FALSE;
            globus_i_gsc_terminate(server_handle, 0);
        }
    }

    return res;
}

globus_result_t
globus_i_gsc_command_add(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            command_name,
    globus_gsc_command_cb_t                 command_cb,
    globus_gsc_command_desc_t               desc,
    int                                     min_argc,
    int                                     max_argc,
    const char *                            help,
    void *                                  user_arg)
{
    globus_list_t *                         list;
    globus_result_t                         res;
    globus_l_gsc_cmd_ent_t *                cmd_ent;
    GlobusGridFTPServerName(globus_gsc_command_add);

    cmd_ent = (globus_l_gsc_cmd_ent_t *)globus_malloc(
        sizeof(globus_l_gsc_cmd_ent_t));
    if(cmd_ent == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("cmd_ent");
        goto err;
    }

    strcpy(cmd_ent->cmd_name, command_name);
    cmd_ent->cmd_cb = command_cb;
    cmd_ent->desc = desc;
    cmd_ent->user_arg = user_arg;
    cmd_ent->help = globus_libc_strdup(help);
    cmd_ent->min_argc = min_argc;
    cmd_ent->max_argc = max_argc;

    list = (globus_list_t *) globus_hashtable_lookup(
        &server_handle->cmd_table, (char *)command_name);
    globus_list_insert(&list, cmd_ent);
    globus_hashtable_insert(
        &server_handle->cmd_table, (char *)command_name, list);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

char *
globus_i_gsc_get_help(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            command_name)
{
    globus_list_t *                         list;
    globus_l_gsc_cmd_ent_t *                cmd_ent;
    char *                                  help_str;
    char *                                  tmp_ptr;
    int                                     cmd_ctr;
    int                                     sc;
    char                                    cmd_name[5];

    if(command_name == NULL)
    {
        help_str = globus_libc_strdup(
            "214-The following commands are recognized:");
        tmp_ptr = help_str;
        globus_hashtable_to_list(&server_handle->cmd_table, &list);
        cmd_ctr = 0;
        while(!globus_list_empty(list))
        {
            if(cmd_ctr == 0)
            {
                help_str = globus_common_create_string(
                    "%s\r\n", help_str);
                globus_free(tmp_ptr);
                tmp_ptr = help_str;
            }
            cmd_ent = (globus_l_gsc_cmd_ent_t *)
                globus_list_first(globus_list_first(list));
            sc = sprintf(cmd_name, "%s", cmd_ent->cmd_name);
            if(sc < 4)
            {
                cmd_name[3] = ' ';
                cmd_name[4] = '\0';
            }
            help_str = globus_common_create_string(
                "%s    %s", help_str, cmd_name);
            globus_free(tmp_ptr);
            tmp_ptr = help_str;

            cmd_ctr++;
            if(cmd_ctr == 8)
            {
                cmd_ctr = 0;
            }
            list = globus_list_rest(list);
        }
        help_str = globus_common_create_string(
            "%s\r\n214 End\r\n", help_str);
        globus_free(tmp_ptr);

        return help_str;
    }
    else
    {
        list = (globus_list_t *) globus_hashtable_lookup(
                        &server_handle->cmd_table, (char *)command_name);
        if(list == NULL)
        {
            return globus_common_create_string("502 Unknown command '%s'.\r\n",
                command_name);
        }

        while(!globus_list_empty(list))
        {
            cmd_ent = (globus_l_gsc_cmd_ent_t *)
                globus_list_first(list);
            if(cmd_ent->help != NULL)
            {
                return globus_libc_strdup(cmd_ent->help);
            }
            list = globus_list_rest(list);
        }
        return globus_common_create_string(
            "502 No help available for '%s'.\r\n",
            command_name);
    }

    return NULL;
}

globus_result_t
globus_i_gsc_resource_query(
    globus_i_gsc_op_t *                     op,
    const char *                            path,
    globus_gridftp_server_control_resource_mask_t mask,
    globus_i_gsc_resource_cb_t              cb,
    void *                                  user_arg)
{
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_i_gsc_resource_query);

    if(op == NULL)
    {
    }
    if(path == NULL)
    {
    }

    op->type = GLOBUS_L_GSC_OP_TYPE_RESOURCE;
    op->stat_cb = cb;
    op->path = globus_libc_strdup(path);
    op->mask = mask;
    op->user_arg = user_arg;
    op->res = GLOBUS_SUCCESS;

    if(op->server_handle->resource_cb != NULL)
    {
        op->server_handle->resource_cb(
            op,
            op->path,
            op->mask);
    }
    else
    {
        res = GLOBUS_FAILURE;
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_i_gsc_authenticate(
    globus_i_gsc_op_t *                     op,
    const char *                            user,
    const char *                            pass,
    gss_cred_id_t                           cred,
    gss_cred_id_t                           del_cred,
    globus_i_gsc_auth_cb_t                  cb,
    void *                                  user_arg)
{
    GlobusGridFTPServerName(globus_i_gsc_authenticate);

    if(op == NULL)
    {
    }

    op->auth_cb = cb;
    op->type = GLOBUS_L_GSC_OP_TYPE_AUTH;
    op->res = GLOBUS_SUCCESS;
    op->user_arg = user_arg;

    if(user != NULL)
    {
        op->username = globus_libc_strdup(user);
    }
    if(pass != NULL)
    {
        op->password = globus_libc_strdup(pass);
    }
    op->cred = cred;
    op->del_cred = del_cred;

    /* call out to user */
    if(op->server_handle->auth_cb != NULL)
    {
        op->server_handle->auth_cb(
            op,
            op->username,
            op->password,
            op->cred,
            op->del_cred);
    }
    /* just always authenticate... so just call the callback */
    else
    {
        GlobusLGSCRegisterInternalCB(op);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gsc_port(
    globus_i_gsc_op_t *                     op,
    const char **                           contact_strings,
    int                                     stripe_count,
    int                                     prt,
    globus_i_gsc_port_cb_t                  cb,
    void *                                  user_arg)
{
    int                                     ctr;
    void *                                  user_data_handle = NULL;
    globus_gridftp_server_control_data_destroy_cb_t data_destroy_cb = NULL;

    if(op == NULL)
    {
    }
    for(ctr = 0; ctr < stripe_count; ctr++)
    {
        if(!globus_i_gridftp_server_control_cs_verify(
            contact_strings[ctr], prt))
        {
            /* return error */
        }
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object != NULL)
        {
            data_destroy_cb = op->server_handle->data_destroy_cb;
            user_data_handle = op->server_handle->data_object->user_handle;
            globus_free(op->server_handle->data_object);
            op->server_handle->data_object = NULL;
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    if(user_data_handle != NULL)
    {
        data_destroy_cb(user_data_handle);
    }

    op->type = GLOBUS_L_GSC_OP_TYPE_CREATE_PORT;
    op->net_prt = prt;
    op->port_cb = cb;
    op->max_cs = stripe_count;
    op->user_arg = user_arg;

    op->cs = globus_malloc(sizeof(char *) * stripe_count);
    for(ctr = 0; ctr < stripe_count; ctr++)
    {
        op->cs[ctr] = globus_libc_strdup(contact_strings[ctr]);
    }

    if(op->server_handle->active_cb != NULL)
    {
        op->server_handle->active_cb(
            op,
            op->net_prt,
            (const char **)op->cs,
            op->max_cs);
    }
    else
    {
        GlobusLGSCRegisterInternalCB(op);
    }

    return GLOBUS_SUCCESS;
}


globus_result_t
globus_i_gsc_passive(
    globus_i_gsc_op_t *                     op,
    int                                     max,
    int                                     net_prt,
    globus_i_gsc_passive_cb_t               cb,
    void *                                  user_arg)
{
    void *                                  user_data_handle = NULL;
    globus_gridftp_server_control_data_destroy_cb_t data_destroy_cb = NULL;

    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object != NULL)
        {
            data_destroy_cb = op->server_handle->data_destroy_cb;
            user_data_handle = op->server_handle->data_object->user_handle;
            globus_free(op->server_handle->data_object);
            op->server_handle->data_object = NULL;
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    if(user_data_handle != NULL)
    {
        data_destroy_cb(user_data_handle);
    }

    op->type = GLOBUS_L_GSC_OP_TYPE_CREATE_PASV;
    op->net_prt = net_prt;
    op->max_cs = max;
    op->passive_cb = cb;
    op->user_arg = user_arg;

    if(op->server_handle->passive_cb != NULL)
    {
        op->server_handle->passive_cb(
            op,
            op->net_prt,
            op->max_cs);
    }
    else
    {
        GlobusLGSCRegisterInternalCB(op);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gsc_send(
    globus_i_gsc_op_t *                     op,
    const char *                            path,
    const char *                            mod_name,
    const char *                            mod_parms,
    globus_i_gsc_transfer_cb_t              transfer_cb,
    globus_i_gsc_event_cb_t                 event_cb,
    void *                                  user_arg)
{
    globus_gridftp_server_control_transfer_cb_t user_cb;

    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object == NULL ||
            !(op->server_handle->data_object->dir & 
                    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND))
        {

        }
        if(mod_name == NULL)
        {
            user_cb = op->server_handle->default_send_cb;
        }
        else
        {
            user_cb = (globus_gridftp_server_control_transfer_cb_t)
                globus_hashtable_lookup(
                    &op->server_handle->send_cb_table, (char *)mod_name);
            if(user_cb == NULL)
            {
            }
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    op->type = GLOBUS_L_GSC_OP_TYPE_TRANSFER;
    op->path = globus_libc_strdup(path);
    if(mod_name != NULL)
    {
        op->mod_name = globus_libc_strdup(mod_name);
    }
    if(mod_parms != NULL)
    {
        op->mod_parms = globus_libc_strdup(mod_parms);
    }
    op->transfer_cb = transfer_cb;
    op->event_cb = event_cb;
    op->user_arg = user_arg;

    if(user_cb != NULL)
    {
        user_cb(
            op, 
            op->server_handle->data_object->user_handle,
            op->path,
            op->mod_name,
            op->mod_parms);
    }
    else
    {
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gsc_recv(
    globus_i_gsc_op_t *                     op,
    const char *                            path,
    const char *                            mod_name,
    const char *                            mod_parms,
    globus_i_gsc_transfer_cb_t              transfer_cb,
    globus_i_gsc_event_cb_t                 event_cb,
    void *                                  user_arg)
{
    globus_gridftp_server_control_transfer_cb_t user_cb;

    if(op == NULL)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object == NULL ||
            !(op->server_handle->data_object->dir & 
                    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_RECV))
        {

        }
        if(mod_name == NULL)
        {
            user_cb = op->server_handle->default_recv_cb;
        }
        else
        {
            user_cb = (globus_gridftp_server_control_transfer_cb_t)
                globus_hashtable_lookup(
                    &op->server_handle->recv_cb_table, (char *)mod_name);
            if(user_cb == NULL)
            {
            }
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    op->type = GLOBUS_L_GSC_OP_TYPE_TRANSFER;
    op->path = globus_libc_strdup(path);
    if(mod_name != NULL)
    {
        op->mod_name = globus_libc_strdup(mod_name);
    }
    if(mod_parms != NULL)
    {
        op->mod_parms = globus_libc_strdup(mod_parms);
    }
    op->transfer_cb = transfer_cb;
    op->event_cb = event_cb;
    op->user_arg = user_arg;

    if(user_cb != NULL)
    {
        user_cb(
            op, 
            op->server_handle->data_object->user_handle,
            op->path,
            op->mod_name,
            op->mod_parms);
    }
    else
    {
    }

    return GLOBUS_SUCCESS;
}

 /*************************************************************************
 *      user command finished functions
 *      -------------------------------
 *  check and store parameters, then just one shot.  easiest way to go.
 *************************************************************************/
static void
globus_l_gsc_internal_cb_kickout(
    void *                                  user_arg)
{
    globus_i_gsc_op_t *                     op;

    op = (globus_i_gsc_op_t *) user_arg;

    switch(op->type)
    {
        case GLOBUS_L_GSC_OP_TYPE_AUTH:
            op->auth_cb(
                op,
                op->res,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_RESOURCE:
            op->stat_cb(
                op,
                op->res,
                op->path,
                op->stat_info,
                op->stat_count,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PASV:
            op->passive_cb(
                op,
                op->res,
                (const char **)op->cs,
                op->max_cs,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PORT:
            op->port_cb(
                op,
                op->res,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_TRANSFER:
            op->transfer_cb(
                op,
                op->res,
                op->user_arg);
            break;

        default:
            globus_assert(0 && "bad op type");
            break;
    }
}

globus_result_t
globus_gridftp_server_control_finished_auth(
    globus_i_gsc_op_t *                     op,
    globus_result_t                         res,
    uid_t                                   uid)
{
    if(op == NULL)
    {
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_AUTH)
    {
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(res == GLOBUS_SUCCESS)
        {
            op->server_handle->authenticated = GLOBUS_TRUE;
            op->uid = uid;
        }
        op->res = res;
        if(op->auth_cb != NULL)
        {
            GlobusLGSCRegisterInternalCB(op);
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_finished_resource(
    globus_gridftp_server_control_op_t      op,
    globus_result_t                         result,
    globus_gridftp_server_control_stat_t *  stat_info_array,
    int                                     stat_count)
{
    int                                     ctr;
    globus_result_t                         res = GLOBUS_SUCCESS;

    if(op == NULL)
    {
    }

    if(res == GLOBUS_SUCCESS)
    {
        op->stat_info = (globus_gridftp_server_control_stat_t *)
            globus_malloc(sizeof(globus_gridftp_server_control_stat_t) *
                stat_count);
        op->stat_count = stat_count;
        for(ctr = 0; ctr < op->stat_count; ctr++)
        {
            globus_i_gsc_stat_cp(
                &op->stat_info[ctr], &stat_info_array[ctr]);
        }
    }
    op->res = result;
    if(op->stat_cb != NULL)
    {
        GlobusLGSCRegisterInternalCB(op);
    }
    else
    {
        res = GLOBUS_FAILURE;
    }

    return res;
}

globus_result_t
globus_gridftp_server_control_finished_active_connect(
    globus_gridftp_server_control_op_t      op,
    void *                                  user_data_handle,
    globus_result_t                         res,
    globus_gridftp_server_control_data_dir_t data_dir)
{
    globus_i_gsc_data_t *                   data_obj;

    if(op == NULL)
    {
    }

    data_obj = (globus_i_gsc_data_t *) globus_malloc(
        sizeof(globus_i_gsc_data_t));
    if(data_obj == NULL)
    {
    }
    data_obj->dir = data_dir;
    data_obj->user_handle = user_data_handle;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object != NULL)
        {
        }
        op->server_handle->data_object = data_obj;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    GlobusLGSCRegisterInternalCB(op);

    return GLOBUS_SUCCESS;
}
                                                                                
globus_result_t
globus_gridftp_server_control_finished_passive_connect(
    globus_gridftp_server_control_op_t      op,
    void *                                  user_data_handle,
    globus_result_t                         res,
    globus_gridftp_server_control_data_dir_t data_dir,
    const char **                           cs,
    int                                     cs_count)
{
    globus_i_gsc_data_t *                   data_obj;
    int                                     ctr;

    if(op == NULL)
    {
    }
    for(ctr = 0; ctr < cs_count; ctr++)
    {
        if(!globus_i_gridftp_server_control_cs_verify(cs[ctr], op->net_prt))
        {
            /* return error */
        }
    }

    data_obj = (globus_i_gsc_data_t *) globus_malloc(
        sizeof(globus_i_gsc_data_t));
    if(data_obj == NULL)
    {
    }
    data_obj->dir = data_dir;
    data_obj->user_handle = user_data_handle;

    op->cs = (char **) globus_malloc(sizeof(char *) * cs_count);
    for(ctr = 0; ctr < cs_count; ctr++)
    {
        op->cs[ctr] = globus_libc_strdup(cs[ctr]);
    }
    op->res = res;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object != NULL)
        {
        }
        op->server_handle->data_object = data_obj;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    GlobusLGSCRegisterInternalCB(op);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_disconnected(
    globus_gridftp_server_control_t         server,
    void *                                  user_data_handle)
{
    globus_gridftp_server_control_data_destroy_cb_t destroy_cb = NULL;

    if(server == NULL)
    {
    }
    if(user_data_handle == NULL)
    {
    }

    globus_mutex_lock(&server->mutex);
    {
        if(server->data_object != NULL &&
            server->data_object->user_handle == user_data_handle)
        {
            globus_free(server->data_object);
            server->data_object = NULL;
            destroy_cb = server->data_destroy_cb;
        }
    }
    globus_mutex_unlock(&server->mutex);

    if(destroy_cb != NULL)
    {
        destroy_cb(user_data_handle);
    }

    return GLOBUS_SUCCESS;
}

                                                                                
globus_result_t
globus_gridftp_server_control_begin_transfer(
    globus_gridftp_server_control_op_t      op)
{
    if(op == NULL)
    {
    }

    globus_i_gsc_intermediate_reply(op, "150 Begining transfer.\r\n");

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_finished_transfer(
    globus_gridftp_server_control_op_t      op,
    globus_result_t                         res)
{
    if(op == NULL)
    {
    }

    op->res = res;

    GlobusLGSCRegisterInternalCB(op);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridft_server_control_send_event(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_event_type_t type,
    const char *                            msg)
{
    return GLOBUS_SUCCESS;
}

