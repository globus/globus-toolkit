#include "globus_i_gridftp_server_control.h"
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

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

typedef struct globus_l_gsc_restart_ent_s
{
    globus_off_t                            offset;
    globus_off_t                            length;
} globus_l_gsc_restart_ent_t;

typedef struct globus_l_gsc_cmd_ent_s
{
    int                                     cmd;
    char                                    cmd_name[16]; /* only 5 needed */
    globus_gsc_959_command_cb_t             cmd_cb;
    globus_gsc_959_command_desc_t           desc;
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

static void
globus_l_gsc_send_perf_marker_cb(
    void *                                  user_arg);

static void
globus_l_gsc_send_perf_marker(
    globus_i_gsc_op_t *                     op);

static void
globus_l_gsc_unreg_perf_marker(
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
    int                                     len,
    globus_i_gsc_server_handle_t *          server_handle)
{
    globus_i_gsc_op_t *                     op;

    op = (globus_i_gsc_op_t *) globus_calloc(sizeof(globus_i_gsc_op_t), 1);
    if(op == NULL)
    {
        return NULL;
    }
    op->command = globus_libc_malloc(len + 1);
    memcpy(op->command, command, len);
    op->command[len] = '\0';
    if(op->command == NULL)
    {
        globus_free(op);
        return NULL;
    }

    server_handle->ref++;
    op->server_handle = server_handle;
    op->res = GLOBUS_SUCCESS;
    op->cmd_list = cmd_list;
    op->ref = 1;

    op->uid = -1;

    return op;
}

static void
globus_l_gsc_op_destroy(
    globus_i_gsc_op_t *                     op)
{
    op->ref--;
    if(op->ref == 0)
    {
        op->server_handle->ref--;
        if(op->server_handle->ref == 0)
        {
            GlobusLRegisterDone(op->server_handle);
        }
        /* clearly leaking here */
        globus_free(op);
    }
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
                        cmd_list, buffer, len, server_handle);
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
                        if(server_handle->funcs.abort_cb != NULL)
                        {
                            server_handle->funcs.abort_cb(
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
                break;

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
    globus_gridftp_server_control_cb_t      done_cb = NULL;

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_assert(
        server_handle->state == GLOBUS_L_GSC_STATE_ABORTING_STOPPING ||
        server_handle->state == GLOBUS_L_GSC_STATE_STOPPING);
    globus_assert(server_handle->ref > 0);

    globus_mutex_lock(&server_handle->mutex);
    {
        server_handle->ref--;
        if(server_handle->ref == 0)
        {
            done_cb = server_handle->funcs.done_cb;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    /* set state to stopped */
    if(done_cb != NULL)
    {
        server_handle->funcs.done_cb(
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
    char *                                  tmp_ptr;
    char **                                 cmd_a = NULL;
    int                                     ctr;
    int                                     ndx;
    globus_bool_t                           done = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_parse_command);

    *out_cmd_a = NULL;

    cmd_a = (char **) globus_malloc(sizeof(char *) * (argc+1));
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
                tmp_ptr = strstr(cmd_a[ctr], "\r\n");
                if(tmp_ptr != NULL)
                {
                    *tmp_ptr = '\0';
                }
            }
            else
            {
                cmd_a[ctr] = globus_libc_strndup(start_ptr, ndx);
            }
            start_ptr += ndx;
        }
    }
    if(ctr > 0)
    {
        for(start_ptr = cmd_a[0]; *start_ptr != '\0'; start_ptr++)
        {
            *start_ptr = toupper(*start_ptr);
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
    globus_gsc_959_command_cb_t             cmd_cb = NULL;
    globus_i_gsc_server_handle_t *          server_handle;

    op = (globus_i_gsc_op_t *) user_arg;

    server_handle = op->server_handle;
    globus_mutex_lock(&server_handle->mutex);
    {
        globus_assert(
            server_handle->state == GLOBUS_L_GSC_STATE_PROCESSING);
        auth = server_handle->authenticated;

        msg = "500 Invalid command.\r\n";
        while(!done)
        {
            /* if we ran out of commands before finishing tell the client
                the command does not exist */
            if(op->cmd_list == NULL)
            {
                res = globus_l_gsc_final_reply(server_handle, msg);
                done = GLOBUS_TRUE;
                globus_l_gsc_op_destroy(op);
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
    globus_mutex_unlock(&server_handle->mutex);

    if(cmd_cb != NULL)
    {
        argc = globus_l_gsc_parse_command(
            op->command, &cmd_array, cmd_ent->max_argc);
        if(argc < cmd_ent->min_argc)
        {
            globus_gsc_959_finished_command(op,
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

    globus_l_gsc_op_destroy(op);
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
    globus_assert(tmp_ptr != NULL); /* XXX remove this */
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
    if(server_handle->ref != 0)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    globus_mutex_lock(&server_handle->mutex);
    {
        if(server_handle->state != GLOBUS_L_GSC_STATE_STOPPED &&
            server_handle->state != GLOBUS_L_GSC_STATE_OPEN)
        {
            globus_mutex_unlock(&server_handle->mutex);
            res = GlobusGridFTPServerErrorParameter("server");
            goto err;
        }

        server_handle->ref = 1;
        server_handle->xio_handle = xio_handle;

        server_handle->funcs.send_cb_table = i_attr->funcs.send_cb_table;
        server_handle->funcs.recv_cb_table = i_attr->funcs.recv_cb_table;
        server_handle->funcs.default_send_cb = i_attr->funcs.default_send_cb;
        server_handle->funcs.default_recv_cb = i_attr->funcs.default_recv_cb;
        server_handle->funcs.auth_cb = i_attr->funcs.auth_cb;
        server_handle->funcs.passive_cb = i_attr->funcs.passive_cb;
        server_handle->funcs.active_cb = i_attr->funcs.active_cb;
        server_handle->funcs.data_destroy_cb = i_attr->funcs.data_destroy_cb;
        server_handle->funcs.list_cb = i_attr->funcs.list_cb;
        server_handle->funcs.resource_cb = i_attr->funcs.resource_cb;
        server_handle->funcs.done_cb = done_cb;
        server_handle->funcs.abort_cb = i_attr->funcs.abort_cb;

        globus_hashtable_copy(
            &server_handle->funcs.send_cb_table, 
            &i_attr->funcs.send_cb_table, NULL);
        globus_hashtable_copy(
            &server_handle->funcs.recv_cb_table, 
            &i_attr->funcs.recv_cb_table, NULL);

        if(server_handle->modes != NULL)
        {
            globus_free(server_handle->modes);
        }
        if(server_handle->types != NULL)
        {
            globus_free(server_handle->types);
        }
        /* default options */
        strcpy(server_handle->opts.mlsx_fact_str, "TMSPUQ");
        server_handle->opts.send_buf = -1; 
        server_handle->opts.perf_frequency = 5;
        server_handle->opts.receive_buf = -1;
        server_handle->opts.parallelism = 1;
        server_handle->opts.packet_size = -1;
        server_handle->opts.delayed_passive = GLOBUS_FALSE;
        server_handle->opts.passive_only = GLOBUS_FALSE;
        server_handle->opts.pasv_max = 1;
        server_handle->opts.port_max = 1;
        server_handle->opts.port_prt = 
            GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4;
        server_handle->opts.pasv_prt = 
            GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4;
        server_handle->opts.dc_parsing_alg = 0;;

        /* default state */
        server_handle->modes = globus_libc_strdup(i_attr->modes);
        server_handle->types = globus_libc_strdup(i_attr->types);
        server_handle->type = 'A';
        server_handle->mode = 'S';

        if(server_handle->cwd != NULL)
        {
            globus_free(server_handle->cwd);
        }
        server_handle->cwd = globus_libc_strdup(i_attr->base_dir);
        if(i_attr->pre_auth_banner != NULL)
        {
            server_handle->pre_auth_banner = 
                globus_libc_strdup(i_attr->pre_auth_banner);
        }
        if(i_attr->post_auth_banner != NULL)
        {
            server_handle->post_auth_banner = 
                globus_libc_strdup(i_attr->post_auth_banner);
        }

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

                if(server_handle->funcs.abort_cb != NULL)
                {
                    server_handle->funcs.abort_cb(
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
globus_gsc_959_finished_command(
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
globus_gsc_959_command_add(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            command_name,
    globus_gsc_959_command_cb_t             command_cb,
    globus_gsc_959_command_desc_t           desc,
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

globus_result_t
globus_gridftp_server_control_add_feature(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            feature)
{
    GlobusGridFTPServerName(globus_i_gsc_resource_query);

    if(server_handle == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server_handle");
    }
    if(feature == NULL)
    {
        return GlobusGridFTPServerErrorParameter("feature");
    }

    globus_list_insert(&server_handle->feature_list, globus_libc_strdup(feature));

    return GLOBUS_SUCCESS;
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

char *
globus_i_gsc_string_to_959(
    const char *                            in_str)
{
    char *                                  tmp_ptr;
    char *                                  out_str;
    char *                                  end;
    int                                     ctr = 0;
    int                                     size;

    for(tmp_ptr = (char *)in_str; 
        tmp_ptr != NULL; 
        tmp_ptr = strchr(tmp_ptr, '\n'))
    {
        ctr++;
    }
    size = strlen(in_str);

    out_str = (char *) globus_malloc((size+ctr+2) * sizeof(char));
    memcpy(out_str, in_str, size);
    end = out_str + size + ctr + 2;
    for(tmp_ptr = out_str; tmp_ptr != NULL; tmp_ptr = strchr(tmp_ptr, '\n'))
    {
        memmove((tmp_ptr + 1), tmp_ptr, end - tmp_ptr - 1);
        *tmp_ptr = '\r';
        tmp_ptr += 2;
    }
    size = strlen(out_str);
    if(out_str[size-1] != '\n')
    {
        out_str[size] = '\r';
        size++;
        out_str[size] = '\n';
        size++;
        out_str[size] = '\0';
    }

    return out_str;
}

char *
globus_i_gsc_nlst_line(
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count)
{
    int                                     ctr;
    int                                     tmp_i;
    char *                                  buf;
    char *                                  tmp_ptr;
    globus_size_t                           buf_len;
    globus_size_t                           buf_left;

    /* take a guess at the size needed */
    buf_len = stat_count * sizeof(char) * 32;
    buf_left = buf_len;
    buf = globus_malloc(buf_len);
    tmp_ptr = buf;
    for(ctr = 0; ctr < stat_count; ctr++)
    {
        tmp_i = strlen(stat_info[ctr].name);
        if(buf_left < tmp_i)
        {
            buf_len *= 2;
            buf = globus_libc_realloc(buf, buf_len);
        }

        sprintf(tmp_ptr, "%s\r\n", stat_info[ctr].name);
        tmp_ptr += tmp_i;
        buf_left -= tmp_i;
    }

    return buf;
}

char *
globus_i_gsc_mlsx_line_single(
    const char *                            mlsx_fact_str,
    int                                     uid,
    globus_gridftp_server_control_stat_t *  stat_info)
{
    char *                                  out_buf;
    char *                                  tmp_ptr;
    char *                                  fact;
    char *                                  dir_ptr;
    int                                     buf_len;
    struct tm *                             tm;
    int                                     is_readable = 0;
    int                                     is_writable = 0;
    int                                     is_executable = 0;

    buf_len = 256; /* this could be suspect */
    out_buf = globus_malloc(buf_len);

    tmp_ptr = out_buf;
    for(fact = (char *)mlsx_fact_str; *fact != '\0'; fact++)
    {
        is_readable = 0;
        is_writable = 0;
        is_executable = 0;

        switch(*fact)
        {
            case GLOBUS_GSC_MLSX_FACT_TYPE:
                if(S_ISREG(stat_info->mode))
                {
                    sprintf(tmp_ptr, "Type=file;"); 
                }
                else if(S_ISDIR(stat_info->mode))
                {
                    dir_ptr = strchr(stat_info->name, '/');
                    if(dir_ptr == NULL)
                    {
                        dir_ptr = stat_info->name;
                    }

                    if(strcmp(dir_ptr, "..") == 0)
                    {
                        sprintf(tmp_ptr, "Type=pdir;");
                    }
                    else if(strcmp(dir_ptr, ".") == 0)
                    {
                        sprintf(tmp_ptr, "Type=cdir;");
                    }
                    else
                    {
                        sprintf(tmp_ptr, "Type=dir;");
                    }
                }
                else if(S_ISCHR(stat_info->mode))
                {
                    sprintf(tmp_ptr, "Type=OS.unix=chr;"); 
                }
                else if(S_ISBLK(stat_info->mode))
                {
                    sprintf(tmp_ptr, "Type=OS.unix=blk;"); 
                }
                else
                {
                    sprintf(tmp_ptr, "Type=OS.unix=other;"); 
                }
                break;

            case GLOBUS_GSC_MLSX_FACT_MODIFY:
                tm = gmtime(&stat_info->mtime);
                sprintf(tmp_ptr, "Modify=%04d%02d%02d%02d%02d%02d;",
                    tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                    tm->tm_hour, tm->tm_min, tm->tm_sec);
                break;

            case GLOBUS_GSC_MLSX_FACT_CHARSET:
                sprintf(tmp_ptr, "Charset=UTF-8;");
                break;

            case GLOBUS_GSC_MLSX_FACT_SIZE:
                sprintf(tmp_ptr, "Size=%llu;", 
                (unsigned long long) stat_info->size);
                break;

            case GLOBUS_GSC_MLSX_FACT_PERM:
                sprintf(tmp_ptr, "Perm=");
                tmp_ptr += 5;
                if(uid == stat_info->uid)
                {
                    if(stat_info->mode & S_IRUSR)
                    {
                        is_readable = 1;
                    }
                    if(stat_info->mode & S_IWUSR)
                    {
                        is_writable = 1;
                    }
                    if(stat_info->mode & S_IXUSR)
                    {
                        is_executable = 1;
                    }
                }
                if(uid == stat_info->gid)
                {
                    if(stat_info->mode & S_IRGRP)
                    {
                        is_readable = 1;
                    }
                    if(stat_info->mode & S_IWGRP)
                    {
                        is_writable = 1;
                    }
                    if(stat_info->mode & S_IXGRP)
                    {
                        is_executable = 1;
                    }
                }
                if(stat_info->mode & S_IROTH)
                {
                    is_readable = 1;
                }
                if(stat_info->mode & S_IWOTH)
                {
                    is_writable = 1;
                }
                if(stat_info->mode & S_IXOTH)
                {
                    is_executable = 1;
                }

                if(is_writable && S_ISREG(stat_info->mode))
                {
                    *(tmp_ptr++) = 'a';
                    *(tmp_ptr++) = 'w';
                }

                if(is_writable && is_executable && 
                    S_ISDIR(stat_info->mode))
                {
                    *(tmp_ptr++) = 'c';
                    *(tmp_ptr++) = 'f';
                    *(tmp_ptr++) = 'm';
                    *(tmp_ptr++) = 'p';
                }
                if(is_executable && S_ISDIR(stat_info->mode))
                {
                    *(tmp_ptr++) = 'e';
                }
                if(is_readable && is_executable && 
                    S_ISDIR(stat_info->mode))
                {
                    *(tmp_ptr++) = 'l';
                }
                if(is_readable && S_ISREG(stat_info->mode))
                {
                    *(tmp_ptr++) = 'r';
                }
                *(tmp_ptr++) = ';';
                *tmp_ptr = '\0';

                break;

            case GLOBUS_GSC_MLSX_FACT_UNIXMODE:
                sprintf(tmp_ptr, "UNIX.mode=%04o;", 
                    (unsigned) (stat_info->mode & 07777));
                break;

            case GLOBUS_GSC_MLSX_FACT_UNIQUE:
                sprintf(tmp_ptr, "Unique=%lx-%lx;", 
                    (unsigned long) stat_info->dev,
                    (unsigned long) stat_info->ino);
                break;

            default:
                globus_assert(0 && "not a valid fact");
                break;
        }
        tmp_ptr += strlen(tmp_ptr);
        sprintf(tmp_ptr, " %s", stat_info->name);
    }
    return out_buf;
}

char *
globus_i_gsc_mlsx_line(
    globus_i_gsc_server_handle_t *          server_handle,
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count)
{
    int                                     ctr;
    char *                                  buf;
    char *                                  tmp_ptr;

    buf = globus_libc_strdup("");
    for(ctr = 0; ctr < stat_count; ctr++)
    {
        tmp_ptr = globus_common_create_string("%s%s\r\n",
            buf,
            globus_i_gsc_mlsx_line_single(
                server_handle->opts.mlsx_fact_str, server_handle->uid, 
                &stat_info[ctr]));
        globus_free(buf);
        buf = tmp_ptr;
    }

    return buf;
}

/*
 *  turn a stat struct into a string
 */
char *
globus_i_gsc_list_single_line(
    globus_gridftp_server_control_stat_t *  stat_info)
{
    char *                                  username;
    char *                                  grpname;
    char                                    user[16];
    char                                    grp[16];
    struct passwd *                         pw;
    struct group *                          gr;
    struct tm *                             tm;
    char                                    perms[11];
    char *                                  tmp_ptr;
    char *                                  month_lookup[12] =
        {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
        "Sep", "Oct", "Nov", "Dec" };

    strcpy(perms, "----------");

    tm = localtime(&stat_info->mtime);
    pw = getpwuid(stat_info->uid);
    if(pw == NULL)
    {
        username = "(null)";
    }
    else
    {
        username = pw->pw_name;
    }
    gr = getgrgid(stat_info->gid);
    if(pw == NULL)
    {
        grpname = "(null)";
    }
    else
    {
        grpname = gr->gr_name;
    }
                                                                            
    if(S_ISDIR(stat_info->mode))
    {
        perms[0] = 'd';
    }
    else if(S_ISLNK(stat_info->mode))
    {
        perms[0] = 'l';
    }
    else if(S_ISFIFO(stat_info->mode))
    {
        perms[0] = 'x';
    }
    else if(S_ISCHR(stat_info->mode))
    {
        perms[0] = 'c';
    }
    else if(S_ISBLK(stat_info->mode))
    {
        perms[0] = 'b';
    }
                                                                            
    if(S_IRUSR & stat_info->mode)
    {
        perms[1] = 'r';
    }
    if(S_IWUSR & stat_info->mode)
    {
        perms[2] = 'w';
    }
    if(S_IXUSR & stat_info->mode)
    {
        perms[3] = 'x';
    }
    if(S_IRGRP & stat_info->mode)
    {
        perms[4] = 'r';
    }
    if(S_IWGRP & stat_info->mode)
    {
        perms[5] = 'w';
    }
    if(S_IXGRP & stat_info->mode)
    {
        perms[6] = 'x';
    }
    if(S_IROTH & stat_info->mode)
    {
        perms[7] = 'r';
    }
    if(S_IWOTH & stat_info->mode)
    {
        perms[8] = 'w';
    }
    if(S_IXOTH & stat_info->mode)
    {
        perms[9] = 'x';
    }

    sprintf(user, "        ");
    tmp_ptr = user + (8 - strlen(username));
    sprintf(tmp_ptr, "%s", username);
    
    sprintf(grp, "        ");
    tmp_ptr = grp + (8 - strlen(grpname));
    sprintf(tmp_ptr, "%s", grpname);

    tmp_ptr = globus_common_create_string(
        "%s %3d %s %s %8ld %s %2d %02d:%02d %s",
        perms,
        stat_info->nlink,
        user,
        grp,
        stat_info->size,
        month_lookup[tm->tm_mon],
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        stat_info->name);

    return tmp_ptr;
}

char *
globus_i_gsc_list_line(
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                     stat_count)
{
    int                                     ctr;
    char *                                  buf;
    char *                                  tmp_ptr;

    buf = globus_libc_strdup("");
    for(ctr = 0; ctr < stat_count; ctr++)
    {
        tmp_ptr = globus_common_create_string("%s%s\r\n",
            buf,
            globus_i_gsc_list_single_line(&stat_info[ctr]));
        globus_free(buf);
        buf = tmp_ptr;
    }

    return buf;
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

    if(op->server_handle->funcs.resource_cb != NULL)
    {
        op->server_handle->funcs.resource_cb(
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
        return GlobusGridFTPServerErrorParameter("op");
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
    if(op->server_handle->funcs.auth_cb != NULL)
    {
        op->server_handle->funcs.auth_cb(
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
    GlobusGridFTPServerName(globus_i_gsc_port);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    for(ctr = 0; ctr < stripe_count; ctr++)
    {
        if(!globus_i_gridftp_server_control_cs_verify(
            contact_strings[ctr], prt))
        {
            return GlobusGridFTPServerErrorParameter("contact_strings");
        }
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object != NULL)
        {
            data_destroy_cb = op->server_handle->funcs.data_destroy_cb;
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

    if(op->server_handle->funcs.active_cb != NULL)
    {
        op->server_handle->funcs.active_cb(
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
    GlobusGridFTPServerName(globus_i_gsc_passive);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object != NULL)
        {
            data_destroy_cb = op->server_handle->funcs.data_destroy_cb;
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

    if(op->server_handle->funcs.passive_cb != NULL)
    {
        op->server_handle->funcs.passive_cb(
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
globus_i_gsc_list(
    globus_i_gsc_op_t *                     op,
    const char *                            path,
    globus_gridftp_server_control_resource_mask_t mask,
    globus_i_gsc_op_type_t                  type,
    globus_i_gsc_transfer_cb_t              list_cb,
    void *                                  user_arg)
{
    globus_gridftp_server_control_list_cb_t user_cb;
    GlobusGridFTPServerName(globus_i_gsc_list);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object == NULL ||
            !(op->server_handle->data_object->dir & 
                    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND))
        {
            globus_mutex_unlock(&op->server_handle->mutex);
            return GlobusGridFTPServerErrorParameter("op");
        }
        user_cb = op->server_handle->funcs.list_cb;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    op->type = type;
    op->path = globus_libc_strdup(path);
    op->transfer_cb = list_cb;
    op->mask = mask;
    op->user_arg = user_arg;

    if(user_cb != NULL)
    {
        user_cb(
            op, 
            op->server_handle->data_object->user_handle,
            op->path);
    }
    else
    {
        return GlobusGridFTPServerNotACommand();
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
    void *                                  user_arg)
{
    globus_gridftp_server_control_transfer_cb_t user_cb;
    GlobusGridFTPServerName(globus_i_gsc_send);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object == NULL ||
            !(op->server_handle->data_object->dir & 
                    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND))
        {
            globus_mutex_unlock(&op->server_handle->mutex);
            return GlobusGridFTPServerErrorParameter("op");
        }
        if(mod_name == NULL)
        {
            user_cb = op->server_handle->funcs.default_send_cb;
        }
        else
        {
            user_cb = (globus_gridftp_server_control_transfer_cb_t)
                globus_hashtable_lookup(
                    &op->server_handle->funcs.send_cb_table, (char *)mod_name);
            if(user_cb == NULL)
            {
                globus_mutex_unlock(&op->server_handle->mutex);
                return GlobusGridFTPServerErrorParameter("op");
            }
        }
        op->restart_marker = op->server_handle->restart_marker;
        op->server_handle->restart_marker = NULL;
        if(op->restart_marker == NULL)
        {
            op->restart_marker = globus_i_gsc_restart_create();
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    op->type = GLOBUS_L_GSC_OP_TYPE_SEND;
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
    op->user_arg = user_arg;

    if(user_cb != NULL)
    {
        user_cb(
            op, 
            op->server_handle->data_object->user_handle,
            op->path,
            op->mod_name,
            op->mod_parms,
            op->restart_marker);
    }
    else
    {
        return GlobusGridFTPServerNotACommand();
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
    void *                                  user_arg)
{
    globus_gridftp_server_control_transfer_cb_t user_cb;
    GlobusGridFTPServerName(globus_i_gsc_recv);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->data_object == NULL ||
            !(op->server_handle->data_object->dir & 
                    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_RECV))
        {
            globus_mutex_unlock(&op->server_handle->mutex);
            return GlobusGridFTPServerErrorParameter("op");
        }
        if(mod_name == NULL)
        {
            user_cb = op->server_handle->funcs.default_recv_cb;
        }
        else
        {
            user_cb = (globus_gridftp_server_control_transfer_cb_t)
                globus_hashtable_lookup(
                    &op->server_handle->funcs.recv_cb_table, (char *)mod_name);
            if(user_cb == NULL)
            {
                globus_mutex_unlock(&op->server_handle->mutex);
                return GlobusGridFTPServerErrorParameter("op");
            }
        }
        op->restart_marker = op->server_handle->restart_marker;
        op->server_handle->restart_marker = NULL;
        if(op->restart_marker == NULL)
        {
            op->restart_marker = globus_i_gsc_restart_create();
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    op->type = GLOBUS_L_GSC_OP_TYPE_RECV;
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
    op->user_arg = user_arg;

    if(user_cb != NULL)
    {
        user_cb(
            op, 
            op->server_handle->data_object->user_handle,
            op->path,
            op->mod_name,
            op->mod_parms,
            op->restart_marker);
    }
    else
    {
        return GlobusGridFTPServerNotACommand();
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

        case GLOBUS_L_GSC_OP_TYPE_SEND:
        case GLOBUS_L_GSC_OP_TYPE_RECV:
        case GLOBUS_L_GSC_OP_TYPE_LIST:
        case GLOBUS_L_GSC_OP_TYPE_NLST:
        case GLOBUS_L_GSC_OP_TYPE_MLSD:
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
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_auth);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_AUTH)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(res == GLOBUS_SUCCESS)
        {
            op->server_handle->authenticated = GLOBUS_TRUE;
            op->server_handle->uid = uid;
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
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_resource);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
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
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_active_connect);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_CREATE_PORT)
    {
        return GlobusGridFTPServerErrorParameter("op");
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
        op->server_handle->stripe_count = op->max_cs;
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
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_passive_connect);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_CREATE_PASV)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    for(ctr = 0; ctr < cs_count; ctr++)
    {
        if(!globus_i_gridftp_server_control_cs_verify(cs[ctr], op->net_prt))
        {
            return GlobusGridFTPServerErrorParameter("contact string");
        }
    }

    data_obj = (globus_i_gsc_data_t *) globus_malloc(
        sizeof(globus_i_gsc_data_t));
    if(data_obj == NULL)
    {
        return GlobusGridFTPServerErrorMemory("data obj");
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
        op->server_handle->stripe_count = cs_count;
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
    GlobusGridFTPServerName(globus_gridftp_server_control_disconnected);

    if(server == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server");
    }
    if(user_data_handle == NULL)
    {
        return GlobusGridFTPServerErrorParameter("user_data_handle");
    }

    globus_mutex_lock(&server->mutex);
    {
        if(server->data_object != NULL &&
            server->data_object->user_handle == user_data_handle)
        {
            globus_free(server->data_object);
            server->data_object = NULL;
            destroy_cb = server->funcs.data_destroy_cb;
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
    globus_gridftp_server_control_op_t      op,
    int                                     event_mask)
{
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_begin_transfer);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_SEND &&
        op->type != GLOBUS_L_GSC_OP_TYPE_RECV &&
        op->type != GLOBUS_L_GSC_OP_TYPE_LIST &&
        op->type != GLOBUS_L_GSC_OP_TYPE_NLST &&
        op->type != GLOBUS_L_GSC_OP_TYPE_MLSD) 
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        /* TODO: determine if cached */
        res = globus_i_gsc_intermediate_reply(op, "150 Begining transfer.\r\n");
        /* send the first perf marker, start timer */
        if(op->type == GLOBUS_L_GSC_OP_TYPE_RECV &&
            op->server_handle->opts.perf_frequency >= 0 &&
            event_mask & GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF)
        {
            globus_reltime_t                delay;

            op->event.stripe_count = op->server_handle->stripe_count;
            op->done = GLOBUS_FALSE;
            op->ref++;
            op->event.stripe_total_bytes = (globus_off_t *)
                globus_calloc(sizeof(globus_off_t *) * 
                    op->server_handle->stripe_count, 1);
            globus_l_gsc_send_perf_marker(op);

            GlobusTimeReltimeSet(delay, 
                op->server_handle->opts.perf_frequency, 0);
            op->event.perf_running = 1;
            globus_callback_register_periodic(
                &op->event.periodic_handle,
                &delay,
                &delay,
                globus_l_gsc_send_perf_marker_cb,
                op);
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_finished_transfer(
    globus_gridftp_server_control_op_t      op,
    globus_result_t                         res)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_transfer);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_SEND &&
        op->type != GLOBUS_L_GSC_OP_TYPE_RECV &&
        op->type != GLOBUS_L_GSC_OP_TYPE_LIST &&
        op->type != GLOBUS_L_GSC_OP_TYPE_NLST &&
        op->type != GLOBUS_L_GSC_OP_TYPE_MLSD) 
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    op->res = res;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->event.perf_running)
        {
            globus_l_gsc_send_perf_marker(op);
            /* cancel callback send last one */
            op->done = GLOBUS_TRUE;
            globus_callback_unregister(
                op->event.periodic_handle,
                globus_l_gsc_unreg_perf_marker,
                op,
                NULL);
        }
        globus_i_gsc_restart_destroy(op->restart_marker);
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    GlobusLGSCRegisterInternalCB(op);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_list_buffer_alloc(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_stat_t *  stat_info_array,
    int                                     stat_count,
    globus_byte_t **                        out_buf,
    globus_size_t *                         out_size)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_list_buffer_malloc);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(stat_info_array == NULL)
    {
        return GlobusGridFTPServerErrorParameter("stat_info_array");
    }
    if(stat_count < 1)
    {
        return GlobusGridFTPServerErrorParameter("stat_count");
    }
    if(out_buf == NULL)
    {
        return GlobusGridFTPServerErrorParameter("out_buf");
    }
    if(out_size == NULL)
    {
        return GlobusGridFTPServerErrorParameter("out_size");
    }

    switch(op->type)
    { 
        case GLOBUS_L_GSC_OP_TYPE_LIST:
            *out_buf = globus_i_gsc_list_line(stat_info_array, stat_count);
            break;

        case GLOBUS_L_GSC_OP_TYPE_NLST:
            *out_buf = globus_i_gsc_nlst_line(stat_info_array, stat_count);
            break;

        case GLOBUS_L_GSC_OP_TYPE_MLSD:
            *out_buf = globus_i_gsc_mlsx_line(op->server_handle,
                stat_info_array, stat_count);
            break;

        default:
            return GlobusGridFTPServerErrorParameter("op");
            break;

    }

    *out_size = strlen(*out_buf);

    return GLOBUS_SUCCESS;
}

void
globus_gridftp_server_control_list_buffer_free(
    globus_byte_t *                         buffer)
{
    globus_free(buffer);
}

int
globus_l_gsc_restart_q_cmp(
    void *                                  p1,
    void *                                  p2)
{
    globus_l_gsc_restart_ent_t *            ent1;
    globus_l_gsc_restart_ent_t *            ent2;

    ent1 = (globus_l_gsc_restart_ent_t *) p1;
    ent2 = (globus_l_gsc_restart_ent_t *) p2;

    if(ent1->offset == ent2->offset)
    {
        return 0;
    }
    else if(ent1->offset < ent2->offset)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

globus_i_gsc_restart_t *
globus_i_gsc_restart_create()
{
    globus_i_gsc_restart_t *                restart;

    restart = (globus_i_gsc_restart_t *)
        globus_calloc(sizeof(globus_i_gsc_restart_t), 1);
    if(restart == NULL)
    {
        return NULL;
    }
    globus_priority_q_init(&restart->q, globus_l_gsc_restart_q_cmp);

    return restart;
}

void
globus_i_gsc_restart_add(
    globus_i_gsc_restart_t *                restart,
    globus_off_t                            start_off,
    globus_off_t                            end_off)
{
    globus_l_gsc_restart_ent_t *            ent;

    ent = (globus_l_gsc_restart_ent_t *)
        globus_malloc(sizeof(globus_l_gsc_restart_ent_t));
    ent->offset = start_off;
    ent->length = end_off - start_off;

    globus_priority_q_enqueue(&restart->q, ent, ent);
}

int
globus_gridftp_server_control_restart_get(
    globus_i_gsc_restart_t *                restart,
    globus_off_t *                          offset,
    globus_off_t *                          length)
{
    int                                     size;
    int                                     ndx;
    globus_l_gsc_restart_ent_t *            ent;

    if(restart->offset_a == NULL)
    {
        size = globus_priority_q_size(&restart->q) + 1;
        restart->offset_a = (globus_off_t *) 
            globus_malloc(sizeof(globus_off_t) * size);
        restart->length_a = (globus_off_t *) 
            globus_malloc(sizeof(globus_off_t) * size);

        if(size == 1)
        {
            restart->offset_a[0] = 0;
            restart->length_a[0] = -1;
            ndx++;
        }
        else
        {
            ndx = 0;
            ent = (globus_l_gsc_restart_ent_t *)
                globus_priority_q_first(&restart->q);
            if(ent->offset != 0)
            {
                restart->offset_a[ndx] = 0;
                restart->length_a[ndx] = ent->offset;
                ndx++;
            }
            while(globus_priority_q_size(&restart->q) != 1)
            {
                ent = (globus_l_gsc_restart_ent_t *)
                    globus_priority_q_dequeue(&restart->q);
                restart->offset_a[ndx] = ent->offset + ent->length;
                globus_free(ent);

                ent = (globus_l_gsc_restart_ent_t *)
                    globus_priority_q_first(&restart->q);
                restart->length_a[ndx] = ent->offset - restart->offset_a[ndx];
                ndx++;
            }
            ent = (globus_l_gsc_restart_ent_t *)
                    globus_priority_q_dequeue(&restart->q);

            restart->offset_a[ndx] = ent->offset + ent->length;
            restart->length_a[ndx] = -1;
            ndx++;

            globus_free(ent);

        }
        restart->size = ndx;
    }

    if(restart->ndx >= restart->size)
    {
        return -1;
    }
    if(offset != NULL)
    {
        *offset = restart->offset_a[restart->ndx];
    }
    if(length != NULL)
    {
        *length = restart->length_a[restart->ndx];
    }
    restart->ndx++;

    return 0;
}

void
globus_i_gsc_restart_destroy(
    globus_i_gsc_restart_t *                restart)
{
    if(restart->offset_a != NULL)
    {
        globus_free(restart->offset_a);
    }
    if(restart->length_a != NULL)
    {
        globus_free(restart->length_a);
    }
    globus_priority_q_destroy(&restart->q);
    globus_free(restart);
}

void
globus_l_gsc_send_restart_marker()
{

}

static void
globus_l_gsc_unreg_perf_marker(
    void *                                  user_arg)
{
    globus_i_gsc_op_t *                     op;

    op = (globus_i_gsc_op_t *) user_arg;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        globus_l_gsc_op_destroy(op);
    }
    globus_mutex_unlock(&op->server_handle->mutex);
}

static void
globus_l_gsc_send_perf_marker_cb(
    void *                                  user_arg)
{
    globus_i_gsc_op_t *                     op;

    op = (globus_i_gsc_op_t *) user_arg;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(!op->done)
        {
            globus_l_gsc_send_perf_marker(op);
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);
}

static void
globus_l_gsc_send_perf_marker(
    globus_i_gsc_op_t *                     op)
{
    char *                                  msg;
    int                                     ctr;
    struct timeval                          now;
    globus_i_gsc_event_data_t *             event;

    event = &op->event;
    gettimeofday(&now, NULL);
    for(ctr = 0; ctr < event->stripe_count; ctr++)
    {
        msg = globus_common_create_string(
                "112-Perf Marker.\r\n"
                " Timestamp:  %ld.%01ld\r\n"
                " Stripe Index: %d\r\n"
                " Stripe Bytes Transferred: %"GLOBUS_OFF_T_FORMAT"\r\n"
                " Total Stripe Count: %d\r\n"
                "112 End.\r\n",
                    now.tv_sec, now.tv_usec / 100000,
                    ctr,
                    event->stripe_total_bytes[ctr],
                    event->stripe_count);
        globus_i_gsc_intermediate_reply(op, msg); 
    }
}

globus_result_t
globus_gridftp_server_control_update_bytes(
    globus_gridftp_server_control_op_t      op,
    int                                     stripe_ndx,
    globus_off_t                            offset,
    globus_off_t                            length)
{
    if(op == NULL)
    {
    }

    if(op->event.stripe_total_bytes == NULL)
    {
    }
    if(stripe_ndx > op->event.stripe_count || stripe_ndx < 0)
    {
    }

    op->event.stripe_total_bytes[stripe_ndx] += length;

    return GLOBUS_SUCCESS;
}
