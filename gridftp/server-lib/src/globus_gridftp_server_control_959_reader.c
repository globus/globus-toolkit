#include "globus_i_gridftp_server_control.h"
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

#define GlobusL959RegisterDone(_h)                                      \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    _res = globus_callback_space_register_oneshot(                      \
                NULL,                                                   \
                NULL,                                                   \
                globus_l_gsc_959_user_close_kickout,                    \
                (void *)_h,                                             \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    if(_res != GLOBUS_SUCCESS)                                          \
    {                                                                   \
        globus_panic();                                                 \
    }                                                                   \
} while(0)

/*************************************************************************
 *              functions prototypes
 *
 ************************************************************************/

static globus_result_t
globus_l_gsc_959_intermediate_reply(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            message);

static globus_result_t
globus_l_gsc_959_final_reply(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            message);

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
static globus_byte_t                        globus_l_gsc_959_fake_buffer[1];
static globus_size_t                        globus_l_gsc_959_fake_buffer_len 
    = 1;

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
globus_l_gsc_959_read_callback(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_l_gsc_959_handle_t *             handle_959;
    globus_list_t *                         cmd_list;
    globus_gsc_op_959_t *                   op_959;
    /* largest know command is 4, but possible the user sent a huge one */
    char *                                  command_name;
    int                                     sc;
    int                                     ctr;
    GlobusGridFTPServerName(globus_l_gsc_959_read_callback);

    handle_959 = (globus_l_gsc_959_handle_t *) user_arg;

    globus_mutex_lock(&handle_959->server->mutex);
    {
        /*  terminate will be called twice because of the canceled read
            this is safe, due to the state machine. */
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_terminate(handle_959);
            globus_mutex_unlock(&handle_959->server->mutex);
            goto exit;
        }

        switch(handle->state)
        {
            /* OPEN: we will process this command */
            case GLOBUS_L_GSP_959_STATE_OPEN:
            /* PROCESSING we will add this command to a q */
            case GLOBUS_L_GSP_959_STATE_PROCESSING:
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
                                &handle_959->cmd_table, command_name);
                /*  This may be NULL, if so  we don't suport this command.
                 *  Just to the q anyway, it will be dealt with later. */

                /* if not an abort */
                if(strcmp(command_name, "ABOR") != 0)
                {
                    op_959 = globus_gsc_op_959_create(
                        cmd_list, buffer, handle_969);
                    if(op_959 == NULL)
                    {
                        globus_l_gsc_959_terminate(handle_959);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }

                    globus_fifo_enqueue(&handle->read_q, op_959);
                    /* if no errors outstanding */
                    if(handle->state == GLOBUS_L_GSP_959_STATE_OPEN)
                    {
                        globus_l_gsc_959_process_next_cmd(handle_959);
                    }
                    /* allow outstanding commands, just queue them up */
                    res = globus_xio_register_read(
                            xio_handle,
                            globus_l_gsc_959_fake_buffer,
                            globus_l_gsc_959_fake_buffer_len,
                            globus_l_gsc_959_fake_buffer_len,
                            NULL,
                            globus_l_gsc_959_read_callback,
                            (void *) handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsc_959_terminate(handle);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }
                }
                else
                {
                    /* if we are in the open state then there is no
                       outstanding operation to cancel and we can just
                       reply to the ABOR */
                    if(handle->state == GLOBUS_L_GSP_959_STATE_OPEN)
                    {
                        globus_assert(globus_fifo_empty(&handle->read_q));

                        handle->state = GLOBUS_L_GSP_959_STATE_PROCESSING;
                        res = globus_l_gsc_959_final_reply(
                                handle,
                                "226 Abort successful\r\n");
                        if(res != GLOBUS_SUCCESS)
                        {
                            globus_l_gsc_959_terminate(handle);
                            globus_mutex_unlock(&handle->server->mutex);
                            goto exit;
                        }
                    }
                    else
                    {
                        handle->state = GLOBUS_L_GSP_959_STATE_ABORTING;
                        /*
                         *  cancel the outstanding command.  In its callback
                         *  we flush the q and respond to the ABOR
                         */
                        globus_assert(handle->outstanding_op != NULL);

                        /*
                         *  noptify user that an abort is requested if they
                         *  are interested in hearing about it.
                         *  In any case  we will just wait for them to finish 
                         *  to respond to the abort.  Their notification cb
                         *  is simply a way to allow *them* to cancel what 
                         *  they are doing 
                         */
                        if(handle->abort_func != NULL)
                        {
                            handle->abort_func(
                                handle->outstanding_op,
                                handle->abort_arg);
                        }
                    }
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsc_959_terminate(handle);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }
                }

                globus_free(command_name);
                break;

            /* these only happen if result cam back an error, in which case
                we will jump around this part */
            case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPING:

            /* should never be in stopped state while a read is posted */
            case GLOBUS_L_GSP_959_STATE_STOPPED:
            /* we should not be in these states with a read posted
               ever.  When an abort is read we flush the queue and
               do not post another read until we are back in the open
               state */
            case GLOBUS_L_GSP_959_STATE_ABORTING:
            case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
            default:
                globus_assert(0 && "invalid state, likely memory curroption");
                break;
        }
    }
    globus_mutex_unlock(&handle->server->mutex);

  exit:

    return;
}

/*
 *  220 mesage write callback
 *
 *  This only happens once at the begining of the handle life cycle.
 */
static void 
globus_l_gsc_959_220_write_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res;
    globus_l_gsc_959_handle_t *             handle_959;
    GlobusGridFTPServerName(globus_l_gsc_959_220_write_cb);

    GlobusGridFTPServerDebugEnter();

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    globus_free(buffer);

    globus_mutex_lock(&handle->server->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_terminate(handle_959);
            globus_mutex_unlock(&handle->server->mutex);
            goto err;
        }

        /*  post a read on the fake buffers
         *  TODO:  deal with it if they are not using the right stack  */
        res = globus_xio_register_read(
                xio_handle,
                globus_l_gsc_959_fake_buffer,
                globus_l_gsc_959_fake_buffer_len,
                globus_l_gsc_959_fake_buffer_len,
                NULL,
                globus_l_gsc_959_read_callback,
                (void *) handle);
        if(res != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_terminate(handle);
            globus_mutex_unlock(&handle->server->mutex);
            goto err;
        }
    }
    globus_mutex_unlock(&handle->server->mutex);

    GlobusGridFTPServerDebugExit();
    return;

  err:
    GlobusGridFTPServerDebugExitWithError();
}

/*
 *  callback for replies
 */
static void 
globus_l_gsc_959_final_reply_cb(
    globus_xio_handle_t                             xio_handle,
    globus_result_t                                 result,
    globus_byte_t *                                 buffer,
    globus_size_t                                   length,
    globus_size_t                                   nbytes,
    globus_xio_data_descriptor_t                    data_desc,
    void *                                          user_arg)
{
    globus_result_t                                 res;
    globus_l_gsc_959_handle_t *                     handle;
    GlobusGridFTPServerName(globus_l_gsc_959_final_reply_cb);

    globus_free(buffer);

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->server->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_terminate(handle);
            globus_mutex_unlock(&handle->server->mutex);
            return;
        }

        switch(handle->state)
        {
            case GLOBUS_L_GSP_959_STATE_ABORTING:
                /* if all of the replies in response to the abort
                   have returned we can move back to the open state
                   and post another read */

                /* abort should have flushed the q and not posted
                   another read.  This must be empty */
                globus_assert(globus_fifo_empty(&handle->read_q));

                handle->abort_cnt--;
                if(handle->abort_cnt == 0)
                {
                    /* post a new read */
                    res = globus_xio_register_read(
                            handle->xio_handle,
                            globus_l_gsc_959_fake_buffer,
                            globus_l_gsc_959_fake_buffer_len,
                            1,
                            NULL,
                            globus_l_gsc_959_read_callback,
                            (void *) handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsc_959_terminate(handle);
                    }
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                handle->state = GLOBUS_L_GSP_959_STATE_OPEN;
                globus_l_gsc_959_process_next_cmd(handle);
                break;

            case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPING:
                GLOBUS_XIO_CLOSE_NO_CANCEL
                res = globus_xio_register_close(
                    handle_959->xio_handle,
                    globus_l_gsc_959_close_cb,
                    handle_959);
                if(res != GLOBUS_SUCCESS)
                {
                    GlobusL959RegisterDone(handle_959);
                }
                break;

            /* in open state if intermediate message has been sent */
            case GLOBUS_L_GSP_959_STATE_OPEN:
                break;

            case GLOBUS_L_GSP_959_STATE_STOPPED:
            default:
                globus_assert(0 && "should never reach this state");
                break;
        }
    }
    globus_mutex_unlock(&handle->server->mutex);
}

static void 
globus_l_gsc_959_intermediate_reply_cb(
    globus_xio_handle_t                             xio_handle,
    globus_result_t                                 result,
    globus_byte_t *                                 buffer,
    globus_size_t                                   length,
    globus_size_t                                   nbytes,
    globus_xio_data_descriptor_t                    data_desc,
    void *                                          user_arg)
{
    globus_l_gsc_959_reply_ent_t *                  reply_ent;
    globus_result_t                                 res;
    globus_l_gsc_959_handle_t *                     handle;
    GlobusGridFTPServerName(globus_l_gsc_959_final_reply_cb);

    globus_free(buffer);

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->server->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_terminate(handle);
            globus_mutex_unlock(&handle->server->mutex);
            return;
        }

        if(!globus_fifo_empty(&handle->reply_q))
        {
            reply_ent = (globus_l_gsc_959_reply_ent_t *)
                globus_fifo_dequeue(&handle->reply_q);
            if(reply_ent->final)
            {
                globus_l_gsc_959_finished_op(
                    reply_ent->op, reply_ent->msg);
            }
            else
            {
                res = globus_l_gsc_959_intermediate_reply(
                            handle,
                            reply_ent->msg);
                if(res != GLOBUS_SUCCESS)
                {
                    handle->reply_outstanding = GLOBUS_FALSE;
                    globus_l_gsc_959_terminate(handle);
                    globus_free(reply_ent->msg);
                }
            }
            globus_free(reply_ent);
        }
        else
        {
            handle->reply_outstanding = GLOBUS_FALSE;
        }
    }
    globus_mutex_lock(&handle->server->mutex);
}

static void
globus_l_gsc_959_user_close_kickout(
    void *                                  user_arg)
{
    globus_l_gsc_959_handle_t *             handle_959;

    handle_959 = (globus_l_gsc_959_handle_t *) user_arg;

    globus_assert(
        handle_959->state == GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING ||
        handle_959->state == GLOBUS_L_GSP_959_STATE_STOPPING);

    /* set state to stopped */
    if(handle_959->server->done_func != NULL)
    {
        handle_959->server->done_func(
            handle_959->server,
            handle_959->cached_res,
            handle_959->server->user_arg);
    }
    globus_l_gsc_959_handle_destroy(handle_959);
}

/*
 *  close callback
 * 
 *  handle is not closed until user requests a close.
 */
static void
globus_l_gsc_959_close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_gsc_959_user_close_kickout(user_arg);
}

/************************************************************************
 *                         utility functions
 *                         -----------------
 *
 ***********************************************************************/
static globus_l_gsc_959_handle_t *
globus_l_gsc_959_handle_create(
    globus_i_gsc_server_t *                 server,
    globus_xio_handle_t                     xio_handle)
{
    globus_l_gsc_959_handle_t *             handle;

    handle = (globus_l_gsc_959_handle_t *)
        globus_malloc(sizeof(globus_l_gsc_959_handle_t));
    if(handle == NULL)
    {
        return NULL;
    }
    memset(handle, '\0', sizeof(globus_l_gsc_959_handle_t));

    handle->state = GLOBUS_L_GSP_959_STATE_OPENING;
    handle->reply_outstanding = GLOBUS_FALSE;
    globus_fifo_init(&handle->read_q);
    globus_fifo_init(&handle->reply_q);

    globus_hashtable_init(
        &handle->cmd_table,
        128,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    
    handle->xio_handle = xio_handle;
    handle->server = server;
    
    globus_i_gsc_959_add_commands(handle);

    return handle;
}

/*
 *  clean up a handle
 */
static void
globus_l_gsc_959_handle_destroy(
    globus_l_gsc_959_handle_t *             handle)
{
    globus_fifo_destroy(&handle->read_q);
    globus_fifo_destroy(&handle->reply_q);
    globus_hashtable_destroy(&handle->cmd_table);
    globus_free(handle);
}

/*
 *   create a 959 op
 */
static globus_gsc_op_959_t *
globus_gsc_op_959_create(
    globus_list_t *                         cmd_list,
    char *                            	    buffer,
    globus_l_gsc_959_handle_t *             handle)
{
    globus_gsc_op_959_t *                   op_959;

    op_959 = (globus_gsc_op_959_t *)
        globus_malloc(sizeof(globus_gsc_op_959_t));
    if(op_959 == NULL)
    {
        return NULL;
    }

    op_959->cmd_list = cmd_list;
    op_959->handle = handle;
    op_959->command = buffer;
    op_959->server = handle->server;

    return op_959;
}

/*
 * destroy a 959 op
 */
static void
globus_gsc_op_959_destroy(
    globus_gsc_op_959_t *                   op_959)
{
    globus_free(op_959);
}

/*
 *  flush all reads in panic, abort, or early termination by the server.
 */
static globus_result_t
globus_l_gsc_959_flush_reads(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            reply_msg)
{
    globus_result_t                         res;
    globus_result_t                         tmp_res;
    globus_gsc_op_959_t *                   op_959;

    while(!globus_fifo_empty(&handle->read_q))
    {
        op_959 = (globus_gsc_op_959_t *)
            globus_fifo_dequeue(&handle->read_q);
        globus_assert(op_959 != NULL);
        globus_gsc_op_959_destroy(op_959);

        tmp_res = globus_l_gsc_959_final_reply(handle, reply_msg);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            res = tmp_res;
        }
    }

    return res;
}

/*
 *  callout into the command code
 */
static void
globus_l_gsc_959_command_callout(
    globus_gsc_op_959_t *                   op_959)
{
    globus_bool_t                           auth = GLOBUS_FALSE;

    if(op_959->server->state == GLOBUS_L_GS_STATE_OPEN)
    {
        auth = GLOBUS_TRUE;
    }
    while(!done)
    {
        /* if we ran out of commands before finishing tell the client
            the command does not exist */
        if(op_959->cmd_list == NULL)
        {
            res = globus_l_gsc_959_final_reply(op_959->handle, msg);
            done = GLOBUS_TRUE;
            globus_free(op_959);
        }
        else
        {
            cmd_ent = (globus_l_gsc_959_cmd_ent_t *)
                globus_list_first(op_959->cmd_list);
            /* must advance before calling the user callback */
            op_959->cmd_list = globus_list_rest(op_959->cmd_list);
            if(!auth && !(cmd_ent->desc & GLOBUS_GSC_959_COMMAND_PRE_AUTH))
            {
                msg = "530 Please login with USER and PASS.\r\n";
            }
            else if(auth && 
                !(cmd_ent->desc & GLOBUS_GSC_959_COMMAND_POST_AUTH))
            {
                msg = "503 You are already logged in!\r\n";
            }
            else
            {
                /*
                 *  call out to the users command
                 */
                cmd_ent->cmd_func(
                    op_959,
                    cmd_ent->cmd_name,
                    op_959->command,
                    cmd_ent->user_arg);

                done = GLOBUS_TRUE;
            }
        }
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
globus_l_gsc_959_process_next_cmd(
    globus_l_gsc_959_handle_t *             handle)
{
    globus_result_t                         res;
    globus_gsc_op_959_t *                   op_959;
    GlobusGridFTPServerName(globus_l_gsc_959_process_next_cmd);

    GlobusGridFTPServerDebugEnter();

    globus_assert(handle->state == GLOBUS_L_GSP_959_STATE_OPEN);

    if(!globus_fifo_empty(&handle->read_q))
    {
        handle->state = GLOBUS_L_GSP_959_STATE_PROCESSING;

        op_959 = (gglobus_gsc_op_959_t *)
            globus_fifo_dequeue(&handle->read_q);

        handle->outstanding_op = op_959;

        globus_l_gsc_959_command_callout(op_959);
    }

    GlobusGridFTPServerDebugExit();
}

/*
 *  seperated from the exteranally visible function to allow for only
 *  1 write at a time.
 */
static void
globus_l_gsc_959_finished_op(
    globus_gsc_op_959_t *                           op_959,
    char *                                          reply_msg)
{
    globus_l_gsc_959_handle_t *                     handle;
    globus_result_t                                 res;
    globus_bool_t                                   stopping = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_959_finished_op);

    handle = op_959->handle;

    switch(handle->state)
    {
        /* after receiving the servers reply to the abor we 
           clear everything in the Q and respond */
        case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
            stopping = GLOBUS_TRUE;
        case GLOBUS_L_GSP_959_STATE_ABORTING:

            /* if user considers this command incomplete it does not
               matter, we are aborting anyway */
            if(reply_msg == NULL)
            {
                reply_msg = "426 Command Aborted\r\n";
            }

            handle->abort_cnt = globus_fifo_size(&handle->read_q);
            handle->abort_cnt += 2;

            /* reply to the outstanding message */
            res = globus_l_gsc_959_final_reply(
                    handle,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                globus_l_gsc_959_terminate(handle);
                break;
            }
            res = globus_l_gsc_959_flush_reads(
                    handle,
                    "426 Command Aborted\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_l_gsc_959_terminate(handle);
                break;
            }
            res = globus_l_gsc_959_final_reply(
                    handle,
                    "226 Abort successful\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_l_gsc_959_terminate(handle);
                break;
            }
            break;

        case GLOBUS_L_GSP_959_STATE_PROCESSING:

            if(reply_msg == NULL && op_959->cmd_list == NULL)
            {
                reply_msg = "500 Command not supported\r\n";
            }

            if(reply_msg == NULL)
            {
                globus_l_gsc_959_command_callout(op_959);
            }
            else
            {
                res = globus_l_gsc_959_final_reply(
                        handle,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    globus_l_gsc_959_terminate(handle);
                }
            }
            break;

        case GLOBUS_L_GSP_959_STATE_STOPPING:
            stopping = GLOBUS_TRUE;
            break;

        case GLOBUS_L_GSP_959_STATE_OPEN:
        case GLOBUS_L_GSP_959_STATE_STOPPED:
        default:
            globus_assert(0);
            break;
    }

    if(stopping)
    {
        GLOBUS_XIO_CLOSE_NO_CANCEL
        res = globus_xio_register_close(
            handle_959->xio_handle,
            globus_l_gsc_959_close_cb,
            handle_959);
        if(res != GLOBUS_SUCCESS)
        {
            GlobusL959RegisterDone(handle_959);
        }
    }

    globus_free(op_959->command);
    globus_free(op_959);
}

static globus_result_t
globus_l_gsc_959_final_reply(
    globus_l_gsc_959_handle_t *                     handle,
    const char *                                    message)
{
    globus_result_t                                 res;
    char *                                          tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_959_final_reply);

    globus_assert(globus_fifo_empty(&handle->reply_q));

    tmp_ptr = globus_libc_strdup(message);
    /*TODO: check state */
    res = globus_xio_register_write(
            handle->xio_handle,
            tmp_ptr,
            strlen(tmp_ptr),
            strlen(tmp_ptr),
            NULL,
            globus_l_gsc_959_final_reply_cb,
            handle);
    if(res != GLOBUS_SUCCESS)
    {
        globus_mutex_unlock(&handle->server->mutex);
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
globus_l_gsc_959_intermediate_reply(
    globus_l_gsc_959_handle_t *                     handle,
    const char *                                    message)
{
    globus_result_t                                 res;
    char *                                          tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_959_intermediate_reply);

    globus_assert(globus_fifo_empty(&handle->reply_q));

    tmp_ptr = globus_libc_strdup(message);
    /*TODO: check state */
    res = globus_xio_register_write(
            handle->xio_handle,
            tmp_ptr,
            strlen(tmp_ptr),
            strlen(tmp_ptr),
            NULL,
            globus_l_gsc_959_intermediate_reply_cb,
            handle);
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

/*
 *  959 start
 *  ---------
 *  Write the 220 then start reading.
 */
globus_result_t
globus_i_gsc_959_start(
    globus_i_gsc_server_t *                 server,
    globus_xio_handle_t                     xio_handle)
{
    globus_result_t                         res;
    globus_l_gsc_959_handle_t *             handle_959;
    GlobusGridFTPServerName(globus_l_gsc_959_start);

    GlobusGridFTPServerDebugEnter();

    handle_959 = globus_l_gsc_959_handle_create(server, xio_handle);
    if(handle_959 == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("handle");
        goto err;
    }

    res = globus_xio_register_write(
                handle_959->xio_handle,
                server->pre_auth_banner,
                strlen(server->pre_auth_banner),
                strlen(server->pre_auth_banner),
                NULL, /* may need a DD here */
                globus_l_gsc_959_220_write_cb,
                handle);
    if(res != GLOBUS_SUCCESS)
    {
        globus_l_gsc_959_handle_destroy(handle_959);
        goto err;
    }

    GlobusGridFTPServerDebugExit()

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

/*
 *  terminate
 *  ---------
 *  This is called whenever an error occurs.  It attempts to nicely
 *  send a message to the user then changes to a stopping state.
 */
void
globus_i_gsc_959_terminate(
    globus_l_gsc_959_handle_t *             handle)
{
    globus_bool_t                           close = GLOBUS_TRUE;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_l_gsc_959_terminate);

    switch(handle->state)
    {
        /* if already stopping, just punt. this is likely to happen */
        case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
        case GLOBUS_L_GSP_959_STATE_STOPPING:
            close = GLOBUS_FALSE;
            break;

        case GLOBUS_L_GSP_959_STATE_ABORTING:
            handle->state = GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING;
            /* if aborting no read is posted, and there are no commands 
               to flush */
            break;

        /*  Clear out whatever commands we have if we can */
        case GLOBUS_L_GSP_959_STATE_PROCESSING:
            /* start abort process */
            handle->state = GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING;
            /*
             *  cancel the outstanding command.  In its callback
             *  we flush the q and respond to the ABOR
             */
            globus_assert(handle->outstanding_op != NULL);
            /* called locked like God intended. */
            if(handle->abort_func != NULL)
            {
                handle->abort_func(
                    handle->outstanding_op,
                    handle->abort_arg);
            }

            globus_xio_handle_cancel_operations(
                handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            globus_l_gsc_959_flush_reads(
                handle,
                "421 Service not available, closing control connection.\r\n");
            close = GLOBUS_FALSE;
            break;

        /*
         *  goto panic state and cancel the read
         */
        case GLOBUS_L_GSP_959_STATE_OPEN:
            handle->state = GLOBUS_L_GSP_959_STATE_STOPPING;
            globus_xio_handle_cancel_operations(
                handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            /* no commands to flush */
            break;

        /* shouldn't do anything once we hit the stopped state */
        case GLOBUS_L_GSP_959_STATE_STOPPED:
        /* no other states */
        default:
            globus_assert(0);
            break;
    }

    if(close)
    {
GLOBUS_XIO_CLOSE_NO_CANCEL
        res = globus_xio_register_close(
            handle_959->xio_handle,
            globus_l_gsc_959_close_cb,
            handle_959);
        if(res != GLOBUS_SUCCESS)
        {
            GlobusL959RegisterDone(handle_959);
        }
    }
}


void
globus_i_gsc_959_finished_op(
    globus_gsc_op_959_t *                   op,
    char *                                  reply_msg)
{
    globus_l_gsc_959_handle_t *             handle;
    globus_l_gsc_959_reply_ent_t *          reply_ent;
    GlobusGridFTPServerName(globus_gsc_959_finished_op);

    handle = op_959->handle;

    if(handle->reply_outstanding)
    {
        reply_ent = (globus_l_gsc_959_reply_ent_t *)
            globus_malloc(sizeof(globus_l_gsc_959_reply_ent_t));
        reply_ent->msg = reply_msg;
        reply_ent->op = op;
        reply_ent->final = GLOBUS_TRUE;

        globus_fifo_enqueue(&handle->reply_q, reply_ent);
    }
    else
    {
        globus_l_gsc_959_finished_op(op, reply_msg);
    }
}

globus_result_t
globus_i_gsc_959_intermediate_reply(
    globus_gsc_op_959_t *                   op,
    char *                                  reply_msg)
{
    globus_l_gsc_959_reply_ent_t *          reply_ent;
    globus_l_gsc_959_handle_t *             handle;
    globus_result_t                         res;

    handle = op_959->handle;

    if(handle->reply_outstanding)
    {
        reply_ent = (globus_l_gsc_959_reply_ent_t *)
            globus_malloc(sizeof(globus_l_gsc_959_reply_ent_t));
        reply_ent->msg = reply_msg;
        reply_ent->op = op;
        reply_ent->final = GLOBUS_FALSE;

        globus_fifo_enqueue(&handle->reply_q, reply_ent);
    }
    else
    {
        handle->reply_outstanding = GLOBUS_TRUE;
        res = globus_l_gsc_959_intermediate_reply(
                handle,
                reply_msg);
        if(res != GLOBUS_SUCCESS)
        {
            handle->reply_outstanding = GLOBUS_FALSE;
            globus_l_gsc_959_terminate(handle);
        }
    }

    return res;
}

globus_result_t
globus_i_gsc_959_command_add(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            command_name,
    globus_gsc_959_command_func_t           command_func,
    globus_gsc_959_command_desc_t           desc,
    const char *                            help,
    void *                                  user_arg)
{
    globus_list_t *                         list;
    globus_result_t                         res;
    globus_l_gsc_959_cmd_ent_t *            cmd_ent;
    GlobusGridFTPServerName(globus_gsc_959_command_add);

    if(handle == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("handle");
        goto err;
    }
    if(command_name == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("command_name");
        goto err;
    }
    if(strlen(command_name) > 5)
    {
        res = GlobusGridFTPServerErrorParameter("command_name");
        goto err;
    }

    cmd_ent = (globus_l_gsc_959_cmd_ent_t *)globus_malloc(
        sizeof(globus_l_gsc_959_cmd_ent_t));
    if(cmd_ent == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("cmd_ent");
        goto err;
    }

    strcpy(cmd_ent->cmd_name, command_name);
    cmd_ent->cmd_func = command_func;
    cmd_ent->desc = desc;
    cmd_ent->user_arg = user_arg;
    cmd_ent->help = globus_libc_strdup(help);

    list = (globus_list_t *) globus_hashtable_lookup(
        &handle->cmd_table, (char *)command_name);
    globus_list_insert(&list, cmd_ent);
    globus_hashtable_insert(&handle->cmd_table, (char *)command_name, list);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

char *
globus_i_gsc_959_get_help(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            command_name)
{
    globus_list_t *                         list;
    globus_l_gsc_959_cmd_ent_t *            cmd_ent;
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
        globus_hashtable_to_list(&handle->cmd_table, &list);
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
            cmd_ent = (globus_l_gsc_959_cmd_ent_t *)
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
                        &handle->cmd_table, (char *)command_name);
        if(list == NULL)
        {
            return globus_common_create_string("502 Unknown command '%s'.\r\n",
                command_name);
        }

        while(!globus_list_empty(list))
        {
            cmd_ent = (globus_l_gsc_959_cmd_ent_t *)
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
