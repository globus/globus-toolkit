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
/*
 *  close
 *  -----
 *
 *  The server library tells the protocol module when to close.  A call
 *  to _stop() tells the protocol module to stop processing on the
 *  handle.  When the protocol module has completed all operations and
 *  cleaned up resources associcate with the handle (with the acception
 *  of the xio_handle, this will be closed by the user).  Once the 
 *  protocol module finishes with this clean up it calls the callback
 *  passed in as a parameter.  Once the protocol module makes the call to
 *  that callback it must have no outstanging operations on the xio_handle
 *  and may post no more operations.  Once the _stop() function returns
 *  the protocol module may not make any more calls to the server lib
 *  in reference to this handle.
 *
 *  If the sittuation occurs where the protocol module needs to initiate
 *  a close.  the pmod calls _done().  This
 *  will tell the lib that the procotol module can no longer continue
 *  and will result in the lib calling _stop().  From there the process
 *  continues as described above.
 */

#define GlobusL959RegisterStop(handle)                                  \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
    _res = globus_callback_space_register_oneshot(                      \
                NULL,                                                   \
                NULL,                                                   \
                globus_l_gsc_959_stop_kickout,                          \
                (void *)handle,                                         \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    globus_assert(_res == GLOBUS_SUCCESS); /* don't do this */          \
} while(0)

/*************************************************************************
 *              functions prototypes
 *
 ************************************************************************/
globus_l_gsc_959_handle_t *
globus_l_gsc_959_handle_create(
    globus_i_gsc_server_t *                 server,
    globus_xio_handle_t                     xio_handle);

void
globus_l_gsc_959_handle_destroy(
    globus_l_gsc_959_handle_t *             handle);

static globus_result_t
globus_l_gsc_959_intermediate_reply(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            message);

static globus_result_t
globus_l_gsc_959_final_reply(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            message);

void
globus_i_gsc_959_add_commands(
    globus_gsc_959_handle_t                 handle);

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
 *                         utility functions
 *                         -----------------
 *
 ***********************************************************************/
globus_l_gsc_959_handle_t *
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

    handle->ref = 1; /* i for start call and 1 for read about to post */
    handle->state = GLOBUS_L_GSP_959_STATE_OPEN;
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
void
globus_l_gsc_959_handle_destroy(
    globus_l_gsc_959_handle_t *             handle)
{
    globus_assert(handle->ref == 0);
    globus_fifo_destroy(&handle->read_q);
    globus_fifo_destroy(&handle->reply_q);
    globus_hashtable_destroy(&handle->cmd_table);
    globus_free(handle);
}

globus_gsc_op_959_t *
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

globus_result_t
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

        handle->ref++;
        tmp_res = globus_l_gsc_959_final_reply(handle, reply_msg);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            handle->ref--;
            res = tmp_res;
        }
        globus_assert(op_959 != NULL);
    }

    return res;
}

/*
 *  stop callback kickout
 */
void
globus_l_gsc_959_stop_kickout(
    void *                                  user_arg)
{
    globus_l_gsc_959_handle_t *             handle;

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    /* call the servers stop callback.  at this point everything should
        be finished */
    handle->stop_cb(handle->server);

    globus_assert(handle->state == GLOBUS_L_GSP_959_STATE_STOPPED);
    globus_l_gsc_959_handle_destroy(handle);
}

/*
 *  panic
 *  -----
 *  When ever an error occurs in this protocol module that will cause
 *  the server object to no longere operate (alloc errors, or xio errors)
 *  this function is called.  This function will do nothing if we are already
 *  panicing, or it will do what is needed to give the client as much info
 *  as possible, then close everything as quickly as possible.
 */
void
globus_l_gsc_959_panic(
    globus_l_gsc_959_handle_t *             handle)
{
    GlobusGridFTPServerName(globus_l_gsc_959_panic);

    switch(handle->state)
    {
        /* if already in panic mode, just punt */
        case GLOBUS_L_GSP_959_STATE_PANIC:
        case GLOBUS_L_GSP_959_STATE_PANIC_STOPPING:
            return;
            break;

        case GLOBUS_L_GSP_959_STATE_ABORTING:
            handle->state = GLOBUS_L_GSP_959_STATE_PANIC;
            /* if aborting no read is posted, and there are no commands 
               to flush */
            globus_assert(handle->stop_cb == NULL);
            break;

        /*
         *  Clear out whatever commands we have if we can
         */
        case GLOBUS_L_GSP_959_STATE_PROCESSING:
            handle->state = GLOBUS_L_GSP_959_STATE_PANIC;
            globus_xio_handle_cancel_operations(
                handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            globus_l_gsc_959_flush_reads(
                handle,
                "421 Service not available, closing control connection.\r\n");
            globus_assert(handle->stop_cb == NULL);
            break;

        /*
         *  goto panic state and cancel the read
         */
        case GLOBUS_L_GSP_959_STATE_OPEN:
            handle->state = GLOBUS_L_GSP_959_STATE_PANIC;
            globus_xio_handle_cancel_operations(
                handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            /* stop has not been called, this should be NULL */
            globus_assert(handle->stop_cb == NULL);
            break;

        /*
         *  if already stopping, go directly to panic_stopping.
         *  should be nothing to cancel.
         */
        case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
        case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
        case GLOBUS_L_GSP_959_STATE_STOPPING:
            handle->state = GLOBUS_L_GSP_959_STATE_PANIC_STOPPING;
            break;

        /* shouldn't do anything once we hit the stopped state */
        case GLOBUS_L_GSP_959_STATE_STOPPED:
        /* no other states */
        default:
            globus_assert(0);
            break;
    }

    globus_gridftp_server_control_pmod_done(handle->server, res);
}

void
globus_gsc_959_panic(
    globus_gsc_op_959_t *                   op_959)
{
    globus_l_gsc_959_handle_t *             handle;

    handle = op_959->handle;

    globus_mutex_lock(&handle->server->mutex);
    {
        globus_l_gsc_959_finised_op(
            op_959, 
            "421 Service not available, closing control connection.\r\n");
        globus_l_gsc_959_panic(handle);
    }
    globus_mutex_unlock(&handle->server->mutex);

    globus_l_gsc_959_handle_destroy(handle);
}

void
globus_l_gsc_959_command_kickout(
    void *                                  user_arg)
{
    globus_gsc_op_959_t *                   op_959;
    globus_l_gsc_959_cmd_ent_t *            cmd_ent;
    globus_bool_t                           auth = GLOBUS_FALSE;
    globus_bool_t                           done = GLOBUS_FALSE;
    char *                                  msg;
    globus_result_t                         res = GLOBUS_SUCCESS;

    GlobusGridFTPServerDebugEnter();

    op_959 = (globus_gsc_op_959_t *) user_arg;
    
    msg = "500 Command not implemented.\r\n";

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
            /* user already assignied ref for reply */
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
            else if(auth && !(cmd_ent->desc & GLOBUS_GSC_959_COMMAND_POST_AUTH))
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

    GlobusGridFTPServerDebugExit();
}

/*
 *  This pulls a command out of the read_q if there is one and processes
 *  it based on its type.  All callbacks for the commands are the same.
 *  This function should only be called in the PROCESSING state.
 */
void
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

        /* increment the reference, will be deced in reply_cb */
        handle->ref++; 

        handle->outstanding_op = op_959;
        res = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gsc_959_command_kickout,
            (void *) op_959);

        /* this will never happen ever, but why not account 
            for it anyway? */
        if(res != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_panic(op_959->handle);
            globus_free(op_959);
        }
    }

    GlobusGridFTPServerDebugExit();
}

/*
 *  since the authentication module is we are guarenteed 1 command
 *  per callback.
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
    globus_l_gsc_959_handle_t *             handle;
    globus_list_t *                         cmd_list;
    globus_gsc_op_959_t *                   op_959;
    /* largest know command is 4, but possible the user sent a huge one */
    char *                                  command_name;
    int                                     sc;
    int                                     ctr;
    GlobusGridFTPServerName(globus_l_gsc_959_read_callback);

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->server->mutex);
    {
        /* decrement for read callback returning */
        handle->ref--;

        /*
         *  The panic function can deal with being called in panic mode
         */
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_panic(handle);
            globus_mutex_unlock(&handle->server->mutex);
            globus_l_gsc_959_handle_destroy(handle);
            goto exit;
        }

        switch(handle->state)
        {
            case GLOBUS_L_GSP_959_STATE_OPEN:
            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                /*
                 *  parse out the command name
                 */
                command_name = (char *) globus_malloc(len + 1);
                sc = sscanf(buffer, "%s", command_name);
                /* stack will make sure this never happens */
                globus_assert(sc > 0);
                for(ctr = 0; command_name[ctr] != '\0'; ctr++)
                {
                    command_name[ctr] = toupper(command_name[ctr]);
                }

                /* calling pers function will likely result in a write being
                    post, the next read will be posted there. */
                cmd_list = (globus_list_t *) globus_hashtable_lookup(
                                &handle->cmd_table, command_name);

                /*
                 *  If NULL we don't suport this command.  Just add it
                 *  to the q anyway
                 */
                if(strcasecmp(command_name, "ABOR") != 0)
                {
                    op_959 = globus_gsc_op_959_create(
                        cmd_list, buffer, handle);
                    if(op_959 == NULL)
                    {
                        globus_l_gsc_959_panic(handle);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }

                    globus_fifo_enqueue(&handle->read_q, op_959);
                    if(handle->state == GLOBUS_L_GSP_959_STATE_OPEN)
                    {
                        globus_l_gsc_959_process_next_cmd(handle);
                    }
                    /* allow outstanding commands, just queue them up */
                    res = globus_xio_register_read(
                            xio_handle,
                            globus_l_gsc_959_fake_buffer,
                            globus_l_gsc_959_fake_buffer_len,
                            1,
                            NULL,
                            globus_l_gsc_959_read_callback,
                            (void *) handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsc_959_panic(handle);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }
                    handle->ref++;
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
                        handle->ref++;
                        res = globus_l_gsc_959_final_reply(
                                handle,
                                "226 Abort successful\r\n");
                        if(res != GLOBUS_SUCCESS)
                        {
                            handle->ref--;
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
                        globus_l_gsc_959_panic(handle);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }
                }

                globus_free(command_name);
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPING:
            case GLOBUS_L_GSP_959_STATE_PANIC_STOPPING:
                /* if the ref is zero we can finish this sucker off,
                   otherwise we do nothing.  All command received after
                   the server tells us to stop are ignored. */
                if(handle->ref == 0)
                {
                    handle->state = GLOBUS_L_GSP_959_STATE_STOPPED;
                    if(handle->stop_cb != NULL)
                    {
                        GlobusL959RegisterStop(handle);
                    }
                }
                break;

            /*
             *  If we are in panic mode, we are not trying to stop so
             *  all we need to do is dec reference (done) and end.
             */
            case GLOBUS_L_GSP_959_STATE_PANIC:
                break;

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
 *  write callback
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
    globus_l_gsc_959_handle_t *             handle;
    GlobusGridFTPServerName(globus_l_gsc_959_220_write_cb);

    GlobusGridFTPServerDebugEnter();

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    globus_free(buffer);

    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gsc_959_panic(handle);
    }

    /*
     *  post a read on the fake buffers
     *
     *  TODO:  deal with it if they are not using the right stack 
     */
    res = globus_xio_register_read(
            xio_handle,
            globus_l_gsc_959_fake_buffer,
            globus_l_gsc_959_fake_buffer_len,
            1,
            NULL,
            globus_l_gsc_959_read_callback,
            (void *) handle);
    if(res != GLOBUS_SUCCESS)
    {
        handle->ref--; /* didn't start reading */
        globus_l_gsc_959_handle_destroy(handle);
    }

    GlobusGridFTPServerDebugExit();
    return;

  err:
    GlobusGridFTPServerDebugExitWithError();
}

/*
 *  start up the server by posting first read on the control channel.
 *  As commands come in the server library is notified of them.
 */
static globus_result_t
globus_l_gsc_959_start(
    globus_i_gsc_server_t *                 server,
    globus_xio_handle_t                     xio_handle,
    void **                                 user_arg)
{
    globus_result_t                         res;
    globus_l_gsc_959_handle_t *             handle;
    GlobusGridFTPServerName(globus_l_gsc_959_start);

    GlobusGridFTPServerDebugEnter();

    handle = globus_l_gsc_959_handle_create(server, xio_handle);
    if(handle == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("handle");
        goto err;
    }

    res = globus_xio_register_write(
                handle->xio_handle,
                server->pre_auth_banner,
                strlen(server->pre_auth_banner),
                strlen(server->pre_auth_banner),
                NULL, /* may need a DD here */
                globus_l_gsc_959_220_write_cb,
                handle);
    if(res != GLOBUS_SUCCESS)
    {
        handle->ref--; /* didn't start reading */
        globus_l_gsc_959_handle_destroy(handle);
        goto err;
    }

    *user_arg = handle;

    GlobusGridFTPServerDebugExit()

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

/*
 *  When the server lib has finished with a server handle this function is
 *  called.  Depending on the state we cache the callback, wait for all
 *  outstanding references to return, then call that callback.  Once that
 *  callback is called we are finished with the xio_handle, and once 
 *  we return from this function no more calls into the lib should be made.
 */
static globus_result_t
globus_l_gsc_959_stop(
    globus_i_gsc_server_t *                         server,,
    globus_gridftp_server_control_stopped_cb_t      cb,
    void *                                          user_arg)
{
    globus_l_gsc_959_handle_t *                     handle;
    GlobusGridFTPServerName(globus_l_gsc_959_stop);

    handle = (globus_l_gsc_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->server->mutex);
    {
        handle->stop_cb = cb;
        switch(handle->state)
        {
            case GLOBUS_L_GSP_959_STATE_ABORTING:
                handle->state = GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING;
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                handle->state = GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING;
                break;

            case GLOBUS_L_GSP_959_STATE_OPEN:
                handle->state = GLOBUS_L_GSP_959_STATE_STOPPING;
                if(handle->ref == 0)
                {
                    handle->state = GLOBUS_L_GSP_959_STATE_STOPPED;
                    GlobusL959RegisterStop(handle);
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PANIC:
                handle->state = GLOBUS_L_GSP_959_STATE_PANIC_STOPPING;
                if(handle->ref == 0)
                {
                    handle->state = GLOBUS_L_GSP_959_STATE_STOPPED;
                    GlobusL959RegisterStop(handle);
                }
                break;

            /*
             *  stop should not be called twice
             */
            case GLOBUS_L_GSP_959_STATE_PANIC_STOPPING:
            case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPED:
            default:
                globus_assert(0 && "should never get stop call in this state");
                break;
        }
    }
    globus_mutex_unlock(&handle->server->mutex);

    return GLOBUS_SUCCESS;
}

void
globus_l_gsc_959_finished_op(
    globus_gsc_op_959_t *                           op_959,
    char *                                          reply_msg)
{
    globus_l_gsc_959_handle_t *                     handle;
    globus_result_t                                 res;
    globus_bool_t                                   stopping = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_959_finished_op);

    handle = op_959->handle;

    handle->ref--;
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
            handle->ref++;
            res = globus_l_gsc_959_final_reply(
                    handle,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                handle->ref--;
                globus_l_gsc_959_panic(handle);
                break;
            }
            res = globus_l_gsc_959_flush_reads(
                    handle,
                    "426 Command Aborted\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_l_gsc_959_panic(handle);
                break;
            }
            handle->ref++;
            res = globus_l_gsc_959_final_reply(
                    handle,
                    "226 Abort successful\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                handle->ref--;
                globus_l_gsc_959_panic(handle);
                break;
            }
            break;

        case GLOBUS_L_GSP_959_STATE_PROCESSING:

            handle->ref++;
            if(reply_msg == NULL && op_959->cmd_list == NULL)
            {
                reply_msg = "500 Command not supported\r\n";
            }

            if(reply_msg == NULL)
            {
                res = globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_gsc_959_command_kickout,
                    (void *) op_959);
                                                                            
                /* this will never happen ever, but why not account
                    for it anyway? */
                if(res != GLOBUS_SUCCESS)
                {
                    handle->ref--;
                    globus_l_gsc_959_panic(op_959->handle);
                }
            }
            else
            {
                res = globus_l_gsc_959_final_reply(
                        handle,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    handle->ref--;
                    globus_l_gsc_959_panic(handle);
                }
            }
            break;

        case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
            stopping = GLOBUS_TRUE;
            /* attempt to register replys, if the fail the ref count
               will not be incremented, so as long as we check for that
               going to zero we can ignore the return code of the
               reply() */
            if(reply_msg == NULL)
            {
                reply_msg = 
                  "421 Service not available, closing control connection.\r\n";
            }
            handle->ref++;
            res = globus_l_gsc_959_final_reply(
                    handle,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                handle->ref--;
                globus_l_gsc_959_panic(handle);
                break;
            }
            res = globus_l_gsc_959_flush_reads(
                    handle,
                "421 Service not available, closing control connection.\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_l_gsc_959_panic(handle);
                break;
            }
            break;

        case GLOBUS_L_GSP_959_STATE_STOPPING:
        case GLOBUS_L_GSP_959_STATE_PANIC_STOPPING:
            stopping = GLOBUS_TRUE;
            break;
        case GLOBUS_L_GSP_959_STATE_PANIC:
            break;

        case GLOBUS_L_GSP_959_STATE_OPEN:
        case GLOBUS_L_GSP_959_STATE_STOPPED:
        default:
            globus_assert(0);
            break;
    }

    if(stopping)
    {
        if(handle->ref == 0)
        {
            handle->state = GLOBUS_L_GSP_959_STATE_STOPPED;
            if(handle->stop_cb != NULL)
            {
                GlobusL959RegisterStop(handle);
            }
        }
    }

    globus_free(op_959->command);
    globus_free(op_959);
}

void
globus_gsc_959_finished_op(
    globus_gsc_op_959_t *                           op,
    char *                                          reply_msg)
{
    globus_l_gsc_959_handle_t *                     handle;
    globus_l_gsc_959_reply_ent_t *                  reply_ent;
    GlobusGridFTPServerName(globus_gsc_959_finished_op);

    handle = op_959->handle;
    globus_mutex_lock(&handle->server->mutex);
    {
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
    globus_mutex_unlock(&handle->server->mutex);
}

globus_result_t
globus_gsc_959_intermediate_reply(
    globus_gsc_op_959_t *                           op,
    char *                                          reply_msg)
{
    globus_l_gsc_959_reply_ent_t *                  reply_ent;
    globus_l_gsc_959_handle_t *                     handle;
    globus_result_t                                 res;

    handle = op_959->handle;

    globus_mutex_lock(&handle->server->mutex);
    {
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
            handle->ref++;
            res = globus_l_gsc_959_intermediate_reply(
                        handle,
                        reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                handle->reply_outstanding = GLOBUS_FALSE;
                handle->ref--;
                globus_l_gsc_959_panic(handle);
            }
        }
    }
    globus_mutex_unlock(&handle->server->mutex);

    return res;
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
        handle->ref--;

        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_panic(handle);
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
                        globus_l_gsc_959_panic(handle);
                        break;
                    }
                    handle->ref++;
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                handle->state = GLOBUS_L_GSP_959_STATE_OPEN;
                globus_l_gsc_959_process_next_cmd(handle);
                break;

            case GLOBUS_L_GSP_959_STATE_PANIC_STOPPING:
            case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPING:
                if(handle->ref == 0)
                {
                    handle->state = GLOBUS_L_GSP_959_STATE_STOPPED;
                    if(handle->stop_cb != NULL)
                    {
                        GlobusL959RegisterStop(handle);
                    }
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

static globus_result_t
globus_l_gsc_959_final_reply(
    globus_l_gsc_959_handle_t *                     handle,
    const char *                                    message)
{
    globus_result_t                                 res;
    char *                                          tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_959_final_reply);

    globus_mutex_lock(&handle->server->mutex);
    {
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
        handle->ref++;
    }
    globus_mutex_unlock(&handle->server->mutex);

    return GLOBUS_SUCCESS;

  err:

    return res;
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
        handle->ref--;

        globus_assert(handle->ref != 0);

        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsc_959_panic(handle);
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
                handle->ref++;
                res = globus_l_gsc_959_intermediate_reply(
                            handle,
                            reply_ent->msg);
                if(res != GLOBUS_SUCCESS)
                {
                    handle->reply_outstanding = GLOBUS_FALSE;
                    handle->ref--;
                    globus_l_gsc_959_panic(handle);
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
    handle->ref++;

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gsc_959_command_add(
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
globus_gsc_959_get_help(
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
