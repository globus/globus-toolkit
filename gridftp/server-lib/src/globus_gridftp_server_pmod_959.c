#include "globus_i_gridftp_server.h"
#include "globus_gridftp_server_pmod_959.h"

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
 *  that can be put into "super mode" (gssapi_ftp driveri or _______).
 *  This mode gaurentees that each read callback will contain a 
 *  complete command.
 *
 *  On activate a table of commands is built.  This table can be index
 *  by the command name string.  Each entry in the table contains an
 *  integer representation of the command type (for faster decisions)
 *  and a parse function.  Typically each parse function services multiple
 *  command types, they check the command to verify that all needed 
 *  parameters were sent (and not too many) then it uses the integer
 *  command code to decide what to do with this command.
 *
 *  In most cases when a command is received it maps directly to a single
 *  server library function call.  The server functions take a callback
 *  to be executed upon completion.  When that callback is called this 
 *  protocol module replys to the command and processes the next command
 *  in the read queue, if no command is present processing suspends until
 *  one comes in.
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
 *  A situation may occur where the protocol module needs to initiate
 *  a close.  This typically happens in the case of an error.  The
 *  protocol module can then call  globus_i_gsp_error_occured().  This
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
                globus_l_gsp_959_stop_kickout,                          \
                (void *)handle,                                         \
                GLOBUS_CALLBACK_GLOBAL_SPACE);                          \
    globus_assert(_res == GLOBUS_SUCCESS); /* don't do this */          \
} while(0)

/*************************************************************************
 *              typedefs
 *
 ************************************************************************/

typedef enum globus_l_gsp_959_state_e
{
    GLOBUS_L_GSP_959_STATE_OPEN,
    GLOBUS_L_GSP_959_STATE_PROCESSING,
    GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING,
    GLOBUS_L_GSP_959_STATE_ABORTING,
    GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING,
    GLOBUS_L_GSP_959_STATE_STOPPING,
    GLOBUS_L_GSP_959_STATE_STOPPED,
    GLOBUS_L_GSP_959_STATE_PANIC,
    GLOBUS_L_GSP_959_STATE_PANIC_STOPPING,
} globus_l_gsp_state_t;

/*
 *  command types
 *  -------------
 *  Each command is mapped to an enum via the hastable
 */
enum
{
    GLOBUS_L_GSP_959_ABOR,
    GLOBUS_L_GSP_959_CDUP,
    GLOBUS_L_GSP_959_CWD,
    GLOBUS_L_GSP_959_DELE,
    GLOBUS_L_GSP_959_FEAT,
    GLOBUS_L_GSP_959_HELP,
    GLOBUS_L_GSP_959_LIST,
    GLOBUS_L_GSP_959_MKD,
    GLOBUS_L_GSP_959_MODE,
    GLOBUS_L_GSP_959_NLST,
    GLOBUS_L_GSP_959_NOOP,
    GLOBUS_L_GSP_959_PASS,
    GLOBUS_L_GSP_959_PASV,
    GLOBUS_L_GSP_959_PWD,
    GLOBUS_L_GSP_959_QUIT,
    GLOBUS_L_GSP_959_RETR,
    GLOBUS_L_GSP_959_RMD,
    GLOBUS_L_GSP_959_SITE,
    GLOBUS_L_GSP_959_SIZE,
    GLOBUS_L_GSP_959_SPAS,
    GLOBUS_L_GSP_959_STAT,
    GLOBUS_L_GSP_959_STOR,
    GLOBUS_L_GSP_959_STOU,
    GLOBUS_L_GSP_959_SYST,
    GLOBUS_L_GSP_959_TYPE,
    GLOBUS_L_GSP_959_USER,
};

typedef struct globus_l_gsp_959_handle_s 
{
    globus_gridftp_server_t                 server;
    globus_xio_handle_t                     xio_handle;
    globus_mutex_t                          mutex;
    globus_l_gsp_state_t                    state;
    int                                     ref;
    globus_fifo_t                           read_q;
    int                                     abort_cnt;
    globus_gridftp_server_stop_cb_t         stop_cb; 
} globus_l_gsp_959_handle_t;

typedef struct globus_l_gsp_959_cmd_ent_s
{
    int                                     cmd;
    char                                    cmd_name[16]; /* only 5 needed */
    globus_gs_pmod_959_command_func_t       cmd_func;
    globus_gs_pmod_959_reply_format_func_t  format_func;
    void *                                  user_arg;
} globus_l_gsp_959_cmd_ent_t;

typedef struct globus_l_gsp_959_read_ent_s
{
    globus_l_gsp_959_handle_t *             handle;
    globus_l_gsp_959_cmd_ent_t *            cmd_ent;
    char *                                  command;
} globus_l_gsp_959_read_ent_t;

/*************************************************************************
 *              functions prototypes
 *
 ************************************************************************/
globus_l_gsp_959_handle_t *
globus_l_gsp_959_handle_create();

void
globus_l_gsp_959_handle_destroy(
    globus_l_gsp_959_handle_t *             handle);

static globus_result_t
globus_l_gsp_959_reply(
    globus_l_gsp_959_handle_t *             handle,
    int                                     code,
    const char *                            message);

/*************************************************************************
 *              globals
 *
 ************************************************************************/
static globus_hashtable_t                   globus_l_gsp_959_command_table;
static globus_byte_t *                      globus_l_gsp_959_fake_buffer 
    = (globus_byte_t *) 0x1;
static globus_size_t                        globus_l_gsp_959_fake_buffer_len 
    = 1;

/************************************************************************
 *                         utility functions
 *                         -----------------
 *
 ***********************************************************************/
globus_l_gsp_959_handle_t *
globus_l_gsp_959_handle_create()
{
    globus_l_gsp_959_handle_t *             handle;

    handle = (globus_l_gsp_959_handle_t *)
        globus_malloc(sizeof(globus_l_gsp_959_handle_t));
    if(handle == NULL)
    {
        return NULL;
    }
    globus_mutex_init(&handle->mutex, NULL);
    handle->ref = 1; /* i for start call and 1 for read about to post */
    handle->state = GLOBUS_L_GSP_959_STATE_OPEN;
    globus_fifo_init(&handle->read_q);

    return handle;
}

/*
 *  clean up a handle
 */
void
globus_l_gsp_959_handle_destroy(
    globus_l_gsp_959_handle_t *             handle)
{
    globus_assert(handle->ref == 0);
    globus_mutex_destroy(&handle->mutex);
    globus_fifo_destroy(&handle->read_q);
    globus_free(handle);
}

globus_l_gsp_959_read_ent_t *
globus_l_gsp_959_read_ent_create(
    globus_l_gsp_959_cmd_ent_t *            cmt_ent,
    char *                            	    buffer,
    globus_l_gsp_959_handle_t *             handle)
{
    globus_l_gsp_959_read_ent_t *           read_ent;

    read_ent = (globus_l_gsp_959_read_ent_t *)
        globus_malloc(sizeof(globus_l_gsp_959_read_ent_t));
    if(read_ent == NULL)
    {
        return NULL;
    }

    read_ent->cmd_ent = cmt_ent;
    read_ent->handle = handle;
    read_ent->command = buffer;

    return read_ent;
}

globus_result_t
globus_l_gsp_959_flush_reads(
    globus_l_gsp_959_handle_t *             handle,
    int                                     reply_code,
    const char *                            reply_msg)
{
    globus_result_t                         res;
    globus_result_t                         tmp_res;
    globus_l_gsp_959_read_ent_t *           read_ent;

    while(!globus_fifo_empty(&handle->read_q))
    {
        read_ent = (globus_l_gsp_959_read_ent_t *)
            globus_fifo_dequeue(&handle->read_q);

        handle->ref++;
        tmp_res = globus_l_gsp_959_reply(handle, reply_code, reply_msg);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            handle->ref--;
            res = tmp_res;
        }
        globus_assert(read_ent != NULL);
    }

    return res;
}

/*
 *  stop callback kickout
 */
void
globus_l_gsp_959_stop_kickout(
    void *                                  user_arg)
{
    globus_l_gsp_959_handle_t *             handle;

    handle = (globus_l_gsp_959_handle_t *) user_arg;

    handle->stop_cb(handle->server);

    globus_assert(handle->state == GLOBUS_L_GSP_959_STATE_STOPPED);
    globus_l_gsp_959_handle_destroy(handle);
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
globus_l_gsp_959_panic(
    globus_l_gsp_959_handle_t *             handle,
    globus_result_t                         res)
{
    GlobusGridFTPServerName(globus_l_gsp_959_panic);

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
            globus_l_gsp_959_flush_reads(
                handle,
                421,
                "Service not available, closing control connection.");
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

    globus_gridftp_server_pmod_done(handle->server, res);
}

void
globus_l_gsp_959_command_kickout(
    void *                                  user_arg)
{
    globus_l_gsp_959_read_ent_t *           read_ent;
    globus_result_t                         res;
    int                                     reply_code;
    char *                                  reply_msg;

    read_ent = (globus_l_gsp_959_read_ent_t *) user_arg;

    /*
     *  call out to the users command
     */
    res = read_ent->cmd_ent->cmd_func(
        read_ent->handle,
        read_ent,
        read_ent->command,
        read_ent->cmd_ent->user_arg);
    if(res != GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&read_ent->handle->mutex);
        {
            read_ent->cmd_ent->format_func(
                read_ent->handle,
                res,
                read_ent->cmd_ent->user_arg,
                &reply_code,
                &reply_msg);
            res = globus_l_gsp_959_reply(
                    read_ent->handle,
                    reply_code,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                read_ent->handle->ref--; /* CALLBACK RETURN ?? */
                globus_l_gsp_959_panic(read_ent->handle, res);
            }
            /* not much error checking here, we trust user to return a
                globus_free()able string */
            globus_free(reply_msg);
        }
        globus_mutex_unlock(&read_ent->handle->mutex);
    }
}

/*
 *  This pulls a command out of the read_q if there is one and processes
 *  it based on its type.  All callbacks for the commands are the same.
 *  This function should only be called in the PROCESSING state.
 */
void
globus_l_gsp_959_process_next_cmd(
    globus_l_gsp_959_handle_t *             handle)
{
    int                                     reply_code;
    char *                                  reply_msg;
    globus_result_t                         res;
    globus_l_gsp_959_read_ent_t *           read_ent;
    GlobusGridFTPServerName(globus_l_gsp_959_process_next_cmd);

    globus_assert(handle->state == GLOBUS_L_GSP_959_STATE_PROCESSING);

    if(!globus_fifo_empty(&handle->read_q))
    {
        read_ent = (globus_l_gsp_959_read_ent_t *)
            globus_fifo_dequeue(&handle->read_q);

        /* increment the reference, will be deced in reply_cb */
        handle->ref++; 

        res = globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_l_gsp_959_command_kickout,
            (void *) read_ent);

        /* this will never happen ever, but why not account for it anyway? */
        if(res != GLOBUS_SUCCESS)
        {
            read_ent->cmd_ent->format_func(
                handle,
                res,
                read_ent->cmd_ent->user_arg,
                &reply_code,
                &reply_msg);
            
            res = globus_l_gsp_959_reply(
                    handle,
                    reply_code,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                handle->ref--; /* if failed we will have no callback */
                globus_l_gsp_959_panic(handle, res);
            }

            /* not much error checking here, we trust user to return a
                globus_free()able string */
            globus_free(reply_msg);
        }
    }
}

/*
 *  since the authentication module is we are guarenteed 1 command
 *  per callback.
 */
static void
globus_l_gsp_959_read_callback(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_l_gsp_959_handle_t *             handle;
    globus_l_gsp_959_cmd_ent_t *            cmd_ent;
    globus_l_gsp_959_read_ent_t *           read_ent;
    /* largest know command is 4, but possible the user sent a huge one */
    char *                                  command_name;
    int                                     sc;
    GlobusGridFTPServerName(globus_l_gsp_959_read_callback);

    handle = (globus_l_gsp_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        /* decrement for read callback returning */
        handle->ref--;

        /*
         *  The panic function can deal with being called in panic mode
         */
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsp_959_panic(handle, result);
        }

        switch(handle->state)
        {
            case GLOBUS_L_GSP_959_STATE_OPEN:
            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                /*
                 *  parse out the command name
                 */
                command_name = (char *) globus_malloc(len);
                sc = sscanf(buffer, "%s", command_name);
                /* stack will make sure this never happens */
                globus_assert(sc > 0);

                /* calling pers function will likely result in a write being
                    post, the next read will be posted there. */
                cmd_ent = (globus_l_gsp_959_cmd_ent_t *) 
                            globus_hashtable_lookup(
                                &globus_l_gsp_959_command_table,
                                command_name);

                if(cmd_ent == GLOBUS_L_GSP_959_ABOR)
                {
                    /* if we are in the open state then there is no
                       outstanding operation to cancel and we can just
                       reply to the ABOR */
                    if(handle->state == GLOBUS_L_GSP_959_STATE_OPEN)
                    {
                        globus_assert(globus_fifo_empty(&handle->read_q));

                        handle->state = GLOBUS_L_GSP_959_STATE_PROCESSING;
                        handle->ref++;
                        res = globus_l_gsp_959_reply(
                                handle,
                                226,
                                "Abort successful");
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
                        res = globus_gridftp_server_pmod_command_cancel(
                                handle->server);
                    }
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsp_959_panic(handle, res);
                        globus_mutex_unlock(&handle->mutex);
                        goto exit;
                    }
                }
                else
                {
                    read_ent = globus_l_gsp_959_read_ent_create(
                        cmd_ent, buffer, handle);
                    if(read_ent == NULL)
                    {
                        globus_l_gsp_959_panic(handle, res);
                        globus_mutex_unlock(&handle->mutex);
                        goto exit;
                    }

                    globus_fifo_enqueue(&handle->read_q, read_ent);
                    if(handle->state == GLOBUS_L_GSP_959_STATE_OPEN)
                    {
                        globus_assert(globus_fifo_empty(&handle->read_q));
                        handle->state = GLOBUS_L_GSP_959_STATE_PROCESSING;
                        globus_l_gsp_959_process_next_cmd(handle);
                    }
                    /* allow outstanding commands, just queue them up */
                    res = globus_xio_register_read(
                            xio_handle,
                            globus_l_gsp_959_fake_buffer,
                            globus_l_gsp_959_fake_buffer_len,
                            1,
                            NULL,
                            globus_l_gsp_959_read_callback,
                            (void *) handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsp_959_panic(handle, res);
                        globus_mutex_unlock(&handle->mutex);
                        goto exit;
                    }
                    handle->ref++;
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
    globus_mutex_unlock(&handle->mutex);

  exit:

    return;
}

/***************************************************************************
 *
 **************************************************************************/

/************************************************************************
 *                         interface functions
 *                         -------------------
 *
 *  These are functions called from the server library to this protocol
 *  module.   globus_l_gsp_959_command_cb() is not technically an 
 *  interface function, but it is called only from the server library
 *  so it belongs in this category.
 ***********************************************************************/
/*
 *  start up the server by posting first read on the control channel.
 *  As commands come in the server library is notified of them.
 */
static globus_result_t
globus_l_gsp_959_start(
    globus_gridftp_server_t                 server,
    globus_xio_handle_t                     xio_handle,
    void **                                 user_arg)
{
    globus_result_t                         res;
    globus_l_gsp_959_handle_t *             handle;
    GlobusGridFTPServerName(globus_l_gsp_959_start);

    handle = globus_l_gsp_959_handle_create();

    if(handle == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("handle");
        goto err;
    }
    handle->xio_handle = xio_handle;
    handle->server = server;

    res = globus_xio_register_read(
            xio_handle,
            globus_l_gsp_959_fake_buffer,
            globus_l_gsp_959_fake_buffer_len,
            1,
            NULL,
            globus_l_gsp_959_read_callback,
            (void *) handle);
    if(res != GLOBUS_SUCCESS)
    {
        handle->ref--; /* didn't start reading */
        globus_l_gsp_959_handle_destroy(handle);
        goto err;
    }

    *user_arg = handle;

    return GLOBUS_SUCCESS;

  err:

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
globus_l_gsp_959_stop(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_stop_cb_t         cb,
    void *                                  user_arg)
{
    globus_l_gsp_959_handle_t *             handle;
    GlobusGridFTPServerName(globus_l_gsp_959_stop);

    handle = (globus_l_gsp_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
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
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;
}

void
globus_gs_pmod_959_finished_op(
    globus_gs_pmod_959_op_t                 op,
    globus_result_t                         result)
{
    int                                     reply_code;
    char *                                  reply_msg;
    globus_l_gsp_959_read_ent_t *           read_ent;
    globus_l_gsp_959_handle_t *             handle;
    globus_result_t                         res;
    globus_bool_t                           stopping = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_gs_pmod_959_finished_op);

    if(op == NULL)
    {

    }

    read_ent = (globus_l_gsp_959_read_ent_t *) op;
    handle = read_ent->handle;

    read_ent->cmd_ent->format_func(
        handle, result, read_ent->cmd_ent->user_arg, &reply_code, &reply_msg);

    globus_mutex_lock(&handle->mutex);
    {
        handle->ref--;
        switch(handle->state)
        {
            /* after receiving the servers reply to the abor we 
               clear everything in the Q and respond */
            case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
                stopping = GLOBUS_TRUE;
            case GLOBUS_L_GSP_959_STATE_ABORTING:
                handle->abort_cnt = globus_fifo_size(&handle->read_q);
                handle->abort_cnt += 2;

                /* reply to the outstanding message */
                handle->ref++;
                res = globus_l_gsp_959_reply(
                        handle,
                        reply_code,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    handle->ref--;
                    globus_l_gsp_959_panic(handle, res);
                    break;
                }
                res = globus_l_gsp_959_flush_reads(
                        handle,
                        426,
                        "Command Aborted");
                if(res != GLOBUS_SUCCESS)
                {
                    globus_l_gsp_959_panic(handle, res);
                    break;
                }
                handle->ref++;
                res = globus_l_gsp_959_reply(
                        handle,
                        226,
                        "Abort successful");
                if(res != GLOBUS_SUCCESS)
                {
                    handle->ref--;
                    globus_l_gsp_959_panic(handle, res);
                    break;
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                handle->ref++;
                res = globus_l_gsp_959_reply(
                        handle,
                        reply_code,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    handle->ref--;
                    globus_l_gsp_959_panic(handle, res);
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING_STOPPING:
                stopping = GLOBUS_TRUE;
                /* attempt to register replys, if the fail the ref count
                   will not be incremented, so as long as we check for that
                   going to zero we can ignore the return code of the
                   reply() */
                handle->ref++;
                res = globus_l_gsp_959_reply(
                        handle,
                        reply_code,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    handle->ref--;
                    globus_l_gsp_959_panic(handle, res);
                    break;
                }
                res = globus_l_gsp_959_flush_reads(
                        handle,
                        421,
                        "Service not available, closing control connection.");
                if(res != GLOBUS_SUCCESS)
                {
                    globus_l_gsp_959_panic(handle, res);
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
    }
    globus_mutex_unlock(&handle->mutex);
}

/*
 *  callback for replies
 */
static void 
globus_l_gsp_959_reply_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_xio_iovec_t *                    iovec,
    int                                     count,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res;
    globus_l_gsp_959_handle_t *             handle;
    GlobusGridFTPServerName(globus_l_gsp_959_reply_cb);

    globus_free(iovec[0].iov_base);
    globus_free(iovec[1].iov_base);
    globus_free(iovec);

    handle = (globus_l_gsp_959_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        handle->ref--;

        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gsp_959_panic(handle, result);
            globus_mutex_unlock(&handle->mutex);
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
                            globus_l_gsp_959_fake_buffer,
                            globus_l_gsp_959_fake_buffer_len,
                            1,
                            NULL,
                            globus_l_gsp_959_read_callback,
                            (void *) handle);
                    if(res != GLOBUS_SUCCESS)
                    {
                        globus_l_gsp_959_panic(handle, result);
                        break;
                    }
                    handle->ref++;
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                handle->state = GLOBUS_L_GSP_959_STATE_OPEN;
                globus_l_gsp_959_process_next_cmd(handle);
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

            case GLOBUS_L_GSP_959_STATE_OPEN:
            case GLOBUS_L_GSP_959_STATE_STOPPED:
            default:
                globus_assert(0 && "should never reach this state");
                break;
        }
    }
    globus_mutex_unlock(&handle->mutex);
}

static globus_result_t
globus_l_gsp_959_reply(
    globus_l_gsp_959_handle_t *             handle,
    int                                     code,
    const char *                            message)
{
    globus_result_t                         res;
    char *                                  code_str;
    globus_xio_iovec_t *                    iov;
    GlobusGridFTPServerName(globus_l_gsp_959_reply);

    globus_mutex_lock(&handle->mutex);
    {
        /*TODO: check state */
        code_str = (char *) globus_malloc(40);
        if(code_str == NULL)
        {
            globus_mutex_unlock(&handle->mutex);
            res = GlobusGridFTPServerErrorMemory("code_str");
            goto err;
        }
        iov = (globus_xio_iovec_t *) 
            globus_malloc(sizeof(globus_xio_iovec_t) * 2);
        if(iov == NULL)
        {
            globus_mutex_unlock(&handle->mutex);
            res = GlobusGridFTPServerErrorMemory("iov");
            globus_free(code_str);
            goto err;
        }
        iov[0].iov_base = (globus_byte_t *) code_str;
        iov[0].iov_len = strlen(code_str);
        iov[1].iov_len = strlen(message);
        iov[1].iov_base = globus_malloc(iov[1].iov_len + 2);
        strcpy((char *)iov[1].iov_len, message);
        strcat((char *)iov[1].iov_len, "\r\n");
        sprintf(code_str, "%d", code);
        res = globus_xio_register_writev(
                handle->xio_handle,
                iov,
                2,
                iov[0].iov_len + iov[1].iov_len, /* wait for everything */
                NULL,
                globus_l_gsp_959_reply_cb,
                handle);
        if(res != GLOBUS_SUCCESS)
        {
            globus_mutex_unlock(&handle->mutex);
            goto err;
        }
        handle->ref++;
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

  err:

    return res;
}


/************************************************************************
 *                        command functions
 *                        -----------------
 *
 ***********************************************************************/
globus_result_t
globus_l_gsp_959_parse_port(
    globus_gridftp_server_t                 server,
    int                                     cmd,
    const char *                            command)
{
    int                                     count = 0;
    int                                     ctr;
    int                                     sc;
    unsigned int                            h_p[6];
    char *                                  tmp_ptr;
    globus_result_t                         res;

    /* skip past inital spaces and command name */
    tmp_ptr = (char *) command;
    /* skip any leading spaces */
    while(isspace(*tmp_ptr)) tmp_ptr++;
    /* skip the first command */
    while(!isspace(*tmp_ptr)) tmp_ptr++;
    /* skip sspaces until next start */
    while(isspace(*tmp_ptr)) tmp_ptr++;

    while(*tmp_ptr != '\0')
    {
        sc = sscanf(tmp_ptr, "%u,%u,%u,%u,%u,%u",
                &h_p[0],
                &h_p[1],
                &h_p[2],
                &h_p[3],
                &h_p[4],
                &h_p[5]);
        if(sc < 6)
        {
            goto err;
        }
        for(ctr = 0; ctr < 6; ctr++)
        {
            if(h_p[ctr] > 255)
            {
                goto err;
            }
        }
        /* skip the current port */
        while(*tmp_ptr != '\0' && !isspace(*tmp_ptr)) tmp_ptr++;
        /* skip spaces until next start */
        while(*tmp_ptr != '\0' && isspace(*tmp_ptr)) tmp_ptr++;
        count++;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}


/* 
 *  set up the command table.
 */
static globus_result_t
globus_l_gsp_959_init()
{
    return GLOBUS_SUCCESS;
};

static globus_result_t
globus_l_gsp_959_destroy()
{
    return GLOBUS_SUCCESS;
}

globus_i_gridftp_server_pmod_t              globus_i_gsp_959_proto_mod =
{
    globus_l_gsp_959_init,
    globus_l_gsp_959_destroy,
    globus_l_gsp_959_start,
    globus_l_gsp_959_stop
};
