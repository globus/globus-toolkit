#include "globus_i_gridftp_server_control.h"
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include "version.h"


#define GSC_MAX_COMMAND_NAME_LEN        4
#define GLOBUS_L_GSC_DEFAULT_220   "GridFTP Server.\n"

#define GlobusLRegisterDone(_h)                                         \
do                                                                      \
{                                                                       \
    globus_result_t                         _res;                       \
                                                                        \
   GlobusGSDebugPrintf(                                                 \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_WARNING,                    \
        ("[%s] ### Register done \n", _gridftp_server_name));           \
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
    int                                 cmd;
    char *                              cmd_name;
    globus_gsc_959_command_cb_t         cmd_cb;
    globus_gsc_959_command_desc_t       desc;
    char *                              help;
    void *                              user_arg;
    int                                 max_argc;
    int                                 min_argc;
} globus_l_gsc_cmd_ent_t;

typedef struct globus_l_gsc_reply_ent_s
{
    char *                              msg;
    globus_bool_t                       final;
    globus_i_gsc_op_t *                 op;
} globus_l_gsc_reply_ent_t;

/*************************************************************************
 *              functions prototypes
 *
 ************************************************************************/

static void
globus_l_gsc_process_next_cmd(
    globus_i_gsc_server_handle_t *      server_handle);

static globus_result_t
globus_l_gsc_final_reply(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        message);

static void
globus_l_gsc_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);

static void
globus_l_gsc_user_close_kickout(
    void *                              user_arg);

static globus_result_t
globus_l_gsc_intermediate_reply(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        message);

static void
globus_l_gsc_finished_op(
    globus_i_gsc_op_t *                 op,
    char *                              reply_msg);

static void
globus_l_gsc_internal_cb_kickout(
    void *                              user_arg);

static globus_result_t
globus_l_gsc_flush_reads(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        reply_msg);

static void
globus_l_gsc_server_ref_check(
    globus_i_gsc_server_handle_t *      server_handle);

static void
globus_l_gsc_command_callout(
    void *                              user_arg);

static void 
globus_l_gsc_free_command_array(
    char **                             cmd_a);
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
static globus_byte_t                    globus_l_gsc_fake_buffer[1];
static globus_size_t                    globus_l_gsc_fake_buffer_len = 1;

static globus_gridftp_server_control_attr_t globus_l_gsc_default_attr;
static globus_xio_driver_t              globus_l_gsc_tcp_driver;
static globus_xio_driver_t              globus_l_gsc_gssapi_ftp_driver;
static globus_xio_driver_t              globus_l_gsc_telnet_driver;
static globus_xio_driver_t              globus_l_gsc_queue_driver;

GlobusDebugDefine(GLOBUS_GRIDFTP_SERVER_CONTROL);

static int
globus_l_gsc_activate()
{
    int                                 rc = 0;
    globus_result_t                     res;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != 0)
    {
        return rc;
    }

    res = globus_xio_driver_load("gssapi_ftp", &globus_l_gsc_gssapi_ftp_driver);
    if(res != GLOBUS_SUCCESS)
    {
        return GLOBUS_FAILURE;
    }
    res = globus_xio_driver_load("telnet", &globus_l_gsc_telnet_driver);
    if(res != GLOBUS_SUCCESS)
    {
        return GLOBUS_FAILURE;
    }
    res = globus_xio_driver_load("tcp", &globus_l_gsc_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
        return GLOBUS_FAILURE;
    }
    res = globus_xio_driver_load("queue", &globus_l_gsc_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
        return GLOBUS_FAILURE;
    }

    GlobusDebugInit(GLOBUS_GRIDFTP_SERVER_CONTROL,
        ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);

    /* add all the default command handlers */
    globus_gridftp_server_control_attr_init(&globus_l_gsc_default_attr);

    return rc;
}

static int
globus_l_gsc_deactivate()
{
    int                                 rc;

    globus_gridftp_server_control_attr_destroy(globus_l_gsc_default_attr);

    globus_xio_driver_unload(globus_l_gsc_tcp_driver);
    globus_xio_driver_unload(globus_l_gsc_telnet_driver);
    globus_xio_driver_unload(globus_l_gsc_gssapi_ftp_driver);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);

    return rc;
}

/*
 *  module
 */
globus_module_descriptor_t              globus_i_gsc_module =
{
    "globus_gridftp_server_control",
    globus_l_gsc_activate,
    globus_l_gsc_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 *  timeout for all operations
 */
static globus_bool_t
globus_l_gsc_timeout_cb(
    globus_xio_handle_t                 handle,
    globus_xio_operation_type_t         type,
    void *                              user_arg)
{
    int                                 rc;
    globus_i_gsc_server_handle_t *      server_handle;

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_mutex_lock(&server_handle->mutex);
    {
        if(server_handle->outstanding_op != NULL)
        {
            rc = GLOBUS_FALSE;
        }
        else
        {
            globus_l_gsc_final_reply(server_handle, 
                "421 Idle Timeout: closing control connection.\r\n");
            rc = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    return rc;
}

static globus_i_gsc_op_t *
globus_l_gsc_op_create(
    globus_list_t *                     cmd_list,
    const char *                        command,
    int                                 len,
    globus_i_gsc_server_handle_t *      server_handle)
{
    globus_i_gsc_op_t *                 op;

    op = (globus_i_gsc_op_t *) globus_calloc(1, sizeof(globus_i_gsc_op_t));
    if(op == NULL)
    {
        return NULL;
    }
    op->command = globus_libc_malloc(len + 1);
    if(op->command == NULL)
    {
        globus_free(op);
        return NULL;
    }
    memcpy(op->command, command, len);
    op->command[len] = '\0';

    server_handle->ref++;

    op->server_handle = server_handle;
    op->response_type = GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS;
    op->cmd_list = globus_list_concat(server_handle->all_cmd_list, cmd_list);
    op->ref = 1;

    op->uid = -1;
    globus_range_list_init(&op->perf_range_list);

    return op;
}

void
globus_i_gsc_op_destroy(
    globus_i_gsc_op_t *                 op)
{
    int                                 ctr;

    op->ref--;
    if(op->ref == 0)
    {
        if(op->username != NULL)
        {
            globus_free(op->username);
        }
        if(op->password != NULL)
        {
            globus_free(op->password);
        }
        if(op->path != NULL)
        {
            globus_free(op->path);
        }
        if(op->mod_name != NULL)
        {
            globus_free(op->mod_name);
        }
        if(op->mod_parms != NULL)
        {
            globus_free(op->mod_parms);
        }
        if(op->cs != NULL)
        {
            for(ctr = 0; op->cs[ctr] != NULL; ctr++)
            {
                globus_free(op->cs[ctr]);
            }
            globus_free(op->cs);
        }
        globus_free(op->command);
        if(op->response_msg != NULL)
        {
            globus_free(op->response_msg);
        }

        op->server_handle->ref--;
        globus_l_gsc_server_ref_check(op->server_handle);
        globus_range_list_destroy(op->perf_range_list);

        globus_free(op);
    }
}

void
globus_i_gsc_log(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        command,
    int                                 mask)
{
    if(mask & server_handle->funcs.log_mask)
    {
        server_handle->funcs.log_func(
            server_handle, command, mask, server_handle->funcs.log_arg);
    }
}

/************************************************************************
 *                      state machine functions
 *                      -----------------------
 *
 ***********************************************************************/

/*
 *  Read Callback
 *  -------------
 *  Every time a command comes in this function is called.  
 *
 *  Reads are continually posted and queued.  The reason for this is
 *  the ABOR case.  Since an ABOR is read as oobinline we must have
 *  a read posted while a command is being process.  This leads to
 *  the possibility of commands other than ABOR being read while a 
 *  preceding command is being processed, the solution to this is to
 *  constantly read and queue all commands.
 *
 *  states
 *      on error simply call terminate
 *
 *      OPEN : 
 *          read and queue the command.  If the command is ABOR reply
 *          imediatly and post another read, else start processing
 *          the next command in the queue
 *
 *      PROCESSING : 
 *          simply queue the command and post another read.  if the command
 *          is ABOR, change to ABORTING STATE and call the users abort 
 *          callback.
 *
 *      STOPPING/ABORTING_STOPPING:
 *          happens when a command is successful read and this callback
 *          is waiting for the lock just as the state is changed to stopping
 *          in this case we decrement the reference count and check to
 *          see if we are done.
 *
 *      ABORTING/STOPPED/OPENING: should never happen
 *
 */
static void
globus_l_gsc_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    char *                              tmp_ptr;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_gsc_server_handle_t *      server_handle;
    globus_list_t *                     cmd_list;
    globus_i_gsc_op_t *                 op;
    char *                              command_name = NULL;
    int                                 ctr;
    GlobusGridFTPServerName(globus_l_gsc_read_cb);

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    globus_mutex_lock(&server_handle->mutex);
    {
        switch(server_handle->state)
        {
            /* OPEN: add command to the queue, it will be imediatly processed */
            case GLOBUS_L_GSC_STATE_OPEN:
            /* PROCESSING process the head of the queue */
            case GLOBUS_L_GSC_STATE_PROCESSING:
                /*  parse out the command name */
                command_name = (char *) globus_malloc(len + 1);
                for(ctr = 0, tmp_ptr = buffer; 
                    *tmp_ptr != ' ' && *tmp_ptr != '\r'; 
                    tmp_ptr++, ctr++)
                {
                    command_name[ctr] = toupper(*tmp_ptr);
                }
                command_name[ctr] = '\0';

                /* if not an abort */
                if(strcmp(command_name, "ABOR") != 0)
                {
                    cmd_list = (globus_list_t *) globus_hashtable_lookup(
                        &server_handle->cmd_table, command_name);
                    op = globus_l_gsc_op_create(
                        cmd_list, buffer, len, server_handle);
                    if(op == NULL)
                    {
                        res = GlobusGridFTPServerControlErrorSytem();
                        goto err_unlock;
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
                        goto err_unlock;
                    }
                }
                else
                {
                    if(server_handle->state == GLOBUS_L_GSC_STATE_OPEN)
                    {
                        /* for final reply use the ref on the read cb */
                        server_handle->state=GLOBUS_L_GSC_STATE_PROCESSING;
                        res = globus_l_gsc_final_reply(
                            server_handle,
                            "226 Abort successful\r\n");
                        if(res != GLOBUS_SUCCESS)
                        {
                            goto err_unlock;
                        }
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
                            goto err_unlock;
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

                        server_handle->outstanding_op->aborted = GLOBUS_TRUE;
                        if(server_handle->outstanding_op->event.event_mask &
                            GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT)
                        {
                            server_handle->outstanding_op->event.user_cb(
                                server_handle->outstanding_op,
                                GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT,
                                server_handle->outstanding_op->event.user_arg);
                            server_handle->outstanding_op->aborted = 
                                GLOBUS_FALSE;
                        }
                    }
                }

                globus_free(command_name);
                break;

            case GLOBUS_L_GSC_STATE_STOPPING:
            case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
                goto err_unlock;
                break;


            case GLOBUS_L_GSC_STATE_STOPPED:
            case GLOBUS_L_GSC_STATE_OPENING:
            case GLOBUS_L_GSC_STATE_ABORTING:
            default:
                globus_assert(0 && "invalid state, likely memory curroption");
                break;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    globus_free(buffer);
    return;

  err_unlock:
    globus_mutex_unlock(&server_handle->mutex);

  err:
    if(command_name != NULL)
    {
        globus_free(command_name);
    }
    server_handle->cached_res = res;
    server_handle->ref--;
    globus_i_gsc_terminate(server_handle);
    globus_l_gsc_server_ref_check(server_handle);
    globus_mutex_unlock(&server_handle->mutex);

    return;
}

/*
 *  stop the server
 *
 *   This is called in a few places.  It is called when a user decideds
 *   to terminate the conection via _stop(), when the command modules
 *   panic (typically due to being out of memory) or when an error 
 *   occurs on the client connection (typically due to it closing).
 *
 *   states:
 * 
 *   OPENING:
 *      Noting has really been done yet, there is possibly an outstanding
 *      open or an outstaning write.  cancel any open and write callbacks.
 *      the termination process will continue when these callback return
 *
 *   OPEN:
 *      There are no outstanidng commands so move to the stoping state,
 *      cancel the command read that is posted.  When the canceled read 
 *      returns the termination process will continue.  
 *
 *   PROCESSING:
 *      A command is outstanding so move to the ABORTING_STOPPING state,
 *      call the users abort callback.  When the finished op command returns
 *      the termination process will continue.  
 *      Flush any commands that have been read with an error.
 *
 *   ABORTING:
 *      Move to the ABORTING STOPING state and dec the reference the server
 *      has to itself.  when the command comes back it will finish the
 *      termination process.
 *
 *  ABORTING_STOPPING/STOPPING:
 *      Noting tobe done, it just means this function was called twice,
 *      which can happen due to a user calling _stop() then a callback
 *      returning with an error.
 */
void
globus_i_gsc_terminate(
    globus_i_gsc_server_handle_t *      server_handle)
{
    GlobusGridFTPServerName(globus_i_gsc_terminate);

    switch(server_handle->state)
    {
        case GLOBUS_L_GSC_STATE_OPENING:
            server_handle->state = GLOBUS_L_GSC_STATE_STOPPING;
            globus_assert(server_handle->ref == 0);
            globus_xio_handle_cancel_operations(
                server_handle->xio_handle,
                GLOBUS_XIO_CANCEL_OPEN | GLOBUS_XIO_CANCEL_WRITE);
            break;

        case GLOBUS_L_GSC_STATE_OPEN:
            server_handle->state = GLOBUS_L_GSC_STATE_STOPPING;
            /* ok to ignore result here */
            globus_xio_handle_cancel_operations(
                server_handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            break;

        case GLOBUS_L_GSC_STATE_PROCESSING:
            server_handle->state = GLOBUS_L_GSC_STATE_ABORTING_STOPPING;

            /* this doesn't feel right, may require a new state, but
               may effect every state, this works but if it trips anything
               else it should be reconsidered. */
            if(server_handle->outstanding_op != NULL)
            {
                server_handle->outstanding_op->aborted = GLOBUS_TRUE;
                if(server_handle->outstanding_op->event.event_mask &
                    GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT)
                {
                    server_handle->outstanding_op->event.user_cb(
                        server_handle->outstanding_op,
                        GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_ABORT,
                        server_handle->outstanding_op->event.user_arg);
                    server_handle->outstanding_op->aborted = GLOBUS_FALSE;
                }
            }
            /* ignore return code, we are stopping so it doesn' matter */
            globus_l_gsc_flush_reads(
                server_handle,
                "421 Service not available, closing control connection.\r\n");
            globus_xio_handle_cancel_operations(
                server_handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            break;

        case GLOBUS_L_GSC_STATE_ABORTING:
            server_handle->state = GLOBUS_L_GSC_STATE_ABORTING_STOPPING;
            break;

        /* these two cases can only happen if the server is stopped twice:
           ex: client quits, read callback returns with error, then user
               quits before getting the done callback.  
           In these cases there is nothing to be done. */
        case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
        case GLOBUS_L_GSC_STATE_STOPPING:
        case GLOBUS_L_GSC_STATE_STOPPED:
            break;

        /* no other states */
        default:
            globus_assert(0);
            break;
    }
}

/*
 *  this is ulmiately called when a command module finishes a command
 *
 *  states:
 * 
 *  PROCESSING:
 *      if the command is finished (reply_msg != NULL), then send the final
 *      reply else call the next in the chain.  The state will be changed
 *      when the final reply returns.
 * 
 *  ABORTING:
 *      flush the commands read q and send out the final abort message, if 
 *      final reply is successful another read will be posted.
 *
 *  ABORTING_STOPPING:
 *      move to the STOPPING state.  If reference is zero kickout done 
 *      callback
 *
 *  STOPPING:
 *      destroy th op, if the reference count is 0 close
 *
 *  OPENING/OPEN/STOPPED:
 *      invalid
 *
 *  on any error decrement the reference and check for 0
 */
static void
globus_l_gsc_finished_op(
    globus_i_gsc_op_t *                 op,
    char *                              reply_msg)
{
    globus_i_gsc_server_handle_t *      server_handle;
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_l_gsc_finished_op);

    server_handle = op->server_handle;

    switch(server_handle->state)
    {
        case GLOBUS_L_GSC_STATE_PROCESSING:
            if(reply_msg == NULL && op->cmd_list == NULL)
            {
                server_handle->outstanding_op = NULL;
                reply_msg = "500 Command not supported.\r\n";
            }
            if(reply_msg == NULL)
            {
                GlobusLGSCRegisterCmd(op);
            }
            else
            {
                server_handle->outstanding_op = NULL;
                globus_i_gsc_op_destroy(op);
                res = globus_l_gsc_final_reply(
                        server_handle,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    goto err;
                }
            }
            break;

        case GLOBUS_L_GSC_STATE_ABORTING:

            server_handle->outstanding_op = NULL;
            globus_i_gsc_op_destroy(op);
            if(reply_msg == NULL)
            {
                reply_msg = "426 Command Aborted.\r\n";
            }

            server_handle->abort_cnt = globus_fifo_size(&server_handle->read_q);
            server_handle->abort_cnt += 2;

            res = globus_l_gsc_final_reply(
                    server_handle,
                    reply_msg);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
            res = globus_l_gsc_flush_reads(
                    server_handle,
                    "426 Command Aborted.\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
            res = globus_l_gsc_final_reply(
                    server_handle,
                    "226 Abort successful\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
            break;

        case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
            server_handle->outstanding_op = NULL;
            server_handle->state = GLOBUS_L_GSC_STATE_STOPPING;
            globus_i_gsc_op_destroy(op);
            break;

        case GLOBUS_L_GSC_STATE_STOPPING:
            server_handle->outstanding_op = NULL;
            globus_i_gsc_op_destroy(op);
            server_handle->ref--;
            globus_l_gsc_server_ref_check(server_handle);
            break;

        case GLOBUS_L_GSC_STATE_OPENING:
        case GLOBUS_L_GSC_STATE_OPEN:
        case GLOBUS_L_GSC_STATE_STOPPED:
        default:
            globus_assert(0);
            break;
    }

    return;

  err:
    globus_i_gsc_terminate(server_handle);
    server_handle->ref--;
    globus_l_gsc_server_ref_check(server_handle);
}

/*
 *  part of the opening sequence.  first the open is posted, then
 *  the 220 is written before we move to the open start.  This callback
 *  is called once the 220 is written and if succesful moves things
 *  to the OPEN state.
 */
static void 
globus_l_gsc_220_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_i_gsc_server_handle_t *      server_handle;
    globus_xio_attr_t                   close_attr;
    GlobusGridFTPServerName(globus_l_gsc_220_write_cb);

    GlobusGridFTPServerDebugEnter();

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_free(buffer);
    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }
    globus_mutex_lock(&server_handle->mutex);
    {
        server_handle->state = GLOBUS_L_GSC_STATE_OPEN;
        /*  post a read on the fake buffers */
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
            goto err_unlock;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    GlobusGridFTPServerDebugExit();
    return;

  err_unlock:
    globus_mutex_unlock(&server_handle->mutex);

  err:

    globus_xio_attr_init(&close_attr);
    server_handle->ref--;
    globus_l_gsc_server_ref_check(server_handle);
    globus_mutex_unlock(&server_handle->mutex);
}

/*
 *  state:
 *  pretty easy case, if it fails, kick out the done callback, if
 *  it succeeds, register the 220 write, if the register fails, kickout
 *  the done callback.
 */
static void
globus_l_gsc_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_i_gsc_server_handle_t *      server_handle;
    char *                              msg;
    GlobusGridFTPServerName(globus_l_gsc_open_cb);

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_assert(server_handle->state == GLOBUS_L_GSC_STATE_OPENING);

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    msg = globus_i_gsc_string_to_959(220, server_handle->pre_auth_banner);
    globus_mutex_lock(&server_handle->mutex);
    {
        res = globus_xio_register_write(
            server_handle->xio_handle,
            msg,
            strlen(msg),
            strlen(msg),
            NULL,
            globus_l_gsc_220_write_cb,
            server_handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err_unlock;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    return;

  err_unlock:
    globus_mutex_unlock(&server_handle->mutex);
  err:
    server_handle->cached_res = res;
    server_handle->ref--;
    globus_l_gsc_server_ref_check(server_handle);
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
            res = result;
            goto err;
        }

        server_handle->ref--;
        switch(server_handle->state)
        {
            case GLOBUS_L_GSC_STATE_ABORTING:
                server_handle->outstanding_op = NULL;
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
                        server_handle->ref--;
                        globus_i_gsc_terminate(server_handle);
                    }
                    server_handle->state = GLOBUS_L_GSC_STATE_OPEN;
                }
                break;

            case GLOBUS_L_GSC_STATE_PROCESSING:
                server_handle->state = GLOBUS_L_GSC_STATE_OPEN;
                globus_l_gsc_process_next_cmd(server_handle);
                break;

            case GLOBUS_L_GSC_STATE_ABORTING_STOPPING:
            case GLOBUS_L_GSC_STATE_STOPPING:
                globus_l_gsc_server_ref_check(server_handle);
                break;

            case GLOBUS_L_GSC_STATE_OPEN:
            case GLOBUS_L_GSC_STATE_STOPPED:
            default:
                globus_assert(0 && "should never reach this state");
                break;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    return;

  err:

    globus_i_gsc_terminate(server_handle);
    globus_l_gsc_server_ref_check(server_handle);
    globus_mutex_unlock(&server_handle->mutex);
    return;
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
        server_handle->ref--;
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gsc_terminate(server_handle);
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
                    globus_i_gsc_terminate(server_handle);
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
globus_l_gsc_user_data_destroy_cb_kickout(
    void *                                  user_arg)
{
    globus_i_gsc_data_t *                   data_object;
    globus_i_gsc_server_handle_t *          server_handle;

    data_object = (globus_i_gsc_data_t *) user_arg;
    server_handle = data_object->server_handle;

    if(server_handle->funcs.data_destroy_cb != NULL)
    {
        server_handle->funcs.data_destroy_cb(
            data_object->user_handle, server_handle->funcs.data_destroy_arg);
    }
    globus_free(data_object);

    globus_mutex_lock(&server_handle->mutex);
    {
        server_handle->ref--;
        globus_l_gsc_server_ref_check(server_handle);
    }
    globus_mutex_unlock(&server_handle->mutex);
}

static void
globus_l_gsc_user_close_kickout(
    void *                                  user_arg)
{
    globus_i_gsc_server_handle_t *          server_handle;
    globus_gridftp_server_control_cb_t      done_cb = NULL;

    server_handle = (globus_i_gsc_server_handle_t *) user_arg;

    globus_mutex_lock(&server_handle->mutex);
    {
        globus_assert(server_handle->ref == 0);
        globus_assert(
            server_handle->state == GLOBUS_L_GSC_STATE_STOPPED);
        done_cb = server_handle->funcs.done_cb;
        server_handle->state = GLOBUS_L_GSC_STATE_NONE;
    }
    globus_mutex_unlock(&server_handle->mutex);

    if(server_handle->data_object != NULL)
    {
        if(server_handle->funcs.data_destroy_cb != NULL)
        {
            globus_l_gsc_user_data_destroy_cb_kickout(
                server_handle->data_object);
        }
        else
        {
            globus_free(server_handle->data_object);
        }
    }

    if(done_cb != NULL)
    {
        server_handle->funcs.done_cb(
            server_handle,
            server_handle->cached_res,
            server_handle->funcs.done_arg);
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
globus_bool_t
globus_i_guc_data_object_destroy(
    globus_i_gsc_server_handle_t *      server_handle)
{
    globus_bool_t                       rc = GLOBUS_FALSE;
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_i_guc_data_object_destroy);

    if(server_handle->data_object != NULL)
    {
        if(server_handle->funcs.data_destroy_cb != NULL)
        {
            server_handle->ref++;
            res = globus_callback_space_register_oneshot(
                NULL,
                NULL,
                globus_l_gsc_user_data_destroy_cb_kickout,
                (void *)server_handle->data_object,
                GLOBUS_CALLBACK_GLOBAL_SPACE);
            if(res != GLOBUS_SUCCESS)
            {
                globus_panic(&globus_i_gsc_module, res, "one shot failed.");
            }
            rc = GLOBUS_TRUE;
        }
        else
        {
            globus_free(server_handle->data_object);
        }
        server_handle->data_object = NULL;
    }

    return rc;
}

static void
globus_l_gsc_server_ref_check(
    globus_i_gsc_server_handle_t *      server_handle)
{
    globus_xio_attr_t                   close_attr;
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_l_gsc_server_ref_check);

    globus_assert(server_handle->state != GLOBUS_L_GSC_STATE_STOPPED);

    if(server_handle->ref == 0)
    {
        server_handle->state = GLOBUS_L_GSC_STATE_STOPPED;
        globus_xio_attr_init(&close_attr);
        globus_xio_attr_cntl(
            close_attr, NULL, GLOBUS_XIO_ATTR_CLOSE_NO_CANCEL);
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

static int
globus_l_gsc_parse_command(
    char *                              command,
    char ***                            out_cmd_a,
    int                                 argc)
{
    globus_size_t                       command_len;
    char *                              start_ptr;
    char *                              tmp_ptr;
    char **                             cmd_a = NULL;
    int                                 argc_ndx;
    int                                 ctr;
    int                                 ndx;
    globus_bool_t                       done = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_parse_command);

    *out_cmd_a = NULL;

    command_len = strlen(command);

    /* verify that it ends properly */
    if(command[command_len-1] != '\n' || command[command_len-2] != '\r')
    {
        return -1;
    }

    cmd_a = (char **) globus_calloc(1, sizeof(char *) * (argc+1));
    if(cmd_a == NULL)
    {
        return -1;
    }
    *out_cmd_a = cmd_a;

    /* parse out the first command name, move to upper and verify length */
    argc_ndx = 0;
    tmp_ptr = globus_malloc(GSC_MAX_COMMAND_NAME_LEN+1);
    cmd_a[0] = tmp_ptr;
    ctr = 0;
    for(start_ptr = command;*start_ptr!=' '&&*start_ptr!='\r';start_ptr++)
    {
        if(!isalpha(*start_ptr))
        {
            goto err;
        }
        if(ctr >= GSC_MAX_COMMAND_NAME_LEN)
        {
            goto err;
        }
        *tmp_ptr = toupper(*start_ptr);
        tmp_ptr++;
        ctr++;
    }
    *tmp_ptr = '\0';
    argc_ndx++;

    while(argc_ndx < argc && !done)
    {
        /* skip past all leading spaces */
        while(isspace(*start_ptr) && *start_ptr != '\r')
        {
            start_ptr++;
        }

        /* if we hit the end just return the count */
        if(*start_ptr == '\r')
        {
            cmd_a[argc_ndx] = NULL;
            return argc_ndx;
        }

        /* reserve room for the next parameter */
        cmd_a[argc_ndx] = globus_malloc(strlen(start_ptr));
        tmp_ptr = cmd_a[argc_ndx];
        /* move to the next blank, verify parameter is alpha numeric */
        for(ndx = 0; !isspace(start_ptr[ndx]) && start_ptr[ndx] != '\r'; ndx++)
        {
            *tmp_ptr = start_ptr[ndx];
            tmp_ptr++;
        }
        if(start_ptr[ndx] == '\r')
        {
            done = GLOBUS_TRUE;
        }
        else if(argc_ndx == argc-1)
        {
            /* copy in the rest of the command */
            while(start_ptr[ndx] != '\r')
            {
                *tmp_ptr = start_ptr[ndx];
                tmp_ptr++;
                ndx++;
            }
            done = GLOBUS_TRUE;
        }
        start_ptr += ndx;
        argc_ndx++;
        *tmp_ptr = '\0';
    }

    cmd_a[argc_ndx] = NULL;
    return argc_ndx;

  err:

    globus_l_gsc_free_command_array(cmd_a);

    return -1;
}

static void 
globus_l_gsc_free_command_array(
    char **                             cmd_a)
{
    int                                 ctr;

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
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        reply_msg)
{
    globus_result_t                     res;
    globus_result_t                     tmp_res;
    globus_i_gsc_op_t *                 op;

    while(!globus_fifo_empty(&server_handle->read_q))
    {
        op = (globus_i_gsc_op_t *)
            globus_fifo_dequeue(&server_handle->read_q);
        globus_assert(op != NULL);
        globus_i_gsc_op_destroy(op);

        tmp_res = globus_l_gsc_final_reply(server_handle, reply_msg);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            server_handle->ref--;
            res = tmp_res;
        }
    }

    return res;
}

char *
globus_i_gsc_concat_path(
    globus_i_gsc_server_handle_t *      i_server,
    const char *                        in_path)
{
    char *                              tmp_path;
    char *                              tmp_ptr;
    char *                              tmp_ptr2;

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
    const char *                        cs,
    globus_gridftp_server_control_network_protocol_t net_prt)
{
    int                                 sc;
    int                                 ctr;
    unsigned int                        ip[8];
    unsigned int                        port;
    char *                              host_str;

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
           port > 65535)
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

        /* verify that the string contains nothing but
         * hex digits, ':'. and '.'
         */
        for(ctr = 0; ctr < strlen(cs); ctr++)
        {
            if(cs[ctr] != ':' && cs[ctr] != '.' && !isxdigit(cs[ctr]))
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

static void
globus_l_gsc_cmd_site(
    globus_i_gsc_op_t *                 op,
    const char *                        full_command,
    char **                             cmd_a,
    int                                 argc,
    void *                              user_arg)
{
    char *                              tmp_ptr;
    
    /* to upper in the actual initial buffer */
    for(tmp_ptr = strstr(full_command, cmd_a[1]); tmp_ptr && *tmp_ptr && *tmp_ptr != ' '; tmp_ptr++)
    {
        *tmp_ptr = toupper(*tmp_ptr);
    }
    for(tmp_ptr = cmd_a[1]; tmp_ptr && *tmp_ptr && *tmp_ptr != ' '; tmp_ptr++)
    {
        *tmp_ptr = toupper(*tmp_ptr);
    }
    *tmp_ptr = '\0';
    
    globus_assert(op->cmd_list == NULL);

    op->cmd_list = (globus_list_t *) globus_hashtable_lookup(
        &op->server_handle->site_cmd_table, cmd_a[1]);
    GlobusLGSCRegisterCmd(op);
}

/*
 *  callout into the command code
 */
static void
globus_l_gsc_command_callout(
    void *                              user_arg)
{
    int                                 argc;
    globus_bool_t                       auth = GLOBUS_FALSE;
    char **                             cmd_array;
    char *                              msg;
    globus_result_t                     res;
    globus_l_gsc_cmd_ent_t *            cmd_ent;
    globus_bool_t                       done = GLOBUS_FALSE;
    globus_i_gsc_op_t *                 op;
    globus_gsc_959_command_cb_t         cmd_cb = NULL;
    globus_i_gsc_server_handle_t *      server_handle;

    op = (globus_i_gsc_op_t *) user_arg;

    server_handle = op->server_handle;
    globus_mutex_lock(&server_handle->mutex);
    {
        /* could have gone bad while waiting on this callback */
        if(server_handle->state != GLOBUS_L_GSC_STATE_PROCESSING)
        {
            globus_i_gsc_op_destroy(op);
            globus_l_gsc_server_ref_check(server_handle);
            globus_mutex_unlock(&server_handle->mutex);
            return;
        }

        auth = server_handle->authenticated;

        msg = "500 Invalid command.\r\n";
        while(!done)
        {
            /* if we ran out of commands before finishing tell the client
                the command does not exist */
            if(op->cmd_list == NULL)
            {
                /* log unknown */
                globus_i_gsc_log(server_handle, op->command, 
                    GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_ERROR);

                globus_i_gsc_op_destroy(op);
                res = globus_l_gsc_final_reply(server_handle, msg);
                done = GLOBUS_TRUE;
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
                    msg = "503 You are already logged in.\r\n";
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
                "501 Syntax error in parameters or arguments.\r\n");
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
        if(argc != -1)
        {
            globus_l_gsc_free_command_array(cmd_array);
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
globus_l_gsc_process_next_cmd(
    globus_i_gsc_server_handle_t *      server_handle)
{
    globus_i_gsc_op_t *                 op;
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

static globus_result_t
globus_l_gsc_final_reply(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        message)
{
    globus_result_t                     res;
    char *                              tmp_ptr;
    GlobusGridFTPServerName(globus_l_gsc_final_reply);

    globus_assert(globus_fifo_empty(&server_handle->reply_q));

    tmp_ptr = globus_libc_strdup(message);
    if(tmp_ptr == NULL)
    {
        res = GlobusGridFTPServerControlErrorSytem();
        goto err;
    }

    globus_i_gsc_log(
        server_handle, message, GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_REPLY);
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
        goto err;
    }
    server_handle->ref++;
    server_handle->reply_outstanding = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/*
 *  only called when an intermediate command is not outstanding
 */
static globus_result_t
globus_l_gsc_intermediate_reply(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        message)
{
    globus_size_t                       len;
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_l_gsc_intermediate_reply);

    /*TODO: check state */
    globus_i_gsc_log(
        server_handle, message, GLOBUS_GRIDFTP_SERVER_CONTROL_LOG_REPLY);

    len = strlen(message);
    res = globus_xio_register_write(
            server_handle->xio_handle,
            (globus_byte_t *)message,
            len,
            len,
            NULL,
            globus_l_gsc_intermediate_reply_cb,
            server_handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    server_handle->ref++;

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
    globus_gridftp_server_control_t *   server)
{
    globus_i_gsc_server_handle_t *      server_handle;
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_gridftp_server_control_init);

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    server_handle = (globus_i_gsc_server_handle_t *) globus_calloc(
        1, sizeof(globus_i_gsc_server_handle_t));
    if(server_handle == NULL)
    {
        res = GlobusGridFTPServerControlErrorSytem();
        goto err;
    }

    globus_mutex_init(&server_handle->mutex, NULL);

    server_handle->state = GLOBUS_L_GSC_STATE_NONE;
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
    
    globus_hashtable_init(
        &server_handle->site_cmd_table,
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
    globus_gridftp_server_control_t     server)
{
    globus_i_gsc_server_handle_t *      server_handle;
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_gridftp_server_control_destroy);

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    server_handle = (globus_i_gsc_server_handle_t *) server;
    if(server_handle->state != GLOBUS_L_GSC_STATE_NONE)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    if(server_handle->cwd != NULL)
    {
        globus_free(server_handle->cwd);
    }
    if(server_handle->modes != NULL)
    {
        globus_free(server_handle->modes);
    }
    if(server_handle->types != NULL)
    {
        globus_free(server_handle->types);
    }
    if(server_handle->pre_auth_banner != NULL)
    {
        globus_free(server_handle->pre_auth_banner);
    }
    if(server_handle->username != NULL)
    {
        globus_free(server_handle->username);
    }
    if(server_handle->dcau_subject != NULL)
    {
        globus_free(server_handle->dcau_subject);
    }

    globus_mutex_destroy(&server_handle->mutex);
    globus_hashtable_destroy(&server_handle->cmd_table);
    globus_hashtable_destroy(&server_handle->funcs.send_cb_table);
    globus_hashtable_destroy(&server_handle->funcs.recv_cb_table);
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
    globus_gridftp_server_control_t     server,
    globus_gridftp_server_control_attr_t attr,
    globus_xio_system_handle_t          system_handle,
    globus_gridftp_server_control_cb_t  done_cb,
    void *                              user_arg)
{
    globus_reltime_t                    delay;
    globus_result_t                     res;
    globus_i_gsc_server_handle_t *      server_handle;
    globus_i_gsc_attr_t *               i_attr;
    globus_xio_stack_t                  xio_stack;
    globus_xio_attr_t                   xio_attr;
    GlobusGridFTPServerName(globus_gridftp_server_control_start);

    GlobusGridFTPServerDebugEnter();

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }
    if(system_handle < 0)
    {
        res = GlobusGridFTPServerErrorParameter("system_handle");
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
    if(server_handle->state != GLOBUS_L_GSC_STATE_STOPPED &&
        server_handle->state != GLOBUS_L_GSC_STATE_NONE)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    res = globus_xio_stack_init(&xio_stack, GLOBUS_NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    res = globus_xio_stack_push_driver(xio_stack, globus_l_gsc_tcp_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    res = globus_xio_attr_init(&xio_attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    /* if gssapi might be used */
    if(i_attr->security & GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI)
    {
        res = globus_xio_attr_cntl(xio_attr, globus_l_gsc_gssapi_ftp_driver,
                GLOBUS_XIO_GSSAPI_ATTR_TYPE_FORCE_SERVER, GLOBUS_TRUE);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        res = globus_xio_stack_push_driver(
            xio_stack, globus_l_gsc_gssapi_ftp_driver);

        /* if we are allowing both types of security tell the driver
           about it */
        if(i_attr->security & GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE)
        {
            res = globus_xio_attr_cntl(
                xio_attr, globus_l_gsc_gssapi_ftp_driver,
                GLOBUS_XIO_GSSAPI_ATTR_TYPE_ALLOW_CLEAR, GLOBUS_TRUE);
        }
    }
    else
    {
        res = globus_xio_stack_push_driver(
            xio_stack, globus_l_gsc_telnet_driver);
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    res = globus_xio_stack_push_driver(
        xio_stack, globus_l_gsc_queue_driver);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    res = globus_xio_attr_cntl(xio_attr, globus_l_gsc_telnet_driver,
            GLOBUS_XIO_TELNET_FORCE_SERVER, GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    res = globus_xio_attr_cntl(xio_attr, globus_l_gsc_telnet_driver,
            GLOBUS_XIO_TELNET_BUFFER, GLOBUS_TRUE);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    res = globus_xio_attr_cntl(xio_attr, globus_l_gsc_tcp_driver,
        GLOBUS_XIO_TCP_SET_HANDLE, system_handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    res = globus_xio_handle_create(&server_handle->xio_handle, xio_stack);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    server_handle->security_type = i_attr->security;
    globus_xio_stack_destroy(xio_stack);
    server_handle->ref = 1;

    server_handle->funcs.default_send_cb = i_attr->funcs.default_send_cb;
    server_handle->funcs.default_send_arg = i_attr->funcs.default_send_arg;
    server_handle->funcs.default_recv_cb = i_attr->funcs.default_recv_cb;
    server_handle->funcs.default_recv_arg = i_attr->funcs.default_recv_arg;
    server_handle->funcs.auth_cb = i_attr->funcs.auth_cb;
    server_handle->funcs.auth_arg = i_attr->funcs.auth_arg;
    server_handle->funcs.passive_cb = i_attr->funcs.passive_cb;
    server_handle->funcs.passive_arg = i_attr->funcs.passive_arg;
    server_handle->funcs.active_cb = i_attr->funcs.active_cb;
    server_handle->funcs.active_arg = i_attr->funcs.active_arg;
    server_handle->funcs.data_destroy_cb = i_attr->funcs.data_destroy_cb;
    server_handle->funcs.data_destroy_arg = i_attr->funcs.data_destroy_arg;
    server_handle->funcs.list_cb = i_attr->funcs.list_cb;
    server_handle->funcs.list_arg = i_attr->funcs.list_arg;
    server_handle->funcs.resource_cb = i_attr->funcs.resource_cb;
    server_handle->funcs.resource_arg = i_attr->funcs.resource_arg;
    server_handle->funcs.log_func = i_attr->funcs.log_func;
    server_handle->funcs.log_arg = i_attr->funcs.log_arg;
    server_handle->funcs.log_mask = i_attr->funcs.log_mask;
    server_handle->funcs.done_cb = done_cb;

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
    server_handle->opts.restart_frequency = 5;
    server_handle->opts.receive_buf = -1;
    server_handle->opts.parallelism = 1;
    server_handle->opts.packet_size = -1;
    server_handle->opts.delayed_passive = GLOBUS_FALSE;
    server_handle->opts.passive_only = GLOBUS_FALSE;

    /* default state */
    server_handle->modes = globus_libc_strdup(i_attr->modes);
    server_handle->types = globus_libc_strdup(i_attr->types);
    server_handle->type = 'A';
    server_handle->mode = 'S';
    server_handle->prot = 'C';
    server_handle->dcau = 'N';

    if(i_attr->idle_timeout > 0)
    {
        GlobusTimeReltimeSet(delay, i_attr->idle_timeout, 0);
        globus_xio_attr_cntl(
            xio_attr,
            NULL,
            GLOBUS_XIO_ATTR_SET_TIMEOUT_ALL,
            globus_l_gsc_timeout_cb,
            &delay,
            server_handle);
    }
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

    globus_gsc_959_command_add(
        server_handle,
        "SITE",
        globus_l_gsc_cmd_site,
        GLOBUS_GSC_COMMAND_PRE_AUTH |
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        NULL,
        NULL);
    server_handle->funcs.done_arg = user_arg;

    globus_mutex_lock(&server_handle->mutex);
    {
        server_handle->state = GLOBUS_L_GSC_STATE_OPENING;
        res = globus_xio_register_open(
            server_handle->xio_handle, 
            NULL, 
            xio_attr,
            globus_l_gsc_open_cb,
            server_handle);
        globus_xio_attr_destroy(xio_attr);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err_unlock:
    globus_mutex_unlock(&server_handle->mutex);

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_stop(
    globus_gridftp_server_control_t     server)
{
    globus_i_gsc_server_handle_t *      server_handle;
    globus_result_t                     res;
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
        globus_i_gsc_terminate(server_handle);
    }
    globus_mutex_unlock(&server_handle->mutex);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/************************************************************************
 *          suport functions for built in commands
 *          --------------------------------------
 *
 ***********************************************************************/

globus_result_t
globus_i_gsc_command_panic(
    globus_i_gsc_op_t *                 op)
{
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_i_gsc_command_panic);

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->server_handle->state != GLOBUS_L_GSC_STATE_PROCESSING)
        {
            res = GlobusGridFTPServerErrorParameter("op");
            goto err;
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
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;

  err:

    globus_mutex_unlock(&op->server_handle->mutex);
    return res;
}


void
globus_gsc_959_finished_command(
    globus_i_gsc_op_t *                 op,
    char *                              reply_msg)
{
    globus_i_gsc_server_handle_t *      server_handle;
    globus_l_gsc_reply_ent_t *          reply_ent;
    GlobusGridFTPServerName(globus_gsc_finished_op);

    server_handle = op->server_handle;

    if(server_handle->reply_outstanding)
    {
        reply_ent = (globus_l_gsc_reply_ent_t *)
            globus_malloc(sizeof(globus_l_gsc_reply_ent_t));
        reply_ent->msg = globus_libc_strdup(reply_msg);
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
    globus_i_gsc_op_t *                 op,
    char *                              reply_msg)
{
    globus_l_gsc_reply_ent_t *          reply_ent;
    globus_i_gsc_server_handle_t *      server_handle;
    globus_result_t                     res = GLOBUS_SUCCESS;
    char *                              msg_cpy;
    GlobusGridFTPServerName(globus_i_gsc_intermediate_reply);

    server_handle = op->server_handle;

    if(server_handle->state != GLOBUS_L_GSC_STATE_PROCESSING)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    if(server_handle->reply_outstanding)
    {
        reply_ent = (globus_l_gsc_reply_ent_t *)
            globus_malloc(sizeof(globus_l_gsc_reply_ent_t));
        reply_ent->msg = globus_libc_strdup(reply_msg);
        globus_assert(reply_ent->msg != NULL); /* XXX do the right htings */
        reply_ent->op = op;
        reply_ent->final = GLOBUS_FALSE;

        globus_fifo_enqueue(&server_handle->reply_q, reply_ent);
    }
    else
    {
        msg_cpy = globus_libc_strdup(reply_msg);
        globus_assert(msg_cpy != NULL); /* XXX do the right htings */
        server_handle->reply_outstanding = GLOBUS_TRUE;
        res = globus_l_gsc_intermediate_reply(
                server_handle,
                msg_cpy);
        if(res != GLOBUS_SUCCESS)
        {
            server_handle->reply_outstanding = GLOBUS_FALSE;
            globus_i_gsc_terminate(server_handle);
        }
    }

    return res;
}

globus_result_t
globus_gsc_959_command_add(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        command_name,
    globus_gsc_959_command_cb_t         command_cb,
    globus_gsc_959_command_desc_t       desc,
    int                                 min_argc,
    int                                 max_argc,
    const char *                        help,
    void *                              user_arg)
{
    globus_list_t *                     list;
    globus_result_t                     res;
    globus_l_gsc_cmd_ent_t *            cmd_ent;
    char *                              cmd_name;
    char *                              tmp_ptr;
    GlobusGridFTPServerName(globus_gsc_command_add);

    cmd_ent = (globus_l_gsc_cmd_ent_t *)globus_malloc(
        sizeof(globus_l_gsc_cmd_ent_t));
    if(cmd_ent == NULL)
    {
        res = GlobusGridFTPServerControlErrorSytem();
        goto err;
    }

    cmd_ent->cmd_cb = command_cb;
    cmd_ent->desc = desc;
    cmd_ent->user_arg = user_arg;
    cmd_ent->help = globus_libc_strdup(help);
    cmd_ent->min_argc = min_argc;
    cmd_ent->max_argc = max_argc;
    if(command_name == NULL)
    {
        globus_list_insert(&server_handle->all_cmd_list, cmd_ent);
        cmd_ent->cmd_name = strdup("\0");
        return GLOBUS_SUCCESS;
    }

    cmd_ent->cmd_name = strdup(command_name);
    if(strncmp("SITE ", command_name, 5) == 0 && strlen(command_name) > 5)
    {
        tmp_ptr = (char *)&command_name[5]; 
        while(*tmp_ptr == ' ') tmp_ptr++;
        cmd_name = strdup(tmp_ptr);

        list = (globus_list_t *) globus_hashtable_remove(
            &server_handle->site_cmd_table, cmd_name);
        globus_list_insert(&list, cmd_ent);
        globus_hashtable_insert(
            &server_handle->site_cmd_table, cmd_name, list);
    }
    else
    {
        list = (globus_list_t *) globus_hashtable_remove(
            &server_handle->cmd_table, (char *)command_name);
        globus_list_insert(&list, cmd_ent);
        globus_hashtable_insert(
            &server_handle->cmd_table, (char *)command_name, list);
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

char *
globus_i_gsc_get_help(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        command_name)
{
    globus_list_t *                     list;
    globus_list_t *                     site_list;
    globus_l_gsc_cmd_ent_t *            cmd_ent;
    char *                              help_str;
    char *                              tmp_ptr;
    int                                 cmd_ctr;
    int                                 sc;
    char                                cmd_name[5];

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
            sc = snprintf(cmd_name, 5, "%s", cmd_ent->cmd_name);
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
        /* XXX site specific stuff */
        if(strcmp(command_name, "SITE") == 0)
        {
            globus_hashtable_to_list(
                &server_handle->site_cmd_table, &site_list);
            help_str = globus_common_create_string(
                "214-Help for %s:\r\n", command_name);
            while(!globus_list_empty(site_list))
            {
                list = (globus_list_t *) globus_list_first(site_list);

                while(!globus_list_empty(list))
                {
                    cmd_ent = (globus_l_gsc_cmd_ent_t *) 
                        globus_list_first(list);
                    if(cmd_ent->help != NULL)
                    {
                        tmp_ptr = globus_common_create_string(
                            "%s %s\r\n", help_str, cmd_ent->help);
                        globus_free(help_str);
                        help_str = tmp_ptr;
                    }
                    list = globus_list_rest(list);
                }
                site_list = globus_list_rest(site_list);
            }
            tmp_ptr = globus_common_create_string("%s214 End.\r\n", help_str);
            globus_free(help_str);

            return tmp_ptr;
        }
        else
        {
            list = (globus_list_t *) globus_hashtable_lookup(
                &server_handle->cmd_table, (char *)command_name);
            if(list == NULL)
            {
                return globus_common_create_string(
                    "502 Unknown command '%s'.\r\n", command_name);
            }

            help_str = globus_common_create_string(
                "214-Help for %s:\r\n", command_name);
            while(!globus_list_empty(list))
            {
                cmd_ent = (globus_l_gsc_cmd_ent_t *) globus_list_first(list);
                if(cmd_ent->help != NULL)
                {
                    tmp_ptr = globus_common_create_string(
                        "%s %s\r\n", help_str, cmd_ent->help);
                    globus_free(help_str);
                    help_str = tmp_ptr;
                }
                list = globus_list_rest(list);
            }
            tmp_ptr = globus_common_create_string("%s214 End.\r\n", help_str);
            globus_free(help_str);

            return tmp_ptr;
        }
    }

    return NULL;
}

char *
globus_i_gsc_string_to_959(
    int                                 code,
    const char *                        in_str)
{
    globus_bool_t                       done = GLOBUS_FALSE;
    char *                              msg;
    char *                              tmp_ptr;
    char *                              start_ptr;
    char *                              end_ptr;
    int                                 ctr = 0;

    if(in_str == NULL)
    {
        msg = globus_common_create_string("%d .\r\n", code);
    }
    else
    {
        start_ptr = strdup(in_str);
        msg = strdup("");
        while(!done)
        {
            end_ptr = strchr(start_ptr, '\n');
            if(end_ptr != NULL)
            {
                *end_ptr = '\0';
                end_ptr++;
                if(*end_ptr == '\0')
                {
                    end_ptr = NULL;
                    done = GLOBUS_TRUE;
                }
                else
                {
                    end_ptr = strdup(end_ptr);
                }
            }
            else
            {
                done = GLOBUS_TRUE;
            }

            tmp_ptr = msg;
            msg = globus_common_create_string("%s%d-%s\r\n", 
                tmp_ptr, code, start_ptr);
            globus_free(tmp_ptr);

            start_ptr = end_ptr;
            ctr++;
        }
        if(ctr == 1)
        {
            msg[3] = ' ';
        }
        else
        {
            tmp_ptr = msg;
            msg = globus_common_create_string("%s%d End.\r\n", tmp_ptr, code);
            globus_free(tmp_ptr);
        }
    }

    return msg;
}

char *
globus_i_gsc_nlst_line(
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                 stat_count)
{
    int                                 ctr;
    int                                 tmp_i;
    char *                              buf;
    char *                              tmp_ptr;
    globus_size_t                       buf_len;
    globus_size_t                       buf_left;

    /* take a guess at the size needed */
    buf_len = stat_count * sizeof(char) * 32;
    buf_left = buf_len;
    buf = globus_malloc(buf_len);
    tmp_ptr = buf;
    for(ctr = 0; ctr < stat_count; ctr++)
    {
        tmp_i = strlen(stat_info[ctr].name) + 3;
        if(buf_left < tmp_i)
        {
            buf_len *= 2;
            buf = globus_libc_realloc(buf, buf_len);
        }

        snprintf(tmp_ptr, tmp_i+3, "%s\r\n", stat_info[ctr].name);
        tmp_ptr += tmp_i;
        buf_left -= tmp_i;
    }

    return buf;
}

char *
globus_i_gsc_mlsx_line_single(
    const char *                        mlsx_fact_str,
    int                                 uid,
    globus_gridftp_server_control_stat_t *  stat_info)
{
    char *                              out_buf;
    char *                              tmp_ptr;
    char *                              fact;
    char *                              dir_ptr;
    int                                 buf_len;
    struct tm *                         tm;
    int                                 is_readable = 0;
    int                                 is_writable = 0;
    int                                 is_executable = 0;

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
    globus_gridftp_server_control_stat_t *  stat_info,
    int                                 stat_count,
    const char *                        mlsx_fact_str,
    uid_t                               uid)
{
    int                                 ctr;
    char *                              buf;
    char *                              tmp_ptr;

    buf = globus_libc_strdup("");
    for(ctr = 0; ctr < stat_count; ctr++)
    {
        tmp_ptr = globus_common_create_string("%s%s\r\n",
            buf,
            globus_i_gsc_mlsx_line_single(
                mlsx_fact_str,
                uid,
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
    char *                              username;
    char *                              grpname;
    char                                user[16];
    char                                grp[16];
    struct passwd *                     pw;
    struct group *                      gr;
    struct tm *                         tm;
    char                                perms[11];
    char *                              tmp_ptr;
    char *                              month_lookup[12] =
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
    int                                 stat_count)
{
    int                                 ctr;
    char *                              buf;
    char *                              tmp_ptr;

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
    globus_i_gsc_op_t *                 op,
    const char *                        path,
    globus_gridftp_server_control_resource_mask_t mask,
    globus_i_gsc_resource_cb_t          cb,
    void *                              user_arg)
{
    globus_result_t                     res;
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
    op->response_type = GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS;

    if(op->server_handle->funcs.resource_cb != NULL)
    {
        op->server_handle->funcs.resource_cb(
            op,
            op->path,
            op->mask,
            op->server_handle->funcs.resource_arg);
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
    globus_i_gsc_op_t *                 op,
    const char *                        user,
    const char *                        pass,
    globus_i_gsc_auth_cb_t              cb,
    void *                              user_arg)
{
    int                                 type;
    GlobusGridFTPServerName(globus_i_gsc_authenticate);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    op->auth_cb = cb;
    op->type = GLOBUS_L_GSC_OP_TYPE_AUTH;
    op->response_type = GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS;
    op->user_arg = user_arg;

    if(user != NULL)
    {
        op->username = globus_libc_strdup(user);
    }
    if(pass != NULL)
    {
        op->password = globus_libc_strdup(pass);
    }

    if(op->server_handle->security_type & GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI)
    {
        /* if this fails the values are just left null */
        globus_xio_handle_cntl(
            op->server_handle->xio_handle,
            globus_l_gsc_gssapi_ftp_driver,
            GLOBUS_XIO_DRIVER_GSSAPI_FTP_GET_AUTH,
            &type,
            &op->server_handle->context,
            &op->server_handle->cred,
            &op->server_handle->del_cred,
            &op->server_handle->subject);
        if(type == GLOBUS_XIO_GSSAPI_FTP_SECURE)
        {
            type = GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI;
            op->server_handle->dcau = 'A';
        }
        else
        {
            type = GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE;
        }
    }
    /* call out to user */
    if(op->server_handle->funcs.auth_cb != NULL)
    {
        op->server_handle->funcs.auth_cb(
            op,
            type,
            op->server_handle->context,
            op->server_handle->subject,
            op->username,
            op->password,
            op->server_handle->funcs.auth_arg);
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
    globus_i_gsc_op_t *                 op,
    const char **                       contact_strings,
    int                                 stripe_count,
    int                                 prt,
    globus_i_gsc_port_cb_t              cb,
    void *                              user_arg)
{
    int                                 ctr;
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
        globus_i_guc_data_object_destroy(op->server_handle);
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    op->type = GLOBUS_L_GSC_OP_TYPE_CREATE_PORT;
    op->net_prt = prt;
    op->port_cb = cb;
    op->max_cs = stripe_count;
    op->user_arg = user_arg;

    op->cs = globus_malloc(sizeof(char *) * (stripe_count+1));
    for(ctr = 0; ctr < stripe_count; ctr++)
    {
        op->cs[ctr] = globus_libc_strdup(contact_strings[ctr]);
    }
    op->cs[ctr] = NULL;

    if(op->server_handle->funcs.active_cb != NULL)
    {
        op->server_handle->funcs.active_cb(
            op,
            op->net_prt,
            (const char **)op->cs,
            op->max_cs,
            op->server_handle->funcs.active_arg);
    }
    else
    {
        GlobusLGSCRegisterInternalCB(op);
    }

    return GLOBUS_SUCCESS;
}


globus_result_t
globus_i_gsc_passive(
    globus_i_gsc_op_t *                 op,
    int                                 max,
    int                                 net_prt,
    const char *                        pathname,
    globus_i_gsc_passive_cb_t           cb,
    void *                              user_arg)
{
    GlobusGridFTPServerName(globus_i_gsc_passive);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        globus_i_guc_data_object_destroy(op->server_handle);
    }
    globus_mutex_unlock(&op->server_handle->mutex);

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
            op->max_cs,
            pathname,
            op->server_handle->funcs.passive_arg);
    }
    else
    {
        GlobusLGSCRegisterInternalCB(op);
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gsc_list(
    globus_i_gsc_op_t *                 op,
    const char *                        path,
    globus_gridftp_server_control_resource_mask_t mask,
    globus_i_gsc_op_type_t              type,
    globus_i_gsc_transfer_cb_t          list_cb,
    void *                              user_arg)
{
    char *                              fact_str;
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

    switch(type)
    {
        case GLOBUS_L_GSC_OP_TYPE_LIST:
            fact_str = "LIST:";
            break;
        case GLOBUS_L_GSC_OP_TYPE_NLST:
            fact_str = "NLST:";
            break;

        case GLOBUS_L_GSC_OP_TYPE_MLSD:
        default:
            fact_str = op->server_handle->opts.mlsx_fact_str;
            break;
    }

    if(user_cb != NULL)
    {
        user_cb(
            op, 
            op->server_handle->data_object->user_handle,
            op->path,
            fact_str,
            op->server_handle->funcs.data_destroy_arg);
    }
    else
    {
        return GlobusGridFTPServerControlErrorSyntax();
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gsc_send(
    globus_i_gsc_op_t *                 op,
    const char *                        path,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_i_gsc_transfer_cb_t          transfer_cb,
    void *                              user_arg)
{
    globus_gridftp_server_control_transfer_cb_t user_cb;
    globus_i_gsc_module_func_t *        mod_func;
    void *                              mod_arg;
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
            mod_arg = op->server_handle->funcs.default_send_arg;
        }
        else
        {
            mod_func = (globus_i_gsc_module_func_t *)
                globus_hashtable_lookup(
                    &op->server_handle->funcs.send_cb_table, (char *)mod_name);
            if(mod_func == NULL)
            {
                globus_mutex_unlock(&op->server_handle->mutex);
                return GlobusGridFTPServerErrorParameter("op");
            }
            user_cb = mod_func->func;
            mod_arg = mod_func->user_arg;
        }
        globus_range_list_init(&op->range_list);
        if(op->server_handle->range_list == NULL)
        {
            globus_range_list_insert(op->range_list, 0, GLOBUS_RANGE_LIST_MAX);
        }
        else
        {
            globus_i_gsc_reverse_restart(
                op->server_handle->range_list, op->range_list);
        }
        op->server_handle->range_list = NULL;
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
            op->range_list,
            mod_arg);
    }
    else
    {
        return GlobusGridFTPServerControlErrorSyntax();
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_gsc_recv(
    globus_i_gsc_op_t *                 op,
    const char *                        path,
    const char *                        mod_name,
    const char *                        mod_parms,
    globus_i_gsc_transfer_cb_t          transfer_cb,
    void *                              user_arg)
{
    globus_i_gsc_module_func_t *        mod_func;
    void *                              mod_arg;
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
            mod_arg = op->server_handle->funcs.default_recv_arg;
        }
        else
        {
            mod_func = (globus_i_gsc_module_func_t *)
                globus_hashtable_lookup(
                    &op->server_handle->funcs.recv_cb_table, (char *)mod_name);
            if(mod_func == NULL)
            {
                globus_mutex_unlock(&op->server_handle->mutex);
                return GlobusGridFTPServerErrorParameter("op");
            }
            user_cb = mod_func->func;
            mod_arg = mod_func->user_arg;
        }
        globus_range_list_init(&op->range_list);
        if(op->server_handle->range_list == NULL)
        {
            globus_range_list_insert(op->range_list, 0, GLOBUS_RANGE_LIST_MAX);
        }
        else
        {
            globus_i_gsc_reverse_restart(
                op->server_handle->range_list, op->range_list);
        }
        op->server_handle->range_list = NULL;
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
            op->range_list,
            mod_arg);
    }
    else
    {
        return GlobusGridFTPServerControlErrorSyntax();
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
    void *                              user_arg)
{
    globus_i_gsc_op_t *                 op;

    op = (globus_i_gsc_op_t *) user_arg;

    switch(op->type)
    {
        case GLOBUS_L_GSC_OP_TYPE_AUTH:
            op->auth_cb(
                op,
                op->response_type,
                op->response_msg,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_RESOURCE:
            op->stat_cb(
                op,
                op->response_type,
                op->response_msg,
                op->path,
                op->stat_info,
                op->stat_count,
                op->uid,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PASV:
            op->passive_cb(
                op,
                op->response_type,
                op->response_msg,
                (const char **)op->cs,
                op->max_cs,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PORT:
            op->port_cb(
                op,
                op->response_type,
                op->response_msg,
                op->user_arg);
            break;

        case GLOBUS_L_GSC_OP_TYPE_SEND:
        case GLOBUS_L_GSC_OP_TYPE_RECV:
        case GLOBUS_L_GSC_OP_TYPE_LIST:
        case GLOBUS_L_GSC_OP_TYPE_NLST:
        case GLOBUS_L_GSC_OP_TYPE_MLSD:
            op->transfer_cb(
                op,
                op->response_type,
                op->response_msg,
                op->user_arg);
            break;

        default:
            globus_assert(0 && "bad op type");
            break;
    }
}

globus_result_t
globus_gridftp_server_control_finished_auth(
    globus_i_gsc_op_t *                 op,
    const char *                        username,
    globus_gridftp_server_control_response_t response_code,
    const char *                        msg)
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
        if(username != NULL)
        {
            if(op->server_handle->username != NULL)
            {
                globus_free(op->server_handle->username);
            }
            op->server_handle->username = strdup(username);
        }
        op->response_type = response_code;
        if(op->response_type == GLOBUS_GRIDFTP_SERVER_CONTROL_RESPONSE_SUCCESS)
        {
            op->server_handle->authenticated = GLOBUS_TRUE;
        }
        op->response_msg = NULL;
        if(msg != NULL)
        {
            op->response_msg = strdup(msg);
        }
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
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_stat_t *  stat_info_array,
    int                                 stat_count,
    uid_t                               uid,
    globus_gridftp_server_control_response_t response_code,
    const char *                            msg)
{
    int                                 ctr;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_resource);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    op->response_type = response_code;
    op->response_msg = NULL;
    if(msg != NULL)
    {
        op->response_msg = strdup(msg);
    }
    
    if(res == GLOBUS_SUCCESS)
    {
        op->stat_info = (globus_gridftp_server_control_stat_t *)
            globus_malloc(sizeof(globus_gridftp_server_control_stat_t) *
                stat_count);
        op->stat_count = stat_count;
        op->uid = uid;
        for(ctr = 0; ctr < op->stat_count; ctr++)
        {
            globus_i_gsc_stat_cp(
                &op->stat_info[ctr], &stat_info_array[ctr]);
        }
    }
    if(op->stat_cb != NULL)
    {
        GlobusLGSCRegisterInternalCB(op);
    }
    else
    {
        res = GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_finished_active_connect(
    globus_gridftp_server_control_op_t  op,
    void *                              user_data_handle,
    globus_gridftp_server_control_data_dir_t data_dir,
    globus_gridftp_server_control_response_t response_code,
    const char *                            msg)
{
    globus_i_gsc_data_t *               data_obj;
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
        return GlobusGridFTPServerControlErrorSytem();
    }
    data_obj->dir = data_dir;
    data_obj->user_handle = user_data_handle;
    data_obj->server_handle = op->server_handle;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        op->server_handle->data_object = data_obj;
        op->server_handle->stripe_count = op->max_cs;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    GlobusLGSCRegisterInternalCB(op);

    return GLOBUS_SUCCESS;
}
                                                                                
globus_result_t
globus_gridftp_server_control_finished_passive_connect(
    globus_gridftp_server_control_op_t  op,
    void *                              user_data_handle,
    globus_gridftp_server_control_data_dir_t data_dir,
    const char **                       cs,
    int                                 cs_count,
    globus_gridftp_server_control_response_t response_code,
    const char *                            msg)
{
    globus_i_gsc_data_t *               data_obj;
    int                                 ctr;
    GlobusGridFTPServerName(globus_gridftp_server_control_finished_passive_connect);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_CREATE_PASV)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    data_obj = (globus_i_gsc_data_t *) globus_malloc(
        sizeof(globus_i_gsc_data_t));
    if(data_obj == NULL)
    {
        return GlobusGridFTPServerControlErrorSytem();
    }
    data_obj->dir = data_dir;
    data_obj->user_handle = user_data_handle;
    data_obj->server_handle = op->server_handle;

    op->cs = (char **) globus_malloc(sizeof(char *) * (cs_count + 1));
    for(ctr = 0; ctr < cs_count; ctr++)
    {
        op->cs[ctr] = globus_libc_strdup(cs[ctr]);
    }
    op->cs[ctr] = NULL;
    op->max_cs = cs_count;

    op->response_type = response_code;
    op->response_msg = NULL;
    if(msg != NULL)
    {
        op->response_msg = strdup(msg);
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        op->server_handle->data_object = data_obj;
        op->server_handle->stripe_count = cs_count;
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    GlobusLGSCRegisterInternalCB(op);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_disconnected(
    globus_gridftp_server_control_t     server,
    void *                              user_data_handle)
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
        globus_i_guc_data_object_destroy(server);
    }
    globus_mutex_unlock(&server->mutex);

    if(destroy_cb != NULL)
    {
        destroy_cb(user_data_handle, server->funcs.data_destroy_arg);
    }

    return GLOBUS_SUCCESS;
}

                                                                                
globus_result_t
globus_gridftp_server_control_begin_transfer(
    globus_gridftp_server_control_op_t  op)
{
    globus_result_t                     res;
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
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return res;
}

globus_result_t
globus_gridftp_server_control_finished_transfer(
    globus_gridftp_server_control_op_t  op,
    globus_gridftp_server_control_response_t response_code,
    const char *                            msg)
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

    op->response_type = response_code;
    op->response_msg = NULL;
    if(msg != NULL)
    {
        op->response_msg = strdup(msg);
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(op->range_list != NULL)
        {
            globus_range_list_destroy(op->range_list);
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    GlobusLGSCRegisterInternalCB(op);
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gridftp_server_control_list_buffer_alloc(
    const char *                                fact_str,
    uid_t                                       uid,
    globus_gridftp_server_control_stat_t *      stat_info_array,
    int                                         stat_count,
    globus_byte_t **                            out_buf,
    globus_size_t *                             out_size)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_list_buffer_malloc);

    if(fact_str == NULL)
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

    if(strcmp("LIST:", fact_str) == 0) 
    {
        *out_buf = globus_i_gsc_list_line(stat_info_array, stat_count);
    }
    else if(strcmp("NLST:", fact_str) == 0)
    {
        *out_buf = globus_i_gsc_nlst_line(stat_info_array, stat_count);
    }
    else
    {
        *out_buf = globus_i_gsc_mlsx_line(
            stat_info_array, stat_count, fact_str, uid);
    }

    *out_size = strlen(*out_buf);

    return GLOBUS_SUCCESS;
}

void
globus_gridftp_server_control_list_buffer_free(
    globus_byte_t *                     buffer)
{
    globus_free(buffer);
}

globus_result_t
globus_gridftp_server_control_events_enable(
    globus_gridftp_server_control_op_t  op,
    int                                 event_mask,
    globus_gridftp_server_control_event_cb_t event_cb,
    void *                              user_arg)
{
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_gridftp_server_control_events_enable);

    if(op == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("op");
        goto error_param;
    }
    if(op->type != GLOBUS_L_GSC_OP_TYPE_SEND &&
        op->type != GLOBUS_L_GSC_OP_TYPE_RECV &&
        op->type != GLOBUS_L_GSC_OP_TYPE_LIST &&
        op->type != GLOBUS_L_GSC_OP_TYPE_NLST &&
        op->type != GLOBUS_L_GSC_OP_TYPE_MLSD) 
    {
        res = GlobusGridFTPServerErrorParameter("op");
        goto error_param;
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        /* TODO: determine if cached */
        globus_i_gsc_event_start(op, event_mask, event_cb, user_arg);
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;

  error_param:

    return res;
}

globus_result_t
globus_gridftp_server_control_events_disable(
    globus_gridftp_server_control_op_t  op)
{
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_gridftp_server_control_events_disable);

    if(op == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("op");
        goto error_param;
    }

    globus_mutex_lock(&op->server_handle->mutex);
    {
        globus_i_gsc_event_end(op);
    }
    globus_mutex_unlock(&op->server_handle->mutex);

    return GLOBUS_SUCCESS;

  error_param:

    return res;
}

globus_result_t
globus_gridftp_server_control_add_feature(
    globus_i_gsc_server_handle_t *      server_handle,
    const char *                        feature)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_add_feature);

    if(server_handle == NULL)
    {
        return GlobusGridFTPServerErrorParameter("server_handle");
    }
    if(feature == NULL)
    {
        return GlobusGridFTPServerErrorParameter("feature");
    }

    globus_list_insert(
        &server_handle->feature_list, globus_libc_strdup(feature));

    return GLOBUS_SUCCESS;
}
