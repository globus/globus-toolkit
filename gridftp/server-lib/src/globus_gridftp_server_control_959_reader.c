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
globus_module_descriptor_t      globus_i_gridftp_server_control_module =
{
    "globus_gridftp_server_control",
    globus_l_gsc_activate,
    globus_l_gsc_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

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
    globus_i_gsc_op_t *                     op;
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
            globus_i_gsc_959_terminate(handle_959);
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
                    op = globus_gsc_op_create(
                        cmd_list, buffer, handle_969);
                    if(op == NULL)
                    {
                        globus_i_gsc_959_terminate(handle_959);
                        globus_mutex_unlock(&handle->server->mutex);
                        goto exit;
                    }

                    globus_fifo_enqueue(&handle->read_q, op);
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
                        globus_i_gsc_959_terminate(handle);
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
                            globus_i_gsc_959_terminate(handle);
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
                        globus_i_gsc_959_terminate(handle);
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
            globus_i_gsc_959_terminate(handle_959);
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
            globus_i_gsc_959_terminate(handle);
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
            globus_i_gsc_959_terminate(handle);
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
                        globus_i_gsc_959_terminate(handle);
                    }
                }
                break;

            case GLOBUS_L_GSP_959_STATE_PROCESSING:
                handle->state = GLOBUS_L_GSP_959_STATE_OPEN;
                globus_l_gsc_959_process_next_cmd(handle);
                break;

            case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
            case GLOBUS_L_GSP_959_STATE_STOPPING:
                globus_xio_attr_init(&close_attr);
                globus_xio_attr_cntl(
                    &close_attr, NULL, GLOBUS_XIO_CLOSE_NO_CANCEL);
                res = globus_xio_register_close(
                    handle_959->xio_handle,
                    globus_l_gsc_959_close_cb,
                    handle_959);
                globus_xio_attr_destroy(&close_attr);
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
            globus_i_gsc_959_terminate(handle);
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
                    globus_i_gsc_959_terminate(handle);
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
static globus_result_t
globus_l_gsc_parse_command(
    char *                                  command,
    char ***                                out_cmd_a,
    int                                     argc)
{
    char *                                  start_ptr;
    char **                                 cmd_a = NULL;
    int                                     ctr;
    globus_result_t                         res;
    int                                     ctr;
    GlobusXIOName(globus_l_gsc_parse_command);

    *out_cmd_a = NULL;

    cmd_a = (char **) globus_malloc(sizeof(char *) * argc);
    if(cmd_a == NULL)
    {
        res = GlobusXIOGssapiFTPAllocError();
        goto err;
    }

    start_ptr = command;
    for(ctr = 0; ctr < argc; ctr++)
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
                !isspace(start_ptr[ndx]) && start_ptr[ndx] != '\r'; 
                ndx++)
            {
                ndx++;
            }
            if(ctr == argc - 1)
            {
                cmd_a[ctr] = globus_libc_strndup(start_ptr, ndx);
            }
            else
            {
                cmd_a[ctr] = globus_libc_strdup(start_ptr);
            }
        }
    }
    *out_cmd_a = cmd_a;

    return GLOBUS_SUCCESS;

  err:
    return res;
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
 *   create a 959 op
 */
static globus_i_gsc_op_t *
globus_l_gsc_op_create(
    globus_list_t *                         cmd_list,
    char *                            	    buffer,
    globus_l_gsc_959_handle_t *             handle)
{
    globus_i_gsc_op_t *                       op;

    op = (globus_i_gsc_op_t *)
        globus_malloc(sizeof(globus_i_gsc_op_t));
    if(op == NULL)
    {
        return NULL;
    }

    op->cmd_list = cmd_list;
    op->handle = handle;
    op->command = buffer;
    op->server = handle->server;

    return op;
}

/*
 * destroy a 959 op
 */
static void
globus_gsc_op_destroy(
    globus_i_gsc_op_t *                       op)
{
    globus_free(op);
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
    globus_i_gsc_op_t *                     op;

    while(!globus_fifo_empty(&handle->read_q))
    {
        op = (globus_i_gsc_op_t *)
            globus_fifo_dequeue(&handle->read_q);
        globus_assert(op != NULL);
        globus_l_gsc_op_destroy(op);

        tmp_res = globus_l_gsc_959_final_reply(handle, reply_msg);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            res = tmp_res;
        }
    }

    return res;
}

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



/*
 *  callout into the command code
 */
static void
globus_l_gsc_959_command_callout(
    globus_i_gsc_op_t *                     op)
{
    globus_bool_t                           auth = GLOBUS_FALSE;
    char **                                 cmd_array;

    if(op->server->state == GLOBUS_L_GS_STATE_OPEN)
    {
        auth = GLOBUS_TRUE;
    }
    while(!done)
    {
        /* if we ran out of commands before finishing tell the client
            the command does not exist */
        if(op->cmd_list == NULL)
        {
            res = globus_l_gsc_959_final_reply(op->handle, msg);
            done = GLOBUS_TRUE;
            globus_free(op);
        }
        else
        {
            cmd_ent = (globus_l_gsc_959_cmd_ent_t *)
                globus_list_first(op->cmd_list);
            /* must advance before calling the user callback */
            op->cmd_list = globus_list_rest(op->cmd_list);
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
                globus_l_gsc_parse_command(
                    op->command, &cmd_array, cmd_ent->argc);
                /*
                 *  call out to the users command
                 */
                cmd_ent->cmd_func(
                    op,
                    op->command,
                    cmd_array,
                    cmd_ent->argc,
                    cmd_ent->user_arg);
                globus_l_gsc_free_command_array(cmd_array);

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
    globus_i_gsc_op_t *                     op;
    GlobusGridFTPServerName(globus_l_gsc_959_process_next_cmd);

    GlobusGridFTPServerDebugEnter();

    globus_assert(handle->state == GLOBUS_L_GSP_959_STATE_OPEN);

    if(!globus_fifo_empty(&handle->read_q))
    {
        handle->state = GLOBUS_L_GSP_959_STATE_PROCESSING;

        op = (gglobus_i_gsc_op_t *)
            globus_fifo_dequeue(&handle->read_q);

        handle->outstanding_op = op;

        globus_l_gsc_959_command_callout(op);
    }

    GlobusGridFTPServerDebugExit();
}

/*
 *  seperated from the exteranally visible function to allow for only
 *  1 write at a time.
 */
static void
globus_l_gsc_959_finished_op(
    globus_i_gsc_op_t *                             op,
    char *                                          reply_msg)
{
    globus_l_gsc_959_handle_t *                     handle;
    globus_result_t                                 res;
    globus_bool_t                                   stopping = GLOBUS_FALSE;
    GlobusGridFTPServerName(globus_l_gsc_959_finished_op);

    handle = op->handle;

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
                globus_i_gsc_959_terminate(handle);
                break;
            }
            res = globus_l_gsc_959_flush_reads(
                    handle,
                    "426 Command Aborted\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_i_gsc_959_terminate(handle);
                break;
            }
            res = globus_l_gsc_959_final_reply(
                    handle,
                    "226 Abort successful\r\n");
            if(res != GLOBUS_SUCCESS)
            {
                globus_i_gsc_959_terminate(handle);
                break;
            }
            break;

        case GLOBUS_L_GSP_959_STATE_PROCESSING:

            if(reply_msg == NULL && op->cmd_list == NULL)
            {
                reply_msg = "500 Command not supported\r\n";
            }

            if(reply_msg == NULL)
            {
                globus_l_gsc_959_command_callout(op);
            }
            else
            {
                res = globus_l_gsc_959_final_reply(
                        handle,
                        reply_msg);
                if(res != GLOBUS_SUCCESS)
                {
                    globus_i_gsc_959_terminate(handle);
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

    globus_free(op->command);
    globus_free(op);
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
globus_result_t
globus_gridftp_server_control_init(
    globus_gridftp_server_control_t *       server)
{
    globus_i_gsc_server_handle_t *          server_handle;

    if(server == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server");
        goto err;
    }

    server_handle = (globus_i_gsc_server_handle_t *) globus_malloc(
        sizeof(globus_i_gsc_server_t));
    if(server_handle == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("server_handle");
        goto err;
    }

    memset(server_handle, '\0', sizeof(globus_i_gsc_server_handle_t));

    globus_mutex_init(&server_handle->mutex, NULL);

    server_handle->state = GLOBUS_L_GSP_959_STATE_OPENING;
    server_handle->reply_outstanding = GLOBUS_FALSE;
    globus_fifo_init(&server_handle->read_q);
    globus_fifo_init(&server_handle->reply_q);
    globus_fifo_init(&server_handle->data_q);

    globus_hashtable_init(
        &server_handle->cmd_table,
        128,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    
    server_handle->xio_handle = xio_handle;
    
    globus_i_gsc_959_add_commands(server_handle);

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
    if(server_handle->state != GLOBUS_L_GSP_959_STATE_STOPPED)
    {
        res = GlobusGridFTPServerErrorState(server_handle->state);
        goto err;
    }

    globus_mutex_destroy(&server_handle->mutex);
    globus_hashtable_destroy(&server_handle->cmd_handle);
    globus_fifo_destroy(&server_handle->read_q);
    globus_fifo_destroy(&server_handle->reply_q);
    globus_free(server_handle);

    return GLOBUS_SUCCESS;

  err:
    return res;
}

/*
 *  959 start
 *  ---------
 *  Write the 220 then start reading.
 */
globus_result_t
globus_gridftp_server_control_start(
    globus_gridftp_server_control_t         server,
    globus_gridftp_server_control_attr_t    attr,
    globus_xio_handle_t                     xio_handle,
    globus_gridftp_server_control_callback_t done_cb,
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
        if(server_handle->state != GLOBUS_L_GSP_959_STATE_STOPPED &&
            server_handle->state != GLOBUS_L_GSP_959_STATE_OPENING)
        {
            globus_mutex_unlock(&i_server->mutex);
            res = GlobusGridFTPServerErrorParameter("server");
            goto err;
        }

        server_hanndle->xio_handle = xio_handle;
        globus_hashtable_copy(
            &server_handle->send_table, &i_attr->send_func_table, NULL);
        globus_hashtable_copy(
            &server_handle->recv_table, &i_attr->recv_func_table, NULL);
        server_handle->resource_func = i_attr->resource_func;
        server_handle->auth_cb = i_attr->auth_func;
        server_handle->done_func = i_attr->done_func;
        server_handle->passive_func = i_attr->passive_func;
        server_handle->active_func = i_attr->active_func;
        server_handle->data_destroy_func = i_attr->data_destroy_func;
        server_handle->default_stor = i_attr->default_stor;
        server_handle->default_retr = i_attr->default_retr;

        server_handle->delete_func = i_attr->delete_func;
        server_handle->mkdir_func = i_attr->mkdir_func;
        server_handle->rmdir_func = i_attr->rmdir_func;
        server_handle->move_func = i_attr->move_func;

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
        server_handle->mode = 'S'

        if(server_handle->cwd != NULL)
        {
            globus_free(server_handle->cwd);
        }
        server_handle->cwd = globus_libc_strdup(i_attr->base_dir);

        server_handle->user_arg = user_arg;

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
            goto err;
        }
    }
    globus_mutex_unlock(&server_handle->mutex);

    GlobusGridFTPServerDebugExit()

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

    if(op->server->state != GLOBUS_L_GSP_959_STATE_PROCESSING)
    {

    }

    globus_xio_handle_cancel_operations(
        server_handle->xio_handle,
        GLOBUS_XIO_CANCEL_READ);
    globus_l_gsc_959_flush_reads(
        server_handle,
        "421 Service not available, closing control connection.\r\n");
    op->server_handle->state = GLOBUS_L_GSP_959_STATE_STOPPING;

    /* not much can be done about an error here, we are terminating 
        anyway */
    res = globus_l_gsc_959_final_reply(
            handle,
            reply_msg);

    return GLOBUS_SUCCESS;
}


/*
 *  terminate
 *  ---------
 *  This is called whenever an error occurs.  It attempts to nicely
 *  send a message to the user then changes to a stopping state.
 */
void
globus_i_gsc_959_terminate(
    globus_i_gsc_server_handle_t *          server_handle)
{
    globus_bool_t                           close = GLOBUS_TRUE;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_i_gsc_959_terminate);

    switch(server_handle->state)
    {
        /* if already stopping, just punt. this is likely to happen */
        case GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING:
        case GLOBUS_L_GSP_959_STATE_STOPPING:
            close = GLOBUS_FALSE;
            break;

        case GLOBUS_L_GSP_959_STATE_ABORTING:
            server_handle->state = GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING;
            /* if aborting no read is posted, and there are no commands 
               to flush */
            break;

        /*  Clear out whatever commands we have if we can */
        case GLOBUS_L_GSP_959_STATE_PROCESSING:
            /* start abort process */
            server_handle->state = GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING;
            /*
             *  cancel the outstanding command.  In its callback
             *  we flush the q and respond to the ABOR
             */
            globus_assert(server_handle->outstanding_op != NULL);

            if(server_handle->abort_func != NULL)
            {
                server_handle->abort_func(
                    server_handle->outstanding_op,
                    server_handle->abort_arg);
            }

            globus_xio_handle_cancel_operations(
                server_handle->xio_handle,
                GLOBUS_XIO_CANCEL_READ);
            globus_l_gsc_959_flush_reads(
                server_handle,
                "421 Service not available, closing control connection.\r\n");
            close = GLOBUS_FALSE;
            break;

        /*
         *  goto panic state and cancel the read
         */
        case GLOBUS_L_GSP_959_STATE_OPEN:
            server_handle->state = GLOBUS_L_GSP_959_STATE_STOPPING;
            globus_xio_handle_cancel_operations(
                server_handle->xio_handle,
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
            server_handle->xio_handle,
            globus_l_gsc_959_close_cb,
            server_handle);
        if(res != GLOBUS_SUCCESS)
        {
            GlobusL959RegisterDone(server_handle);
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
        if(server_handle->state != GLOBUS_L_GS_STATE_OPEN)
        {
            globus_mutex_unlock(&server_handle->mutex);
            res = GlobusGridFTPServerErrorParameter("server");
            goto err;
        }
        globus_i_gsc_959_terminate(server_handle);
    }
    globus_mutex_unlock(&server_handle->mutex);


    return GLOBUS_SUCCESS;

  err:

    return res;
}


void
globus_i_gsc_959_finished_op(
    globus_i_gsc_op_t *                     op,
    char *                                  reply_msg)
{
    globus_l_gsc_959_handle_t *             handle;
    globus_l_gsc_959_reply_ent_t *          reply_ent;
    GlobusGridFTPServerName(globus_gsc_959_finished_op);

    handle = op->handle;

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
globus_i_gsc_intermediate_reply(
    globus_i_gsc_op_t *                     op,
    char *                                  reply_msg)
{
    globus_l_gsc_959_reply_ent_t *          reply_ent;
    globus_l_gsc_959_handle_t *             handle;
    globus_result_t                         res;

    handle = op->handle;

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
            globus_i_gsc_959_terminate(handle);
        }
    }

    return res;
}

globus_result_t
globus_i_gsc_command_add(
    globus_i_gsc_server_handle_t *          server_handle,
    const char *                            command_name,
    globus_gsc_959_command_func_t           command_func,
    globus_gsc_959_command_desc_t           desc,
    int                                     argc,
    const char *                            help,
    void *                                  user_arg)
{
    globus_list_t *                         list;
    globus_result_t                         res;
    globus_l_gsc_959_cmd_ent_t *            cmd_ent;
    GlobusGridFTPServerName(globus_gsc_959_command_add);

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
    cmd_ent->argc = argc;

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

static void
globus_l_gsc_user_op_kickout(
    void *                                          user_arg)
{
    globus_i_gsc_server_t *                         i_server;
    globus_i_gsc_op_t *                             i_op;

    i_op = (globus_i_gsc_op_t *) user_arg;
    i_server = i_op->server;

    switch(i_op->type)
    {
        case GLOBUS_L_GSC_OP_TYPE_AUTH:
            i_server->auth_cb(
                i_op,
                i_op->username,
                i_op->password,
                i_op->cred,
                i_op->del_cred);
            break;

        case GLOBUS_L_GSC_OP_TYPE_RESOURCE:
            i_server->resource_func(
                i_op,
                i_op->path,
                i_op->mask);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PASV:
            /*
             *  all of this should be safe outside of lock
             */
            /* the data channel is not cacheable so destroy it */
            if(i_server->data_object != NULL)
            {
                i_server->data_destroy_func(
                    i_server->data_object->user_handle);
                globus_free(i_server->data_object);
                i_server->data_object = NULL;
            }
            /* call the user passive func */
            i_server->passive_func(
                i_op,
                i_op->net_prt,
                i_op->max_cs);
            break;

        case GLOBUS_L_GSC_OP_TYPE_CREATE_PORT:
            if(i_server->data_object != NULL)
            {
                i_server->data_destroy_func(
                    i_server->data_object->user_handle);
                globus_free(i_server->data_object);
                i_server->data_object = NULL;
            }
            i_op->server->active_func(
                i_op,
                i_op->net_prt,
                (const char **)i_op->cs,
                i_op->max_cs);
            break;

        case GLOBUS_L_GSC_OP_TYPE_DATA:
            globus_assert(i_server->data_object != NULL);
            i_op->user_data_cb(
                i_op,
                i_server->data_object->user_handle,
                i_op->path,
                i_op->mod_name,
                i_op->mod_parms);
            break;

        default:
            globus_assert(0);
            break;
    }
}


static globus_result_t
globus_l_gsc_perform_op(
    globus_i_gsc_op_t *                             op)
{
    globus_result_t                                 res = GLOBUS_SUCCESS;
    GlobusGridFTPServerName(globus_l_gsc_perform_op);

    /* check state and register oneshot */
    res = globus_callback_space_register_oneshot(
            NULL,
            NULL,
            globus_l_gsc_user_op_kickout,
            (void *)op,
            GLOBUS_CALLBACK_GLOBAL_SPACE);

    return res;
}


globus_result_t
globus_i_gsc_resource_query(
    globus_i_gsc_op_t *                     op,
    const char *                            path,
    int                                     mask,
    globus_gridftp_server_control_resource_callback_t cb,
    void *                                  user_arg)
{
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_i_gsc_resource_query);

    op->type = GLOBUS_L_GSC_OP_TYPE_RESOURCE;
    op->res = GLOBUS_SUCCESS;
    op->user_arg = user_arg;
    op->stat_cb = cb;
    op->path = globus_i_gsc_concat_path(op->server_handle, path);
    if(user_op->path == NULL)
    {
        globus_gsc_959_panic(op_959);
        goto err;
    }
    res = globus_l_gsc_perform_op(user_op);
    if(res != GLOBUS_SUCCESS)
    {
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
    globus_gridftp_server_control_auth_callback_t cb,
    void *                                  user_arg)
{
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_i_gsc_authenticate);

    op->auth_cb = cb;
    op->type = GLOBUS_L_GSC_OP_TYPE_AUTH;
    op->res = GLOBUS_SUCCESS;
    op->user_arg = user_arg;

    if(username != NULL)
    {
        op->username = globus_libc_strdup(user);
    }
    if(password != NULL)
    {
        op->password = globus_libc_strdup(pass);
    }
    op->cred = cred;
    op->del_cred = del_cred;

    res = globus_l_gsc_perform_op(i_op);

    return res;
}

globus_result_t
globus_i_gsc_passive(
    globus_i_gsc_op_t *                     op,
    int                                     max
    int                                     net_prt,
    globus_gridftp_server_control_pmod_passive_callback_t   cb,
    void *                                  user_arg)
{

    op->res = GLOBUS_SUCCESS;
    op->user_arg = user_arg;
    op->max_cs = max;
    op->net_prt = net_prt;
    op->passive_cb = cb;
    op->cs = NULL;
    op->type = GLOBUS_L_GSC_OP_TYPE_CREATE_PASV;

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
