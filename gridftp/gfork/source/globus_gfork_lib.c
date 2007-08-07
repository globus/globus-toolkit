#include "globus_i_gfork.h"
#include "version.h"

#define GFORK_CHILD_READ_ENV "GFORK_CHILD_READ_ENV"
#define GFORK_CHILD_WRITE_ENV "GFORK_CHILD_WRITE_ENV"

globus_xio_stack_t                      gfork_i_file_stack;
globus_xio_attr_t                       gfork_i_file_attr;
globus_xio_driver_t                     gfork_i_file_driver;

static globus_bool_t                    gfork_l_globals_set = GLOBUS_FALSE;

/* can only be 1 pipe per process, but we allow a list of callbacks */
static gfork_child_handle_t             gfork_l_handle;

GlobusDebugDefine(GLOBUS_GFORK);

static
globus_result_t
gfork_l_get_env_fd(
    char *                              env,
    int *                               out_fd);

static
void
gfork_l_child_read_header_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
gfork_l_child_read_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gfork_i_lib_handle_t *            handle;

    handle = (gfork_i_lib_handle_t *) user_arg;

    handle->close_cb(handle, handle->user_arg, getpid());

    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
}

static
void
gfork_l_child_write_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gfork_i_lib_handle_t *            handle;

    handle = (gfork_i_lib_handle_t *) user_arg;

    result = globus_xio_register_close(
        handle->read_xio, NULL,
        gfork_l_child_read_close_cb, handle);
    if(result != GLOBUS_SUCCESS)
    {
        gfork_l_child_read_close_cb(handle->read_xio, GLOBUS_SUCCESS, handle);
    }

}

static
void
gfork_l_child_error(
    gfork_i_lib_handle_t *            handle)
{
    globus_result_t                     result;

    switch(handle->state)
    {
        /* we are already doing it */
        case GFORK_STATE_CLOSING:
            break;

        case GFORK_STATE_OPEN:
            result = globus_xio_register_close(
                handle->write_xio, NULL,
                gfork_l_child_write_close_cb, handle);
            if(result != GLOBUS_SUCCESS)
            {
                /* wtf ? */
            }
            handle->state = GFORK_STATE_CLOSING;

            break;

        default:
            globus_assert(0 && "Invalid state");
    }
}

static
void
gfork_l_child_read_body_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gfork_i_lib_handle_t *            handle;

    handle = (gfork_i_lib_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error_incoming;
    }

    handle->incoming_cb(
        handle,
        handle->user_arg,
        handle->header.from_pid,
        buffer,
        nbytes);

    result = globus_xio_register_read(
        handle->read_xio,
        (globus_byte_t *)&handle->header,
        sizeof(gfork_i_msg_header_t),
        sizeof(gfork_i_msg_header_t),
        NULL,
        gfork_l_child_read_header_cb,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_post;
    }

    return;

error_post:
error_incoming:

    free(buffer);
    globus_mutex_lock(&handle->mutex);
    {
        gfork_l_child_error(handle);
    }
    globus_mutex_unlock(&handle->mutex);
}


static
void
gfork_l_child_read_header_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gfork_i_lib_handle_t *            handle;
    globus_bool_t                       call_close = GLOBUS_FALSE;
    globus_bool_t                       call_open = GLOBUS_FALSE;

    handle = (gfork_i_lib_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error_incoming;
        }

        switch(handle->header.type)
        {
            case GLOBUS_GFORK_MSG_DATA:
                if(handle->header.size <= 0)
                {
                    /* assume a bad message, report header */
                    result = globus_xio_register_read(
                        handle->read_xio,
                        (globus_byte_t *)&handle->header,
                        sizeof(gfork_i_msg_header_t),
                        sizeof(gfork_i_msg_header_t),
                        NULL,
                        gfork_l_child_read_header_cb,
                        handle);
                    if(result != GLOBUS_SUCCESS)
                    {
                        goto error_post;
                    }
                }
                else
                {
                    handle->data = globus_malloc(handle->header.size);
    
                    result = globus_xio_register_read(
                        handle->read_xio,
                        handle->data,
                        handle->header.size,
                        handle->header.size,
                        NULL,
                        gfork_l_child_read_body_cb,
                        handle);
                    if(result != GLOBUS_SUCCESS)
                    { 
                        goto error_post;
                    }
                }
                break;

            /* any of these we consider garbage */
            case GLOBUS_GFORK_MSG_OPEN:
                call_open = handle->master;
                /* assume a bad message, report header */
                result = globus_xio_register_read(
                    handle->read_xio,
                    (globus_byte_t *)&handle->header,
                    sizeof(gfork_i_msg_header_t),
                    sizeof(gfork_i_msg_header_t),
                    NULL,
                    gfork_l_child_read_header_cb,
                    handle);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_post;
                }

                break;
            case GLOBUS_GFORK_MSG_CLOSE:
                call_close = handle->master;

                /* assume a bad message, report header */
                result = globus_xio_register_read(
                    handle->read_xio,
                    (globus_byte_t *)&handle->header,
                    sizeof(gfork_i_msg_header_t),
                    sizeof(gfork_i_msg_header_t),
                    NULL,
                    gfork_l_child_read_header_cb,
                    handle);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_post;
                }

                break;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    /* shold only happen on maste rprocess */
    if(call_open && handle->open_cb)
    {
        handle->open_cb(handle, handle->user_arg, handle->header.from_pid);
    }
    else if(call_close && handle->close_cb)
    {
        handle->close_cb(handle, handle->user_arg, handle->header.from_pid);
    }

    return;

error_post:
error_incoming:

    gfork_l_child_error(handle);
    globus_mutex_unlock(&handle->mutex);
}

static
globus_result_t
globus_l_gfork_child_start(
    gfork_child_handle_t *              out_handle,
    const char *                        in_env_suffix,
    globus_gfork_open_func_t            open_cb,
    globus_gfork_closed_func_t          close_cb,
    globus_gfork_incoming_cb_t          incoming_cb,
    void *                              user_arg,
    globus_bool_t                       master)
{
    globus_result_t                     result;
    gfork_i_lib_handle_t *            handle;
    char *                              env;
    char *                              env_suffix;
    int                                 read_fd;
    int                                 write_fd;

    handle = (gfork_i_lib_handle_t *)
        globus_calloc(1, sizeof(gfork_i_lib_handle_t));

    handle->state = GFORK_STATE_OPEN;
    handle->open_cb = open_cb;
    handle->close_cb = close_cb;
    handle->incoming_cb = incoming_cb;
    handle->user_arg = user_arg;
    handle->master = master;
    globus_mutex_init(&handle->mutex, NULL);
    globus_fifo_init(&handle->write_q);

    if(in_env_suffix == NULL)
    {
        env_suffix = "";
    }
    else
    {
        env_suffix = (char *) in_env_suffix;
    }
    env = globus_common_create_string("%s%s", GFORK_CHILD_READ_ENV, env_suffix);
    result = gfork_l_get_env_fd(env, &read_fd);

    globus_free(env);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_read_env;
    }

    env = globus_common_create_string("%s%s",GFORK_CHILD_WRITE_ENV,env_suffix);
    result = gfork_l_get_env_fd(env, &write_fd);
    globus_free(env);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_write_env;
    }

    result = gfork_i_make_xio_handle(&handle->read_xio, read_fd);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_read_convert;
    }
    result = gfork_i_make_xio_handle(&handle->write_xio, write_fd);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_write_convert;
    }

    globus_mutex_lock(&handle->mutex);
    {
        result = globus_xio_register_read(
            handle->read_xio,
            (globus_byte_t *)&handle->header,
            sizeof(gfork_i_msg_header_t),
            sizeof(gfork_i_msg_header_t),
            NULL,
            gfork_l_child_read_header_cb,
            handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_post;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    *out_handle = handle;

    return GLOBUS_SUCCESS;

error_post:
    gfork_l_child_error(handle);
    globus_mutex_unlock(&handle->mutex);
error_write_convert:
    globus_xio_close(handle->read_xio, NULL);
error_read_convert:
error_write_env:
error_read_env:
    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);

    return result;
}


globus_result_t
globus_gfork_child_worker_start(
    gfork_child_handle_t *              out_handle,
    const char *                        in_env_suffix,
    globus_gfork_closed_func_t          close_cb,
    globus_gfork_incoming_cb_t          incoming_cb,
    void *                              user_arg)
{
    return globus_l_gfork_child_start(
        out_handle,
        in_env_suffix,
        NULL,
        close_cb,
        incoming_cb,
        user_arg,
        GLOBUS_FALSE);
}

globus_result_t
globus_gfork_child_master_start(
    gfork_child_handle_t *              out_handle,
    const char *                        in_env_suffix,
    globus_gfork_open_func_t            open_cb,
    globus_gfork_closed_func_t          close_cb,
    globus_gfork_incoming_cb_t          incoming_cb,
    void *                              user_arg)
{   
    return globus_l_gfork_child_start(
        out_handle,
        in_env_suffix,
        open_cb,
        close_cb,
        incoming_cb,
        user_arg,
        GLOBUS_TRUE);
}

globus_result_t
globus_gfork_child_stop(
    gfork_child_handle_t                in_handle)
{
    gfork_i_lib_handle_t *            handle;

    handle = (gfork_i_lib_handle_t *) in_handle;
    globus_mutex_lock(&handle->mutex);
    {
        gfork_l_child_error(handle);
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_get_env_fd(
    char *                              env,
    int *                               out_fd)
{
    globus_result_t                     res;
    char *                              tmp_str;
    int                                 sc;
    int                                 fd;
    GForkFuncName(gfork_l_get_env_fd);

    tmp_str = globus_libc_getenv(env);
    if(tmp_str == NULL)
    {
        res = GForkErrorStr("Env not set");
        goto error_env;
    }
    sc = sscanf(tmp_str, "%d", &fd);
    if(sc != 1)
    {
        res = GForkErrorStr("Env not and integer");
        goto error_scan;
    }

    *out_fd = fd;

    return GLOBUS_SUCCESS;

error_scan:
error_env:
    return res; 
}

globus_result_t
gfork_i_make_xio_handle(
    globus_xio_handle_t *               xio_handle,
    int                                 fd)
{
    globus_result_t                     res;
    globus_xio_attr_t                   attr;
    globus_xio_handle_t                 handle;

    res = globus_xio_attr_init(&attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_copy;
    }
    res = globus_xio_attr_cntl(attr, gfork_i_file_driver,
        GLOBUS_XIO_FILE_SET_HANDLE, fd);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }

    res = globus_xio_handle_create(&handle, gfork_i_file_stack);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_create;
    }

    /* the way the stack is set up xio should not poll. */
    res = globus_xio_open(
        handle,
        NULL,
        attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    globus_xio_attr_destroy(attr);
    *xio_handle = handle;

    return GLOBUS_SUCCESS;
error_open:
error_create:
error_attr:
    globus_xio_attr_destroy(attr);
error_copy:
    return res;
}

static
void
gfork_l_client_writev_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gfork_i_msg_t *                     msg;
    gfork_i_lib_handle_t *              handle;

    msg = (gfork_i_msg_t *) user_arg;
    handle = msg->lib_handle;

    /* lazy reuse of XIO callback.  perhaps we should define our own */
    if(msg->client_cb)
    {
        msg->client_cb(NULL, result, &msg->iov[1],
            count - 1, nbytes, data_desc, msg->user_arg);
    }
    globus_free(msg->iov);
    globus_free(msg);

    globus_mutex_lock(&handle->mutex);
    {
        handle->writing = GLOBUS_FALSE;
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        if(!globus_fifo_empty(&handle->write_q))
        {
            msg = (gfork_i_msg_t *) globus_fifo_dequeue(&handle->write_q);

            result = globus_xio_register_writev(
                handle->write_xio,
                msg->iov,
                msg->iovc,
                msg->nbytes,
                NULL,
                gfork_l_client_writev_cb,
                msg);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
            handle->writing = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return;
error:
assert(0);
    globus_mutex_unlock(&handle->mutex);
}


globus_result_t
globus_l_gfork_send(
    gfork_i_lib_handle_t *              handle,
    uid_t                               pid,
    globus_xio_iovec_t *                iov,
    int                                 iovc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg)
{
    int                                 i;
    globus_size_t                       nbytes;
    gfork_i_msg_t *                     msg;
    globus_result_t                     result = GLOBUS_SUCCESS;

    msg = (gfork_i_msg_t *) globus_calloc(1, sizeof(gfork_i_msg_t));

    msg->header.from_pid = getpid();
    msg->header.to_pid = pid;
    msg->header.type = GLOBUS_GFORK_MSG_DATA;
    msg->lib_handle = handle;

    msg->user_arg = user_arg;

    msg->iov = (globus_xio_iovec_t *) globus_calloc(
        iovc + 1, sizeof(globus_xio_iovec_t));
    msg->iov[0].iov_base = &msg->header;
    msg->iov[0].iov_len = sizeof(gfork_i_msg_header_t);

    nbytes = 0;
    for(i = 0; i < iovc; i++)
    {
        msg->iov[i+1].iov_base = iov[i].iov_base;
        msg->iov[i+1].iov_len = iov[i].iov_len;
        nbytes += iov[i].iov_len;
    }
    msg->client_cb = cb;
    msg->header.size = nbytes;

    nbytes += msg->iov[0].iov_len;

    msg->nbytes = nbytes;
    msg->iovc = iovc+1;
    if(!handle->writing)
    {
        handle->writing = GLOBUS_TRUE;
        result = globus_xio_register_writev(
            handle->write_xio,
            msg->iov,
            msg->iovc,
            msg->nbytes,
            NULL,
            gfork_l_client_writev_cb,
            msg);
    }
    else
    {
        globus_fifo_enqueue(&handle->write_q, msg);
    }
    return result;
}

globus_result_t
globus_gfork_broadcast(
    gfork_child_handle_t                in_handle,
    globus_xio_iovec_t *                iov,
    int                                 iovc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    gfork_i_lib_handle_t *              handle;

    handle = (gfork_i_lib_handle_t *) in_handle;

    globus_mutex_lock(&handle->mutex);
    {
        result = globus_l_gfork_send(handle, -1, iov, iovc, cb, user_arg);
    }
    globus_mutex_unlock(&handle->mutex);

    return result;
}

globus_result_t
globus_gfork_send(
    gfork_child_handle_t                in_handle,
    uid_t                               pid,
    globus_xio_iovec_t *                iov,
    int                                 iovc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg)
{
    globus_result_t                     result;
    gfork_i_lib_handle_t *              handle;

    handle = (gfork_i_lib_handle_t *) in_handle;

    globus_mutex_lock(&handle->mutex);
    {
        result = globus_l_gfork_send(handle, pid, iov, iovc, cb, user_arg);
    }
    globus_mutex_unlock(&handle->mutex);

    return result;
}

static
int
gfork_l_activate()
{
    int                                 rc;
    globus_result_t                     res;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != 0)
    {
        goto error_activate;
    }

    if(!gfork_l_globals_set)
    {
        GlobusDebugInit(GLOBUS_GFORK,
            ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);


        gfork_i_state_init();

        res = globus_xio_stack_init(&gfork_i_file_stack, NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_file_stack;
        }
        res = globus_xio_driver_load("file", &gfork_i_file_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_file_driver;
        }
        res = globus_xio_stack_push_driver(
            gfork_i_file_stack, gfork_i_file_driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_file_push;
        }
        globus_xio_attr_init(&gfork_i_file_attr);

    }
    gfork_l_globals_set = GLOBUS_TRUE;

    return 0;
error_file_push:
    globus_xio_driver_unload(gfork_i_file_driver);
error_file_driver:
    globus_xio_stack_destroy(gfork_i_file_stack);
error_file_stack:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
error_activate:
    return 1;
}

static int
gfork_l_parent_activate()
{
    int                                 rc;

    rc = gfork_l_activate();
    if(rc != 0)
    {
        goto error_activate;
    }

    return 0;

error_activate:
    return 1;
}


static int
gfork_l_child_activate()
{
    int                                 rc;

    rc = gfork_l_activate();
    if(rc != 0)
    {
        goto error_activate;
    }

    return 0;

error_activate:
    return 1;
}

static int
gfork_l_deactivate()
{
    gfork_l_globals_set = GLOBUS_FALSE;

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}

globus_module_descriptor_t              globus_i_gfork_parent_module =
{
    "globus_gfork",
    gfork_l_parent_activate,
    gfork_l_deactivate,
    NULL,
    NULL,
    &local_version
};

globus_module_descriptor_t              globus_i_gfork_child_module =
{
    "globus_gfork",
    gfork_l_child_activate,
    gfork_l_deactivate,
    NULL,
    NULL,
    &local_version
};

