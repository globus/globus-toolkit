states
{
    GFS_XIO_CP_STATE_OPEN,
    GFS_XIO_CP_STATE_EOF,
    GFS_XIO_CP_STATE_ERROR
};

static
void
gfs_l_xio_cp_post_read(
    globus_xio_handle_t                 xio_h,
    gfs_l_xio_read_buffer_t *           read_buf);


static
void
gfs_l_xio_cp_close_os(
    void *                              user_arg)
{
    gfs_i_xio_cp_handle_t *             cp_h;

    cp_h = (gfs_i_xio_cp_handle_t *) user_arg;

    cp_h->complete_cb(cp_h, cp_h->user_arg, cp_h->err_obj);

    globus_fifo_destroy(cp_h->read_all_q);
    globus_fifo_destroy(cp_h->write_all_q);
    globus_fifo_destroy(cp_h->write_q);
    globus_mutex_destroy(cp_h->mutex);
    globus_free(cp_h);
}

static
void
gfs_l_xio_cp_write_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_bool_t                       close = GLOBUS_FALSE;

    globus_mutex_lock(&cp_h->mutex);
    {
        cp_h->write_handle_count--;

        /* if all of the reads are closed, close the writes */
        if(cp_h->write_handle_count == 0)
        {
            close = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&cp_h->mutex);

    if(close)
    {
        gfs_l_xio_cp_close_os(user_arg);
    }
}

static
void
gfs_l_xio_close_write_handles(
    gfs_i_xio_cp_handle_t *             cp_h)
{
    globus_xio_handle_t                 xio_h;

    while(!globus_fifo_empty(cp_h->write_all_q))
    {
        xio_h = (globus_xio_handle_t)
            globus_fifo_dequeue(cp_h->write_all_q);

        result = globus_xio_register_close(
            xio_h,
            NULL,
            gfs_l_xio_cp_write_close_cb,
            cp_h);
        if(result != GLOBUS_SUCCESS)
        {
            cp_h->write_handle_count--;
        }
    }

    if(cp_h->write_handle_count == 0)
    {
        globus_callback_register_oneshot(
            NULL,
            NULL,
            gfs_l_xio_cp_close_os,
            cp_h);
    }
}

static
void
gfs_l_xio_cp_read_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_mutex_lock(&cp_h->mutex);
    {
        cp_h->read_handle_count--;

        /* if all of the reads are closed, close the writes */
        if(cp_h->read_handle_count == 0)
        {
            gfs_l_xio_close_write_handles(cp_h);
        }
    }
    globus_mutex_unlock(&cp_h->mutex);
}

/*
 * called locked
 */
static
void
gfs_l_xio_cp_error(
    gfs_i_xio_cp_handle_t *             cp_h,
    globus_result_t                     result)
{
    globus_xio_handle_t                 xio_h;

    /* call this for shutdown in error cases, but some error cases will
        be a result of closing. */
    if(cp_h->state != GFS_CIO_CP_STATE_OPEN)
    {
        return;
    }

    cp_h->state = GFS_CIO_CP_STATE_ERROR;
    cp_h->err_obj = globus_error_get(result);

    while(!globus_fifo_empty(cp_h->read_all_q))
    {
        xio_h = (globus_xio_handle_t) globus_fifo_dequeue(cp_h->read_all_q);

        result = globus_xio_register_close(
            xio_h,
            NULL,
            gfs_l_xio_cp_read_close_cb,
            cp_h);
        if(result != GLOBUS_SUCCESS)
        {
            cp_h->read_handle_count--;
        }
    }

    if(cp_h->read_handle_count <= 0)
    {
        gfs_l_xio_close_write_handles(cp_h);
    }
}

static
void
gfs_l_xio_cp_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gfs_l_xio_read_buffer_t *           read_buf;
    gfs_i_xio_cp_handle_t *             cp_h;

    read_buf = (gfs_l_xio_read_buffer_t *) user_arg;
    cp_h = read_buf->whos_my_daddy;
    globus_free(read_buf);

    globus_mutex_lock(&cp_h->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        if(cp_h->state == GFS_CIO_CP_STATE_ERROR)
        {
            goto error;
        }

        /* if there are outstanding read buffers left use this handle
            to write one */
        if(!globus_fifo_empty(cp_h->read_buffer_q))
        {
            read_buf = (gfs_l_xio_read_buffer_t *)
                globus_fifo_dequeue(&cp_h->write_q);

            globus_xio_handle_cntl(
                read_buf->write_xio,
                NULL, /* QUERY MAYBE? */
                GLOBUS_XIO_SEEK,
                read_buf->offset);

            result = globus_xio_register_write(
                read_buf->write_xio,
                read_buf->buffer,
                read_buf->nbytes,
                read_buf->nbytes,
                NULL,
                gfs_l_xio_cp_write_cb,
                read_buf);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        /* if read buffers are gone and all read handles are gone
            then we are at eof and can start cloising the writes */
        else if(globus_fifo_empty(cp_h->read_all_q))
        {
            gfs_l_xio_close_write_handles(cp_h);
        }
        /* if still going but nothing to write just put this back in the
            queue */
        else
        {
            globus_fifo_enqueue(&cp_h->write_q, read_buf->write_xio);
        }
    }
    globus_mutex_unlock(&cp_h->mutex);

    if(cp_h->update_cb)
    {
        cp_h->update_cb(offset, nbytes, cp_h->user_arg);
    }

    return;

error:

    globus_free(read_buf);
    gfs_l_xio_cp_error(cp_h, result);
    globus_mutex_unlock(&cp_h->mutex);
}

static
void
gfs_l_xio_cp_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gfs_l_xio_read_buffer_t *           read_buf;
    gfs_i_xio_cp_handle_t *             cp_h;

    read_buf = (gfs_l_xio_read_buffer_t *) user_arg;
    cp_h = read_buf->whos_my_daddy;

    globus_mutex_lock(&cp_h->mutex);
    {
        read_buf->nbytes = nbytes;
        if(result != GLOBUS_SUCCESS)
        {
            if(eof)
            {
                read_buf->eof = GLOBUS_TRUE;
            }
            else
            {
                /* what if this is just EOF */
                goto error;
            }
        }
        /* it is possible to get here in the CLOSING state without an error */
        if(cp_h->state == GFS_CIO_CP_STATE_ERROR)
        {
            goto error;
        }

        /* XXX need to get an offset for this buffer */
        read_buf->nbytes = nbytes;
        result = globus_xio_data_descriptor_cntl(
            data_desc,
            NULL,
            GLOBUS_XIO_DD_GET_OFFSET,
            &offset);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        read_buf->offset = offset;

        if(!globus_fifo_empty(cp_h->write_q))
        {
            read_buf->write_xio = 
                (globus_xio_handle_t) globus_fifo_dequeue(cp_h->write_q);
            result = globus_xio_handle_cntl(
                read_buf->write_xio,
                GLOBUS_XIO_QUERY,
                GLOBUS_XIO_SEEK,
                read_buf->offset);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }

            result = globus_xio_register_write(
                read_buf->write_xio,
                read_buf->buffer,
                read_buf->nbytes,
                read_buf->nbytes,
                NULL,
                gfs_l_xio_cp_write_cb,
                read_buf);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        else
        {
            /* stick this one in the queue */
            globus_fifo_enqueue(&cp_h->read_buffer_q, read_buf);
        }

        if(!eof)
        {
            /* make and post a new one */
            read_buf = (gfs_l_xio_read_buffer_t *)
                globus_calloc(sizeof(gfs_l_xio_read_buffer_t)+block_size, 1);
            read_buf->block_size = cp_h->block_size;
            read_buf->whos_my_daddy = cp_h;
            /* do this last since it can inspire the CLOSING state */
            gfs_l_xio_cp_post_read(xio_h, read_buf);
        }
        else
        {
            /* remove it from close q and close */
            globus_fifo_remove(cp_h->read_all_q, read_buf->read_xio);
            result = globus_xio_register_close(
                read_buf->read_xio,
                NULL,
                gfs_l_xio_cp_close_cb,
                cp_h);
            if(result != GLOBUS_SUCCESS)
            {
                cp_h->read_handle_count--;
            }
            if(cp_h->read_handle_count <= 0)
            {
                gfs_l_xio_close_write_handles(cp_h);
            }
        }
    }
    globus_mutex_unlock(&cp_h->mutex);

    return;

error:
    globus_free(read_buf);
    gfs_l_xio_cp_error(cp_h, result);
    globus_mutex_unlock(&cp_h->mutex);
}

static
void
gfs_l_xio_cp_post_read(
    globus_xio_handle_t                 xio_h,
    gfs_l_xio_read_buffer_t *           read_buf)
{
    globus_result_t                     result;

    read_buf->read_xio = xio_h;
    result = globus_xio_register_read(
        xio_h,
        read_buf->buffer,
        read_buf->block_size,
        read_buf->block_size,
        gfs_l_xio_cp_read_cb,
        NULL,
        read_buf);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;

error:
    globus_free(read_buf);
    gfs_l_xio_cp_error(cp_h, result);
    globus_mutex_unlock(&cp_h->mutex);
}

globus_result_t
gfs_i_xio_cp_start(
    gfs_i_xio_cp_handle_t **            cp_h_out,
    globus_fifo_t *                     read_handle_fifo,
    globus_fifo_t *                     write_handle_fifo,
    globus_callback_func_t              complete_cb,
    globus_callback_func_t              update_cb,
    void *                              user_arg)
{
    globus_fifo_t *                     read_q;
    gfs_i_xio_cp_handle_t *             cp_h;

    cp_h = (gfs_i_xio_cp_handle_t *)
        globus_calloc(1, sizeof(gfs_i_xio_cp_handle_t));
    cp_h->read_all_q = globus_fifo_copy(net_handle_fifo);
    cp_h->write_all_q = globus_fifo_copy(net_handle_fifo);
    cp_h->write_q = globus_fifo_copy(net_handle_fifo);
    globus_fifo_init(&cp_h->read_buffer_q);
    cp_h->block_size = block_size;
    cp_h->cb = complete_cb;
    cp_h->user_arg = user_arg;
    globus_mutex_init(&cp_h->mutex, NULL);
    cp_h->state = GFS_XIO_CP_STATE_OPEN;
    read_q = globus_fifo_copy(net_handle_fifo);

    cp_h->read_handle_count = globus_fifo_size(cp_h->read_all_q);
    cp_h->write_handle_count = globus_fifo_size(cp_h->write_all_q);

    *cp_h_out = cp_h;

    globus_mutex_lock(&cp_h->mutex);
    {
        while(!globus_fifo_empty(read_q))
        {
            xio_h = (globus_xio_handle_t) globus_fifo_dequeue(cp_h->read_q);

            read_buf = (gfs_l_xio_read_buffer_t *)
                globus_calloc(sizeof(gfs_l_xio_read_buffer_t)+block_size, 1);
            read_buf->block_size = block_size;
            read_buf->whos_my_daddy = cp_h;

            gfs_l_xio_cp_post_read(xio_h, read_buf);
        }
    }
    globus_mutex_unlock(&cp_h->mutex);

    globus_fifo_destroy(read_q);

    return GLOBUS_SUCCESS;
}
