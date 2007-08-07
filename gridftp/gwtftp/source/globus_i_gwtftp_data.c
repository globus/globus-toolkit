#include "globus_i_gwtftp.h"

#define GWTFTP_BUFFER_SIZE              (1024*1024)

enum
{
    GWTFTP_DATA_STATE_NONE,
    GWTFTP_DATA_STATE_ACCEPTING,
    GWTFTP_DATA_STATE_SEVER_CLOSING,
    GWTFTP_DATA_STATE_PASSIVE_OPENING,
    GWTFTP_DATA_STATE_ACTIVE_OPENING,
    GWTFTP_DATA_STATE_OPEN,
    GWTFTP_DATA_STATE_CLOSING
};

static
void
gwtftp_l_data_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

/* closing logic */

static
void
gwtftp_l_data_passive_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    data_h->close_cb(handle, data_h->error_result, data_h->user_arg);

    if(data_h->active_cs)
    {
        globus_free(data_h->active_cs);
    }
    globus_free(data_h->active_buffer);
    globus_free(data_h->passive_buffer);
    globus_free(data_h);
}

static
void
gwtftp_l_data_server_error_close_cb(
    globus_xio_server_t                 server,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    gwtftp_l_data_passive_close_cb(NULL, data_h->error_result, user_arg);
}

static
void
gwtftp_l_data_active_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    result = globus_xio_register_close(
        data_h->passive_xio,
        NULL,
        gwtftp_l_data_passive_close_cb,
        data_h);
    if(result != GLOBUS_SUCCESS)
    {
        /* goto it directly */
        gwtftp_l_data_passive_close_cb(data_h->passive_xio, result, data_h);
    }
}

void
gwtftp_l_data_close(
    gwtftp_i_data_t *                   data_h)
{
    globus_xio_callback_t               close_cb = NULL;
    globus_result_t                     result;

    globus_mutex_lock(&data_h->mutex);
    {
        switch(data_h->state)
        {
            case GWTFTP_DATA_STATE_ACCEPTING:
                result = globus_xio_server_register_close(
                    data_h->server,
                    gwtftp_l_data_server_error_close_cb,
                   data_h);
                if(result != GLOBUS_SUCCESS)
                {
                    close_cb =  gwtftp_l_data_passive_close_cb;
                }
                data_h->state = GWTFTP_DATA_STATE_CLOSING;

                break;

            case GWTFTP_DATA_STATE_PASSIVE_OPENING:
            case GWTFTP_DATA_STATE_SEVER_CLOSING:
                result = globus_xio_register_close(
                    data_h->passive_xio,
                    NULL,
                    gwtftp_l_data_passive_close_cb,
                    data_h);
                if(result != GLOBUS_SUCCESS)
                {
                    close_cb =  gwtftp_l_data_passive_close_cb;
                }
                data_h->state = GWTFTP_DATA_STATE_CLOSING;
                break;

            case GWTFTP_DATA_STATE_OPEN:
            case GWTFTP_DATA_STATE_ACTIVE_OPENING:

                result = globus_xio_register_close(
                    data_h->active_xio,
                    NULL,
                    gwtftp_l_data_active_close_cb,
                    data_h);
                if(result != GLOBUS_SUCCESS)
                {
                    close_cb =  gwtftp_l_data_active_close_cb;
                }
                data_h->state = GWTFTP_DATA_STATE_CLOSING;
                break;

            case GWTFTP_DATA_STATE_CLOSING:
                break;
        }
    }
    globus_mutex_unlock(&data_h->mutex);

    if(close_cb)
    {
        close_cb(NULL, result, data_h);
    }
}

void
gwtftp_i_data_close_oneshot_cb(
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    globus_mutex_lock(&data_h->mutex);
    {
        gwtftp_l_data_close(data_h);
    }
    globus_mutex_unlock(&data_h->mutex);
}

void
gwtftp_i_data_close(
    gwtftp_i_data_t *                   data_h)
{
    globus_callback_register_oneshot(
        NULL,
        NULL,
        gwtftp_i_data_close_oneshot_cb,
        data_h);
}


/* data logic */
static
void
gwtftp_l_data_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_xio_handle_t                 xio_h;
    gwtftp_i_data_t *                   data_h;
    globus_byte_t *                     buf;

    data_h = (gwtftp_i_data_t *) user_arg;
    globus_mutex_lock(&data_h->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        /* determine the handle */
        if(data_h->active_xio == handle)
        {
            xio_h = data_h->passive_xio;
            buf = data_h->passive_buffer;
        }
        else if(data_h->passive_xio == handle)
        {
            xio_h = data_h->active_xio;
            buf = data_h->active_buffer;
        }

        result = globus_xio_register_read(
            xio_h,
            buf,
            data_h->buffer_size,
            data_h->buffer_size,
            NULL,
            gwtftp_l_data_read_cb,
            data_h);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_post;
        }
    }
    globus_mutex_unlock(&data_h->mutex);
    return;
error_post:
error:
    data_h->error_result = result;
    gwtftp_l_data_close(data_h);
    globus_mutex_unlock(&data_h->mutex);
}

static
void
gwtftp_l_data_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_xio_handle_t                 xio_h;
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    globus_mutex_lock(&data_h->mutex);
    {
        if(result != GLOBUS_SUCCESS && nbytes <= 0)
        {
            /* error on read is fine, could be just eof */
            goto error;
        }

        /* determine the handle */
        if(data_h->active_xio == handle)
        {
            xio_h = data_h->passive_xio;
        }
        else
        {
            xio_h = data_h->active_xio;
        }

        result = globus_xio_register_write(
            xio_h,
            buffer,
            nbytes,
            nbytes,
            NULL,
            gwtftp_l_data_write_cb,
            data_h);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_post;
        }
    }
    globus_mutex_unlock(&data_h->mutex);
    return;
error_post:
error:
    data_h->error_result = result;
    gwtftp_l_data_close(data_h);
    globus_mutex_unlock(&data_h->mutex);
}

/* establishment logic */
static
void
gwtftp_l_data_active_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    globus_mutex_lock(&data_h->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        data_h->state = GWTFTP_DATA_STATE_OPEN;

        /* start the works */
        result = globus_xio_register_read(
            data_h->active_xio,
            data_h->active_buffer,
            data_h->buffer_size,
            data_h->buffer_size,
            NULL,
            gwtftp_l_data_read_cb,
            data_h);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        result = globus_xio_register_read(
            data_h->passive_xio,
            data_h->passive_buffer,
            data_h->buffer_size,
            data_h->buffer_size,
            NULL,
            gwtftp_l_data_read_cb,
            data_h);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_mutex_unlock(&data_h->mutex);
    return;
error:
    data_h->error_result = result;
    gwtftp_l_data_close(data_h);
    globus_mutex_unlock(&data_h->mutex);
}

static
void
gwtftp_l_data_passive_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;
    globus_xio_attr_t                   xio_attr;

    data_h = (gwtftp_i_data_t *) user_arg;

    globus_mutex_lock(&data_h->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error_param;
        }

        result = globus_xio_handle_create(
            &data_h->active_xio, data_h->active_stack);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_create;
        }

        globus_xio_attr_init(&xio_attr);
        /* ignore return.  allow gsi driver to not b e on stack */ 
        globus_xio_attr_cntl(xio_attr, gwtftp_l_gsi_driver,
            GLOBUS_XIO_GSI_SET_AUTHORIZATION_MODE,
            GLOBUS_XIO_GSI_SELF_AUTHORIZATION);
        globus_xio_attr_cntl(xio_attr, gwtftp_l_gsi_driver,
            GLOBUS_XIO_GSI_SET_DELEGATION_MODE,
            GLOBUS_XIO_GSI_DELEGATION_MODE_NONE);
        globus_xio_attr_cntl(xio_attr, gwtftp_l_gsi_driver,
            GLOBUS_XIO_GSI_SET_PROTECTION_LEVEL,
            GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE);
        result = globus_xio_register_open(
            data_h->active_xio,
            data_h->active_cs,
            xio_attr,
            gwtftp_l_data_active_open_cb,
            data_h);
        globus_xio_attr_destroy(xio_attr);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_open;
        }
        data_h->state = GWTFTP_DATA_STATE_ACTIVE_OPENING;
    }
    globus_mutex_unlock(&data_h->mutex);

    return;
error_open:
    globus_xio_register_close(data_h->active_xio, NULL, NULL, NULL);
error_create:
error_param:
    data_h->error_result = result;
    gwtftp_l_data_close(data_h);
    globus_mutex_unlock(&data_h->mutex);
}

static
void
gwtftp_l_data_server_close_cb(
    globus_xio_server_t                 server,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;
    globus_result_t                     result;

    data_h = (gwtftp_i_data_t *) user_arg;

    globus_mutex_lock(&data_h->mutex);
    {
        data_h->state = GWTFTP_DATA_STATE_PASSIVE_OPENING;
        result = globus_xio_register_open(
            data_h->passive_xio,
            NULL,
            NULL,
            gwtftp_l_data_passive_open_cb,
            data_h);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_open;
        }
    }
    globus_mutex_unlock(&data_h->mutex);

    return;
error_open:
    data_h->error_result = result;
    gwtftp_l_data_close(data_h);
    globus_mutex_unlock(&data_h->mutex);
}

static
void
gwtftp_l_data_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;

    data_h = (gwtftp_i_data_t *) user_arg;

    globus_mutex_lock(&data_h->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        else
        {
            data_h->state = GWTFTP_DATA_STATE_SEVER_CLOSING;
            data_h->passive_xio = handle;
            result = globus_xio_server_register_close(
                data_h->server,
                gwtftp_l_data_server_close_cb,
                data_h);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
    }
    globus_mutex_unlock(&data_h->mutex);

    return;
error:
    data_h->error_result = result;
    gwtftp_l_data_close(data_h);
    globus_mutex_unlock(&data_h->mutex);
}

globus_result_t
gwtftp_i_data_new(
    gwtftp_i_data_t **                  out_handle,
    globus_xio_stack_t                  active_stack,
    globus_xio_stack_t                  passive_stack,
    char *                              active_cs,
    char **                             out_passive_cs,
    globus_xio_callback_t               close_cb,
    void *                              user_arg)
{
    gwtftp_i_data_t *                   data_h;
    globus_result_t                     result;
    char *                              cs;

    data_h = (gwtftp_i_data_t *)globus_calloc(1, sizeof(gwtftp_i_data_t));
    if(data_h == NULL)
    {
        goto error_mem;
    }
    data_h->close_cb = close_cb;
    data_h->user_arg = user_arg;
    data_h->state = GWTFTP_DATA_STATE_ACCEPTING;
    data_h->buffer_size = GWTFTP_BUFFER_SIZE;
    data_h->active_buffer = globus_malloc(data_h->buffer_size);
    data_h->passive_buffer = globus_malloc(data_h->buffer_size);
    data_h->active_stack = active_stack;
    data_h->passive_stack = passive_stack;

    result = globus_xio_server_create(
        &data_h->server, NULL, data_h->passive_stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_create;
    }

    result = globus_xio_server_cntl(
        data_h->server,
        gwtftp_l_tcp_driver,
        GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
        &cs);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_cntl;
    }

    result = globus_xio_server_register_accept(
        data_h->server,
        gwtftp_l_data_accept_cb,
        data_h);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_accept;
    }
    data_h->active_cs = strdup(active_cs);
    *out_passive_cs = cs;
    *out_handle = data_h;

    return GLOBUS_SUCCESS;

error_accept:
    globus_xio_server_register_close(data_h->server, NULL, NULL);
    globus_free(cs);
error_cntl:
error_create:
    globus_free(data_h);
error_mem:

    return result;
}
