#include "globus_i_gwtftp.h"

typedef struct gwtftp_l_server_session_s
{
    globus_xio_handle_t                 client_xio;
    globus_xio_handle_t                 server_xio;
    globus_fifo_t *                     openning_command_q;
    globus_byte_t *                     greeting;
    globus_size_t                       greeting_len; 
} gwtftp_l_server_session_t;

static char * gwtftp_l_server_user_msg = "USER :globus-mapping:\r\n";
static char * gwtftp_l_server_pass_msg = "PASS whatever\r\n";
static globus_fifo_t                    gwtftp_l_open_cmd_q;


static
void
gwtftp_l_write_next_opening_cmd(
    gwtftp_l_server_session_t *       session);

static
void
gwtftp_l_write_pass_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
gwtftp_l_read_opening_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    buffer[len - 2] = '\0';
    gwtftp_i_log(FTP2GRID_LOG_INFO, "%s\n", buffer);
    free(buffer);

    gwtftp_l_write_next_opening_cmd(session);
}

static
void
gwtftp_l_write_opening_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    result = globus_xio_register_read(
        session->server_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_read_opening_reply_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    return;
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Error sending openning commands, closing\n");
    gwtftp_i_close(session->client_xio,  NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_free(session->greeting);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);

}

static
void
gwtftp_l_write_next_opening_cmd(
    gwtftp_l_server_session_t *       session)
{
    globus_result_t                     result;
    char *                              msg;

    if(globus_fifo_empty(session->openning_command_q))
    {
        result = globus_xio_register_write(
            session->client_xio,
            session->greeting,
            session->greeting_len,
            session->greeting_len,
            NULL,
            gwtftp_l_write_pass_reply_cb,
            session);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        msg = (char *) globus_fifo_dequeue(session->openning_command_q);
        result = globus_xio_register_write(
            session->server_xio,
            msg,
            strlen(msg),
            strlen(msg),
            NULL,
            gwtftp_l_write_opening_cb,
            session);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    return;
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Error sending openning commands, closing: %s\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_free(session->greeting);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);

}

static
void
gwtftp_l_write_pass_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_gwtftp_new_session(
        session->client_xio, session->server_xio);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    globus_free(session->greeting);
    free(session);
    return;

error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Writting PASS reply to client with error, closing:\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    globus_free(session->greeting);
    free(session);
}

static
void
gwtftp_l_server_read_pass_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    session->greeting = buffer;
    session->greeting_len = nbytes;

    gwtftp_l_write_next_opening_cmd(session);
    return;

error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Reading PASS reply from server with error, closing\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
}

static
void
gwtftp_l_server_write_pass_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
   /* write user */
    result = globus_xio_register_read(
        session->server_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_server_read_pass_reply_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Writting PASS to server with error, closing\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
}

/* ignore bad replies and jsut write the next message */
static
void
gwtftp_l_server_read_user_reply_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    /* maybe log the buffer */
    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
   /* write user */
    result = globus_xio_register_write(
        session->server_xio,
        gwtftp_l_server_pass_msg,
        strlen(gwtftp_l_server_pass_msg),
        strlen(gwtftp_l_server_pass_msg),
        NULL,
        gwtftp_l_server_write_pass_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_write;
    }
    globus_free(buffer);

    return;
error_write:
    globus_free(buffer);
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Reading USER reply from server with error, closing\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
}

static
void
gwtftp_l_server_write_user_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
   /* write user */
    result = globus_xio_register_read(
        session->server_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_server_read_user_reply_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Writing user to server with error, closing\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
}

/* ignore bad replies and jsut write the next message */
static
void
gwtftp_l_server_read_banner_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    buffer[len -2] = '\0';
    gwtftp_i_log(FTP2GRID_LOG_INFO,"Banner %s\n", buffer);
    free(buffer);

    session->server_xio = handle;

    /* write user */
    result = globus_xio_register_write(
        session->server_xio,
        gwtftp_l_server_user_msg,
        strlen(gwtftp_l_server_user_msg),
        strlen(gwtftp_l_server_user_msg),
        NULL,
        gwtftp_l_server_write_user_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Reading banner with error, closing\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
}

static
void
gwtftp_l_server_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_l_server_session_t *         session;

    session = (gwtftp_l_server_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    gwtftp_i_log(FTP2GRID_LOG_INFO, "Connected to server\n");

    session->server_xio = handle;

    /* write user */
    result = globus_xio_register_read(
        session->server_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_server_read_banner_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;
error:
    gwtftp_i_log_result(FTP2GRID_LOG_WARN, result,
        "Connected to server with error, closing:\n");
    gwtftp_i_close(session->client_xio, NULL, NULL);
    gwtftp_i_close(session->server_xio, NULL, NULL);
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
}


globus_result_t
gwtftp_i_server_conn_open(
    globus_xio_handle_t                 server_xio,
    char *                              cs,
    globus_xio_handle_t                 client_xio)
{
    globus_result_t                     result;
    gwtftp_l_server_session_t *       session;

    gwtftp_i_log(FTP2GRID_LOG_INFO,
        "Connecting to server: %s\n", cs);

    session = globus_malloc(sizeof(gwtftp_l_server_session_t));
    if(session == NULL)
    {
        result = 0x1;
        goto error_allo;
    }
    session->client_xio = client_xio;
    session->server_xio = server_xio;
    session->openning_command_q = globus_fifo_copy(&gwtftp_l_open_cmd_q);

    result = globus_xio_register_open(
        server_xio,
        cs,
        NULL,
        gwtftp_l_server_open_cb,
        session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    return GLOBUS_SUCCESS;

error_open:
    globus_fifo_destroy(session->openning_command_q);
    globus_free(session->openning_command_q);
    free(session);
error_allo:
    return result;
}

void
gwtftp_i_server_init()
{
    globus_fifo_init(&gwtftp_l_open_cmd_q);
    globus_fifo_enqueue(&gwtftp_l_open_cmd_q, "DCAU N\r\n");
    globus_fifo_enqueue(&gwtftp_l_open_cmd_q, "STAT\r\n");
}
