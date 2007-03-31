#include "globus_i_gwtftp.h"

typedef struct gwtftp_l_connection_s
{
    globus_xio_handle_t                 read_xio;
    globus_xio_handle_t                 write_xio;
    globus_fifo_t                       write_q;
    globus_bool_t                       outstanding_write;
    globus_mutex_t                      mutex;
} gwtftp_l_connection_t;

typedef struct gwtftp_l_write_ent_s
{
    globus_byte_t *                     buffer;
    globus_size_t                       len;
} gwtftp_l_write_ent_t;

typedef void
(*gwtftp_l_msg_handler_t)(
    gwtftp_l_connection_t *           conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len);

static
void
gwtftp_l_quit(
    gwtftp_l_connection_t *           conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len);

typedef struct gwtftp_l_command_ent_s
{
    char *                              name;
    gwtftp_l_msg_handler_t            handler;
} gwtftp_l_command_ent_t;

static
void
gwtftp_l_route(
    gwtftp_l_connection_t *           conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len);

static
void
gwtftp_l_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
gwtftp_l_write(
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    gwtftp_l_connection_t *           conn);

static gwtftp_l_command_ent_t         gwtftp_l_cmd_table[] =
{
    {"221", gwtftp_l_quit},
    {NULL, gwtftp_l_route}
};


/*
 *  for 2 RDONLY->WRONLY pairs.  Treat the seperately and start reading
 *  on both.
 */
globus_result_t
globus_gwtftp_new_session(
    globus_xio_handle_t                 client_xio,
    globus_xio_handle_t                 server_xio)
{
    globus_result_t                     result;
    gwtftp_l_connection_t *           c2s_conn;
    gwtftp_l_connection_t *           s2c_conn;

    c2s_conn = (gwtftp_l_connection_t *)
        globus_calloc(1, sizeof(gwtftp_l_connection_t));
    if(c2s_conn == NULL)
    {
        goto error_client_mem;
    }
    s2c_conn = (gwtftp_l_connection_t *)
        globus_calloc(1, sizeof(gwtftp_l_connection_t));
    if(s2c_conn == NULL)
    {
        goto error_server_mem;
    }

    c2s_conn->read_xio = client_xio;
    c2s_conn->write_xio = server_xio;
    globus_fifo_init(&c2s_conn->write_q);
    globus_mutex_init(&c2s_conn->mutex, NULL);

    s2c_conn->read_xio = server_xio;
    s2c_conn->write_xio = client_xio;
    globus_fifo_init(&s2c_conn->write_q);
    globus_mutex_init(&s2c_conn->mutex, NULL);

    result = globus_xio_register_read(
        c2s_conn->read_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_read_cb,
        c2s_conn);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_client_post;
    }

    result = globus_xio_register_read(
        s2c_conn->read_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_read_cb,
        s2c_conn);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_post;
    }

    return GLOBUS_SUCCESS;

error_server_post:
error_client_post:
    globus_free(s2c_conn);
error_server_mem:
    globus_free(c2s_conn);
error_client_mem:

    return result;
}

/* called locked */
static
void
gwtftp_l_error(
    gwtftp_l_connection_t *           conn,
    globus_result_t                     result)
{
    gwtftp_i_close(conn->read_xio);
    gwtftp_i_close(conn->write_xio);
    gwtftp_i_log(FTP2GRID_LOG_INFO,
        "Error on: 0x%x)\n", conn);
}

static
gwtftp_l_command_ent_t *
gwtftp_l_command_lookup(
    globus_byte_t *                     name, 
    globus_size_t                       len)
{
    int                                 i;

    for(i = 0; gwtftp_l_cmd_table[i].name != NULL; i++)
    {
        if(strncmp(gwtftp_l_cmd_table[i].name, name, len) == 0)
        {
            return &gwtftp_l_cmd_table[i];
        }
    }
    return &gwtftp_l_cmd_table[i];
}

static
void
gwtftp_l_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_connection_t *           conn;
    gwtftp_l_write_ent_t *            write_ent; 

    conn = (gwtftp_l_connection_t *) user_arg;

    globus_free(buffer);
    globus_mutex_lock(&conn->mutex);
    {
        conn->outstanding_write = GLOBUS_FALSE;

        if(result != GLOBUS_SUCCESS)
        {
            goto error_callback;
        }

        if(!globus_fifo_empty(&conn->write_q))
        {
            write_ent = (gwtftp_l_write_ent_t *) 
                globus_fifo_dequeue(&conn->write_q);

            gwtftp_l_write(write_ent->buffer, write_ent->len, conn);

            free(write_ent);
        }
    }
    globus_mutex_unlock(&conn->mutex);

    return;

error_callback:
    gwtftp_l_error(conn, result);
    globus_mutex_unlock(&conn->mutex);
}

/* just to have the writing and error handling in the same place
   called locked.
*/
static
void
gwtftp_l_write(
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    gwtftp_l_connection_t *           conn)
{
    globus_result_t                     result;

    /* send it write here */
    result = globus_xio_register_write(
        conn->write_xio,
        buffer,
        len,
        len,
        NULL,
        gwtftp_l_write_cb,
        conn);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_write;
    }
    conn->outstanding_write = GLOBUS_TRUE;

    return;

error_write:
    gwtftp_l_error(conn, result);
}


/* this handler just sends the command along the other handler

    called locked
 */

static
void
gwtftp_l_quit(
    gwtftp_l_connection_t *           conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    gwtftp_i_log(FTP2GRID_LOG_INFO, "Qutting\n");
    gwtftp_l_error(conn, GLOBUS_SUCCESS);
}

static
void
gwtftp_l_route(
    gwtftp_l_connection_t *           conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_result_t                     result;
    gwtftp_l_write_ent_t *            write_ent;
    char *                              forlog;

    forlog = malloc(len+1);
    memcpy(forlog, buffer, len);
    forlog[len] = '\0';
    gwtftp_i_log(FTP2GRID_LOG_INFO,
        "0x%x) Routing message: %s\n", conn, forlog);
    free(forlog);

    if(!conn->outstanding_write)
    {
        gwtftp_l_write(buffer, len, conn);
    }
    else
    {
        write_ent = (gwtftp_l_write_ent_t *)
            globus_calloc(1, sizeof(gwtftp_l_write_ent_t));
        if(write_ent == NULL)
        {
            goto error;
        }

        write_ent->buffer = buffer;
        write_ent->len = len;

        globus_fifo_enqueue(&conn->write_q, write_ent);
    }

    return;
error:
    gwtftp_l_error(conn, result);
}

/* 
 *  read message from client
 *  look up the command type in the table
 *  execute the hanlder in the table
 *  post for another read
 */
static
void
gwtftp_l_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_connection_t *           conn;
    char *                              tmp_ptr;
    gwtftp_l_command_ent_t *          cmd_ent;

    conn = (gwtftp_l_connection_t *) user_arg;

    globus_mutex_lock(&conn->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error_callback;
        }

        /* parse out the command */
        tmp_ptr = memchr(buffer, ' ', nbytes);
        len = tmp_ptr - (char *)buffer;
        /* Look up the command */
        cmd_ent = gwtftp_l_command_lookup(buffer, len);

        cmd_ent->handler(conn, buffer, nbytes);

        result = globus_xio_register_read(
            conn->read_xio,
            FAKE_BUFFER,
            FAKE_BUFFER_LENGTH,
            FAKE_BUFFER_LENGTH,
            NULL,
            gwtftp_l_read_cb,
            conn);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_post;
        }
    }
    globus_mutex_unlock(&conn->mutex);

    return;

error_post:
error_callback:
    gwtftp_l_error(conn, result);
    globus_mutex_unlock(&conn->mutex);
}
