#include "globus_i_gwtftp.h"

typedef struct gwtftp_l_connection_s
{
    globus_xio_handle_t                 read_xio;
    globus_xio_handle_t                 write_xio;
    globus_fifo_t                       write_q;
    globus_bool_t                       outstanding_write;
    struct gwtftp_l_connection_pair_s * whos_my_daddy;
} gwtftp_l_connection_t;

typedef struct gwtftp_l_connection_pair_s
{
    gwtftp_l_connection_t               c2s;
    gwtftp_l_connection_t               s2c;
    globus_mutex_t                      mutex;
    int                                 ref;
    globus_bool_t                       closing;
    globus_bool_t                       data_listening;
    gwtftp_i_data_t *                   data;
} gwtftp_l_connection_pair_t;

typedef struct gwtftp_l_write_ent_s
{
    globus_byte_t *                     buffer;
    globus_size_t                       len;
} gwtftp_l_write_ent_t;

typedef globus_bool_t
(*gwtftp_l_msg_handler_t)(
    gwtftp_l_connection_t *             conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len);

static
globus_bool_t
gwtftp_l_quit(
    gwtftp_l_connection_t *             conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len);

typedef struct gwtftp_l_command_ent_s
{
    char *                              name;
    gwtftp_l_msg_handler_t              handler;
} gwtftp_l_command_ent_t;

static
globus_bool_t
gwtftp_l_route(
    gwtftp_l_connection_t *             conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len);

static
globus_bool_t
gwtftp_l_pasv227(
    gwtftp_l_connection_t *             conn,
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
globus_result_t
gwtftp_l_write(
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    gwtftp_l_connection_t *             conn);

static gwtftp_l_command_ent_t         gwtftp_l_cmd_table[] =
{
    {"227", gwtftp_l_pasv227},
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
    gwtftp_l_connection_pair_t *        conn_pair;
    gwtftp_l_connection_t *             c2s_conn;
    gwtftp_l_connection_t *             s2c_conn;

    conn_pair = (gwtftp_l_connection_pair_t *)
        globus_calloc(1, sizeof(gwtftp_l_connection_pair_t));
    if(conn_pair == NULL)
    {
        goto error_mem;
    }
    globus_mutex_init(&conn_pair->mutex, NULL);
    conn_pair->ref = 2;

    c2s_conn = &conn_pair->c2s;
    s2c_conn = &conn_pair->s2c;

    c2s_conn->whos_my_daddy = conn_pair;
    c2s_conn->read_xio = client_xio;
    c2s_conn->write_xio = server_xio;
    globus_fifo_init(&c2s_conn->write_q);

    s2c_conn->whos_my_daddy = conn_pair;
    s2c_conn->read_xio = server_xio;
    s2c_conn->write_xio = client_xio;
    globus_fifo_init(&s2c_conn->write_q);

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
    globus_free(conn_pair);
error_mem:

    return result;
}

static
void
gwtftp_l_cmd_error_data_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_l_connection_pair_t *        conn_pair;
    globus_bool_t                       free_it = GLOBUS_FALSE;

    conn_pair = (gwtftp_l_connection_pair_t *) user_arg;

    globus_mutex_lock(&conn_pair->mutex);
    {
        conn_pair->data_listening = GLOBUS_FALSE;
        conn_pair->ref--;
        if(conn_pair->ref == 0)
        {
            free_it = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&conn_pair->mutex);

    if(free_it)
    {
        globus_mutex_destroy(&conn_pair->mutex);
        globus_fifo_destroy(&conn_pair->c2s.write_q);
        globus_fifo_destroy(&conn_pair->s2c.write_q);
        globus_free(conn_pair);
    }
}


static
void
gwtftp_l_error_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_l_connection_pair_t *        conn_pair;
    globus_bool_t                       free_it = GLOBUS_FALSE;

    conn_pair = (gwtftp_l_connection_pair_t *) user_arg;

    globus_mutex_lock(&conn_pair->mutex);
    {
        conn_pair->ref--;
        if(conn_pair->ref == 0)
        {
            free_it = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&conn_pair->mutex);

    if(free_it)
    {
        globus_mutex_destroy(&conn_pair->mutex);
        globus_fifo_destroy(&conn_pair->c2s.write_q);
        globus_fifo_destroy(&conn_pair->s2c.write_q);
        globus_free(conn_pair);
    }
}

static
void
gwtftp_l_error(
    gwtftp_l_connection_pair_t *        conn_pair,
    globus_result_t                     result)
{
    if(conn_pair->closing)
    {
        gwtftp_i_log(FTP2GRID_LOG_INFO,
            "Error alread closed: 0x%x)\n", conn_pair);
        return;
    }

    conn_pair->closing = GLOBUS_TRUE;
    gwtftp_i_close(
        conn_pair->c2s.read_xio, gwtftp_l_error_close_cb, conn_pair);
    gwtftp_i_close(
        conn_pair->c2s.write_xio, gwtftp_l_error_close_cb, conn_pair);
    gwtftp_i_log(FTP2GRID_LOG_INFO,
        "Error on: 0x%x)\n", conn_pair);
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
        if(strncmp(gwtftp_l_cmd_table[i].name, name, 
            strlen(gwtftp_l_cmd_table[i].name)) == 0)
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
    gwtftp_l_connection_pair_t *        conn_pair;
    gwtftp_l_connection_t *             conn;
    gwtftp_l_write_ent_t *              write_ent; 

    conn = (gwtftp_l_connection_t *) user_arg;
    conn_pair = conn->whos_my_daddy;

    globus_free(buffer);
    globus_mutex_lock(&conn_pair->mutex);
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

            result = gwtftp_l_write(write_ent->buffer, write_ent->len, conn);
            free(write_ent);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_write;
            }
        }
    }
    globus_mutex_unlock(&conn_pair->mutex);

    return;
error_write:
error_callback:
    gwtftp_l_error(conn_pair, result);
    globus_mutex_unlock(&conn_pair->mutex);
}

/* just to have the writing and error handling in the same place
   called locked.
*/
static
globus_result_t
gwtftp_l_write(
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    gwtftp_l_connection_t *             conn)
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

    return GLOBUS_SUCCESS;

error_write:
    globus_free(buffer);
    return result;
}

static
char *
gwtftp_l_pasv_reply_to_cs(
    int                                 type,
    char *                              reply,
    globus_size_t                       len)
{
    int                                 sc;
    char *                              tmp_ptr;
    char *                              cs;
    int                                 host[4];
    int                                 hi;
    int                                 low;

    if(type == 1)
    {
        tmp_ptr = memchr(reply, '(', len);
        if(tmp_ptr == NULL)
        {
            goto error;
        }
        sc = sscanf(tmp_ptr, "(%d,%d,%d,%d,%d,%d)",
            &host[0],
            &host[1],
            &host[2],
            &host[3],
            &hi,
            &low);
        if(sc != 6)
        {
            goto error;
        }
        cs = globus_common_create_string("%d.%d.%d.%d:%d",
            host[0], host[1], host[2], host[3], hi*256+low);
    }
    else
    {
        goto error;
    }

    return cs;

error:

    return NULL;
}

static
char *
gwtftp_l_pasv_cs_to_reply(
    int                                 type,
    char *                              cs,
    globus_size_t                       len)
{
    char *                              reply;
    char *                              tmp_ptr;
    char *                              port_str;
    int                                 sc;
    int                                 port;
    int                                 i;
    int                                 hi;
    int                                 low;

    if(type == 1)
    {
        tmp_ptr = strchr(cs, ':');
        if(tmp_ptr == NULL)
        {
            return NULL;
        }
        *tmp_ptr = '\0';
        tmp_ptr++;
        port_str = tmp_ptr;
        sc = sscanf(port_str, "%d", &port);
        if(sc != 1)
        {
            return NULL;
        }
        hi = port / 256;
        low = port % 256;

        reply = globus_common_create_string(
            "227 Entering Passive Mode (%s,%d,%d)\r\n",
            cs, hi, low);

        for(i = 0; i < 3; i++)
        {
            tmp_ptr = strchr(reply, '.');
            if(tmp_ptr == NULL)
            {
                goto error_dots;
            }
            *tmp_ptr = ',';
        }

        return reply;
    }

    return NULL;
error_dots:
    globus_free(reply);
    return NULL;
}

static
globus_bool_t
gwtftp_l_pasv227(
    gwtftp_l_connection_t *             conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_result_t                     result;
    gwtftp_l_connection_pair_t *        conn_pair;
    char *                              passive_cs;
    char *                              cs;
    char *                              reply;
    globus_bool_t                       post;
    int                                 type = 1;

    conn_pair = conn->whos_my_daddy;

    cs = gwtftp_l_pasv_reply_to_cs(type, buffer, len);
    if(cs == NULL)
    {
        /* forward through */
    }

    /* create a listener */
    if(conn_pair->data_listening)
    {
        conn_pair->data_listening = GLOBUS_FALSE;
        /* close the open server */
        gwtftp_i_data_close(conn_pair->data);
    }

    /* parse passive response */
    result = gwtftp_i_data_new(
        &conn_pair->data,
        gwtftp_l_data_gsi_stack,
        gwtftp_l_data_tcp_stack,
        cs,
        &passive_cs,
        gwtftp_l_cmd_error_data_close_cb,
        conn_pair);
    globus_free(cs);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    conn_pair->ref++;
    conn_pair->data_listening = GLOBUS_TRUE;

    reply = gwtftp_l_pasv_cs_to_reply(
        type, passive_cs, strlen(passive_cs));
    globus_free(passive_cs);
    if(reply == NULL)
    {
        goto error;
    }
    /* form new message */
    post = gwtftp_l_route(&conn_pair->s2c, reply, strlen(reply));
    globus_free(buffer);

    return post;
error:
    globus_free(buffer);
    gwtftp_l_error(conn_pair, result);

    return GLOBUS_FALSE;
}

static
globus_bool_t
gwtftp_l_quit(
    gwtftp_l_connection_t *             conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_free(buffer);
    gwtftp_i_log(FTP2GRID_LOG_INFO, "Qutting\n");
    gwtftp_l_error(conn->whos_my_daddy, GLOBUS_SUCCESS);

    return GLOBUS_FALSE;
}

static
globus_bool_t
gwtftp_l_route(
    gwtftp_l_connection_t *             conn,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
    globus_result_t                     result;
    gwtftp_l_write_ent_t *              write_ent;
    char *                              forlog;

    forlog = malloc(len+1);
    memcpy(forlog, buffer, len);
    forlog[len] = '\0';
    gwtftp_i_log(FTP2GRID_LOG_INFO,
        "0x%x) Routing message: %s\n", conn, forlog);
    free(forlog);

    if(!conn->outstanding_write)
    {
        result = gwtftp_l_write(buffer, len, conn);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
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

    return GLOBUS_TRUE;
error:
    globus_free(buffer);
    gwtftp_l_error(conn->whos_my_daddy, result);
    return GLOBUS_FALSE;
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
    gwtftp_l_connection_t *             conn;
    char *                              tmp_ptr;
    gwtftp_l_command_ent_t *            cmd_ent;
    globus_bool_t                       post;
    gwtftp_l_connection_pair_t *        conn_pair;

    conn = (gwtftp_l_connection_t *) user_arg;
    conn_pair = conn->whos_my_daddy;

    globus_mutex_lock(&conn_pair->mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error_callback;
        }

        /* parse out the command */
        tmp_ptr = memchr(buffer, ' ', nbytes);
        len = tmp_ptr - (char *)buffer;
        /* Look up the command */
        cmd_ent = gwtftp_l_command_lookup(buffer, nbytes);

        post = cmd_ent->handler(conn, buffer, nbytes);

        if(post)
        {
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
    }
    globus_mutex_unlock(&conn_pair->mutex);

    return;

error_post:
error_callback:
    gwtftp_l_error(conn_pair, result);
    globus_mutex_unlock(&conn_pair->mutex);
}
