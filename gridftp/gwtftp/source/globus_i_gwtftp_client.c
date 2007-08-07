#include "globus_i_gwtftp.h"

typedef struct gwtftp_l_client_session_s
{
    globus_xio_data_callback_t          read_cb;
    char *                              user_buffer;
    char *                              cs;
    char *                              subject;
    char *                              pw;
    globus_xio_handle_t                 client_xio;
} gwtftp_l_client_session_t;

static
void
gwtftp_l_client_badcmd_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

globus_byte_t                           gwtftp_l_fake_buf[1];

/* funcitons below decide if the client is valid */
static
void
gwtftp_l_client_read_pass_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_client_session_t *       auth_session;
    char *                              tmp_ptr;
    char *                              buf;
    char *                              pw;

    auth_session = (gwtftp_l_client_session_t *) user_arg;
    buf = (char *) buffer;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    /* parse out and validate user info */

    tmp_ptr = memchr(buf, ' ', nbytes);
    if(strncasecmp("PASS", buf, tmp_ptr - buf) == 0)
    {
        /* go past all the spaces */
        while(*tmp_ptr == ' ' && tmp_ptr - buf < nbytes) tmp_ptr++;
        pw = tmp_ptr;
        /* set the \r to a \0 */
        buf[len - 2] = '\0';

        /* once we call this we are done caring about this handle.  the
           remaining code will have the worry of setting it up with a
           server side handle */
        gwtftp_i_authorized_user(
            auth_session->client_xio,
            auth_session->cs,
            pw);
        free(auth_session->user_buffer);
        free(auth_session);
        free(buffer);
    }
    else
    {
        free(buffer);
        auth_session->read_cb = gwtftp_l_client_read_pass_cb;
        /* pass this callback pointer just to same repeated code
            between this and pass error msgs */
        result = globus_xio_register_write(
            handle,
            FTP_530_MSG,
            FTP_530_MSG_LENGTH,
            FTP_530_MSG_LENGTH,
            NULL,
            gwtftp_l_client_badcmd_write_cb,
            auth_session);        
        if(result != GLOBUS_SUCCESS)
        {
            goto error_write;
        }
    }
    return;

error_write:
error:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session->user_buffer);
    free(auth_session);
}

static
void
gwtftp_l_user_reply_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_client_session_t *       auth_session;

    auth_session = (gwtftp_l_client_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* post read for USER command */
    result = globus_xio_register_read(
        handle,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_client_read_pass_cb,
        auth_session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;
error:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session->user_buffer);
    free(auth_session);
}

static
void
gwtftp_l_client_badcmd_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_client_session_t *       auth_session;

    auth_session = (gwtftp_l_client_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* post read for USER command */
    result = globus_xio_register_read(
        handle,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        auth_session->read_cb,
        auth_session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;
error:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session);
}

static
void
gwtftp_l_client_read_user_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    char *                              tmp_ptr;
    char *                              buf;
    gwtftp_l_client_session_t *       auth_session;
    globus_bool_t                       ok = GLOBUS_FALSE;

    buf = (char *) buffer;
    auth_session = (gwtftp_l_client_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    auth_session->user_buffer = buffer;

    /* set the \r to a \0 */
    buf[nbytes - 2] = '\0';
    gwtftp_i_log(FTP2GRID_LOG_INFO, "Received user cmd: %s\n", buf);

    /* parse out and validate user info */

    ok = GLOBUS_TRUE;
    tmp_ptr = memchr(buf, ' ', nbytes);
    if(strncasecmp("USER", buf, tmp_ptr - buf) == 0)
    {
        /* go past all the spaces */
        while(*tmp_ptr == ' ' && tmp_ptr - buf < nbytes) tmp_ptr++;
        auth_session->cs = tmp_ptr;

        if(strlen(auth_session->cs) <= 0)
        {
            ok = GLOBUS_FALSE;
        }
    }
    else
    {
        ok = GLOBUS_FALSE;
    }

    if(ok)
    {
        result = globus_xio_register_write(
            handle,
            FTP_331_MSG,
            FTP_331_MSG_LENGTH,
            FTP_331_MSG_LENGTH,
            NULL,
            gwtftp_l_user_reply_write_cb,
            auth_session);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_write;
        }
    }
    else
    {
        gwtftp_i_log(FTP2GRID_LOG_INFO, "Rejecting user cmd: %s\n", buf);
        auth_session->read_cb = gwtftp_l_client_read_user_cb;
        /* pass this callback pointer just to same repeated code
            between this and pass error msgs */
        result = globus_xio_register_write(
            handle,
            FTP_530_MSG,
            FTP_530_MSG_LENGTH,
            FTP_530_MSG_LENGTH,
            NULL,
            gwtftp_l_client_badcmd_write_cb,
            auth_session);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_write;
        }
    }
    return;

error_write:
    free(auth_session->user_buffer);
error:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session);
}

static
void
gwtftp_l_client_write220_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    gwtftp_l_client_session_t *       auth_session;

    auth_session = (gwtftp_l_client_session_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* post read for USER command */
    result = globus_xio_register_read(
        auth_session->client_xio,
        FAKE_BUFFER,
        FAKE_BUFFER_LENGTH,
        FAKE_BUFFER_LENGTH,
        NULL,
        gwtftp_l_client_read_user_cb,
        auth_session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    return;

error:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session);
}

static
void
gwtftp_l_client_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    gwtftp_l_client_session_t *       auth_session;

    auth_session = (gwtftp_l_client_session_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_register_write(
        auth_session->client_xio,
        FTP_220_MSG,
        FTP_220_MSG_LENGTH,
        FTP_220_MSG_LENGTH,
        NULL,
        gwtftp_l_client_write220_cb,
        auth_session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    return;

error:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session);
}

globus_result_t
gwtftp_i_new_connection(
    globus_xio_handle_t                 handle)
{
    globus_result_t                     result;
    gwtftp_l_client_session_t *       auth_session;

    auth_session = (gwtftp_l_client_session_t *) globus_calloc(
        1, sizeof(gwtftp_l_client_session_t));
    if(auth_session == NULL)
    {
        result = 0x1;
        goto error_mem;
    }
    auth_session->client_xio = handle;

    /* verify that we allow this IP  */
    result = gwtftp_i_ip_ok(handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_ip;
    }
    result = globus_xio_register_open(
        handle, NULL, NULL, gwtftp_l_client_open_cb, auth_session);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }

    return GLOBUS_SUCCESS;
error_open:
error_ip:
    gwtftp_i_close(auth_session->client_xio, NULL, NULL);
    free(auth_session);
error_mem:
    return result;
}

