#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_error_string.h"
#include "globus_xio_gssapi_ftp.h"
#include <globus_gss_assist.h>
#include <gssapi.h>
#include <string.h>

#define REPLY_530_BAD_MESSAGE "530 Please login with USER and PASS.\r\n"
#define REPLY_504_BAD_AUTH_TYPE "504 Unknown authentication type.\r\n"
#define REPLY_334_GOOD_AUTH_TYPE "334 Using authentication type; ADAT must follow\r\n"
#define REPLY_530_EXPECTING_ADAT "530 Must perform GSSAPI authentication\r\n"

#define REPLY_235_ADAT_DATA "235 ADAT="
#define REPLY_335_ADAT_DATA "335 ADAT="

#define CLIENT_AUTH_GSSAPI_COMMAND "AUTH GSSAPI\r\n"



#define GSSAPI_FTP_DEFAULT_BUFSIZE 1024

static char                                 globus_l_xio_gssapi_ftp_pad = '=';
static char *                               globus_l_xio_gssapi_ftp_radix_n =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                                                                


typedef enum  globus_l_xio_gssapi_ftp_state_s
{
    GSSAPI_FTP_STATE_SERVER_READING_AUTH,
    GSSAPI_FTP_STATE_SERVER_GSSAPI_READ,
    GSSAPI_FTP_STATE_SERVER_READING_ADAT,
    GSSAPI_FTP_STATE_SERVER_ADAT_REPLY,

    GSSAPI_FTP_STATE_CLIENT_READING_220,
    GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH,
    GSSAPI_FTP_STATE_CLIENT_ADAT_INIT,
    GSSAPI_FTP_STATE_CLIENT_SENDING_ADAT,

    GSSAPI_FTP_STATE_OPEN,
    GSSAPI_FTP_STATE_READING,
    GSSAPI_FTP_STATE_WRITTING,
    GSSAPI_FTP_STATE_ERROR,
} globus_l_xio_gssapi_ftp_state_t;

#define ErrorWriteOnly()                                                    \
    globus_error_put(                                                       \
        globus_error_construct_string(                                      \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            "This is a write only driver"))

static int
globus_l_xio_gssapi_ftp_activate();

static int
globus_l_xio_gssapi_ftp_deactivate();

typedef struct globus_l_xio_gssapi_ftp_target_s
{
    char *                                  host;
    globus_bool_t                           client;
} globus_l_xio_gssapi_ftp_target_t;

typedef struct globus_l_xio_gssapi_ftp_handle_s
{
    /* gssapi security info */
    gss_ctx_id_t                            gssapi_context;
    gss_cred_id_t                           cred_handle;
    gss_cred_id_t                           delegated_cred_handle;
    char *                                  auth_gssapi_subject;
    gss_name_t                              target_name;
    globus_bool_t                           encrypt;
    char *                                  host;

    globus_l_xio_gssapi_ftp_state_t         state;

    globus_xio_context_t                    context;
    globus_bool_t                           client;

    globus_xio_iovec_t                      read_iov;
    globus_byte_t *                         read_buffer;
    globus_size_t                           read_buffer_length;
    globus_size_t                           read_buffer_ndx;

    globus_xio_iovec_t *                    write_iov;
    globus_size_t                           write_iov_count;
    globus_size_t                           write_iov_size;
    globus_byte_t *                         write_buffer;
    globus_size_t                           write_buffer_length;
    globus_size_t                           write_buffer_ndx;
    globus_size_t                           write_sent_length;
} globus_l_xio_gssapi_ftp_handle_t;

static globus_result_t
globus_l_xio_gssapi_ftp_server_command(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    globus_xio_operation_t                  op,
    char **                                 cmd_a);

static void
globus_l_xio_gssapi_ftp_open_reply_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg);

static globus_result_t
globus_l_xio_gssapi_ftp_decode_adat(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    const char *                            wrapped_command,
    char **                                 out_reply,
    globus_bool_t *                         out_complete);

globus_result_t
globus_l_xio_gssapi_ftp_client_reply(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    globus_xio_operation_t                  op,
    char **                                 cmd_a);

#include "version.h"

static globus_module_descriptor_t  globus_i_xio_gssapi_ftp_module =
{
    "globus_xio_gssapi_ftp",
    globus_l_xio_gssapi_ftp_activate,
    globus_l_xio_gssapi_ftp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/************************************************************************
 *                  utility functions
 *                  ------------------
 *
 *  A variety of operations use these function.
 ***********************************************************************/
globus_bool_t
globus_l_xio_gssapi_ftp_complete_command(
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_bool_t                           client,
    globus_size_t *                         end_offset)
{
    globus_byte_t *                         tmp_ptr;
    globus_size_t                           end_off;

    tmp_ptr = globus_libc_memrchr(buffer, '\r', length);
    /* IF There is no '\r' */
    if(tmp_ptr == NULL)
    {
        return GLOBUS_FALSE;
    }
    end_off = tmp_ptr - buffer;

    /* if the '\r' is the last character, or the next isn't '\n' */
    if(end_off == length - 1 || tmp_ptr[1] != '\n')
    {
        return GLOBUS_FALSE;
    }

    /* if server we are done as soon as we get \r\n */
    if(!client)
    {
        *end_offset = end_off;
        return GLOBUS_TRUE;
    }

    /* server must check for continuation commands */
    tmp_ptr = globus_libc_memrchr(buffer, '\r', end_off - 1);
    /* if not found just check from start */
    if(tmp_ptr == NULL)
    {
        tmp_ptr = buffer;
    }
    else
    {
        tmp_ptr += 2; /* move beyound \r\n */
    }
    /* if 4th colums is a space and first is a number we are done */
    if(tmp_ptr[3] == ' ' && isdigit(tmp_ptr[0]))
    {
        *end_offset = end_off;
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}


static globus_l_xio_gssapi_ftp_handle_t *
globus_l_xio_gssapi_ftp_handle_create()
{
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_handle_create);
    /*
     *  create a new handle and initialize it
     */
    handle = (globus_l_xio_gssapi_ftp_handle_t *) 
                globus_libc_malloc(sizeof(globus_l_xio_gssapi_ftp_handle_t));
    if(handle == NULL)
    {
        return NULL;
    }
    handle->gssapi_context = GSS_C_NO_CONTEXT;
    handle->delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    handle->encrypt = GLOBUS_FALSE;
    handle->host = NULL;

    handle->read_buffer = globus_malloc(GSSAPI_FTP_DEFAULT_BUFSIZE);
    handle->read_buffer_length = GSSAPI_FTP_DEFAULT_BUFSIZE;
    handle->read_buffer_ndx = 0;

    handle->write_iov_size = 2;
    handle->write_iov = (globus_xio_iovec_t *) 
        globus_malloc(sizeof(globus_xio_iovec_t) * handle->write_iov_size);
    handle->write_buffer_ndx = 0;
    handle->write_buffer_length = GSSAPI_FTP_DEFAULT_BUFSIZE;
    handle->write_buffer = globus_malloc(GSSAPI_FTP_DEFAULT_BUFSIZE);


    return handle;
}

static void
globus_l_xio_gssapi_ftp_handle_destroy(
    globus_l_xio_gssapi_ftp_handle_t *      handle)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_handle_destroy);

    if(handle->host)
    {
        globus_free(handle->host);
    }

    globus_free(handle);
}

globus_result_t
globus_l_xio_gssapi_ftp_radix_decode(
    globus_byte_t *                         inbuf,
    globus_byte_t *                         outbuf,
    globus_size_t *                         length)
{
    int                                     i;
    int                                     j;
    int                                     D;
    char *                                  p;
    GlobusXIOName(globus_l_xio_gssapi_ftp_radix_decode);

    for (i=0,j=0; inbuf[i] && inbuf[i] != globus_l_xio_gssapi_ftp_pad; i++)
    {
        if ((p = strchr(globus_l_xio_gssapi_ftp_radix_n, inbuf[i])) == NULL)
        {
            return GlobusXIOGssapiFTPEncodingError();
        }
        D = p - globus_l_xio_gssapi_ftp_radix_n;
        switch (i&3)
        {
            case 0:
                outbuf[j] = D<<2;
                break;
            case 1:
                outbuf[j++] |= D>>4;
                outbuf[j] = (D&15)<<4;
                break;
            case 2:
                outbuf[j++] |= D>>2;
                outbuf[j] = (D&3)<<6;
                break;
            case 3:
                outbuf[j++] |= D;
                break;
            default:
                globus_assert(0);
                break;
        }
    }

    switch (i&3)
    {
        case 1:
            return GlobusXIOGssapiFTPEncodingError();
 
       case 2:
            if (D&15)
            {
                return GlobusXIOGssapiFTPEncodingError();
            }
            if (strcmp((char *)&inbuf[i], "=="))
            {
                return GlobusXIOGssapiFTPEncodingError();
            }
            break;

        case 3:
            if (D&3)
            {
                return GlobusXIOGssapiFTPEncodingError();
            }
            if (strcmp((char *)&inbuf[i], "="))
            {
                return GlobusXIOGssapiFTPEncodingError();
            }
            break;

        default:
            globus_assert(0);
            break;
    }
    *length = j;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_radix_encode(
    globus_byte_t *                         inbuf,
    globus_byte_t *                         outbuf,
    globus_size_t *                         length)
{
    int                                     i;
    int                                     j;
    unsigned char                           c;
    GlobusXIOName(globus_l_xio_gssapi_ftp_radix_encode);

    for (i=0,j=0; i < *length; i++)
    {
        switch (i%3)
        {
            case 0:
                outbuf[j++] = globus_l_xio_gssapi_ftp_radix_n[inbuf[i]>>2];
                c = (inbuf[i]&3)<<4;
                break;
            case 1:
                outbuf[j++] = globus_l_xio_gssapi_ftp_radix_n[c|inbuf[i]>>4];
                c = (inbuf[i]&15)<<2;
                break;
            case 2:
                outbuf[j++] = globus_l_xio_gssapi_ftp_radix_n[c|inbuf[i]>>6];
                outbuf[j++] = globus_l_xio_gssapi_ftp_radix_n[inbuf[i]&63];
                c = 0;
                break;
            default:
                globus_assert(0);
                break;
        }
    }
    if (i%3)
    {
        outbuf[j++] = globus_l_xio_gssapi_ftp_radix_n[c];
    }
    switch (i%3)
    {
        case 1:
            outbuf[j++] = globus_l_xio_gssapi_ftp_pad;
        case 2:
            outbuf[j++] = globus_l_xio_gssapi_ftp_pad;
    }

    outbuf[*length = j] = '\0';

    return GLOBUS_SUCCESS;
}


char **
globus_l_xio_gssapi_ftp_parse_command(
    globus_byte_t *                         command,
    globus_size_t                           length)
{
    char *                                  tmp_ptr;
    char **                                 cmd_a = NULL;
    int                                     cmd_len = 16;
    int                                     ctr;
    char *                                  cmd_copy;
    GlobusXIOName(globus_l_xio_gssapi_ftp_parse_command);

    cmd_a = (char **) globus_malloc(sizeof(char *) * cmd_len);
    if(cmd_a == NULL)
    {
        return NULL;
    }

    cmd_copy = globus_libc_strndup(command, length);
    tmp_ptr = globus_libc_strtok(cmd_copy, " ");
    globus_assert(tmp_ptr != NULL); /* there has to be at least 1 */
    for(ctr = 0; tmp_ptr != NULL; ctr++)
    {
        cmd_a[ctr] = globus_libc_strdup(tmp_ptr);
        if(ctr == cmd_len)
        {
            cmd_len *= 2;
            cmd_a = (char **) globus_libc_realloc(cmd_a,
                                sizeof(char *) * cmd_len);
        }
        tmp_ptr = globus_libc_strtok(NULL, " ");
    }
    cmd_a[ctr] = NULL;
    globus_free(cmd_copy);

    return cmd_a;
}


/*
 *  continue to post more reads until a complete command is received.
 *  Once receive action will be based on current state.
 */
void
globus_l_xio_gssapi_ftp_read_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    globus_size_t                           end_off;
    globus_size_t                           next_length = 1;
    globus_bool_t                           complete = GLOBUS_TRUE;
    globus_result_t                         res;
    char **                                 cmd_a;
    globus_size_t                           remain;
    GlobusXIOName(globus_l_xio_gssapi_ftp_read_cb);

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    handle->read_buffer_ndx += nbytes;
    complete = globus_l_xio_gssapi_ftp_complete_command(
                    handle->read_buffer,
                    handle->read_buffer_ndx,
                    handle->client,
                    &end_off);
    /*
     *  if not complete setup the iov and post the next read.
     *  posted with wait for of minimum that it takes to finish
     *  finishe the command and a length to fill the entire buffer
     */
    if(!complete)
    {
        /* if buffer is too small double it */
        if(handle->read_buffer_ndx + next_length >= handle->read_buffer_length)
        {
            handle->read_buffer_length = 
                (handle->read_buffer_length + next_length) * 2;
            handle->read_buffer = globus_libc_realloc(
                    handle->read_buffer,
                    handle->read_buffer_length);
        }
        handle->read_iov.iov_base = 
            &handle->read_buffer[handle->read_buffer_ndx];
        handle->read_iov.iov_len =
            handle->read_buffer_length - handle->read_buffer_ndx;
        GlobusXIODriverPassRead(
            res,
            op, 
            &handle->read_iov,
            1,
            next_length,
            globus_l_xio_gssapi_ftp_read_cb, 
            handle);
    }
    /*
     * Have an entire command
     */
    else
    {
        /* if we read beyound a command, move everything to the front */
        remain = handle->read_buffer_ndx - end_off - 2;
        /* reset the read pointer */
        handle->read_buffer_ndx = 0;
        if(remain > 0)
        {
            memmove(
                handle->read_buffer, 
                &handle->read_buffer[end_off + 2],   
                remain);
        }
        handle->read_buffer[end_off] = '\0';
        /* tokenize the command */
        cmd_a = globus_l_xio_gssapi_ftp_parse_command(
                    handle->read_buffer,
                    end_off);
        if(handle->client)
        {
            res = globus_l_xio_gssapi_ftp_client_reply(handle, op, cmd_a);
        }
        else
        {
            res = globus_l_xio_gssapi_ftp_server_command(handle, op, cmd_a);
        }
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return;

  err:

    /* assume open for now, if other operations use this we will have
        to alter this */
    GlobusXIODriverFinishedOpen(handle->context, handle, op, res);

    return;
}

globus_result_t
globus_l_xio_gssapi_ftp_encode(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    globus_byte_t  *                        in_buf, 
    globus_size_t                           length,
    char **                                 out_buffer,
    globus_bool_t                           client)
{
    char *                                  encoded_buf;
    int                                     conf_state;
    gss_buffer_desc                         gss_in_buf;
    gss_buffer_desc                         gss_out_buf;
    OM_uint32                               maj_stat;
    OM_uint32                               min_stat;
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_encode);

    gss_in_buf.value = in_buf;
    gss_in_buf.length = length;
                                                                                
    maj_stat = gss_wrap(&min_stat,
                        handle->gssapi_context,
                        0,
                        GSS_C_QOP_DEFAULT,
                        &gss_in_buf,
                        &conf_state,
                        &gss_out_buf);
    if(maj_stat  != GSS_S_COMPLETE)
    {
        res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
        goto err;
    }

    encoded_buf = (char *) 
        globus_libc_malloc((gss_out_buf.length + 3) * 8 / 6 + 9);
    if(encoded_buf == NULL)
    {
        gss_release_buffer(&min_stat, &gss_out_buf);
        res = GlobusXIOGssapiFTPAllocError();
        goto err;
    }

    if(client)
    {
        if(conf_state == 0)
        {
            memcpy(encoded_buf, "MIC ", 4);
        }
        else
        {
            memcpy(encoded_buf, "ENC ", 4);
        }
    }
    else
    {
        if(conf_state == 0)
        {
            memcpy(encoded_buf, "631 ", 4);
        }
        else
        {
            memcpy(encoded_buf, "632 ", 4);
        }
    }

    globus_l_xio_gssapi_ftp_radix_encode(
        gss_out_buf.value,
        &encoded_buf[4],
        &gss_out_buf.length);

    encoded_buf[gss_out_buf.length+4]='\r';
    encoded_buf[gss_out_buf.length+5]='\n';
    encoded_buf[gss_out_buf.length+6]='\0';
    *out_buffer = encoded_buf;

    gss_release_buffer(&min_stat, &gss_out_buf);

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/************************************************************************
 *                  server open
 *                  -----------
 *
 *  This section contains the functions used by a server in openning 
 *  a handle.
 ***********************************************************************/
/*
 *  when a full command comes in for the server this is called.
 */
globus_result_t
globus_l_xio_gssapi_ftp_server_command(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    globus_xio_operation_t                  op,
    char **                                 cmd_a)
{
    char *                                  msg;
    globus_result_t                         res;
    globus_bool_t                           complete;
    GlobusXIOName(globus_l_xio_gssapi_ftp_server_command);

    switch(handle->state)
    {
        /* verifiy that we can handle this auth type */
        case GSSAPI_FTP_STATE_SERVER_READING_AUTH:
            /* if command is not expected, stay in this state. */
            if(globus_libc_strcmp(cmd_a[0], "AUTH") != 0)
            {
                msg = globus_libc_strdup(REPLY_530_BAD_MESSAGE);
            }
            /* only accepting gssapi for now. may want to get 
               cleaver later */
            else if(globus_libc_strcmp(cmd_a[1], "GSSAPI") != 0)
            {
                msg = globus_libc_strdup(REPLY_504_BAD_AUTH_TYPE);
            }
            else
            {
                handle->state = GSSAPI_FTP_STATE_SERVER_GSSAPI_READ;
                msg = globus_libc_strdup(REPLY_334_GOOD_AUTH_TYPE);
            }

            break;

        /* on errors we stay in this state */
        case GSSAPI_FTP_STATE_SERVER_READING_ADAT:
            if(globus_libc_strcmp(cmd_a[0], "ADAT") != 0)
            {
                msg = globus_libc_strdup(REPLY_530_EXPECTING_ADAT);
            }
            else if(cmd_a[1] == NULL)
            {
                msg = globus_libc_strdup(REPLY_530_EXPECTING_ADAT);
            }
            /* do all the work to figure out adat reply */
            else
            {
                res = globus_l_xio_gssapi_ftp_decode_adat(
                        handle,
                        cmd_a[1],
                        &msg,
                        &complete);
                if(res != GLOBUS_SUCCESS)
                {
                    goto err;
                }

                /* if compete change to the next state */
                if(complete)
                {
                    handle->state = GSSAPI_FTP_STATE_SERVER_ADAT_REPLY;
                }
            }

            break;

        default:
            globus_assert(0 && "Handle should be in reading state");
            break;
    }

    /* send the entire reply */
    handle->write_iov[0].iov_base = msg;
    handle->write_iov[0].iov_len = globus_libc_strlen(msg);
    GlobusXIODriverPassWrite(
        res, 
        op, 
        handle->write_iov,
        1, 
        handle->write_iov[0].iov_len,
        globus_l_xio_gssapi_ftp_open_reply_cb,
        handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/*
 *  while in the open authentication process, this callback is used for
 *  all of the writes.  
 */ 
static void
globus_l_xio_gssapi_ftp_open_reply_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_bool_t                           done = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_gssapi_ftp_open_reply_cb);

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    /* if there was an error, finish the open with an error */
    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    switch(handle->state)
    {
        /* this case occurs when a bad command wasread when an auth
            was expected.  Remain in this state and pass another read */
        case GSSAPI_FTP_STATE_SERVER_READING_AUTH:
            break;

        /* occurs after AUTH GSSAPI successfuly read, move to the
            ADAT state */
        case GSSAPI_FTP_STATE_SERVER_GSSAPI_READ:
            handle->state = GSSAPI_FTP_STATE_SERVER_READING_ADAT;
            break;

        /* occurs when unexpected command happens when adat is expected,
            remain in this state, and post another read */
        case GSSAPI_FTP_STATE_SERVER_READING_ADAT:
            break;

        case GSSAPI_FTP_STATE_SERVER_ADAT_REPLY:
            handle->state = GSSAPI_FTP_STATE_OPEN;
            done = GLOBUS_TRUE;
            break;

        default:
            break;
    }

    if(!done)
    {
        /* reset the iov */
        handle->read_iov.iov_base = handle->read_buffer;
        handle->read_iov.iov_len = handle->read_buffer_length;
        GlobusXIODriverPassRead(
            res,
            op,
            &handle->read_iov,
            1,
            5, /* at least 5 to make 1 command */
            globus_l_xio_gssapi_ftp_read_cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    else
    {
        GlobusXIODriverFinishedOpen(handle->context, handle, op, res);
    }

    return;

  err:
    GlobusXIODriverFinishedOpen(handle->context, handle, op, res);

    return;
}


/*
 *  decode a command
 */
static globus_result_t
globus_l_xio_gssapi_ftp_decode_adat(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    const char *                            wrapped_command,
    char **                                 out_reply,
    globus_bool_t *                         out_complete)
{
    char *                                  reply;
    globus_result_t                         res;
    OM_uint32                               ret_flags = 0;
    OM_uint32                               min_stat;
    OM_uint32                               maj_stat;
    globus_size_t                           length;
    char *                                  decoded_cmd;
    gss_buffer_desc                         recv_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                         send_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                         subject_buf = GSS_C_EMPTY_BUFFER;
    gss_OID                                 mech_type;
    GlobusXIOName(globus_l_xio_gssapi_ftp_decode_adat);

    length = globus_libc_strlen(wrapped_command);
    if(length <= 0)
    {
        res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
        goto err;
    }

    decoded_cmd = (char *) globus_libc_malloc((length+3) * 6/8);
    if(decoded_cmd == NULL)
    {
        res = GlobusXIOGssapiFTPAllocError();
        goto err;
    }
    res = globus_l_xio_gssapi_ftp_radix_decode(
            (globus_byte_t *) wrapped_command,
            decoded_cmd,
            &length);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(decoded_cmd);
        goto err;
    }

    recv_tok.value = decoded_cmd;
    recv_tok.length = length;
    maj_stat = gss_accept_sec_context(
        &min_stat,
        &handle->gssapi_context,
        handle->cred_handle,
        &recv_tok,
        GSS_C_NO_CHANNEL_BINDINGS,
        &handle->target_name,
        &mech_type,
        &send_tok,
        &ret_flags,
        GLOBUS_NULL,
        &handle->delegated_cred_handle);
    globus_free(decoded_cmd);

    switch(maj_stat)
    {
        /* if we have finished the security exchange */
        case GSS_S_COMPLETE:
            /* get the subject and copy into handle */
            maj_stat = gss_display_name(
                        &min_stat,
                        handle->target_name,
                        &subject_buf,
                        GSS_C_NO_OID);
            handle->auth_gssapi_subject =
                globus_libc_strndup(subject_buf.value, subject_buf.length);
                                                                                
            if(handle->auth_gssapi_subject == NULL)
            {
                gss_release_buffer(&min_stat, &send_tok);
                res = GlobusXIOGssapiFTPAllocError();
                goto err;
            }

            /* may have to still send some adat stuff back, check out len */
            if(send_tok.length == 0)
            {
                reply = globus_libc_strdup(
                            "235 GSSAPI Authentication succeeded\r\n");
                if(reply == NULL)
                {
                    gss_release_buffer(&min_stat, &send_tok);
                    res = GlobusXIOGssapiFTPAllocError();
                    goto err;
                }
            }
            else
            {
                reply = (char *) globus_libc_malloc(
                                send_tok.length * 8 / 6 + 16);
                if(reply == NULL)
                {
                    gss_release_buffer(&min_stat, &send_tok);
                    res = GlobusXIOGssapiFTPAllocError();
                    goto err;
                }
                strcpy(reply, REPLY_235_ADAT_DATA);
                length = send_tok.length;
                res = globus_l_xio_gssapi_ftp_radix_encode(
                        send_tok.value,
                        &reply[strlen(REPLY_235_ADAT_DATA)],
                        &length);
                if(res != GLOBUS_SUCCESS)
                {
                    gss_release_buffer(&min_stat, &send_tok);
                    goto err;
                }
            }
            *out_complete = GLOBUS_TRUE;
            break;

        /* if we have more ADATS to send around */
        case GSS_S_CONTINUE_NEEDED:
            reply = (char *) globus_libc_malloc(
                            send_tok.length * 8 / 6 + 16);
            if(reply == NULL)
            {
                globus_free(reply);
                gss_release_buffer(&min_stat, &send_tok);
                res = GlobusXIOGssapiFTPAllocError();
                goto err;
            }
            strcpy(reply, REPLY_335_ADAT_DATA);
            length = send_tok.length;
            res = globus_l_xio_gssapi_ftp_radix_encode(
                    send_tok.value,
                    &reply[strlen(REPLY_335_ADAT_DATA)],
                    &length);
            if(res != GLOBUS_SUCCESS)
            {
                globus_free(reply);
                gss_release_buffer(&min_stat, &send_tok);
                goto err;
            }
            memcpy(&reply[strlen(REPLY_335_ADAT_DATA)+length], "\r\n\0", 3);

            *out_complete = GLOBUS_FALSE;
            break;

        default:
            res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
            goto err;
            break;
    }

    *out_reply = reply;

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/*
 *   accepting
 *
 *   Meary pass the accept, set target state to server.  The open will
 *   take care of the protocol exchange.
 */
static void
globus_l_xio_gssapi_ftp_accept_cb(
    globus_i_xio_op_t *                     op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_xio_gssapi_ftp_target_t *      target;
    GlobusXIOName(globus_l_xio_gssapi_ftp_accept_cb);

    if(result != GLOBUS_SUCCESS)
    {
        goto err;
    }

    target = (globus_l_xio_gssapi_ftp_target_t *)
                globus_malloc(sizeof(globus_l_xio_gssapi_ftp_target_t));
    if(target == NULL)
    {
        result = GlobusXIOGssapiFTPAllocError();
        goto err;
    }
    target->client = GLOBUS_FALSE;

    GlobusXIODriverFinishedAccept(op, target, GLOBUS_SUCCESS);
    return;

  err:

    GlobusXIODriverFinishedAccept(op, NULL, result);
    return;
}

/*
 *  callback for the pass open.  If the state is not completely open 
 *  post a read to move to the next point in the authentication 
 *  process.  In the normal case this will be AUTH, however the user
 *  may circumvent these steps.
 */
static void
globus_l_xio_gssapi_ftp_open_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_open_cb);

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    if(handle->state != GSSAPI_FTP_STATE_OPEN && result == GLOBUS_SUCCESS)
    {
        handle->read_iov.iov_base = handle->read_buffer,
        handle->read_iov.iov_len = handle->read_buffer_length;
        GlobusXIODriverPassRead(
            result,
            op,
            &handle->read_iov,
            1,
            5, /* at least 5 to make 1 command */
            globus_l_xio_gssapi_ftp_read_cb,
            handle);
    }

    /* if error occured on the way in or due to read, finish the open
        with an error, or we started in the open state, then finish
        with success */
    if(result != GLOBUS_SUCCESS || handle->state == GSSAPI_FTP_STATE_OPEN)
    {
        GlobusXIODriverFinishedOpen(handle->context, handle, op, result);
    }
}

/************************************************************************
 *                  client open functions
 *                  ---------------------
 *  
 *   This section has functions that open a handle for a client
 ***********************************************************************/

globus_result_t
globus_l_xio_gssapi_ftp_client_adat(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    const char *                            buffer,
    char **                                 out_buffer,
    globus_bool_t *                         complete)
{
    gss_buffer_desc                         send_tok;
    gss_buffer_desc                         recv_tok;
    gss_buffer_desc *                       token_ptr;
    OM_uint32                               min_stat;
    OM_uint32                               maj_stat;
    OM_uint32                               req_flags = 0;
    globus_result_t                         res;
    globus_byte_t *                         radix_buf;
    globus_size_t                           length;
    char *                                  error_str;
    char                                    hostname[128+5];
    GlobusXIOName(globus_l_xio_gssapi_ftp_client_adat);

    switch(handle->state)
    {
        case GSSAPI_FTP_STATE_CLIENT_ADAT_INIT:

            sprintf(hostname, "host@%s", handle->host);

            send_tok.value = hostname;
            send_tok.length = strlen(hostname) + 1;
            maj_stat = gss_import_name(
                            &min_stat,
                            &send_tok,
                            GSS_C_NT_HOSTBASED_SERVICE,
                            &handle->target_name);
            if(maj_stat != GSS_S_COMPLETE)
            {
                res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
                globus_l_xio_gssapi_ftp_handle_destroy(handle);
                goto err;
            }

            token_ptr = GSS_C_NO_BUFFER;

            break;

        case GSSAPI_FTP_STATE_CLIENT_SENDING_ADAT:
            /* base64 decode the reply */
            length = globus_libc_strlen(buffer);
                                                                                
            radix_buf = globus_libc_malloc((length + 1) * 6 / 8 + 1);
                                                                                
            if(radix_buf == GLOBUS_NULL)
            {
                res = GlobusXIOGssapiFTPAllocError();
                goto err;
            }
                                                                                
            res = globus_l_xio_gssapi_ftp_radix_decode(
                    buffer,
                    radix_buf,
                    &length);
            if(res != GLOBUS_SUCCESS)
            {
                globus_libc_free(radix_buf);
                goto err;
            }

            recv_tok.value = radix_buf;
            recv_tok.length = length;
            token_ptr = &recv_tok;
            break;

        default:
            globus_assert(0);
            break;
    }

    req_flags |= GSS_C_MUTUAL_FLAG;
    req_flags |= GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG|GSS_C_DELEG_FLAG;
    if(handle->encrypt)
    {
        req_flags |= GSS_C_CONF_FLAG;
    }

    maj_stat = gss_init_sec_context(
        &min_stat,
        handle->cred_handle,
        &handle->gssapi_context,
        handle->target_name,
        GSS_C_NULL_OID,
        req_flags,
        0,
        NULL,
        token_ptr,
        NULL,
        &send_tok,
        NULL,
        NULL);
    *complete = GLOBUS_FALSE;
    *out_buffer = NULL;
    switch(maj_stat)
    {
        case GSS_S_COMPLETE:
            *complete = GLOBUS_TRUE;

        case GSS_S_CONTINUE_NEEDED:
            if(send_tok.length != 0)
            {
                radix_buf = globus_libc_malloc(send_tok.length * 8 / 6 + 11);
                if(radix_buf == NULL)
                {
                    res = GlobusXIOGssapiFTPAllocError();
                    goto err;
                }

                memcpy(radix_buf, "ADAT ", 5);
                length = send_tok.length;
                res = globus_l_xio_gssapi_ftp_radix_encode(
                        send_tok.value, &radix_buf[5], &length);
                if(res != GLOBUS_SUCCESS)
                {
                    globus_free(radix_buf);
                    goto err;
                }
                radix_buf[length+5] = '\r';
                radix_buf[length+6] = '\n';
                radix_buf[length+7] = '\0';

                *out_buffer = radix_buf;
            }

            break; 

        default:
            globus_gss_assist_display_status_str(&error_str,
                                                     GLOBUS_NULL,
                                                     maj_stat,
                                                     min_stat,
                                                     0);

            res = GlobusXIOGssapiFTPAuthenticationFailure(error_str);
            goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_l_xio_gssapi_ftp_client_reply(
    globus_l_xio_gssapi_ftp_handle_t *      handle,
    globus_xio_operation_t                  op,
    char **                                 cmd_a)
{
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_bool_t                           complete;
    globus_result_t                         res = GLOBUS_SUCCESS;
    char *                                  send_buffer;
    char *                                  tmp_buf;
    GlobusXIOName(globus_l_xio_gssapi_ftp_client_reply);

    switch(handle->state)
    {
        case GSSAPI_FTP_STATE_CLIENT_READING_220:
            /* if we did not get a 220 from the server finsh the open
                with an error */
            if(strcmp(cmd_a[0], "220") != 0)
            {
                res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
                goto err;
            }
            else
            {
                handle->state = GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH;
                send_buffer = globus_libc_strdup(CLIENT_AUTH_GSSAPI_COMMAND);
            }
            break;

        case GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH:
            if(strcmp(cmd_a[0], "334") != 0)
            {
                res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
                goto err;
            }
            else
            {
               handle->state = GSSAPI_FTP_STATE_CLIENT_ADAT_INIT;
               res = globus_l_xio_gssapi_ftp_client_adat(
                        handle,
                        NULL,
                        &send_buffer,
                        &complete);
                if(res != GLOBUS_SUCCESS)
                {
                    goto err;
                }
                if(send_buffer == NULL)
                {
                    res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
                    goto err;
                }
            }

            break;

        /* change state and fall through */
        case GSSAPI_FTP_STATE_CLIENT_ADAT_INIT:
            handle->state = GSSAPI_FTP_STATE_CLIENT_SENDING_ADAT;

        case GSSAPI_FTP_STATE_CLIENT_SENDING_ADAT:
            /* if completed successfully */
            if(*cmd_a[0] == '2')
            {
                if(strncmp(cmd_a[1], "ADAT=", 5) == 0)
                {
                    tmp_buf = cmd_a[1] + strlen("ADAT=");
                    res = globus_l_xio_gssapi_ftp_client_adat(
                            handle,
                            cmd_a[1],
                            &send_buffer,
                            &complete);
                    if(res != GLOBUS_SUCCESS)
                    {
                        goto err;
                    }
                    if(!complete || send_buffer != NULL)
                    {
                        res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
                        goto err;
                    }
                }
                handle->state = GSSAPI_FTP_STATE_OPEN;
                done = GLOBUS_TRUE;
            }
            /* if we still need to send more adats, but all is well */
            else if(*cmd_a[0] == '3')
            {
                tmp_buf = cmd_a[1] + strlen("ADAT=");
                res = globus_l_xio_gssapi_ftp_client_adat(
                        handle,
                        tmp_buf,
                        &send_buffer,
                        &complete);
                if(res != GLOBUS_SUCCESS)
                {
                    goto err;
                }
                if(send_buffer == NULL)
                {
                    res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
                    goto err;
                }
            }
            /* if an error occurred */
            else
            {
                res = GlobusXIOGssapiFTPAuthenticationFailure(cmd_a[0]);
                goto err;
            }
            break;

        default:
            break;
    }

    if(!done)
    {
        handle->write_iov[0].iov_base = send_buffer;
        handle->write_iov[0].iov_len = globus_libc_strlen(send_buffer);
        GlobusXIODriverPassWrite(
            res,
            op,
            handle->write_iov,
            1,
            handle->write_iov[0].iov_len,
            globus_l_xio_gssapi_ftp_open_reply_cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    else
    {
        GlobusXIODriverFinishedOpen(handle->context, handle, op, res);
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

/************************************************************************
 *                  write functions
 *                  ---------------
 *  
 *  This section has function that handle writes
 ***********************************************************************/

void
globus_l_xio_gssapi_ftp_write_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    int                                     ctr;
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_write_cb);
    /* change state back and free stuff */

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    handle->state = GSSAPI_FTP_STATE_OPEN;

    GlobusXIODriverFinishedWrite(op, GLOBUS_SUCCESS, handle->write_sent_length);

    for(ctr = 0; ctr < handle->write_iov_count; ctr++)
    {
        globus_free(handle->write_iov[ctr].iov_base);
    }
    globus_free(handle->write_iov);
}

/************************************************************************
 *                  read functions
 *                  --------------
 *  
 *  This section has function that handle writes
 ***********************************************************************/


/************************************************************************
 *                  target handling
 *                  ---------------
 ***********************************************************************/
static globus_result_t
globus_l_xio_gssapi_ftp_target_init(
    void **                                 out_target,
    void *                                  driver_attr,
    const char *                            contact_string)
{
    globus_l_xio_gssapi_ftp_target_t *      target;
    char *                                  tmp_ptr;
    GlobusXIOName(globus_l_xio_gssapi_ftp_target_init);

    target = (globus_l_xio_gssapi_ftp_target_t *)
                globus_malloc(sizeof(globus_l_xio_gssapi_ftp_target_t));

    target->client = GLOBUS_TRUE;
    target->host = globus_libc_strdup(contact_string);
    tmp_ptr = strchr(target->host, ':');
    *tmp_ptr = '\0';

    *out_target = target;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_target_cntl(
    void *                                  driver_target,
    int                                     cmd,
    va_list                                 ap)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_target_cntl);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_gssapi_ftp_target_destroy(
    void *                                  driver_target)
{
    globus_l_xio_gssapi_ftp_target_t *      target;
    GlobusXIOName(globus_l_xio_gssapi_ftp_target_destroy);

    target = (globus_l_xio_gssapi_ftp_target_t *) driver_target;

    globus_free(target);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_accept(
    void *                                  driver_server,
    void *                                  driver_attr,
    globus_xio_operation_t                  accept_op)
{
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_accept);

    GlobusXIODriverPassAccept(res, accept_op, 
        globus_l_xio_gssapi_ftp_accept_cb, NULL);

    return res;
}

/************************************************************************
 *                  attr handling
 *                  ---------------
 ***********************************************************************/
static globus_result_t
globus_l_xio_gssapi_ftp_attr_init(
    void **                             out_attr)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_init);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_cntl);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_attr_copy(
    void **                             dst,
    void *                              src)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_copy);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_attr_destroy(
    void *                              driver_attr)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_destroy);
    return GLOBUS_SUCCESS;
}

/************************************************************************
 *                    io handlers
 *                    -----------
 ***********************************************************************/

static globus_result_t
globus_l_xio_gssapi_ftp_open(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_operation_t                  op)
{
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    globus_l_xio_gssapi_ftp_target_t *      target;
    globus_result_t                         res;
    OM_uint32                               maj_stat;
    OM_uint32                               min_stat;
    GlobusXIOName(globus_l_xio_gssapi_ftp_open);

    target = (globus_l_xio_gssapi_ftp_target_t *) driver_target;

    /*
     *  create a new handle and initialize it 
     */
    handle = globus_l_xio_gssapi_ftp_handle_create();
    if(handle == NULL)
    {
        res = GlobusXIOGssapiFTPAllocError();
        goto err;
    }
    handle->client = target->client;

    /* do client protocol */
    if(handle->client)
    {
        handle->host = globus_libc_strdup(target->host);
        handle->state = GSSAPI_FTP_STATE_CLIENT_READING_220;
        handle->cred_handle = GSS_C_NO_CREDENTIAL;
        GlobusXIODriverPassOpen(res, handle->context, op,
                            globus_l_xio_gssapi_ftp_open_cb, handle);
    }
    /* do server protocol */
    else
    {
        /* get the credential now.  if we can't get it fail */
        maj_stat = globus_gss_assist_acquire_cred(
                        &min_stat,
                        GSS_C_ACCEPT,
                        &handle->cred_handle);
        if(maj_stat != GSS_S_COMPLETE)
        {
            res = GlobusXIOGssapiFTPAuthenticationFailure("auth");
            globus_l_xio_gssapi_ftp_handle_destroy(handle);
            goto err;
        }

        handle->state = GSSAPI_FTP_STATE_SERVER_READING_AUTH;
        GlobusXIODriverPassOpen(res, handle->context, op,
                            globus_l_xio_gssapi_ftp_open_cb, handle);
    }
    if(res != GLOBUS_SUCCESS)
    {
        globus_l_xio_gssapi_ftp_handle_destroy(handle);
        goto err;
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

static globus_result_t
globus_l_xio_gssapi_ftp_close(
    void *                                  driver_handle,
    void *                                  attr,
    globus_xio_context_t                    context,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_close);

    /*
     *  TODO: free resources
     */

    GlobusXIODriverPassClose(res, op, NULL, NULL);

    return GLOBUS_SUCCESS;
}

/* client and server are both the same except for the header */
static globus_result_t
globus_l_xio_gssapi_ftp_write(
    void *                                  driver_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    char *                                  tmp_ptr;
    globus_byte_t *                         buf;
    char *                                  encoded_buf;
    int                                     ctr;
    globus_size_t                           end_off;
    globus_size_t                           length;
    globus_l_xio_gssapi_ftp_handle_t *      handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_write);

    handle = (globus_l_xio_gssapi_ftp_handle_t *) driver_handle;

    if(handle->state != GSSAPI_FTP_STATE_OPEN)
    {
        res = GlobusXIOGssapiFTPOutstandingOp();
        goto err;
    }

    /* verify there is enough room in the write buffer */
    GlobusXIOUtilIovTotalLength(length, iovec, iovec_count);
    if(length + handle->write_buffer_ndx >= handle->write_buffer_length)
    {
        handle->write_buffer_length = (handle->write_buffer_length+length)*2;
        handle->write_buffer = globus_libc_realloc(
            handle->write_buffer, handle->write_buffer_length);
    }
    GlobusXIOUtilIovSerialize(
        &handle->write_buffer[handle->write_buffer_ndx], iovec, iovec_count);

    handle->write_buffer_ndx += length;
    tmp_ptr = strstr(handle->write_buffer, "\r\n");
    /* if this is not a complete command we simply cache it and say we 
        are finished */
    if(tmp_ptr == NULL)
    {
        GlobusXIODriverFinishedWrite(op, GLOBUS_SUCCESS, length);
    }
    else
    {
        ctr = 0;
        buf = handle->write_buffer;
        handle->write_sent_length = 0;
        while(tmp_ptr != NULL)
        {
            res = globus_l_xio_gssapi_ftp_encode(
                    handle, buf, (globus_byte_t *)tmp_ptr - buf, 
                    &encoded_buf, handle->client);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
            
            handle->write_iov[ctr].iov_base = encoded_buf;
            handle->write_iov[ctr].iov_len = globus_libc_strlen(encoded_buf);

            handle->write_sent_length += handle->write_iov[ctr].iov_len;

            buf = tmp_ptr;
            tmp_ptr = strstr(buf, "\r\n");
            ctr++;
            if(ctr >= handle->write_iov_size)
            {
                handle->write_iov_size *= 2;
                handle->write_iov = globus_libc_realloc(
                    handle->write_iov, 
                    handle->write_iov_size * (sizeof(globus_xio_iovec_t)));
            }
        }
        handle->write_iov_count = ctr;
        /* see if we need to shift everything over */
        end_off = buf - handle->write_buffer + 2;
        handle->write_buffer_ndx = handle->write_buffer_ndx - end_off;
        if(handle->write_buffer_ndx != 0)
        {
            memmove(
                handle->write_buffer, 
                &handle->write_buffer[end_off], 
                handle->write_buffer_ndx);
        }

        GlobusXIODriverPassWrite(
            res, 
            op, 
            handle->write_iov, 
            handle->write_iov_count,
            length,
            globus_l_xio_gssapi_ftp_write_cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    return GLOBUS_SUCCESS;

  err:

    return res;
}

static globus_result_t
globus_l_xio_gssapi_ftp_read(
    void *                                  driver_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_read);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_load(
    globus_xio_driver_t *                   out_driver,
    va_list                                 ap)
{
    globus_xio_driver_t                     driver;
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_load);

    res = globus_xio_driver_init(&driver, "smtp", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_gssapi_ftp_open,
        globus_l_xio_gssapi_ftp_close,
        /*globus_l_xio_gssapi_ftp_read, */ NULL,
        globus_l_xio_gssapi_ftp_write,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_gssapi_ftp_attr_init,
        globus_l_xio_gssapi_ftp_attr_copy,
        globus_l_xio_gssapi_ftp_attr_cntl,
        globus_l_xio_gssapi_ftp_attr_destroy);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_gssapi_ftp_target_init,
        globus_l_xio_gssapi_ftp_target_cntl,
        globus_l_xio_gssapi_ftp_target_destroy);

    globus_xio_driver_set_server(
        driver,
        NULL,
        globus_l_xio_gssapi_ftp_accept,
        NULL,
        NULL,
        globus_l_xio_gssapi_ftp_target_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}



static void
globus_l_xio_gssapi_ftp_unload(
    globus_xio_driver_t                     driver)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_unload);
    globus_xio_driver_destroy(driver);
}


static int
globus_l_xio_gssapi_ftp_activate(void)
{
    int                                     rc;
    GlobusXIOName(globus_l_xio_gssapi_ftp_activate);

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);

    return rc;
}

static int
globus_l_xio_gssapi_ftp_deactivate(void)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_deactivate);
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    gssapi_ftp,
    &globus_i_xio_gssapi_ftp_module,
    globus_l_xio_gssapi_ftp_load,
    globus_l_xio_gssapi_ftp_unload);

