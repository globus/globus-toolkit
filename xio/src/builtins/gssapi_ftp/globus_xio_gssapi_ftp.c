#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_error_string.h"
#include "globus_xio_gssapi_ftp.h"
#include "globus_error_openssl.h"
#include "globus_gss_assist.h"
#include "gssapi.h"
#include <string.h>

GlobusDebugDefine(GLOBUS_XIO_GSSAPI_FTP);

#define GlobusXIOGssapiftpDebugPrintf(level, message)                      \
    GlobusDebugPrintf(GLOBUS_XIO_GSSAPI_FTP, level, message)

#define GlobusXIOGssapiftpDebugEnter()                                     \
    GlobusXIOGssapiftpDebugPrintf(                                         \
        GLOBUS_L_XIO_GSSAPI_FTP_DEBUG_TRACE,                               \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOGssapiftpDebugExit()                                      \
    GlobusXIOGssapiftpDebugPrintf(                                         \
        GLOBUS_L_XIO_GSSAPI_FTP_DEBUG_TRACE,                               \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOGssapiftpDebugExitWithError()                             \
    GlobusXIOGssapiftpDebugPrintf(                                         \
        GLOBUS_L_XIO_GSSAPI_FTP_DEBUG_TRACE,                               \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_GSSAPI_FTP_DEBUG_TRACE       = 1,
    GLOBUS_L_XIO_GSSAPI_FTP_DEBUG_INFO        = 2
};

#define REPLY_530_BAD_MESSAGE "530 Please login with USER and PASS.\r\n"
#define REPLY_504_BAD_AUTH_TYPE "504 Unknown authentication type.\r\n"
#define REPLY_334_GOOD_AUTH_TYPE "334 Using authentication type; ADAT must follow\r\n"
#define REPLY_530_EXPECTING_ADAT "530 Must perform GSSAPI authentication\r\n"

#define REPLY_235_ADAT_DATA "235 ADAT="
#define REPLY_335_ADAT_DATA "335 ADAT="

#define CLIENT_AUTH_GSSAPI_COMMAND "AUTH GSSAPI\r\n"

#define REPLY_221_QUIT "221 Goodbye\r\n"


#define GSSAPI_FTP_DEFAULT_BUFSIZE 1024

static char                             globus_l_xio_gssapi_ftp_pad = '=';
static char *                           globus_l_xio_gssapi_ftp_radix_n =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                                                                
/**************************************************************************
 *                    data type definitions 
 *                    ---------------------
 *************************************************************************/

/**
 *  opening
 *  -------
 *  When a user opens a handle the authentication process begins.  The 
 *  default case will do the entire authentication processes as described
 *  in the state machine.  However the user can override various bits
 *  of the authentication process by setting the start state on the handle
 *  attr.
 */
/*
 *  writting
 *  --------
 *  Once an open handle is esstablished the user may post writes.  If 
 *  a write is posted that does not contain a complete command (no \r\n)
 *  then it is copied to an internal buffer and the user is told that the
 *  write operation is complete.  As soon as a complete comman is received
 *  it is wrapped and encoded then passed down the stack.  Additional 
 *  data beyound a complete command is cached in the same way.
 */

/*
 *  reading
 *  -------
 *  When the user request a read into a buffer a request structure is created
 *  and added to a queue.  The queue is then polled for availuable data.
 *  There is alos a queue of complete commands recevied.  If this queue
 *  when the user requests data and a read is not outstanding, then another
 *  read is posted.  If it is not empty the command is removed and unwrapped.
 *  Unwrapped commands are put into yet another queue.  The first element
 *  in the unwrapped copied to the user buffer.  If the user buffer is not
 *  larege enough to compy the entire unwrapped command, then the remaining
 *  bits of it are left in the queue, otherwise it is removed.
 *
 *  note:  the reason for the queue which holds the commands before they
 *         are unrapped is fo the autenticaton of the open processes,  It
 *         may be possible to remove the need for this queue but at this point
 *         it is not causing any problems.
 */
typedef struct globus_l_xio_gssapi_ftp_handle_s
{
    /* gssapi security info */
    gss_ctx_id_t                        gssapi_context;
    gss_cred_id_t                       cred_handle;
    gss_cred_id_t                       delegated_cred_handle;
    char *                              auth_gssapi_subject;
    gss_name_t                          target_name;
    globus_bool_t                       encrypt;
    char *                              host;
    char *                              subject;

    char **                             banner;

    globus_i_xio_gssapi_ftp_state_t     state;

    globus_bool_t                       client;

    globus_fifo_t                       read_command_q;
    globus_bool_t                       read_posted;

    globus_bool_t                       super_mode;
    globus_xio_iovec_t                  read_iov;
    globus_byte_t *                     read_buffer;
    globus_size_t                       read_buffer_length;
    globus_size_t                       read_buffer_ndx;
    globus_fifo_t                       read_req_q;
    globus_fifo_t                       unwrapped_q;
 
    globus_xio_iovec_t *                write_iov;
    globus_size_t                       write_iov_count;
    globus_size_t                       write_iov_size;
    globus_byte_t *                     write_buffer;
    globus_size_t                       write_buffer_length;
    globus_size_t                       write_buffer_ndx;
    globus_size_t                       write_sent_length;
    globus_bool_t                       write_posted;
} globus_l_xio_gssapi_ftp_handle_t;

/*
 *  attribute structure.
 */
typedef struct globus_l_xio_gssapi_attr_s
{
    globus_bool_t                       encrypt;
    char *                              subject;
    globus_i_xio_gssapi_ftp_state_t     start_state;
    globus_bool_t                       super_mode;
} globus_l_xio_gssapi_attr_t;

typedef struct globus_l_xio_gssapi_read_req_s
{
    globus_xio_iovec_t *                iov;
    int                                 iovc;
} globus_l_xio_gssapi_read_req_t;

typedef struct globus_l_xio_gssapi_buffer_s
{
    globus_size_t                       length;
    globus_size_t                       ndx;
    globus_byte_t *                     buf;
} globus_l_xio_gssapi_buffer_t;

/**************************************************************************
 *                    function prototypes
 *                    -------------------
 *************************************************************************/
static int
globus_l_xio_gssapi_ftp_activate();

static int
globus_l_xio_gssapi_ftp_deactivate();

static void
globus_l_xio_gssapi_ftp_server_open_reply_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static void
globus_l_xio_gssapi_ftp_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static globus_result_t
globus_l_xio_gssapi_ftp_server_incoming(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op,
    char **                             cmd_a);

static void
globus_l_xio_gssapi_ftp_client_open_reply_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static globus_result_t
globus_l_xio_gssapi_ftp_decode_adat(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    const char *                        wrapped_command,
    char **                             out_reply,
    globus_bool_t *                     out_complete);

globus_result_t
globus_l_xio_gssapi_ftp_client_incoming(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op,
    char **                             cmd_a);

globus_result_t
globus_l_xio_gssapi_finshed_read(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op);

char **
globus_l_xio_gssapi_ftp_command_array_copy(
    char **                             cmd_a);

/**************************************************************************
 *                    global data
 *                    -----------
 *************************************************************************/
#include "version.h"

static globus_module_descriptor_t       globus_i_xio_gssapi_ftp_module =
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
/*
 *  given a buffer this function will tell you if it contains a 
 *  complete command.
 */
globus_bool_t
globus_l_xio_gssapi_ftp_complete_command(
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_bool_t                       client,
    globus_size_t *                     end_offset)
{
    globus_byte_t *                     tmp_ptr;
    globus_size_t                       end_off;
    GlobusXIOName(globus_l_xio_gssapi_ftp_complete_command);

    GlobusXIOGssapiftpDebugEnter();

    /* all a 0 length to be passed */
    if(length == 0)
    {
        GlobusXIOGssapiftpDebugExit();
        return GLOBUS_FALSE;
    }

    tmp_ptr = globus_libc_memrchr(buffer, '\r', length);
    /* IF There is no '\r' */
    if(tmp_ptr == NULL)
    {
        GlobusXIOGssapiftpDebugExit();
        return GLOBUS_FALSE;
    }
    end_off = tmp_ptr - buffer;

    /* if the '\r' is the last character, or the next isn't '\n' */
    if(end_off == length - 1 || tmp_ptr[1] != '\n')
    {
        GlobusXIOGssapiftpDebugExit();
        return GLOBUS_FALSE;
    }

    /* if server we are done as soon as we get \r\n */
    if(!client)
    {
        *end_offset = end_off;
        GlobusXIOGssapiftpDebugExit();
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
        GlobusXIOGssapiftpDebugExit();
        return GLOBUS_TRUE;
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_FALSE;
}


/*
 *  allocate the memory for and initialize an internal handle
 */
static globus_l_xio_gssapi_ftp_handle_t *
globus_l_xio_gssapi_ftp_handle_create()
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_handle_create);

    GlobusXIOGssapiftpDebugEnter();

    /*
     *  create a new handle and initialize it
     */
    handle = (globus_l_xio_gssapi_ftp_handle_t *) 
                globus_libc_malloc(sizeof(globus_l_xio_gssapi_ftp_handle_t));
    if(handle == NULL)
    {
	goto err; 	
    }
    handle->gssapi_context = GSS_C_NO_CONTEXT;
    handle->delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    handle->encrypt = GLOBUS_FALSE;
    handle->host = NULL;
    handle->super_mode = GLOBUS_FALSE;
    handle->subject = NULL;
    handle->target_name = GSS_C_NO_NAME;

    /* read data members */
    globus_fifo_init(&handle->read_command_q);
    handle->read_posted = GLOBUS_FALSE;
    handle->write_posted = GLOBUS_FALSE;

    /* allocate a static buffer for reading in commands.  Since only
       one read is passed down at a  time. */
    handle->read_buffer = globus_malloc(GSSAPI_FTP_DEFAULT_BUFSIZE);
    if(handle->read_buffer == NULL)
    {
        globus_free(handle);
	goto err;
    }
    handle->read_buffer_length = GSSAPI_FTP_DEFAULT_BUFSIZE;
    handle->read_buffer_ndx = 0;
    globus_fifo_init(&handle->read_req_q);
    globus_fifo_init(&handle->unwrapped_q);

    /* write data members */
    handle->write_iov_size = 2;
    handle->write_iov = (globus_xio_iovec_t *) 
        globus_malloc(sizeof(globus_xio_iovec_t) * handle->write_iov_size);
    if(handle->write_iov == NULL)
    {
        globus_free(handle->read_buffer);
        globus_free(handle);
	goto err;
    }
    handle->write_buffer_ndx = 0;
    handle->write_buffer_length = GSSAPI_FTP_DEFAULT_BUFSIZE;
    handle->write_buffer = globus_malloc(GSSAPI_FTP_DEFAULT_BUFSIZE);
    if(handle->write_buffer == NULL)
    {
        globus_free(handle->read_buffer);
        globus_free(handle->write_iov);
        globus_free(handle);
	goto err;
    }

    GlobusXIOGssapiftpDebugExit();
    return handle;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return NULL;
}

/*
 *  clean up a handle and all memory associated with it
 */
static void
globus_l_xio_gssapi_ftp_handle_destroy(
    globus_l_xio_gssapi_ftp_handle_t *  handle)
{
    OM_uint32                           min_stat;
    GlobusXIOName(globus_l_xio_gssapi_ftp_handle_destroy);

    GlobusXIOGssapiftpDebugEnter();

    if(handle->subject)
    {
        globus_free(handle->subject);
    }
    if(handle->host)
    {
        globus_free(handle->host);
    }

    if(handle->target_name != GSS_C_NO_NAME)
    {
        gss_release_name(&min_stat, &handle->target_name);
    }
    if(handle->gssapi_context != GSS_C_NO_CONTEXT)
    {
        gss_delete_sec_context(
            &min_stat,
            &handle->gssapi_context,
            GLOBUS_NULL);
    }

    globus_free(handle->read_buffer);
    globus_free(handle->write_buffer);
    globus_free(handle->write_iov);
    globus_fifo_destroy(&handle->read_req_q);
    globus_fifo_destroy(&handle->unwrapped_q);
    globus_fifo_destroy(&handle->read_command_q);

    globus_free(handle);
    GlobusXIOGssapiftpDebugExit();
}

/*
 *  decode a base64 encoded string.  The caller provides all the needed
 *  memory.
 *
 *  TODO: move this to globus common
 */
globus_result_t
globus_l_xio_gssapi_ftp_radix_decode(
    const unsigned char  *              inbuf,
    globus_byte_t *                     outbuf,
    globus_size_t *                     out_len)
{
    int                                 i;
    int                                 j;
    int                                 D;
    char *                              p;
    GlobusXIOName(globus_l_xio_gssapi_ftp_radix_decode);

    GlobusXIOGssapiftpDebugEnter();

    for (i=0,j=0; inbuf[i] && inbuf[i] != globus_l_xio_gssapi_ftp_pad; i++)
    {
        if ((p = strchr(globus_l_xio_gssapi_ftp_radix_n, inbuf[i])) == NULL)
        {
	    goto err;
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
                break;
        }
    }

    switch (i&3)
    {
        case 1:
	    goto err;
 
       case 2:
            if (D&15)
            {
	        goto err;
            }
            if (strcmp((char *)&inbuf[i], "=="))
            {
	        goto err;
            }
            break;

        case 3:
            if (D&3)
            {
	        goto err;
            }
            if (strcmp((char *)&inbuf[i], "="))
            {
	        goto err;
            }
            break;

        default:
            break;
    }
    *out_len = j;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return GlobusXIOGssapiFTPEncodingError();

}

/*
 *  base64 encode a string, string may not be null terminated
 *
 *  TODO: move this to globus common
 */
static globus_result_t
globus_l_xio_gssapi_ftp_radix_encode(
    const unsigned char *               inbuf,
    globus_size_t                       in_len,
    globus_byte_t *                     outbuf,
    globus_size_t *                     out_len)
{
    int                                 i;
    int                                 j;
    unsigned char                       c;
    GlobusXIOName(globus_l_xio_gssapi_ftp_radix_encode);

    GlobusXIOGssapiftpDebugEnter();

    for (i=0,j=0; i < in_len; i++)
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

    outbuf[j] = '\0';
    *out_len = j;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;
}

/*
 *  tokenze a bufer based on the globus ftp protocol.  White space will
 *  seperate tokens and DRLF will be removed from them.
 */
globus_byte_t *
globus_l_xio_gssapi_ftp_token(
    globus_byte_t *                     in_str,
    globus_size_t                       length,
    globus_size_t *                     out_start_off,
    globus_size_t *                     out_length)
{
    globus_byte_t *                     start_ptr;
    globus_byte_t *                     tmp_ptr;
    globus_byte_t *                     end_ptr;
    GlobusXIOName(globus_l_xio_gssapi_ftp_token);

    GlobusXIOGssapiftpDebugEnter();

    end_ptr = &in_str[length];
    tmp_ptr = (char *)in_str;
    while(tmp_ptr != end_ptr && isspace(*tmp_ptr))
    {
        tmp_ptr++;
    }
    if(tmp_ptr == end_ptr)
    {
        GlobusXIOGssapiftpDebugExit();
        return NULL;
    }
    start_ptr = tmp_ptr;
    *out_start_off = (tmp_ptr - in_str);

    while(tmp_ptr != end_ptr && !isspace(*tmp_ptr))
    {
        tmp_ptr++;
    }
    *out_length = tmp_ptr - start_ptr;

    GlobusXIOGssapiftpDebugExit();
    return start_ptr;
}

/*
 *  tokenize a command into a null teminated array of strings.  If the
 *  command being tokenized is a reply from the server this code will
 *  remove all continuation headers (631-) and the first element in the
 *  finally tokenized reply array will be the reply number.
 */
globus_result_t
globus_l_xio_gssapi_ftp_parse_command(
    globus_byte_t *                     command,
    globus_size_t                       length,
    globus_bool_t                       client,
    char ***                            out_cmd_a)
{
    char *                              tmp_ptr;
    char **                             cmd_a = NULL;
    int                                 cmd_len = 16;
    int                                 ctr;
    globus_size_t                       start_ndx;
    globus_result_t                     res;
    globus_size_t                       len;
    globus_size_t                       sub_len;
    globus_bool_t                       multi = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_gssapi_ftp_parse_command);

    GlobusXIOGssapiftpDebugEnter();

    *out_cmd_a = NULL;
    /* validate the entire command */
    for(len = 0; len < length; len++)
    {
        if(!isalnum(command[len]) && !isspace(command[len]) && 
            command[len] != '\r' && command[len] != '\n')
        {
            /* TODO: deal with this */
        }
    }

    cmd_a = (char **) globus_malloc(sizeof(char *) * cmd_len);
    if(cmd_a == NULL)
    {
        res = GlobusXIOGssapiFTPAllocError();
	goto err;
    }

    len = length;
    ctr = 0;
    tmp_ptr = globus_l_xio_gssapi_ftp_token(
        command, len, &start_ndx, &sub_len);
    while(tmp_ptr != NULL)
    {
        len -= start_ndx; /* start ndx is removed from the front */
        /* special handling for multiplart commands */
        if(client)
        {
            /* if this will be a multipart command */
            if(ctr == 0 && tmp_ptr[3] == '-')
            {
                cmd_a[ctr] = globus_libc_strndup(tmp_ptr, 3);
                multi = GLOBUS_TRUE;
                len -= 4;
                tmp_ptr += 4;
                sub_len -= 4;
                ctr++;
            }
            /* if a continuation line move past the start */
            else if(multi && sub_len >= 3 &&
                    strncmp(cmd_a[0], tmp_ptr, 3) == 0)
            {
                if(tmp_ptr[3] == ' ')
                {
                    len -= 4;
                    tmp_ptr = globus_l_xio_gssapi_ftp_token(
                        &tmp_ptr[4], len, &start_ndx, &sub_len);
                }
                else if(tmp_ptr[3] == '-')
                {
                    len -= 4;
                    tmp_ptr += 4;
                    sub_len -= 4;
                }
                /* feat is returning continuation commands that look strabge
                   this allows it to work, but TODO: verifiy server is 
                   correct */
                else
                {
                    len -= 4;
                    tmp_ptr += 4;
                    sub_len -= 4;
                }
            }
        }
        cmd_a[ctr] = globus_libc_strndup(
            tmp_ptr, sub_len);
        len -= sub_len;
        tmp_ptr += sub_len;
        tmp_ptr = globus_l_xio_gssapi_ftp_token(
            tmp_ptr, len, &start_ndx, &sub_len);
        ctr++;
        if(ctr == cmd_len)
        {
            cmd_len *= 2;
            cmd_a = (char **) globus_libc_realloc(cmd_a,
                                sizeof(char *) * cmd_len);
        }
    }
    cmd_a[ctr] = NULL;

    *out_cmd_a = cmd_a;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:
    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

/*
 *  turn a command array back into a sericalized buffer
 */
globus_result_t
globus_l_xio_gssapi_ftp_serialize_command_array(
    char **                             cmd_a,
    globus_byte_t *                     out_buffer,
    globus_size_t                       buffer_length)
{
    int                                 ctr;
    globus_size_t                       len = 0;
    globus_size_t                       ndx = 0;
    GlobusXIOName(globus_l_xio_gssapi_ftp_serialize_command_array);

    GlobusXIOGssapiftpDebugEnter();

    for(ctr = 0; cmd_a[ctr] != NULL; ctr++)
    {
        len = strlen(cmd_a[ctr]);
        if(len + ndx + 1 > buffer_length)
        {
	    goto err;
        }
        memcpy(&out_buffer[ndx], cmd_a[ctr], len); 
        ndx += len;
        out_buffer[ndx] = ' ';
        ndx++;
    }
    out_buffer[ndx - 1] = '\r';
    out_buffer[ndx] = '\n';
    out_buffer[ndx + 1] = '\0';

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return GlobusXIOGssapiFTPAllocError();
}

/*
 *  return he buffer length needed to serialize a command array
 */
globus_size_t
globus_l_xio_gssapi_ftp_command_array_size(
    char **                             cmd_a)
{
    int                                 ctr;
    globus_size_t                       len = 0;
    GlobusXIOName(globus_l_xio_gssapi_ftp_command_array_size);

    GlobusXIOGssapiftpDebugEnter();

    for(ctr = 0; cmd_a[ctr] != NULL; ctr++)
    {
        len += strlen(cmd_a[ctr]);
        len++; /* for a space */
    }
    len += 2; /* for CRLF */

    GlobusXIOGssapiftpDebugExit();
    return len;
}

/*
 *  return he buffer length needed to serialize a command array
 */
char **
globus_l_xio_gssapi_ftp_command_array_copy(
    char **                             cmd_a)
{
    char **                             out_cmd_a;
    int                                 ctr;
    globus_size_t                       size;
    GlobusXIOName(globus_l_xio_gssapi_ftp_command_array_copy);

    GlobusXIOGssapiftpDebugEnter();

    size = globus_l_xio_gssapi_ftp_command_array_size(cmd_a);


    for(ctr = 0; cmd_a[ctr] != NULL; ctr++)
    {
    }
    size = ctr + 1;
    out_cmd_a = (char **) globus_malloc(sizeof(char **) * size);

    for(ctr = 0; cmd_a[ctr] != NULL; ctr++)
    {
        out_cmd_a[ctr] = globus_libc_strdup(cmd_a[ctr]);
    }
    out_cmd_a[ctr] = NULL;

    GlobusXIOGssapiftpDebugExit();
    return out_cmd_a;
}


/*
 *  take a wrapped buffer and decode and unwrap it.  The caller is 
 *  responsible for freeing the out buffer if the function returns 
 *  successfully.
 */
globus_result_t
globus_l_xio_gssapi_ftp_unwrap(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    const char  *                       in_buf,
    globus_size_t                       in_length,
    char **                             out_buffer)
{
    globus_result_t                     res;
    gss_buffer_desc                     wrapped_token;
    gss_buffer_desc                     unwrapped_token;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    globus_byte_t *                     buf;
    globus_size_t                       len;
    GlobusXIOName(globus_l_xio_gssapi_ftp_unwrap);

    GlobusXIOGssapiftpDebugEnter();

    /* allocate out buffer same size as in, assuming unwrap will be samller */
    buf =  globus_malloc(in_length);
    if(buf == NULL)
    {
        goto err;
    }
    len = in_length;

    res = globus_l_xio_gssapi_ftp_radix_decode(in_buf, buf, &len);
    if(res != GLOBUS_SUCCESS)
    {
        res = GlobusXIOGssapiFTPAllocError();
        globus_free(buf);
        goto err;
    }

    wrapped_token.value = buf;
    wrapped_token.length = len;

    maj_stat = gss_unwrap(
                    &min_stat,
                    handle->gssapi_context,
                    &wrapped_token,
                    &unwrapped_token,
                    NULL,
                    NULL);
    if(maj_stat != GSS_S_COMPLETE)
    {
        res = GlobusXIOGssapiFTPGSIAuthFailure(maj_stat, min_stat);
        globus_free(buf);
        goto err;
    }

    /* copy the unwrapped token in */
    memcpy(buf, unwrapped_token.value, unwrapped_token.length);
    len = unwrapped_token.length;

    /* get rid of terminating NULL */
    if(buf[len - 1] == '\0')
    {
        len--;
    }
    buf[len] = '\0';

    *out_buffer = (char *) buf;

    gss_release_buffer(&min_stat, &unwrapped_token);

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

/*
 *  wrap a command with gssapi encoding then base 64 encode it.  If the
 *  function returns successfully the caller is responsible for freeing
 *  the out_buffer.  The out buffer is formed into a ftp buffer based on
 *  values in the handle.  ex: if client starts with MIC or ENC. if server
 *  starts with 631 or 632
 */
globus_result_t
globus_l_xio_gssapi_ftp_wrap(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_byte_t  *                    in_buf, 
    globus_size_t                       length,
    char **                             out_buffer,
    globus_bool_t                       client)
{
    char *                              encoded_buf;
    int                                 conf_state;
    gss_buffer_desc                     gss_in_buf;
    gss_buffer_desc                     gss_out_buf;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_wrap);

    GlobusXIOGssapiftpDebugEnter();

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
        res = GlobusXIOGssapiFTPGSIAuthFailure(maj_stat, min_stat);
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
        gss_out_buf.length,
        &encoded_buf[4],
        &gss_out_buf.length);

    encoded_buf[gss_out_buf.length+4]='\r';
    encoded_buf[gss_out_buf.length+5]='\n';
    encoded_buf[gss_out_buf.length+6]='\0';
    *out_buffer = encoded_buf;

    gss_release_buffer(&min_stat, &gss_out_buf);

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

/*
 *  post a request for more data.  Data comes in via a call to 
 *  globus_l_xio_gssapi_ftp_client_incoming or 
 *  globus_l_xio_gssapi_ftp_server_incoming.  If the returns successfully
 *  the operation has been consumend by either a Pass or a Finsihed.
 *  This function should be called locked.
 */
globus_result_t
globus_l_xio_gssapi_get_data(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op)
{
    int                                 ctr;
    char **                             cmd_a;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_gssapi_get_data);

    GlobusXIOGssapiftpDebugEnter();

    /* if data is already available hand it off */
    if(!globus_fifo_empty(&handle->read_command_q))
    {
        cmd_a = (char **) globus_fifo_dequeue(&handle->read_command_q);
        if(handle->client)
        {
            res = globus_l_xio_gssapi_ftp_client_incoming(handle, op, cmd_a);
        }
        else
        {
            res = globus_l_xio_gssapi_ftp_server_incoming(handle, op, cmd_a);
        }
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }

        for(ctr = 0; cmd_a[ctr] != NULL; ctr++)
        {
            globus_free(cmd_a[ctr]);
        }
        globus_free(cmd_a);
    }
    /* if no data is ready and we are not already waiting for it
       post another read */
    else if(!handle->read_posted)
    {
        /* if buffer is too small double it */
        if(handle->read_buffer_ndx + 1 >= handle->read_buffer_length)
        {
            handle->read_buffer_length =
                (handle->read_buffer_length + 1) * 2;
            handle->read_buffer = globus_libc_realloc(
                    handle->read_buffer,
                    handle->read_buffer_length);
        }
        handle->read_iov.iov_base =
            &handle->read_buffer[handle->read_buffer_ndx];
        handle->read_iov.iov_len =
            handle->read_buffer_length - handle->read_buffer_ndx;
        res = globus_xio_driver_pass_read(
            op,
            &handle->read_iov,
            1,
            1,
            globus_l_xio_gssapi_ftp_read_cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        handle->read_posted = GLOBUS_TRUE;
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

/*
 *  continue to post more reads until a complete command is received.
 *  Once receive action will be based on current state.
 */
static void
globus_l_xio_gssapi_ftp_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    globus_size_t                       end_off;
    globus_bool_t                       complete = GLOBUS_TRUE;
    globus_result_t                     res;
    char **                             cmd_a;
    globus_size_t                       remain;
    GlobusXIOName(globus_l_xio_gssapi_ftp_read_cb);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    /* read_posted flag makes sure that only 1 read is outstanding
        at a time */
    handle->read_posted = GLOBUS_FALSE;
    handle->read_buffer_ndx += nbytes;
    complete = globus_l_xio_gssapi_ftp_complete_command(
                    handle->read_buffer,
                    handle->read_buffer_ndx,
                    handle->client,
                    &end_off);
    /*
     *  go through every complete command in the buffer.  Most often
     *  this will be only 1
     */
    while(complete)
    {
        /* null terminate teh command, overwritting the '\r' */
        handle->read_buffer[end_off] = '\0';
        /* tokenize the command */
        globus_l_xio_gssapi_ftp_parse_command(
                handle->read_buffer,
                end_off,
                handle->client,
                &cmd_a);
        if(cmd_a == NULL)
        {
            res = GlobusXIOGssapiFTPAllocError();
            goto err;
        }
        globus_fifo_enqueue(&handle->read_command_q, cmd_a);

        /* if we read beyound a command, move everything to the front */
        remain = handle->read_buffer_ndx - end_off - 2;
        /* reset the read pointer and move everything after the CRLF to
            the begining of the buffer */
        if(remain > 0)
        {
            memmove(
                handle->read_buffer, 
                &handle->read_buffer[end_off + 2],   
                remain);
        }
        handle->read_buffer_ndx = remain;

        /* see if there is another complate command in the buffer */
        complete = globus_l_xio_gssapi_ftp_complete_command(
                    handle->read_buffer,
                    handle->read_buffer_ndx,
                    handle->client,
                    &end_off);
    } /* end while */
    /* either an event occured to process or we need to post again for 
       the incomplete event */
    res = globus_l_xio_gssapi_get_data(handle, op);

    /* check error code of call to next command */
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIOGssapiftpDebugExit();
    return;

  err:

    /* determine if this was part of a read operation or part of a open */
    if(handle->state == GSSAPI_FTP_STATE_OPEN)
    {
        globus_xio_driver_finished_read(op, res, 0);
    }
    else
    {
        globus_xio_driver_finished_open(handle, op, res);
    }
    GlobusXIOGssapiftpDebugExitWithError();
    return;
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
globus_l_xio_gssapi_ftp_server_incoming(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op,
    char **                             cmd_a)
{
    char *                              out_buf;
    char *                              msg;
    globus_result_t                     res;
    globus_bool_t                       complete;
    globus_bool_t                       reply = GLOBUS_TRUE;
    globus_l_xio_gssapi_buffer_t *      w_buf = NULL;
    GlobusXIOName(globus_l_xio_gssapi_ftp_server_incoming);

    GlobusXIOGssapiftpDebugEnter();

    if(globus_libc_strcmp(cmd_a[0], "QUIT") == 0)
    {
        msg = globus_libc_strdup(REPLY_221_QUIT);
        handle->state = GSSAPI_FTP_STATE_SERVER_QUITING;
    }
    else
    {
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

            case GSSAPI_FTP_STATE_OPEN:
                reply = GLOBUS_FALSE;
                w_buf = (globus_l_xio_gssapi_buffer_t *)
                    globus_malloc(sizeof(globus_l_xio_gssapi_buffer_t));
                if(w_buf == NULL)
                {
                    res = GlobusXIOGssapiFTPAllocError();
                    goto err;
                }
                res = globus_l_xio_gssapi_ftp_unwrap(
                        handle,
                        cmd_a[1],
                        strlen(cmd_a[1]),
                        &out_buf);
                if(res != GLOBUS_SUCCESS)
                {
                    goto err;
                }
                w_buf->length = strlen(out_buf);
                w_buf->buf = out_buf;
                w_buf->ndx = 0;
                globus_fifo_enqueue(&handle->unwrapped_q, w_buf);
                res = globus_l_xio_gssapi_finshed_read(handle, op);

                break;

            default:
                globus_assert(0 && "Handle should be in reading state");
                break;
        }
    }

    if(reply)
    {
        /* send the entire reply */
        handle->write_iov[0].iov_base = msg;
        handle->write_iov[0].iov_len = globus_libc_strlen(msg);
        res = globus_xio_driver_pass_write(
            op, 
            handle->write_iov,
            1, 
            handle->write_iov[0].iov_len,
            globus_l_xio_gssapi_ftp_server_open_reply_cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:
    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

/*
 *  while in the open authentication process, this callback is used for
 *  all of the writes.  
 */ 
static void
globus_l_xio_gssapi_ftp_server_open_reply_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_bool_t                       done = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_gssapi_ftp_server_open_reply_cb);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    /* if there was an error, finish the open with an error */
    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    handle->write_posted = GLOBUS_FALSE;
    globus_free(handle->write_iov[0].iov_base);
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

        case GSSAPI_FTP_STATE_SERVER_QUITING:
            done = GLOBUS_TRUE;
            res = GlobusXIOGssapiFTPAuthenticationFailure("received QUIT");
            break;

        default:
            break;
    }

    if(!done)
    {
        /* start processing the next command */
        res = globus_l_xio_gssapi_get_data(handle, op);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    else
    {
        globus_xio_driver_finished_write(op, res, nbytes);
    }

    GlobusXIOGssapiftpDebugExit();
    return;

  err:
    globus_xio_driver_finished_write(op, res, nbytes);
    GlobusXIOGssapiftpDebugExitWithError();
    return;
}
/*
 *  while in the open authentication process, this callback is used for
 *  all of the writes.  
 */ 
static void
globus_l_xio_gssapi_ftp_client_open_reply_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_gssapi_ftp_client_open_reply_cb);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    globus_free(handle->write_iov[0].iov_base);
    /* if there was an error, finish the open with an error */
    if(result != GLOBUS_SUCCESS)
    {
        res = result;
        goto err;
    }

    res = globus_l_xio_gssapi_get_data(handle, op);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIOGssapiftpDebugExit();
    return;

  err:
    globus_xio_driver_finished_open(handle, op, res);
    GlobusXIOGssapiftpDebugExitWithError();
    return;
}


/*
 *  decode a command
 */
static globus_result_t
globus_l_xio_gssapi_ftp_decode_adat(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    const char *                        wrapped_command,
    char **                             out_reply,
    globus_bool_t *                     out_complete)
{
    char *                              reply;
    globus_result_t                     res;
    OM_uint32                           ret_flags = 0;
    OM_uint32                           min_stat;
    OM_uint32                           maj_stat;
    globus_size_t                       length;
    char *                              decoded_cmd;
    gss_buffer_desc                     recv_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                     send_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                     subject_buf = GSS_C_EMPTY_BUFFER;
    gss_OID                             mech_type;
    GlobusXIOName(globus_l_xio_gssapi_ftp_decode_adat);

    GlobusXIOGssapiftpDebugEnter();

    length = globus_libc_strlen(wrapped_command);
    if(length <= 0)
    {
        res = GlobusXIOGssapiFTPAuthenticationFailure(
            "attempting to wrap a 0 length command.");
        goto err;
    }

    decoded_cmd = (char *) globus_libc_malloc((length+3) * 6/8);
    if(decoded_cmd == NULL)
    {
        res = GlobusXIOGssapiFTPAllocError();
        goto err;
    }
    res = globus_l_xio_gssapi_ftp_radix_decode(
            wrapped_command,
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
             maj_stat = gss_export_name(
                        &min_stat,
                        handle->target_name,
                        &subject_buf);

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
                        send_tok.length,
                        &reply[strlen(REPLY_235_ADAT_DATA)],
                        &length);
                if(res != GLOBUS_SUCCESS)
                {
                    gss_release_buffer(&min_stat, &send_tok);
                    goto err;
                }
		memcpy(&reply[strlen(REPLY_235_ADAT_DATA)+length], "\r\n\0", 3);
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
                    send_tok.length,
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
            res = GlobusXIOGssapiFTPGSIAuthFailure(maj_stat, min_stat);
            goto err;
            break;
    }

    *out_reply = reply;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

/*
 *   accepting
 *
 *   Meary pass the accept, set handle state to server.  The open will
 *   take care of the protocol exchange.
 */
static void
globus_l_xio_gssapi_ftp_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_accept_cb);

    GlobusXIOGssapiftpDebugEnter();

    if(result != GLOBUS_SUCCESS)
    {
        goto err;
    }

    globus_xio_driver_finished_accept(op, (void *) 0x01, GLOBUS_SUCCESS);

    GlobusXIOGssapiftpDebugExit();
    return;

  err:

    globus_xio_driver_finished_accept(op, NULL, result);
    GlobusXIOGssapiftpDebugExitWithError();
    return;
}

/*
 *  callback for the pass open.  If the state is not completely open 
 *  post a read to move to the next point in the authentication 
 *  process.  In the normal case this will be AUTH, however the user
 *  may circumvent these steps.
 */
static void
globus_l_xio_gssapi_ftp_client_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_client_open_cb);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    globus_assert(handle->client);

    if(handle->state != GSSAPI_FTP_STATE_OPEN && result == GLOBUS_SUCCESS)
    {
        result = globus_l_xio_gssapi_get_data(handle, op);
    }
    /* if error occured on the way in or due to read, finish the open
        with an error, or we started in the open state, then finish
        with success */
    if(result != GLOBUS_SUCCESS || handle->state == GSSAPI_FTP_STATE_OPEN)
    {
        globus_xio_driver_finished_open(handle, op, result);
    }

    GlobusXIOGssapiftpDebugExit();
}

static void
globus_l_xio_gssapi_ftp_server_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_server_open_cb);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    globus_xio_driver_finished_open(handle, op, result);

    GlobusXIOGssapiftpDebugExit();
}

/************************************************************************
 *                  client open functions
 *                  ---------------------
 *  
 *   This section has functions that open a handle for a client
 ***********************************************************************/

globus_result_t
globus_l_xio_gssapi_ftp_client_adat(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    const char *                        buffer,
    char **                             out_buffer,
    globus_bool_t *                     complete)
{
    gss_buffer_desc                     send_tok;
    gss_buffer_desc                     recv_tok;
    gss_buffer_desc *                   token_ptr;
    OM_uint32                           min_stat;
    OM_uint32                           maj_stat;
    OM_uint32                           req_flags = 0;
    globus_result_t                     res;
    globus_byte_t *                     radix_buf;
    globus_size_t                       length;
    char                                hostname[128+5];
    gss_OID                             name_type;
    GlobusXIOName(globus_l_xio_gssapi_ftp_client_adat);

    GlobusXIOGssapiftpDebugEnter();

    switch(handle->state)
    {
        case GSSAPI_FTP_STATE_CLIENT_ADAT_INIT:

            if(handle->subject == NULL)
            {
                sprintf(hostname, "host@%s", handle->host);

                send_tok.value = hostname;
                send_tok.length = strlen(hostname) + 1;
                name_type = GSS_C_NT_HOSTBASED_SERVICE;
            }
            else
            {
                send_tok.value = handle->subject;
                send_tok.length = strlen(handle->subject) + 1;
                name_type = GSS_C_NT_USER_NAME;
            }
            maj_stat = gss_import_name(
                            &min_stat,
                            &send_tok,
                            name_type,
                            &handle->target_name);
            if(maj_stat != GSS_S_COMPLETE)
            {
                res = GlobusXIOGssapiFTPGSIAuthFailure(maj_stat, min_stat);
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
                        send_tok.value, 
                        send_tok.length, 
                        &radix_buf[5],
                        &length);
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
            res = GlobusXIOGssapiFTPGSIAuthFailure(maj_stat, min_stat);
            goto err;
    }
    gss_release_buffer(&min_stat, &send_tok);
    gss_release_buffer(&min_stat, token_ptr);

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

globus_result_t
globus_l_xio_gssapi_ftp_client_incoming(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op,
    char **                             cmd_a)
{
    globus_size_t                       len;
    globus_bool_t                       done = GLOBUS_FALSE;
    globus_bool_t                       complete;
    globus_result_t                     res = GLOBUS_SUCCESS;
    char *                              send_buffer;
    char *                              tmp_buf;
    int                                 ctr;
    globus_l_xio_gssapi_buffer_t *      w_buf;
    GlobusXIOName(globus_l_xio_gssapi_ftp_client_incoming);

    GlobusXIOGssapiftpDebugEnter();

    switch(handle->state)
    {
        case GSSAPI_FTP_STATE_CLIENT_READING_220:
            /* if we did not get a 220 from the server finsh the open
                with an error */
            if(strcmp(cmd_a[0], "220") != 0)
            {
                res = GlobusXIOGssapiFTPAuthenticationFailure("Expected 220");
                goto err;
            }
            else
            {
                handle->state = GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH;
                send_buffer = globus_libc_strdup(CLIENT_AUTH_GSSAPI_COMMAND);

                handle->banner = globus_l_xio_gssapi_ftp_command_array_copy(
                    cmd_a);
            }
            break;

        case GSSAPI_FTP_STATE_CLIENT_SENDING_AUTH:
            if(strcmp(cmd_a[0], "334") != 0)
            {
                res = GlobusXIOGssapiFTPAuthenticationFailure("Expected 334");
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
                    res = GlobusXIOGssapiFTPAuthenticationFailure(
                        "Client should have adat buffer to send");
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
                            tmp_buf,
                            &send_buffer,
                            &complete);
                    if(res != GLOBUS_SUCCESS)
                    {
                        goto err;
                    }
                    if(!complete || send_buffer != NULL)
                    {
                        res = GlobusXIOGssapiFTPAuthenticationFailure(
                        "Client should have adat buffer to send");
                        goto err;
                    }
                }
                handle->state = GSSAPI_FTP_STATE_OPEN;
                globus_fifo_enqueue(&handle->read_command_q, handle->banner);
                done = GLOBUS_TRUE;
                globus_xio_driver_finished_open(handle, op, res);
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
                    globus_byte_t *     e_buf;
                    globus_size_t       e_len;

                    e_len = globus_l_xio_gssapi_ftp_command_array_size(cmd_a);
                    e_buf = globus_malloc(e_len + 1);
                    globus_l_xio_gssapi_ftp_serialize_command_array(
                        cmd_a,
                        e_buf,
                        e_len);
                    e_buf[e_len] = '\0';
                    res = GlobusXIOGssapiFTPAuthenticationFailure(e_buf);
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

        /* if open, we are reading.  unwrap and leave queue until reads are
            posted */
        case GSSAPI_FTP_STATE_OPEN:
            w_buf = (globus_l_xio_gssapi_buffer_t *)
                globus_malloc(sizeof(globus_l_xio_gssapi_buffer_t));
            if(w_buf == NULL)
            {
                res = GlobusXIOGssapiFTPAllocError();
                goto err;
            }
            w_buf->buf = NULL;
            w_buf->length = 0;
            w_buf->ndx = 0;

            /* TODO: test for 631 or 632 */
            if(*cmd_a[0] == '6')
            {
                for(ctr = 1; cmd_a[ctr] != NULL; ctr++)
                {
                    res = globus_l_xio_gssapi_ftp_unwrap(
                            handle,
                            cmd_a[ctr],
                            strlen(cmd_a[ctr]),
                            &send_buffer);
                    if(res != GLOBUS_SUCCESS)
                    {
                        goto err;
                    }
                    w_buf->length += strlen(send_buffer);
                    w_buf->buf = globus_libc_realloc(
                        w_buf->buf, w_buf->length + 1);
                    memcpy(&w_buf->buf[w_buf->ndx], 
                        send_buffer, strlen(send_buffer) + 1);
                    w_buf->ndx += strlen(send_buffer);
                    globus_free(send_buffer);
                }
                w_buf->ndx = 0;
                globus_fifo_enqueue(&handle->unwrapped_q, w_buf);
                res = globus_l_xio_gssapi_finshed_read(handle, op);
                done = GLOBUS_TRUE;
            }
            /* TODO: this should possible be an error */
            else
            {
                len = globus_l_xio_gssapi_ftp_command_array_size(cmd_a);
                w_buf->buf = globus_malloc(len+1);
                res = globus_l_xio_gssapi_ftp_serialize_command_array(
                    cmd_a,
                    w_buf->buf,
                    len);
                if(res != GLOBUS_SUCCESS)
                {
                    globus_free(w_buf);
                    goto err;
                }
                w_buf->length = strlen(w_buf->buf);
                w_buf->ndx = 0;
                globus_fifo_enqueue(&handle->unwrapped_q, w_buf);
                res = globus_l_xio_gssapi_finshed_read(handle, op);
                done = GLOBUS_TRUE;
            }
            break;

        default:
            break;
    }

    if(!done)
    {
        handle->write_iov[0].iov_base = send_buffer;
        handle->write_iov[0].iov_len = globus_libc_strlen(send_buffer);
        res = globus_xio_driver_pass_write(
            op,
            handle->write_iov,
            1,
            handle->write_iov[0].iov_len,
            globus_l_xio_gssapi_ftp_client_open_reply_cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_gssapi_ftp_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_accept);

    GlobusXIOGssapiftpDebugEnter();

    res = globus_xio_driver_pass_accept(accept_op, 
        globus_l_xio_gssapi_ftp_accept_cb, NULL);

    GlobusXIOGssapiftpDebugExit();
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
    globus_l_xio_gssapi_attr_t *        attr;
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_init);

    GlobusXIOGssapiftpDebugEnter();

    attr = (globus_l_xio_gssapi_attr_t *) 
        globus_malloc(sizeof(globus_l_xio_gssapi_attr_t));
    if(attr == NULL)
    {
	goto err;
    }
    attr->subject = NULL;
    attr->start_state = GSSAPI_FTP_STATE_NONE;
    attr->super_mode = GLOBUS_FALSE;

    *out_attr = attr;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return GlobusXIOGssapiFTPAllocError();
}

static globus_result_t
globus_l_xio_gssapi_ftp_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_gssapi_attr_t *        attr;
    char *                              subject;
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_cntl);

    GlobusXIOGssapiftpDebugEnter();

    attr = (globus_l_xio_gssapi_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT:
            subject = va_arg(ap, char *);
            if(subject != NULL)
            {
                if(attr->subject != NULL)
                {
                    globus_free(attr->subject);
                }
                attr->subject = globus_libc_strdup(subject);
            }
            break;

        case GLOBUS_XIO_GSSAPI_ATTR_TYPE_START_STATE:
            attr->start_state = va_arg(ap, int);
            break;

        case GLOBUS_XIO_GSSAPI_ATTR_TYPE_ENCRYPT:
            attr->encrypt = va_arg(ap, int);
            break;

        case GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUPER_MODE:
            attr->super_mode = va_arg(ap, globus_bool_t);
            break;

        default:
            break;
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gssapi_ftp_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_result_t                     res;
    globus_l_xio_gssapi_attr_t *        src_attr;
    globus_l_xio_gssapi_attr_t *        dst_attr;
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_copy);

    GlobusXIOGssapiftpDebugEnter();

    src_attr = (globus_l_xio_gssapi_attr_t *) src;
    res = globus_l_xio_gssapi_ftp_attr_init((void **) &dst_attr);
    if(res != GLOBUS_SUCCESS)
    {
	goto err;
    }
    memcpy(dst_attr, src_attr, sizeof(globus_l_xio_gssapi_attr_t));
    if(src_attr->subject != NULL)
    {
        dst_attr->subject = strdup(src_attr->subject);
    }
    *dst = dst_attr;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_gssapi_ftp_attr_destroy(
    void *                              driver_attr)
{
    globus_l_xio_gssapi_attr_t *        attr;
    GlobusXIOName(globus_l_xio_gssapi_ftp_attr_destroy);

    GlobusXIOGssapiftpDebugEnter();

    attr = (globus_l_xio_gssapi_attr_t *) driver_attr;
    if(attr->subject != NULL)
    {
        globus_free(attr->subject);
    }
    globus_free(attr);

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;
}

/************************************************************************
 *                    io handlers
 *                    -----------
 ***********************************************************************/

static globus_result_t
globus_l_xio_gssapi_ftp_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    globus_l_xio_gssapi_attr_t *        attr;
    globus_result_t                     res;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    GlobusXIOName(globus_l_xio_gssapi_ftp_open);

    GlobusXIOGssapiftpDebugEnter();

    attr = (globus_l_xio_gssapi_attr_t *) driver_attr;
    
    if(!(driver_link || contact_info->host))
    {
        res = GlobusXIOErrorContactString("missing host");
        goto err;
    }
    
    /*
     *  create a new handle and initialize it 
     */
    handle = globus_l_xio_gssapi_ftp_handle_create();
    if(handle == NULL)
    {
        res = GlobusXIOGssapiFTPAllocError();
        goto err;
    }
    handle->client = driver_link ? GLOBUS_FALSE : GLOBUS_TRUE;

    if(attr != NULL)
    {
        if(attr->subject != NULL)
        {
            handle->subject = strdup(attr->subject);
        }
        handle->encrypt = attr->encrypt;
        handle->super_mode = attr->super_mode;
    }

    /* do client protocol */
    if(handle->client)
    {
        handle->host = globus_libc_strdup(contact_info->host);
        handle->state = GSSAPI_FTP_STATE_CLIENT_READING_220;
        handle->cred_handle = GSS_C_NO_CREDENTIAL;
        res = globus_xio_driver_pass_open(
            op, contact_info, globus_l_xio_gssapi_ftp_client_open_cb, handle);
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
            res = GlobusXIOGssapiFTPGSIAuthFailure(maj_stat, min_stat);
            globus_l_xio_gssapi_ftp_handle_destroy(handle);
            goto err;
        }

        handle->state = GSSAPI_FTP_STATE_SERVER_READING_AUTH;
        res = globus_xio_driver_pass_open(
            op, contact_info, globus_l_xio_gssapi_ftp_server_open_cb, handle);
    }
    if(res != GLOBUS_SUCCESS)
    {
        globus_l_xio_gssapi_ftp_handle_destroy(handle);
        goto err;
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_gssapi_ftp_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_close);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) driver_specific_handle;

    globus_l_xio_gssapi_ftp_handle_destroy(handle);
    res = globus_xio_driver_pass_close(op, NULL, NULL);

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;
}

/************************************************************************
 *                  write functions
 *                  ---------------
 *  
 *  This section has function that handle writes
 ***********************************************************************/

void
globus_l_xio_gssapi_ftp_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    int                                 ctr;
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    GlobusXIOName(globus_l_xio_gssapi_ftp_write_cb);

    GlobusXIOGssapiftpDebugEnter();

    /* change state back and free stuff */

    handle = (globus_l_xio_gssapi_ftp_handle_t *) user_arg;

    /* set back to writable */
    handle->write_posted = GLOBUS_FALSE;
    handle->write_buffer_ndx = 0;

    globus_xio_driver_finished_write(
        op, GLOBUS_SUCCESS, handle->write_sent_length);

    for(ctr = 0; ctr < handle->write_iov_count; ctr++)
    {
        globus_free(handle->write_iov[ctr].iov_base);
    }

    GlobusXIOGssapiftpDebugExit();
}

/* client and server are both the same except for the header */
static globus_result_t
globus_l_xio_gssapi_ftp_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    char *                              tmp_ptr;
    globus_byte_t *                     buf;
    char *                              encoded_buf;
    int                                 ctr;
    globus_size_t                       end_off;
    globus_size_t                       length;
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    globus_xio_driver_data_callback_t   cb;
    GlobusXIOName(globus_l_xio_gssapi_ftp_write);

    GlobusXIOGssapiftpDebugEnter();

    handle = (globus_l_xio_gssapi_ftp_handle_t *) driver_specific_handle;

    if(handle->write_posted)
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
    tmp_ptr = globus_libc_memmem(handle->write_buffer, length, "\r\n", 2);
    /* if this is not a complete command we simply cache it and say we 
        are finished */
    if(tmp_ptr == NULL)
    {
        globus_xio_driver_finished_write(op, GLOBUS_SUCCESS, length);
    }
    else
    {
        ctr = 0;
        buf = handle->write_buffer;
        handle->write_sent_length = 0;

        if(handle->state != GSSAPI_FTP_STATE_OPEN && !handle->client)
        {
            handle->write_iov[ctr].iov_len = 
                ((globus_byte_t *)tmp_ptr - buf) + 2;
            handle->write_iov[ctr].iov_base = globus_malloc(
                handle->write_iov[ctr].iov_len);
            memcpy(handle->write_iov[ctr].iov_base, buf,
                handle->write_iov[ctr].iov_len);

            cb = globus_l_xio_gssapi_ftp_server_open_reply_cb;
            ctr = 1;
        }
        else
        {
            /* find all complete commands and set each one as an entry in the
                iovec */
            while(tmp_ptr != NULL)
            {
                res = globus_l_xio_gssapi_ftp_wrap(
                        handle, buf, (globus_byte_t *)tmp_ptr - buf, 
                        &encoded_buf, handle->client);
                if(res != GLOBUS_SUCCESS)
                {
                    goto err;
                }
            
                handle->write_iov[ctr].iov_base = encoded_buf;
                handle->write_iov[ctr].iov_len = 
                    globus_libc_strlen(encoded_buf);
                handle->write_sent_length += handle->write_iov[ctr].iov_len;
                buf = tmp_ptr + 2;
                tmp_ptr = globus_libc_memmem(buf, 
                        length - (buf - handle->write_buffer), "\r\n", 2);
                ctr++;
                if(ctr >= handle->write_iov_size)
                {
                    handle->write_iov_size *= 2;
                    handle->write_iov = globus_libc_realloc(
                        handle->write_iov, 
                        handle->write_iov_size * (sizeof(globus_xio_iovec_t)));
                }
            }
            cb = globus_l_xio_gssapi_ftp_write_cb;
        }
        handle->write_iov_count = ctr;
        /* if we received more than a complete command shift remainer to the
            begining of the buffer. */
        end_off = buf - handle->write_buffer;
        handle->write_buffer_ndx = handle->write_buffer_ndx - end_off;
        if(handle->write_buffer_ndx != 0)
        {
            memmove(
                handle->write_buffer, 
                &handle->write_buffer[end_off], 
                handle->write_buffer_ndx);
        }

        res = globus_xio_driver_pass_write(
            op, 
            handle->write_iov, 
            handle->write_iov_count,
            length,
            cb,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        /* try and stop the user from registering multiple at once.  This
           if really the job of the framwork a queuing driver or the user
           themself so little effort is made here. */
        handle->write_posted = GLOBUS_TRUE;
        handle->write_buffer_ndx = 0;
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

  err:
    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}
/************************************************************************
 *                  read functions
 *                  --------------
 *  
 *  This section has function that handle writes
 ***********************************************************************/

/*
 *  called to kick out a read operation.
 */
globus_result_t
globus_l_xio_gssapi_finshed_read(
    globus_l_xio_gssapi_ftp_handle_t *  handle,
    globus_xio_operation_t              op)
{
    globus_l_xio_gssapi_read_req_t *    req;
    globus_size_t                       ncopied;
    globus_size_t                       ndx;
    int                                 ctr;
    globus_l_xio_gssapi_buffer_t *      w_buf;
    GlobusXIOName(globus_l_xio_gssapi_finshed_read);

    GlobusXIOGssapiftpDebugEnter();

    /* if there is a request */
    if(!globus_fifo_empty(&handle->read_req_q))
    {
       req = (globus_l_xio_gssapi_read_req_t *)
                globus_fifo_dequeue(&handle->read_req_q);
        globus_assert(req != NULL);
        w_buf = (globus_l_xio_gssapi_buffer_t *)
            globus_fifo_peek(&handle->unwrapped_q);
        ndx = w_buf->ndx;

        /* if super mode the user breaks the semantics and says
           they will free whatever buffer i give them.  This makes
           it so i can garentuee them exactly 1 command per buffer */
        if(handle->super_mode)
        {
            req->iov[0].iov_base = globus_malloc(w_buf->length);
            req->iov[0].iov_len = w_buf->length;
            memcpy(req->iov[0].iov_base, w_buf->buf, w_buf->length);
            ndx = w_buf->length;
        }
        else
        {
            for(ctr = 0; 
                ctr < req->iovc && ndx < w_buf->length;
                ctr++)
            {
                /* copy as much as we can up to the length of
                    the suers buffer */
                ncopied = w_buf->length - ndx;
                if(ncopied > req->iov[ctr].iov_len)
                {
                    ncopied = req->iov[ctr].iov_len;
                }
                memcpy(req->iov[ctr].iov_base,
                    &w_buf->buf[ndx],
                    ncopied);
                ndx += ncopied;
            }
            if(ndx != w_buf->length)
            {
                w_buf->ndx = ndx;
            }
            else
            {
                void * x = globus_fifo_dequeue(&handle->unwrapped_q);
                globus_assert(x = w_buf);
                globus_free(w_buf->buf);
                globus_free(w_buf);
            }
        }
        /* finish the read */
        globus_xio_driver_finished_read(op, GLOBUS_SUCCESS, ndx);
        globus_free(req);
    }

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;
}


static globus_result_t
globus_l_xio_gssapi_ftp_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_xio_gssapi_ftp_handle_t *  handle;
    globus_result_t                     res;
    globus_l_xio_gssapi_read_req_t *    req;
    GlobusXIOName(globus_l_xio_gssapi_ftp_read);

    GlobusXIOGssapiftpDebugEnter();


    handle = (globus_l_xio_gssapi_ftp_handle_t *) driver_specific_handle;

    req = (globus_l_xio_gssapi_read_req_t *)
        globus_malloc(sizeof(globus_l_xio_gssapi_read_req_t));
    req->iov = (globus_xio_iovec_t *)iovec;
    req->iovc = iovec_count;

    globus_fifo_enqueue(&handle->read_req_q, req);

    res = globus_l_xio_gssapi_get_data(handle, op);

    if (res != GLOBUS_SUCCESS)
    {
	goto err;
    }	
    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}

static globus_result_t
globus_l_xio_gssapi_ftp_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_gssapi_ftp_load);

    GlobusXIOGssapiftpDebugEnter();

    res = globus_xio_driver_init(&driver, "gssapi_ftp", NULL);
    if(res != GLOBUS_SUCCESS)
    {
	goto err;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_gssapi_ftp_open,
        globus_l_xio_gssapi_ftp_close,
        globus_l_xio_gssapi_ftp_read,
        globus_l_xio_gssapi_ftp_write,
        NULL,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_gssapi_ftp_attr_init,
        globus_l_xio_gssapi_ftp_attr_copy,
        globus_l_xio_gssapi_ftp_attr_cntl,
        globus_l_xio_gssapi_ftp_attr_destroy);

    globus_xio_driver_set_server(
        driver,
        NULL,
        globus_l_xio_gssapi_ftp_accept,
        NULL,
        NULL,
        NULL,
        NULL);

    *out_driver = driver;

    GlobusXIOGssapiftpDebugExit();
    return GLOBUS_SUCCESS;

err:

    GlobusXIOGssapiftpDebugExitWithError();
    return res;
}



static void
globus_l_xio_gssapi_ftp_unload(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_unload);

    GlobusXIOGssapiftpDebugEnter();

    globus_xio_driver_destroy(driver);

    GlobusXIOGssapiftpDebugExit();
}


static int
globus_l_xio_gssapi_ftp_activate(void)
{
    int                                 rc;
    GlobusXIOName(globus_l_xio_gssapi_ftp_activate);
    GlobusDebugInit(GLOBUS_XIO_GSSAPI_FTP, TRACE);

    GlobusXIOGssapiftpDebugEnter();

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

    GlobusXIOGssapiftpDebugExit();
    return rc;
}

static int
globus_l_xio_gssapi_ftp_deactivate(void)
{
    GlobusXIOName(globus_l_xio_gssapi_ftp_deactivate);

    GlobusXIOGssapiftpDebugEnter();

    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

    GlobusXIOGssapiftpDebugExit();
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    gssapi_ftp,
    &globus_i_xio_gssapi_ftp_module,
    globus_l_xio_gssapi_ftp_load,
    globus_l_xio_gssapi_ftp_unload);

