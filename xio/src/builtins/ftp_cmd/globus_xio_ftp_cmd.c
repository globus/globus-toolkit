#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_ftp_cmd.h"
#include "globus_xio_util.h"

#define GLOBUS_L_XIO_FTP_CMD_DEFAULT_BUFFER_SIZE    1024

typedef struct globus_l_xio_ftp_cmd_target_s
{
    globus_bool_t                           client;
    globus_bool_t                           create_buffer_mode;
} globus_l_xio_ftp_cmd_target_t;


typedef struct globus_l_xio_ftp_cmd_handle_s
{
    globus_byte_t *                         buffer;
    globus_size_t                           buffer_length;
    globus_size_t                           buffer_ndx;
    globus_fifo_t                           read_q;
    globus_bool_t                           client;
    globus_bool_t                           create_buffer_mode;
    globus_mutex_t                          mutex;
    globus_xio_context_t                    context;
    globus_xio_iovec_t                      iovec;
    globus_xio_iovec_t *                    out_iovec;
    globus_bool_t                           create_buffer;
} globus_l_xio_ftp_cmd_handle_t;

/**************************************************************************
 *                    function prototypes
 *                    -------------------
 *************************************************************************/
static int
globus_l_xio_ftp_cmd_activate();

static int
globus_l_xio_ftp_cmd_deactivate();

static void
globus_l_xio_ftp_cmd_read_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg);
/**************************************************************************
 *                    global data
 *                    -----------
 *************************************************************************/
#include "version.h"

static globus_module_descriptor_t  globus_i_xio_ftp_cmd_module =
{
    "globus_xio_ftp_cmd",
    globus_l_xio_ftp_cmd_activate,
    globus_l_xio_ftp_cmd_deactivate,
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
globus_l_xio_ftp_cmd_complete_command(
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_bool_t                           client,
    globus_size_t *                         end_offset)
{
    globus_byte_t *                         tmp_ptr;
    globus_size_t                           end_off;

    /* all a 0 length to be passed */
    if(length == 0)
    {
        return GLOBUS_FALSE;
    }

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

/************************************************************************
 *                  target handling
 *                  ---------------
 ***********************************************************************/
static globus_result_t
globus_l_xio_ftp_cmd_target_init(
    void **                                 out_target,
    void *                                  driver_attr,
    const char *                            contact_string)
{
    globus_l_xio_ftp_cmd_target_t *         target;

    target = (globus_l_xio_ftp_cmd_target_t *) globus_malloc(
        sizeof(globus_l_xio_ftp_cmd_target_t));
    target->client = GLOBUS_TRUE;
    target->create_buffer_mode = GLOBUS_FALSE;
    *out_target = target;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_ftp_cmd_target_cntl(
    void *                                  driver_target,
    int                                     cmd,
    va_list                                 ap)
{
    globus_l_xio_ftp_cmd_target_t *         target;
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_ftp_cmd_target_cntl);

    target = (globus_l_xio_ftp_cmd_target_t *) driver_target;

    switch(cmd)
    {
        case GLOBUS_XIO_DRIVER_FTP_CMD_BUFFER:
            target->create_buffer_mode = va_arg(ap, globus_bool_t);
            break;

        default:
            res = GlobusXIOErrorInvalidCommand(cmd);
            return res;
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_ftp_cmd_target_destroy(
    void *                                  driver_target)
{
    globus_free(driver_target);

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_ftp_cmd_accept_cb(
    globus_i_xio_op_t *                     op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_xio_ftp_cmd_target_t *          target;

    target = (globus_l_xio_ftp_cmd_target_t *) globus_malloc(
        sizeof(globus_l_xio_ftp_cmd_target_t));
    target->client = GLOBUS_FALSE;
    target->create_buffer_mode = GLOBUS_FALSE;

    GlobusXIODriverFinishedAccept(op, target, GLOBUS_SUCCESS);
}

static globus_result_t
globus_l_xio_ftp_cmd_accept(
    void *                                  driver_server,
    void *                                  driver_attr,
    globus_xio_operation_t                  accept_op)
{
    globus_result_t                         res;

    GlobusXIODriverPassAccept(
        res, accept_op, globus_l_xio_ftp_cmd_accept_cb, NULL);

    return res;
}

/************************************************************************
 *                  read functions
 *                  --------------
 *  
 ***********************************************************************/
static void
globus_l_xio_ftp_cmd_open_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_xio_ftp_cmd_handle_t *          handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        globus_free(handle->buffer);
        globus_free(handle);
    }

    GlobusXIODriverFinishedOpen(handle->context, handle, op, result);
}

static globus_result_t
globus_l_xio_ftp_cmd_open(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_l_xio_ftp_cmd_handle_t *         handle;
    globus_l_xio_ftp_cmd_target_t *         target;
    GlobusXIOName(globus_l_xio_ftp_cmd_open);

    target = (globus_l_xio_ftp_cmd_target_t *) driver_target;

    handle = (globus_l_xio_ftp_cmd_handle_t *) globus_malloc(
        sizeof(globus_l_xio_ftp_cmd_handle_t));
    if(handle == NULL)
    {
        res = GlobusXIOErrorMemory("handle");
        return res;
    }

    handle->create_buffer_mode = target->create_buffer_mode;
    handle->client = target->client;

    handle->buffer_length = GLOBUS_L_XIO_FTP_CMD_DEFAULT_BUFFER_SIZE;
    handle->buffer = globus_malloc(handle->buffer_length);
    if(handle->buffer == NULL)
    {
        res = GlobusXIOErrorMemory("buffer");
        return res;
    }
    handle->buffer_ndx = 0;
    globus_mutex_init(&handle->mutex, NULL);
    globus_fifo_init(&handle->read_q);

    GlobusXIODriverPassOpen(
        res,
        handle->context,
        op, 
        globus_l_xio_ftp_cmd_open_cb,
        handle);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_ftp_cmd_request_data(
    globus_l_xio_ftp_cmd_handle_t *          handle,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res = GLOBUS_SUCCESS;

    /*
     *  if the queue is empty repass a request for more data down
     */
    if(globus_fifo_empty(&handle->read_q))
    {
        if(handle->buffer_ndx + 1 >= handle->buffer_length)
        {
            handle->buffer_length++;
            handle->buffer_length *= 2;
            handle->buffer = globus_libc_realloc(
                handle->buffer, handle->buffer_length);
        }
        handle->iovec.iov_base = &handle->buffer[handle->buffer_ndx];
        handle->iovec.iov_len = 
            handle->buffer_length - handle->buffer_ndx;
        GlobusXIODriverPassRead(
            res,
            op,
            &handle->iovec,
            1,
            1,
            globus_l_xio_ftp_cmd_read_cb,
            handle);
    }
    else
    {
        handle->out_iovec[0].iov_base = globus_fifo_dequeue(&handle->read_q);
        handle->out_iovec[0].iov_len = strlen(handle->out_iovec[0].iov_base);

        GlobusXIODriverFinishedRead(
            op, GLOBUS_SUCCESS, handle->iovec.iov_len);
    }

    return res;
}

static void
globus_l_xio_ftp_cmd_read_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_bool_t                           complete;
    globus_result_t                         res;
    globus_l_xio_ftp_cmd_handle_t *         handle;
    globus_size_t                           end_offset;
    globus_size_t                           remain;
    char *                                  tmp_ptr;
    char *                                  done_buf;

    handle = (globus_l_xio_ftp_cmd_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        if(result != GLOBUS_SUCCESS || !handle->create_buffer_mode)
        {
            GlobusXIODriverFinishedRead(op, result, nbytes);
        }
        else
        {
            handle->buffer_ndx += nbytes;
            complete = globus_l_xio_ftp_cmd_complete_command(
                handle->buffer, 
                handle->buffer_ndx,
                handle->client,
                &end_offset);
            while(complete)
            {
                tmp_ptr = handle->buffer;
                while(isspace(*tmp_ptr))
                {
                    tmp_ptr++;
                    end_offset--;
                }
                /* copy it into its own buffer */
                done_buf = globus_malloc(end_offset+1);
                memcpy(done_buf, handle->buffer, end_offset+1);
                done_buf[end_offset] = '\0';
                globus_fifo_enqueue(&handle->read_q, done_buf);

                remain = handle->buffer_ndx - end_offset - 2;
                if(remain > 0)
                {
                    memmove(
                        handle->buffer,
                        &handle->buffer[handle->buffer_ndx],
                        remain);
                }
                handle->buffer_ndx = remain;

                complete = globus_l_xio_ftp_cmd_complete_command(
                    handle->buffer,
                    handle->buffer_ndx,
                    handle->client,
                    &end_offset);
            }

            res = globus_l_xio_ftp_cmd_request_data(handle, op);
            if(res != GLOBUS_SUCCESS)
            {
                GlobusXIODriverFinishedRead(op, res, nbytes);
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);
}

static globus_result_t
globus_l_xio_ftp_cmd_read(
    void *                                  driver_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_l_xio_ftp_cmd_handle_t *         handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) driver_handle;

    globus_mutex_lock(&handle->mutex);
    {
        handle->out_iovec = (globus_xio_iovec_t *)iovec;
        res = globus_l_xio_ftp_cmd_request_data(handle, op);
    }
    globus_mutex_unlock(&handle->mutex);

    return res;
}

static void
globus_l_xio_ftp_cmd_close_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_l_xio_ftp_cmd_handle_t *         handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) user_arg;

    GlobusXIODriverFinishedClose(op, result);

    globus_free(handle->buffer);
    globus_fifo_destroy(&handle->read_q);
    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
}

static globus_result_t
globus_l_xio_ftp_cmd_close(
    void *                                  driver_handle,
    void *                                  attr,
    globus_xio_context_t                    context,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_l_xio_ftp_cmd_handle_t *         handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) driver_handle;

    GlobusXIODriverPassClose(res, op, globus_l_xio_ftp_cmd_close_cb, handle);

    return res;
}

static globus_result_t
globus_l_xio_ftp_cmd_load(
    globus_xio_driver_t *                   out_driver,
    va_list                                 ap)
{
    globus_xio_driver_t                     driver;
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_ftp_cmd_load);

    res = globus_xio_driver_init(&driver, "ftp_cmd", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_ftp_cmd_open,
        globus_l_xio_ftp_cmd_close,
        globus_l_xio_ftp_cmd_read,
        NULL, /* leave write null for now */
        NULL);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_ftp_cmd_target_init,
        globus_l_xio_ftp_cmd_target_cntl,
        globus_l_xio_ftp_cmd_target_destroy);

    globus_xio_driver_set_server(
        driver,
        NULL,
        globus_l_xio_ftp_cmd_accept,
        NULL,
        NULL,
        globus_l_xio_ftp_cmd_target_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}



static void
globus_l_xio_ftp_cmd_unload(
    globus_xio_driver_t                     driver)
{
    GlobusXIOName(globus_l_xio_ftp_cmd_unload);
    globus_xio_driver_destroy(driver);
}


static int
globus_l_xio_ftp_cmd_activate(void)
{
    int                                     rc;
    GlobusXIOName(globus_l_xio_ftp_cmd_activate);

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    return rc;
}

static int
globus_l_xio_ftp_cmd_deactivate(void)
{
    GlobusXIOName(globus_l_xio_ftp_cmd_deactivate);
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    ftp_cmd,
    &globus_i_xio_ftp_cmd_module,
    globus_l_xio_ftp_cmd_load,
    globus_l_xio_ftp_cmd_unload);

