#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_ftp_cmd.h"
#include "globus_xio_util.h"

#define GLOBUS_L_XIO_FTP_CMD_DEFAULT_BUFFER_SIZE    1024

typedef struct globus_l_xio_ftp_cmd_handle_s
{
    globus_byte_t *                     buffer;
    globus_size_t                       buffer_length;
    globus_size_t                       buffer_ndx;
    globus_fifo_t                       read_q;
    globus_bool_t                       client;
    globus_bool_t                       create_buffer_mode;
    globus_mutex_t                      mutex;
    globus_xio_iovec_t                  iovec;
    globus_xio_iovec_t *                out_iovec;
    globus_bool_t                       create_buffer;
} globus_l_xio_ftp_cmd_handle_t;

typedef struct
{
    globus_bool_t                       create_buffer_mode;
    globus_bool_t                       force_server;
} globus_l_xio_ftp_cmd_attr_t;
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
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);
/**************************************************************************
 *                    global data
 *                    -----------
 *************************************************************************/
#include "version.h"

GlobusXIODefineModule(ftp_cmd) =
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
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_bool_t                       client,
    globus_size_t *                     end_offset)
{
    globus_byte_t *                     tmp_ptr;
    globus_size_t                       len;
    globus_byte_t *                     start_ptr;
    globus_bool_t                       done = GLOBUS_FALSE;

    /* all a 0 length to be passed */
    if(length == 0)
    {
        return GLOBUS_FALSE;
    }

    tmp_ptr = globus_libc_memmem(buffer, length, "\r\n", 2);
    /* IF There is no '\r' */
    if(tmp_ptr == NULL)
    {
        return GLOBUS_FALSE;
    }

    /* if server we are done as soon as we get \r\n */
    if(!client)
    {
        *end_offset = tmp_ptr - buffer + 2;
        return GLOBUS_TRUE;
    }

    start_ptr = buffer;
    len = length;
    while(!done)
    {
        /* if 4th colums is a space and first is a number we are done */
        if(start_ptr[3] == ' ' && isdigit(start_ptr[0]))
        {
            *end_offset = tmp_ptr - buffer + 2;
            return GLOBUS_TRUE;
        }
        else
        {
            len -= start_ptr - tmp_ptr - 2;
            start_ptr = tmp_ptr + 2;
            tmp_ptr = globus_libc_memmem(start_ptr, len, "\r\n", 2);
            if(tmp_ptr == NULL)
            {
                done = GLOBUS_TRUE;;
            }
        }
    }

    return GLOBUS_FALSE;
}

static globus_result_t
globus_l_xio_ftp_cmd_attr_init(
    void **                             out_driver_attr)
{
    globus_l_xio_ftp_cmd_attr_t *       attr;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_ftp_cmd_attr_init);
    
    attr = (globus_l_xio_ftp_cmd_attr_t *)
        globus_calloc(sizeof(globus_l_xio_ftp_cmd_attr_t), 1);
    if(!attr)
    {
        res = GlobusXIOErrorMemory("attr");
        goto error;
    }

    *out_driver_attr = attr;
    
    return GLOBUS_SUCCESS;

error:
    return res;
}

static globus_result_t
globus_l_xio_ftp_cmd_attr_copy(
    void **                             out_driver_attr,
    void *                              src_driver_attr)
{
    globus_l_xio_ftp_cmd_attr_t *       src_attr;
    globus_l_xio_ftp_cmd_attr_t *       dest_attr;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_ftp_cmd_attr_init);
    
    res = globus_l_xio_ftp_cmd_attr_init((void **) &dest_attr);
    if(res == GLOBUS_SUCCESS)
    {
        src_attr = (globus_l_xio_ftp_cmd_attr_t *) src_driver_attr;
        dest_attr->create_buffer_mode = src_attr->create_buffer_mode;
        dest_attr->force_server = src_attr->force_server;
        
        *out_driver_attr = dest_attr;
    }
    
    return res;
}

static globus_result_t
globus_l_xio_ftp_cmd_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_ftp_cmd_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_ftp_cmd_attr_t *       attr;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_ftp_cmd_attr_cntl);

    attr = (globus_l_xio_ftp_cmd_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_DRIVER_FTP_CMD_BUFFER:
            attr->create_buffer_mode = va_arg(ap, globus_bool_t);
            break;

        case GLOBUS_XIO_DRIVER_FTP_CMD_FORCE_SERVER:
            attr->force_server = va_arg(ap, globus_bool_t);
            break;

        default:
            res = GlobusXIOErrorInvalidCommand(cmd);
            return res;
    }

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_ftp_cmd_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_accept(op, (void *) 0x01, result);
}

static globus_result_t
globus_l_xio_ftp_cmd_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;

    res = globus_xio_driver_pass_accept(
        accept_op, globus_l_xio_ftp_cmd_accept_cb, NULL);

    return res;
}

/************************************************************************
 *                  read functions
 *                  --------------
 *  
 ***********************************************************************/
static void
globus_l_xio_ftp_cmd_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_ftp_cmd_handle_t *     handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        globus_free(handle->buffer);
        globus_free(handle);
    }

    globus_xio_driver_finished_open(handle, op, result);
}

static globus_result_t
globus_l_xio_ftp_cmd_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_l_xio_ftp_cmd_attr_t *       attr;
    globus_l_xio_ftp_cmd_handle_t *     handle;
    GlobusXIOName(globus_l_xio_ftp_cmd_open);

    attr = (globus_l_xio_ftp_cmd_attr_t *) driver_attr;
    
    handle = (globus_l_xio_ftp_cmd_handle_t *) globus_malloc(
        sizeof(globus_l_xio_ftp_cmd_handle_t));
    if(handle == NULL)
    {
        res = GlobusXIOErrorMemory("handle");
        return res;
    }

    if(attr != NULL && attr->force_server)
    {
        handle->client = GLOBUS_FALSE;
    }
    else
    {    
        handle->client = driver_link ? GLOBUS_FALSE : GLOBUS_TRUE;
    }
    handle->create_buffer_mode = attr 
        ? attr->create_buffer_mode : GLOBUS_FALSE;

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

    res = globus_xio_driver_pass_open(
        op,
        contact_info,
        globus_l_xio_ftp_cmd_open_cb,
        handle);

    return res;
}


static void
globus_l_xio_ftp_cmd_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_write(op, result, nbytes);
}
                                                                                
static globus_result_t
globus_l_xio_ftp_cmd_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;

    res = globus_xio_driver_pass_write(
        op,
        iovec,
        iovec_count,
        globus_xio_operation_get_wait_for(op),
        globus_l_xio_ftp_cmd_write_cb,
        NULL);

    return res;
}

globus_result_t
globus_l_xio_ftp_cmd_request_data(
    globus_l_xio_ftp_cmd_handle_t *     handle,
    globus_xio_operation_t              op)
{
    globus_result_t                     res = GLOBUS_SUCCESS;

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
        res = globus_xio_driver_pass_read(
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
        handle->out_iovec[0].iov_len = 
            strlen((char*)handle->out_iovec[0].iov_base);

        globus_xio_driver_finished_read(
            op, GLOBUS_SUCCESS, handle->out_iovec[0].iov_len);
    }

    return res;
}

static void
globus_l_xio_ftp_cmd_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_bool_t                       complete;
    globus_result_t                     res;
    globus_l_xio_ftp_cmd_handle_t *     handle;
    globus_size_t                       end_offset;
    globus_size_t                       remain;
    char *                              tmp_ptr;
    char *                              done_buf;

    handle = (globus_l_xio_ftp_cmd_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        if(result != GLOBUS_SUCCESS || !handle->create_buffer_mode)
        {
            globus_xio_driver_finished_read(op, result, nbytes);
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
                memcpy(done_buf, handle->buffer, end_offset);
                done_buf[end_offset] = '\0';
                globus_fifo_enqueue(&handle->read_q, done_buf);

                remain = handle->buffer_ndx - end_offset;
                if(remain > 0)
                {
                    memmove(
                        handle->buffer,
                        &handle->buffer[end_offset],
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
                globus_xio_driver_finished_read(op, res, nbytes);
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);
}

static globus_result_t
globus_l_xio_ftp_cmd_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_l_xio_ftp_cmd_handle_t *     handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) driver_specific_handle;

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
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_ftp_cmd_handle_t *     handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) user_arg;

    globus_xio_driver_finished_close(op, result);

    globus_free(handle->buffer);
    globus_fifo_destroy(&handle->read_q);
    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
}

static globus_result_t
globus_l_xio_ftp_cmd_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_l_xio_ftp_cmd_handle_t *     handle;

    handle = (globus_l_xio_ftp_cmd_handle_t *) driver_specific_handle;

    res = globus_xio_driver_pass_close(
        op, globus_l_xio_ftp_cmd_close_cb, handle);

    return res;
}

static globus_result_t
globus_l_xio_ftp_cmd_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_ftp_cmd_init);

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
        globus_l_xio_ftp_cmd_write,
        NULL,
        NULL);

    globus_xio_driver_set_server(
        driver,
        NULL,
        globus_l_xio_ftp_cmd_accept,
        NULL,
        NULL,
        NULL,
        NULL);
    
    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_ftp_cmd_attr_init,
        globus_l_xio_ftp_cmd_attr_copy,
        globus_l_xio_ftp_cmd_attr_cntl,
        globus_l_xio_ftp_cmd_attr_destroy);
    
    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_ftp_cmd_destroy(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_ftp_cmd_destroy);
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    ftp_cmd,
    globus_l_xio_ftp_cmd_init,
    globus_l_xio_ftp_cmd_destroy);

static int
globus_l_xio_ftp_cmd_activate(void)
{
    int                                 rc;
    GlobusXIOName(globus_l_xio_ftp_cmd_activate);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(ftp_cmd);
    }
    
    return rc;
}

static int
globus_l_xio_ftp_cmd_deactivate(void)
{
    GlobusXIOName(globus_l_xio_ftp_cmd_deactivate);
    GlobusXIOUnRegisterDriver(ftp_cmd);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
