#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_error_string.h"
#include "globus_xio_smtp.h"


#define ErrorWriteOnly()                                                    \
    globus_error_put(                                                       \
        globus_error_construct_string(                                      \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            "This is a write only driver"))

typedef enum
{
    SMTP_HELO,
    SMTP_FROM,
    SMTP_TO,
    SMTP_DATA,
    SMTP_MESSAGE,
} l_smtp_state_t;

typedef struct l_smtp_info_s
{
    l_smtp_state_t                          state;
    char *                                  return_address[256];
    char                                    to_address[256];
    char                                    message[1024];
    int                                     buf_len;
    int                                     read_offset;
    globus_xio_iovec_t                      iovec;
} l_smtp_info_t;

static char *                               globus_l_return_address = NULL;
static char                                 globus_l_hostname[MAXHOSTNAMELEN];

static void
globus_l_xio_smtp_write_header_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg);


static int
globus_l_xio_smtp_activate();

static int
globus_l_xio_smtp_deactivate();

#include "version.h"

static globus_module_descriptor_t  globus_i_xio_smtp_module =
{
    "globus_xio_smtp",
    globus_l_xio_smtp_activate,
    globus_l_xio_smtp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

l_smtp_info_t *
l_smtp_create_new_info()
{
    l_smtp_info_t *                         info;

    info = (l_smtp_info_t *) globus_malloc(sizeof(l_smtp_info_t));
    info->state = SMTP_HELO;
    info->read_offset = 0;
    info->buf_len = 1024;
    info->iovec.iov_base = info->message;
    info->iovec.iov_len = info->buf_len;
    sprintf(info->return_address, "%s", globus_l_return_address);

    return info;
}

/*
 *  used as attr and handle
 */

globus_result_t
globus_l_xio_smtp_target_destroy(
    void *                                  driver_target)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_smtp_attr_init(
    void **                             out_attr)
{
    l_smtp_info_t *                     info;

    info = l_smtp_create_new_info();

    *out_attr = info;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_smtp_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              to_addr;
    l_smtp_info_t *                     info;

    info = (l_smtp_info_t *) driver_attr;

    if(cmd == 1)
    {
        to_addr = (char *) va_arg(ap, char *);
        sprintf(info->to_address, "%s", to_addr);        
    }

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_smtp_attr_copy(
    void **                             dst,
    void *                              src)
{
    l_smtp_info_t *                     src_info;
    l_smtp_info_t *                     dst_info;

    src_info = (l_smtp_info_t *) src;
    dst_info = l_smtp_create_new_info();
    memcpy(dst_info, src_info, sizeof(l_smtp_info_t));

    *dst = dst_info;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_smtp_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);

    return GLOBUS_SUCCESS;
}

void
next_state(
    l_smtp_info_t *                         info,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_xio_context_t                    context;

    context = GlobusXIOOperationGetContext(op);
    switch(info->state)
    {
        case SMTP_HELO:
            sprintf(info->message, "HELO %s\r\n", globus_l_hostname);
            info->state = SMTP_FROM;
            break;

        case SMTP_FROM:
            sprintf(info->message, "MAIL From: %s\r\n", info->return_address);
            info->state = SMTP_TO;
            break;

        case SMTP_TO:
            sprintf(info->message, "RCPT To: %s\r\n", info->to_address);
            info->state = SMTP_DATA;
            break;

        case SMTP_DATA:
            sprintf(info->message, "DATA\r\n");
            info->state = SMTP_MESSAGE;
            break;

        case SMTP_MESSAGE:
            GlobusXIODriverFinishedOpen(context, info, op, GLOBUS_SUCCESS);
            return;
            break;
    }

    info->iovec.iov_base = info->message;
    info->iovec.iov_len = strlen(info->message);
    GlobusXIODriverPassWrite(res, op, &info->iovec, 1, info->iovec.iov_len,
        globus_l_xio_smtp_write_header_cb, (void *)info);

    if(res != GLOBUS_SUCCESS)
    {
        GlobusXIODriverFinishedOpen(context, info, op, res);
        globus_xio_driver_context_close(context);
    }
}

static void
globus_l_xio_smtp_read_header_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    l_smtp_info_t *                         info;
    globus_xio_context_t                    context;
    globus_result_t                         res;

    info = (l_smtp_info_t *) user_arg;
   /*
     *  if any of these fail, punt on the open
     */
    context = GlobusXIOOperationGetContext(op);
    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIODriverFinishedOpen(context, info, op, result);
        globus_xio_driver_context_close(context);
    }
    else
    {
        /* if we have not recieved the entire message repost */
        info->read_offset += nbytes;
        if(info->read_offset < 2 || 
            info->message[info->read_offset - 2] != '\r' ||
            info->message[info->read_offset - 1] != '\n')
        {
            info->iovec.iov_base = &info->message[info->read_offset];
            info->iovec.iov_len = info->buf_len - info->read_offset;

            GlobusXIODriverPassRead(res, op, &info->iovec, 1, 1,
                globus_l_xio_smtp_read_header_cb, (void *)  info);
            if(res != GLOBUS_SUCCESS)
            {
                GlobusXIODriverFinishedOpen(context, info, op, res);
                globus_xio_driver_context_close(context);
            }
        }
        /* if we have the entire message */
        else
        {
            int                             response_code;

            sscanf(info->message, "%d", &response_code);
            info->read_offset = 0;

            /* if a bad response code was recieved */
            if(response_code > 399 || response_code < 200)
            {
                res = globus_error_put(
                    globus_error_construct_string(
                    GLOBUS_XIO_MODULE,
                    GLOBUS_NULL,
                    "SMTP Error: %s.",
                    info->message));


                GlobusXIODriverFinishedOpen(context, info, op, res);
            }
            /* ,ove to next state */
            else
            {
                next_state(info, op);
            }
        }
    }
}

static void
globus_l_xio_smtp_write_header_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_result_t                         res;
    l_smtp_info_t *                         info;

    info = (l_smtp_info_t *) user_arg;

    /*
     *  if any of these fail, punt on the open
     */
    if(result != GLOBUS_SUCCESS)
    {
        globus_xio_context_t                context;

        context = GlobusXIOOperationGetContext(op);

        GlobusXIODriverFinishedOpen(context, info, op, result);
        globus_xio_driver_context_close(context);
    }
    /*
     *  read the response
     */
    else
    {
        GlobusXIODriverPassRead(res, op, &info->iovec, 1,
            1, globus_l_xio_smtp_read_header_cb, (void *)  info);
    }
}


/*
 *  open
 */
void
globus_l_xio_smtp_open_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_xio_context_t                    context;
    l_smtp_info_t *                         info;

    info = (l_smtp_info_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        context = GlobusXIOOperationGetContext(op);
        GlobusXIODriverFinishedOpen(context, info, op, result);
    }
    else
    {
        next_state(info, op);
    }
}   

static
globus_result_t
globus_l_xio_smtp_open(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_xio_context_t                    context;
    l_smtp_info_t *                         info;

    if(driver_attr == NULL)
    {
        return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }

    globus_l_xio_smtp_attr_copy(&info, driver_attr);

    GlobusXIODriverPassOpen(res, context, op, globus_l_xio_smtp_open_cb, info);

    return res;
}

/*
 *  close
 */
void
globus_l_xio_smtp_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    globus_xio_context_t                context;

    context = GlobusXIOOperationGetContext(op);
    GlobusXIODriverFinishedClose(op, result);
    globus_xio_driver_context_close(context);
}   

void
globus_l_xio_smtp_write_close_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_result_t                         res;

    GlobusXIODriverPassClose(res, op, globus_l_xio_smtp_close_cb, user_arg);
}

/*
 *  simply pass the close on down
 */
static globus_result_t
globus_l_xio_smtp_close(
    void *                                  driver_handle,
    void *                                  attr,
    globus_xio_context_t                    context,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    l_smtp_info_t *                         info;

    info = (l_smtp_info_t *) driver_handle;

    sprintf(info->message, "\r\n.\r\nQUIT\r\n");
    info->iovec.iov_base = info->message;
    info->iovec.iov_len = strlen(info->message);
    GlobusXIODriverPassWrite(res, op, &info->iovec, 1, info->iovec.iov_len,
        globus_l_xio_smtp_write_close_cb, (void *)info);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_smtp_write_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    GlobusXIODriverFinishedWrite(op, result, nbytes);
}

/*
 *  writes are easy, just pass everything along
 */
static
globus_result_t
globus_l_xio_smtp_write(
    void *                                  driver_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_size_t                           wait_for;
    l_smtp_info_t *                         info;

    info = (l_smtp_info_t *) driver_handle;

    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_smtp_write_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_smtp_read(
    void *                                  driver_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    return ErrorWriteOnly();
}

static globus_result_t
globus_l_xio_smtp_load(
    globus_xio_driver_t *                   out_driver,
    va_list                                 ap)
{
    globus_xio_driver_t                     driver;
    globus_result_t                         res;

    res = globus_xio_driver_init(&driver, "smtp", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_smtp_open,
        globus_l_xio_smtp_close,
        globus_l_xio_smtp_read,
        globus_l_xio_smtp_write,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_smtp_attr_init,
        globus_l_xio_smtp_attr_copy,
        globus_l_xio_smtp_attr_cntl,
        globus_l_xio_smtp_attr_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}



static void
globus_l_xio_smtp_unload(
    globus_xio_driver_t                     driver)
{
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_smtp_activate(void)
{
    int                                     rc;
    struct passwd *                         pw_ent;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    pw_ent = getpwuid(getuid());
    globus_libc_gethostname(globus_l_hostname, MAXHOSTNAMELEN);

    globus_l_return_address = globus_malloc(strlen(globus_l_hostname) + 2 + 
                                strlen(pw_ent->pw_name));
    sprintf(globus_l_return_address, "%s@%s",
        pw_ent->pw_name, globus_l_hostname);

    return rc;
}

static
int
globus_l_xio_smtp_deactivate(void)
{
    globus_free(globus_l_return_address);

    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    smtp,
    &globus_i_xio_smtp_module,
    globus_l_xio_smtp_load,
    globus_l_xio_smtp_unload);
