#include "globus_i_xioperf.h"
#include "globus_options.h"
#include "globus_xio_gsi.h"
#include "globus_xio_ordering_driver.h"

extern globus_options_entry_t            globus_i_xioperf_opts_table[];

static FILE *                           globus_l_xioperf_log_fptr;
static FILE *                           globus_l_xioperf_err_fptr;

static
globus_result_t
xioperf_next_write(
    globus_i_xioperf_info_t *           info);

static
globus_result_t
xioperf_start(
    globus_i_xioperf_info_t *           info);

void
xio_perf_log(
    globus_i_xioperf_info_t *           info,
    int                                 level,
    char *                              fmt,
    ...)
{
    va_list                             ap;

    if(info->quiet && level != 0)
    {
        return;
    }
    va_start(ap, fmt);
    vfprintf(globus_l_xioperf_log_fptr, fmt, ap);
    va_end(ap);
}

static
void
xioperf_l_log(
    const char *                        msg,
    globus_result_t                     res)
{
    fprintf(globus_l_xioperf_err_fptr,
        "%s: %s\n", msg, globus_object_printable_to_string(
        globus_error_get(res)));
}

static
char *
xioperf_outformat_bw(
    char                                type,
    double                              time,
    globus_off_t                        bytes,
    globus_bool_t                       with_type)
{
    char * str;
    char * tmp_ptr;
    double val;

    if(type == 'm' || type == 'k' || type == 'b' || type == 'g')
    {
        bytes *= 8;
    }
    val = (double) bytes;
    switch(type)
    {
        case 'G':
        case 'g':
            val /= 1024;
        case 'M':
        case 'm':
            val /= 1024;
        case 'K':
        case 'k':
            val /= 1024;

        default:
            break;
    }
    val /= time;

    str = globus_common_create_string("%-10.2lf       ", val);
    tmp_ptr = strchr(str, ' ');
    if(with_type)
    {
        sprintf(tmp_ptr, " %c/s", type);
    }
    else
    {
        *tmp_ptr = '\0';
    }
    return str;
}

static
char *
xioperf_outformat_bytes(
    char                                type,
    globus_off_t                        bytes,
    globus_bool_t                       with_type)
{
    char * str;
    char * tmp_ptr;
    double val;

    type = toupper(type);
    val = (double) bytes;
    switch(type)
    {
        case 'G':
            val /= 1024;
        case 'M':
            val /= 1024;
        case 'K':
            val /= 1024;

        default:
            break;
    }

    str = globus_common_create_string("%-10.2lf       ", val);
    tmp_ptr = strchr(str, ' ');
    if(with_type)
    {
        sprintf(tmp_ptr, " %c", type);
    }
    else
    {
        *tmp_ptr = '\0';
    }
    return str;
}

/* summary info always goes to stdout */
static
void
xioperf_l_print_summary(
    globus_i_xioperf_info_t *           info)
{
    double                              secs;
    int                                 mins;
    globus_reltime_t                    elps_time;
    long                                usecs;

    GlobusTimeAbstimeGetCurrent(info->end_time);
    GlobusTimeAbstimeDiff(elps_time, info->end_time, info->start_time);
    GlobusTimeReltimeToUSec(usecs, elps_time);

    secs = usecs / 1000000.0;
    mins = (int)secs/60;

    if(info->quiet)
    {
        printf("%02d:%02.4f %s %s %s %s\n",
            mins, secs-(mins*60),
            xioperf_outformat_bytes(info->format, info->bytes_recv, 0),
            xioperf_outformat_bw(info->format, secs, info->bytes_recv, 0),
            xioperf_outformat_bytes(info->format, info->bytes_sent, 0),
            xioperf_outformat_bw(info->format, secs, info->bytes_sent, 0));
    }
    else
    {
        printf("\tTime:         %02d:%02.4f\n", mins, secs-(mins*60));
        if(info->writer)
        {
            printf("\tBytes sent:   %s\n",
                xioperf_outformat_bytes(info->format, info->bytes_sent, 1));
            printf("\tWrite BW:     %s\n",
                xioperf_outformat_bw(info->format, secs, info->bytes_sent, 1));
        }
        if(info->reader)
        {
            printf("\tBytes recv:   %s\n",
                xioperf_outformat_bytes(info->format, info->bytes_recv, 1));
            printf("\tRead BW:      %s\n",
                xioperf_outformat_bw(info->format, secs, info->bytes_recv, 1));
        }
    }
}

static
globus_result_t
xioperf_l_opts_unknown(
   globus_options_handle_t             opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "xioperf_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        unknown_arg));
}

static
globus_i_xioperf_info_t *
xioperf_l_parse_opts(
    int                                 argc,
    char **                             argv)
{
    globus_size_t                       nbytes;
    globus_result_t                     res;
    globus_options_handle_t             opt_h;
    globus_i_xioperf_info_t *           info;
    GlobusXIOPerfFuncName(xioperf_l_parse_opts);

    info = (globus_i_xioperf_info_t *) globus_calloc(
        1, sizeof(globus_i_xioperf_info_t));
    if(info == NULL)
    {
        goto error;
    }

    globus_fifo_init(&info->driver_name_q);
    globus_mutex_init(&info->mutex, NULL);
    globus_cond_init(&info->cond, NULL);
    info->server = GLOBUS_TRUE;
    info->stream_count = 1;
    info->len = 8*1024;
    info->block_size = 64*1024;
    info->format = 'm';
    GlobusTimeReltimeSet(info->time, 10, 0);
    globus_xio_stack_init(&info->stack, NULL);
    globus_xio_attr_init(&info->attr);

    globus_options_init(
        &opt_h, xioperf_l_opts_unknown, info);

    globus_options_add_table(opt_h, globus_i_xioperf_opts_table, info);
    res = globus_options_command_line_process(opt_h, argc, argv);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_result;
    }

    if(globus_fifo_size(&info->driver_name_q) == 0)
    {
        res = GlobusXIOPerfError(
            "must have at least 1 driver on the stack",
            GLOBUS_XIO_PERF_ERROR_PARM);
        goto error_result;
    }
    if(info->interval > 0 &&
        (info->file || info->bytes_to_transfer)) 
    {
        fprintf(globus_l_xioperf_err_fptr, "ignoring interval parameter\n");
    }
    if(info->daemon && !info->server)
    {
        res = GlobusXIOPerfError(
                "only a server can be in daemon mode",
                GLOBUS_XIO_PERF_ERROR_PARM);
        goto error_result;
    }

    if(info->quiet)
    {
        
    }

    info->next_write_buffer = (globus_byte_t *)globus_malloc(info->block_size);
    info->next_buf_size = info->block_size;
    if(!info->reader && !info->writer)
    {
        if(info->server)
        {
            info->reader = GLOBUS_TRUE;
        }
        else
        {
            info->writer = GLOBUS_TRUE;
        }
    }
    if(!info->reader)
    {
        info->read_done = GLOBUS_TRUE;
    }
    if(!info->writer)
    {
        info->write_done = GLOBUS_TRUE;
        if(info->bytes_to_transfer > 0)
        {
            fprintf(globus_l_xioperf_err_fptr, 
                "ignoring --num, only relvent when sending\n");
        }
        info->bytes_to_transfer = 0;
    }

    if(info->reader && info->writer && info->file)
    {
        res = GlobusXIOPerfError(
                "cannot read and write if using a file",
                GLOBUS_XIO_PERF_ERROR_PARM);
        goto error_result;
    }
    if(info->file)
    {
        if(info->reader)
        {
            info->fptr = fopen(info->file, "w");
            if(info->fptr == NULL)
            {
                res = GlobusXIOPerfError(
                    "could not open the specified file for writing",
                    GLOBUS_XIO_PERF_ERROR_PARM);
                goto error_result;
            }
        }
        else if(info->writer)
        {
            info->fptr = fopen(info->file, "r");
            if(info->fptr == NULL)
            {
                res = GlobusXIOPerfError(
                    "could not open the specified file for writing",
                    GLOBUS_XIO_PERF_ERROR_PARM);
                goto error_result;
            }
            nbytes = 
               fread(info->next_write_buffer, 1, info->block_size, info->fptr);
            if(nbytes < info->block_size)
            {
                info->eof = GLOBUS_TRUE;
            }
            info->next_buf_size = nbytes;
        }
    }

    return info;
error_result:
    fprintf(globus_l_xioperf_err_fptr, "%s\n",
        globus_error_print_friendly(globus_error_get(res)));
error:
    return NULL;
}

static
void
xioperf_interval(
    void *                              user_arg)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        xioperf_l_print_summary(info);
        xio_perf_log(info, 1,
        "---------------------------------------------------------------\n");
        GlobusTimeAbstimeGetCurrent(info->start_time);
        info->bytes_sent = 0;
        info->bytes_recv = 0;
    }
    globus_mutex_unlock(&info->mutex);
}

static
void
xioperf_timeout(
    void *                              user_arg)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        fprintf(globus_l_xioperf_err_fptr, "Time exceeded.  Terminating.\n");
        info->read_done = GLOBUS_TRUE;
        info->write_done = GLOBUS_TRUE;
        globus_xio_handle_cancel_operations(
            info->xio_handle, GLOBUS_XIO_CANCEL_WRITE);
    }
    globus_mutex_unlock(&info->mutex);
}

static
void
xioperf_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        info->bytes_recv += nbytes;

        if(info->fptr != NULL && nbytes > 0)
        {
            /* seek when needed */
            fwrite(buffer, 1, nbytes, info->fptr);
        }
        info->ref--;
        if(result != GLOBUS_SUCCESS)
        {
            info->err = globus_error_get(result);
            goto error;
        }
        if(info->read_done || info->die)
        {
            /* happens with ctl+c */
            goto error;
        }

        /* if we are going by a count only register a new read if
            we have not gotten all we want.  need this for bi-directional */
        if(info->bytes_to_transfer == 0 ||
            info->bytes_recv < info->bytes_to_transfer ||
            !info->writer)
        {
            result = globus_xio_register_read(
                info->xio_handle,
                buffer,
                info->block_size,
                1,
                NULL,
                xioperf_read_cb,
                info);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
            info->ref++;
        }
        else
        {
            info->read_done = GLOBUS_TRUE;
            globus_cond_signal(&info->cond);
        }
    }
    globus_mutex_unlock(&info->mutex);

    return;
error:
    globus_free(buffer);
    info->read_done = GLOBUS_TRUE;
    globus_cond_signal(&info->cond);
    globus_mutex_unlock(&info->mutex);
}

static
void
xioperf_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        globus_free(buffer);
        info->bytes_sent += nbytes;
        info->ref--;
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        if(info->bytes_to_transfer > 0 &&
            info->bytes_sent >= info->bytes_to_transfer)
        {
            info->write_done = GLOBUS_TRUE;
        }
        if(!info->write_done)
        {
            result = xioperf_next_write(info);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);

    return;
error:

    if(!globus_xio_error_is_canceled(result))
    {
        xioperf_l_log("write_cb error: ", result);
    }
    info->err = globus_error_get(result);
    info->write_done = GLOBUS_TRUE;
    globus_cond_signal(&info->cond);
    globus_mutex_unlock(&info->mutex);
}


static
globus_result_t
xioperf_next_write(
    globus_i_xioperf_info_t *           info)
{
    size_t                              nbytes;
    globus_result_t                     res;

    globus_assert(!info->write_done);
    res = globus_xio_register_write(
        info->xio_handle,
        info->next_write_buffer,
        info->next_buf_size,
        info->next_buf_size,
        NULL,
        xioperf_write_cb,
        info);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }
    info->ref++;

    info->next_write_buffer = (globus_byte_t*)globus_malloc(info->block_size);
    if(info->eof)
    {
        info->write_done = GLOBUS_TRUE;
    }
    else if(info->fptr != NULL)
    {
        nbytes = fread(
            info->next_write_buffer, 1, info->block_size, info->fptr);
        if(nbytes != info->block_size)
        {
            info->eof = GLOBUS_TRUE;
        }
        info->next_buf_size = nbytes;
    }
    return GLOBUS_SUCCESS;
error:
    return res;
}

static
void
xioperf_l_interrupt_cb(
    void *                              user_arg)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) user_arg;

    globus_mutex_lock(&info->mutex);
    {
        printf("Dieing...\n");
        if(info->die)
        {
            /* if they hit it twice */
            exit(1);
        }
        info->die = GLOBUS_TRUE;
        info->read_done = GLOBUS_TRUE;
        info->write_done = GLOBUS_TRUE;
        if(info->server_handle != NULL)
        {
            globus_xio_server_cancel_accept(info->server_handle);
        }
        globus_xio_handle_cancel_operations(
            info->xio_handle, GLOBUS_XIO_CANCEL_WRITE | GLOBUS_XIO_CANCEL_READ);
        globus_cond_signal(&info->cond);
    }
    globus_mutex_unlock(&info->mutex);
}

static
globus_result_t
xioperf_l_build_stack(
    globus_i_xioperf_info_t *           info)
{
    char *                              driver_opts;
    char *                              driver_name;
    globus_result_t                     res;
    globus_xio_driver_t                 driver;
    globus_bool_t                       push_driver;
    int                                 driver_count = 0;

    while(globus_fifo_size(&info->driver_name_q) > 0)
    {
        push_driver = GLOBUS_TRUE;
        driver_name = (char *) globus_fifo_dequeue(&info->driver_name_q);

        driver_opts = strchr(driver_name, ':');
        if(driver_opts != NULL)
        {
            *driver_opts = '\0';
            driver_opts++;
        }
        
        res = globus_xio_driver_load(driver_name, &driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
        if(driver_opts != NULL)
        {
            globus_xio_attr_cntl(
                info->attr,
                driver,
                GLOBUS_XIO_SET_STRING_OPTIONS,
                driver_opts);
        }

        /* driver speical case code */
        if(strcmp(driver_name, "tcp") == 0)
        {
            if(info->window > 0)
            {
                int                         w = (int)info->window;
                res = globus_xio_attr_cntl(
                    info->attr, driver, GLOBUS_XIO_TCP_SET_SNDBUF, w);
                res = globus_xio_attr_cntl(
                    info->attr, driver, GLOBUS_XIO_TCP_SET_RCVBUF, w);
            }
            globus_xio_attr_cntl(
                info->attr, driver, GLOBUS_XIO_TCP_SET_NODELAY, info->nodelay);
            if(info->bind_addr != NULL)
            {
                globus_xio_attr_cntl(
                    info->attr,
                    driver, GLOBUS_XIO_TCP_SET_INTERFACE, info->bind_addr);
            }
            if(info->port != 0)
            {
                globus_xio_attr_cntl(
                    info->attr, driver, GLOBUS_XIO_TCP_SET_PORT, info->port);
            }
        }
        if(strcmp(driver_name, "gsi") == 0)
        {
            if(info->subject != NULL)
            {
                gss_buffer_desc             send_tok;
                OM_uint32                   min_stat;
                OM_uint32                   maj_stat;
                gss_name_t                  target_name;

                send_tok.value = (void *) info->subject;
                send_tok.length = strlen(info->subject) + 1;
                maj_stat = gss_import_name(
                    &min_stat,
                    &send_tok,
                    GSS_C_NT_USER_NAME,
                    &target_name);
                if(maj_stat == GSS_S_COMPLETE &&
                    target_name != GSS_C_NO_NAME)
                {
                    globus_xio_attr_cntl(
                        info->attr, driver,
                        GLOBUS_XIO_GSI_SET_TARGET_NAME,
                        target_name);
                    gss_release_name(&min_stat, &target_name);
                    globus_xio_attr_cntl(
                        info->attr, driver,
                        GLOBUS_XIO_GSI_SET_AUTHORIZATION_MODE,
                        GLOBUS_XIO_GSI_IDENTITY_AUTHORIZATION);
                }
            }
        }
        if(strcmp(driver_name, "mode_e") == 0)
        {
            globus_xio_attr_t           new_attr;

            if(driver_count > 0)
            {
                globus_xio_attr_init(&new_attr);
                globus_xio_attr_cntl(
                    new_attr, driver, GLOBUS_XIO_MODE_E_SET_STACK,
                    info->stack);
                globus_xio_attr_cntl(
                    new_attr, driver, GLOBUS_XIO_MODE_E_SET_STACK_ATTR,
                    info->attr);

                globus_xio_stack_destroy(info->stack);
                globus_xio_attr_destroy(info->attr);
                info->attr = new_attr;
                globus_xio_stack_init(&info->stack, NULL);
            }
            res = globus_xio_attr_cntl(
                info->attr, driver,
                GLOBUS_XIO_MODE_E_SET_NUM_STREAMS,
                info->stream_count);
            if(res != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        if(strcmp(driver_name, "ordering") == 0)
        {
            res = globus_xio_attr_cntl(
                info->attr, driver,
                GLOBUS_XIO_ORDERING_SET_MAX_READ_COUNT,
                info->stream_count*2);
            if(res != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        if(strcmp(driver_name, "bidi") == 0)
        {
            globus_xio_attr_t           new_attr;

            if(driver_count > 0)
            {
                globus_xio_attr_init(&new_attr);
                globus_xio_attr_cntl(
                    new_attr, driver, 1, /*GLOBUS_XIO_BIDI_SET_READ_STACK, */
                    info->stack);
                globus_xio_attr_cntl(
                    new_attr, driver, 2, /*GLOBUS_XIO_BIDI_SET_WRITE_STACK, */
                    info->stack);
                globus_xio_attr_cntl(
                    new_attr, driver, 4, /*GLOBUS_XIO_BIDI_SET_READ_ATTR, */
                    info->attr);
                globus_xio_attr_cntl(
                    new_attr, driver, 5, /*GLOBUS_XIO_BIDI_SET_WRITE_ATTR, */
                    info->attr);

                globus_xio_stack_destroy(info->stack);
                globus_xio_attr_destroy(info->attr);
                info->attr = new_attr;
                globus_xio_stack_init(&info->stack, NULL);
            }
            info->stream_count = 1;
        }


        if(push_driver)
        {
            res = globus_xio_stack_push_driver(info->stack, driver);
            if(res != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }

        driver_count++;
    }

    return GLOBUS_SUCCESS;
error:
    return res;
}

int
main(
    int                                 argc,
    char **                             argv)
{
    char *                              cs;
    globus_i_xioperf_info_t *           info;
    globus_i_xioperf_info_t             info_copy;
    globus_result_t                     res;
 
    globus_module_activate(GLOBUS_XIO_MODULE);

    globus_l_xioperf_log_fptr = stdout;
    globus_l_xioperf_err_fptr = stderr;

    info = xioperf_l_parse_opts(argc, argv);
    if(info == NULL)
    {
        goto error;
    }
    globus_callback_register_signal_handler(
        GLOBUS_SIGNAL_INTERRUPT,
        GLOBUS_TRUE,
        xioperf_l_interrupt_cb,
        info);

    xioperf_l_build_stack(info);

    xio_perf_log(info, 1,
    "---------------------------------------------------------------\n");
    /* driver specif stuff will be tricky */
    if(info->server)
    {
        res = globus_xio_server_create(
            &info->server_handle, info->attr, info->stack);
        if(res != GLOBUS_SUCCESS)
        {
            xioperf_l_log("setup error:",res);
            goto error;
        }
        globus_xio_server_get_contact_string(info->server_handle, &cs);
        xio_perf_log(info, 1, "server listening on: %s\n", cs);
        xio_perf_log(info, 1, 
        "---------------------------------------------------------------\n");
        globus_free(cs);

        do
        {
            res = globus_xio_server_accept(
                &info->xio_handle, info->server_handle);
            if(res != GLOBUS_SUCCESS)
            {
                xioperf_l_log("accept error:", res);
            }
            else
            {
                /* copy initial values */
                memcpy(&info_copy, info, sizeof(globus_i_xioperf_info_t));
                res = xioperf_start(&info_copy);
                if(res != GLOBUS_SUCCESS)
                {
                    xioperf_l_log("connection error:",res);
                }
            }
        } while(info->daemon && !info->die);
        res = globus_xio_server_close(info->server_handle);
        if(res != GLOBUS_SUCCESS)
        {
            xioperf_l_log("server close error:", res);
        }
    }
    else
    {
        res = globus_xio_handle_create(&info->xio_handle, info->stack);
        if(res != GLOBUS_SUCCESS)
        {
            xioperf_l_log("setup error:",res);
            goto error;
        }
        res = xioperf_start(info);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 0;

error:
    fprintf(globus_l_xioperf_err_fptr, "failed.\n");
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 1;
}

static
globus_result_t
xioperf_post_io(
    globus_i_xioperf_info_t *           info)
{
    int                                 i;
    globus_result_t                     res;
    globus_byte_t *                     buffer;

    for(i = 0; i < info->stream_count; i++)
    {
        if(info->reader && !info->read_done)
        {
            buffer = (globus_byte_t*)globus_malloc(info->block_size);
            res = globus_xio_register_read(
                info->xio_handle,
                buffer,
                info->block_size,
                1,
                NULL,
                xioperf_read_cb,
                info);
            if(res != GLOBUS_SUCCESS)
            {
                info->read_done = GLOBUS_TRUE;
                xioperf_l_log("initial read error:", res);
                goto error;
            }
            else
            {
                info->ref++;
            }
        }
        if(info->writer && !info->write_done)
        {
            res = xioperf_next_write(info);
            if(res != GLOBUS_SUCCESS)
            {
                info->write_done = GLOBUS_TRUE;
                xioperf_l_log("initial write error:", res);
                goto error;
            }
        }
    }
    return GLOBUS_SUCCESS;
error:
    return res;
}


static
globus_result_t
xioperf_start(
    globus_i_xioperf_info_t *           info)
{
    globus_result_t                     res;
    globus_reltime_t                    period; 
    globus_xio_attr_t                   close_attr;

    /* do driver specific stuff */
    globus_xio_attr_init(&close_attr);
    globus_xio_attr_cntl(
        close_attr, NULL, GLOBUS_XIO_ATTR_CLOSE_NO_CANCEL, GLOBUS_TRUE);
    /* tcp specific */

    globus_mutex_lock(&info->mutex);
    {
        /* if we are doing time */
        if(info->interval > 0)
        {
            GlobusTimeReltimeSet(period, info->interval, 0);
            globus_callback_register_periodic(
                NULL,
                &period,
                &period,
                xioperf_interval,
                info);
        }
        else if(info->bytes_to_transfer == 0 
            && info->writer && info->fptr == NULL)
        {
            globus_callback_register_oneshot(
                NULL,
                &info->time,
                xioperf_timeout,
                info);
        }

        GlobusTimeAbstimeGetCurrent(info->start_time);
        res = globus_xio_open(info->xio_handle, info->client, info->attr);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
        xio_perf_log(info, 1, "Connection esstablished\n");
        xio_perf_log(info, 1, 
        "---------------------------------------------------------------\n");
        res = xioperf_post_io(info);

        while(!info->read_done || info->ref > 0 || !info->write_done)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
        if(!info->die && info->dual)
        {
            if(info->server)
            {
                info->write_done = GLOBUS_FALSE;
                info->writer = GLOBUS_TRUE;
                info->reader = GLOBUS_FALSE;
            }
            else
            {
                info->read_done = GLOBUS_FALSE;
                info->reader = GLOBUS_TRUE;
                info->writer = GLOBUS_FALSE;
            }
            res = xioperf_post_io(info);
            while(!info->read_done || info->ref > 0 || !info->write_done)
            {
                globus_cond_wait(&info->cond, &info->mutex);
            }
        }
        res = globus_xio_close(info->xio_handle, close_attr);
        if(res != GLOBUS_SUCCESS)
        {
            xioperf_l_log("close error", res);
        }
        xioperf_l_print_summary(info);
    }
    globus_mutex_unlock(&info->mutex);

    if(info->fptr != NULL)
    {
        fclose(info->fptr);
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return GLOBUS_SUCCESS;
error:
    return res;
}
