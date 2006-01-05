#include "globus_i_xioperf.h"
#include "globus_options.h"

extern globus_options_entry_t            globus_i_xioperf_opts_table[];

static
globus_result_t
xioperf_next_write(
    globus_i_xioperf_info_t *           info);

static
globus_result_t
xioperf_start(
    globus_i_xioperf_info_t *           info);

static
void
xioperf_l_log(
    const char *                        msg,
    globus_result_t                     res)
{
    fprintf(stderr, "%s: %s\n", msg, globus_object_printable_to_string(
        globus_error_get(res)));
}

static
char *
xioperf_outformat_bw(
    char                                type,
    double                              time,
    globus_off_t                        bytes)
{
    char * str;
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
    sprintf(strchr(str, ' '), " %c/s", type);
    return str;
}

static
char *
xioperf_outformat_bytes(
    char                                type,
    globus_off_t                        bytes)
{
    char * str;
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
    sprintf(strchr(str, ' '), " %c", type);
    return str;
}

static
void
xioperf_l_print_sumary(
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
    printf("\tTime:         %02d:%02.4f\n", mins, secs-mins);

    if(info->writer)
    {
        printf("\tBytes sent:   %s\n",
            xioperf_outformat_bytes(info->format, info->bytes_sent));
        printf("\tWrite BW:     %s\n",
            xioperf_outformat_bw(info->format, secs, info->bytes_sent));
    }
    if(info->reader)
    {
        printf("\tBytes recv:   %s\n",
            xioperf_outformat_bytes(info->format, info->bytes_recv));
        printf("\tRead BW:      %s\n",
            xioperf_outformat_bw(info->format, secs, info->bytes_recv));
    }
}

static
globus_result_t
xioperf_l_opts_unknown(
    const char *                        parm,
    void *                              arg)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "xioperf_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        parm));
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

    globus_mutex_init(&info->mutex, NULL);
    globus_cond_init(&info->cond, NULL);
    info->server = GLOBUS_TRUE;
    info->stream_count = 1;
    info->port = 9999;
    info->len = 8*1024;
    info->block_size = 64*1024;
    info->format = 'm';
    GlobusTimeReltimeSet(info->time, 10, 0);
    globus_xio_stack_init(&info->stack, NULL);

    globus_options_init(
        &opt_h, xioperf_l_opts_unknown, info, globus_i_xioperf_opts_table);
    res = globus_options_command_line_process(opt_h, argc, argv);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_result;
    }

    if(info->interval > 0 &&
        (info->file || info->bytes_to_transfer)) 
    {
        fprintf(stderr, "ignoring interval parameter\n");
    }
    if(info->daemon && !info->server)
    {
        res = GlobusXIOPerfError(
                "only a server can be in daemon mode",
                GLOBUS_XIO_PERF_ERROR_PARM);
        goto error;
    }

    info->next_write_buffer = globus_malloc(info->block_size);
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
    if(info->reader && info->writer && info->file)
    {
        res = GlobusXIOPerfError(
                "cannot read and write if using a file",
                GLOBUS_XIO_PERF_ERROR_PARM);
        goto error;
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
                goto error;
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
                goto error;
            }
            nbytes = 
               fread(info->next_write_buffer, info->block_size, 1, info->fptr);
            if(nbytes < info->block_size)
            {
                info->eof = GLOBUS_TRUE;
            }
        }
    }

    return info;
error_result:
    fprintf(stderr, "%s\n",
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
        xioperf_l_print_sumary(info);
        fprintf(stdout, 
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
        printf("Time exceeded.  Terminating.\n");
        info->done = GLOBUS_TRUE;
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

        if(info->fptr != NULL)
        {
            /* seek when needed */
            fwrite(buffer, nbytes, 1, info->fptr);
        }
        info->ref--;
        if(result != GLOBUS_SUCCESS)
        {
            info->err = globus_error_get(result);
            goto error;
        }

        result = globus_xio_register_read(
            info->xio_handle,
            buffer,
            info->block_size,
            info->block_size,
            NULL,
            xioperf_read_cb,
            info);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        info->ref++;
    }
    globus_mutex_unlock(&info->mutex);

    return;
error:
    globus_free(buffer);
    info->done = GLOBUS_TRUE;
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
            info->done = GLOBUS_TRUE;
        }
        if(!info->done)
        {
            result = xioperf_next_write(info);
            if(result != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
    }
    globus_mutex_unlock(&info->mutex);

    return;
error:

    if(!globus_xio_error_is_canceled(result))
    {
        xioperf_l_log("write_cb error: ", result);
    }
    info->err = globus_error_get(result);
    info->done = GLOBUS_TRUE;
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

    globus_assert(!info->done);
    res = globus_xio_register_write(
        info->xio_handle,
        info->next_write_buffer,
        info->block_size,
        info->block_size,
        NULL,
        xioperf_write_cb,
        info);
    if(res != GLOBUS_SUCCESS)
    {
        goto error;
    }
    info->ref++;

    info->next_write_buffer = globus_malloc(info->block_size);
    if(info->eof)
    {
        info->done = GLOBUS_TRUE;
    }
    else if(info->fptr != NULL)
    {
        nbytes = fread(
            info->next_write_buffer, 1, info->block_size, info->fptr);
        if(nbytes != info->block_size)
        {
            info->eof = GLOBUS_TRUE;
        }
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
    globus_result_t                     res;
 
    globus_module_activate(GLOBUS_XIO_MODULE);

    info = xioperf_l_parse_opts(argc, argv);
    if(info == NULL)
    {
        goto error;
    }

    fprintf(stdout, 
    "---------------------------------------------------------------\n");
    /* driver specif stuff will be tricky */
    if(info->server)
    {
        res = globus_xio_server_create(&info->server_handle, NULL, info->stack);
        if(res != GLOBUS_SUCCESS)
        {
            xioperf_l_log("setup error:",res);
            goto error;
        }
        globus_xio_server_get_contact_string(info->server_handle, &cs);
        fprintf(stdout, "server listening on: %s\n", cs);
        fprintf(stdout, 
        "---------------------------------------------------------------\n");
        globus_free(cs);

        do
        {
            res = globus_xio_server_accept(&info->xio_handle, info->server_handle);
            if(res != GLOBUS_SUCCESS)
            {
                xioperf_l_log("accept error:", res);
            }
            res = xioperf_start(info);
        } while(info->daemon);
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
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 1;
}


static
globus_result_t
xioperf_start(
    globus_i_xioperf_info_t *           info)
{
    int                                 i;
    globus_byte_t *                     buffer;
    globus_result_t                     res;
    globus_reltime_t                    period;

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
        res = globus_xio_open(info->xio_handle, info->client, NULL);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }
        printf("Connection esstablished\n");
        fprintf(stdout, 
        "---------------------------------------------------------------\n");
        for(i = 0; i < info->stream_count && !info->done; i++)
        {
            if(info->reader)
            {
                buffer = malloc(info->block_size);
                res = globus_xio_register_read(
                    info->xio_handle,
                    buffer,
                    info->block_size,
                    info->block_size,
                    NULL,
                    xioperf_read_cb,
                    info);
                if(res != GLOBUS_SUCCESS)
                {
                    info->done = GLOBUS_TRUE;
                    xioperf_l_log("initial read error:", res);
                }
                else
                {
                    info->ref++;
                }
            }
            if(info->writer && !info->done)
            {
                res = xioperf_next_write(info);
                if(res != GLOBUS_SUCCESS)
                {
                    info->done = GLOBUS_TRUE;
                    xioperf_l_log("initial write error:", res);
                }
            }
        }

        while(!info->done && info->ref > 0)
        {
            globus_cond_wait(&info->cond, &info->mutex);
        }
        res = globus_xio_close(info->xio_handle, NULL);
        if(res != GLOBUS_SUCCESS)
        {
            xioperf_l_log("close error", res);
        }
        xioperf_l_print_sumary(info);
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
