#include "globus_i_xio_banner.h"
#include "globus_options.h"
#include "globus_xio_gsi.h"

#define BUFFER_SIZE 256

extern globus_options_entry_t            globus_i_xiobanner_opts_table[];

void
xiobanner_log(
    globus_i_xiobanner_info_t *         info,
    int                                 level,
    char *                              fmt,
    ...)
{
    va_list                             ap;

    if(info && info->quiet && level != 0)
    {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static
globus_result_t
xiobanner_l_opts_unknown(
    const char *                        parm,
    void *                              arg)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "xiobanner_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        parm));
}

static
globus_i_xiobanner_info_t *
xiobanner_l_parse_opts(
    int                                 argc,
    char **                             argv)
{
    globus_result_t                     res;
    globus_options_handle_t             opt_h;
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_parse_opts);

    info = (globus_i_xiobanner_info_t *) globus_calloc(
        1, sizeof(globus_i_xiobanner_info_t));
    if(info == NULL)
    {
        goto error;
    }

    globus_mutex_init(&info->mutex, NULL);
    globus_hashtable_init(&info->driver_table, 8, 
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    GlobusTimeReltimeSet(info->time, 10, 0);
    globus_xio_stack_init(&info->stack, NULL);
    globus_xio_attr_init(&info->attr);

    globus_options_init(
        &opt_h, xiobanner_l_opts_unknown, info, globus_i_xiobanner_opts_table);
    res = globus_options_command_line_process(opt_h, argc, argv);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_result;
    }
    if(info->deliminator == NULL)
    {
        info->deliminator = "\n";
    }
    if(info->max_len == 0)
    {
        info->max_len = 80;
    }
    if(info->driver_count == 0)
    {
        globus_xio_driver_t                 driver;

        res = globus_xio_driver_load("tcp", &driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_result;
        }
        res = globus_xio_stack_push_driver(info->stack, driver);
        if(res != GLOBUS_SUCCESS)
        {
            goto error_result;
        }
    }

    return info;
error_result:
    xiobanner_log(info, 10, "%s\n",
        globus_error_print_friendly(globus_error_get(res)));
error:
    return NULL;
}

int
main(
    int                                 argc,
    char **                             argv)
{
    globus_i_xiobanner_info_t *         info;
    globus_result_t                     res;
    globus_size_t                       nbytes;
    int                                 del_len;
    globus_byte_t *                     buffer;
    globus_size_t                       ndx = 0;
    globus_size_t                       buf_len = 256;
    globus_size_t                       read_sz = 256;
    globus_byte_t *                     ptr;
 
    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_COMMON_MODULE);

    info = xiobanner_l_parse_opts(argc, argv);
    if(info == NULL)
    {
        goto error_end;
    }
    res = globus_xio_handle_create(&info->xio_handle, info->stack);
    if(res != GLOBUS_SUCCESS)
    {
        xiobanner_log(info, 1, "setup error:",res);
        goto error;
    }

    buffer = globus_malloc(buf_len);
    del_len = strlen(info->deliminator);
    globus_mutex_lock(&info->mutex);
    {
        res = globus_xio_open(info->xio_handle, info->cs, info->attr);
        if(res != GLOBUS_SUCCESS)
        {
            goto error;
        }

        while(!info->done)
        {
            if(ndx + read_sz > buf_len)
            {
                buf_len = (buf_len + read_sz) * 2;
                buffer = globus_realloc(buffer, buf_len);
            }
            res = globus_xio_read(info->xio_handle, &buffer[ndx], read_sz,
                1, &nbytes, NULL);
            if(res != GLOBUS_SUCCESS)
            {
                info->done = GLOBUS_TRUE;
            }
            ndx += nbytes;
            ptr = globus_libc_memmem(buffer, BUFFER_SIZE, 
                info->deliminator, del_len);
            if(ptr != NULL)
            {
                ndx = ptr + del_len - buffer;
                info->done = GLOBUS_TRUE;
            }
            else if(ndx > info->max_len)
            {
                ndx = info->max_len;
                info->done = GLOBUS_TRUE;
            }
        }
    }
    globus_mutex_unlock(&info->mutex);

    globus_xio_close(info->xio_handle, NULL);

    write(STDOUT_FILENO, buffer, ndx);

    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 0;

error:
    fprintf(stderr, "%s\n",
        globus_error_print_friendly(globus_error_get(res)));
error_end:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 1;
}
