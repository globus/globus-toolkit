#include <globus_logging.h>
#include <globus_common.h>

#define GLOBUS_L_LOGGING_OUTSTANDING_LINES  32

#ifdef __GNUC__
#define GlobusGridFTPServerName(func) static const char * _globus_logging_name __attribute__((__unused__)) = #func
#else
#define GlobusGridFTPServerName(func) static const char * _globus_logging_name = #func
#endif
                                                                                
/*
 *  error types
 */
#define GlobusGridFTPServerErrorParameter(param_name)                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_COMMON_MODULE,                                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_LOGGING_ERROR_PARAMETER,                                 \
            __FILE__,                                                       \
            _globus_logging_name,                                           \
            __LINE__,                                                       \
            "Bad parameter, %s",                                            \
            (param_name)))

#define GlobusGridFTPServerMemory()                                         \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_COMMON_MODULE,                                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_LOGGING_ERROR_ALLOC,                                     \
            __FILE__,                                                       \
            _globus_logging_name,                                           \
            __LINE__,                                                       \
            "Out of memory"))

typedef struct globus_l_logging_handle_s
{
    globus_mutex_t                      mutex;
    int                                 type_mask;
    int                                 max_log_line;
    globus_size_t                       buffer_length;
    globus_size_t                       used_length;
    void *                              user_arg;
    globus_callback_handle_t            callback_handle;
    globus_logging_module_t             module;
    globus_bool_t                       periodic_running;
    globus_byte_t                       buffer[1];
} globus_l_logging_handle_t;

/*
 *  flush the buffer
 */
static void
globus_l_logging_flush(
    globus_l_logging_handle_t *         handle)
{
    if(handle->used_length > 0)
    {
        handle->module.write_func(
            handle->buffer, handle->used_length, handle->user_arg);
    }
    handle->used_length = 0;
}

/*
 *  unregister callback.  clean up happens here
 */
static void
globus_l_logging_unregister(
    void *                              user_arg)
{
    globus_l_logging_handle_t *         handle;

    handle = (globus_l_logging_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        if(handle->module.close_func != NULL)
        {
            handle->module.close_func(handle->user_arg);
        }
    }
    globus_mutex_unlock(&handle->mutex);

    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
}

/*
 *  callback for delayed logging, just lock and flush.
 */
static void
globus_l_logging_periodic(
    void *                              user_arg)
{
    globus_l_logging_handle_t *         handle;

    handle = (globus_l_logging_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        globus_l_logging_flush(handle); 
    }
    globus_mutex_unlock(&handle->mutex);
}

/*
 *  external functions
 */
globus_result_t
globus_logging_init(
    globus_logging_handle_t *           out_handle,
    globus_reltime_t *                  flush_period,
    int                                 max_log_line,
    int                                 log_type,   
    globus_logging_module_t *           module,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_l_logging_handle_t *         handle;
    globus_size_t                       buffer_length;
    GlobusGridFTPServerName(globus_logging_init);

    if(out_handle == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("out_handle");
        goto err;
    }
    if(max_log_line < 0)
    {
        res = GlobusGridFTPServerErrorParameter("max_mem_buffer");
        goto err;
    }
    if(module == NULL || module->write_func == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("module");
        goto err;
    }

    buffer_length = max_log_line * GLOBUS_L_LOGGING_OUTSTANDING_LINES;

    handle = (globus_l_logging_handle_t *)
        globus_malloc(sizeof(globus_l_logging_handle_t) + buffer_length - 1);
    if(handle == NULL)
    {
        res = GlobusGridFTPServerMemory();
        goto err;
    }

    handle->module.open_func = module->open_func;
    handle->module.write_func = module->write_func;
    handle->module.close_func = module->close_func;
    handle->module.time_func = module->time_func;

    globus_mutex_init(&handle->mutex, NULL);
    handle->type_mask = log_type;
    handle->buffer_length = buffer_length;
    handle->max_log_line = max_log_line;
    handle->used_length = 0;
    handle->user_arg = user_arg;

    if(handle->module.open_func)
    {
        handle->module.open_func(handle->user_arg);
    }

    if(flush_period != NULL)
    {
        res = globus_callback_register_periodic(
            &handle->callback_handle,
            flush_period,
            flush_period,
            globus_l_logging_periodic,
            handle);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        handle->periodic_running = GLOBUS_TRUE;
    }
    else
    {
        /* insist that all are inline */
        handle->type_mask |= GLOBUS_LOGGING_INLINE;
        handle->periodic_running = GLOBUS_FALSE;
    }
    *out_handle = handle;

    return GLOBUS_SUCCESS;

  err:

    return res;
}
globus_result_t
globus_logging_vwrite(
    globus_logging_handle_t             handle,
    int                                 type,
    const char *                        fmt,
    va_list                             ap)
{
    globus_result_t                     res;
    globus_size_t                       remain;
    globus_size_t                       nbytes;
    GlobusGridFTPServerName(globus_logging_write);

    if(handle == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("handle");
        goto err;
    }
    if(fmt == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("fmt");
        goto err;
    }

    globus_mutex_lock(&handle->mutex);
    {
        if(type & handle->type_mask)
        {
            remain = handle->buffer_length - handle->used_length;
            if(remain < handle->max_log_line)
            {
                globus_l_logging_flush(handle);
                remain = handle->buffer_length;
            }
            if(handle->module.time_func != NULL)
            {
                nbytes = remain;
                handle->module.time_func(
                    &handle->buffer[handle->used_length],
                    &nbytes);
                handle->used_length += nbytes;
                remain -= nbytes;
            }
            nbytes = vsnprintf(
                &handle->buffer[handle->used_length], remain, fmt, ap);
            handle->used_length += nbytes;
            if(type & GLOBUS_LOGGING_INLINE || 
                handle->type_mask & GLOBUS_LOGGING_INLINE)
            {
                globus_l_logging_flush(handle);
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

  err:
    return res;
}
    
globus_result_t
globus_logging_write(
    globus_logging_handle_t             handle,
    int                                 type,
    const char *                        fmt,
    ...)
{
    va_list                             ap;
    globus_result_t                     res;
    va_start(ap, fmt);
    res = globus_logging_vwrite(handle, type, fmt, ap);
    va_end(ap);

    return res;
}

globus_result_t
globus_logging_flush(
    globus_logging_handle_t             handle)
{
    GlobusGridFTPServerName(globus_logging_flush);

    globus_mutex_lock(&handle->mutex);
    {
        globus_l_logging_flush(handle);
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_logging_destroy(
    globus_logging_handle_t             handle)
{
    globus_result_t                     res;
    GlobusGridFTPServerName(globus_logging_destroy);

    if(handle == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("handle");
        goto err;
    }

    globus_mutex_lock(&handle->mutex);
    {
        globus_l_logging_flush(handle);

        if(handle->periodic_running)
        {
            res = globus_callback_unregister(
                handle->callback_handle,
                globus_l_logging_unregister,
                handle,
                NULL);
            if(res != GLOBUS_SUCCESS)
            {
                globus_mutex_unlock(&handle->mutex);
                goto err;
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return GLOBUS_SUCCESS;

  err:
    return res;
}

void
globus_logging_stdio_write_func(
    globus_byte_t *                     buf,
    globus_size_t                       length,
    void *                              user_arg)
{
    FILE *                              fptr;

    fptr = (FILE *) user_arg;

    fwrite(buf, length, 1, fptr);
}

void
globus_logging_stdio_time_func(
    char *                              buf,
    globus_size_t *                     len)
{
    char *                              str;
    time_t                              tm;
    globus_size_t                       str_len;

    tm = time(NULL);
    str = ctime(&tm);
    str_len = strlen(str);

    if(str_len < *len)
    {
        *len = str_len-1;
    }
    memcpy(buf, str, *len);
    buf[*len] = ' ';
    (*len)++;
    buf[*len] = ':';
    (*len)++;
    buf[*len] = ':';
    (*len)++;
    buf[*len] = ' ';
    (*len)++;
}

globus_logging_module_t                 globus_logging_stdio_module =
{
    NULL,
    globus_logging_stdio_write_func,
    NULL,
    globus_logging_stdio_time_func
};

globus_logging_module_t                 globus_logging_syslog_module =
{
    NULL,
    NULL,
    NULL,
    NULL
};
