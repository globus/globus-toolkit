
#include "globus_i_gridftp_server.h"

/**
 * should select logging based on configuration.  log output funcs should
 * still be usable before this and will output to stderr.
 * 
 * if this fails, just print to stderr.
 */
 
static globus_logging_handle_t          log_handle;
static FILE *                           log_file = NULL;

void
globus_i_gfs_log_open(void)
{
    char *                              logfilename;
    
    logfilename = globus_i_gfs_config_string("logfile");
    if(logfilename != NULL)
    {
        log_file = fopen(logfilename, "a");
        if(globus_i_gfs_config_bool("log_public"))
        {
            chmod(logfilename, 0644);
        }
        else
        {
            chmod(logfilename, 0600);
        }            
    }
    if(log_file == NULL)
    {
        log_file = stderr;
    }
    globus_logging_init(
        &log_handle,
        GLOBUS_NULL, /* no buffered logs */
        16384,
        globus_i_gfs_config_int("debug_level"), 
        &globus_logging_stdio_module,
        log_file);
}

void
globus_i_gfs_log_close(void)
{
    globus_logging_flush(log_handle);
    globus_logging_destroy(log_handle);
    if(log_file != stderr && log_file != NULL)
    {
        fclose(log_file);
    }
}

void
globus_i_gfs_log_message(
    globus_i_gfs_log_type_t             type,
    const char *                        format,
    ...)
{
    va_list                             ap;
    
    va_start(ap, format);
    globus_logging_vwrite(log_handle, type, format, ap);
    va_end(ap);
}

void
globus_i_gfs_log_result(
    const char *                        lead,
    globus_result_t                     result)
{
    char *                              message;
    
    if(result != GLOBUS_SUCCESS)
    {
        message = globus_error_print_friendly(globus_error_peek(result));
    }
    else
    {
        message = globus_libc_strdup("(no error)");
    }
    globus_i_gfs_log_message(GLOBUS_I_GFS_LOG_ERR, "%s:\n%s\n", lead, message);
    globus_free(message);
}
