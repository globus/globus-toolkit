
#include "globus_i_gridftp_server.h"

/**
 * should select logging based on configuration.  log output funcs should
 * still be usable before this and will output to stderr.
 * 
 * if this fails, just print to stderr.
 */
 

static globus_logging_handle_t          globus_l_gfs_log_handle = NULL;
static FILE *                           globus_l_gfs_log_file = NULL;

void
globus_i_gfs_log_open(void)
{
    char *                              module;
    globus_logging_module_t *           log_mod;
    void *                              log_arg;
        
    /* XXX should use the globus_extension stuff here */
    module = globus_i_gfs_config_string("log_module");
    if(module == NULL || strcmp(module, "stdio") == 0)
    {
        log_mod = &globus_logging_stdio_module;
    }
    else if(strcmp(module, "syslog") == 0)
    {
        log_mod = &globus_logging_syslog_module;
        /* set syslog options and pass in log_arg */
    }
    else
    {
        globus_libc_fprintf(stderr, 
            "Invalid logging module specified, using stdio.\n");
        log_mod = &globus_logging_stdio_module;
    }

    if(log_mod == &globus_logging_stdio_module)
    {          
        char *                          logfilename;
        char *                          logunique;
        int                             log_filemode;
        
        logfilename = globus_i_gfs_config_string("log_single");
        if(logfilename == NULL)
        {
            logunique = globus_i_gfs_config_string("log_unique");
            if(logunique != NULL)
            {
                logfilename = globus_common_create_string(
                    "%sgridftp.%d.log", logunique, getpid());
            }
        }
        if(logfilename != NULL)
        {
            
            globus_l_gfs_log_file = fopen(logfilename, "a"); 
            if((log_filemode = globus_i_gfs_config_int("log_filemode")) != 0)
            {
                chmod(logfilename, log_filemode);
            }
            globus_free(logfilename);
        }
        if(globus_l_gfs_log_file == NULL)
        {
            globus_l_gfs_log_file = stderr;
        }
        
        log_arg = globus_l_gfs_log_file;
    }
    
    globus_logging_init(
        &globus_l_gfs_log_handle,
        GLOBUS_NULL, /* no buffered logs */
        2048,
        globus_i_gfs_config_int("debug_level"), 
        log_mod,
        log_arg);
}

void
globus_i_gfs_log_close(void)
{
    globus_logging_flush(globus_l_gfs_log_handle);
    globus_logging_destroy(globus_l_gfs_log_handle);
    if(globus_l_gfs_log_file != stderr && globus_l_gfs_log_file != NULL)
    {
        fclose(globus_l_gfs_log_file);
        globus_l_gfs_log_file = NULL;
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
    globus_logging_vwrite(globus_l_gfs_log_handle, type, format, ap);
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
