
#include "globus_i_gridftp_server.h"

/**
 * should select logging based on configuration.  log output funcs should
 * still be usable before this and will output to stderr.
 * 
 * if this fails, just print to stderr.
 */
 

static globus_logging_handle_t          globus_l_gfs_log_handle = NULL;
static FILE *                           globus_l_gfs_log_file = NULL;
static FILE *                           globus_l_gfs_transfer_log_file = NULL;

void
globus_i_gfs_log_open(void)
{
    char *                              module;
    globus_logging_module_t *           log_mod;
    void *                              log_arg;
    char *                              logfilename;
    int                                 log_filemode;
    char *                              logunique;
        
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
        
    if((logfilename = globus_i_gfs_config_string("log_transfer")) != NULL)
    {
        globus_l_gfs_transfer_log_file = fopen(logfilename, "a"); 
        setvbuf(globus_l_gfs_transfer_log_file, NULL, _IOLBF, 0);
        if((log_filemode = globus_i_gfs_config_int("log_filemode")) != 0)
        {
            chmod(logfilename, log_filemode);
        }
        globus_free(logfilename);
    }
        
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
    if(globus_l_gfs_transfer_log_file != NULL)
    {
        fclose(globus_l_gfs_transfer_log_file);
        globus_l_gfs_transfer_log_file = NULL;
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

void
globus_i_gfs_log_transfer(
    int                                 stripe_count,
    int                                 stream_count, 
    struct timeval *                    start_gtd_time,
    struct timeval *                    end_gtd_time,
    char *                              dest_ip,
    globus_size_t                       blksize,
    globus_size_t                       tcp_bs,
    const char *                        fname,
    globus_size_t                       nbytes,
    int                                 code,
    char *                              volume,
    char *                              type,
    char *                              username)
{
    time_t                              start_time_time;
    time_t                              end_time_time;
    struct tm *                         tmp_tm_time;
    struct tm                           start_tm_time;
    struct tm                           end_tm_time;
    char                                out_buf[4096];
    long                                win_size;

    if(globus_l_gfs_transfer_log_file == NULL)
    {
        return;
    }

    start_time_time = (time_t)start_gtd_time->tv_sec;
    tmp_tm_time = gmtime(&start_time_time);
    if(tmp_tm_time == NULL)
    {
        return;
    }
    start_tm_time = *tmp_tm_time;

    end_time_time = (time_t)end_gtd_time->tv_sec;
    tmp_tm_time = gmtime(&end_time_time);
    if(tmp_tm_time == NULL)
    {
        return;
    }
    end_tm_time = *tmp_tm_time;

    if(tcp_bs == 0)
    {
        win_size = 0;
/*      int                             sock;
        int                             opt_len;
        int                             opt_dir;

        if(strcmp(type, "RETR") == 0 || strcmp(type, "ERET") == 0)
        {
            opt_dir = SO_SNDBUF;
            sock = STDOUT_FILENO;
        }
        else
        {
            opt_dir = SO_RCVBUF;
            sock = STDIN_FILENO;
        }
        opt_len = sizeof(win_size);
        getsockopt(sock, SOL_SOCKET, opt_dir, &win_size, &opt_len);
*/
    }
    else
    {
        win_size = tcp_bs;
    }

    sprintf(out_buf, 
        "DATE=%04d%02d%02d%02d%02d%02d.%d "
        "HOST=%s "
        "PROG=%s "
        "NL.EVNT=FTP_INFO "
        "START=%04d%02d%02d%02d%02d%02d.%d "
        "USER=%s "
        "FILE=%s "
        "BUFFER=%ld "
        "BLOCK=%ld "
        "NBYTES=%ld "
        "VOLUME=%s "
        "STREAMS=%d "
        "STRIPES=%d "
        "DEST=[%s] " 
        "TYPE=%s " 
        "CODE=%d\n",
        /* end time */
        end_tm_time.tm_year + 1900,
        end_tm_time.tm_mon + 1,
        end_tm_time.tm_mday,
        end_tm_time.tm_hour,
        end_tm_time.tm_min,
        end_tm_time.tm_sec,
        (int) end_gtd_time->tv_usec,
        globus_i_gfs_config_string("fqdn"),
        "globus-gridftp-server",
        /* start time */
        start_tm_time.tm_year + 1900,
        start_tm_time.tm_mon + 1,
        start_tm_time.tm_mday,
        start_tm_time.tm_hour,
        start_tm_time.tm_min,
        start_tm_time.tm_sec,
        (int) start_gtd_time->tv_usec,
        /* other args */
        username,
        fname,
        win_size,
        (long) blksize,
        (long) nbytes,
        volume,
        stream_count, 
        stripe_count,
        dest_ip,
        type, 
        code);
        
    fwrite(out_buf, 1, strlen(out_buf), globus_l_gfs_transfer_log_file);
}
