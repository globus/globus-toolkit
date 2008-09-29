/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_i_gridftp_server.h"

/**
 * should select logging based on configuration.  log output funcs should
 * still be usable before this and will output to stderr.
 *
 * if this fails, just print to stderr.
 */


static globus_logging_handle_t          globus_l_gfs_log_handle = NULL;
static globus_list_t *                  globus_l_gfs_log_usage_handle_list = NULL;
static FILE *                           globus_l_gfs_log_file = NULL;
static FILE *                           globus_l_gfs_transfer_log_file = NULL;
static globus_bool_t                    globus_l_gfs_log_events = GLOBUS_FALSE;

#define GLOBUS_L_GFS_USAGE_ID 0
#define GLOBUS_L_GFS_USAGE_VER 0

#define GLOBUS_GFS_DEFAULT_TAGLIST "eEvbBNsStcDATaV"
#define GLOBUS_GFS_ALL_TAGLIST "eEvbBNsStcfiIudCDATaVU"
#define GLOBUS_GFS_MAX_TAGCOUNT 25

typedef enum globus_i_gfs_log_usage_tag_e
{
    GLOBUS_I_GFS_USAGE_START    = 'e',
    GLOBUS_I_GFS_USAGE_END      = 'E',
    GLOBUS_I_GFS_USAGE_VER      = 'v',
    GLOBUS_I_GFS_USAGE_BUFFER   = 'b',
    GLOBUS_I_GFS_USAGE_BLOCK    = 'B',
    GLOBUS_I_GFS_USAGE_NBYTES   = 'N',
    GLOBUS_I_GFS_USAGE_STREAMS  = 's',
    GLOBUS_I_GFS_USAGE_STRIPES  = 'S',
    GLOBUS_I_GFS_USAGE_TYPE     = 't',
    GLOBUS_I_GFS_USAGE_CODE     = 'c',
    GLOBUS_I_GFS_USAGE_FILE     = 'f',
    GLOBUS_I_GFS_USAGE_CLIENTIP = 'i',
    GLOBUS_I_GFS_USAGE_DATAIP   = 'I',
    GLOBUS_I_GFS_USAGE_USER     = 'u',
    GLOBUS_I_GFS_USAGE_USERDN   = 'd',
    GLOBUS_I_GFS_USAGE_CONFID   = 'C',
    GLOBUS_I_GFS_USAGE_DSI      = 'D',
    GLOBUS_I_GFS_USAGE_EM       = 'A',
    GLOBUS_I_GFS_USAGE_SCHEMA   = 'T',
    GLOBUS_I_GFS_USAGE_APP      = 'a',
    GLOBUS_I_GFS_USAGE_APPVER   = 'V',
    GLOBUS_I_GFS_USAGE_SESSID   = 'U'
    /* !! ADD to ALL_TAGLIST above when adding here */
} globus_i_gfs_log_usage_tag_t;

typedef struct globus_l_gfs_log_usage_ent_s
{
    globus_usage_stats_handle_t         handle;
    char *                              target;
    char *                              taglist;
} globus_l_gfs_log_usage_ent_t;


int
globus_l_gfs_log_matchlevel(
    char *                              tag)
{
    int                                 out = 0;
    GlobusGFSName(globus_l_gfs_log_matchlevel);
    GlobusGFSDebugEnter();

    if(strcasecmp(tag, "ERROR") == 0)
    {
        out = GLOBUS_GFS_LOG_ERR;
    }
    else if(strcasecmp(tag, "WARN") == 0)
    {
        out = GLOBUS_GFS_LOG_WARN;
    }
    else if(strcasecmp(tag, "INFO") == 0)
    {
        out = GLOBUS_GFS_LOG_INFO;
    }
    else if(strcasecmp(tag, "STATUS") == 0)
    {
        out = GLOBUS_GFS_LOG_STATUS;
    }
    else if(strcasecmp(tag, "DUMP") == 0)
    {
        out = GLOBUS_GFS_LOG_DUMP;
    }
    else if(strcasecmp(tag, "ALL") == 0)
    {
        out = GLOBUS_GFS_LOG_ALL;
    }

    GlobusGFSDebugExit();
    return out;
}


static
globus_result_t
globus_l_gfs_log_usage_stats_init()
{
    globus_result_t                     result;
    char *                              target_str;
    char *                              ptr;
    char *                              target;
    char *                              entry;
    globus_list_t *                     list;
    globus_l_gfs_log_usage_ent_t *      usage_ent;

    target_str = globus_libc_strdup(
        globus_i_gfs_config_string("usage_stats_target"));

    if(target_str && strchr(target_str, '!'))
    {
        target = target_str;
        while((ptr = strchr(target, ',')) != NULL)
        {
            usage_ent = (globus_l_gfs_log_usage_ent_t *)
                globus_malloc(sizeof(globus_l_gfs_log_usage_ent_t));

            *ptr = '\0';
            entry = globus_libc_strdup(target);
            target = ptr + 1;

            if((ptr = strchr(entry, '!')) != NULL)
            {
                *ptr = '\0';
                usage_ent->taglist = globus_libc_strdup(ptr + 1);
                if(strlen(usage_ent->taglist) > GLOBUS_GFS_MAX_TAGCOUNT)
                {
                    usage_ent->taglist[GLOBUS_GFS_MAX_TAGCOUNT + 1] = '\0';
                }
            }
            else
            {
                usage_ent->taglist = 
                    globus_libc_strdup(GLOBUS_GFS_DEFAULT_TAGLIST);
            }
            
            if(strcasecmp(usage_ent->taglist, "default") == 0)
            {
                globus_free(usage_ent->taglist);
                usage_ent->taglist = 
                    globus_libc_strdup(GLOBUS_GFS_DEFAULT_TAGLIST);
            }                
            else if(strcasecmp(usage_ent->taglist, "all") == 0)
            {
                globus_free(usage_ent->taglist);
                usage_ent->taglist = 
                    globus_libc_strdup(GLOBUS_GFS_ALL_TAGLIST);
            }                
            
            usage_ent->target = entry;

            globus_list_insert(&globus_l_gfs_log_usage_handle_list, usage_ent);
        }
        if(ptr == NULL)
        {
            usage_ent = (globus_l_gfs_log_usage_ent_t *)
                globus_malloc(sizeof(globus_l_gfs_log_usage_ent_t));

            entry = globus_libc_strdup(target);
            target = ptr + 1;

            if((ptr = strchr(entry, '!')) != NULL)
            {
                *ptr = '\0';
                usage_ent->taglist = globus_libc_strdup(ptr + 1);
                if(strlen(usage_ent->taglist) > GLOBUS_GFS_MAX_TAGCOUNT)
                {
                    usage_ent->taglist[GLOBUS_GFS_MAX_TAGCOUNT + 1] = '\0';
                }
            }
            else
            {
                usage_ent->taglist = 
                    globus_libc_strdup(GLOBUS_GFS_DEFAULT_TAGLIST);
            }

            if(strcasecmp(usage_ent->taglist, "default") == 0)
            {
                globus_free(usage_ent->taglist);
                usage_ent->taglist = 
                    globus_libc_strdup(GLOBUS_GFS_DEFAULT_TAGLIST);
            }                
            else if(strcasecmp(usage_ent->taglist, "all") == 0)
            {
                globus_free(usage_ent->taglist);
                usage_ent->taglist = 
                    globus_libc_strdup(GLOBUS_GFS_ALL_TAGLIST);
            }                

            usage_ent->target = entry;

            globus_list_insert(&globus_l_gfs_log_usage_handle_list, usage_ent);
        }

        globus_free(target_str);
    }
    else
    {
        usage_ent = (globus_l_gfs_log_usage_ent_t *)
            globus_malloc(sizeof(globus_l_gfs_log_usage_ent_t));

        usage_ent->target = target_str;
        usage_ent->taglist = globus_libc_strdup(GLOBUS_GFS_DEFAULT_TAGLIST);

        globus_list_insert(&globus_l_gfs_log_usage_handle_list, usage_ent);
    }


    for(list = globus_l_gfs_log_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (globus_l_gfs_log_usage_ent_t *) globus_list_first(list);

        usage_ent->handle = NULL;
        result = globus_usage_stats_handle_init(
            &usage_ent->handle,
            GLOBUS_L_GFS_USAGE_ID,
            GLOBUS_L_GFS_USAGE_VER,
            usage_ent->target);
    }

    return result;
}


void
globus_i_gfs_log_open()
{
    char *                              module;
    char *                              module_str;
    globus_logging_module_t *           log_mod;
    void *                              log_arg = NULL;
    char *                              logfilename = NULL;
    char *                              log_filemode = NULL;
    char *                              logunique = NULL;
    char *                              log_level = NULL;
    int                                 log_mask = 0;
    char *                              ptr;
    int                                 len;
    int                                 ctr;
    char *                              tag;
    globus_result_t                     result;
    globus_reltime_t                    flush_interval;
    globus_size_t                       buffer;
    GlobusGFSName(globus_i_gfs_log_open);
    GlobusGFSDebugEnter();

    GlobusTimeReltimeSet(flush_interval, 5, 0);
    buffer = 65536;

    /* parse user supplied log level string */
    log_level = globus_libc_strdup(globus_i_gfs_config_string("log_level"));
    if(log_level != NULL)
    {
        len = strlen(log_level);
        for(ctr = 0; ctr < len && isdigit(log_level[ctr]); ctr++);
        /* just a number, set log level to the supplied level || every level
            below */
        if(ctr == len)
        {
            log_mask = atoi(log_level);
            if(log_mask > 1)
            {
                log_mask |= (log_mask >> 1) | ((log_mask >> 1)  - 1);
            }
        }
        else
        {
            tag = log_level;
            while((ptr = strchr(tag, ',')) != NULL)
            {
                *ptr = '\0';
                log_mask |= globus_l_gfs_log_matchlevel(tag);
                tag = ptr + 1;
            }
            if(ptr == NULL)
            {
                log_mask |= globus_l_gfs_log_matchlevel(tag);
            }
        }
        globus_free(log_level);
    }

    module_str = globus_libc_strdup(globus_i_gfs_config_string("log_module"));
    module = module_str;
    if(module_str != NULL)
    {
        char *                          opts;
        char *                          end;
        globus_off_t                    tmp_off;
        int                             rc;

        end = module_str + strlen(module_str);
        ptr = strchr(module_str, ':');
        if(ptr != NULL)
        {
            *ptr = '\0';
            ptr++;

            do
            {
                opts = ptr;
                ptr = strchr(opts, ':');
                if(ptr)
                {
                    *ptr = '\0';
                    ptr++;
                    if(ptr >= end)
                    {
                        ptr = NULL;
                    }
                }
                if(strncasecmp(opts, "buffer=", 7) == 0)
                {
                    rc = globus_args_bytestr_to_num(
                        opts + 7, &tmp_off);
                    if(rc != 0)
                    {
                        fprintf(stderr, "Invalid value for log buffer\n");
                    }
                    if(tmp_off == 0)
                    {
                        log_mask |= GLOBUS_LOGGING_INLINE;
                    }
                    if(tmp_off < 2048)
                    {
                         buffer = 2048;
                    }
                    else
                    {
                        buffer = (globus_size_t) tmp_off;
                    }
                }
                else if(strncasecmp(opts, "interval=", 9) == 0)
                {
                    rc = globus_args_bytestr_to_num(
                        opts + 9, &tmp_off);
                    if(rc != 0)
                    {
                        fprintf(stderr,
                            "Invalid value for log flush interval\n");
                    }
                    GlobusTimeReltimeSet(flush_interval, (int) tmp_off, 0);
                }
                else
                {
                    fprintf(stderr, "Invalid log module option: %s\n", opts);
                }


            } while(ptr && *ptr);
        }
    }

    if(module == NULL || strcmp(module, "stdio") == 0)
    {
        log_mod = &globus_logging_stdio_module;
    }
    else if(strcmp(module, "syslog") == 0)
    {
        log_mod = &globus_logging_syslog_module;
    }
    else if(strcmp(module, "stdio_ng") == 0)
    {
        log_mod = &globus_logging_stdio_ng_module;
        globus_l_gfs_log_events = GLOBUS_TRUE;
        log_mask |= GLOBUS_GFS_LOG_INFO | 
            GLOBUS_GFS_LOG_WARN | GLOBUS_GFS_LOG_ERR;
    }
    else if(strcmp(module, "syslog_ng") == 0)
    {
        log_mod = &globus_logging_syslog_ng_module;
        globus_l_gfs_log_events = GLOBUS_TRUE;
        log_mask |= GLOBUS_GFS_LOG_INFO | 
            GLOBUS_GFS_LOG_WARN | GLOBUS_GFS_LOG_ERR;
    }
    else
    {
        globus_libc_fprintf(stderr,
            "Invalid logging module specified, using stdio.\n");
        log_mod = &globus_logging_stdio_module;
    }

    if(log_mod == &globus_logging_stdio_module ||
        log_mod == &globus_logging_stdio_ng_module )
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
            if(globus_l_gfs_log_file == NULL)
            {
                if(!globus_i_gfs_config_bool("inetd"))
                {
                    globus_libc_fprintf(stderr,
                        "Unable to open %s for logging. "
                        "Using stderr instead.\n", logfilename);
                    globus_l_gfs_log_file = stderr;
                }
            }
            else
            {
                setvbuf(globus_l_gfs_log_file, NULL, _IOLBF, 0);
                if((log_filemode =
                    globus_i_gfs_config_string("log_filemode")) != NULL)
                {
                    int                     mode = 0;
                    mode = strtoul(log_filemode, NULL, 0);
                    chmod(logfilename, mode);
                }
            }
        }

        if(globus_l_gfs_log_file == NULL)
        {
            globus_l_gfs_log_file = stderr;
        }

        log_arg = globus_l_gfs_log_file;

        if(logunique != NULL)
        {
            globus_free(logfilename);
        }
    }

    if(!((log_mod == &globus_logging_stdio_module ||
        log_mod == &globus_logging_stdio_ng_module) && log_arg == NULL))
    {
        globus_logging_init(
            &globus_l_gfs_log_handle,
            &flush_interval,
            buffer,
            log_mask,
            log_mod,
            log_arg);
    }

    if((logfilename = globus_i_gfs_config_string("log_transfer")) != NULL)
    {
        globus_l_gfs_transfer_log_file = fopen(logfilename, "a");
        if(globus_l_gfs_transfer_log_file == NULL)
        {
            if(!globus_i_gfs_config_bool("inetd"))
            {
                globus_libc_fprintf(stderr,
                    "Unable to open %s for transfer logging.\n", logfilename);
            }
        }
        else
        {
            setvbuf(globus_l_gfs_transfer_log_file, NULL, _IOLBF, 0);
            if((log_filemode = globus_i_gfs_config_string("log_filemode")) != 0)
            {
                int                     mode = 0;
                mode = strtoul(log_filemode, NULL, 0);
                chmod(logfilename, mode);
            }
        }
    }

    if(!globus_i_gfs_config_bool("disable_usage_stats"))
    {
        result = globus_l_gfs_log_usage_stats_init();
    }


    if(module_str)
    {
        globus_free(module_str);
    }

    GlobusGFSDebugExit();
}

void
globus_i_gfs_log_close(void)
{
    globus_list_t *                     list;
    GlobusGFSName(globus_i_gfs_log_close);
    GlobusGFSDebugEnter();

    if(globus_l_gfs_log_handle != NULL)
    {
        globus_logging_flush(globus_l_gfs_log_handle);
        globus_logging_destroy(globus_l_gfs_log_handle);
    }
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
    
    list = globus_l_gfs_log_usage_handle_list;
    
    while(!globus_list_empty(list))
    {
        globus_l_gfs_log_usage_ent_t *  usage_ent;
        
        usage_ent = (globus_l_gfs_log_usage_ent_t *) 
            globus_list_remove(&list, list);
    
        if(usage_ent)
        {
            if(usage_ent->handle)
            {
                globus_usage_stats_handle_destroy(usage_ent->handle);
            }
            if(usage_ent->target)
            {
                globus_free(usage_ent->target);
            }
            if(usage_ent->taglist)
            {
                globus_free(usage_ent->taglist);
            }
            globus_free(usage_ent);
        }
    }

    GlobusGFSDebugExit();
}

void
globus_gfs_log_message(
    globus_gfs_log_type_t               type,
    const char *                        format,
    ...)
{
    va_list                             ap;
    GlobusGFSName(globus_gfs_log_message);
    GlobusGFSDebugEnter();

    if(globus_l_gfs_log_handle != NULL && !globus_l_gfs_log_events)
    {
        va_start(ap, format);
        globus_logging_vwrite(globus_l_gfs_log_handle, type, format, ap);
        va_end(ap);
    }

    GlobusGFSDebugExit();
}

void
globus_gfs_log_result(
    globus_gfs_log_type_t               type,
    const char *                        lead,
    globus_result_t                     result)
{
    char *                              message;
    GlobusGFSName(globus_gfs_log_result);
    GlobusGFSDebugEnter();

    if(result != GLOBUS_SUCCESS)
    {
        message = globus_error_print_friendly(globus_error_peek(result));
    }
    else
    {
        message = globus_libc_strdup("(unknown error)");
    }
    globus_gfs_log_message(type, "%s:\n%s\n", lead, message);
    globus_free(message);

    GlobusGFSDebugExit();
}


void
globus_i_gfs_log_tr(
    char *                              msg,
    char                                from,
    char                                to)
{
    char *                              ptr;
    GlobusGFSName(globus_l_gfs_log_tr);
    GlobusGFSDebugEnter();

    ptr = strchr(msg, from);
    while(ptr != NULL)
    {
        *ptr = to;
        ptr = strchr(ptr, from);
    }
    GlobusGFSDebugExit();
}


void
globus_gfs_log_event(
    globus_gfs_log_type_t               type,
    globus_gfs_log_event_type_t         event_type,
    const char *                        event_name,
    globus_result_t                     result,
    const char *                        format,
    ...)
{
    va_list                             ap;
    char *                              msg;
    char *                              tmp = NULL;
    char *                              startend;
    char *                              status;
    char *                              message = NULL;
    GlobusGFSName(globus_gfs_log_message);
    GlobusGFSDebugEnter();

    if(globus_l_gfs_log_handle != NULL && globus_l_gfs_log_events)
    {
        if(format)
        {
            va_start(ap, format);
            tmp = globus_common_v_create_string(format, ap);
            va_end(ap);

            globus_i_gfs_log_tr(tmp, '\n', ' ');
        }

        if(result != GLOBUS_SUCCESS)
        {
            message = globus_error_print_friendly(globus_error_peek(result));
            globus_i_gfs_log_tr(message, '\n', ' ');
            globus_i_gfs_log_tr(message, '\"', '\'');
        }

        switch(event_type)
        {
            case GLOBUS_GFS_LOG_EVENT_START:
                startend = "start";
                status = NULL;
                break;
            case GLOBUS_GFS_LOG_EVENT_END:
                startend = "end";
                if(result == GLOBUS_SUCCESS)
                {
                    status = " status=0";
                }
                else
                {
                    status = " status=-1";
                }
                break;
            case GLOBUS_GFS_LOG_EVENT_MESSAGE:
                startend = "message";
                status = NULL;
                break;
            default:
                startend = "error";
                status = " status=-1";
                break;
        }

        msg = globus_common_create_string(
            "event=globus-gridftp-server%s%s.%s%s%s%s%s%s%s\n",
            event_name ? "." : "",
            event_name ? event_name : "",
            startend,
            tmp ? " " : "",
            tmp ? tmp : "",
            message ? " msg=\"" : "",
            message ? message : "",
            message ? "\"" : "",
            status ? status : "");

        globus_logging_write(globus_l_gfs_log_handle, type, msg);

        globus_free(msg);
        if(tmp)
        {
            globus_free(tmp);
        }
        if(message)
        {
            globus_free(message);
        }
    }

    GlobusGFSDebugExit();
}

char *
globus_i_gfs_log_create_transfer_event_msg(
    int                                 stripe_count,
    int                                 stream_count,
    char *                              dest_ip,
    globus_size_t                       blksize,
    globus_size_t                       tcp_bs,
    const char *                        fname,
    globus_off_t                        nbytes,
    char *                              type,
    char *                              username)
{
    char *                              transfermsg;
    GlobusGFSName(globus_i_gfs_log_transfer);
    GlobusGFSDebugEnter();

    transfermsg = globus_common_create_string(
        "localuser=%s "
        "file=%s "
        "tcpbuffer=%ld "
        "blocksize=%ld "
        "bytes=%"GLOBUS_OFF_T_FORMAT" "
        "streams=%d "
        "stripes=%d "
        "remoteIP=%s "
        "type=%s ",
        username,
        fname,
        (long) tcp_bs,
        (long) blksize,
        nbytes,
        stream_count,
        stripe_count,
        dest_ip,
        type);

    GlobusGFSDebugExit();
    return transfermsg;
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
    globus_off_t                        nbytes,
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
    GlobusGFSName(globus_i_gfs_log_transfer);
    GlobusGFSDebugEnter();

    if(globus_l_gfs_transfer_log_file == NULL)
    {
        goto err;
    }

    start_time_time = (time_t)start_gtd_time->tv_sec;
    tmp_tm_time = gmtime(&start_time_time);
    if(tmp_tm_time == NULL)
    {
        goto err;
    }
    start_tm_time = *tmp_tm_time;

    end_time_time = (time_t)end_gtd_time->tv_sec;
    tmp_tm_time = gmtime(&end_time_time);
    if(tmp_tm_time == NULL)
    {
        goto err;
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
        "NBYTES=%"GLOBUS_OFF_T_FORMAT" "
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
        nbytes,
        volume,
        stream_count,
        stripe_count,
        dest_ip,
        type,
        code);

    fwrite(out_buf, 1, strlen(out_buf), globus_l_gfs_transfer_log_file);

    GlobusGFSDebugExit();
    return;

err:
    GlobusGFSDebugExitWithError();
}


void
globus_i_gfs_log_usage_stats(
    struct timeval *                    start_gtd_time,
    struct timeval *                    end_gtd_time,
    int                                 stripe_count,
    int                                 stream_count,
    globus_size_t                       blksize,
    globus_size_t                       tcp_bs,
    globus_off_t                        nbytes,
    int                                 code,
    char *                              type,
    char *                              filename,
    char *                              dataip,
    char *                              clientip,
    char *                              username,
    char *                              userdn,
    char *                              app,
    char *                              appver,
    char *                              schema)
{
    time_t                              start_time_time;
    time_t                              end_time_time;
    struct tm *                         tmp_tm_time;
    struct tm                           start_tm_time;
    struct tm                           end_tm_time;
    char                                start_b[256];
    char                                end_b[256];
    char                                dsi_b[256];
    char                                block_b[256];
    char                                buffer_b[256];
    char                                nbytes_b[256];
    char                                streams_b[256];
    char                                stripes_b[256];
    char                                code_b[256];
    globus_result_t                     result;
    globus_list_t *                     list;
    globus_l_gfs_log_usage_ent_t *      usage_ent;
    char *                              keys[GLOBUS_GFS_MAX_TAGCOUNT];
    char *                              values[GLOBUS_GFS_MAX_TAGCOUNT];
    char *                              ptr;
    char *                              key;
    char *                              value;
    char *                              tmp;    
    int                                 i = 0;
    char *                              save_taglist = NULL;
    GlobusGFSName(globus_i_gfs_log_usage_stats);
    GlobusGFSDebugEnter();


    for(list = globus_l_gfs_log_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (globus_l_gfs_log_usage_ent_t *) globus_list_first(list);

        if(!usage_ent || usage_ent->handle == NULL)
        {
            goto err;
        }
        
        if(save_taglist == NULL || 
            strcmp(save_taglist, usage_ent->taglist) != 0)
        {
            save_taglist = usage_ent->taglist;
            
            ptr = usage_ent->taglist;
            i = 0;
            while(ptr && *ptr)
            {
                switch(*ptr)
                {
                  case GLOBUS_I_GFS_USAGE_START:
                    key = "START";
                    start_time_time = (time_t)start_gtd_time->tv_sec;
                    tmp_tm_time = gmtime(&start_time_time);
                    if(tmp_tm_time == NULL)
                    {
                        goto err;
                    }
                    start_tm_time = *tmp_tm_time;
                    sprintf(start_b, "%04d%02d%02d%02d%02d%02d.%d",
                        start_tm_time.tm_year + 1900,
                        start_tm_time.tm_mon + 1,
                        start_tm_time.tm_mday,
                        start_tm_time.tm_hour,
                        start_tm_time.tm_min,
                        start_tm_time.tm_sec,
                        (int) start_gtd_time->tv_usec);
                    value = start_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_END:
                    key = "END";
                    end_time_time = (time_t)end_gtd_time->tv_sec;
                    tmp_tm_time = gmtime(&end_time_time);
                    if(tmp_tm_time == NULL)
                    {
                        goto err;
                    }
                    end_tm_time = *tmp_tm_time;
                    sprintf(end_b, "%04d%02d%02d%02d%02d%02d.%d",
                        end_tm_time.tm_year + 1900,
                        end_tm_time.tm_mon + 1,
                        end_tm_time.tm_mday,
                        end_tm_time.tm_hour,
                        end_tm_time.tm_min,
                        end_tm_time.tm_sec,
                        (int) end_gtd_time->tv_usec);
                    value = end_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_VER:
                    key = "VER";
                    value = globus_i_gfs_config_string("version_string");
                    break;
    
                  case GLOBUS_I_GFS_USAGE_BUFFER:
                    key = "BUFFER";
                    sprintf(buffer_b, "%ld", (long) tcp_bs);
                    value = buffer_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_BLOCK:
                    key = "BLOCK";
                    sprintf(block_b, "%ld",(long) blksize);
                    value = block_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_NBYTES:
                    key = "NBYTES";
                    sprintf(nbytes_b, "%"GLOBUS_OFF_T_FORMAT, nbytes);
                    value = nbytes_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_STREAMS:
                    key = "STREAMS";
                    sprintf(streams_b, "%d", stream_count);
                    value = streams_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_STRIPES:
                    key = "STRIPES";
                    sprintf(stripes_b, "%d", stripe_count);
                    value = stripes_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_TYPE:
                    key = "TYPE";
                    value = type;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_CODE:
                    key = "CODE";
                    sprintf(code_b, "%d", code);
                    value = code_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_FILE:
                    key = "FILE";
                    value = filename;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_CLIENTIP:
                    key = "CLIENTIP";
                    value = clientip;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_DATAIP:
                    key = "DATAIP";
                    value = dataip;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_USER:
                    key = "USER";
                    value = username;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_USERDN:
                    key = "USERDN";
                    value = userdn;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_CONFID:
                    key = "CONFID";
                    value = globus_i_gfs_config_string("usage_stats_id");
                    break;
    
                  case GLOBUS_I_GFS_USAGE_DSI:
                    key = "DSI";
                    tmp = globus_i_gfs_config_string("load_dsi_module");
                    strncpy(dsi_b, tmp, sizeof(dsi_b));
                    dsi_b[sizeof(dsi_b - 1)] = '\0';
                    if((tmp = strchr(dsi_b, ':')) != NULL)
                    {
                        *tmp = '\0';
                    }
                    value = dsi_b;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_EM:
                    key = "EM";
                    value = globus_i_gfs_config_string("acl");
                    break;
    
                  case GLOBUS_I_GFS_USAGE_SCHEMA:
                    key = "SCHEMA";
                    value = schema;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_APP:
                    key = "APP";
                    value = app;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_APPVER:
                    key = "APPVER";
                    value = appver;
                    break;
    
                  case GLOBUS_I_GFS_USAGE_SESSID:
                    key = "SESSID";
                    value = NULL;
                    break;
    
                  default:
                    key = NULL;
                    value = NULL;
                    break;
                }
                
                if(key != NULL && value != NULL)
                {
                    keys[i] = key;
                    values[i] = value;
                    i++;
                }
                
                ptr++;
            }
        }
        
        result = globus_usage_stats_send_array(
            usage_ent->handle, i, keys, values);
        
    }
    
    GlobusGFSDebugExit();
    return;

err:
    GlobusGFSDebugExitWithError();
}

