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

#include "globus_common.h"
#include "globus_scheduler_event_generator.h"
#include "globus_strptime.h"
#include "version.h"

#include <string.h>

#define SEGPbsEnter() \
        SEGPbsDebug(SEG_PBS_DEBUG_INFO, ("Enter %s\n", _globus_func_name))

#define SEGPbsExit() \
        SEGPbsDebug(SEG_PBS_DEBUG_INFO, ("Exit %s\n", _globus_func_name))

/**
 * Debug levels:
 * If the environment variable SEG_PBS_DEBUG is set to a bitwise or
 * of these values, then a corresponding log message will be generated.
 */
typedef enum
{
    /**
     * Information of function calls and exits
     */
    SEG_PBS_DEBUG_INFO = (1<<0),
    /**
     * Warnings of things which may be bad.
     */
    SEG_PBS_DEBUG_WARN = (1<<1),
    /**
     * Fatal errors.
     */
    SEG_PBS_DEBUG_ERROR = (1<<2),
    /**
     * Details of function executions.
     */
    SEG_PBS_DEBUG_TRACE = (1<<3)
}
globus_l_seg_pbs_debug_level_t;

#ifdef BUILD_DEBUG
#define SEGPbsDebug(level, message) \
    GlobusDebugPrintf(SEG_PBS, level, ("%s", globus_l_seg_pbs_level_string(level))); \
    GlobusDebugPrintf(SEG_PBS, level, message)
#else
#define SEGPbsDebug(level, message) \
    if (level == SEG_PBS_DEBUG_ERROR) \
    { \
        fprintf(stderr, "%s", globus_l_seg_pbs_level_string(level)); \
        globus_l_seg_pbs_debug message; \
    }
static
void
globus_l_seg_pbs_debug(const char * fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
#endif

static
char *
globus_l_seg_pbs_level_string(globus_l_seg_pbs_debug_level_t level)
{
    switch (level)
    {
        case SEG_PBS_DEBUG_INFO:
            return "[INFO] ";
        case SEG_PBS_DEBUG_WARN:
            return "[WARN] ";
        case SEG_PBS_DEBUG_ERROR:
            return "[ERROR] ";
        case SEG_PBS_DEBUG_TRACE:
            return "[TRACE] ";
        default:
            return "";
    }
}
enum
{
    SEG_PBS_ERROR_UNKNOWN = 1,
    SEG_PBS_ERROR_OUT_OF_MEMORY,
    SEG_PBS_ERROR_BAD_PATH,
    SEG_PBS_ERROR_LOG_PERMISSIONS,
    SEG_PBS_ERROR_LOG_NOT_PRESENT
};

/**
 * State of the PBS log file parser.
 */
typedef struct 
{
    /** Path of the current log file being parsed */
    char *                              path;
    /** Timestamp of when to start generating events from */
    struct tm                           start_timestamp;
    /** Stdio file handle of the log file */
    FILE *                              fp;
    /** Buffer of log file data */
    char *                              buffer;
    /** Callback for periodic file polling */
    globus_callback_handle_t            callback;
    /** Length of the buffer */
    size_t                              buffer_length;
    /** Starting offset of valid data in the buffer. */
    size_t                              buffer_point;
    /** Amount of valid data in the buffer */
    size_t                              buffer_valid;
    /**
     * Flag inidicating that this logfile isn't the one corresponding to
     * today, so and EOF on it should require us to close and open a newer
     * one
     */
    globus_bool_t                       old_log;

    /**
     * Path to the directory where the PBS server log files are located
     */
    char *                              log_dir;
} globus_l_pbs_logfile_state_t;

static const time_t                     SECS_IN_DAY = 60*60*24;
static globus_mutex_t                   globus_l_pbs_mutex;
static globus_cond_t                    globus_l_pbs_cond;
static globus_bool_t                    shutdown_called;
static int                              callback_count;


GlobusDebugDefine(SEG_PBS);

static
int
globus_l_pbs_module_activate(void);

static
int
globus_l_pbs_module_deactivate(void);

static
void
globus_l_pbs_read_callback(
    void *                              user_arg);

static
int
globus_l_pbs_parse_events(
    globus_l_pbs_logfile_state_t *      state);

static
int
globus_l_pbs_clean_buffer(
    globus_l_pbs_logfile_state_t *      state);

static
int
globus_l_pbs_increase_buffer(
    globus_l_pbs_logfile_state_t *      state);

static
int
globus_l_pbs_split_into_fields(
    globus_l_pbs_logfile_state_t *      state,
    char ***                            fields,
    size_t *                            nfields);

static
void
globus_l_pbs_normalize_date(
    struct tm *                         tm);

static
int
globus_l_pbs_find_logfile(
    globus_l_pbs_logfile_state_t *      state);

globus_module_descriptor_t
globus_scheduler_event_module_ptr =
{
    "globus_scheduler_event_generator_pbs",
    globus_l_pbs_module_activate,
    globus_l_pbs_module_deactivate,
    NULL,
    NULL,
    &local_version,
    NULL
};

static
int
globus_l_pbs_module_activate(void)
{
    time_t                              timestamp_val;
    globus_l_pbs_logfile_state_t *      logfile_state;
    int                                 rc;
    globus_reltime_t                    delay;
    globus_result_t                     result;
    struct stat                         st;
    GlobusFuncName(globus_l_pbs_module_activate);

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Fatal error activating GLOBUS_COMMON_MODULE\n");
        goto error;
    }
    if (globus_module_getenv("SEG_PBS_DEBUG") == NULL)
    {
        globus_module_setenv("SEG_PBS_DEBUG", "ERROR");
    }
    GlobusDebugInit(SEG_PBS, INFO WARN ERROR TRACE);

    rc = globus_mutex_init(&globus_l_pbs_mutex, NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error initializing mutex\n"));
        goto deactivate_common_error;
    }
    rc = globus_cond_init(&globus_l_pbs_cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error initializing cond\n"));
        goto destroy_mutex_error;
    }
    shutdown_called = GLOBUS_FALSE;
    callback_count = 0;

    logfile_state = globus_libc_calloc(
            1,
            sizeof(globus_l_pbs_logfile_state_t));

    if (logfile_state == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error: out of memory\n"));
        goto destroy_cond_error;
    }

    rc = globus_l_pbs_increase_buffer(logfile_state);
    if (rc != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error: out of memory\n"));
        goto free_logfile_state_error;
    }

    /* Configuration info */
    result = globus_scheduler_event_generator_get_timestamp(&timestamp_val);

    if (result != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error (unable to parse timestamp)\n"));
        goto free_logfile_state_buffer_error;
    }

    if (timestamp_val != 0)
    {
        if (globus_libc_localtime_r(&timestamp_val,
                &logfile_state->start_timestamp) == NULL)
        {
            goto free_logfile_state_buffer_error;
        }
    }
    result = globus_common_get_attribute_from_config_file(
            NULL,
            "etc/globus-pbs.conf",
            "log_path",
            &logfile_state->log_dir);
    if (result != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error: unable to read log_path from "
                "GLOBUS_LOCATION/etc/globus-pbs.conf\n"));

        goto free_logfile_state_buffer_error;
    }

    if ((rc = stat(logfile_state->log_dir, &st)) != 0)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                    ("Fatal error checking log directory: %s\n",
                     strerror(errno)));

        goto free_logfile_state_buffer_error;
    }

    /* Convert timestamp to filename */
    rc = globus_l_pbs_find_logfile(logfile_state);

    if (rc == GLOBUS_SUCCESS)
    {
        logfile_state->fp = fopen(logfile_state->path, "r");

        if (logfile_state->fp == NULL)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                    ("Error opening %s: %s\n",
                     logfile_state->path,
                     strerror(errno)));
            rc = SEG_PBS_ERROR_OUT_OF_MEMORY;

            goto free_logfile_state_path_error;
        }
        GlobusTimeReltimeSet(delay, 0, 0);
    }
    else if(rc == SEG_PBS_ERROR_LOG_NOT_PRESENT)
    {
            SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                    ("Log file %s not (currently) present\n",
                     logfile_state->path));
        GlobusTimeReltimeSet(delay, 1, 0);
    }
    else
    {
        goto free_logfile_state_path_error;
    }

    result = globus_callback_register_oneshot(
            &logfile_state->callback,
            &delay,
            globus_l_pbs_read_callback,
            logfile_state);
    if (result != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                ("Error registering oneshot: %s\n",
                globus_error_print_friendly(globus_error_peek(result))));

        goto free_logfile_state_path_error;
    }
    callback_count++;

    SEGPbsExit();
    return 0;

free_logfile_state_path_error:
    if (logfile_state->path)
    {
        globus_libc_free(logfile_state->path);
    }
    if (logfile_state->log_dir)
    {
        globus_libc_free(logfile_state->log_dir);
    }
free_logfile_state_buffer_error:
    globus_libc_free(logfile_state->buffer);
free_logfile_state_error:
    globus_libc_free(logfile_state);
destroy_cond_error:
    globus_cond_destroy(&globus_l_pbs_cond);
destroy_mutex_error:
    globus_mutex_destroy(&globus_l_pbs_mutex);
deactivate_common_error:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
error:
    return 1;
}
/* globus_l_pbs_module_activate() */

static
int
globus_l_pbs_module_deactivate(void)
{
    GlobusFuncName(globus_l_pbs_module_deactivate);

    SEGPbsEnter();

    globus_mutex_lock(&globus_l_pbs_mutex);
    shutdown_called = GLOBUS_TRUE;

    while (callback_count > 0)
    {
        globus_cond_wait(&globus_l_pbs_cond, &globus_l_pbs_mutex);
    }
    globus_mutex_unlock(&globus_l_pbs_mutex);

    SEGPbsExit();
    GlobusDebugDestroy(SEG_PBS);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}

/**
 * read_cb:
 *  parse_events(buffer)
 *
 *  if (!eof) // do i need to check stat state or will this behave well w/local
 *            // files?
 *      register read (read_cb)
 *  else
 *      if (it's an old logfile)
 *          register_close(old_close_cb)
 *      else
 *          register wakeup (wakeup_cb)
 */
static
void
globus_l_pbs_read_callback(
    void *                              user_arg)
{
    int                                 rc;
    globus_l_pbs_logfile_state_t *      state = user_arg;
    size_t                              max_to_read;
    globus_bool_t                       eof_hit = GLOBUS_FALSE;
    globus_reltime_t                    delay;
    globus_result_t                     result;
    time_t                              now;
    struct tm                           tm_now;
    struct tm *                         tm_result;
    time_t                              now_day;
    time_t                              restart_day;

    GlobusFuncName(globus_l_pbs_read_callback);

    SEGPbsEnter();

    globus_mutex_lock(&globus_l_pbs_mutex);
    if (shutdown_called)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("polling while deactivating"));

        globus_mutex_unlock(&globus_l_pbs_mutex);
        goto error;
    }
    globus_mutex_unlock(&globus_l_pbs_mutex);

    now = time(NULL);

    tm_result = globus_libc_localtime_r(&now, &tm_now);
    if (tm_result == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR, ("error converting time"));

        goto error;
    }
    tm_now.tm_sec = 0;
    tm_now.tm_min = 0;
    tm_now.tm_hour = 0;
    now_day = mktime(&tm_now);

    memcpy(&tm_now, &state->start_timestamp, sizeof(struct tm));
    tm_now.tm_sec = 0;
    tm_now.tm_min = 0;
    tm_now.tm_hour = 0;
    restart_day = mktime(&tm_now);

    if ((tm_result != NULL) && (now_day > restart_day))
    {
        state->old_log = GLOBUS_TRUE;
    }

    if (state->fp != NULL)
    {
        /* Read data */
        max_to_read = state->buffer_length - state->buffer_valid
                - state->buffer_point;

        SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                ("reading a maximum of %u bytes\n", max_to_read));

        rc = fread(state->buffer + state->buffer_point + state->buffer_valid,
                1, max_to_read, state->fp);
        
        SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                ("read %d bytes\n", rc));

        if (rc < max_to_read)
        {
            if (feof(state->fp))
            {
                SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("hit eof\n"));
                eof_hit = GLOBUS_TRUE;
                clearerr(state->fp);
            }
            else
            {
                /* XXX: Read error */
            }
        }

        state->buffer_valid += rc;

        /* Parse data */
        rc = globus_l_pbs_parse_events(state);

        rc = globus_l_pbs_clean_buffer(state);
    }

    /* If end of log, close this logfile and look for a new one. Also, if
     * the current day's log doesn't exist yet, check for it
     */
    if ((eof_hit && state->old_log) || state->fp == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("got Log closed msg\n"));

        if (state->fp)
        {
            fclose(state->fp);
            state->fp = NULL;

            state->start_timestamp.tm_mday++;
            state->start_timestamp.tm_hour = 0;
            state->start_timestamp.tm_min = 0;
            state->start_timestamp.tm_sec = 0;
            globus_l_pbs_normalize_date(&state->start_timestamp);
        }

        rc = globus_l_pbs_find_logfile(state);

        if (rc == GLOBUS_SUCCESS)
        {
            /* Opening a new logfile, run w/out delay */
            state->fp = fopen(state->path, "r");
            if (state->fp == NULL)
            {
                goto error;
            }
            eof_hit = GLOBUS_FALSE;

            GlobusTimeReltimeSet(delay, 0, 0);
        }
        else if (rc == SEG_PBS_ERROR_LOG_NOT_PRESENT)
        {
            /* Current day's logfile not present, wait a bit longer for
             * it to show up
             */
            GlobusTimeReltimeSet(delay, 30, 0);
            eof_hit = GLOBUS_TRUE;
        }
        else
        {
            goto error;
        }
    }
    else if(eof_hit)
    {
        /* eof on current logfile, wait for new data */
        GlobusTimeReltimeSet(delay, 2, 0);
    }
    else
    {
        /* still data available in current file, hurry up! */
        GlobusTimeReltimeSet(delay, 0, 0);
    }

    result = globus_callback_register_oneshot(
            &state->callback,
            &delay,
            globus_l_pbs_read_callback,
            state);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    SEGPbsExit();
    return;
error:
    globus_mutex_lock(&globus_l_pbs_mutex);
    if (shutdown_called)
    {
        callback_count--;

        if (callback_count == 0)
        {
            globus_cond_signal(&globus_l_pbs_cond);
        }
    }
    globus_mutex_unlock(&globus_l_pbs_mutex);

    SEGPbsExit();
    return;
}
/* globus_l_pbs_read_callback() */

/**
 * Determine the next available PBS log file name from the 
 * timestamp stored in the logfile state structure.
 * 
 * @param state
 *     PBS log state structure. The path field of the structure may be
 *     modified by this function.
 *
 * @retval GLOBUS_SUCCESS
 *     Name of an log file name has been found and the file exists.
 * @retval 1
 *     Something bad occurred.
 */
static
int
globus_l_pbs_find_logfile(
    globus_l_pbs_logfile_state_t *      state)
{
    struct tm *                         tm_result;
    struct tm                           tm_val;
    struct tm                           tm_now;
    globus_bool_t                       user_timestamp = GLOBUS_TRUE;
    time_t                              now;
    struct stat                         s;
    int                                 rc;
    GlobusFuncName(globus_l_pbs_find_logfile);

    SEGPbsEnter();

    if (state->path == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("allocating path\n"));
        state->path = malloc(strlen(state->log_dir) + 10);

        if (state->path == NULL)
        {
            rc = SEG_PBS_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    now = time(NULL);

    tm_result = globus_libc_localtime_r(&now, &tm_now);
    if (tm_result == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_WARN, ("localtime_r failed\n"));
        rc = SEG_PBS_ERROR_OUT_OF_MEMORY;

        goto error;
    }
    else
    {
        /* Get the first log message of the day */
        tm_now.tm_sec = 0;
        tm_now.tm_min = 0;
        tm_now.tm_hour = 0;
    }

    if (state->start_timestamp.tm_sec == 0 &&
        state->start_timestamp.tm_min == 0 &&
        state->start_timestamp.tm_hour == 0 &&
        state->start_timestamp.tm_mday == 0 &&
        state->start_timestamp.tm_mon == 0 &&
        state->start_timestamp.tm_year == 0)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                ("no timestamp set, using current time\n"));
        memcpy(&state->start_timestamp, &tm_now, sizeof(struct tm));
        user_timestamp = GLOBUS_FALSE;
    }

    memcpy(&tm_val, &state->start_timestamp, sizeof(struct tm));

    tm_result = &tm_val;

    do
    {
        if (tm_result == NULL)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                ("couldn't get tm from timestmap\n"));

            rc = SEG_PBS_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        if (tm_val.tm_year < tm_now.tm_year ||
            (tm_val.tm_year == tm_now.tm_year &&
             tm_val.tm_mon < tm_now.tm_mon) ||
            (tm_val.tm_year == tm_now.tm_year &&
             tm_val.tm_mon == tm_now.tm_mon &&
             tm_val.tm_mday < tm_now.tm_mday))
        {
            state->old_log = GLOBUS_TRUE;
        }
        else
        {
            state->old_log = GLOBUS_FALSE;
        }

        rc = sprintf(state->path,
                "%s/%4d%02d%02d",
                state->log_dir,
                tm_val.tm_year+1900,
                tm_val.tm_mon+1,
                tm_val.tm_mday);

        if (rc < 0)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                ("couldn't format date to string\n"));
            rc = SEG_PBS_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = stat(state->path, &s);

        if (rc < 0)
        {
            switch (errno)
            {
                case ENOENT:
                    /* Doesn't exist, advance to the next day's log
                     * for next try if we're not looking to the future.
                     */
                    SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                        ("file %s doesn't exist\n", state->path));

                    /* Increment day by 1, then normalize to be a proper
                     * struct tm without having tm_mday exceed what is valid
                     * for the month.
                     */
                    tm_val.tm_mday++;

                    globus_l_pbs_normalize_date(&tm_val);

                    if (tm_val.tm_year > tm_now.tm_year ||
                        (tm_val.tm_year == tm_now.tm_year &&
                         tm_val.tm_mon > tm_now.tm_mon) ||
                        (tm_val.tm_year == tm_now.tm_year &&
                         tm_val.tm_mon == tm_now.tm_mon &&
                         tm_val.tm_mday > tm_now.tm_mday))
                    {
                        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                            ("looking for file in the future!\n"));
                        rc = SEG_PBS_ERROR_LOG_NOT_PRESENT;

                        goto error;
                    }

                    /* Starting new log, get all messages in that file */
                    tm_val.tm_sec = 0;
                    tm_val.tm_min = 0;
                    tm_val.tm_hour = 0;

                    memcpy(&state->start_timestamp,
                            &tm_val,
                            sizeof(struct tm));

                    break;

                case EACCES:
                    SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                        ("permissions needed to access logfile %s\n",
                        state->path));
                    /* Permission problem (fatal) */
                    rc = SEG_PBS_ERROR_LOG_PERMISSIONS;
                    goto error;

                case ENOTDIR:
                case ELOOP:
                case ENAMETOOLONG:
                    /* broken path (fatal) */
                    SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                        ("broken path to logfile %s\n",
                        state->path));
                    rc = SEG_PBS_ERROR_BAD_PATH;
                    goto error;

                case EFAULT:
                    SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                        ("bad pointer\n"));
                    globus_assert(errno != EFAULT);

                case EINTR:
                case ENOMEM: /* low kernel mem */
                    /* try again later */
                    SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                        ("going to have to retry stat()\n"));
                    continue;

                default:
                    SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                        ("unexpected errno\n"));
                    rc = SEG_PBS_ERROR_UNKNOWN;
                    goto error;
            }
        }
    }
    while ((rc != 0) && user_timestamp);

    if (rc != 0)
    {
        goto error;
    }

    SEGPbsExit();
    return 0;

error:
    SEGPbsExit();
    return rc;
}
/* globus_l_pbs_find_logfile() */

/**
 * Move any data in the state buffer to the beginning, to enable reusing 
 * buffer space which has already been parsed.
 */
static
int
globus_l_pbs_clean_buffer(
    globus_l_pbs_logfile_state_t *      state)
{
    GlobusFuncName(globus_l_pbs_clean_buffer);

    SEGPbsEnter();

    /* move data to head of buffer */
    if (state->buffer != NULL)
    {
        if(state->buffer_point > 0)
        {
            if (state->buffer_valid > 0)
            {
                memmove(state->buffer,
                        state->buffer+state->buffer_point,
                        state->buffer_valid);
            }
            state->buffer_point = 0;
        }
    }
    SEGPbsExit();
    return 0;
}
/* globus_l_pbs_clean_buffer() */

/**
 * Reduce unused space in the log buffer, increasing the size of the buffer
 * if it is full.
 *
 * @param state
 *     PBS log state structure. The buffer-related fields of the structure
 *     may be modified by this function.
 */
static
int
globus_l_pbs_increase_buffer(
    globus_l_pbs_logfile_state_t *      state)
{
    char *                              save = state->buffer;
    const size_t                        GLOBUS_PBS_READ_BUFFER_SIZE = 4096;
    int                                 rc;
    GlobusFuncName(globus_l_pbs_increase_buffer);

    SEGPbsEnter();
    /* If the buffer is full, resize */
    if (state->buffer_valid == state->buffer_length)
    {
        state->buffer = globus_libc_realloc(state->buffer,
                    state->buffer_length + GLOBUS_PBS_READ_BUFFER_SIZE);
        if (state->buffer == NULL)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_ERROR, ("realloc() failed: %s\n",
                        strerror(errno)));

            rc = SEG_PBS_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    state->buffer_length += GLOBUS_PBS_READ_BUFFER_SIZE;

    SEGPbsExit();
    return 0;

error:
    SEGPbsExit();
    state->buffer = save;
    return rc;
}
/* globus_l_pbs_increase_buffer() */

static
int
globus_l_pbs_parse_events(
    globus_l_pbs_logfile_state_t *      state)
{
    char *                              eol;
    char *                              rp;
    struct tm                           tm;
    time_t                              stamp;
    char **                             fields = NULL;
    size_t                              nfields;
    time_t                              when;
    int                                 evttype;
    int                                 rc;
    int                                 exit_status;
    GlobusFuncName(globus_l_pbs_parse_events);

    SEGPbsEnter();

    while ((eol = memchr(state->buffer + state->buffer_point,
                '\n',
                state->buffer_valid)) != NULL)
    {
        *eol = '\0';

        SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                ("parsing line %s\n", state->buffer + state->buffer_point));

        rc = globus_l_pbs_split_into_fields(state, &fields, &nfields);

        if (rc != GLOBUS_SUCCESS)
        {
            goto free_fields;
        }

        if (nfields < 3)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                    ("too few fields, freeing and getting next line\n"));
            goto free_fields;
        }

        rp = globus_strptime(fields[0], 
                "%m/%d/%Y %H:%M:%S",
                &tm);
        if (rp == NULL || (*rp) != '\0')
        {
            goto free_fields;
        }
        stamp = mktime(&tm);
        if (stamp == -1)
        {
            goto free_fields;
        }

        rc = sscanf(fields[1], "%04x", &evttype);

        if (rc < 1)
        {
            goto free_fields;
        }
        rc = 0;

        when = mktime(&state->start_timestamp);

        if (stamp < when)
        {
            /* Skip messages which are before our start timestamp */
            goto free_fields;
        }

        switch (evttype)
        {
        case 0x0002: /* Batch System/Server Events */
            if (nfields < 6)
            {
                rc = 1;
                break;
            }
            if (strstr(fields[5], "Log closed") == fields[5])
            {
            }
            break;

        case 0x0010: /* Job Resource Usage */
        case 0x0008: /* Job Events */
            if (nfields < 6)
            {
                rc = 1;
                break;
            }
            if (strstr(fields[5], "Job Queued") == fields[5])
            {
                SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                        ("job %s pending\n", fields[4]));
                rc = globus_scheduler_event_pending(stamp, fields[4]);
            }
            else if (strstr(fields[5], "Job Run") == fields[5])
            {
                SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                        ("job %s active\n", fields[4]));
                rc = globus_scheduler_event_active(stamp, fields[4]);
            }
            else if (strstr(fields[5], "Exit_status") == fields[5])
            {
                rc = sscanf(fields[5], "Exit_status=%d", &exit_status);

                if (rc < 0)
                {
                    break;
                }
                SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                        ("job %s done\n", fields[4]));
                rc = globus_scheduler_event_done(stamp,
                        fields[4],
                        exit_status);
            }
            else if (strstr(fields[5], "Job deleted") == fields[5])
            {
                SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                    ("job %s failed\n", fields[4]));
                rc = globus_scheduler_event_failed(stamp, fields[4], 0);
            }
            break;
        }

free_fields:
        if (fields != NULL)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_INFO,
                    ("freeing fields\n"));
            globus_libc_free(fields);
            fields = NULL;
        }

        state->buffer_valid -= eol + 1 - state->buffer - state->buffer_point;
        state->buffer_point = eol + 1 - state->buffer;
    }

    SEGPbsExit();
    return 0;
}
/* globus_l_pbs_parse_events() */

/**
 * Replaces instances of ';' (the PBS log field separator with NULL. Allocates
 * an array of pointers into the state buffer at the beginning of each field.
 *
 * @param state
 *     Log state structure. The string pointed to by
 *     state-\>buffer + state-\>buffer_point is modified 
 * @param fields
 *     Modified to point to a newly allocated array of char * pointers which
 *     point to the start of each field within the state buffer block.
 * @param nfields
 *     Modified value pointed to by this will contain the number of fields in
 *     the @a fields array after completion.
 */
static
int
globus_l_pbs_split_into_fields(
    globus_l_pbs_logfile_state_t *      state,
    char ***                            fields,
    size_t *                            nfields)
{
    size_t                              i = 0;
    size_t                              cnt = 1;
    char *                              tmp;
    int                                 rc;
    GlobusFuncName(globus_l_pbs_split_into_fields);

    SEGPbsEnter();

    *fields = NULL;
    *nfields = 0;

    tmp = state->buffer + state->buffer_point;

    SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("splitting %s\n", tmp));

    while (*tmp != '\0')
    {
        if (*tmp == ';')
        {
            cnt++;
        }
        tmp++;
    }
    SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("%u fields\n", cnt));

    *fields = globus_libc_calloc(cnt, sizeof(char **));

    if (*fields == NULL)
    {
        rc = SEG_PBS_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    *nfields = cnt;

    tmp = state->buffer + state->buffer_point;

    (*fields)[i++] = tmp;

    while (*tmp != '\0' && i < cnt)
    {
        if (*tmp == ';')
        {
            (*fields)[i++] = tmp+1;
            *tmp = '\0';
        }
        tmp++;
    }

#   if BUILD_DEBUG
    {
        for (i = 0; i < cnt; i++)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_TRACE, ("field[%u]=%s\n",
                        i, (*fields)[i]));
        }
    }
#   endif

    SEGPbsExit();

    return 0;

error:
    SEGPbsExit();
    return rc;
}
/* globus_l_pbs_split_into_fields() */

/* Leap year is year divisible by 4, unless divisibly by 100 and not by 400 */
#define IS_LEAP_YEAR(Y) \
     (!(Y % 4)) && ((Y % 100) || !(Y % 400))
static
void
globus_l_pbs_normalize_date(
    struct tm *                         tm)
{
    int                                 test_year;
    int                                 overflow_days = 0;
    static int                          mday_max[] =
    {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 
    };
    static int                          mday_leap_max[] =
    {
        31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 
    };

    do
    {
        if (overflow_days > 0)
        {
            tm->tm_mday = overflow_days;
            tm->tm_mon++;
        }

        /* skipped to the next year */
        if (tm->tm_mon == 12)
        {
            tm->tm_year++;
            tm->tm_mon = 0;
        }

        test_year = tm->tm_year + 1900;
        overflow_days = IS_LEAP_YEAR(test_year) 
                ? tm->tm_mday - mday_leap_max[tm->tm_mon]
                : tm->tm_mday - mday_max[tm->tm_mon];
    } while (overflow_days > 0);
}

