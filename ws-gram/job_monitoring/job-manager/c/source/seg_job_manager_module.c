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
#include "globus_gram_protocol_constants.h"
#include "version.h"

#include <string.h>

/**
 * @mainpage Job Manager SEG Module
 */
#define SEG_JOB_MANAGER_DEBUG(level, message) \
    GlobusDebugPrintf(SEG_JOB_MANAGER, level, message)

#define JOB_MANAGER_SEG_SCHEDULER "JOB_MANAGER_SEG_SCHEDULER"

/**
 * Debug levels:
 * If the environment variable SEG_JOB_MANAGER_DEBUG is set to a bitwise or
 * of these values, then a corresponding log message will be generated.
 */
typedef enum
{
    /**
     * Information of function calls and exits
     */
    SEG_JOB_MANAGER_DEBUG_INFO = (1<<0),
    /**
     * Warnings of things which may be bad.
     */
    SEG_JOB_MANAGER_DEBUG_WARN = (1<<1),
    /**
     * Fatal errors.
     */
    SEG_JOB_MANAGER_DEBUG_ERROR = (1<<2),
    /**
     * Details of function executions.
     */
    SEG_JOB_MANAGER_DEBUG_TRACE = (1<<3)
}
globus_l_seg_job_manager_debug_level_t;

enum
{
    SEG_JOB_MANAGER_ERROR_UNKNOWN = 1,
    SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY,
    SEG_JOB_MANAGER_ERROR_BAD_PATH,
    SEG_JOB_MANAGER_ERROR_LOG_PERMISSIONS,
    SEG_JOB_MANAGER_ERROR_LOG_NOT_PRESENT
};

/**
 * State of the JOB_MANAGER log file parser.
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
     * Flag indicating a Log close event indicating that the current
     * log was found in the log
     */
    globus_bool_t                       end_of_log;
    /**
     * Flag inidicating that this logfile isn't the one corresponding to
     * today, so and EOF on it should require us to close and open a newer
     * one
     */
    globus_bool_t                       old_log;

    /**
     * Path to the directory where the JOB_MANAGER server log files are located
     */
    char *                              log_dir;
} globus_l_job_manager_logfile_state_t;

static const time_t                     SECS_IN_DAY = 60*60*24;
static globus_mutex_t                   globus_l_job_manager_mutex;
static globus_cond_t                    globus_l_job_manager_cond;
static globus_bool_t                    shutdown_called;
static int                              callback_count;


GlobusDebugDefine(SEG_JOB_MANAGER);

static
int
globus_l_job_manager_module_activate(void);

static
int
globus_l_job_manager_module_deactivate(void);

static
void
globus_l_job_manager_read_callback(
    void *                              user_arg);

static
int
globus_l_job_manager_parse_events(
    globus_l_job_manager_logfile_state_t *      state);

static
int
globus_l_job_manager_clean_buffer(
    globus_l_job_manager_logfile_state_t *      state);

static
int
globus_l_job_manager_increase_buffer(
    globus_l_job_manager_logfile_state_t *      state);

static
void
globus_l_job_manager_normalize_date(
    struct tm *                         tm);

static
int
globus_l_job_manager_find_logfile(
    globus_l_job_manager_logfile_state_t *      state);

static
time_t
seg_l_timegm(
    const struct tm *                   tm);

GlobusExtensionDefineModule(globus_seg_job_manager) =
{
    "globus_seg_job_manager",
    globus_l_job_manager_module_activate,
    globus_l_job_manager_module_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
globus_l_job_manager_module_activate(void)
{
    time_t                              timestamp_val;
    globus_l_job_manager_logfile_state_t *      
                                        logfile_state;
    int                                 rc;
    globus_reltime_t                    delay;
    globus_result_t                     result;
    char *                              scheduler;
    char                                log_path_key[64];

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }
    rc = globus_mutex_init(&globus_l_job_manager_mutex, NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        goto deactivate_common_error;
    }
    rc = globus_cond_init(&globus_l_job_manager_cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        goto destroy_mutex_error;
    }
    shutdown_called = GLOBUS_FALSE;
    callback_count = 0;

    GlobusDebugInit(
        SEG_JOB_MANAGER,
        SEG_JOB_MANAGER_DEBUG_INFO
        SEG_JOB_MANAGER_DEBUG_WARN
        SEG_JOB_MANAGER_DEBUG_ERROR
        SEG_JOB_MANAGER_DEBUG_TRACE);

    logfile_state = globus_libc_calloc(
            1,
            sizeof(globus_l_job_manager_logfile_state_t));

    if (logfile_state == NULL)
    {
        goto destroy_cond_error;
        return 1;
    }

    rc = globus_l_job_manager_increase_buffer(logfile_state);
    if (rc != GLOBUS_SUCCESS)
    {
        goto free_logfile_state_error;
    }

    /* Configuration info */
    result = globus_scheduler_event_generator_get_timestamp(&timestamp_val);

    if (result != GLOBUS_SUCCESS)
    {
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
    scheduler = globus_libc_getenv(JOB_MANAGER_SEG_SCHEDULER);
    if (scheduler == NULL)
    {
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
            ("Error: %s not set\n", JOB_MANAGER_SEG_SCHEDULER));

        result = GLOBUS_FAILURE;
        goto free_logfile_state_buffer_error;
    }

    sprintf(log_path_key, "%s_log_path", scheduler);

    result = globus_common_get_attribute_from_config_file(
            NULL,
            "etc/globus-job-manager-seg.conf",
            log_path_key,
            &logfile_state->log_dir);
    if (result != GLOBUS_SUCCESS)
    {
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
                ("unable to find log file in configuration\n"));
        goto free_logfile_state_buffer_error;
    }
    /* Convert timestamp to filename */
    rc = globus_l_job_manager_find_logfile(logfile_state);

    if (rc == GLOBUS_SUCCESS)
    {
        logfile_state->fp = fopen(logfile_state->path, "r");

        if (logfile_state->fp == NULL)
        {
            rc = SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY;

            goto free_logfile_state_path_error;
        }
        GlobusTimeReltimeSet(delay, 0, 0);
    }
    else if(rc == SEG_JOB_MANAGER_ERROR_LOG_NOT_PRESENT)
    {
        GlobusTimeReltimeSet(delay, 1, 0);
    }
    else
    {
        goto free_logfile_state_path_error;
    }

    result = globus_callback_register_oneshot(
            &logfile_state->callback,
            &delay,
            globus_l_job_manager_read_callback,
            logfile_state);
    if (result != GLOBUS_SUCCESS)
    {
        goto free_logfile_state_path_error;
    }
    callback_count++;

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
    globus_cond_destroy(&globus_l_job_manager_cond);
destroy_mutex_error:
    globus_mutex_destroy(&globus_l_job_manager_mutex);
deactivate_common_error:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
error:
    return 1;
}
/* globus_l_job_manager_module_activate() */

static
int
globus_l_job_manager_module_deactivate(void)
{
    globus_mutex_lock(&globus_l_job_manager_mutex);
    shutdown_called = GLOBUS_TRUE;

    while (callback_count > 0)
    {
        globus_cond_wait(&globus_l_job_manager_cond, &globus_l_job_manager_mutex);
    }
    globus_mutex_unlock(&globus_l_job_manager_mutex);

    GlobusDebugDestroy(SEG_JOB_MANAGER);

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
globus_l_job_manager_read_callback(
    void *                              user_arg)
{
    int                                 rc;
    globus_l_job_manager_logfile_state_t *      state = user_arg;
    size_t                              max_to_read;
    globus_bool_t                       eof_hit = GLOBUS_FALSE;
    globus_reltime_t                    delay;
    globus_result_t                     result;

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_read_callback()\n"));

    globus_mutex_lock(&globus_l_job_manager_mutex);
    if (shutdown_called)
    {
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
                ("polling while deactivating"));

        globus_mutex_unlock(&globus_l_job_manager_mutex);
        goto error;
    }
    globus_mutex_unlock(&globus_l_job_manager_mutex);

    if (state->fp != NULL)
    {
        /* Read data */
        max_to_read = state->buffer_length - state->buffer_valid
                - state->buffer_point;

        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                ("reading a maximum of %u bytes\n", max_to_read));

        rc = fread(state->buffer + state->buffer_point + state->buffer_valid,
                1, max_to_read, state->fp);
        
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                ("read %d bytes\n", rc));

        if (rc < max_to_read)
        {
            if (feof(state->fp))
            {
                SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                        ("hit eof\n"));
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
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                ("parsing events\n"));
        rc = globus_l_job_manager_parse_events(state);

        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                ("cleaning buffer\n"));
        rc = globus_l_job_manager_clean_buffer(state);
    }

    /* If end of log, close this logfile and look for a new one. Also, if
     * the current day's log doesn't exist yet, check for it
     */
    if (state->end_of_log || (eof_hit && state->old_log) || state->fp == NULL)
    {
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                ("got Log closed msg\n"));

        if (state->fp)
        {
            fclose(state->fp);
            state->fp = NULL;
            state->start_timestamp.tm_mday++;
            state->start_timestamp.tm_hour = 0;
            state->start_timestamp.tm_min = 0;
            state->start_timestamp.tm_sec = 0;
        }

        rc = globus_l_job_manager_find_logfile(state);

        if (rc == GLOBUS_SUCCESS)
        {
            /* Opening a new logfile, run w/out delay */
            state->fp = fopen(state->path, "r");
            if (state->fp == NULL)
            {
                goto error;
            }
            state->end_of_log = GLOBUS_FALSE;
            eof_hit = GLOBUS_FALSE;

            GlobusTimeReltimeSet(delay, 0, 0);
        }
        else if (rc == SEG_JOB_MANAGER_ERROR_LOG_NOT_PRESENT)
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
            globus_l_job_manager_read_callback,
            state);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_read_callback() exited with/success\n"));
    return;
error:
    globus_mutex_lock(&globus_l_job_manager_mutex);
    if (shutdown_called)
    {
        callback_count--;

        if (callback_count == 0)
        {
            globus_cond_signal(&globus_l_job_manager_cond);
        }
    }
    globus_mutex_unlock(&globus_l_job_manager_mutex);

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
            ("globus_l_job_manager_read_callback() exited with/error\n"));
    return;
}
/* globus_l_job_manager_read_callback() */

/**
 * Determine the next available JOB_MANAGER log file name from the 
 * timestamp stored in the logfile state structure.
 * 
 * @param state
 *     JOB_MANAGER log state structure. The path field of the structure may be
 *     modified by this function.
 *
 * @retval GLOBUS_SUCCESS
 *     Name of an log file name has been found and the file exists.
 * @retval 1
 *     Something bad occurred.
 */
static
int
globus_l_job_manager_find_logfile(
    globus_l_job_manager_logfile_state_t *      state)
{
    struct tm *                         tm_result;
    struct tm                           tm_val;
    struct tm                           tm_now;
    globus_bool_t                       user_timestamp = GLOBUS_TRUE;
    time_t                              now;
    struct stat                         s;
    int                                 rc;

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_find_logfile()\n"));

    if (state->path == NULL)
    {
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
                ("allocating path\n"));
        state->path = malloc(strlen(state->log_dir) + 10);

        if (state->path == NULL)
        {
            rc = SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    now = time(NULL);

    tm_result = globus_libc_localtime_r(&now, &tm_now);
    if (tm_result == NULL)
    {
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
                ("localtime_r failed\n"));
        rc = SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY;

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
        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_TRACE,
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
            SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
                ("couldn't get tm from timestmap\n"));

            rc = SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY;
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
            SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
                ("couldn't format date to string\n"));
            rc = SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY;
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
                    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
                        ("file %s doesn't exist\n", state->path));

                    /* Increment day by 1, then normalize to be a proper
                     * struct tm without having tm_mday exceed what is valid
                     * for the month.
                     */
                    tm_val.tm_mday++;

                    globus_l_job_manager_normalize_date(&tm_val);

                    if (tm_val.tm_year > tm_now.tm_year ||
                        (tm_val.tm_year == tm_now.tm_year &&
                         tm_val.tm_mon > tm_now.tm_mon) ||
                        (tm_val.tm_year == tm_now.tm_year &&
                         tm_val.tm_mon == tm_now.tm_mon &&
                         tm_val.tm_mday > tm_now.tm_mday))
                    {
                        SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
                            ("looking for file in the future!\n"));
                        rc = SEG_JOB_MANAGER_ERROR_LOG_NOT_PRESENT;
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
                    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
                        ("permissions needed to access logfile %s\n",
                        state->path));
                    /* Permission problem (fatal) */
                    rc = SEG_JOB_MANAGER_ERROR_LOG_PERMISSIONS;
                    goto error;

                case ENOTDIR:
                case ELOOP:
                case ENAMETOOLONG:
                    /* broken path (fatal) */
                    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
                        ("broken path to logfile %s\n",
                        state->path));
                    rc = SEG_JOB_MANAGER_ERROR_BAD_PATH;
                    goto error;

                case EFAULT:
                    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
                        ("bad pointer\n"));
                    globus_assert(errno != EFAULT);

                case EINTR:
                case ENOMEM: /* low kernel mem */
                    /* try again later */
                    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
                        ("going to have to retry stat()\n"));
                    continue;

                default:
                    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR,
                        ("unexpected errno\n"));
                    rc = SEG_JOB_MANAGER_ERROR_UNKNOWN;
                    goto error;
            }
        }
    }
    while ((rc != 0) && user_timestamp);

    if (rc != 0)
    {
        goto error;
    }

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_find_logfile() exits w/out error\n"));
    return 0;

error:
    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
            ("globus_l_job_manager_find_logfile() exits w/error\n"));
    return rc;
}
/* globus_l_job_manager_find_logfile() */

/**
 * Move any data in the state buffer to the beginning, to enable reusing 
 * buffer space which has already been parsed.
 */
static
int
globus_l_job_manager_clean_buffer(
    globus_l_job_manager_logfile_state_t *      state)
{
    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_clean_buffer() called\n"));

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
    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_clean_buffer() exits\n"));
    return 0;
}
/* globus_l_job_manager_clean_buffer() */

/**
 * Reduce unused space in the log buffer, increasing the size of the buffer
 * if it is full.
 *
 * @param state
 *     JOB_MANAGER log state structure. The buffer-related fields of the structure
 *     may be modified by this function.
 */
static
int
globus_l_job_manager_increase_buffer(
    globus_l_job_manager_logfile_state_t *      state)
{
    char *                              save = state->buffer;
    const size_t                        GLOBUS_JOB_MANAGER_READ_BUFFER_SIZE = 4096;
    int                                 rc;

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_increase_buffer() called\n"));
    /* If the buffer is full, resize */
    if (state->buffer_valid == state->buffer_length)
    {
        state->buffer = globus_libc_realloc(state->buffer,
                    state->buffer_length + GLOBUS_JOB_MANAGER_READ_BUFFER_SIZE);
        if (state->buffer == NULL)
        {
            SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_ERROR, ("realloc() failed\n"));

            rc = SEG_JOB_MANAGER_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    state->buffer_length += GLOBUS_JOB_MANAGER_READ_BUFFER_SIZE;

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_increase_buffer() exits w/success\n"));
    return 0;

error:
    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_WARN,
            ("globus_l_job_manager_increase_buffer() exits w/failure\n"));
    state->buffer = save;
    return rc;
}
/* globus_l_job_manager_increase_buffer() */

static
int
globus_l_job_manager_parse_events(
    globus_l_job_manager_logfile_state_t *      state)
{
    char *                              eol;
    int                                 rc;
    char *                              p;
    int                                 protocol_msg_type;
    time_t                              stamp;
    char *                              jobid;
    int                                 job_state;
    int                                 exit_code;
    int                                 jobid_start;
    int                                 jobid_end;
    time_t                              start_timestamp;
    enum {
        EXIT_CODE_UNASSIGNED = -1492

    };

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_parse_events() called\n"));

    state->buffer[state->buffer_point + state->buffer_valid] = '\0';

    p = state->buffer + state->buffer_point;

    while ((eol = strchr(p, '\n')) != NULL)
    {
        *(eol) = '\0';

        exit_code = EXIT_CODE_UNASSIGNED;

        rc = sscanf(p, "%d;%ld;%n%*[^;]%n;%d;%d", 
            &protocol_msg_type,
            &stamp,
            &jobid_start,
            &jobid_end,
            &job_state,
            &exit_code);

        if (rc < 4 || exit_code == EXIT_CODE_UNASSIGNED)
        {
            goto bad_line;
        }

        jobid = p + jobid_start;
        *(p + jobid_end) = '\0';

        if (protocol_msg_type != 1)
        {
            goto bad_line;
        }

        start_timestamp = seg_l_timegm(&state->start_timestamp);

        if (stamp < start_timestamp)
        {
            goto bad_line;
        }

        switch(job_state)
        {
        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
            globus_scheduler_event_pending(stamp, jobid);
            break;

        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
            globus_scheduler_event_active(stamp, jobid);
            break;

        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
            globus_scheduler_event_done(stamp, jobid, exit_code);
            break;

        case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
            globus_scheduler_event_failed(stamp, jobid, exit_code);
            break;

        default:
            goto bad_line;
        }
bad_line:
        p = eol+1;
    }

    state->buffer_valid -= p - (state->buffer + state->buffer_point);
    state->buffer_point = p - state->buffer;

    SEG_JOB_MANAGER_DEBUG(SEG_JOB_MANAGER_DEBUG_INFO,
            ("globus_l_job_manager_parse_events() exits\n"));
    return 0;
}
/* globus_l_job_manager_parse_events() */

/* Leap year is year divisible by 4, unless divisibly by 100 and not by 400 */
#define IS_LEAP_YEAR(Y) \
     (!(Y % 4)) && ((Y % 100) || !(Y % 400))
static
void
globus_l_job_manager_normalize_date(
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

/**
 * Convert a struct tm to a time_t without accounting for the local timezone
 * or modifying the struct tm contents.
 *
 * This may get a little kooky when the TZ shift occurs near the DST change.
 */
static
time_t
seg_l_timegm(
    const struct tm *                   tm)
{
    struct tm                           tmp;
    struct tm                           local_tm;
    time_t                              local_time;
    time_t                              shifted_time;

    memcpy(&tmp, tm, sizeof(struct tm));

    /* convert the tm to time_t in the local timezone */
    local_time = mktime(&tmp);

    /* create a new tm with this time (but without the TZ-related parts of the
     * tm set) */
    globus_libc_gmtime_r(&local_time, &local_tm);

    /* convert the time to local time again, causing it to be shifted by
     * time zone twice
     */
    shifted_time = mktime(&local_tm);

    /*
     * The difference between shifted_time and local_time is the TZ correction.
     */
    return local_time + (local_time - shifted_time);
}
/* wsrl_l_timegm() */

