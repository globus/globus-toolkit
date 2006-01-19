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
#include "globus_gram_protocol.h"
#include "version.h"

#include <time.h>
#include <string.h>

#define SEG_FORK_DEBUG(level, message) \
    GlobusDebugPrintf(SEG_FORK, level, message)

/**
 * Debug levels:
 * If the environment variable SEG_FORK_DEBUG is set to a bitwise or
 * of these values, then a corresponding log message will be generated.
 */
typedef enum
{
    /**
     * Information of function calls and exits
     */
    SEG_FORK_DEBUG_INFO = (1<<0),
    /**
     * Warnings of things which may be bad.
     */
    SEG_FORK_DEBUG_WARN = (1<<1),
    /**
     * Fatal errors.
     */
    SEG_FORK_DEBUG_ERROR = (1<<2),
    /**
     * Details of function executions.
     */
    SEG_FORK_DEBUG_TRACE = (1<<3)
}
globus_l_seg_fork_debug_level_t;

enum
{
    SEG_FORK_ERROR_UNKNOWN = 1,
    SEG_FORK_ERROR_OUT_OF_MEMORY,
    SEG_FORK_ERROR_BAD_PATH,
    SEG_FORK_ERROR_LOG_PERMISSIONS,
    SEG_FORK_ERROR_LOG_NOT_PRESENT,
    SEG_FORK_ERROR_PARSE

};

/**
 * State of the FORK log file parser.
 */
typedef struct 
{
    /** Path of the log file being parsed */
    char *                              path;
    /** Timestamp of when to start generating events from */
    time_t                              start_timestamp;
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
} globus_l_fork_logfile_state_t;

static globus_mutex_t                   globus_l_fork_mutex;
static globus_cond_t                    globus_l_fork_cond;
static globus_bool_t                    shutdown_called;
static int                              callback_count;


GlobusDebugDefine(SEG_FORK);

static
int
globus_l_fork_module_activate(void);

static
int
globus_l_fork_module_deactivate(void);

static
void
globus_l_fork_read_callback(
    void *                              user_arg);

static
int
globus_l_fork_parse_events(
    globus_l_fork_logfile_state_t *     state);

static
int
globus_l_fork_clean_buffer(
    globus_l_fork_logfile_state_t *     state);

static
int
globus_l_fork_increase_buffer(
    globus_l_fork_logfile_state_t *     state);

static
int
globus_l_fork_find_logfile(
    globus_l_fork_logfile_state_t *     state);

globus_module_descriptor_t
globus_scheduler_event_module_ptr =
{
    "globus_scheduler_event_generator_fork",
    globus_l_fork_module_activate,
    globus_l_fork_module_deactivate,
    NULL,
    NULL,
    &local_version,
    NULL
};

static
int
globus_l_fork_module_activate(void)
{
    globus_l_fork_logfile_state_t *     logfile_state;
    int                                 rc;
    globus_reltime_t                    delay;
    globus_result_t                     result;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }
    rc = globus_mutex_init(&globus_l_fork_mutex, NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        goto deactivate_common_error;
    }
    rc = globus_cond_init(&globus_l_fork_cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        goto destroy_mutex_error;
    }
    shutdown_called = GLOBUS_FALSE;
    callback_count = 0;

    GlobusDebugInit(
        SEG_FORK,
        SEG_FORK_DEBUG_INFO
        SEG_FORK_DEBUG_WARN
        SEG_FORK_DEBUG_ERROR
        SEG_FORK_DEBUG_TRACE);

    logfile_state = globus_libc_calloc(
            1,
            sizeof(globus_l_fork_logfile_state_t));

    if (logfile_state == NULL)
    {
        goto destroy_cond_error;
        return 1;
    }

    rc = globus_l_fork_increase_buffer(logfile_state);
    if (rc != GLOBUS_SUCCESS)
    {
        goto free_logfile_state_error;
    }

    /* Configuration info */
    result = globus_scheduler_event_generator_get_timestamp(
            &logfile_state->start_timestamp);

    if (result != GLOBUS_SUCCESS)
    {
        goto free_logfile_state_buffer_error;
    }

    if (logfile_state->start_timestamp == 0)
    {
        logfile_state->start_timestamp = time(NULL);
    }

    /* Convert timestamp to filename */
    rc = globus_l_fork_find_logfile(logfile_state);

    if (rc == GLOBUS_SUCCESS)
    {
        logfile_state->fp = fopen(logfile_state->path, "r");

        if (logfile_state->fp == NULL)
        {
            rc = SEG_FORK_ERROR_OUT_OF_MEMORY;

            goto free_logfile_state_path_error;
        }
        GlobusTimeReltimeSet(delay, 0, 0);
    }
    else if(rc == SEG_FORK_ERROR_LOG_NOT_PRESENT)
    {
        GlobusTimeReltimeSet(delay, 60, 0);
    }
    else
    {
        goto free_logfile_state_path_error;
    }

    result = globus_callback_register_oneshot(
            &logfile_state->callback,
            &delay,
            globus_l_fork_read_callback,
            logfile_state);

    if (result != GLOBUS_SUCCESS)
    {
        goto free_logfile_state_path_error;
    }
    callback_count++;

    return 0;

free_logfile_state_path_error:
    globus_libc_free(logfile_state->path);
free_logfile_state_buffer_error:
    globus_libc_free(logfile_state->buffer);
free_logfile_state_error:
    globus_libc_free(logfile_state);
destroy_cond_error:
    globus_cond_destroy(&globus_l_fork_cond);
destroy_mutex_error:
    globus_mutex_destroy(&globus_l_fork_mutex);
deactivate_common_error:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
error:
    return 1;
}
/* globus_l_fork_module_activate() */

static
int
globus_l_fork_module_deactivate(void)
{
    globus_mutex_lock(&globus_l_fork_mutex);
    shutdown_called = GLOBUS_TRUE;

    while (callback_count > 0)
    {
        globus_cond_wait(&globus_l_fork_cond, &globus_l_fork_mutex);
    }
    globus_mutex_unlock(&globus_l_fork_mutex);

    GlobusDebugDestroy(SEG_FORK);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}

static
void
globus_l_fork_read_callback(
    void *                              user_arg)
{
    int                                 rc;
    globus_l_fork_logfile_state_t *     state = user_arg;
    size_t                              max_to_read;
    globus_bool_t                       eof_hit = GLOBUS_FALSE;
    globus_reltime_t                    delay;
    globus_result_t                     result;

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_read_callback()\n"));

    globus_mutex_lock(&globus_l_fork_mutex);
    if (shutdown_called)
    {
        SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
                ("polling while deactivating"));

        globus_mutex_unlock(&globus_l_fork_mutex);
        goto error;
    }
    globus_mutex_unlock(&globus_l_fork_mutex);

    if (state->fp != NULL)
    {
        /* Read data --- leave an extra byte space so we can null-terminate
         * and use strstr()
         */
        max_to_read = state->buffer_length - state->buffer_valid
                - state->buffer_point - 1;

        SEG_FORK_DEBUG(SEG_FORK_DEBUG_TRACE,
                ("reading a maximum of %u bytes\n", max_to_read));

        rc = fread(state->buffer + state->buffer_point + state->buffer_valid,
                1, max_to_read, state->fp);
        
        SEG_FORK_DEBUG(SEG_FORK_DEBUG_TRACE,
                ("read %d bytes\n", rc));

        if (rc < max_to_read)
        {
            if (feof(state->fp))
            {
                SEG_FORK_DEBUG(SEG_FORK_DEBUG_TRACE, ("hit eof\n"));
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
        SEG_FORK_DEBUG(SEG_FORK_DEBUG_TRACE, ("parsing events\n"));
        rc = globus_l_fork_parse_events(state);

        SEG_FORK_DEBUG(SEG_FORK_DEBUG_TRACE, ("cleaning buffer\n"));
        rc = globus_l_fork_clean_buffer(state);

        if (eof_hit)
        {
            GlobusTimeReltimeSet(delay, 2, 0);
        }
        else
        {
            /* still data available in current file, hurry up! */
            GlobusTimeReltimeSet(delay, 0, 0);
        }
    }
    else
    {
        rc = globus_l_fork_find_logfile(state);
        if(rc == SEG_FORK_ERROR_LOG_NOT_PRESENT)
        {
            GlobusTimeReltimeSet(delay, 60, 0);
        }
        else
        {
            goto error;
        }
    }

    result = globus_callback_register_oneshot(
            &state->callback,
            &delay,
            globus_l_fork_read_callback,
            state);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_read_callback() exited with/success\n"));
    return;
error:
    globus_mutex_lock(&globus_l_fork_mutex);
    if (shutdown_called)
    {
        callback_count--;

        if (callback_count == 0)
        {
            globus_cond_signal(&globus_l_fork_cond);
        }
    }
    globus_mutex_unlock(&globus_l_fork_mutex);

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_WARN,
            ("globus_l_fork_read_callback() exited with/error\n"));
    return;
}
/* globus_l_fork_read_callback() */

/**
 * Determine the next available FORK log file name from the 
 * timestamp stored in the logfile state structure.
 * 
 * @param state
 *     FORK log state structure. The path field of the structure may be
 *     modified by this function.
 *
 * @retval GLOBUS_SUCCESS
 *     Name of an log file name has been found and the file exists.
 * @retval 1
 *     Something bad occurred.
 */
static
int
globus_l_fork_find_logfile(
    globus_l_fork_logfile_state_t *     state)
{
    char                                logfile[] = "/tmp/gram_fork_log";
    struct stat                         s;
    int                                 rc;

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_find_logfile()\n"));

    if (state->path == NULL)
    {
        SEG_FORK_DEBUG(SEG_FORK_DEBUG_TRACE, ("allocating path\n"));

        globus_common_get_attribute_from_config_file(NULL,
                "etc/globus-fork.conf", "log_path", &state->path);

        if (state->path == NULL)
        {
            rc = SEG_FORK_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    do
    {
        rc = stat(state->path, &s);

        if (rc < 0)
        {
            switch (errno)
            {
                case ENOENT:
                    SEG_FORK_DEBUG(SEG_FORK_DEBUG_ERROR,
                        ("missing log file\n"));
                    rc = SEG_FORK_ERROR_LOG_NOT_PRESENT;
                    goto error;

                case EACCES:
                    SEG_FORK_DEBUG(SEG_FORK_DEBUG_ERROR,
                        ("permissions needed to access logfile %s\n",
                        state->path));
                    /* Permission problem (fatal) */
                    rc = SEG_FORK_ERROR_LOG_PERMISSIONS;
                    goto error;

                case ENOTDIR:
                case ELOOP:
                case ENAMETOOLONG:
                    /* broken path (fatal) */
                    SEG_FORK_DEBUG(SEG_FORK_DEBUG_ERROR,
                        ("broken path to logfile %s\n",
                        state->path));
                    rc = SEG_FORK_ERROR_BAD_PATH;
                    goto error;

                case EFAULT:
                    SEG_FORK_DEBUG(SEG_FORK_DEBUG_ERROR,
                        ("bad pointer\n"));
                    globus_assert(errno != EFAULT);

                case EINTR:
                case ENOMEM: /* low kernel mem */
                    /* try again later */
                    SEG_FORK_DEBUG(SEG_FORK_DEBUG_WARN,
                        ("going to have to retry stat()\n"));
                    continue;

                default:
                    SEG_FORK_DEBUG(SEG_FORK_DEBUG_ERROR,
                        ("unexpected errno\n"));
                    rc = SEG_FORK_ERROR_UNKNOWN;
                    goto error;
            }
        }
    }
    while (rc != 0);

    if (rc != 0)
    {
        goto error;
    }

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_find_logfile() exits w/out error\n"));
    return 0;

error:
    SEG_FORK_DEBUG(SEG_FORK_DEBUG_WARN,
            ("globus_l_fork_find_logfile() exits w/error\n"));
    return rc;
}
/* globus_l_fork_find_logfile() */

/**
 * Move any data in the state buffer to the beginning, to enable reusing 
 * buffer space which has already been parsed.
 */
static
int
globus_l_fork_clean_buffer(
    globus_l_fork_logfile_state_t *     state)
{
    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_clean_buffer() called\n"));

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
    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_clean_buffer() exits\n"));
    return 0;
}
/* globus_l_fork_clean_buffer() */

/**
 * Reduce unused space in the log buffer, increasing the size of the buffer
 * if it is full.
 *
 * @param state
 *     FORK log state structure. The buffer-related fields of the structure
 *     may be modified by this function.
 */
static
int
globus_l_fork_increase_buffer(
    globus_l_fork_logfile_state_t *     state)
{
    char *                              save = state->buffer;
    const size_t                        GLOBUS_FORK_READ_BUFFER_SIZE = 4096;
    int                                 rc;

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_increase_buffer() called\n"));
    /* If the buffer is full, resize */
    if (state->buffer_valid == state->buffer_length)
    {
        state->buffer = globus_libc_realloc(state->buffer,
                    state->buffer_length + GLOBUS_FORK_READ_BUFFER_SIZE);
        if (state->buffer == NULL)
        {
            SEG_FORK_DEBUG(SEG_FORK_DEBUG_ERROR, ("realloc() failed\n"));

            rc = SEG_FORK_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    state->buffer_length += GLOBUS_FORK_READ_BUFFER_SIZE;

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_increase_buffer() exits w/success\n"));
    return 0;

error:
    SEG_FORK_DEBUG(SEG_FORK_DEBUG_WARN,
            ("globus_l_fork_increase_buffer() exits w/failure\n"));
    state->buffer = save;
    return rc;
}
/* globus_l_fork_increase_buffer() */

static
int
globus_l_fork_parse_events(
    globus_l_fork_logfile_state_t *     state)
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
    enum {
        EXIT_CODE_UNASSIGNED = -1492

    };

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_parse_events() called\n"));

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

        if (stamp < state->start_timestamp)
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

    SEG_FORK_DEBUG(SEG_FORK_DEBUG_INFO,
            ("globus_l_fork_parse_events() exits\n"));
    return 0;
}
/* globus_l_fork_parse_events() */
