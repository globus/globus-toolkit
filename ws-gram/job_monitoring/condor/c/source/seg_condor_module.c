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
#include "version.h"

#include <time.h>
#include <string.h>

#define SEG_CONDOR_DEBUG(level, message) \
    GlobusDebugPrintf(SEG_CONDOR, level, message)

/**
 * Debug levels:
 * If the environment variable SEG_CONDOR_DEBUG is set to a bitwise or
 * of these values, then a corresponding log message will be generated.
 */
typedef enum
{
    /**
     * Information of function calls and exits
     */
    SEG_CONDOR_DEBUG_INFO = (1<<0),
    /**
     * Warnings of things which may be bad.
     */
    SEG_CONDOR_DEBUG_WARN = (1<<1),
    /**
     * Fatal errors.
     */
    SEG_CONDOR_DEBUG_ERROR = (1<<2),
    /**
     * Details of function executions.
     */
    SEG_CONDOR_DEBUG_TRACE = (1<<3)
}
globus_l_seg_condor_debug_level_t;

enum
{
    SEG_CONDOR_ERROR_UNKNOWN = 1,
    SEG_CONDOR_ERROR_OUT_OF_MEMORY,
    SEG_CONDOR_ERROR_BAD_PATH,
    SEG_CONDOR_ERROR_LOG_PERMISSIONS,
    SEG_CONDOR_ERROR_LOG_NOT_PRESENT,
    SEG_CONDOR_ERROR_PARSE

};

/**
 * State of the CONDOR log file parser.
 */
typedef struct 
{
    /** Path of the current log file being parsed */
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
} globus_l_condor_logfile_state_t;

static
int
globus_l_condor_parse_event(
    char *                              buffer,
    time_t                              start_timestamp);

static globus_mutex_t                   globus_l_condor_mutex;
static globus_cond_t                    globus_l_condor_cond;
static globus_bool_t                    shutdown_called;
static int                              callback_count;


GlobusDebugDefine(SEG_CONDOR);

static
int
globus_l_condor_module_activate(void);

static
int
globus_l_condor_module_deactivate(void);

static
void
globus_l_condor_read_callback(
    void *                              user_arg);

static
int
globus_l_condor_parse_events(
    globus_l_condor_logfile_state_t *      state);

static
int
globus_l_condor_clean_buffer(
    globus_l_condor_logfile_state_t *      state);

static
int
globus_l_condor_increase_buffer(
    globus_l_condor_logfile_state_t *      state);

static
int
globus_l_condor_find_logfile(
    globus_l_condor_logfile_state_t *      state);

globus_module_descriptor_t
globus_scheduler_event_module_ptr =
{
    "globus_scheduler_event_generator_condor",
    globus_l_condor_module_activate,
    globus_l_condor_module_deactivate,
    NULL,
    NULL,
    &local_version,
    NULL
};

static
int
globus_l_condor_module_activate(void)
{
    globus_l_condor_logfile_state_t *   logfile_state;
    int                                 rc;
    globus_reltime_t                    delay;
    globus_result_t                     result;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }
    rc = globus_mutex_init(&globus_l_condor_mutex, NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        goto deactivate_common_error;
    }
    rc = globus_cond_init(&globus_l_condor_cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        goto destroy_mutex_error;
    }
    shutdown_called = GLOBUS_FALSE;
    callback_count = 0;

    GlobusDebugInit(
        SEG_CONDOR,
        SEG_CONDOR_DEBUG_INFO
        SEG_CONDOR_DEBUG_WARN
        SEG_CONDOR_DEBUG_ERROR
        SEG_CONDOR_DEBUG_TRACE);

    logfile_state = globus_libc_calloc(
            1,
            sizeof(globus_l_condor_logfile_state_t));

    if (logfile_state == NULL)
    {
        goto destroy_cond_error;
        return 1;
    }

    rc = globus_l_condor_increase_buffer(logfile_state);
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

    /* Convert timestamp to filename */
    rc = globus_l_condor_find_logfile(logfile_state);

    if (rc == GLOBUS_SUCCESS)
    {
        logfile_state->fp = fopen(logfile_state->path, "r");

        if (logfile_state->fp == NULL)
        {
            rc = SEG_CONDOR_ERROR_OUT_OF_MEMORY;

            goto free_logfile_state_path_error;
        }
        GlobusTimeReltimeSet(delay, 0, 0);
    }
    else if(rc == SEG_CONDOR_ERROR_LOG_NOT_PRESENT)
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
            globus_l_condor_read_callback,
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
    globus_cond_destroy(&globus_l_condor_cond);
destroy_mutex_error:
    globus_mutex_destroy(&globus_l_condor_mutex);
deactivate_common_error:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
error:
    return 1;
}
/* globus_l_condor_module_activate() */

static
int
globus_l_condor_module_deactivate(void)
{
    globus_mutex_lock(&globus_l_condor_mutex);
    shutdown_called = GLOBUS_TRUE;

    while (callback_count > 0)
    {
        globus_cond_wait(&globus_l_condor_cond, &globus_l_condor_mutex);
    }
    globus_mutex_unlock(&globus_l_condor_mutex);

    GlobusDebugDestroy(SEG_CONDOR);

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
globus_l_condor_read_callback(
    void *                              user_arg)
{
    int                                 rc;
    globus_l_condor_logfile_state_t *      state = user_arg;
    size_t                              max_to_read;
    globus_bool_t                       eof_hit = GLOBUS_FALSE;
    globus_reltime_t                    delay;
    globus_result_t                     result;

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_read_callback()\n"));

    globus_mutex_lock(&globus_l_condor_mutex);
    if (shutdown_called)
    {
        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
                ("polling while deactivating"));

        globus_mutex_unlock(&globus_l_condor_mutex);
        goto error;
    }
    globus_mutex_unlock(&globus_l_condor_mutex);

    if (state->fp != NULL)
    {
        /* Read data --- leave an extra byte space so we can null-terminate
         * and use strstr()
         */
        max_to_read = state->buffer_length - state->buffer_valid
                - state->buffer_point - 1;

        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                ("reading a maximum of %u bytes\n", max_to_read));

        rc = fread(state->buffer + state->buffer_point + state->buffer_valid,
                1, max_to_read, state->fp);
        
        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                ("read %d bytes\n", rc));

        if (rc < max_to_read)
        {
            if (feof(state->fp))
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE, ("hit eof\n"));
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
        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE, ("parsing events\n"));
        rc = globus_l_condor_parse_events(state);

        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE, ("cleaning buffer\n"));
        rc = globus_l_condor_clean_buffer(state);

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
        rc = globus_l_condor_find_logfile(state);
        if(rc == SEG_CONDOR_ERROR_LOG_NOT_PRESENT)
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
            globus_l_condor_read_callback,
            state);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_read_callback() exited with/success\n"));
    return;
error:
    globus_mutex_lock(&globus_l_condor_mutex);
    if (shutdown_called)
    {
        callback_count--;

        if (callback_count == 0)
        {
            globus_cond_signal(&globus_l_condor_cond);
        }
    }
    globus_mutex_unlock(&globus_l_condor_mutex);

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
            ("globus_l_condor_read_callback() exited with/error\n"));
    return;
}
/* globus_l_condor_read_callback() */

/**
 * Determine the next available CONDOR log file name from the 
 * timestamp stored in the logfile state structure.
 * 
 * @param state
 *     CONDOR log state structure. The path field of the structure may be
 *     modified by this function.
 *
 * @retval GLOBUS_SUCCESS
 *     Name of an log file name has been found and the file exists.
 * @retval 1
 *     Something bad occurred.
 */
static
int
globus_l_condor_find_logfile(
    globus_l_condor_logfile_state_t *   state)
{
    struct stat                         s;
    int                                 rc;

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_find_logfile()\n"));

    if (state->path == NULL)
    {
        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE, ("allocating path\n"));

        globus_common_get_attribute_from_config_file(NULL,
                "etc/globus-condor.conf", "log_path", &state->path);

        if (state->path == NULL)
        {
            rc = SEG_CONDOR_ERROR_OUT_OF_MEMORY;
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
                    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR,
                        ("missing log file\n"));
                    rc = SEG_CONDOR_ERROR_LOG_NOT_PRESENT;
                    goto error;

                case EACCES:
                    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR,
                        ("permissions needed to access logfile %s\n",
                        state->path));
                    /* Permission problem (fatal) */
                    rc = SEG_CONDOR_ERROR_LOG_PERMISSIONS;
                    goto error;

                case ENOTDIR:
                case ELOOP:
                case ENAMETOOLONG:
                    /* broken path (fatal) */
                    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR,
                        ("broken path to logfile %s\n",
                        state->path));
                    rc = SEG_CONDOR_ERROR_BAD_PATH;
                    goto error;

                case EFAULT:
                    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR,
                        ("bad pointer\n"));
                    globus_assert(errno != EFAULT);

                case EINTR:
                case ENOMEM: /* low kernel mem */
                    /* try again later */
                    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                        ("going to have to retry stat()\n"));
                    continue;

                default:
                    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR,
                        ("unexpected errno\n"));
                    rc = SEG_CONDOR_ERROR_UNKNOWN;
                    goto error;
            }
        }
    }
    while (rc != 0);

    if (rc != 0)
    {
        goto error;
    }

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_find_logfile() exits w/out error\n"));
    return 0;

error:
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
            ("globus_l_condor_find_logfile() exits w/error\n"));
    return rc;
}
/* globus_l_condor_find_logfile() */

/**
 * Move any data in the state buffer to the beginning, to enable reusing 
 * buffer space which has already been parsed.
 */
static
int
globus_l_condor_clean_buffer(
    globus_l_condor_logfile_state_t *      state)
{
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_clean_buffer() called\n"));

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
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_clean_buffer() exits\n"));
    return 0;
}
/* globus_l_condor_clean_buffer() */

/**
 * Reduce unused space in the log buffer, increasing the size of the buffer
 * if it is full.
 *
 * @param state
 *     CONDOR log state structure. The buffer-related fields of the structure
 *     may be modified by this function.
 */
static
int
globus_l_condor_increase_buffer(
    globus_l_condor_logfile_state_t *      state)
{
    char *                              save = state->buffer;
    const size_t                        GLOBUS_CONDOR_READ_BUFFER_SIZE = 4096;
    int                                 rc;

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_increase_buffer() called\n"));
    /* If the buffer is full, resize */
    if (state->buffer_valid == state->buffer_length)
    {
        state->buffer = globus_libc_realloc(state->buffer,
                    state->buffer_length + GLOBUS_CONDOR_READ_BUFFER_SIZE);
        if (state->buffer == NULL)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR, ("realloc() failed\n"));

            rc = SEG_CONDOR_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    state->buffer_length += GLOBUS_CONDOR_READ_BUFFER_SIZE;

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_increase_buffer() exits w/success\n"));
    return 0;

error:
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
            ("globus_l_condor_increase_buffer() exits w/failure\n"));
    state->buffer = save;
    return rc;
}
/* globus_l_condor_increase_buffer() */

static
int
globus_l_condor_parse_events(
    globus_l_condor_logfile_state_t *   state)
{
    char *                              eot;
    int                                 rc;
    char *                              p;
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_parse_events() called\n"));

    state->buffer[state->buffer_point + state->buffer_valid] = '\0';

    p = state->buffer + state->buffer_point;

    while (isspace(*p))
    {
        p++;
    }
    while ((eot = strstr(p, "</c>\n"))
            != NULL)
    {
        *(eot+4) = '\0';

        if (strncmp(p, "<c>", 3) == 0)
        {
            p += 3;

            rc = globus_l_condor_parse_event(p, state->start_timestamp);
        }

        state->buffer_valid -= eot + 4 - state->buffer - state->buffer_point;
        state->buffer_point = eot + 4 - state->buffer;

        if (state->buffer_valid > 0)
        {
            state->buffer_valid--;
            state->buffer_point++;
        }

        p = state->buffer + state->buffer_point;
    }

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_parse_events() exits\n"));
    return 0;
}
/* globus_l_condor_parse_events() */


static
int
globus_l_condor_parse_event(
    char *                              buffer,
    time_t                              start_timestamp)
{
    char *                              p;
    char *                              attr;
    char *                              tmp;
    int                                 event_type_number;
    char *                              event_time;
    int                                 cluster;
    int                                 proc;
    int                                 subproc;
    globus_bool_t                       terminated_normally;
    int                                 return_value = 0;
    struct tm                           event_tm;
    time_t                              event_stamp;
    char *                              jobid;
    int                                 jobid_len;
    int                                 len;
    globus_result_t                     result;

    enum condor_attr_e
    {
        DONTCARE,
        EVENT_TYPE_NUMBER,
        EVENT_TIME,
        CLUSTER,
        PROC,
        SUBPROC,
        TERMINATED_NORMALLY,
        RETURN_VALUE
    } condor_attr;
    typedef enum
    {
        CONDOR_STRING,
        CONDOR_INTEGER,
        CONDOR_BOOLEAN,
        CONDOR_REAL
    } condor_parse_type_t;
    union
    {
        condor_parse_type_t type;

        struct
        {
            condor_parse_type_t type;
            char * s;
        } s;

        struct
        {
            condor_parse_type_t type;
            int i;
        } i;

        struct
        {
            condor_parse_type_t type;
            globus_bool_t b;
        } b;

        struct
        {
            condor_parse_type_t type;
            float r;
        } r;
    } pu;

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
            ("parsing event %s\n", buffer));
    p = buffer;

    while(isspace(*p))
    {
        p++;
    }
    while ((strncmp(p, "<a", 2)) == 0)
    {
        p += 6; /* [[<a n="]] */
        attr = p;
        while (*p && *p != '"')
        {
            p++;
        }
        if (!*p)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                ("short buffer"));
            return 1;
        }
        *(p++) = '\0';
        if (*p == '\0')
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                ("short buffer"));
            return 1;
        }
        p++;

        if (strcmp(attr, "EventTypeNumber") == 0)
        {
            condor_attr = EVENT_TYPE_NUMBER;
        }
        else if (strcmp(attr, "EventTime") == 0)
        {
            condor_attr = EVENT_TIME;
        }
        else if (strcmp(attr, "Cluster") == 0)
        {
            condor_attr = CLUSTER;
        }
        else if (strcmp(attr, "Proc") == 0)
        {
            condor_attr = PROC;
        }
        else if (strcmp(attr, "Subproc") == 0)
        {
            condor_attr = SUBPROC;
        }
        else if (strcmp(attr, "TerminatedNormally") == 0)
        {
            condor_attr = TERMINATED_NORMALLY;
        }
        else if (strcmp(attr, "ReturnValue") == 0)
        {
            condor_attr = RETURN_VALUE;
        }
        else
        {
            condor_attr = DONTCARE;
        }
        if (strncmp(p, "<s>", 3) == 0)
        {
            /* String value */
            p += 3;

            if (*p == '\0')
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("short buffer"));
                return 1;
            }
            pu.type = CONDOR_STRING;
            pu.s.s = p;
            p = strstr(p, "</s>");
            *p = '\0';
            p += 4;

        }
        else if (strncmp(p, "<i>", 3) == 0)
        {
            /* Integer value */
            p += 3;
            if (*p == '\0')
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("short buffer"));
                return 1;
            }
            pu.type = CONDOR_INTEGER;
            tmp = p;
            p = strstr(p, "</i>");
            *p = '\0';
            p += 4;
            pu.i.i = atoi(tmp);
        }
        else if (strncmp(p, "<b v=\"t\"/>", 10) == 0)
        {
            /* Boolean true value */
            p += 10;
            pu.type = CONDOR_BOOLEAN;
            pu.b.b = GLOBUS_TRUE;
        }
        else if (strncmp(p, "<b v=\"f\"/>", 10) == 0)
        {
            /* Boolean false value */
            p += 10;
            pu.type = CONDOR_BOOLEAN;
            pu.b.b = GLOBUS_FALSE;
        }
        else if (strncmp(p, "<r>", 3) == 0)
        {
            /* Real value */
            p += 3;
            if (*p == '\0')
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("short buffer"));
                return 1;
            }
            pu.type = CONDOR_REAL;
            tmp = p;
            sscanf(p, "%f%n", &pu.r.r, &len);
            p += len;
            if (*p == '\0')
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("short buffer"));
                return 1;
            }
            if (strncmp(p, "</r>", 4) != 0)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("expected </r>, got %s\n", p));
                return 1;
            }
            *p = '\0';
            p += 4;

        }
        else
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_ERROR,
                ("unknown token at %s\n", p));
            break;
        }

        switch (condor_attr)
        {
        case EVENT_TYPE_NUMBER:
            if (pu.type != CONDOR_INTEGER)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("EventTypeNumber: expected int, got %d\n", pu.type));
                break;

            }
            event_type_number = pu.i.i;
            break;
        case EVENT_TIME:
            if (pu.type != CONDOR_STRING)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("EventTime: expected string, got %d\n", pu.type));
                break;
            }
            event_time = pu.s.s;

            sscanf(event_time, "%04d-%02d-%02dT%2d:%2d:%2d",
                &event_tm.tm_year,
                &event_tm.tm_mon,
                &event_tm.tm_mday,
                &event_tm.tm_hour,
                &event_tm.tm_min,
                &event_tm.tm_sec);

            event_tm.tm_year -= 1900;
            event_tm.tm_mon -= 1;
            event_tm.tm_isdst = -1;

            event_stamp = mktime(&event_tm);

            break;
        case CLUSTER:
            if (pu.type != CONDOR_INTEGER)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("Cluster: expected int, got %d\n", pu.type));
                break;

            }
            cluster = pu.i.i;
            break;
        case PROC:
            if (pu.type != CONDOR_INTEGER)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("Proc: expected int, got %d\n", pu.type));
                break;

            }
            proc = pu.i.i;
            break;
        case SUBPROC:
            if (pu.type != CONDOR_INTEGER)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("Subproc: expected int, got %d\n", pu.type));
                break;

            }
            subproc = pu.i.i;
            break;
        case TERMINATED_NORMALLY:
            if (pu.type != CONDOR_BOOLEAN)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("TerminatedNormally: expected bool, got %d\n", pu.type));
                break;

            }
            terminated_normally = pu.b.b;
            break;
        case RETURN_VALUE:
            if (pu.type != CONDOR_INTEGER)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("ReturnValue: expected int, got %d\n", pu.type));
                break;

            }
            return_value = pu.i.i;
            break;
        case DONTCARE:
        default:
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                ("Ignoring attribute %s\n", attr));
            break;
        }
        if (strncmp(p, "</a>", 4) != 0)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                ("missing </a> at %s\n", p));
            return 1;
        }
        p += 4;

        while (isspace(*p))
        {
            p++;
        }
    }

    if (event_stamp < start_timestamp)
    {
        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
            ("ignoring old event type %d for job %03d.%03d.%03d\n",
            event_type_number, cluster, proc, subproc));

        return 0;
    }

    jobid_len = globus_libc_printf_length(
            "%03d.%03d.%03d", cluster, proc, subproc);

    jobid = malloc(jobid_len+1);

    sprintf(jobid, "%03d.%03d.%03d", cluster, proc, subproc);

    switch (event_type_number)
    {
    case 0: /* SubmitEvent */
        result = globus_scheduler_event_pending(event_stamp, jobid);

        if (result != GLOBUS_SUCCESS)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                ("Unable to send pending event: %s\n",
                globus_object_printable_to_string(
                    globus_error_peek(result))));
        }
        break;
    case 1: /* ExecuteEvent */
        result = globus_scheduler_event_active(event_stamp, jobid);

        if (result != GLOBUS_SUCCESS)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                ("Unable to send pending event: %s\n",
                globus_object_printable_to_string(
                    globus_error_peek(result))));
        }
        break;

    case 5: /* JobTerminatedEvent */
        if (terminated_normally)
        {
            result = globus_scheduler_event_done(event_stamp, jobid,
                return_value);

            if (result != GLOBUS_SUCCESS)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("Unable to send done event: %s\n",
                    globus_object_printable_to_string(
                        globus_error_peek(result))));
            }
        }
        else
        {
    case 9: /* JobAbortedEvent */
            result = globus_scheduler_event_failed(event_stamp, jobid,
                return_value);

            if (result != GLOBUS_SUCCESS)
            {
                SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("Unable to send failed event: %s\n",
                    globus_object_printable_to_string(
                        globus_error_peek(result))));
            }
        }
        break;
    }
    globus_libc_free(jobid);

    return 0;
}
/* globus_l_condor_parse_event() */
