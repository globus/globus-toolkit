
#include "globus_common.h"
#include "globus_scheduler_event_generator.h"
#include "version.h"

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
globus_l_condor_parse_exit_code(
    const char *                        buffer,
    globus_bool_t *                     normal_termination,
    int *                               exit_status);

static const time_t                     SECS_IN_DAY = 60*60*24;
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
    globus_l_condor_logfile_state_t *      state)
{
    char                                log_dir[] = "/home/joe/condor_test";
    struct stat                         s;
    int                                 rc;

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_find_logfile()\n"));

    if (state->path == NULL)
    {
        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE, ("allocating path\n"));
        state->path = malloc(sizeof(log_dir) + strlen("results.log") + 2);

        if (state->path == NULL)
        {
            rc = SEG_CONDOR_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }


    do
    {
        rc = sprintf(state->path,
                "%s/%s",
                log_dir,
                "results.log");

        if (rc < 0)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_WARN,
                    ("couldn't format path\n"));
            rc = SEG_CONDOR_ERROR_OUT_OF_MEMORY;
            goto error;
        }
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
    char *                              eor;
    struct tm                           tm;
    time_t                              stamp;
    size_t                              nb;
    int                                 evttype;
    int                                 cluster;
    int                                 process;
    int                                 sub;
    int                                 rc;
    int                                 exit_status;
    char *                              jobid;
    globus_bool_t                       normal_termination;
    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_parse_events() called\n"));

    state->buffer[state->buffer_point + state->buffer_valid] = '\0';

    while ((eor = strstr(state->buffer + state->buffer_point,
                "\n...\n")) != NULL)
    {
        *eor = '\0';

        SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                ("parsing event %s\n", state->buffer + state->buffer_point));

        /*
         * Grab a current timestamp to find out what year we are in. We'll
         * use the year in our events, since condor doesn't provide it in the
         * logs.
         */
        stamp = time(NULL);
        if (globus_libc_localtime_r(&stamp, &tm) == NULL)
        {
            goto next_msg;
        }
        tm.tm_isdst = -1;

        rc = sscanf(state->buffer + state->buffer_point,
                "%03d (%d.%d.%d) %02d/%2d %d:%d:%d%n",
                &evttype, &cluster, &process, &sub, &tm.tm_mon, &tm.tm_mday,
                &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &nb);

        if (rc < 9)
        {
            goto next_msg;
        }

        jobid = globus_libc_malloc(strlen(state->buffer+state->buffer_point));
        if (jobid == NULL)
        {
            goto next_msg;
        }
        rc = sprintf(jobid, "%03d.%03d.%03d", cluster, process, sub);
        if (rc < 0)
        {
            goto next_msg;
        }

        stamp = mktime(&tm);

        if (stamp < state->start_timestamp)
        {
            goto next_msg;
        }

        switch (evttype)
        {
        case 0: /* Job Submitted */
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                    ("job submitted\n"));
            globus_scheduler_event_pending(stamp, jobid);
            break;
        case 1: /* Job Executing */
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                    ("job started\n"));
            globus_scheduler_event_active(stamp, jobid);
            break;
        case 5: /* Job Terminated */
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                    ("job done\n"));
            globus_l_condor_parse_exit_code(
                    state->buffer + state->buffer_point + nb + 1,
                    &normal_termination,
                    &exit_status);
            
            if (normal_termination)
            {
                globus_scheduler_event_done(stamp, jobid, exit_status);
            }
            else
            {
                globus_scheduler_event_failed(stamp, jobid, exit_status);
            }
            break;
        case 2: /* Job Not Executable */
        case 9: /* Job Aborted By User */
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                    ("job failed\n"));
            globus_scheduler_event_failed(stamp, jobid, exit_status);
            break;
        case 4: /* Job Evicted (suspended?)*/
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_TRACE,
                    ("job suspended\n"));
        }

next_msg:
        if (jobid != NULL)
        {
            SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
                    ("freeing jobid\n"));
            globus_libc_free(jobid);
            jobid = NULL;
        }

        state->buffer_valid -= eor + 5 - state->buffer - state->buffer_point;
        state->buffer_point = eor + 5 - state->buffer;
    }

    SEG_CONDOR_DEBUG(SEG_CONDOR_DEBUG_INFO,
            ("globus_l_condor_parse_events() exits\n"));
    return 0;
}
/* globus_l_condor_parse_events() */


static
int
globus_l_condor_parse_exit_code(
    const char *                        buffer,
    globus_bool_t *                     normal_termination,
    int *                               exit_status)
{
    char *                              eol;
    int                                 rc;

    *exit_status = 0;
    *normal_termination = GLOBUS_TRUE;

    while ((eol = strchr(buffer, '\n')) != NULL)
    {
        buffer = eol+1;

        rc = sscanf(buffer,
                "\t(1) Normal termination (return value %d)",
                exit_status);
        if (rc == 1)
        {
            return 0;
        }
        
        rc = sscanf(buffer,
                "\t(0) Abnormal termination (signal %d)",
                exit_status);
        if (rc == 1)
        {
            *normal_termination = GLOBUS_FALSE;
            return 0;
        }
    }

    return 0;
}
/* globus_l_condor_parse_exit_code() */
