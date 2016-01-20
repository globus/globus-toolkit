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

#ifndef HAVE_GETLINE
#if !(__STDC_VERSION__ >= 199901L)
#define restrict
#endif
ssize_t
seg_getline(char ** restrict linep, size_t * restrict linecapp, FILE * restrict stream);
#define getline(l,c,s) seg_getline(l,c,s)
#endif

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
    SEG_PBS_ERROR_END_OF_FILE,
    SEG_PBS_ERROR_TIME,
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
    /** Date of the log file */
    struct tm                           path_time;
    /** Timestamp of when to start generating events from */
    time_t                              start_timestamp;
    /** Offset of the next event to read from the log file */
    off_t                               log_offset;
    /** Buffer of log file data */
    char *                              buffer;
    /** Length of the buffer */
    size_t                              buffer_length;
    /**
     * Path to the directory where the PBS server log files are located
     */
    char *                              log_dir;
} globus_l_pbs_logfile_state_t;

static const globus_l_pbs_logfile_state_t logfile_state_static_initializer={0};
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
    globus_l_pbs_logfile_state_t *      state,
    FILE *                              fp,
    off_t *                             end_of_parse);

static
void
globus_l_pbs_increment_date(
    struct tm *                         tm);

static
int
globus_l_pbs_find_next(
    globus_l_pbs_logfile_state_t *      state,
    char **                             next_file);

static
time_t
globus_l_pbs_make_start_of_day(time_t * when);

GlobusExtensionDefineModule(globus_seg_pbs) =
{
    "globus_seg_pbs",
    globus_l_pbs_module_activate,
    globus_l_pbs_module_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
globus_l_pbs_module_activate(void)
{
    globus_l_pbs_logfile_state_t *      logfile_state;
    int                                 rc;
    globus_reltime_t                    delay;
    globus_result_t                     result;
    struct stat                         st;
    char *                              config_path = NULL;
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

    logfile_state = malloc(sizeof(globus_l_pbs_logfile_state_t));

    if (logfile_state == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error: out of memory\n"));
        goto destroy_cond_error;
    }
    *logfile_state = logfile_state_static_initializer;

    /* Configuration info */
    result = globus_scheduler_event_generator_get_timestamp(
            &logfile_state->start_timestamp);
    if (result != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error (unable to parse timestamp)\n"));
        goto get_timestamp_failed;
    }
    if (logfile_state->start_timestamp == 0)
    {
        logfile_state->start_timestamp = time(NULL);
    }

    result = globus_eval_path(
            "${sysconfdir}/globus/globus-pbs.conf", &config_path);
    if (result != GLOBUS_SUCCESS || config_path == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error: unable to allocate path to config file\n"));
        goto eval_path_failed;
    }
    result = globus_common_get_attribute_from_config_file(
            "",
            config_path,
            "log_path",
            &logfile_state->log_dir);
    if (result != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                ("Fatal error: unable to read log_path from "
                "${sysconfdir}/globus/globus-pbs.conf\n"));

        goto get_log_path_failed;
    }

    if ((rc = stat(logfile_state->log_dir, &st)) != 0)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                    ("Fatal error checking log directory: %s\n",
                     strerror(errno)));

        goto stat_log_dir_failed;
    }
    if (localtime_r(&logfile_state->start_timestamp, &logfile_state->path_time)
            == NULL)
    {
        struct tm initializer = {0};

        logfile_state->path_time = initializer;

        logfile_state->path_time.tm_year = 70;
        logfile_state->path_time.tm_mon = 0;
        logfile_state->path_time.tm_mday = 1;
    }

    logfile_state->path = globus_common_create_string(
            "%s/%04d%02d%02d",
            logfile_state->log_dir,
            logfile_state->path_time.tm_year + 1900,
            logfile_state->path_time.tm_mon + 1,
            logfile_state->path_time.tm_mday);

    if (logfile_state->path == NULL)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_ERROR, ("error allocating path\n"));
        goto alloc_path_failed;
    }

    if (access(logfile_state->path, R_OK) == 0)
    {
        GlobusTimeReltimeSet(delay, 0, 0);
    }
    else
    {
        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                ("Log file %s not (currently) present\n",
                 logfile_state->path));
        GlobusTimeReltimeSet(delay, 1, 0);
    }

    result = globus_callback_register_oneshot(
            NULL,
            &delay,
            globus_l_pbs_read_callback,
            logfile_state);
    if (result != GLOBUS_SUCCESS)
    {
        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                ("Error registering oneshot: %s\n",
                globus_error_print_friendly(globus_error_peek(result))));

        goto oneshot_failed;
    }
    callback_count++;

    SEGPbsExit();
    return 0;

oneshot_failed:
    if (logfile_state->path)
    {
        free(logfile_state->path);
    }
alloc_path_failed:
stat_log_dir_failed:
    if (logfile_state->log_dir)
    {
        free(logfile_state->log_dir);
    }
get_log_path_failed:
    if (config_path)
    {
        free(config_path);
    }
eval_path_failed:
get_timestamp_failed:
    free(logfile_state);
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
 * read callback
 *
 * Try to open a log file (either the last one we parsed or a newer one if
 * it doesn't exist or is done).
 *
 * Seek to the file's current parse location
 *
 * Parse events
 *
 * Reregister
 */
static
void
globus_l_pbs_read_callback(
    void *                              user_arg)
{
    int                                 rc;
    globus_l_pbs_logfile_state_t *      state = user_arg;
    globus_reltime_t                    delay;
    globus_result_t                     result;
    FILE *                              fp;
    time_t                              today;

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

    today = globus_l_pbs_make_start_of_day(NULL);

    /* We'll start at the file in state->path, moving forward day by day
     * until we find one we can open. In some cases, we will not find a
     * valid file, so we'll defer the parsing until another callback.
     *
     */
    do
    {
        fp = fopen(state->path, "r");

        if (!fp)
        {
            switch (errno)
            {
            /* Transient Errors.
             * These are out of our control, so we'll defer parsing
             */
            case EINTR:         /* signal occurred during open */
            case ENFILE:        /* systemwide file limit reached */
                GlobusTimeReltimeSet(delay, 30, 0);
                goto reregister;

            /*
             * If the file doesn't exist, and it's an old log file, we'll
             * move forward in time to the next available log file. If it's
             * the current log file, we'll defer until a future callback
             */
            case ENOENT:        /* file doesn't exist */
                if (mktime(&state->path_time) < today)
                {
                    /* If an old file doesn't exist, we'll look for a newer
                     * one
                     */
                    char * next_file;

                    if (globus_l_pbs_find_next(state, &next_file) == 0)
                    {
                        /* If it does, and the old one still doesn't, move
                         * on to the next one
                         */
                        if (access(next_file, R_OK) == 0 &&
                            access(state->path, R_OK) == -1 &&
                            errno == ENOENT)
                        {
                            free(state->path);
                            state->path = next_file;
                            state->log_offset = 0;

                            globus_strptime(next_file + strlen(state->log_dir) + 1, 
                                "%Y%m%d", &state->path_time);
                            break;
                        }
                        else
                        {
                            /* Nothing new yet */
                            free(next_file);
                        }
                    }
                }
                GlobusTimeReltimeSet(delay, 10, 0);
                goto reregister;

            /* Misconfiguration or filesystem error we can't handle  */
            case ELOOP:         /* invalid symlink in path */
            case EACCES:        /* invalid permissions */
            case EMFILE:        /* out of file descriptors for this process */
            case ENAMETOOLONG:  /* path name too long */
            case EOVERFLOW:     /* file bigger than off_t */
                perror("open failed");
                exit(EXIT_FAILURE);

            /* Unexpected Errors */
            case ENOTDIR:       /* path component contains a non-directory */
            case EEXIST:        /* Can only happen if trying to create file */
            case EINVAL:        /* Only related to synchronized I/O */
            case EIO:           /* STREAMS-related */
            case EISDIR:        /* Can only happen when open for write to a dir
                                 */
#ifdef ENOSR
            case ENOSR:         /* STREAMS-related */
#endif
            case ENOSPC:        /* Can only happen when creating file */
            case ENXIO:         /* nonblocking write to a fifo with no reader */
            case EROFS:         /* write to readonly filesystem */
            default:            /* Some other non-standard errno */
                SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                        ("Log file %s not (currently) present: %s\n",
                         state->path,
                         strerror(errno)));
                GlobusTimeReltimeSet(delay, 30, 0);
                goto reregister;
            }
        }
    }
    while (fp == NULL);

    if (fp != NULL)
    {
        do
        {
            errno = 0;
            rc = fseeko(fp, state->log_offset, SEEK_SET);

            if (rc != 0)
            {
                switch (errno)
                {
                    /* Unexpected, but transient errors */
                    case EAGAIN:
                    case EINTR:
                        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                                ("Transient seek error for %s to %e: %s\n",
                                 state->path,
                                 (float) state->log_offset,
                                 strerror(errno)));
                        continue;

                    /* Errors, we'll fail out here and close the fp and
                     * try again next callback
                     */
                    case EBADF:
                    case EOVERFLOW:
                        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                                ("Unable to seek %s to %e: %s\n",
                                 state->path,
                                 (float) state->log_offset,
                                 strerror(errno)));

                        GlobusTimeReltimeSet(delay, 10, 0);
                        goto reregister;

                    /* Shouldn't happen */
                    case EFBIG:
                    case EINVAL:
                    case EIO:
                    case ENOSPC:
                    case ENXIO:
                    case EPIPE:
                    case ESPIPE:
                    default:
                        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                                ("Unable to seek %s to %e: %s\n",
                                 state->path,
                                 (float) state->log_offset,
                                 strerror(errno)));
                        exit(EXIT_FAILURE);
                }
            }
        } while (rc != 0);

        /* Read and parse data */
        rc = globus_l_pbs_parse_events(state, fp, &state->log_offset);

        /* if above returns 0, we (probably) haven't reached the end of
         * file, if it returns EOF, then we hit some I/O error (hopefully EOF).
         * If the latter, we will confirm that we've parsed the entire file,
         * and the next one exists, and if both conditions are true, we'll move
         * on to the next file. If not, we'll keep the current one as the
         * log file to process try again after a bit.
         */
        if (rc == EOF)
        {
            char * next_file;
            struct stat st;

            GlobusTimeReltimeSet(delay, 2, 0);

            /* EOF on current logfile check to see if next exists */
            if (globus_l_pbs_find_next(state, &next_file) == 0)
            {
                if (access(next_file, R_OK) == 0)
                {
                    /* If we are convinced the next file exists and the
                     * current file has been completely parsed, we'll move on
                     * to the beginning of the next file
                     */
                    rc = stat(state->path, &st);
                    if (rc == 0)
                    {
                        if (state->log_offset == st.st_size)
                        {
                            free(state->path);
                            state->path = next_file;

                            globus_strptime(next_file + strlen(state->log_dir) + 1, 
                                "%Y%m%d", &state->path_time);

                            state->log_offset = 0;
                            next_file = NULL;

                            GlobusTimeReltimeSet(delay, 0, 0);
                        }
                    }
                }

                if (next_file)
                {
                    free(next_file);
                }
            }
        }
        else
        {
            /* still data available in current file, allow other callbacks
             * to run, then immediately run this one again
             */
            GlobusTimeReltimeSet(delay, 0, 0);
        }
    }

    fclose(fp);

reregister:
    result = globus_callback_register_oneshot(
            NULL,
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
    else
    {
        fprintf(stderr,
                "FATAL: Unable to register callback. PBS SEG exiting\n");
        exit(EXIT_FAILURE);
    }
    globus_mutex_unlock(&globus_l_pbs_mutex);

    SEGPbsExit();
    return;
}
/* globus_l_pbs_read_callback() */

/**
 * Determine the next available PBS log file name after the current
 * state->path value, returning in the string pointed to by next_file. If a
 * newer log isn't available, the string pointed to by next_file is set to NULL
 * and an errno value is returned.
 * 
 * @param state
 *     PBS log state structure. The path field of the structure is inspected.
 * @param next_file
 *     Pointer to a string to contain the file name of the next pbs logfile.
 *
 * @retval GLOBUS_SUCCESS
 *     Name of an log file name has been found and the file exists.
 * @retval 1
 *     Something bad occurred.
 */
static
int
globus_l_pbs_find_next(
    globus_l_pbs_logfile_state_t *      state,
    char **                             next_file)
{
    char *                              next_path;
    struct tm                           next_path_day;
    static size_t                       dirname_len = 0;
    struct stat                         s;
    int                                 rc;
    time_t                              today_time;
    GlobusFuncName(globus_l_pbs_find_logfile);

    SEGPbsEnter();

    *next_file = NULL;

    if (dirname_len == 0)
    {
        dirname_len = strlen(state->log_dir) + 1;
    }

    /* If we increment to today_tm's date, we stop below.  */
    today_time = globus_l_pbs_make_start_of_day(NULL);

    /* Copy the current log file path to next_path. We'll increment that
     * file name to the next day until we find a file or hit today.
     */
    next_path = strdup(state->path);
    if (next_path == NULL)
    {
        rc = SEG_PBS_ERROR_OUT_OF_MEMORY;
        goto strdup_failed;
    }
    if (globus_strptime(next_path + dirname_len, "%Y%m%d", &next_path_day)
            == NULL)
    {
        rc = SEG_PBS_ERROR_TIME;
        goto strptime_failed;
    }
    do
    {
        /* Increment the date to see if the next day's file exists */
        globus_l_pbs_increment_date(&next_path_day);

        if (strftime(next_path + dirname_len, 9, "%Y%m%d", &next_path_day) == 0)
        {
            rc = SEG_PBS_ERROR_TIME;
            goto strftime_failed;
        }

        errno = 0;
        rc = stat(next_path, &s);
        if (rc < 0)
        {
            switch (errno)
            {
                case EIO:               /* Error reading from filesystem */
                    SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                        ("Unable to stat logfile %s: %s\n",
                        state->path,
                        strerror(errno)));
                    rc = SEG_PBS_ERROR_BAD_PATH;

                    goto stat_failed;


                case ENOENT:
                    /* Doesn't exist, if we're looking into the future, give up
                     * and return NULL, otherwise, we'll continue to increment
                     * until we find one
                     */
                    SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                        ("file %s doesn't exist\n", next_path_day));

                    if (today_time <= mktime(&next_path_day))
                    {
                        SEGPbsDebug(SEG_PBS_DEBUG_WARN,
                            ("looking for file in the future!\n"));
                        rc = SEG_PBS_ERROR_LOG_NOT_PRESENT;
                        goto file_doesnt_exist;
                    }
                    break;

                case EACCES:            /* Bad permissions */
                    SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                        ("Unable to stat logfile %s: %s\n",
                        state->path,
                        strerror(errno)));

                    rc = SEG_PBS_ERROR_LOG_PERMISSIONS;
                    goto unable_to_access_file;

                /* Fatal errors */
                case ELOOP:             /* symlink loop */
                case ENAMETOOLONG:      /* filename too long */
                case ENOTDIR:           /* directory path is not a dir */
                case EOVERFLOW:         /* file size too big to represent in
                                         * stat struct */
                default:
                    SEGPbsDebug(SEG_PBS_DEBUG_ERROR,
                        ("Unable to stat logfile %s: %s\n",
                        state->path,
                        strerror(errno)));

                    rc = SEG_PBS_ERROR_BAD_PATH;
                    goto unable_to_access_file;
            }
        }
    }
    while ((rc != 0));

    *next_file = next_path;

    SEGPbsExit();
    return 0;
stat_failed:
file_doesnt_exist:
unable_to_access_file:
strptime_failed:
strftime_failed:
    free(next_path);
strdup_failed:
    SEGPbsExit();
    return rc;
}
/* globus_l_pbs_find_next() */

/**
 * Parse SEG events from the current log file in fp, returning 0 if
 * successful or EOF if end-of-file or an error was hit.
 * The value pointed to by end_of_parse is set to the offset in the
 * file to begin parsing from in the future if more data becomes available.
 */
static
int
globus_l_pbs_parse_events(
    globus_l_pbs_logfile_state_t *      state,
    FILE *                              fp,
    off_t *                             end_of_parse)
{
    char *                              sep;
    struct tm                           tm;
    time_t                              stamp;
    char *                              f;
    char *                              fields[15];
    size_t                              nfields;
    int                                 evttype;
    int                                 rc;
    int                                 exit_status;
    off_t                               start_of_line;
    int                                 parse_left=1024;

    GlobusFuncName(globus_l_pbs_parse_events);

    SEGPbsEnter();

    start_of_line = ftello(fp);
    while ((parse_left > 0) &&
        (rc = getline(&state->buffer, &state->buffer_length, fp)) > 0)
    {
        if (state->buffer[rc-1] != '\n')
        {
            /* Didn't get a full line, reset file pointer */
            *end_of_parse = start_of_line;
            return EOF;
        }

        nfields = 0;
        for (f = strtok_r(state->buffer, ";\n", &sep);
             f != NULL && nfields < 15;
             f = strtok_r(NULL, ";\n", &sep))
        {
            fields[nfields++] = f;
        }

        if (nfields < 3)
        {
            SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                    ("too few fields, freeing and getting next line\n"));
            goto too_few_fields;
        }

        sep = globus_strptime(fields[0], "%m/%d/%Y %H:%M:%S", &tm);
        if (sep == NULL || (((*sep) != '\0') && ((*sep) != '.')))
        {
            goto strptime_failed;
        }
        stamp = mktime(&tm);
        if (stamp == -1)
        {
            goto mktime_failed;
        }

        rc = sscanf(fields[1], "%04x", &evttype);
        if (rc < 1)
        {
            goto evttype_invalid;
        }
        rc = 0;

        if (stamp < state->start_timestamp)
        {
            /* Skip messages which are before our start timestamp */
            SEGPbsDebug(SEG_PBS_DEBUG_INFO,
                    ("skipping old event for %s\n", fields[4]));
            goto old_event;
        }

        switch (evttype)
        {
        case 0x0002: /* Batch System/Server Events */
            /* Might be "Log closed", but we don't care */
            break;

        case 0x0016: /* Job Resource Usage --- in v 5.1.2, the event type is
                        not hex, but we parsed it as such above */
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
            else if ((strcmp(fields[4], "req_commit") == 0) &&
                     (strstr(fields[5], "job_id:") == fields[5]))
            {
                const char *job_id = fields[5] + strlen("job_id: ");
                SEGPbsDebug(SEG_PBS_DEBUG_TRACE,
                        ("job %s pending\n", fields[4]));
                rc = globus_scheduler_event_pending(stamp, job_id);
            }
            break;
        }

mktime_failed:
old_event:
evttype_invalid:
strptime_failed:
too_few_fields:

        start_of_line = ftello(fp);
        parse_left--;
        rc = 0;
    }

    if (rc < 0)
    {
        rc = EOF;
    }

    *end_of_parse = start_of_line;

    SEGPbsExit();
    return rc;
}
/* globus_l_pbs_parse_events() */

/* Leap year is year divisible by 4, unless divisibly by 100 and not by 400 */
#define IS_LEAP_YEAR(Y) \
     (!(Y % 4)) && ((Y % 100) || !(Y % 400))
static
void
globus_l_pbs_increment_date(
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

    /* Increment day of the month */
    tm->tm_mday++;

    /* Handle end of month or year overflow */
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
/* globus_l_pbs_increment_date() */

/* Computes a time_t which is the start of a day. If the when param is
 * non-NULL, the returned value is the time_t value of the start of
 * the day containing *when. If when is NULL, the returned value is the
 * time_t value of the start of the current day.
 */
static
time_t
globus_l_pbs_make_start_of_day(time_t * when)
{
    time_t now = time(NULL);
    struct tm now_tm;

    if (when)
    {
        now = *when;
    }

    if (localtime_r(&now, &now_tm))
    {
        now_tm.tm_hour = 0;
        now_tm.tm_min = 0;
        now_tm.tm_sec = 0;

        return mktime(&now_tm);
    }
    else
    {
        return (time_t) -1;
    }
}
/* globus_l_pbs_get_start_of_day() */
