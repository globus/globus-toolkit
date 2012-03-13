/*
 * Copyright 1999-2010 University of Chicago
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

/*
 * @file globus_gram_streamer.c GRAM File Streamer Application
 *
 * @details
 *     The globus-gram-streamer program provides support for live file
 *     streaming of stdout and stderr. It is intended to be run by the fork
 *     job management module for cases where output streaming is required during
 *     the execution of the job. It is started as an additional process by
 *     the fork module and its pid is included along with the other pids that
 *     must be monitored for the job to be complete. 
 *     
 * CVS Information:
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_common.h"
#include "globus_gass_transfer.h"
#include "globus_gram_job_manager.h"
#include "globus_symboltable.h"

#include <sys/wait.h>

enum { STREAMER_MAX = 256 };
const off_t STREAMER_BLOCKSIZE = 4096;

typedef enum
{
    GLOBUS_GRAM_STREAM_NONE,
    GLOBUS_GRAM_STREAM_NEW,
    GLOBUS_GRAM_STREAM_ACTIVE,
    GLOBUS_GRAM_STREAM_RESTART,
    GLOBUS_GRAM_STREAM_RESTART_NEW,
    GLOBUS_GRAM_STREAM_FAIL,
    GLOBUS_GRAM_STREAM_DONE
}
globus_gram_stream_state_t;

typedef struct
{
    int                                 fd;
    off_t                               sent;
    char *                              source;
    char *                              destination;
    globus_gass_transfer_request_t      handle;
    globus_gram_stream_state_t          state;
    int                                 blocks;
    int                                 last_sent;
}
globus_gram_stream_t;

typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;

    globus_gram_jobmanager_request_t    request;

    globus_callback_handle_t            local_poll_periodic;
    time_t                              remote_io_url_file_time;

    globus_gram_stream_t                output_stream;
    globus_gram_stream_t                error_stream;

    globus_callback_handle_t            waitpids_poll_periodic;
    pid_t                               pids[STREAMER_MAX];
    int                                 pid_count;
}
globus_gram_streamer_monitor_t;

static
void
globus_l_gram_streamer_request_ready(
    void *                              arg,
    globus_gass_transfer_request_t      request);

static
void
globus_l_gram_streamer_local_poll(
    void *                              arg);

static
int
globus_l_gram_streamer_get_destinations(
    globus_gram_streamer_monitor_t *    monitor);

static
int
globus_l_gram_streamer_open_destination(
    globus_gram_streamer_monitor_t *    monitor,
    globus_gram_stream_t *              stream);

static
void
globus_l_gram_streamer_waitpids(
    void *                              arg);

int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 opt;
    globus_gram_streamer_monitor_t      monitor;
    int                                 rc;
    char                                local_path[16];
    globus_result_t                     result;
    globus_reltime_t                    period;
    globus_module_descriptor_t *        modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GASS_TRANSFER_MODULE,
        NULL
    };
    globus_module_descriptor_t *        failed_module;

    memset(&monitor, 0, sizeof(globus_gram_streamer_monitor_t));
    globus_mutex_init(&monitor.request.mutex, NULL);
    globus_cond_init(&monitor.request.cond, NULL);

    while ((opt = getopt(argc, argv, "s:p:d:h")) != -1)
    {
        switch (opt)
        {
            case 's':
                monitor.request.job_state_file = optarg;
                /*
                 * Assume that the remote I/O file will not be newer than the
                 * current time
                 */
                monitor.remote_io_url_file_time = time(NULL);
                rc = globus_gram_job_manager_state_file_read(&monitor.request);
                if (rc != GLOBUS_SUCCESS)
                {
                    fprintf(stderr, "%d:Error reading state file %s\n",
                            rc, optarg);
                }
                break;

            case 'p':
                if ((monitor.pid_count+1) == STREAMER_MAX)
                {
                    fprintf(stderr, "%d:Too many pids for streamer\n",
                            GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES);
                    exit(EXIT_FAILURE);
                }
                monitor.pids[monitor.pid_count++] =
                        (pid_t) strtol(optarg, NULL, 10);
                break;

            case 'd':
                rc = chdir(optarg);
                if (rc != 0)
                {
                    int save_errno = errno;
                    fprintf(stderr,
                            "%d:Error accessing job state directory: %s (%d)\n",
                            GLOBUS_GRAM_PROTOCOL_ERROR_BAD_DIRECTORY,
                            strerror(save_errno),
                            save_errno);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                printf("Usage: %s -s STATE-FILE -p pid [-p pid]...\n", argv[0]);
                exit(EXIT_SUCCESS);
                break;

            case '?':
            default:
                fprintf(stderr, "%d:Unknown option: %c\n",
                        GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED, 
                        (char) opt);
                exit(EXIT_FAILURE);
        }
    }

    rc = globus_module_activate_array(modules, &failed_module);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "%d:Activation failed: %s %d\n",
                GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED,
                failed_module->module_name,
                rc);
        exit(EXIT_FAILURE);
    }

    strcpy(local_path, "stdout");
    monitor.output_stream.fd = open(local_path, O_RDONLY);

    strcpy(local_path, "stderr");
    monitor.error_stream.fd = open(local_path, O_RDONLY);

    rc = globus_mutex_init(&monitor.mutex, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "%d:Mutex init failed\n",
                GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED);
        exit(EXIT_FAILURE);
    }
    rc = globus_cond_init(&monitor.cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "%d:Mutex init failed\n",
                GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED);
        exit(EXIT_FAILURE);
    }

    globus_mutex_lock(&monitor.mutex);

    GlobusTimeReltimeSet(period, 5, 0);
    result = globus_callback_register_periodic(
            &monitor.local_poll_periodic,
            &globus_i_reltime_zero,
            &period,
            globus_l_gram_streamer_local_poll,
            &monitor);
    if (result != GLOBUS_SUCCESS)
    {
        char * errstr = globus_error_print_friendly(globus_error_peek(result));
        fprintf(stderr, "%d:Initialization error: %s\n",
                GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED,
                errstr);
        free(errstr);
        exit(EXIT_FAILURE);
    }

    result = globus_callback_register_periodic(
            &monitor.waitpids_poll_periodic,
            &globus_i_reltime_zero,
            &period,
            globus_l_gram_streamer_waitpids,
            &monitor);
    if (result != GLOBUS_SUCCESS)
    {
        char * errstr = globus_error_print_friendly(globus_error_peek(result));
        fprintf(stderr, "%d:Initialization error: %s\n",
                GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED,
                errstr);
        free(errstr);
        exit(EXIT_FAILURE);
    }

    rc = globus_l_gram_streamer_get_destinations(
            &monitor);
    if (rc != GLOBUS_SUCCESS)
    {
        exit(EXIT_FAILURE);
    }

    if (monitor.output_stream.fd != -1 &&
        monitor.output_stream.destination != NULL)
    {
        rc = globus_l_gram_streamer_open_destination(
                &monitor,
                &monitor.output_stream);
        if (rc != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "%d:Error opening stdout destination %s (%d)\n",
                    GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDOUT,
                    monitor.output_stream.destination,
                    rc);
            exit(EXIT_FAILURE);
        }
        monitor.output_stream.state = GLOBUS_GRAM_STREAM_NEW;
    }
    else
    {
        monitor.output_stream.state = GLOBUS_GRAM_STREAM_NONE;
    }
    if (monitor.error_stream.fd != -1 &&
        monitor.error_stream.destination != NULL)
    {
        rc = globus_l_gram_streamer_open_destination(
                &monitor,
                &monitor.error_stream);
        if (rc != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "%d:Error opening stderr destination %s (%d)\n",
                    GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDERR,
                    monitor.error_stream.destination,
                    rc);
            exit(EXIT_FAILURE);
        }
        monitor.error_stream.state = GLOBUS_GRAM_STREAM_NEW;
    }
    else
    {
        monitor.error_stream.state = GLOBUS_GRAM_STREAM_NONE;
    }

    while (monitor.pid_count > 0 ||
           (monitor.output_stream.state != GLOBUS_GRAM_STREAM_NONE &&
            monitor.output_stream.state != GLOBUS_GRAM_STREAM_DONE &&
            monitor.output_stream.state != GLOBUS_GRAM_STREAM_FAIL) ||
           (monitor.error_stream.state != GLOBUS_GRAM_STREAM_NONE &&
            monitor.error_stream.state != GLOBUS_GRAM_STREAM_DONE &&
            monitor.error_stream.state != GLOBUS_GRAM_STREAM_FAIL))
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    if (monitor.output_stream.state == GLOBUS_GRAM_STREAM_DONE)
    {
        printf("%s %s\n",
               monitor.output_stream.source,
               monitor.output_stream.destination);
    }
    if (monitor.error_stream.state == GLOBUS_GRAM_STREAM_DONE)
    {
        printf("%s %s\n",
               monitor.error_stream.source,
               monitor.error_stream.destination);
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_module_deactivate(GLOBUS_GASS_TRANSFER_MODULE);
    globus_module_activate(GLOBUS_COMMON_MODULE);

    exit(EXIT_SUCCESS);
}
/* main() */

static
void
globus_l_gram_streamer_request_ready(
    void *                              arg,
    globus_gass_transfer_request_t      request)
{
    globus_gram_streamer_monitor_t *    monitor = arg;
    globus_gram_stream_t *              stream;
    globus_gass_transfer_request_status_t
                                        status;
    globus_mutex_lock(&monitor->mutex);
    stream = globus_gass_transfer_request_get_user_pointer(request);
    status = globus_gass_transfer_request_get_status(request);

    switch (status)
    {
    case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
    case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
        globus_gass_transfer_request_destroy(request);
        stream->state = GLOBUS_GRAM_STREAM_FAIL;
        globus_cond_signal(&monitor->cond);
        break;
    case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
    case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
        globus_gass_transfer_request_destroy(request);
        stream->state = GLOBUS_GRAM_STREAM_FAIL;
        globus_cond_signal(&monitor->cond);
        break;
    case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
        globus_gass_transfer_request_destroy(request);
        stream->state = GLOBUS_GRAM_STREAM_DONE;
        globus_cond_signal(&monitor->cond);
        break;
    case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
        globus_gass_transfer_request_destroy(request);
        stream->state = GLOBUS_GRAM_STREAM_DONE;
        globus_cond_signal(&monitor->cond);
        break;
    case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
        stream->state = GLOBUS_GRAM_STREAM_ACTIVE;
        break;
    default:
        fprintf(stderr, "%d:GASS Transfer returned invalid status: %d\n",
                GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED,
                (int) status);
        exit(EXIT_FAILURE);
    }
    globus_mutex_unlock(&monitor->mutex);
}

static
void
globus_l_gram_streamer_fail(
    void *                              arg,
    globus_gass_transfer_request_t      request)
{
    globus_gram_streamer_monitor_t *    monitor = arg;
    globus_gram_stream_t *              stream;

    globus_mutex_lock(&monitor->mutex);
    stream = globus_gass_transfer_request_get_user_pointer(request);
    stream->state = GLOBUS_GRAM_STREAM_RESTART_NEW;
    stream->sent = 0;
    stream->last_sent = GLOBUS_FALSE;
    lseek(stream->fd, 0, SEEK_SET);
    stream->handle = GLOBUS_NULL_HANDLE;
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_gram_streamer_fail() */

static
void
globus_l_gram_streamer_data_callback(
    void *                              arg,
    globus_gass_transfer_request_t      request,
    globus_byte_t *                     bytes,
    globus_size_t                       length,
    globus_bool_t                       last_data)
{
    globus_gram_streamer_monitor_t *    monitor = arg;
    globus_gram_stream_t *              stream;
    globus_gass_transfer_request_status_t
                                        status;

    globus_mutex_lock(&monitor->mutex);
    stream = globus_gass_transfer_request_get_user_pointer(request);
    free(bytes);
    stream->blocks--;
    status = globus_gass_transfer_request_get_status(request);

    if (last_data && stream->blocks == 0)
    {
        switch (status)
        {
        case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
        case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
        case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
        case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
        case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
            globus_gass_transfer_request_destroy(request);
            if (stream->state != GLOBUS_GRAM_STREAM_RESTART)
            {
                stream->state = GLOBUS_GRAM_STREAM_FAIL;
                globus_cond_signal(&monitor->cond);
            }
            break;
        case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
            globus_gass_transfer_request_destroy(request);
            if (stream->state == GLOBUS_GRAM_STREAM_ACTIVE)
            {
                stream->state = GLOBUS_GRAM_STREAM_DONE;
            }
            globus_cond_signal(&monitor->cond);
            break;
        case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
            break;
        default:
            fprintf(stderr, "%d:GASS Transfer returned invalid status: %d\n",
                    GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED,
                    (int) status);
            exit(EXIT_FAILURE);
        }
    }
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_gram_streamer_data_callback() */

static
void
globus_l_gram_streamer_local_poll(
    void *                              arg)
{
    globus_gram_streamer_monitor_t *    monitor = arg;
    int                                 rc;
    struct stat                         st;
    unsigned char *                     data;
    off_t                               data_size;
    globus_size_t                       amt;
    globus_bool_t                       last_data;
    int                                 i;
    char *                              save_state_file;
    globus_gram_stream_t *              streams[] =
    {
        &monitor->output_stream,
        &monitor->error_stream,
        NULL
    };
    globus_gram_stream_t *              stream;

    globus_mutex_lock(&monitor->mutex);

    /* Check if remote_io_file has changed */
    rc = stat("remote_io_file", &st);
    if (rc == 0)
    {
        if (st.st_mtime > monitor->remote_io_url_file_time)
        {
            /* Start the termination of the current output streams */
            for (i = 0; streams[i] != NULL; i++)
            {
	    	stream = streams[i];

                switch (stream->state)
                {
                case GLOBUS_GRAM_STREAM_NEW:
                case GLOBUS_GRAM_STREAM_ACTIVE:
                    globus_gass_transfer_fail(
                            stream->handle,
                            globus_l_gram_streamer_fail,
                            monitor);
                    stream->state = GLOBUS_GRAM_STREAM_RESTART;
                    break;
                case GLOBUS_GRAM_STREAM_FAIL:
                case GLOBUS_GRAM_STREAM_DONE:
                    stream->state = GLOBUS_GRAM_STREAM_RESTART_NEW;
                    stream->sent = 0;
                    stream->last_sent = GLOBUS_FALSE;
                    lseek(stream->fd, 0, SEEK_SET);
                    stream->handle = GLOBUS_NULL_HANDLE;
                    break;
                case GLOBUS_GRAM_STREAM_RESTART:
                case GLOBUS_GRAM_STREAM_RESTART_NEW:
                case GLOBUS_GRAM_STREAM_NONE:
                    break;
                }
            }
            monitor->remote_io_url_file_time = st.st_mtime;

            /* Load new state file */
            save_state_file = monitor->request.job_state_file;
            monitor->request.job_state_file = NULL;
            globus_gram_job_manager_request_free(&monitor->request);
            monitor->request.rsl = NULL;
            monitor->request.job_state_file = save_state_file;
            rc = globus_gram_job_manager_state_file_read(&monitor->request);
            if (rc != GLOBUS_SUCCESS)
            {
                fprintf(stderr, "%d:",
                        rc);
                exit(EXIT_FAILURE);
            }

            if (monitor->output_stream.source != NULL)
            {
                free(monitor->output_stream.source);
                monitor->output_stream.source = NULL;
            }
            if (monitor->output_stream.destination != NULL)
            {
                free(monitor->output_stream.destination);
                monitor->output_stream.destination = NULL;
            }
            if (monitor->error_stream.source != NULL)
            {
                free(monitor->error_stream.source);
                monitor->error_stream.source = NULL;
            }
            if (monitor->error_stream.destination != NULL)
            {
                free(monitor->error_stream.destination);
                monitor->error_stream.destination = NULL;
            }
            /* Re-evaluate RSL */
            rc = globus_l_gram_streamer_get_destinations(
                    monitor);
        }
    }

    /* On the first poll after everything is ready to restart, we'll reload
     * state information and reopen the stream
     */
    for (i = 0; streams[i] != NULL; i++)
    {
        stream = streams[i];

	if (stream->state == GLOBUS_GRAM_STREAM_RESTART_NEW)
	{
	    /* Re-open output stream */
	    if (stream->fd != -1 &&
		stream->destination != NULL)
	    {
		rc = globus_l_gram_streamer_open_destination(
			monitor,
			stream);
		if (rc == GLOBUS_SUCCESS)
		{
		    stream->state = GLOBUS_GRAM_STREAM_NEW;
		}
		else
		{
		    stream->state = GLOBUS_GRAM_STREAM_FAIL;
		}
	    }
	    else
	    {
		stream->state = GLOBUS_GRAM_STREAM_DONE;
	    }
	}
    }

    /* Only queue data if the transfer is alive */
    for (i = 0; streams[i] != NULL; i++)
    {
        stream = streams[i];

        if (stream->state == GLOBUS_GRAM_STREAM_ACTIVE &&
            (fstat(stream->fd, &st) == 0))
        {
            data_size = st.st_size - stream->sent;
            if (data_size > STREAMER_BLOCKSIZE)
            {
                data_size = STREAMER_BLOCKSIZE;
            }
            amt = 0;

            data = NULL;
            if (data_size > 0)
            {
                data = malloc((size_t) data_size);

                do
                {
                    rc = read(stream->fd, data + amt, data_size - amt);
                    if (rc < 0)
                    {
                        if (errno != EINTR)
                        {
                            break;
                        }
                    }
                    else if (rc == 0)
                    {
                        break;
                    }
                    else
                    {
                        amt += rc;
                    }
                }
                while (amt < data_size);
            }
            if (amt > 0 || ((monitor->pid_count == 0) && (!stream->last_sent)))
            {
                stream->sent += amt;
                stream->blocks++;

                last_data = (monitor->pid_count == 0) &&
                            (stream->sent == st.st_size);

                rc = globus_gass_transfer_send_bytes(
                        stream->handle,
                        (data == NULL) ? malloc(1) : data,
                        amt,
                        last_data,
                        globus_l_gram_streamer_data_callback,
                        monitor);
                switch (rc)
                {
                case GLOBUS_SUCCESS:
                    stream->last_sent = last_data;
                    break;
                case GLOBUS_GASS_TRANSFER_ERROR_NULL_POINTER:
                    fprintf(stderr, "NULL pointer");
                    exit(EXIT_FAILURE);
                    break;
                case GLOBUS_GASS_TRANSFER_ERROR_INVALID_USE:
                    stream->last_sent = GLOBUS_TRUE;
                    globus_gass_transfer_request_destroy(stream->handle);
                    stream->state = GLOBUS_GRAM_STREAM_FAIL;
                    break;
                case GLOBUS_GASS_TRANSFER_ERROR_NOT_INITIALIZED:
                    fprintf(stderr, "Not initialized");
                    exit(EXIT_FAILURE);
                    break;
                case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
                    fprintf(stderr, "Failed ");
                    exit(EXIT_FAILURE);

                }
            }
        }
    }
    globus_mutex_unlock(&monitor->mutex);
}

static
int
globus_l_gram_streamer_get_destinations(
    globus_gram_streamer_monitor_t *    monitor)
{
    globus_list_t *                     tmp;
    globus_gram_job_manager_staging_info_t *
                                        info;
    char *                              s;

    tmp = monitor->request.stage_stream_todo;

    while (tmp != NULL)
    {
        info = globus_list_first(tmp);
        tmp = globus_list_rest(tmp);

        if (monitor->output_stream.destination == NULL)
        {
            s = strstr(info->evaled_from, "/stdout");
            if (s != NULL && strcmp(s, "/stdout") == 0)
            {
                monitor->output_stream.source = strdup(info->evaled_from);
                monitor->output_stream.destination = strdup(info->evaled_to);
                continue;
            }
        }

        if (monitor->error_stream.destination == NULL)
        {
            s = strstr(info->evaled_from, "/stderr");
            if (s != NULL && strcmp(s, "/stderr") == 0)
            {
                monitor->error_stream.source = strdup(info->evaled_from);
                monitor->error_stream.destination = strdup(info->evaled_to);
                continue;
            }
        }
    }
    return 0;
}

static
int
globus_l_gram_streamer_open_destination(
    globus_gram_streamer_monitor_t *    monitor,
    globus_gram_stream_t *              stream)
{
    globus_gass_transfer_requestattr_t  attr;
    char                                scheme[16];
    int                                 i;
    int                                 rc;

    for (i = 0; i < sizeof(scheme); i++)
    {
        if (stream->destination[i] == ':')
        {
            scheme[i] = 0;
            break;
        }
        else
        {
            scheme[i] = stream->destination[i];
        }
    }
    scheme[15] = 0;

    rc = globus_gass_transfer_requestattr_init(
            &attr,
            scheme);
    if (rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    rc = globus_gass_transfer_register_append(
            &stream->handle,
            &attr,
            (char *) stream->destination,
            GLOBUS_GASS_TRANSFER_LENGTH_UNKNOWN,
            globus_l_gram_streamer_request_ready,
            monitor);

    if (rc == GLOBUS_SUCCESS)
    {
        (void) globus_gass_transfer_request_set_user_pointer(
                stream->handle,
                stream);
    }

    (void) globus_gass_transfer_requestattr_destroy(&attr);

    return rc;
}
/* globus_l_gram_streamer_open_destination() */

/**
 * @brief Determine if the job's processes are still running
 *
 * The globus_l_gram_streamer_waitpids() function is called periodically to
 * check whether the pids associated with this streamer are still running.
 * If they are all complete, globus_l_gram_streamer_waitpids() will signal
 * the main thread and disable this callback from being called again.
 */
static
void
globus_l_gram_streamer_waitpids(
    void *                              arg)
{
    int                                 i;
    globus_gram_streamer_monitor_t *    monitor = arg;

    globus_mutex_lock(&monitor->mutex);
    for (i = 0; i < STREAMER_MAX; i++)
    {
        if (monitor->pids[i] == 0)
        {
            continue;
        }
        if (kill(monitor->pids[i], 0) == -1)
        {
            monitor->pids[i] = 0;
            monitor->pid_count--;
        }
    }

    if (monitor->pid_count == 0)
    {
        globus_cond_signal(&monitor->cond);
        globus_callback_unregister(
                monitor->waitpids_poll_periodic,
                NULL,
                NULL,
                NULL);
    }

    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_gram_streamer_waitpids */
