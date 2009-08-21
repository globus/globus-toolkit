/*
 * Copyright 1999-2009 University of Chicago
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
#include "globus_gram_job_manager.h"
#include "globus_scheduler_event_generator.h"
#include "globus_scheduler_event_generator_app.h"

#include <sys/types.h>
#include <utime.h>


typedef struct globus_gram_seg_resume_s
{
    globus_gram_job_manager_t *         manager;
    globus_list_t *                     events;
}
globus_gram_seg_resume_t;

globus_result_t
globus_l_gram_seg_event_callback(
    void *                              user_arg,
    const globus_scheduler_event_t *    event);

static
void
globus_l_gram_fork_poll_callback(
    void *                              user_arg);

static
int
globus_l_gram_deliver_event(
    globus_gram_jobmanager_request_t *  request,
    globus_scheduler_event_t *          event);

static
void
globus_l_seg_resume_callback(
    void *                              user_arg);

globus_result_t
globus_gram_job_manager_init_seg(
    globus_gram_job_manager_t *         manager)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 rc;

    globus_gram_job_manager_log(
            manager,
            "JM: Starting job monitoring for %s jobs\n",
            manager->config->jobmanager_type);

    GlobusGramJobManagerLock(manager);
    if (strcmp(manager->config->jobmanager_type, "fork") == 0)
    {
        globus_reltime_t                delay;

        GlobusTimeReltimeSet(delay, 1, 0);

        result = globus_callback_register_periodic(
                &manager->fork_callback_handle,
                &delay,
                &delay,
                globus_l_gram_fork_poll_callback,
                manager);
        if (result != GLOBUS_SUCCESS)
        {
            goto failed_periodic;
        }
    }
    else
    {
        globus_gram_job_manager_log(
                manager,
                "JM: activating SEG\n");

        rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);
        if (rc != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_log(
                    manager,
                    "JM: Error activating SEG: %d\n", rc);
        }

        globus_scheduler_event_generator_set_event_handler(
                globus_l_gram_seg_event_callback,
                manager);
        globus_scheduler_event_generator_set_timestamp(
                manager->seg_last_timestamp);
        setenv("JOB_MANAGER_SEG_SCHEDULER", manager->config->seg_module, 1);
        rc = globus_scheduler_event_generator_load_module(
                "job_manager");
        if (rc != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_log(
                    manager,
                    "JM: Error loading SEG job_manager module: %d\n", rc);
        }

    }
    manager->seg_started = GLOBUS_TRUE;
failed_periodic:
    GlobusGramJobManagerUnlock(manager);

    return result;
}
/* globus_gram_job_manager_init_seg() */

globus_result_t
globus_gram_job_manager_shutdown_seg(
    const char *                        seg_modele)
{
    globus_module_deactivate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_shutdown_seg() */

globus_result_t
globus_l_gram_seg_event_callback(
    void *                              user_arg,
    const globus_scheduler_event_t *    event)
{
    int                                 rc;
    globus_gram_job_manager_t *         manager = user_arg;
    globus_gram_jobmanager_request_t *  request;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_scheduler_event_t *          new_event;

    globus_gram_job_manager_log(
            manager,
            "SEG Event: Job %s in state %d\n",
            event->job_id,
            (int) event->event_type);
    if (event->event_type == GLOBUS_SCHEDULER_EVENT_RAW)
    {
        rc = GLOBUS_SUCCESS;
        goto raw_event;
    }

    result = globus_scheduler_event_copy(&new_event, event);
    if (result != GLOBUS_SUCCESS)
    {
        goto copy_failed;
    }

    GlobusGramJobManagerLock(manager);
    /* Find the job request associated by this job id */
    rc = globus_gram_job_manager_add_reference_by_jobid(
            manager,
            event->job_id,
            "SEG event",
            &request);

    if (rc != GLOBUS_SUCCESS)
    {
        if (manager->seg_pause_count > 0)
        {
            /* New submit script is running. Avoid race by adding this to the
             * manager-wide queue
             */
            globus_gram_job_manager_log(
                    manager,
                    "Submit running, queueing for later\n"); 
            rc = globus_fifo_enqueue(&manager->seg_event_queue, new_event);
        }
        else
        {
            globus_gram_job_manager_log(
                    manager,
                    "Unknown job ID, ignoring event\n");
        }
    }
    if (rc != GLOBUS_SUCCESS)
    {
        GlobusGramJobManagerUnlock(manager);
        goto manager_event_queue_failed;
    }
    else if (request == NULL)
    {
        /* Ignore unwanted event */
        GlobusGramJobManagerUnlock(manager);
        goto done;
    }
    else
    {
        if (event->timestamp > manager->seg_last_timestamp)
        {
            manager->seg_last_timestamp = event->timestamp;
        }
        GlobusGramJobManagerUnlock(manager);

        rc = globus_l_gram_deliver_event(
                request,
                new_event);
    }

    if (rc != GLOBUS_SUCCESS)
    {
        (void) globus_gram_job_manager_remove_reference(
                request->manager,
                request->job_contact_path,
                "SEG event");
manager_event_queue_failed:
        globus_scheduler_event_destroy(new_event);
copy_failed:
raw_event:
        ;
    }
done:
    result = GLOBUS_SUCCESS;
    return result;
}
/* globus_l_gram_seg_event_callback() */

void
globus_gram_job_manager_seg_handle_event(
    globus_gram_jobmanager_request_t *  request)
{
    globus_scheduler_event_t *          event;
    char *                              subjob_id_ptr = NULL;
    size_t                              subjob_id_len;
    globus_bool_t                       found_subjob_id;

    event = globus_fifo_dequeue(&request->seg_event_queue);

    globus_gram_job_manager_request_log(
            request,
            "JM: Handling event: %s is in state %d (%p)\n",
            event->job_id,
            event->event_type,
            request);


    found_subjob_id = GLOBUS_FALSE;
    subjob_id_len = strlen(event->job_id);
    while (!found_subjob_id)
    {
        subjob_id_ptr = strstr(request->job_id_string, event->job_id);
        assert(subjob_id_ptr != NULL);

        if (subjob_id_ptr == request->job_id_string ||
            (*(subjob_id_ptr - 1) == ','))
        {
            /* request->job_id_string starts with this subjob_id, or this
             * subjob_id happens after a comma. If it ends with a comma or
             * \0, then we've found a match.
             */
            if (subjob_id_ptr[subjob_id_len] == ',')
            {
                found_subjob_id = GLOBUS_TRUE;

                if (event->event_type == GLOBUS_SCHEDULER_EVENT_DONE ||
                    event->event_type == GLOBUS_SCHEDULER_EVENT_FAILED)
                {
                    /* Remove this sub job id from the list by moving
                     * after the comma up until \0 to subjob_id_ptr
                     */
                    memmove(subjob_id_ptr,
                            subjob_id_ptr + subjob_id_len + 1,
                            strlen(subjob_id_ptr + subjob_id_len + 1) + 1);
                }
            }
            else if (subjob_id_ptr[subjob_id_len] == 0)
            {
                /* This is the final subjob in the job_id_string */
                found_subjob_id = GLOBUS_TRUE;
                if (event->event_type == GLOBUS_SCHEDULER_EVENT_DONE ||
                    event->event_type == GLOBUS_SCHEDULER_EVENT_FAILED)
                {
                    /* Don't need to do memmove here, just null terminate at
                     * either the initial part of the string if subjob_id is
                     * the only one in the list, or at the comma otherwise
                     */
                    if (subjob_id_ptr != request->job_id_string)
                    {
                        *(subjob_id_ptr - 1) = '\0';
                    }
                    else
                    {
                        request->job_id_string[0] = '\0';
                    }
                }
            }
        }
    }

    assert(found_subjob_id);

    /* If this is a terminal event (done or failed), we'll update the expected
     * terminal state (in the case of a multi-subjob case) and the exit code
     * if the job's exit code is currently 0
     *
     * Thus, if any subjob fails or exits with a non-0 exit code, we will
     * propogate that in the job state change notification.
     */
    if (event->event_type == GLOBUS_SCHEDULER_EVENT_DONE ||
        event->event_type == GLOBUS_SCHEDULER_EVENT_FAILED)
    {
        if (request->expected_terminal_state ==
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
        {
            request->expected_terminal_state = event->event_type;
        }
        if (event->event_type == GLOBUS_SCHEDULER_EVENT_DONE &&
            request->exit_code == 0)
        {
            request->exit_code = event->exit_code;
        }
    }

    /* If the last job terminated or any job moved to active, we'll update the
     * job status and potentially send notifications.
     */
    if (event->event_type != GLOBUS_SCHEDULER_EVENT_DONE &&
         event->event_type != GLOBUS_SCHEDULER_EVENT_FAILED)
    {
        if (globus_i_gram_job_manager_script_valid_state_change(
                    request,
                    event->event_type))
        {
            globus_gram_job_manager_request_set_status(
                    request,
                    event->event_type);
            request->unsent_status_change = GLOBUS_TRUE;
        }
    }
    else if (*request->job_id_string == '\0')
    {
        if (globus_i_gram_job_manager_script_valid_state_change(
                    request,
                    request->expected_terminal_state))
        {
            globus_gram_job_manager_request_set_status(
                    request,
                    request->expected_terminal_state);
            request->unsent_status_change = GLOBUS_TRUE;
        }
    }

    globus_scheduler_event_destroy(event);

    (void) globus_gram_job_manager_remove_reference(
            request->manager,
            request->job_contact_path,
            "SEG event");
}
/* globus_gram_job_manager_seg_handle_event() */

void
globus_gram_job_manager_seg_pause(
    globus_gram_job_manager_t *         manager)
{
    globus_gram_job_manager_log(
            manager,
            "Pausing SEG (count -> %d)\n",
            manager->seg_pause_count+1);
    GlobusGramJobManagerLock(manager);
    manager->seg_pause_count++;
    GlobusGramJobManagerUnlock(manager);
}
/* globus_gram_job_manager_seg_pause() */

void
globus_gram_job_manager_seg_resume(
    globus_gram_job_manager_t *         manager)
{
    globus_result_t                     result;
    globus_scheduler_event_t *          event;
    globus_gram_seg_resume_t *          resume;

    globus_gram_job_manager_log(
            manager,
            "Resuming SEG (count -> %d)\n",
            manager->seg_pause_count-1);
    GlobusGramJobManagerLock(manager);
    manager->seg_pause_count--;

    if (manager->seg_pause_count == 0 &&
        !globus_fifo_empty(&manager->seg_event_queue))
    {
        globus_gram_job_manager_log(
                manager,
                "Scheduling resume oneshot\n");
        resume = malloc(sizeof(globus_gram_seg_resume_t));
        if (resume != NULL)
        {
            globus_reltime_t            delay;

            GlobusTimeReltimeSet(delay, 0, 0);

            resume->manager = manager;
            resume->events = globus_fifo_convert_to_list(
                    &manager->seg_event_queue);

            result = globus_callback_register_oneshot(
                    NULL,
                    &delay,
                    globus_l_seg_resume_callback,
                    resume);
            if (result != GLOBUS_SUCCESS)
            {
                while (!globus_list_empty(resume->events))
                {
                    event = globus_list_remove(&resume->events, resume->events);

                    globus_scheduler_event_destroy(event);
                }
            }
        }
    }
    GlobusGramJobManagerUnlock(manager);
}
/* globus_gram_job_manager_seg_resume() */

static
void
globus_l_seg_resume_callback(
    void *                              user_arg)
{
    globus_gram_seg_resume_t *          resume = user_arg;
    globus_scheduler_event_t *          event;
    globus_gram_jobmanager_request_t *  request;
    int                                 rc;

    globus_gram_job_manager_log(
            resume->manager,
            "Resume oneshot fired\n");
    while (!globus_list_empty(resume->events))
    {
        event = globus_list_remove(&resume->events, resume->events);

        GlobusGramJobManagerLock(resume->manager);
        rc = globus_gram_job_manager_add_reference_by_jobid(
                resume->manager,
                event->job_id,
                "SEG event",
                &request);
        if (rc != GLOBUS_SUCCESS)
        {
            GlobusGramJobManagerUnlock(resume->manager);
            globus_scheduler_event_destroy(event);
        }
        else
        {
            if (event->timestamp > request->manager->seg_last_timestamp)
            {
                request->manager->seg_last_timestamp = event->timestamp;
            }
            GlobusGramJobManagerUnlock(resume->manager);
            rc = globus_l_gram_deliver_event(
                    request,
                    event);
        }
    }
}
/* globus_l_seg_resume_callback() */

static
int
globus_l_gram_deliver_event(
    globus_gram_jobmanager_request_t *  request,
    globus_scheduler_event_t *          event)
{
    int                                 rc;
    globus_reltime_t                    delay_time;

    GlobusGramJobManagerRequestLock(request);

    globus_gram_job_manager_request_log(
            request,
            "Delivering event for %s to %s (%p)\n",
            event->job_id,
            request->job_contact_path,
            request);

    /* Keep the state file's timestamp up to date so that
     * anything scrubbing the state files of old and dead
     * processes leaves it alone */
    if(request->job_state_file)
    {
        utime(request->job_state_file, NULL);
    }

    globus_gram_job_manager_request_log(
    		request,
		"JM: Enqueuing SEG Event %s state %d, request in jm state %d\n",
		event->job_id,
		event->event_type,
		request->jobmanager_state);
    rc = globus_fifo_enqueue(&request->seg_event_queue, event);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto event_enqueue_failed;
    }

    if (event->event_type == GLOBUS_SCHEDULER_EVENT_DONE ||
        event->event_type ==  GLOBUS_SCHEDULER_EVENT_FAILED)
    {
        (void) globus_gram_job_manager_unregister_job_id(
                request->manager,
                event->job_id);
    }

    if (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
    {
        GlobusTimeReltimeSet(delay_time, 0, 0); 

        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;

        rc = globus_gram_job_manager_state_machine_register(
                request->manager,
                request,
                &delay_time);

        if (rc != GLOBUS_SUCCESS)
        {
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
        }
    }
    rc = GLOBUS_SUCCESS;

event_enqueue_failed:
    GlobusGramJobManagerRequestUnlock(request);

    return rc;
}
/* globus_l_gram_deliver_event() */

static
void
globus_l_gram_fork_poll_callback(
    void *                              user_arg)
{
    int                                 rc;
    globus_gram_job_manager_t *         manager = user_arg;
    globus_list_t *                     l;
    globus_scheduler_event_t *          event;
    globus_list_t *                     events = NULL;
    globus_gram_jobmanager_request_t *  request;
    int                                 pid_count = 0;
    int                                 done_count = 0;
    globus_list_t *                     job_id_list;
    globus_list_t *                     tmp;

    /* Walk the job id list, checking to see if the process has completed */
    rc = globus_gram_job_manager_get_job_id_list(
            manager,
            &job_id_list);

    for (tmp = job_id_list; tmp != NULL; tmp = globus_list_rest(tmp))
    {
        char *                          tok_end = NULL;
        char *                          pid_string;
        char *                          job_id_string;
        char *                          job_id_string_copy;

        job_id_string = globus_list_first(tmp);
        job_id_string_copy = strdup(job_id_string);
        if (job_id_string_copy == NULL)
        {
            continue;
        }

        pid_count = 0;
        done_count = 0;
        for (tok_end = NULL,
                    pid_string = strtok_r(job_id_string, ",", &tok_end);
             pid_string != NULL;
             pid_string = strtok_r(NULL, ",", &tok_end))
        {
            char *                      end = NULL;
            unsigned long               pid;

            pid_count++;
            errno = 0;
            pid = strtoul(pid_string, &end, 10);
            if ((pid == ULONG_MAX && errno != 0) || strlen(end) != 0)
            {
                continue;
            }

            if (kill((pid_t) pid, 0) < 0)
            {
                done_count++;
            }
        }

        if (pid_count == done_count && pid_count > 0)
        {
            /* Synthesize done event */
            event = malloc(sizeof(globus_scheduler_event_t));

            event->event_type = GLOBUS_SCHEDULER_EVENT_DONE;
            event->job_id = job_id_string_copy;
            event->timestamp = time(NULL);
            event->exit_code = 0;
            event->failure_code = 0;
            event->raw_event = NULL;

            globus_list_insert(&events, event);
        }
        else
        {
            free(job_id_string_copy);
        }
        free(job_id_string);
    }
    globus_list_free(job_id_list);

    /* Queue events in the request-specific SEG event queue */
    for (l = events; l != NULL; l = globus_list_rest(l))
    {
        event = globus_list_first(l);

        GlobusGramJobManagerLock(manager);
        rc = globus_gram_job_manager_add_reference_by_jobid(
                manager,
                event->job_id,
                "SEG event",
                &request);
        GlobusGramJobManagerUnlock(manager);

        if (rc == GLOBUS_SUCCESS)
        {
            rc = globus_l_gram_deliver_event(   
                    request,
                    event);

            if (rc != GLOBUS_SUCCESS)
            {
                goto destroy_event;
            }
        }

        if (rc != GLOBUS_SUCCESS)
        {
destroy_event:
            globus_scheduler_event_destroy(event);
        }
    }
    globus_list_free(events);
}
/* globus_l_gram_fork_poll_callback() */
