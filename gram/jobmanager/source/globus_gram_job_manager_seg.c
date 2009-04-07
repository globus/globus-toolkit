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

globus_result_t
globus_l_gram_seg_event_callback(
    void *                              user_arg,
    const globus_scheduler_event_t *    event);

static
void
globus_l_gram_fork_poll_callback(
    void *                              user_arg);

globus_result_t
globus_gram_job_manager_init_seg(
    globus_gram_job_manager_t *         manager)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    globus_mutex_lock(&manager->mutex);
    if (strcmp(manager->config->jobmanager_type, "fork") == 0)
    {
        globus_reltime_t                delay;

        GlobusTimeReltimeSet(delay, 10, 0);

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
        globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);

        globus_scheduler_event_generator_set_event_handler(
                globus_l_gram_seg_event_callback,
                manager);
        globus_scheduler_event_generator_set_timestamp(
                manager->seg_last_timestamp);
        setenv("JOB_MANAGER_SEG_SCHEDULER", manager->config->seg_module, 1);
        globus_scheduler_event_generator_load_module(
                "job_manager");

    }
    manager->seg_started = GLOBUS_TRUE;
failed_periodic:
    globus_mutex_unlock(&manager->mutex);

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

    if (event->event_type == GLOBUS_SCHEDULER_EVENT_RAW)
    {
        rc = GLOBUS_SUCCESS;
        goto raw_event;
    }

    /* Find the job request associated by this job id */
    rc = globus_gram_job_manager_add_reference_by_jobid(
            manager,
            event->job_id,
            &request);

    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_SUCCESS;
        goto no_matching_request;
    }

    globus_mutex_lock(&request->mutex);
    /* Keep the state file's timestamp up to date so that
     * anything scrubbing the state files of old and dead
     * processes leaves it alone */
    if(request->job_state_file)
    {
        utime(request->job_state_file, NULL);
    }

    result = globus_scheduler_event_copy(&new_event, event);
    if (result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto copy_event_failed;
    }
    rc = globus_fifo_enqueue(&request->seg_event_queue, new_event);

    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto event_enqueue_failed;
    }

    if (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
    {
        globus_reltime_t                delay_time;

        GlobusTimeReltimeSet(delay_time, 0, 0); 

        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;

        result = globus_callback_register_oneshot(
                &request->poll_timer,
                &delay_time,
                globus_gram_job_manager_state_machine_callback,
                request);

        if (result != GLOBUS_SUCCESS)
        {
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
        }
    }

event_enqueue_failed:
    if (rc != GLOBUS_SUCCESS)
    {
        free(new_event);
    }
    
copy_event_failed:
    globus_mutex_unlock(&request->mutex);

    if (rc != GLOBUS_SUCCESS)
    {
        (void) globus_gram_job_manager_remove_reference(
                request->manager,
                request->job_contact_path);

no_matching_request:
raw_event:
        ;
    }
    return result;
}
/* globus_l_gram_seg_event_callback() */

void
globus_gram_job_manager_seg_handle_event(
    globus_gram_jobmanager_request_t *  request)
{
    globus_scheduler_event_t *          event;

    event = globus_fifo_dequeue(&request->seg_event_queue);

    if (globus_i_gram_job_manager_script_valid_state_change(
        request, event->event_type))
    {
        globus_gram_job_manager_request_set_status(
                request,
                event->event_type);
        request->unsent_status_change = GLOBUS_TRUE;
    }

    globus_scheduler_event_destroy(event);

    (void) globus_gram_job_manager_remove_reference(
            request->manager,
            request->job_contact_path);
}
/* globus_gram_job_manager_seg_handle_event() */

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

        job_id_string = globus_list_first(tmp);

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
            event->job_id = strdup(globus_list_first(tmp));
            event->timestamp = time(NULL);
            event->exit_code = 0;
            event->failure_code = 0;
            event->raw_event = NULL;

            globus_list_insert(&events, event);
        }
        free(job_id_string);
    }
    globus_list_free(job_id_list);

    /* Queue events in the request-specific SEG event queue */
    for (l = events; l != NULL; l = globus_list_rest(l))
    {
        event = globus_list_first(l);

        rc = globus_gram_job_manager_add_reference_by_jobid(
                manager,
                event->job_id,
                &request);

        if (rc == GLOBUS_SUCCESS)
        {
            globus_mutex_lock(&request->mutex);
            /* Keep the state file's timestamp up to date so that
             * anything scrubbing the state files of old and dead
             * processes leaves it alone */
            if(request->job_state_file)
            {
                utime(request->job_state_file, NULL);
            }
            rc = globus_fifo_enqueue(
                    &request->seg_event_queue,
                    event);
            if (request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
            {
                globus_reltime_t                delay_time;
                globus_result_t                 result;

                GlobusTimeReltimeSet(delay_time, 0, 0); 

                request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;

                result = globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay_time,
                        globus_gram_job_manager_state_machine_callback,
                        request);

                if (result != GLOBUS_SUCCESS)
                {
                    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
                }
            }
            globus_mutex_unlock(&request->mutex);
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
