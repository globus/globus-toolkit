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

globus_result_t
globus_gram_job_manager_init_seg(
    globus_gram_jobmanager_request_t *  request)
{
    if (request->parent_jm)
    {
        globus_mutex_lock(&request->parent_jm->mutex);

        if (! request->parent_jm->seg_started)
        {
            globus_gram_job_manager_request_log(
                        request, 
                        "calling SEG initialization for parent jm\n");
            globus_gram_job_manager_init_seg(request->parent_jm);
        }
        request->seg_started = request->parent_jm->seg_started;

        globus_mutex_unlock(&request->parent_jm->mutex);

        return GLOBUS_SUCCESS;
    }

    globus_gram_job_manager_request_log(
                request, 
                "SEG initialization\n");

    globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);

    globus_scheduler_event_generator_set_event_handler(
            globus_l_gram_seg_event_callback,
            request);
    globus_scheduler_event_generator_set_timestamp(
            request->seg_last_timestamp);
    globus_libc_setenv("JOB_MANAGER_SEG_SCHEDULER", request->seg_module, 1);
    globus_scheduler_event_generator_load_module(
            "job_manager");

    request->seg_started = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_init_seg() */

globus_result_t
globus_gram_job_manager_shutdown_seg(
    globus_gram_jobmanager_request_t *  request)
{
    globus_module_deactivate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_init_seg() */

globus_result_t
globus_l_gram_seg_event_callback(
    void *                              user_arg,
    const globus_scheduler_event_t *    event)
{
    globus_gram_jobmanager_request_t *  request = user_arg;
    globus_bool_t                       event_registered;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_scheduler_event_t *          new_event;
    globus_gram_jobmanager_request_t *  tmp = NULL;

    if (event->event_type == GLOBUS_SCHEDULER_EVENT_RAW)
    {
        /* Deal with this later */
        return GLOBUS_SUCCESS;
    }

    globus_gram_job_manager_request_log(
                request, 
                "SEG event for %s, state = %d\n",
                event->job_id,
                request->status);

    globus_mutex_lock(&request->mutex);
    /* I don't think this is quite safe */
    if (request->restart_jms)
    {
        /* Find the job which this event relates to */
        globus_list_t *                 l;

        globus_gram_job_manager_request_log(
                    request, 
                    "Looking for child JM that has job id %s\n",
                    event->job_id);

        l = request->restart_jms;
        while (! globus_list_empty(l))
        {
            tmp = globus_list_first(l);
            l = globus_list_rest(l);

            if (strcmp(tmp->job_id, event->job_id) == 0)
            {
                globus_gram_job_manager_request_log(
                            request, 
                            "Found child JM that has job id %s: %p\n",
                            event->job_id,
                            tmp);
                break;
            }
            tmp = NULL;
        }
        if (tmp == NULL)
        {
            globus_gram_job_manager_request_log(
                        request, 
                        "Could not find child JM that has job id %s\n",
                        event->job_id);
        }
        globus_mutex_unlock(&request->mutex);
        request = tmp;

        if (request == NULL)
        {
            return GLOBUS_SUCCESS;
        }

        globus_mutex_lock(&request->mutex);
    }


    /* Keep the state file's timestamp up to date so that
     * anything scrubbing the state files of old and dead
     * processes leaves it alone */
    if(request->job_state_file)
    {
        utime(request->job_state_file, NULL);
    }

    if (strcmp(request->job_id, event->job_id) == 0)
    {
        result = globus_scheduler_event_copy(&new_event, event);

        if (result == GLOBUS_SUCCESS)
        {
            globus_fifo_enqueue(&request->seg_event_queue, new_event);
        }
        else
        {
            goto out;
        }

        if (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
        {
            do
            {
                event_registered =
                    globus_gram_job_manager_state_machine(request);
            }
            while (!event_registered);
        }
    }

    globus_mutex_unlock(&request->mutex);

out:
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
}
/* globus_gram_job_manager_seg_handle_event() */
