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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_job_manager_state.c Job Manager State Machine
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#include "globus_gram_job_manager.h"
#include "globus_rsl_assist.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_system_config_constants.h"

#include <string.h>


/* Module Specific Prototypes */

static
globus_bool_t
globus_l_gram_job_manager_set_restart_state(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_job_manager_add_cache_info(
    globus_gram_jobmanager_request_t *  request);

static
void
globus_l_gram_job_manager_cancel_queries(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_remote_io_url_update(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_gss_send_fd(
    void *                              arg,
    void *                              buffer,
    size_t                              length);

static
void
globus_l_gram_file_cleanup(
    globus_gram_jobmanager_request_t *  request);

#ifdef BUILD_DEBUG

#   define GLOBUS_GRAM_JOB_MANAGER_INVALID_STATE(request) \
        globus_gram_job_manager_request_log(request, \
                      "Invalid Job Manager State %s\n", \
                          globus_l_gram_job_manager_state_string(\
                              request->jobmanager_state));\
        globus_assert(0);

#   define GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, when) \
        globus_gram_job_manager_request_log(request, \
                          "Job Manager State Machine (%s): %s\n", \
                          when, \
                          globus_l_gram_job_manager_state_string(\
                              request->jobmanager_state));
static
const char *
globus_l_gram_job_manager_state_string(
    globus_gram_jobmanager_state_t      state);
#else

#   define GLOBUS_GRAM_JOB_MANAGER_INVALID_STATE(request)
#   define GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, when)

#endif
#endif

/*
 * Callback to enter the state machine from a timeout. Used to
 * handle two-phase commit timeouts, and delays between calls to the
 * poll script.
 */
void
globus_gram_job_manager_state_machine_callback(
    void *                              user_arg)
{
    globus_gram_jobmanager_request_t *  request;
    globus_bool_t                       event_registered;

    request = user_arg;

    globus_mutex_lock(&request->mutex);

    /*
     * If nobody tried to cancel this callback, then we need to unregister
     * it to free memory in the callback code.
     */
    if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
    {
        globus_callback_unregister(request->poll_timer, NULL, NULL, NULL);
        request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
    }
    
    do
    {
        event_registered = globus_gram_job_manager_state_machine(
                request);
    }
    while(!event_registered);

    if (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE ||
        request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_DONE ||
        request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE)
    {
        int rc;

        if (request->job_id_string)
        {
            (void) globus_gram_job_manager_unregister_job_id(
                    request->manager,
                    request->job_id_string);
        }

        while (!globus_fifo_empty(&request->seg_event_queue))
        {
            globus_gram_job_manager_seg_handle_event(request);
        }

        globus_mutex_unlock(&request->mutex);

        rc = globus_gram_job_manager_remove_reference(
                request->manager,
                request->job_contact_path);
        assert(rc == GLOBUS_SUCCESS);
    }
    else
    {
        globus_mutex_unlock(&request->mutex);
    }
}
/* globus_gram_job_manager_state_machine_callback() */


/*
 * Job Manager state machine.
 */
globus_bool_t
globus_gram_job_manager_state_machine(
    globus_gram_jobmanager_request_t *  request)
{
    globus_bool_t                       event_registered = GLOBUS_FALSE;
    globus_reltime_t                    delay_time;
    int                                 rc = 0;
    int                                 save_status;
    int                                 save_jobmanager_state;
    globus_gram_job_manager_query_t *   query;
    globus_bool_t                       first_poll = GLOBUS_FALSE;
    globus_gram_jobmanager_state_t      next_state;

    GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, "entering");

    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE;
        /*
         * To do a two-phase commit, we need to send an error
         * message (WAITING_FOR_COMMIT) in the initial reply; otherwise,
         * we just return the current status code.
         * 
         * When doing a dry run, we don't send the reply until we would
         * submit the job (no state callbacks with a dry-run.)
         */
        if(!request->dry_run)
        {
            if(request->two_phase_commit != 0 && rc == GLOBUS_SUCCESS)
            {
                GlobusTimeReltimeSet(delay_time,
                                     request->two_phase_commit,
                                     0);

                globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay_time,
                        globus_gram_job_manager_state_machine_callback,
                        request);

                event_registered = GLOBUS_TRUE;
            }
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
        if(request->two_phase_commit != 0 && request->commit_extend != 0)
        {
            GlobusTimeReltimeSet(delay_time,
                                 request->commit_extend,
                                 0);

            globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay_time,
                        globus_gram_job_manager_state_machine_callback,
                        request);

            request->commit_extend = 0;

            event_registered = GLOBUS_TRUE;
        }
        else if(request->two_phase_commit == 0)
        {
            /* Nothing to do here if we are not doing the two-phase
             * commit protocol
             */
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED;
        }
        else if(request->jm_restart)
        {
            /*
             * commit didn't happen, but this was a restart of a job manager
             * so we'll just stop and leave the job manager state.
             */
            request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
        }
        else
        {
            request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
            /* Send failed message later */
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT;
            request->unsent_status_change = GLOBUS_TRUE;
            /* Don't do two-phase commit after sending FAILED state change */
            request->two_phase_commit = 0;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
        if(request->jm_restart)
        {
            if(globus_l_gram_job_manager_set_restart_state(request))
            {
                break;
            }
        }
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN;

        if(globus_gram_job_manager_rsl_need_stage_in(request))
        {
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN);

            if(!request->dry_run)
            {
                globus_gram_job_manager_contact_state_callback(request);
            }

            rc = globus_gram_job_manager_script_stage_in(request);

            if(rc != GLOBUS_SUCCESS)
            {
                request->failure_code = rc;
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            }
            else
            {
                event_registered = GLOBUS_TRUE;
            }
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
        if((!globus_list_empty(request->stage_in_todo)) ||
           (!globus_list_empty(request->stage_in_shared_todo)))
        {
            /* Didn't successfully stage in everything. */
            request->jobmanager_state = 
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            if(request->failure_code == GLOBUS_SUCCESS)
            {
                request->failure_code =
                    GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_IN_FAILED;
            }
            break;
        }
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT;

        if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED && 
           request->dry_run)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;

            break;
        }
        else if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
        {
            request->jobmanager_state = 
                    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            break;
        }

        request->manager->seg_last_timestamp = time(NULL);

        globus_gram_job_manager_seg_pause(request->manager);

        rc = globus_gram_job_manager_script_submit(request);

        if(rc != GLOBUS_SUCCESS)
        {
            request->failure_code = rc;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);

            if(!request->dry_run)
            {
                request->jobmanager_state = 
                        GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
                request->unsent_status_change = GLOBUS_TRUE;
            }
            globus_gram_job_manager_seg_resume(request->manager);
        }
        else
        {
            event_registered = GLOBUS_TRUE;
        }

        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
        if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED && 
           request->dry_run)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;

            globus_gram_job_manager_seg_resume(request->manager);
            break;
        }
        else if(request->job_id_string == NULL)
        {
            /* submission failed to generate a job id */
            if(request->failure_code == GLOBUS_SUCCESS)
            {
                request->failure_code =
                    GLOBUS_GRAM_PROTOCOL_ERROR_SUBMIT_UNKNOWN;
            }
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
            request->unsent_status_change = GLOBUS_TRUE;
            globus_gram_job_manager_seg_resume(request->manager);
        }
        else
        {
            rc = globus_gram_job_manager_register_job_id(
                    request->manager,
                    request->job_id_string,
                    request);
            if (rc != GLOBUS_SUCCESS)
            {
                request->failure_code = rc;
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
                request->unsent_status_change = GLOBUS_TRUE;
            }
            globus_l_gram_job_manager_add_cache_info(request);
            globus_gram_job_manager_seg_resume(request->manager);
        }
        request->queued_time = time(NULL);
        globus_gram_job_manager_history_file_create(request);
        request->job_history_status = request->status;

        globus_gram_job_manager_state_file_write(request);
        request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
        first_poll = GLOBUS_TRUE;
        
        /* FALLSTHROUGH so we can act on a job state change returned from
         * the submit script.
         */
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
        if (! globus_fifo_empty(&request->seg_event_queue))
        {
            /* A SEG event occurred recently. Let's update our job state
             */
            globus_gram_job_manager_seg_handle_event(request);

        }
        if(request->unsent_status_change)
        {
            globus_gram_job_manager_state_file_write(request);
        }

        /* The request->job_history_status is used to save the last job status
         * that is stored in history file. If it is different with
         * request->status, we have to write history file.
         */ 
        if(request->unsent_status_change &&
                (request->job_history_status != request->status))
        {
            globus_gram_job_manager_history_file_create(request);
            request->job_history_status = request->status;
        }

        if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
        }
        else if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
        {
            /* Job finished! start finalizing */
            if(globus_gram_job_manager_rsl_need_stage_out(request))
            {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT);
                globus_gram_job_manager_contact_state_callback(request);
            }
            request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT;
            break;
        }
        else
        {
            /* Send job state callbacks if necessary */
            if(request->unsent_status_change)
            {
                globus_gram_job_manager_contact_state_callback(request);
                request->unsent_status_change = GLOBUS_FALSE;
            }

            if(!globus_fifo_empty(&request->pending_queries))
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
                break;
            }
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;

            if ((request->config->seg_module != NULL ||
                 strcmp(request->config->jobmanager_type, "fork") == 0) &&
                !request->manager->seg_started)
            {
                /* We want to use the SEG or fork fakeseg, so we'll start that
                 * up. We won't have to reregister the callback after each
                 * event in this case.
                 */
                rc = globus_gram_job_manager_init_seg(request->manager);

                if (rc != GLOBUS_SUCCESS)
                {
                    /* Error starting the SEG. Fallback to non-SEG mode */
                    request->config->seg_module = NULL;
                }
                else
                {
                    /* SEG was now started. When an event arrives, it will
                     * be enqueued and then state will change to POLL1
                     */
                    event_registered = GLOBUS_TRUE;
                }
            }
            else if((! first_poll) && request->config->seg_module == NULL)
            {
                /* Register next poll of job state */
                GlobusTimeReltimeSet(
                        delay_time,
                        request->poll_frequency, 0);

                globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay_time,
                        globus_gram_job_manager_state_machine_callback,
                        request);
                event_registered = GLOBUS_TRUE;
            }
            else
            {
                /* SEG has been started. If there is an event pending,
                 * we should jump to POLL1 state and not set
                 * event_registered, so that we can process it.
                 *
                 * Otherwise, we'll set event_registered and the next
                 * query or SEG event will move the state machine.
                 */
                if (! globus_fifo_empty(&request->seg_event_queue))
                {

                    request->jobmanager_state =
                        GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
                }
                else
                {
                    event_registered = GLOBUS_TRUE;
                }
            }
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
        /* timer expired since last poll. start polling again. */

        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;

        if (request->config->seg_module == NULL)
        {
            rc = globus_gram_job_manager_script_poll(request);
        }
        else if (!globus_fifo_empty(&request->seg_event_queue))
        {
            /* We don't want to set event_registered in this case, because
             * we want to immediately process the event in the queue.
             */
            break;
        }

        if(rc != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_request_log(
                request,
                "Error polling job... resources temporarily depleted?\n");
        }
        else
        {
            event_registered = GLOBUS_TRUE;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1:
        if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1)
        {
            next_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2;
        }
        else
        {
            next_state = GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2;
        }

        /*
         * timer cancelled since last poll, because we may have some
         * queries to process
         */
        query = globus_fifo_peek(&request->pending_queries);

        if (query->type == GLOBUS_GRAM_JOB_MANAGER_SIGNAL)
        {
            rc = globus_gram_job_manager_script_signal(
                    request,
                    query);
        }
        else if(query->type == GLOBUS_GRAM_JOB_MANAGER_CANCEL)
        {
            rc = globus_gram_job_manager_script_cancel(
                    request,
                    query);
        }
        else if(query->type == GLOBUS_GRAM_JOB_MANAGER_PROXY_REFRESH)
        {
            if (request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1)
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH;
            }
            else
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH;
            }
            rc = globus_gram_protocol_accept_delegation(
                    query->handle,
                    GSS_C_NO_OID_SET,
                    GSS_C_NO_BUFFER_SET,
                    GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
                        GSS_C_GLOBUS_SSL_COMPATIBLE,
                    0,
                    globus_gram_job_manager_query_delegation_callback,
                    request);

            if(rc == GLOBUS_SUCCESS)
            {
                event_registered = GLOBUS_TRUE;
            }
            break;
        }
        if(rc == GLOBUS_SUCCESS)
        {
            request->jobmanager_state = next_state;

            event_registered = GLOBUS_TRUE;
        }
        else
        {
            globus_fifo_dequeue(&request->pending_queries);
            query->failure_code = rc;

            globus_gram_job_manager_query_reply(request, query);

            if(globus_fifo_empty(&request->pending_queries))
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
            }
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2:
        query = globus_fifo_dequeue(&request->pending_queries);

        /* Frees the query */
        globus_gram_job_manager_query_reply(
                request,
                query);

        if(globus_fifo_empty(&request->pending_queries))
        {
            GlobusTimeReltimeSet(delay_time,
                                 request->two_phase_commit,
                                 0);

            globus_callback_register_oneshot(
                    &request->poll_timer,
                    &delay_time,
                    globus_gram_job_manager_state_machine_callback,
                    request);

            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE;

            event_registered = GLOBUS_TRUE;
        }
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
        query = globus_fifo_dequeue(&request->pending_queries);

        /* Frees the query */
        globus_gram_job_manager_query_reply(
                request,
                query);

        if(globus_fifo_empty(&request->pending_queries) &&
           (request->unsent_status_change ||
            !globus_fifo_empty(&request->seg_event_queue)))
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
        }
        else if(globus_fifo_empty(&request->pending_queries))
        {
            request->jobmanager_state = 
                GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
        }
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
        }
        break;
    
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH:
        query = globus_fifo_peek(&request->pending_queries);

        globus_assert(query->type == GLOBUS_GRAM_JOB_MANAGER_PROXY_REFRESH);

        if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH)
        {
            request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2;
        }
        else if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH)
        {
            request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2;
        }

        if(query->delegated_credential != GSS_C_NO_CREDENTIAL)
        {
            /*
             * We got a new credential... update our listener and
             * store it on disk
             */
            rc = globus_gram_job_manager_gsi_update_credential(
                    request,
                    query->delegated_credential);
            if(rc != GLOBUS_SUCCESS)
            {
                break;
            }

            rc = globus_gram_job_manager_gsi_update_proxy_timeout(
                    request->manager,
                    query->delegated_credential,
                    request->config->proxy_timeout,
                    &request->manager->proxy_expiration_timer);
            if(rc != GLOBUS_SUCCESS)
            {
                break;
            }
        }
        else
        {
            query->failure_code =
                GLOBUS_GRAM_PROTOCOL_ERROR_DELEGATION_FAILED;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
        if(request->unsent_status_change)
        {
            globus_gram_job_manager_state_file_write(request);
        }
        if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT;
        }
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
        }
        save_status = request->status;
        save_jobmanager_state = request->jobmanager_state;

        /* Reply to any outstanding queries */
        while (!globus_fifo_empty(&request->pending_queries))
        {
            query = globus_fifo_dequeue(&request->pending_queries);

            query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
            /* Frees the query */
            globus_gram_job_manager_query_reply(
                    request,
                    query);
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
        if(request->two_phase_commit != 0 && request->commit_extend != 0)
        {
            GlobusTimeReltimeSet(delay_time,
                                 request->commit_extend,
                                 0);

            globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay_time,
                        globus_gram_job_manager_state_machine_callback,
                        request);

            request->commit_extend = 0;

            event_registered = GLOBUS_TRUE;
        }
        else if(request->two_phase_commit == 0 || !request->client_contacts)
        {
            /* Nothing to do here if we are not doing the two-phase
             * commit protocol or if we have no client callbacks
             */
            if(request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED;
            }
            else
            {
                request->jobmanager_state =
                  GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
            }
        }
        else
        {
            request->jobmanager_state = 
                GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;
            globus_l_gram_job_manager_cancel_queries(request);

            event_registered = GLOBUS_TRUE;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
        if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP;
        }
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP;
        }
        if(globus_gram_job_manager_rsl_need_file_cleanup(request))
        {
            globus_l_gram_file_cleanup(request);
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
        if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP)
        {
            if(request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP;
            }
            else
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
            }
        }
        else if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
        }
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
        }

        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
        if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP;
        }
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP;
        }

        /* Cache cleanup script cleaned gass cache and jobdir */
        globus_gram_job_manager_destroy_directory(
                request,
                request->job_dir);
        globus_gram_job_manager_request_log(
                request,
                "Cleaning up cache tag %s\n",
                request->cache_tag);
        globus_gass_cache_cleanup_tag_all(
                request->cache_handle,
                request->cache_tag);
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP:
        if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_DONE;
        }
        else
        {
            request->jobmanager_state = 
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
        }
        
        if(request->job_state_file)
        {
            remove(request->job_state_file);
        }
        if(request->job_state_lock_file)
        {
            remove(request->job_state_lock_file);
        }
        globus_l_gram_job_manager_cancel_queries(request);
        event_registered = GLOBUS_TRUE;

        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
        /* This state is reached when the job manager decides to stop
         * between the time the job request reply is sent and the 
         * job manager has noticed stop or failed
         */
        request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;

        if(request->job_history_status != request->status)
        {
            globus_gram_job_manager_history_file_create(request);
            request->job_history_status = request->status;
        }

        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
        /*
         * Send the job manager stopped or proxy expired failure callback.
         */
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);

        globus_gram_job_manager_contact_state_callback(request);

        request->jobmanager_state = 
            GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;

        globus_l_gram_job_manager_cancel_queries(request);
        event_registered = GLOBUS_TRUE;
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
        if(request->job_state_file)
        {
            remove(request->job_state_file);
        }
        if(request->job_state_lock_file)
        {
            remove(request->job_state_lock_file);
        }
        globus_l_gram_job_manager_cancel_queries(request);
        /* Write auditing file if job is DONE or FAILED */
        if (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_DONE ||
            request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE)
        {
            if (globus_gram_job_manager_auditing_file_write(request) != GLOBUS_SUCCESS)
            {
                globus_gram_job_manager_request_log(
                        request,
                        "JM: Error writing audit record\n");
            }
        }
        event_registered = GLOBUS_TRUE;
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
        globus_l_gram_job_manager_cancel_queries(request);

        if (globus_gram_job_manager_auditing_file_write(request)
                != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: Error writing audit record\n");
        }
        event_registered = GLOBUS_TRUE;
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
        if (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED && request->failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_OUT_FAILED)
        {
            request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
            break;
        }

        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT;
        if(globus_gram_job_manager_rsl_need_stage_out(request))
        {
            rc = globus_gram_job_manager_script_stage_out(request);
            
            if(rc != GLOBUS_SUCCESS)
            {
                request->failure_code = rc;
                request->jobmanager_state =
                        GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            }
            else
            {
                event_registered = GLOBUS_TRUE;
            }
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
        if(!globus_list_empty(request->stage_out_todo))
        {
            request->jobmanager_state
                    = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
            if(request->failure_code == GLOBUS_SUCCESS)
            {
                request->failure_code =
                    GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_OUT_FAILED;
            }
        }
      /* FALLSTHROUGH */
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
        if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE);
        }
        else if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
        }

        if(request->unsent_status_change)
        {
            if(request->job_history_status != request->status)
            {
                globus_gram_job_manager_history_file_create(request);
                request->job_history_status = request->status;
            }

            globus_gram_job_manager_contact_state_callback(request);
            request->unsent_status_change = GLOBUS_FALSE;
        }

        /*
         * If there are no client callbacks then skip the two phase end
         * commit delay, since there is nobody listening to the state
         * changes to send the commit.
         */

        if(request->two_phase_commit != 0 && request->client_contacts)
        {
            GlobusTimeReltimeSet(delay_time, request->two_phase_commit, 0);

            globus_callback_register_oneshot(
                    &request->poll_timer,
                    &delay_time,
                    globus_gram_job_manager_state_machine_callback,
                    request);

            event_registered = GLOBUS_TRUE;
        }
        break;
    }

    return event_registered;
}
/* globus_gram_job_manager_state_machine() */

/**
 * Send the response to the initial job request to the GRAM client
 *
 * @param request
 *     Job request
 * @param response_code
 *     GLOBUS_SUCCESS, or a GRAM protocol failure code.
 * @param job_contact
 *     Job contact
 * @param response_fd
 *     Descriptor to send response to
 */
int
globus_gram_job_manager_reply(
    globus_gram_jobmanager_request_t *  request,
    int                                 response_code,
    const char *                        job_contact,
    int                                 response_fd,
    gss_ctx_id_t                        response_context)
{
    int                                 rc;
    globus_byte_t *                     reply = NULL;
    globus_size_t                       replysize;
    globus_byte_t *                     sendbuf;
    globus_size_t                       sendsize;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 token_status;

    /* Response to initial job request. */
    rc = globus_gram_protocol_pack_job_request_reply(
            response_code,
            job_contact,
            &reply,
            &replysize);

    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_gram_protocol_frame_reply(
                200,
                reply,
                replysize,
                &sendbuf,
                &sendsize);
    }
    else
    {
        rc = globus_gram_protocol_frame_reply(
                400,
                NULL,
                0,
                &sendbuf,
                &sendsize);
    }
    if(reply)
    {
        free(reply);
    }
    globus_gram_job_manager_request_log( request,
                   "JM: before sending to client: rc=%d (%s)\n",
                   rc, globus_gram_protocol_error_string(rc));
    if(rc == GLOBUS_SUCCESS)
    {
        if (response_context != GSS_C_NO_CONTEXT)
        {
            major_status = globus_gss_assist_wrap_send(
                    &minor_status,
                    response_context,
                    (void *) sendbuf,
                    sendsize,
                    &token_status,
                    globus_l_gram_gss_send_fd,
                    (void *) response_fd,
                    request ? request->manager->jobmanager_log_fp : stderr);
        }
        else
        {
            printf("Job Manager Response: %s\n", sendbuf);
            major_status = 0;
        }

        free(sendbuf);

        if (request && major_status != GSS_S_COMPLETE)
        {
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
        }
    }
    else
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: couldn't send job contact to client: rc=%d (%s)\n",
                rc,
                globus_gram_protocol_error_string(rc));
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
    }

    if (request && rc != GLOBUS_SUCCESS)
    {
        request->failure_code = rc;
    }

    return rc;
}
/* globus_gram_job_manager_reply() */

int
globus_gram_job_manager_read_request(
    globus_gram_job_manager_t *         manager,
    int                                 fd,
    char **                             rsl,
    char **                             client_contact,
    int *                               job_state_mask)
{
    int                                 rc;
    globus_size_t                       jrbuf_size;
    globus_byte_t                       buffer[
                                            GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];

    jrbuf_size = (globus_size_t) lseek(fd, 0, SEEK_END);
    (void) lseek(fd, 0, SEEK_SET);
    if (jrbuf_size > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: RSL file too big\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    if (read(fd, buffer, jrbuf_size) != jrbuf_size)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: Error reading the RSL file\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }

    rc = globus_gram_protocol_unpack_job_request(
            buffer,
            jrbuf_size,
            job_state_mask,
            client_contact,
            rsl);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: request unpack failed because %s\n",
                globus_gram_protocol_error_string(rc));
        return rc;
    }
    return rc;
}
/* globus_gram_job_manager_read_request() */

/**
 * Do the state transition for handling a job manager restart.
 *
 * @param request
 *        The request to changes states.
 *
 * @return
 *       Returns GLOBUS_TRUE if if the job manager's state was
 *       changed as a result of this call; GLOBUS_FALSE otherwise.
 *
 * @note This case statement MUST cover all cases where the
 *        state file can be written (where
 *        globus_gram_job_manager_state_file_write()
 *        is called).
 */
static
globus_bool_t
globus_l_gram_job_manager_set_restart_state(
    globus_gram_jobmanager_request_t *  request)
{
    globus_bool_t                       changed = GLOBUS_FALSE;

    switch(request->restart_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
        changed = GLOBUS_TRUE;
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE);
        request->unsent_status_change = GLOBUS_TRUE;
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
        changed = GLOBUS_TRUE;
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
        request->unsent_status_change = GLOBUS_TRUE;
        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
        changed = GLOBUS_TRUE;
        break;
      default:
        break;
    }
    request->restart_state = GLOBUS_GRAM_JOB_MANAGER_STATE_START;

    return changed;
}
/* globus_l_gram_job_manager_set_restart_state() */


#ifdef BUILD_DEBUG
static
const
char *
globus_l_gram_job_manager_state_string(
    globus_gram_jobmanager_state_t      state)
{
#   define STRING_CASE(x) case x: return #x;

    switch(state)
    {
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_START)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_DONE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH)
        /* Don't put a default case here. */
    }
    return "UNKNOWN";
}
/* globus_l_gram_job_manager_state_string() */
#endif /* BUILD_DEBUG */

static
void
globus_l_gram_job_manager_cancel_queries(
    globus_gram_jobmanager_request_t *  request)
{
    globus_gram_job_manager_query_t *   query;

    while(!globus_fifo_empty(&request->pending_queries))
    {
        query = globus_fifo_dequeue(&request->pending_queries);
        query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;

        /* Frees the query */
        globus_gram_job_manager_query_reply(
                request,
                query);

    }
}
/* globus_l_gram_job_manager_cancel_queries() */

/**
 * Validate that the job manager is running as the username specified in the
 * RSL if it is present.
 *
 * @param request
 *     Request which contains information about the job. We'll only look at
 *     the RSL in the request to check for presence of the username attribute.
 *
 * @retval GLOBUS_SUCCESS
 *     Either the username RSL attribute was not present, or it was present
 *     and its value matched the account this process is running as.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Some system call failed when we tried to look up the user id.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_USER_NAME
 *     This process is not running as the desired user.
 */
int
globus_gram_job_manager_validate_username(
    globus_gram_jobmanager_request_t *  request)
{
    char *                              tmp_str = NULL;
    char *                              buffer = NULL;
    struct passwd                       pwd;
    struct passwd *                     pwd_result = NULL;
    int                                 rc = GLOBUS_SUCCESS;

    /* Validate username RSL attribute if present */
    rc = globus_gram_job_manager_rsl_eval_one_attribute(
            request,
            GLOBUS_GRAM_PROTOCOL_USER_NAME,
            &tmp_str);

    if (rc != 0)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: eval of %s failed\n",
                GLOBUS_GRAM_PROTOCOL_USER_NAME);

        return rc;
    }

    if (tmp_str != NULL)
    {
        buffer = malloc(1024);

        if (buffer == NULL)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: allocating buffer for getpwnam_r failed\n");
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto free_tmp_str_exit;
        }

        rc = globus_libc_getpwnam_r(
                tmp_str,
                &pwd,
                buffer,
                1024,
                &pwd_result);

        if (rc != 0 || pwd_result == NULL)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: getpwnam_r failed\n");

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto free_buffer_exit;
        }

        if (pwd.pw_uid != getuid())
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: job manager is NOT running as %s (uid=%lu)"
                    "---running as uid=%lu\n",
                    tmp_str,
                    (unsigned long )pwd.pw_uid,
                    (unsigned long) getuid());

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_USER_NAME;

            goto free_buffer_exit;
        }
    }

free_buffer_exit:
    if (buffer != NULL)
    {
        free(buffer);
    }

free_tmp_str_exit:
    if (tmp_str != NULL)
    {
        free(tmp_str);
    }

    return rc;
}
/* globus_gram_job_manager_validate_username() */

static
int
globus_l_gram_job_manager_add_cache_info(
    globus_gram_jobmanager_request_t *  request)
{
    char *                              out_file;
    char *                              fname;
    unsigned long                       timestamp;
    FILE *                              file;
    char *                              gk_id;
    int                                 rc;
 
    out_file = globus_common_create_string(
            "x-gass-cache://%s/%s/cache-info",
            request->config->hostname,
            request->uniq_id);

    rc = globus_gass_cache_add(
                request->cache_handle,
                out_file,
                request->cache_tag,
                GLOBUS_TRUE,
                &timestamp,
                &fname);   
    if(rc != GLOBUS_GASS_CACHE_ADD_NEW &&
       rc != GLOBUS_GASS_CACHE_ADD_EXISTS)
    {
        globus_gram_job_manager_request_log(
                request,
                "Adding cache-info to gass cache failed, "
                "globus_gram_cache_add() returned %d\n", rc);
        return 1;
    }

    file = fopen(fname,"w");
    if (file != NULL)
    {
        gk_id = getenv("GATEKEEPER_JM_ID");
        if (gk_id == NULL)
        {
            gk_id = "-";
        }
        fprintf(file,"%s\n%s\n%s\n%s\n",request->uniq_id,request->job_id_string,
                                        request->config->jobmanager_type,gk_id);
        fclose(file);
        time((time_t *)&timestamp);
        globus_gass_cache_add_done(
                request->cache_handle,
                out_file,   
                request->cache_tag,
                timestamp);
    }
    else
    {
        globus_gass_cache_delete(
                request->cache_handle,
                out_file,
                request->cache_tag,
                timestamp,
                GLOBUS_TRUE);
    }

    free(fname);
    free(out_file);
    return 0;
}
/* globus_l_gram_job_manager_add_cache_info() */

static
int
globus_l_gram_remote_io_url_update(
    globus_gram_jobmanager_request_t *  request)
{
    FILE *                              fp;
    int                                 rc = GLOBUS_SUCCESS;

    fp = fopen(request->remote_io_url_file, "w");
    if (fp == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

        goto fopen_failed;
    }
    rc = fprintf(fp, "%s\n", request->remote_io_url);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

        goto fprintf_failed;

    }
fprintf_failed:
    rc = fclose(fp);
    if (rc == EOF)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;
        goto fclose_failed;
    }

fclose_failed:
fopen_failed:
    return rc;
}
/* globus_l_gram_remote_io_url_update() */


/**
 * Write a GSSAPI token to a file descriptor
 *
 * Unlike the functions in globus_gss_assist, this uses file descriptors, not
 * FILE * values for @a arg. Writes a 4-byte header for the same conditions
 * as the function in globus_gss_assist.
 *
 * @param arg
 *     Void * cast of the file descriptor number
 * @param buffer
 *     GSSAPI token buffer to send
 * @param length
 *     Token length
 *     
 */
static
int
globus_l_gram_gss_send_fd(
    void *                              arg,
    void *                              buffer,
    size_t                              length)
{
    unsigned char                       lengthbuf[4];
    unsigned char *                     header = buffer;
    int                                 fd;
    int                                 rc;
    ssize_t                             written = 0;
    
    fd = (int) arg;

    lengthbuf[0] = length >> 24;
    lengthbuf[1] = length >> 16;
    lengthbuf[2] = length >> 8;
    lengthbuf[3] = length;
    
    if (!(length > 5 && header[0] <= 26 && header[0] >= 20
          && ((header[1] == 3 && (header[2] == 0 || header[2] == 1))
          || (header[1] == 2 && header[2] == 0))))
    {
        written = 0;
        do
        {
            rc = write((int) fd, lengthbuf + written, (size_t) (4 - written));
            if (rc < 0)
            {
                if (errno == EINTR)
                {
                    rc = 0;
                }
                else
                {
                    return GLOBUS_GSS_ASSIST_TOKEN_EOF;
                }
            }
            written += rc;
        }
        while (written < 4);
    }

    written = 0;
    do
    {
        rc = write((int) fd, header + written, (size_t) (length - written));
        if (rc < 0)
        {
            if (errno == EINTR)
            {
                rc = 0;
            }
            else
            {
                return GLOBUS_GSS_ASSIST_TOKEN_EOF;
            }
        }
        written += rc;
    }
    while (written < length);

    return 0;
}
/* globus_l_gram_gss_send_fd() */

static
void
globus_l_gram_file_cleanup(
    globus_gram_jobmanager_request_t *  request)
{
    globus_rsl_t *                      relation;
    globus_rsl_value_t *                value_sequence;
    globus_list_t *                     value_list;
    globus_rsl_value_t *                value;
    char *                              path;

    relation = globus_gram_job_manager_rsl_extract_relation(
            request->rsl,
            GLOBUS_GRAM_PROTOCOL_FILE_CLEANUP_PARAM);

    if (!relation)
    {
        goto not_found;
    }

    value_sequence = globus_rsl_relation_get_value_sequence(relation);
    if (!value_sequence)
    {
        goto no_sequence;
    }

    value_list = globus_rsl_value_sequence_get_value_list(value_sequence);
    while (!globus_list_empty(value_list))
    {
        value = globus_list_remove(&value_list, value_list);

        path = globus_rsl_value_literal_get_string(value);

        if (path)
        {
            unlink(path);
            free(path);
        }
    }

no_sequence:
    globus_rsl_free_recursive(relation);
not_found:
    return;
}
/* globus_l_gram_file_cleanup() */
