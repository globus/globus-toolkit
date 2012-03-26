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

#include "globus_gram_job_manager.h"
#include "version.h"

#include <string.h>

typedef struct globus_gram_job_manager_contact_s
{
    char *                              contact;
    int                                 job_state_mask;
    int                                 failed_count;
}
globus_gram_job_manager_contact_t;

typedef struct globus_gram_job_callback_context_s
{
    globus_gram_jobmanager_request_t *  request;
    globus_list_t *                     contacts;
    unsigned char *                     message;
    globus_size_t                       message_length;
    int                                 active;
    globus_bool_t                       restart_state_when_done;
}
globus_gram_job_callback_context_t;


static
int
globus_l_gram_callback_queue(
    globus_gram_job_manager_t *         manager,
    globus_gram_job_callback_context_t *context);

static
void
globus_l_gram_callback_reply(
    void  *                             arg,
    globus_gram_protocol_handle_t       handle,
    globus_byte_t *                     message,
    globus_size_t                       msgsize,
    int                                 errorcode,
    char *                              uri);

/**
 * Add a callback contact to the request's list.
 *
 * @param request
 *        The request to modify
 * @param contact
 *        The callback contact URL string.
 * @param job_state_mask
 *        The job state mask for this callback contact.
 *
 * @retval GLOBUS_SUCCESS
 *         The callback contact was successfully added to the
 *         request.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INSERTING_CONTACT
 *         The callback contact failed to be inserted into the
 *         request.
 */
int
globus_gram_job_manager_contact_add(
    globus_gram_jobmanager_request_t *  request,
    const char *                        contact,
    int                                 job_state_mask)
{
    globus_gram_job_manager_contact_t * callback;
    int                                 rc = GLOBUS_SUCCESS;
    globus_list_t *                     tmp_list;

    globus_gram_job_manager_request_log(
            request,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.callback_register.start "
            "level=TRACE "
            "gramid=%s "
            "contact=%s "
            "mask=%d "
            "\n",
            request->job_contact_path,
            contact,
            job_state_mask);

    /*
     * If the contact is already registered, update the job_state_mask
     * to be the set of states in the old or new job state masks.
     * This means that if a contact is registered multiple times, it will
     * receive only one callback for each job state change that it is
     * registered for.
     */
    tmp_list = request->client_contacts;
    while(!globus_list_empty(tmp_list))
    {
        callback = globus_list_first(tmp_list);
        if(strcmp(contact, callback->contact) == 0)
        {
            callback->job_state_mask |= job_state_mask;
            goto done;
        }

        tmp_list = globus_list_rest(tmp_list);
    }

    callback = malloc(sizeof(globus_gram_job_manager_contact_t));
    if(callback == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback_register.end "
                "level=ERROR "
                "gramid=%s "
                "contact=%s "
                "mask=%d "
                "msg=\"%s\" "
                "status=%d "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                request->job_contact_path,
                contact,
                job_state_mask,
                "Malloc failed",
                -GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED,
                errno,
                strerror(errno));
        goto error_exit;
    }
    callback->contact = strdup(contact);
    if(callback->contact == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback_register.end "
                "level=ERROR "
                "gramid=%s "
                "contact=%s "
                "mask=%d "
                "msg=\"%s\" "
                "status=%d "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                request->job_contact_path,
                contact,
                job_state_mask,
                "Malloc failed",
                -GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED,
                errno,
                strerror(errno));

        goto strdup_contact_failed;
    }
    callback->job_state_mask = job_state_mask;
    callback->failed_count   = 0;

    rc = globus_list_insert(&request->client_contacts, (void *) callback);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback_register.end "
                "level=ERROR "
                "gramid=%s "
                "contact=%s "
                "mask=%d "
                "status=%d "
                "reason=\"%s\" "
                "\n",
                request->job_contact_path,
                contact,
                job_state_mask,
                "List insert failed",
                strerror(errno),
                -GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED);
        goto list_insert_failed;
    }
done:
    globus_gram_job_manager_request_log(
            request,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.callback_register.end "
            "level=TRACE "
            "gramid=%s "
            "contact=%s "
            "mask=%d "
            "status=%d\n",
            request->job_contact_path,
            contact,
            job_state_mask,
            0);

    return rc;

list_insert_failed:
    free(callback->contact);
strdup_contact_failed:
    free(callback);
error_exit:
    return GLOBUS_GRAM_PROTOCOL_ERROR_INSERTING_CLIENT_CONTACT;
}
/* globus_gram_job_manager_contact_add() */

int
globus_gram_job_manager_contact_remove(
    globus_gram_jobmanager_request_t *  request,
    const char *                        contact)
{
    globus_list_t *                     tmp_list;
    int                                 rc;
    globus_gram_job_manager_contact_t * client_contact_node;

    rc = GLOBUS_GRAM_PROTOCOL_ERROR_CLIENT_CONTACT_NOT_FOUND;

    tmp_list = request->client_contacts;

    while(!globus_list_empty(tmp_list))
    {
        client_contact_node = globus_list_first(tmp_list);
        if(strcmp(contact, client_contact_node->contact) == 0)
        {
            globus_list_remove(&request->client_contacts, tmp_list);

            free(client_contact_node->contact);
            free(client_contact_node);
            rc = GLOBUS_SUCCESS;

            break;
        }

        tmp_list = globus_list_rest(tmp_list);
    }
    return rc;
}
/* globus_gram_job_manager_contact_remove() */

int
globus_gram_job_manager_contact_list_free(
    globus_gram_jobmanager_request_t *  request)
{
    globus_gram_job_manager_contact_t *    client_contact_node;

    while(!globus_list_empty(request->client_contacts))
    {
        client_contact_node = globus_list_remove(
                                  &request->client_contacts,
                                  request->client_contacts);

        free (client_contact_node->contact);
        free (client_contact_node);
    }

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_contact_list_free() */

/**
 * @brief Send a job state callback to registered clients
 * @details
 *     Start processing a job state callback for the given request, sending
 *     its current job state to all clients which are registered with a
 *     mask that includes the current state. If the
 *     @a restart_state_machine_when_done parameter is GLOBUS_TRUE, then
 *     the state machine will be reregistered after the callback has been
 *     sent and its reply parsed. Otherwise, the state machine is assumed
 *     to not care about when this completes.
 *
 * @param request
 *     Job request to send state changes about
 * @param restart_state_machine_when_done
 *     Flag indicating whether to restart the state machine when complete
 */
void
globus_gram_job_manager_contact_state_callback(
    globus_gram_jobmanager_request_t *  request,
    globus_bool_t                       restart_state_machine_when_done)
{
    int                                 rc;
    globus_list_t *                     tmp_list;
    globus_gram_job_manager_contact_t * client_contact_node;
    globus_hashtable_t                  extensions = NULL;
    globus_gram_protocol_extension_t *  entry = NULL;
    globus_gram_protocol_job_state_t    state;

    state = (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
            ? GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED
            : request->status;

    globus_gram_job_manager_request_log(
            request,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.callback.start "
            "level=DEBUG "
            "gramid=%s "
            "state=%d "
            "restart_when_done=%s "
            "\n",
            request->job_contact_path,
            state,
            restart_state_machine_when_done ? "true" : "false");

    globus_gram_job_callback_context_t *context = NULL;

    tmp_list = request->client_contacts;

    if (globus_list_empty(tmp_list))
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
                "event=gram.callback.end "
                "level=DEBUG "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "\n",
                request->job_contact_path,
                state,
                0,
                "Empty callback contact list");

        if (restart_state_machine_when_done)
        {
            globus_reltime_t delay;

            GlobusTimeReltimeSet(delay, request->two_phase_commit, 0);
            rc = globus_gram_job_manager_state_machine_register(
                    request->manager,
                    request,
                    &delay);
        }
        return;
    }

    context = malloc(sizeof(globus_gram_job_callback_context_t));
    if (context == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Malloc failed",
                errno,
                strerror(errno));

        goto context_malloc_failed;
    }

    rc = globus_gram_job_manager_add_reference(
            request->manager,
            request->job_contact_path,
            "Job state callbacks",
            &context->request);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                request->job_contact_path,
                state,
                -rc,
                "Add reference failed",
                globus_gram_protocol_error_string(rc));
        goto add_reference_failed;
    }
    context->contacts = NULL;
    context->message = NULL;
    context->message_length = 0;
    context->active = 0;
    context->restart_state_when_done = restart_state_machine_when_done;

    rc = globus_hashtable_init(
            &extensions,
            7,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                request->job_contact_path,
                state,
                -rc,
                "Hashtable init failed",
                globus_gram_protocol_error_string(rc));

        goto fail_extensions_init;
    }

    /* Create message extensions to send exit code if known */
    if (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
        (request->config->seg_module != NULL ||
         strcmp(request->config->jobmanager_type, "condor") == 0))
    {
        entry = globus_gram_protocol_create_extension(
                "exit-code",
                "%d",
                request->exit_code);
        if (entry == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            globus_gram_job_manager_request_log(
                    request,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.callback.end "
                    "level=ERROR "
                    "gramid=%s "
                    "state=%d "
                    "status=%d "
                    "msg=\"%s\" "
                    "reason=\"%s\" "
                    "\n",
                    request->job_contact_path,
                    state,
                    -rc,
                    "Message extension initialization failed",
                    globus_gram_protocol_error_string(rc));

            goto extension_create_failed;
        }

        rc = globus_hashtable_insert(
                &extensions,
                entry->attribute,
                entry);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            globus_gram_job_manager_request_log(
                    request,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.callback.end "
                    "level=ERROR "
                    "gramid=%s "
                    "state=%d "
                    "status=%d "
                    "msg=\"%s\" "
                    "reason=\"%s\" "
                    "\n",
                    request->job_contact_path,
                    state,
                    -rc,
                    "Message extension hashtable insert failed",
                    globus_gram_protocol_error_string(rc));

            goto fail_entry_insert;
        }
    }
    else if (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
        if (request->gt3_failure_type != NULL)
        {
            entry = globus_gram_protocol_create_extension(
                    "gt3-failure-type",
                    "%s",
                    request->gt3_failure_type);
            if (entry == NULL)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension initialization failed",
                        globus_gram_protocol_error_string(rc));

                goto extension_create_failed;
            }

            rc = globus_hashtable_insert(
                    &extensions,
                    entry->attribute,
                    entry);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension hashtable insert failed",
                        globus_gram_protocol_error_string(rc));

                goto fail_entry_insert;
            }
        }
        if (request->gt3_failure_message != NULL)
        {
            entry = globus_gram_protocol_create_extension(
                    "gt3-failure-message",
                    "%s",
                    request->gt3_failure_message);
            if (entry == NULL)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension initialization failed",
                        globus_gram_protocol_error_string(rc));

                goto extension_create_failed;
            }

            rc = globus_hashtable_insert(
                    &extensions,
                    entry->attribute,
                    entry);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension hashtable insert failed",
                        globus_gram_protocol_error_string(rc));
                goto fail_entry_insert;
            }
        }
        if (request->gt3_failure_source != NULL)
        {
            entry = globus_gram_protocol_create_extension(
                    "gt3-failure-source",
                    "%s",
                    request->gt3_failure_source);
            if (entry == NULL)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension hashtable insert failed",
                        globus_gram_protocol_error_string(rc));
                goto extension_create_failed;
            }

            rc = globus_hashtable_insert(
                    &extensions,
                    entry->attribute,
                    entry);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension hashtable insert failed",
                        globus_gram_protocol_error_string(rc));
                goto fail_entry_insert;
            }
        }
        if (request->gt3_failure_destination != NULL)
        {
            entry = globus_gram_protocol_create_extension(
                    "gt3-failure-destination",
                    "%s",
                    request->gt3_failure_destination);
            if (entry == NULL)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension initialization failed",
                        globus_gram_protocol_error_string(rc));
                goto extension_create_failed;
            }

            rc = globus_hashtable_insert(
                    &extensions,
                    entry->attribute,
                    entry);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        "Message extension hashtable insert failed",
                        globus_gram_protocol_error_string(rc));
                goto fail_entry_insert;
            }
        }
    }
    /* Add extensions for version numbers */
    entry = globus_gram_protocol_create_extension(
            "toolkit-version",
            "%s",
            request->config->globus_version);
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Message extension initialization failed",
                globus_gram_protocol_error_string(rc));
        goto extension_create_failed;
    }
    rc = globus_hashtable_insert(
            &extensions,
            entry->attribute,
            entry);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Message extension hashtable insert failed",
                globus_gram_protocol_error_string(rc));
        goto fail_entry_insert;
    }
    entry = globus_gram_protocol_create_extension(
            "version",
            "%d.%d (%d-%d)",
            local_version.major,
            local_version.minor,
            local_version.timestamp,
            local_version.branch_id);
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Message extension initialization failed",
                globus_gram_protocol_error_string(rc));
        goto extension_create_failed;
    }
    rc = globus_hashtable_insert(
            &extensions,
            entry->attribute,
            entry);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Message extension hashtable insert failed",
                globus_gram_protocol_error_string(rc));
        goto fail_entry_insert;
    }

    entry = NULL;

    if (extensions != NULL)
    {
        rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            request->job_contact,
            (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
                ? GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED
                : request->status,
            (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
                ? request->stop_reason
                : request->failure_code,
            &extensions,
            &context->message,
            &context->message_length);
    }
    else
    {
        rc = globus_gram_protocol_pack_status_update_message(
            request->job_contact,
            (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
                ? GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED
                : request->status,
            (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
                ? request->stop_reason
                : request->failure_code,
            &context->message,
            &context->message_length);
    }
    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.end "
                "level=ERROR "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Error packing message",
                globus_gram_protocol_error_string(rc));
        goto pack_message_failed;
    }

    while(!globus_list_empty(tmp_list))
    {
        client_contact_node = globus_list_first(tmp_list);
        tmp_list = globus_list_rest(tmp_list);

        if ((request->status & client_contact_node->job_state_mask) &&
            client_contact_node->failed_count < 4)
        {
            char * contact = strdup(client_contact_node->contact);

            if (contact == NULL)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d"
                        "contact=%s "
                        "msg=\"%s\" "
                        "errno=%d "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        client_contact_node->contact,
                        "Copy of contact string failed",
                        errno,
                        strerror(errno));

                continue;
            }

            rc = globus_list_insert(&context->contacts, contact);

            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.callback.end "
                        "level=ERROR "
                        "gramid=%s "
                        "state=%d "
                        "status=%d"
                        "contact=%s "
                        "msg=\"%s\" "
                        "reason=\"%s\"\n",
                        request->job_contact_path,
                        state,
                        -rc,
                        client_contact_node->contact,
                        "Error inserting contact string into list",
                        globus_gram_protocol_error_string(rc));
                free(contact);
                continue;
            }
        }
    }

    if (globus_list_empty(context->contacts))
    {
        /* Nothing to send... free context */
        rc = GLOBUS_FAILURE;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.callback.end "
                "level=WARN "
                "gramid=%s "
                "state=%d "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Unexpectedly empty contact list",
                globus_gram_protocol_error_string(rc));
        goto nothing_to_send;
    }

    rc = globus_l_gram_callback_queue(request->manager, context);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.callback.end "
                "level=WARN "
                "gramid=%s "
                "state=%d "
                "status=%d"
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                request->job_contact_path,
                state,
                -rc,
                "Error queuing callback messages",
                globus_gram_protocol_error_string(rc));
        goto queue_failed;
    }

    if (extensions != NULL)
    {
        globus_gram_protocol_hash_destroy(&extensions);
    }

    globus_gram_job_manager_request_log(
            request,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.callback.end "
            "level=DEBUG "
            "gramid=%s "
            "state=%d "
            "status=%d "
            "msg=\"%s\"\n",
            request->job_contact_path,
            state,
            rc,
            "Done queuing callback messages");

    if (rc != GLOBUS_SUCCESS)
    {
queue_failed:
        tmp_list = context->contacts;

        while (!globus_list_empty(tmp_list))
        {
            char * tmp = globus_list_first(tmp_list);
            tmp_list = globus_list_rest(tmp_list);

            free(tmp);
        }
nothing_to_send:
        if (restart_state_machine_when_done)
        {
            globus_reltime_t delay;

            GlobusTimeReltimeSet(delay, request->two_phase_commit, 0);

            rc = globus_gram_job_manager_state_machine_register(
                    request->manager,
                    request,
                    &delay);
        }
        free(context->message);

        globus_gram_job_manager_remove_reference(
               request->manager,
               request->job_contact_path,
               "Job state callbacks");
        if (entry != NULL)
        {
fail_entry_insert:
            free(entry->value);
            free(entry->attribute);
            free(entry);
        }
extension_create_failed:
        if (extensions)
        {
            globus_gram_protocol_hash_destroy(&extensions);
        }
fail_extensions_init:
add_reference_failed:
pack_message_failed:
        free(context);
context_malloc_failed:
        ;
    }
}
/* globus_gram_job_manager_state_callback() */

/**
 * Write list of callback contacts to the given file
 *
 * @param request
 *     Job request which should have its callback contacts written
 * @param fp
 *     File to write to
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE
 *     Error writing state file
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 */
int
globus_gram_job_manager_write_callback_contacts(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp)
{
    globus_gram_job_manager_contact_t * contact;
    globus_list_t *                     tmp;
    int                                 rc;

    tmp = request->client_contacts;

    rc = fprintf(fp, "%d\n", globus_list_size(tmp));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;

        goto failed_write_count;
    }

    while (! globus_list_empty(tmp))
    {
        contact = globus_list_first(tmp);
        tmp = globus_list_rest(tmp);

        rc = fprintf(fp, "%d %s\n", contact->job_state_mask, contact->contact);
        if (rc < 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;

            goto failed_write_contact;
        }
    }
    rc = GLOBUS_SUCCESS;

failed_write_contact:
failed_write_count:
    return rc;
}
/* globus_gram_job_manager_write_callback_contacts() */

/**
 * Read list of callback contacts from the given file
 *
 * @param request
 *     Job request which should have its callback contacts read
 * @param fp
 *     File to read from
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE
 *     Error reading state file
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 */
int
globus_gram_job_manager_read_callback_contacts(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp)
{
    globus_gram_job_manager_contact_t * contact;
    globus_list_t **                    tmp;
    int                                 count;
    int                                 rc;
    long                                off1, off2;
    int                                 i;

    request->client_contacts = NULL;
    tmp = &request->client_contacts;

    rc = fscanf(fp, "%d%*[\n]", &count);
    if (rc != 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

        goto failed_read_count;
    }

    for (i = 0; i < count; i++)
    {
        contact = malloc(sizeof(globus_gram_job_manager_contact_t));
        if (contact == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto failed_malloc_contact;
        }
        off1 = ftell(fp);
        if (off1 < 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;
            goto failed_ftell;
        }
        rc = fscanf(fp, "%d %*s%*[\n]", &contact->job_state_mask); 
        if (rc < 1)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

            goto failed_read_mask;
        }
        off2 = ftell(fp);
        if (rc < 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

            goto failed_ftell2;
        }
        rc = fseek(fp, off1, SEEK_SET);
        if (rc < 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

            goto failed_fseek;
        }

        contact->contact = malloc(off2-off1+1);
        if (contact->contact == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto failed_malloc_contact_string_failed;
        }
        rc = fscanf(fp, "%*d %s%*[\n]", contact->contact);
        if (rc < 1)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

            goto failed_scan_contact;
        }
        contact->failed_count = 0;

        rc = globus_list_insert(tmp, contact);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto failed_list_insert;
        }
        tmp = globus_list_rest_ref(*tmp);
    }
    rc = GLOBUS_SUCCESS;

    if (rc != GLOBUS_SUCCESS)
    {
failed_list_insert:
failed_scan_contact:
        free(contact->contact);
failed_malloc_contact_string_failed:
failed_fseek:
failed_ftell2:
failed_read_mask:
failed_ftell:
        free(contact);
failed_malloc_contact:
        globus_gram_job_manager_contact_list_free(request);
failed_read_count:
        ;
    }

    return rc;
}
/* globus_gram_job_manager_read_callback_contacts() */

static
int
globus_l_gram_callback_queue(
    globus_gram_job_manager_t *         manager,
    globus_gram_job_callback_context_t *context)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_list_t *                     references = NULL;
    globus_gram_jobmanager_request_t *  request;

    if (manager->config->log_levels & GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE)
    {
        char *                          message;

        message = globus_gram_prepare_log_string((char *) context->message);

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.callback.queue.start "
                "level=TRACE "
                "gramid=%s "
                "msg=\"%s\" "
                "status_message=\"%s\""
                "\n",
                context->request->job_contact_path,
                "Queuing status update message",
                message ? message : "");
        if (message)
        {
            free(message);
        }
    }

    GlobusGramJobManagerLock(manager);
    rc = globus_fifo_enqueue(&manager->state_callback_fifo, context);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_FAILURE;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.callback.queue.end "
                "level=ERROR "
                "gramid=%s "
                "msg=\"%s\" "
                "status=%d "
                "reason=\"%s\""
                "\n",
                context->request->job_contact_path,
                "Error enqueuing context in callback fifo",
                -rc,
                globus_gram_protocol_error_string(rc));
        goto failed_enqueue;
    }

    while (manager->state_callback_slots > 0 &&
            !globus_fifo_empty(&manager->state_callback_fifo))
    {
        context = globus_fifo_peek(&manager->state_callback_fifo);
        request = context->request;

        while (manager->state_callback_slots > 0 &&
               !globus_list_empty(context->contacts))
        {
            char * contact;
            
            contact = globus_list_remove(&context->contacts, context->contacts);

            if (manager->config->log_levels &
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE)
            {
                char *                  message;

                message = globus_gram_prepare_log_string(
                        (char *) context->message);

                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                        "event=gram.callback.queue.process.start "
                        "level=TRACE "
                        "gramid=%s "
                        "msg=\"%s\" "
                        "contact=%s "
                        "status_message=\"%s\""
                        "\n",
                        context->request->job_contact_path,
                        "Sending status update message",
                        contact,
                        message ? message : "");
                if (message)
                {
                    free(message);
                }
            }

            rc = globus_gram_protocol_post(
                    contact,
                    NULL,
                    NULL,
                    context->message,
                    context->message_length,
                    globus_l_gram_callback_reply,
                    context);

            if (rc == GLOBUS_SUCCESS)
            {
                request->job_stats.callback_count++;
                manager->state_callback_slots--;
                context->active++;

                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                        "event=gram.callback.queue.process.end "
                        "level=TRACE "
                        "gramid=%s "
                        "contact=%s "
                        "msg=\"%s\" "
                        "status=%d "
                        "\n",
                        context->request->job_contact_path,
                        contact,
                        "Message posted",
                        rc);
            }
            else
            {
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                        "event=gram.callback.queue.process.end "
                        "level=WARN "
                        "gramid=%s "
                        "contact=%s "
                        "msg=\"%s\" "
                        "status=%d "
                        "reason=\"%s\" "
                        "\n",
                        context->request->job_contact_path,
                        contact,
                        "Message posted",
                        -rc,
                        globus_gram_protocol_error_string(rc));

                rc = GLOBUS_SUCCESS;
            }
            free(contact);
        }
        if (globus_list_empty(context->contacts))
        {
            (void) globus_fifo_dequeue(&manager->state_callback_fifo);
        }
        if (context->active == 0 && globus_list_empty(context->contacts))
        {
            free(context->message);
            free(context);
            context = NULL;
            globus_list_insert(&references, request->job_contact_path);
        }
    }

failed_enqueue:
    GlobusGramJobManagerUnlock(manager);

    while (!globus_list_empty(references))
    {
        char * key = globus_list_remove(&references, references);

        globus_gram_job_manager_remove_reference(
               manager,
               key,
               "Job state callbacks");
    }

    if (rc == GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.callback.queue.end "
                "level=TRACE "
                "%s%s%s"
                "status=%d\n",
                context ? "gramid=" : "",
                context ? context->request->job_contact_path : "",
                context ? " " : "",
                -rc);
    }

    return rc;
}
/* globus_l_gram_callback_queue() */

static
void
globus_l_gram_callback_reply(
    void  *                             arg,
    globus_gram_protocol_handle_t       handle,
    globus_byte_t *                     message,
    globus_size_t                       msgsize,
    int                                 errorcode,
    char *                              uri)
{
    globus_gram_job_callback_context_t *context;
    globus_gram_jobmanager_request_t *  request;
    globus_gram_job_manager_t *         manager;
    globus_list_t *                     references = NULL;
    globus_list_t *                     references_to_restart = NULL;
    int                                 rc = GLOBUS_SUCCESS;

    context = arg;
    request = context->request;
    manager = request->manager;

    GlobusGramJobManagerLock(manager);
    context->active--;
    manager->state_callback_slots++;

    if (context->active == 0 && globus_list_empty(context->contacts))
    {
        if (context->restart_state_when_done)
        {
            globus_list_insert(&references_to_restart, request);
        }
        else
        {
            globus_list_insert(&references, request);
        }
        free(context->message);
        free(context);
    }

    while (manager->state_callback_slots > 0 &&
           !globus_fifo_empty(&manager->state_callback_fifo))
    {
        context = globus_fifo_peek(&manager->state_callback_fifo);
        request = context->request;

        while (manager->state_callback_slots > 0 &&
               !globus_list_empty(context->contacts))
        {
            char * contact;
            
            contact = globus_list_remove(&context->contacts, context->contacts);

            rc = globus_gram_protocol_post(
                    contact,
                    NULL,
                    NULL,
                    context->message,
                    context->message_length,
                    globus_l_gram_callback_reply,
                    context);

            if (rc == GLOBUS_SUCCESS)
            {
                manager->state_callback_slots--;
                context->active++;
            }
            free(contact);
        }
        if (globus_list_empty(context->contacts))
        {
            (void) globus_fifo_dequeue(&manager->state_callback_fifo);
        }
        if (context->active == 0 && globus_list_empty(context->contacts))
        {
            if (context->restart_state_when_done)
            {
                globus_list_insert(&references_to_restart, request);
            }
            else
            {
                globus_list_insert(&references, request);
            }
            free(context->message);
            free(context);
        }
    }
    GlobusGramJobManagerUnlock(manager);

    while (!globus_list_empty(references))
    {
        request = globus_list_remove(&references, references);

        globus_gram_job_manager_remove_reference(
               manager,
               request->job_contact_path,
               "Job state callbacks");
    }
    while (!globus_list_empty(references_to_restart))
    {
        globus_reltime_t                delay;

        request = globus_list_remove(
                &references_to_restart,
                references_to_restart);

        GlobusGramJobManagerRequestLock(request);
        if (request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
        {
            GlobusTimeReltimeSet(delay, request->two_phase_commit, 0);
        }
        else
        {
            GlobusTimeReltimeSet(delay, 0, 0);
        }

        rc = globus_gram_job_manager_state_machine_register(
                request->manager,
                request,
                &delay);

        globus_gram_job_manager_remove_reference(
               manager,
               request->job_contact_path,
               "Job state callbacks");
        GlobusGramJobManagerRequestUnlock(request);
    }
}
/* globus_l_gram_callback_reply() */
