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
    int                                 rc;


    globus_gram_job_manager_request_log(
            request,
            "JM: Adding new callback contact (url=%s, mask=%d)\n",
            contact,
            job_state_mask);

    callback = malloc(sizeof(globus_gram_job_manager_contact_t));
    if(callback == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: Failed to malloc callback contact structure\n");
        goto error_exit;
    }
    callback->contact = strdup(contact);
    if(callback->contact == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: Failed to make a copy of contact string %s\n",
                contact);

        goto strdup_contact_failed;
    }
    callback->job_state_mask = job_state_mask;
    callback->failed_count   = 0;

    rc = globus_list_insert(&request->client_contacts, (void *) callback);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: Failed to insert callback contact into list\n");
        goto list_insert_failed;
    }

    globus_gram_job_manager_request_log(
            request,
            "JM: Added successfully\n");

    return GLOBUS_SUCCESS;

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

void
globus_gram_job_manager_contact_state_callback(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc;
    globus_list_t *                     tmp_list;
    globus_gram_job_manager_contact_t * client_contact_node;
    globus_gram_job_callback_context_t *context = NULL;

    tmp_list = request->client_contacts;

    globus_gram_job_manager_request_log(
            request,
            "JM: %s empty client callback list.\n",
            (tmp_list) ? ("NOT") : "" );

    if (globus_list_empty(tmp_list))
    {
        return;
    }

    context = malloc(sizeof(globus_gram_job_callback_context_t));
    if (context == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_request_log(
                request,
                "JM: error %d while creating status message\n",
                rc);

        goto context_malloc_failed;
    }

    rc = globus_gram_job_manager_add_reference(
            request->manager,
            request->job_contact_path,
            "Job state callbacks",
            &context->request);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_reference_failed;
    }
    context->contacts = NULL;
    context->message = NULL;
    context->message_length = 0;
    context->active = 0;

    rc = globus_gram_protocol_pack_status_update_message(
        request->job_contact,
        request->status,
        request->failure_code,
        &context->message,
        &context->message_length);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: error %d while creating status message\n",
                rc);
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
                        "JM: error %d while creating status message\n",
                        rc);
                continue;
            }

            rc = globus_list_insert(&context->contacts, contact);

            if (rc != GLOBUS_SUCCESS)
            {
                free(contact);
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_request_log(
                        request,
                        "JM: error %d while creating status message\n",
                        rc);
                continue;
            }
        }
    }

    if (globus_list_empty(context->contacts))
    {
        /* Nothing to send... free context */
        rc = GLOBUS_FAILURE;
        goto nothing_to_send;
    }

    rc = globus_l_gram_callback_queue(request->manager, context);
    if (rc != GLOBUS_SUCCESS)
    {
        goto queue_failed;
    }

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
        free(context->message);

        globus_gram_job_manager_remove_reference(
               request->manager,
               request->job_contact_path,
               "Job state callbacks");
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

    rc = fscanf(fp, "%d\n", &count);
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
        rc = fscanf(fp, "%d %*s\n", &contact->job_state_mask); 
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
        rc = fscanf(fp, "%*d %s\n", contact->contact);
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
failed_read_count:
        ;
    }

    return rc;
}
/* globus_gram_job_manager_write_callback_contacts() */

static
int
globus_l_gram_callback_queue(
    globus_gram_job_manager_t *         manager,
    globus_gram_job_callback_context_t *context)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_list_t *                     references = NULL;
    globus_gram_jobmanager_request_t *  request;

    GlobusGramJobManagerLock(manager);
    rc = globus_fifo_enqueue(&manager->state_callback_fifo, context);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_FAILURE;
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
            else
            {
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
            globus_list_insert(&references, request->job_contact_path);
        }
    }

failed_enqueue:
    GlobusGramJobManagerUnlock(manager);

    while (!globus_list_empty(references))
    {
        char * key = globus_list_remove(&references, references);

        globus_gram_job_manager_log(
                manager,
                "JM: Done sending callbacks, removing reference for %s\n",
                key);
        globus_gram_job_manager_remove_reference(
               manager,
               key,
               "Job state callbacks");
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
    int                                 rc = GLOBUS_SUCCESS;

    context = arg;
    request = context->request;
    manager = request->manager;

    GlobusGramJobManagerLock(manager);
    context->active--;
    manager->state_callback_slots++;

    if (context->active == 0 && globus_list_empty(context->contacts))
    {
        free(context->message);
        free(context);
        globus_list_insert(&references, request->job_contact_path);
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
            free(context->message);
            free(context);
            globus_list_insert(&references, request->job_contact_path);
        }
    }
    GlobusGramJobManagerUnlock(manager);

    while (!globus_list_empty(references))
    {
        char * key = globus_list_remove(&references, references);

        globus_gram_job_manager_remove_reference(
               manager,
               key,
               "Job state callbacks");
    }
}
/* globus_l_gram_callback_reply() */
