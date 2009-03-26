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

typedef struct
{
    char *				contact;
    int					job_state_mask;
    int					failed_count;
}
globus_gram_job_manager_contact_t;

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
    globus_gram_jobmanager_request_t *	request,
    const char *			contact,
    int					job_state_mask)
{
    globus_gram_job_manager_contact_t *	callback;
    int					rc;


    globus_gram_job_manager_request_log(
	    request,
	    "JM: Adding new callback contact (url=%s, mask=%d)\n",
	    contact,
	    job_state_mask);

    callback = globus_libc_malloc(sizeof(globus_gram_job_manager_contact_t));
    if(callback == NULL)
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: Failed to malloc callback contact structure\n");
	goto error_exit;
    }
    callback->contact = globus_libc_strdup(contact);
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
    globus_libc_free(callback->contact);
strdup_contact_failed:
    globus_libc_free(callback);
error_exit:
    return GLOBUS_GRAM_PROTOCOL_ERROR_INSERTING_CLIENT_CONTACT;
}
/* globus_gram_job_manager_contact_add() */

int
globus_gram_job_manager_contact_remove(
    globus_gram_jobmanager_request_t *	request,
    const char *			contact)
{
    globus_list_t *			tmp_list;
    int					rc;
    globus_gram_job_manager_contact_t *	client_contact_node;

    rc = GLOBUS_GRAM_PROTOCOL_ERROR_CLIENT_CONTACT_NOT_FOUND;

    tmp_list = request->client_contacts;

    while(!globus_list_empty(tmp_list))
    {
	client_contact_node = globus_list_first(tmp_list);
	if(strcmp(contact, client_contact_node->contact) == 0)
	{
	    globus_list_remove(&request->client_contacts, tmp_list);

	    globus_libc_free(client_contact_node->contact);
	    globus_libc_free(client_contact_node);
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
    globus_gram_jobmanager_request_t *	request)
{
    globus_gram_job_manager_contact_t *    client_contact_node;

    while(!globus_list_empty(request->client_contacts))
    {
        client_contact_node = globus_list_remove(
		                  &request->client_contacts,
				  request->client_contacts);

        globus_libc_free (client_contact_node->contact);
        globus_libc_free (client_contact_node);
    }

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_contact_list_free() */

void
globus_gram_job_manager_contact_state_callback(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc;
    globus_byte_t *			message;
    globus_size_t			msgsize;
    globus_list_t *			tmp_list;
    globus_gram_job_manager_contact_t *	client_contact_node;

    tmp_list = request->client_contacts;
    message = GLOBUS_NULL;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: %s empty client callback list.\n",
	    (tmp_list) ? ("NOT") : "" );

    if (tmp_list)
    {
	rc = globus_gram_protocol_pack_status_update_message(
	    request->job_contact,
	    request->status,
	    request->failure_code,
	    &message,
	    &msgsize);

	if (rc != GLOBUS_SUCCESS)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: error %d while creating status message\n" );
	    return;
	}
    }

    while(!globus_list_empty(tmp_list))
    {
        client_contact_node = globus_list_first(tmp_list);

        if ((request->status & client_contact_node->job_state_mask) &&
            client_contact_node->failed_count < 4)
        {
            globus_gram_job_manager_request_log(
		    request,
		    "JM: sending callback of status %d "
		    "(failure code %d) to %s.\n",
		    request->status,
		    request->failure_code,
		    client_contact_node->contact);

	    rc = globus_gram_protocol_post(
		    client_contact_node->contact,
		    GLOBUS_NULL /* Ignore handle */,
		    GLOBUS_NULL /* default attr */,
		    message,
		    msgsize,
		    GLOBUS_NULL /* Ignore reply */,
		    GLOBUS_NULL);

	    if (rc != GLOBUS_SUCCESS)
	    {
		/* connect failed, most likely */
		globus_gram_job_manager_request_log(
			request,
			"JM: callback failed, rc = %d, \"%s\"\n",
			rc,
			globus_gram_protocol_error_string (rc));

                client_contact_node->failed_count++;
	    }
        }

        tmp_list = globus_list_rest(tmp_list);
    }

    /* this is safe, as the post() has copied the message to another buffer
       and framed it with HTTP headers etc. */
    if (message)
	globus_libc_free(message);
}
/* globus_gram_job_manager_state_callback() */
