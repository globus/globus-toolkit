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

#include "globus_gram_protocol.h"
#include <string.h>

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_bool_t			done;
    char *				status_request[2];
    int					job_status[2];
    int					failure_code[2];
    int					job_failure_code[2];
    int					error;
}
monitor_t;

static
void
server_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri);

static
void
client_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri);

int main(
    int                                 argc,
    char *                              argv[])
{
    int					rc;
    char *				server_callback_contact;
    globus_byte_t *			msg;
    globus_size_t			msgsize;
    monitor_t 				monitor;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_mutex_lock(&monitor.mutex);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.status_request[0] = "status";
    monitor.job_status[1] = GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE;
    monitor.failure_code[1] = 0;
    monitor.job_failure_code[1] = 0;
    monitor.error = 0;

    rc = globus_gram_protocol_allow_attach(
	    &server_callback_contact,
	    server_callback,
	    &monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	goto unlock_error;
    }

    rc = globus_gram_protocol_pack_status_request(
	    monitor.status_request[0],
	    &msg,
	    &msgsize);

    if(rc != GLOBUS_SUCCESS)
    {
	goto disallow_error;
    }

    if (argc > 1 && !strcmp(argv[1], "invalid_host"))
    {
        globus_free(server_callback_contact);
        server_callback_contact = globus_libc_strdup(
                "https://bogushost.globus.org:7777/7777");
    }

    rc = globus_gram_protocol_post(server_callback_contact,
	                           GLOBUS_NULL,
				   GLOBUS_NULL,
				   msg,
				   msgsize,
				   client_callback,
				   &monitor);
    if(rc != GLOBUS_SUCCESS)
    {
	goto free_msg_error;
    }

    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    globus_libc_free(msg);
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    if(monitor.job_status[0] != monitor.job_status[1] ||
       monitor.failure_code[0] != monitor.failure_code[1] ||
       monitor.job_failure_code[0] != monitor.job_failure_code[1] ||
       strcmp(monitor.status_request[0], monitor.status_request[1]) != 0)
    {
	fprintf(stderr, "transmission error.\n");

	monitor.error++;
    }
    globus_libc_free(monitor.status_request[1]);
    globus_gram_protocol_callback_disallow(server_callback_contact);
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);

    return monitor.error;

free_msg_error:
    globus_libc_free(msg);
disallow_error:
    globus_gram_protocol_callback_disallow(server_callback_contact);
unlock_error:
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

static
void
server_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri)
{
    monitor_t *				monitor;
    globus_byte_t *			reply;
    globus_size_t 			replysize;
    int					rc;

    monitor = (monitor_t *) arg;

    globus_mutex_lock(&monitor->mutex);

    rc = globus_gram_protocol_unpack_status_request(
	    message,
	    msgsize,
	    &monitor->status_request[1]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error unpacking status request because %s.\n",
		globus_gram_protocol_error_string(rc));
	monitor->error++;
    }

    rc = globus_gram_protocol_pack_status_reply(
	    monitor->job_status[1],
	    monitor->failure_code[1],
	    monitor->job_failure_code[1],
	    &reply,
	    &replysize);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed packing status reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	monitor->error++;
    }

    rc = globus_gram_protocol_reply(
	    handle,
	    200,
	    reply,
	    replysize);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed sending reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	monitor->error++;
	monitor->done = GLOBUS_TRUE;
	globus_cond_signal(&monitor->cond);
    }

    globus_libc_free(reply);

    globus_mutex_unlock(&monitor->mutex);
}

static
void
client_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			message,
    globus_size_t			msgsize,
    int					errorcode,
    char *				uri)
{
    monitor_t *				monitor;
    int					rc;

    monitor = (monitor_t *) arg;

    globus_mutex_lock(&monitor->mutex);
    rc = globus_gram_protocol_unpack_status_reply(
	    message,
	    msgsize,
	    &monitor->job_status[0],
	    &monitor->failure_code[0],
	    &monitor->job_failure_code[0]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed unpacking reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	monitor->error++;
    }
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
