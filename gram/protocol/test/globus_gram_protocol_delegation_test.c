/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_gram_protocol.h"
#include <string.h>

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_bool_t			done;
    int					error;
    gss_cred_id_t			credential;
    int job_status;
    int failure_code;
    int job_failure_code;
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

static
void
delegation_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    gss_cred_id_t			credential,
    int					errorcode);

int main()
{
    int					rc;
    char *				server_callback_contact;
    globus_byte_t *			msg;
    globus_size_t			msgsize;
    monitor_t 				monitor;
    globus_gram_protocol_handle_t	handle;
    int					i;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    memset(&monitor, '\0', sizeof(monitor_t));
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_mutex_lock(&monitor.mutex);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.credential = GSS_C_NO_CREDENTIAL;

    rc = globus_gram_protocol_allow_attach(
	    &server_callback_contact,
	    server_callback,
	    &monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	goto unlock_error;
    }

    rc = globus_gram_protocol_pack_status_request(
	    "renew",
	    &msg,
	    &msgsize);

    if(rc != GLOBUS_SUCCESS)
    {
	goto disallow_error;
    }
    for(i = 0; i < 2; i++)
    {

	rc = globus_gram_protocol_post_delegation(
		server_callback_contact,
		&handle,
		GLOBUS_NULL,
		msg,
		msgsize,
		GSS_C_NO_CREDENTIAL,
		GSS_C_NO_OID_SET,
		GSS_C_NO_BUFFER_SET,
		GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG
		    | GSS_C_GLOBUS_SSL_COMPATIBLE,
		0,
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

	globus_mutex_unlock(&monitor.mutex);
	globus_mutex_destroy(&monitor.mutex);
	globus_cond_destroy(&monitor.cond);

	if(monitor.credential == GSS_C_NO_CREDENTIAL)
	{
	    fprintf(stderr, "delegation error.\n");

	    monitor.error++;
	}
	monitor.credential = GSS_C_NO_CREDENTIAL;
	monitor.done = 0;
    }
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
    int					rc;
    char *				status_request;

    monitor = (monitor_t *) arg;

    globus_mutex_lock(&monitor->mutex);

    rc = globus_gram_protocol_unpack_status_request(
	    message,
	    msgsize,
	    &status_request);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error unpacking status request because %s.\n",
		globus_gram_protocol_error_string(rc));
	monitor->error++;
    }

    rc = globus_gram_protocol_accept_delegation(
	    handle,
	    GSS_C_NO_OID_SET,
	    GSS_C_NO_BUFFER_SET,
	    GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG
		| GSS_C_GLOBUS_SSL_COMPATIBLE,
	    0,
	    delegation_callback,
	    monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed starting delegation because %s.\n",
		globus_gram_protocol_error_string(rc));
	monitor->error++;
    }

    globus_mutex_unlock(&monitor->mutex);
}

static
void
delegation_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    gss_cred_id_t			credential,
    int					errorcode)
{
    monitor_t *				monitor;
    globus_byte_t *			reply;
    globus_size_t 			replysize;
    int					rc;

    monitor = (monitor_t *) arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->credential = credential;

    if(credential != GSS_C_NO_CREDENTIAL)
    {
	globus_gram_protocol_set_credentials(credential);
    }

    if(errorcode != GLOBUS_SUCCESS)
    {
	monitor->error++;
	globus_cond_signal(&monitor->cond);
	globus_mutex_unlock(&monitor->mutex);

	return;
    }

    if(credential == GSS_C_NO_CREDENTIAL)
    {
	monitor->error++;
	globus_cond_signal(&monitor->cond);
	globus_mutex_unlock(&monitor->mutex);

	return;
    }

    rc = globus_gram_protocol_pack_status_reply(
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
	    GLOBUS_SUCCESS,
	    GLOBUS_SUCCESS,
	    &reply,
	    &replysize);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error packing status reply because %s.\n",
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
	    &monitor->job_status,
	    &monitor->failure_code,
	    &monitor->job_failure_code);
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
