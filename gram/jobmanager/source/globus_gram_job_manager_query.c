#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_job_manager_query.c Job Manager Query Handlers
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#include "globus_gram_job_manager.h"
#include <string.h>
#endif


static
globus_bool_t
globus_l_gram_job_manager_can_cancel(
    globus_gram_jobmanager_request_t *	request);

static
globus_bool_t
globus_l_gram_job_manager_is_done(
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_job_manager_cancel(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_handle_t	handle,
    globus_bool_t *			reply);

static
int
globus_l_gram_job_manager_signal(
    globus_gram_jobmanager_request_t *	request,
    const char *			args,
    globus_gram_protocol_handle_t	handle,
    globus_bool_t *			reply);

static
int
globus_l_gram_job_manager_register(
    globus_gram_jobmanager_request_t *	request,
    const char *			args);

static
int
globus_l_gram_job_manager_unregister(
    globus_gram_jobmanager_request_t *	request,
    const char *			url);

static
void
globus_l_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_handle_t	handle,
    int					status,
    int					failure_code);

static
globus_bool_t
globus_gram_job_manager_query_valid(
    globus_gram_jobmanager_request_t *	request);

void
globus_gram_job_manager_query_callback(
    void *				arg,
    globus_gram_protocol_handle_t	handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					errorcode)
{
    globus_gram_jobmanager_request_t *	request		= arg;
    char *				query		= GLOBUS_NULL;
    char *				rest;
    int					rc;
    int					status;
    globus_bool_t			reply		= GLOBUS_TRUE;

    globus_mutex_lock(&request->mutex);

    status = request->status;

    rc = globus_gram_protocol_unpack_status_request(buf, nbytes, &query);

    if (rc != GLOBUS_SUCCESS)
    {
	goto unpack_failed;
    }

    globus_gram_job_manager_request_log(
	    request,
	    "JM : in globus_l_gram_job_manager_query_callback, query=%s\n",
		   query);

    rest = strchr(query,' ');
    if (rest)
	*rest++ = '\0';

    if (strcmp(query,"cancel")==0)
    {
	rc = globus_l_gram_job_manager_cancel(request, handle, &reply);
    }
    else if (strcmp(query,"status")==0)
    {
	status = request->status;
    }
    else if (strcmp(query,"signal")==0)
    {
	rc = globus_l_gram_job_manager_signal(request, rest, handle, &reply);
    }
    else if (strcmp(query,"register")==0)
    {
	rc = globus_l_gram_job_manager_register(request, rest);
    }
    else if (strcmp(query,"unregister")==0)
    {
	rc = globus_l_gram_job_manager_unregister(request, rest);
    }
    else
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
    }

unpack_failed:
    if (rc != GLOBUS_SUCCESS)
    {
	status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    }

    globus_gram_job_manager_request_log( request,
		   "JM : reply: (status=%d failure code=%d (%s))\n",
		   status, rc, globus_gram_protocol_error_string(rc));


    if(reply)
    {
	globus_l_gram_job_manager_query_reply(request, handle, status, rc);
    }
    globus_mutex_unlock(&request->mutex);

    if(query)
    {
	globus_libc_free(query);
    }

    return;
}
/* globus_gram_job_manager_query_callback() */

void
globus_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_query_t *	query)
{
    globus_l_gram_job_manager_query_reply(request,
	                                  query->handle,
					  request->status,
					  query->failure_code);
    if(query->signal_arg)
    {
	globus_libc_free(query->signal_arg);
    }
    globus_libc_free(query);
}
/* globus_gram_job_manager_query_reply() */

static
void
globus_l_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_handle_t	handle,
    int					status,
    int					failure_code)
{
    int					rc;
    int					i;
    int					code;
    globus_size_t			replysize;
    globus_byte_t *			reply             = GLOBUS_NULL;

    rc = failure_code;

    if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
    {
	rc = globus_gram_protocol_pack_status_reply(
	    status,
	    rc,
	    failure_code,
	    &reply,
	    &replysize );
    }
    if (rc == GLOBUS_SUCCESS)
    {
	code = 200;
    }
    else
    {
	code = 400;

	globus_libc_free(reply);
	reply = GLOBUS_NULL;
	replysize = 0;
    }
    globus_gram_job_manager_request_log(request,
		  "JM : sending reply:\n");
    for (i=0; i<replysize; i++)
    {
	globus_libc_fprintf(request->jobmanager_log_fp,
			    "%c", reply[i]);
    }
    globus_gram_job_manager_request_log(request,
			  "-------------------\n");

    globus_gram_protocol_reply(handle,
	                       code,
			       reply,
			       replysize);

    if(reply)
    {
	globus_libc_free(reply);
    }
}
/* globus_l_gram_job_manager_query_reply() */

static
int
globus_l_gram_job_manager_cancel(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_handle_t	handle,
    globus_bool_t *			reply)
{
    int 				rc		= GLOBUS_SUCCESS;
    globus_gram_job_manager_query_t *	query;
    globus_reltime_t			delay;

    query = globus_libc_malloc(sizeof(globus_gram_job_manager_query_t));

    query->type = GLOBUS_GRAM_JOB_MANAGER_CANCEL;
    query->handle = handle;
    query->signal = 0;
    query->signal_arg = NULL;

    if(!globus_l_gram_job_manager_can_cancel(request))
    {
       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
       *reply = GLOBUS_TRUE;

       return rc;
    }

    globus_fifo_enqueue(&request->pending_queries, query);
    *reply = GLOBUS_FALSE;

    if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
    {
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
	if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
	{
	    rc = globus_callback_unregister(
		request->poll_timer);
	    if(rc == GLOBUS_SUCCESS)
	    {
		GlobusTimeReltimeSet(delay, 0, 0);
		globus_callback_register_oneshot(
			&request->two_phase_commit_timer,
			&delay,
			globus_gram_job_manager_state_machine_callback,
			request,
			NULL,
			NULL);
	    }
	}
    }
    return rc;
}
/* globus_l_gram_job_manager_cancel() */

static
int
globus_l_gram_job_manager_register(
    globus_gram_jobmanager_request_t *	request,
    const char *			args)
{
    int					rc = GLOBUS_SUCCESS;
    char *				url = NULL;
    int					mask;

    url = globus_libc_malloc(strlen(args));

    if (globus_l_gram_job_manager_is_done(request))
    {
       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
    }
    else if(sscanf(args, "%d %s", &mask, url) != 2)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    else
    {
	rc = globus_gram_job_manager_contact_add(request, url, mask);

    }
    globus_libc_free(url);

    return rc;
}
/* globus_l_gram_job_manager_register() */

static
int
globus_l_gram_job_manager_unregister(
    globus_gram_jobmanager_request_t *	request,
    const char *			url)
{
    int rc;

    if (globus_l_gram_job_manager_is_done(request))
    {
       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
    }
    else if (!url || strlen(url) == 0)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    else
    {
	rc = globus_gram_job_manager_contact_remove(request, url);
    }
    return rc;
}
/* globus_l_gram_job_manager_unregister() */


static
int
globus_l_gram_job_manager_signal(
    globus_gram_jobmanager_request_t *	request,
    const char *			args,
    globus_gram_protocol_handle_t	handle,
    globus_bool_t *			reply)
{
    int					rc;
    int					signal;
    char *				after_signal;
    globus_off_t			out_size = -1;
    globus_off_t			err_size = -1;
    globus_reltime_t			delay;
    globus_gram_job_manager_query_t *	query;

    *reply = GLOBUS_TRUE;
    if(sscanf(args, "%d", &signal) != 1)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    after_signal = strchr(args,' ');
    if (after_signal)
	*after_signal++ = '\0';

    switch(signal)
    {
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_SUSPEND:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_RESUME:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_PRIORITY:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_UPDATE:
	if(!after_signal || strlen(after_signal) == 0)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	    break;
	}
	query = globus_libc_malloc(sizeof(globus_gram_job_manager_query_t));

	query->type = GLOBUS_GRAM_JOB_MANAGER_SIGNAL;
	query->handle = handle;
	query->signal = signal;
	query->signal_arg = globus_libc_strdup(after_signal);

	if(!globus_gram_job_manager_query_valid(request))
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
	    break;
	}

	globus_fifo_enqueue(&request->pending_queries, query);
	*reply = GLOBUS_FALSE;

	if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
	    if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
	    {
		rc = globus_callback_unregister(
		    request->poll_timer);
		if(rc == GLOBUS_SUCCESS)
		{
		    GlobusTimeReltimeSet(delay, 0, 0);
		    globus_callback_register_oneshot(
			    &request->two_phase_commit_timer,
			    &delay,
			    globus_gram_job_manager_state_machine_callback,
			    request,
			    NULL,
			    NULL);
		}
	    }
	}
	break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END:
	if(request->two_phase_commit == 0)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT;

	    break;
	}
	else if(request->jobmanager_state ==
		    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)
	{
	    request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
	}
	else
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;

	    break;
	}
	if(request->two_phase_commit_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
	{
	    rc = globus_callback_unregister(
		    request->two_phase_commit_timer);
	    if(rc == GLOBUS_SUCCESS)
	    {
		/* 
		 * Cancelled callback before it ran--schedule the
		 * state machine to run after the query handler exits.
		 */
		GlobusTimeReltimeSet(delay, 0, 0);
		globus_callback_register_oneshot(
			&request->two_phase_commit_timer,
			&delay,
			globus_gram_job_manager_state_machine_callback,
			request,
			NULL,
			NULL);
	    }
	}
	break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_EXTEND:
	if ((!after_signal) || (strlen(after_signal) == 0))
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	}
	else if(request->two_phase_commit == 0)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMIT_EXTEND;
	    request->commit_extend += atoi(after_signal);
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMIT_EXTEND;
	    request->commit_extend += atoi(after_signal);
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMIT_EXTEND;
	    request->commit_extend += atoi(after_signal);
	}
	break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_SIZE:
	if (after_signal &&
		sscanf(after_signal, "%"GLOBUS_OFF_T_FORMAT" %"GLOBUS_OFF_T_FORMAT,
		       &out_size, &err_size) > 0)
	{
	    if(out_size >= 0)
	    {
		if(!globus_gram_job_manager_output_check_size(
			request,
			GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
			out_size))
		{
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE;
		}
	    }
	    if(err_size >= 0)
	    {
		if(!globus_gram_job_manager_output_check_size(
			request,
			GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
			err_size))
		{
		    rc = GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE;
		}
	    }
	}
	else
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	}
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STOP_MANAGER:
	if(!globus_l_gram_job_manager_can_cancel(request))
	{
	   rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
	}
	else
	{
	    request->status =
		GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->unsent_status_change = GLOBUS_TRUE;
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
	}
	break;
    default:
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_UNKNOWN_SIGNAL_TYPE;
    }
    return rc;
}
/* globus_l_gram_job_manager_signal() */

static
globus_bool_t
globus_l_gram_job_manager_is_done(
    globus_gram_jobmanager_request_t *	request)
{
    if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_DONE ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE)
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: job manager request handling is done, "
		"request will be denied\n");

	return GLOBUS_TRUE;
    }
    globus_gram_job_manager_request_log(
	    request,
	    "JM: job manager request handling is not done yet, "
		"request will be processed\n");
    return GLOBUS_FALSE;
}
/* globus_l_gram_job_manager_is_done() */

static
globus_bool_t
globus_l_gram_job_manager_can_cancel(
    globus_gram_jobmanager_request_t *	request)
{
    if(request->jobmanager_state
	   == GLOBUS_GRAM_JOB_MANAGER_STATE_START ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_MAKE_SCRATCHDIR ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMIT_EXTEND ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1 ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
    {
	return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}
/* globus_l_gram_job_manager_can_cancel() */

static
globus_bool_t
globus_gram_job_manager_query_valid(
    globus_gram_jobmanager_request_t *	request)
{
    switch(
	    (request->restart_state != GLOBUS_GRAM_JOB_MANAGER_STATE_START)
	    ? request->restart_state : request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_MAKE_SCRATCHDIR:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMIT_EXTEND:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
	  return GLOBUS_TRUE;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMIT_EXTEND:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_PRE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_RESPONSE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMIT_EXTEND:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
	  return GLOBUS_FALSE;
    }
    return GLOBUS_FALSE;
}
/* globus_gram_job_manager_query_valid() */
