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
#endif

/* Module Specific Prototypes */
static
globus_bool_t
globus_l_gram_job_manager_need_stage_in(
    globus_gram_jobmanager_request_t *	request);

static
globus_bool_t
globus_l_gram_job_manager_need_stage_out(
    globus_gram_jobmanager_request_t *	request);

static
globus_bool_t
globus_l_gram_job_manager_need_file_cleanup(
    globus_gram_jobmanager_request_t *	request);

#ifdef BUILD_DEBUG

#   define GLOBUS_GRAM_JOB_MANAGER_INVALID_STATE(request) \
        globus_jobmanager_log(request->jobmanager_log_fp, \
	                  "Invalid Job Manager State %d\n", \
			  request->jobmanager_state);\
        globus_assert(0);

#   define GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, when) \
        globus_jobmanager_log(request->jobmanager_log_fp, \
	                  "Job Manager State Machine (%s): %d\n", \
			  when, \
			  request->jobmanager_state)

#else

#   define GLOBUS_GRAM_JOB_MANAGER_INVALID_STATE(request)
#   define GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, when)

#endif

/*
 * Callback to enter the state machine from a timeout. Used to
 * handle two-phase commit timeouts, and delays between calls to the
 * poll script.
 */
globus_bool_t
globus_i_gram_job_manager_state_machine_callback(
    globus_abstime_t *			time_stop,
    void *				user_arg)
{
    globus_gram_jobmanager_request_t *	request;
    globus_bool_t			event_registered;
    globus_reltime_t			delay_time;

    request = user_arg;

    globus_mutex_lock(&request->mutex);
    do
    {
	event_registered = globus_i_gram_job_manager_state_machine(request);
    }
    while(!event_registered);
    globus_mutex_unlock(&request->mutex);

    return GLOBUS_TRUE;
}
/* globus_i_gram_job_manager_state_machine_callback() */


/*
 * Job Manager state machine.
 */
globus_bool_t
globus_i_gram_job_manager_state_machine(
    globus_gram_jobmanager_request_t *	request)
{
    globus_bool_t			event_registered = GLOBUS_FALSE;
    globus_reltime_t			delay_time;
    int					rc;
    int					save_status;
    int					save_jobmanager_state;

    GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, "entering");

    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE;

	/*
	 * To do a two-phase commit, we need to send an error
	 * message (WAITING_FOR_COMMIT) in the initial reply; otherwise,
	 * we just return the current status code
	 */
	if(!request->dry_run)
	{
	    rc = globus_i_gram_job_manager_reply(
		    request,
		    (request->two_phase_commit != 0 && request->failure_code == 0)
			?  GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT
			: request->failure_code);

	    if(request->two_phase_commit != 0 && rc == GLOBUS_SUCCESS)
	    {
		GlobusTimeReltimeSet(delay_time, request->two_phase_commit, 0);

		globus_callback_register_oneshot(
			&request->two_phase_commit_timer,
			&delay_time,
			globus_i_gram_job_manager_state_machine_callback,
			request,
			GLOBUS_NULL,
			GLOBUS_NULL);

		event_registered = GLOBUS_TRUE;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
	if(request->two_phase_commit == 0)
	{
	    /* Nothing to do here if we are not doing the two-phase
	     * commit protocol
	     */
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED;
	}
	else if(request->save_state)
	{
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
	}
	else
	{
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN;

	if(globus_l_gram_job_manager_need_stage_in(request))
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN;

	    if(!request->dry_run)
	    {
		globus_i_gram_job_manager_state_callback(request);
	    }

	    rc = globus_gram_job_manager_stage_in(request);

	    if(rc != GLOBUS_SUCCESS)
	    {
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
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT;

	rc = globus_gram_job_manager_submit(request);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
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

	    globus_i_gram_job_manager_reply(request);
	    break;
	}
	/* FALLSTHROUGH when not a dry-run */
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
	if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	}
	else if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
	{
	    /* Job finished! start staging out */
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT;

	    if(globus_l_gram_job_manager_need_stage_out(request))
	    {
		request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT;

		globus_i_gram_job_manager_state_callback(request);

		rc = globus_jobmanager_request_stage_out(request);

		if(rc != GLOBUS_SUCCESS)
		{
		    request->jobmanager_state =
			GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
		}
	    }
	}
	else
	{
	    /* Send job state callbacks if necessary */
	    if(request->unsent_status_change)
	    {
		globus_i_gram_job_manager_state_callback(request);
		request->unsent_status_change = GLOBUS_FALSE;
	    }

	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;

	    /* Register next poll of job state */
	    GlobusTimeReltimeSet(delay_time, request->poll_frequency, 0);

	    globus_callback_register_oneshot(
		    &request->poll_timer,
		    &delay_time,
		    globus_i_gram_job_manager_state_machine_callback,
		    request,
		    GLOBUS_NULL,
		    GLOBUS_NULL);

	    event_registered = GLOBUS_TRUE;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
	/* timer expired since last poll. poll again. */
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
	rc = globus_gram_job_manager_poll(request);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	}
	else
	{
	    event_registered = GLOBUS_TRUE;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
	if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT)
	{
	    /* stage out completed, close output destinations */
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

	rc = globus_i_gram_job_manager_output_close(request);

	if(rc == GLOBUS_SUCCESS)
	{
	    globus_assert(request->jobmanager_state == save_jobmanager_state);

	    /* Closed without getting cancelled */
	    request->status = save_status;
	    globus_i_gram_job_manager_state_callback(request);
	    request->unsent_status_change = GLOBUS_FALSE;

	    if(request->jobmanager_state ==
		    GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT)
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END;
	    }
	    else
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE;
	    }

	    /* If we are doing the two-phase protocol, then the job state
	     * callback above will inform the client that it will need to
	     * send a commit signal. We'll procede when that signal comes.
	     */

	    if(request->two_phase_commit != 0)
	    {
		GlobusTimeReltimeSet(delay_time, request->two_phase_commit, 0);

		rc = globus_callback_register_oneshot(
			&request->two_phase_commit_timer,
			&delay_time,
			globus_i_gram_job_manager_state_machine_callback,
			request,
			GLOBUS_NULL,
			GLOBUS_NULL);

		if(rc == GLOBUS_SUCCESS)
		{
		    event_registered = GLOBUS_TRUE;
		}
	    }
	}

	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
	if(request->two_phase_commit == 0)
	{
	    /* Nothing to do here if we are not doing the two-phase
	     * commit protocol
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
	else if(request->save_state)
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;
	    globus_cond_signal(&request->cond);
	    event_registered = GLOBUS_TRUE;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
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
	if(globus_l_gram_job_manager_need_file_cleanup(request))
	{
	    rc = globus_jobmanager_request_file_cleanup(request);

	    if(rc != GLOBUS_SUCCESS)
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
	}

	if(globus_l_gram_job_manager_need_scratch_cleanup(request))
	{
	    globus_jobmanager_request_rm_scratchdir(request);
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
	globus_i_gram_job_manager_clean_cache(request);

	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_DONE;
	}
	else
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	}
	globus_cond_signal(&request->cond);
	event_registered = GLOBUS_TRUE;

	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;

	rc = globus_i_gram_job_manager_output_close(request);

	request->jobmanager_state = 
	    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;

	globus_cond_signal(&request->cond);
	event_registered = GLOBUS_TRUE;
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
	break;
    }

    return event_registered;
}
/* globus_i_gram_job_manager_state_machine() */

int
globus_i_gram_job_manager_reply(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc;
    char *				sent_contact;
    globus_byte_t *                     reply = NULL;
    globus_size_t                       replysize;
    globus_byte_t *                     sendbuf;
    globus_size_t                       sendsize;
    OM_uint32				major_status;
    OM_uint32				minor_status;
    int					token_status;


    if(request->failure_code == 0 ||
       request->failure_code ==
	   GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
    {
	sent_contact = request->job_contact;
    }
    else
    {
	sent_contact = NULL;
    }

    /* Response to initial job request. */
    rc = globus_gram_protocol_pack_job_request_reply(
	    request->failure_code,
	    sent_contact,
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
	globus_libc_free(reply);
    }
    globus_jobmanager_log( request->jobmanager_log_fp,
		   "JM: before sending to client: rc=%d (%s)\n",
		   rc, globus_gram_protocol_error_string(rc));
    if(rc == GLOBUS_SUCCESS)
    {
	if(request->response_context != GSS_C_NO_CONTEXT)
	{
	    major_status = globus_gss_assist_wrap_send(
		    &minor_status,
		    request->response_context,
		    sendbuf,
		    sendsize,
		    &token_status,
		    globus_gss_assist_token_send_fd,
		    stdout,
		    request->jobmanager_log_fp);
	}
	else
	{
	    printf("Job Manager Response: %s\n", sendbuf);
	    major_status = 0;
	}
	/*
	 * close the connection (both stdin and stdout are connected to the
	 * socket
	 */
	close(0);
	close(1);

	/*
	 * Reopen stdin and stdout to /dev/null---the job submit code
	 * expects to be able to close them
	 */
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);

	globus_libc_free(sendbuf);

	if(major_status != GSS_S_COMPLETE)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
	}
    }
    else
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JM: couldn't send job contact to client: rc=%d (%s)\n",
		rc,
		globus_gram_protocol_error_string(rc));
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
    }
    gss_delete_sec_context(&minor_status,
			   &request->response_context,
			   NULL);
    request->response_context = GSS_C_NO_CONTEXT;
    if(rc != GLOBUS_SUCCESS)
    {
	request->failure_code = rc;
    }

    GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, "exiting");
    return rc;
}
/* globus_i_gram_job_manager_state_callback() */

static
globus_bool_t
globus_l_gram_job_manager_need_stage_in(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;
    globus_list_t *			node;
    char *				value;
    globus_url_t			url;
    int					i;
    char *				can_stage[] =
					{ GLOBUS_GRAM_PROTOCOL_STDIN_PARAM,
					  GLOBUS_GRAM_PROTOCOL_EXECUTABLE_PARAM,
					  NULL
					};

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_i_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else if(globus_list_search_pred(
		attributes,
		globus_i_gram_job_manager_rsl_match,
		GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_SHARED_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	for(i = 0; can_stage[i] != NULL; i++)
	{
	    node = globus_list_search_pred(attributes,
					   globus_i_gram_job_manager_rsl_match,
					   can_stage[i]);
	    if(node)
	    {
		value =
		    globus_rsl_value_literal_get_string(
			    globus_list_first(node));

		if(globus_url_parse(value, &url) == 0)
		{
		    if(url.scheme_type != GLOBUS_URL_SCHEME_FILE)
		    {
			globus_url_destroy(&url);
			return GLOBUS_TRUE;
		    }
		    else
		    {
			globus_url_destroy(&url);
		    }
		}
	    }
	}
    }
    return GLOBUS_FALSE;
}
/* globus_l_gram_job_manager_need_stage_in() */

static
globus_bool_t
globus_l_gram_job_manager_need_stage_out(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_i_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_FILE_STAGE_OUT_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_l_gram_job_manager_need_stage_out() */

static
globus_bool_t
globus_l_gram_job_manager_need_file_cleanup(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_i_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_FILE_CLEANUP_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_l_gram_job_manager_need_file_cleanup() */

static
globus_bool_t
globus_l_gram_job_manager_need_scratch_cleanup(
    globus_gram_jobmanager_request_t *	request)
{
    globus_list_t *			attributes;

    attributes = globus_rsl_boolean_get_operand_list(request->rsl);

    if(globus_list_search_pred(attributes,
		               globus_i_gram_job_manager_rsl_match,
			       GLOBUS_GRAM_PROTOCOL_SCRATCHDIR_PARAM))
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_l_gram_job_manager_need_scratch_cleanup() */
