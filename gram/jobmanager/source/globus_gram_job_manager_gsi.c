#include "globus_gram_job_manager.h"
#include <string.h>

static
globus_bool_t
globus_l_gram_job_manager_proxy_expiration(
    globus_abstime_t *      		time_stop,
    void *				callback_arg);

int
globus_gram_job_manager_import_sec_context(
    globus_gram_jobmanager_request_t *	request)
{
    OM_uint32				major_status;
    OM_uint32				minor_status;
    int					token_status;

    major_status = globus_gss_assist_import_sec_context(
    	&minor_status,
	&request->response_context,
	&token_status,
	-1,
	request->jobmanager_log_fp);

    if(major_status != GSS_S_COMPLETE)
    {
	globus_gram_job_manager_request_log(request,
	                      "JM: Failed to load security context\n");
	return GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
    }
    globus_gram_job_manager_request_log(request,
			  "JM: Security context imported\n");
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_import_sec_context() */

/**
 * Check to see if we are using GSI.
 *
 * Checks the GSSAPI implementation mechanisms to decide if we
 * are using the GSI implementation of the GSSAPI specification.
 * If so, we can do some nice tricks like relocation of a user proxy
 * into the user's GASS cache.
 *
 * @param request
 *        The request we are processing. Used for logging.
 *
 * @return This function returns GLOBUS_TRUE if the job manager is
 * using GSI, GLOBUS_FALSE otherwise.
 */
globus_bool_t
globus_gram_job_manager_gsi_used(
    globus_gram_jobmanager_request_t *	request)
{
    OM_uint32				major_status;
    OM_uint32				minor_status;
    /*
     * define the Globus object ids
     * This is regestered as a private enterprise
     * via IANA
     * http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
     *
     * iso.org.dod.internet.private.enterprise (1.3.6.1.4.1)
     * globus 3536
     * security 1
     * gssapi_ssleay 1
     */
    gss_OID_desc 			gsi_mech=
	    {9, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01"};
    gss_OID_set				mechs;
    int					present = 0;

    /*
     * relocate the user proxy to the gass cache and
     * return the local file name.
     */
    globus_gram_job_manager_request_log(
	    request,
	    "JM: user proxy relocation\n");

    /*
     * Figure out if we're using GSI
     */
    major_status = gss_indicate_mechs(&minor_status,
				      &mechs);
    if(major_status == GSS_S_COMPLETE)
    {
	major_status = gss_test_oid_set_member(
		&minor_status,
		&gsi_mech,
		mechs,
		&present);
	if(major_status != GSS_S_COMPLETE)
	{
	    present = 0;
	}
	gss_release_oid_set(&minor_status, &mechs);
    }

    return (present ? GLOBUS_TRUE : GLOBUS_FALSE);
}
/* globus_l_gram_job_manager_gsi_used() */

/**
 * Register function to be called before proxy expires
 *
 * @param request
 */
int
globus_gram_job_manager_register_proxy_timeout(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc = GLOBUS_SUCCESS;
    gss_cred_id_t			cred;
    OM_uint32				lifetime;
    OM_uint32				major_status;
    OM_uint32				minor_status;
    globus_reltime_t			delay_time;

    /*
     * According to RFC 2743, this shouldn't be necessary, but GSI
     * doesn't support inquire_cred with the default credential
     */
    major_status = globus_gss_assist_acquire_cred(
	    &minor_status,
	    GSS_C_BOTH,
	    &cred);

    if(major_status != GSS_S_COMPLETE)
    {
	globus_gram_job_manager_request_log(request,
		      "JM: problem reading user proxy\n");
    }
    else
    {
	major_status = gss_inquire_cred(
		&minor_status,
		cred,
		NULL,
		&lifetime,
		NULL,
		NULL);

	if(major_status == GSS_S_COMPLETE)
	{
	    if (lifetime - request->proxy_timeout <= 0)
	    {
		request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
		rc = GLOBUS_FAILURE;
		globus_gram_job_manager_request_log(
			request,
			"JM: user proxy lifetime is less than minimum (5 minutes)\n");
	    }
	    else
	    {
		/* set timer */
		GlobusTimeReltimeSet(delay_time, lifetime - request->proxy_timeout, 0);
		globus_callback_register_oneshot(
			&request->proxy_expiration_timer,
			&delay_time,
			globus_l_gram_job_manager_proxy_expiration,
			request,
			GLOBUS_NULL,
			GLOBUS_NULL);
	    }
	    gss_release_cred(&minor_status, &cred);
	}
	else
	{
	    globus_gram_job_manager_request_log(request,
			  "JM: problem reading user proxy\n");
	}
    }
    return rc;
}
/* globus_gram_job_manager_register_proxy_timeout() */

static
globus_bool_t
globus_l_gram_job_manager_proxy_expiration(
    globus_abstime_t *      		time_stop,
    void *				callback_arg)
{
    globus_gram_jobmanager_request_t *	request;

    request = callback_arg;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: User proxy expired! Abort, but leave job running!\n");

    globus_mutex_lock(&request->mutex);
    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_READ_STATE_FILE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_MAKE_SCRATCHDIR:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_MAKE_SCRATCHDIR:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_REMOTE_IO_FILE_CREATE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_RELOCATE:
	  /* Proxy expiration callback isn't registered until the
	   * proxy has been relocated, so this should NEVER happen.
	   */
	  globus_assert(/* premature proxy expiration */0);
	  break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMIT_EXTEND:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN:
        if(request->save_state)
        {
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
	    request->unsent_status_change = GLOBUS_TRUE;
        }
        else
        {
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    request->unsent_status_change = GLOBUS_TRUE;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
        if(request->save_state)
        {
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
        }
        else
        {
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
        }
        break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
        if(request->save_state)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
	}
	else 
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMIT_EXTEND:
        if(request->save_state)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
	}
	else 
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMIT_EXTEND;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
        if(request->save_state)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
	}
	else 
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
        if(request->save_state)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
	}
	else 
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
        if(request->save_state)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
	}
	else 
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP:
        if(request->save_state)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
	}
	else 
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_PRE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_RESPONSE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMIT_EXTEND:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
	break;

    }
    globus_mutex_unlock(&request->mutex);

    return GLOBUS_TRUE;
}
/* globus_l_gram_job_manager_proxy_expiration() */
