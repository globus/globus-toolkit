#include "globus_gram_job_manager.h"

#include <string.h>

static
globus_bool_t
globus_l_gram_job_manager_proxy_expiration(
    globus_abstime_t *      		time_stop,
    void *				callback_arg);

static
int
globus_l_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_jobmanager_request_t *	request,
    gss_cred_id_t			cred);

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
globus_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_jobmanager_request_t *	request)
{
    OM_uint32				major_status;
    OM_uint32				minor_status;
    gss_cred_id_t			cred;
    int					rc;

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
	return GLOBUS_SUCCESS; /*?*/
    }
    rc = globus_l_gram_job_manager_gsi_register_proxy_timeout(request, cred);
    gss_release_cred(&minor_status, &cred);

    return rc;
}
/* globus_gram_job_manager_gsi_register_proxy_timeout() */

/**
 * Reset the function to be called before proxy expires based on the
 * time left in a newly delegated credential.
 *
 * @param request
 * @param cred
 */
int
globus_gram_job_manager_gsi_update_proxy_timeout(
    globus_gram_jobmanager_request_t *	request,
    gss_cred_id_t			cred)
{
    int rc;

    rc = globus_callback_unregister(request->proxy_expiration_timer);

    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_FAILURE;
    }

    return
	globus_l_gram_job_manager_gsi_register_proxy_timeout(request, cred);
}
/* globus_gram_job_manager_gsi_update_proxy_timeout() */

static
int
globus_l_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_jobmanager_request_t *	request,
    gss_cred_id_t			cred)
{
    int					rc = GLOBUS_SUCCESS;
    OM_uint32				lifetime;
    OM_uint32				major_status;
    OM_uint32				minor_status;
    globus_reltime_t			delay_time;

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
		    "JM: user proxy lifetime is less than minimum "
		    "(%d seconds)\n",
		    request->proxy_timeout);
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
    }
    else
    {
	globus_gram_job_manager_request_log(request,
		      "JM: problem reading user proxy\n");
    }
    return rc;
}
/* globus_l_gram_job_manager_gsi_register_proxy_timeout() */

/**
 * Update the request with a new security credential.
 *
 * @param request
 * @param credential
 */
int
globus_gram_job_manager_gsi_update_credential(
    globus_gram_jobmanager_request_t *	request,
    gss_cred_id_t			credential)
{
    unsigned long			timestamp;
    char *				temporary_cred_url;
    char *				temporary_cred_name;
    FILE *				infp;
    FILE *				outfp;
    OM_uint32				major_status;
    OM_uint32				minor_status;
    gss_buffer_desc			credential_buffer;
    int					rc;
    char *				x509_filename;
    struct stat				statbuf;
    char *				cred_data_buffer;

    rc = globus_gram_protocol_set_credentials(credential);
    if(rc != GLOBUS_SUCCESS)
    {
	(void) gss_release_cred(&minor_status, &credential);
	return rc;
    }
    if(request->x509_user_proxy == NULL ||
	    !globus_gram_job_manager_gsi_used(request))
    {
	/* I don't know what to do with this new credential. */
	return GLOBUS_SUCCESS;
    }

    major_status = gss_export_cred(&minor_status,
	                           credential,
				   GSS_C_NO_OID,
				   1, /* export cred to disk */
				   &credential_buffer);
    if(GSS_ERROR(major_status))
    {
	/* Too bad, can't write the proxy to disk */
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
	goto export_failed;
    }

    temporary_cred_url =
	globus_libc_malloc(GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);

    if(temporary_cred_url == NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
	goto cred_url_malloc_failed;
    }

    sprintf(temporary_cred_url,
	    "%sx509_deleg_proxy",
	    request->job_contact);

    x509_filename = strstr(credential_buffer.value, "=");

    if(x509_filename == NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
	goto strstr_failed;
    }
    /* skip '=' */
    x509_filename++;

    rc = globus_gass_cache_add(&request->cache_handle,
	                       temporary_cred_url,
			       request->cache_tag,
			       GLOBUS_TRUE,
			       &timestamp,
			       &temporary_cred_name);

    if(rc != GLOBUS_GASS_CACHE_ADD_NEW && 
       rc != GLOBUS_GASS_CACHE_ADD_EXISTS)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
	goto cache_add_failed;
    }
    rc = stat(x509_filename, &statbuf);
    if(rc < 0 || statbuf.st_size <= 0)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
	goto stat_failed;
    }
    infp = fopen(x509_filename, "r");
    if(infp == NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
	goto infp_fopen_failed;
    }
    cred_data_buffer = globus_libc_malloc(statbuf.st_size);
    if(cred_data_buffer == NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
	goto cred_data_buffer_malloc_failed;
    }
    rc = fread(cred_data_buffer, statbuf.st_size, 1, infp);
    if(rc != 1)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
	goto fread_failed;
    }
    outfp = fopen(temporary_cred_name, "w");
    if(outfp == NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
	goto outfp_fopen_failed;
    }
    rc = fwrite(cred_data_buffer, statbuf.st_size, 1, outfp);
    if(rc != 1)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;

	goto fwrite_failed;
    }
    rc = fclose(outfp);
    outfp = NULL;
    if(rc < 0)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;

	goto fclose_outfp_failed;
    }
    rc = rename(temporary_cred_name, request->x509_user_proxy);
    if(rc < 0)
    {
	goto rename_failed;
    }

    rc = GLOBUS_SUCCESS;

rename_failed:
fclose_outfp_failed:
    if(rc != GLOBUS_SUCCESS)
    {
	remove(temporary_cred_name);
    }
fwrite_failed:
    if(outfp)
    {
	fclose(outfp);
    }
outfp_fopen_failed:
fread_failed:
    globus_libc_free(cred_data_buffer);
cred_data_buffer_malloc_failed:
    fclose(infp);
infp_fopen_failed:
stat_failed:
    globus_gass_cache_delete(&request->cache_handle,
			     temporary_cred_url,
			     request->cache_tag,
			     timestamp,
			     GLOBUS_TRUE);
    globus_libc_free(temporary_cred_name);
    globus_libc_free(temporary_cred_url);
cache_add_failed:
strstr_failed:
cred_url_malloc_failed:
    remove(x509_filename);
    gss_release_buffer(&minor_status, &credential_buffer);
export_failed:
    return rc;
}
/* globus_gram_job_manager_gsi_update_credential() */

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
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
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
