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

char *
globus_gram_job_manager_gsi_proxy_relocate(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc;
    int					proxy_fd, new_proxy_fd;
    char				buf[512];
    char *				user_proxy_path;
    char *				cache_user_proxy_filename;
    char *				unique_file_name;
    unsigned long			timestamp;

    globus_gram_job_manager_request_log( request,
          "JM: Relocating user proxy file to the gass cache\n");

    user_proxy_path = (char *) getenv("X509_USER_PROXY");
    if (!user_proxy_path)
    {
        return(GLOBUS_NULL);
    }

    unique_file_name = globus_libc_malloc(strlen(request->cache_tag) +
                                    strlen("x509_user_proxy") + 2);

    globus_libc_sprintf(unique_file_name,
                        "%s/%s",
                        request->cache_tag,
                        "x509_user_proxy");

    rc = globus_gass_cache_add(&request->cache_handle,
                               unique_file_name,
                               request->cache_tag,
                               GLOBUS_TRUE,
                               &timestamp,
                               &cache_user_proxy_filename);

    if ( rc == GLOBUS_GASS_CACHE_ADD_EXISTS ||
         rc == GLOBUS_GASS_CACHE_ADD_NEW )
    {

	char *tmp_file_name =
	    globus_libc_malloc(strlen(cache_user_proxy_filename)+5);

	sprintf(tmp_file_name, "%s.tmp", cache_user_proxy_filename);

        if ((proxy_fd = open(user_proxy_path, O_RDONLY)) < 0)
        {
            globus_gram_job_manager_request_log( request,
                "JM: Unable to open (source) user proxy file %s\n",
                user_proxy_path);
            globus_libc_free(unique_file_name);
	    globus_libc_free(tmp_file_name);
            request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
            return(GLOBUS_NULL);
        }

        if ((new_proxy_fd = open(tmp_file_name,
                                 O_CREAT|O_WRONLY|O_TRUNC,
				 0600)) < 0)
        {
            globus_gram_job_manager_request_log( request,
                "JM: Unable to open temp cache file for the user proxy %s\n",
                tmp_file_name);
            globus_libc_free(unique_file_name);
	    globus_libc_free(tmp_file_name);
            request->failure_code =
                  GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
            return(GLOBUS_NULL);
        }

        globus_gram_job_manager_request_log( request,
                "JM: Copying user proxy file from --> %s\n",
                user_proxy_path);
        globus_gram_job_manager_request_log( request,
                "JM:                         to   --> %s\n",
                cache_user_proxy_filename);

        while((rc = read(proxy_fd, buf, sizeof(buf))) > 0)
        {
             write(new_proxy_fd, buf, rc);
        }

        close(proxy_fd);
        close(new_proxy_fd);

	chmod(cache_user_proxy_filename, 0600);

	if (rename( tmp_file_name, cache_user_proxy_filename ) < 0)
	{
	    globus_gram_job_manager_request_log( request,
		    "JM: Unable rename temp cache file for user proxy %s\n",
		    cache_user_proxy_filename);
	    globus_libc_free(unique_file_name);
	    globus_libc_free(tmp_file_name);
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
	    return(GLOBUS_NULL);
	}

	chmod(cache_user_proxy_filename, 0400);

	globus_libc_free(tmp_file_name);

        rc = globus_gass_cache_add_done(&request->cache_handle,
                                        unique_file_name,
                                        request->cache_tag,
                                        timestamp);
        if(rc != GLOBUS_SUCCESS)
        {
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: globus_gass_cache_add_done failed for user proxy file --> %s\n",
		    user_proxy_path);

            if (remove(user_proxy_path) != 0)
            {
                globus_gram_job_manager_request_log( request,
                  "JM: Cannot remove user proxy file %s\n",user_proxy_path);
            }
            globus_libc_free(unique_file_name);
            return(GLOBUS_NULL);
        }
    }
    else
    {
	globus_gram_job_manager_request_log( request,
		       "JM: Cannot get a cache entry for user proxy file %s : %s\n",
		       unique_file_name, globus_gass_cache_error_string(rc));
        if (remove(user_proxy_path) != 0)
        {
            globus_gram_job_manager_request_log( request,
                "JM: Cannot remove user proxy file %s\n",user_proxy_path);
        }
        globus_libc_free(unique_file_name);
        return(GLOBUS_NULL);
    }

    if (remove(user_proxy_path) != 0)
    {
        globus_gram_job_manager_request_log( request,
            "JM: Cannot remove user proxy file %s\n",user_proxy_path);
    }

    return(cache_user_proxy_filename);
}
/* globus_gram_job_manager_gsi_proxy_relocate() */

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
	    if (lifetime - 300 <= 0)
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
		GlobusTimeReltimeSet(delay_time, lifetime - 300, 0);
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
    /* XXX Update jobmanager_state */
    globus_mutex_unlock(&request->mutex);

    return GLOBUS_TRUE;
}
/* globus_l_gram_job_manager_proxy_expiration() */
