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

#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_gsi_system_config.h"
#include "globus_callout.h"
#include "globus_callout_constants.h"
#include "globus_gram_jobmanager_callout_error.h"

#include <string.h>
#include <openssl/evp.h>

static
void
globus_l_gram_job_manager_proxy_expiration(
    void *                              callback_arg);

static
int
globus_l_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    globus_reltime_t *                  timeout,
    globus_callback_handle_t *          callback_handle);

int
globus_gram_job_manager_import_sec_context(
    globus_gram_job_manager_t *         manager,
    int                                 context_fd,
    gss_ctx_id_t *                      response_contextp)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 token_status;
    gss_name_t                          globus_id = NULL;
    gss_buffer_desc                     globus_id_token = { 0, NULL };

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.import_sec_context.start level=TRACE fd=%d\n",
            context_fd);

    major_status = globus_gss_assist_import_sec_context(
        &minor_status,
        response_contextp,
        &token_status,
        context_fd,
        NULL /*manager->jobmanager_log_fp*/);

    if (GSS_ERROR(major_status))
    {
        char *                          error_string = NULL;
        char *                          escaped_error_string;
        globus_gss_assist_display_status_str(
                &error_string,
                "",
                major_status,
                minor_status,
                0);

        escaped_error_string = globus_gram_prepare_log_string(error_string);

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.import_sec_context.end level=ERROR status=%d "
                "major_status=%d msg=\"Failed to load security context\" "
                "reason=\"%s\"\n",
                -GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED,
                major_status,
                escaped_error_string ? escaped_error_string : "");

        if (error_string)
        {
            free(error_string);
        }
        if (escaped_error_string)
        {
            free(escaped_error_string);
        }

        return GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
    }

    if (manager &&
            manager->config->log_levels & GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE)
    {
        do
        {
            major_status = gss_inquire_context(
                    &minor_status,
                    *response_contextp,
                    &globus_id,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
        }
        while (major_status == GSS_S_CONTINUE_NEEDED);

        if (major_status == GSS_S_COMPLETE)
        {
            do 
            {
                major_status = gss_display_name(
                        &minor_status,
                        globus_id,
                        &globus_id_token,
                        NULL);
            }
            while (major_status == GSS_S_CONTINUE_NEEDED);
        }

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.import_sec_context.end "
                "level=TRACE "
                "status=%d "
                "globusid=\"%s\" "
                "\n",
                0,
                globus_id_token.value != NULL ? globus_id_token.value : "");

        gss_release_buffer(
                &minor_status, 
                &globus_id_token);

        gss_release_name(
                &minor_status,
                &globus_id);
    }

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
    globus_gram_jobmanager_request_t *  request)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
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
    gss_OID_desc                        gsi_mech =
        {9, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01"};
    gss_OID_set                         mechs;
    int                                 present = 0;

    /*
     * Figure out if we're using GSI
     */
    major_status = gss_indicate_mechs(
            &minor_status,
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
 * Register timeout to occur when the job manager's proxy is set to expire
 *
 * @param manager
 *     Job manager state (for logging)
 * @param cred
 *     Job manager credential
 * @param timeout
 *     Time (in seconds) to stop the manager if no credential is available.
 * @param callback_handle
 *     Pointer to be set to the handle to the expiration callback.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED
 *     User proxy expired
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES
 *     No resources for callback
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND
 *     Proxy not found
 */
int
globus_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    int                                 timeout,
    globus_callback_handle_t *          callback_handle)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_reltime_t                    delay;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    OM_uint32                           lifetime;
    time_t                              cred_expiration_time;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.register_proxy_timeout.start "
            "level=TRACE "
            "\n");

    *callback_handle = GLOBUS_NULL_HANDLE;

    cred_expiration_time = time(NULL);

    major_status = gss_inquire_cred(
            &minor_status,
            cred,
            NULL,
            &lifetime,
            NULL,
            NULL);

    if (major_status != GSS_S_COMPLETE)
    {
        char *                          error_string = NULL;
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;

        globus_gss_assist_display_status_str(
                &error_string,
                "",
                major_status,
                minor_status,
                0);

        globus_gram_prepare_log_string(error_string);
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.register_proxy_timeout.end "
                "level=ERROR "
                "status=%d "
                "msg=\"%s\" "
                "major_status=%d "
                "reason=\"%s\"\n",
                -rc,
                "gss_inquire_cred failed",
                major_status,
                error_string ? error_string : "");
        if (error_string)
        {
            free(error_string);
        }
        goto failed_inquire_cred;
    }

    if (lifetime == GSS_C_INDEFINITE)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.register_proxy_timeout.end "
                "level=TRACE "
                "status=%d "
                "lifetime=indefinite "
                "msg=\"%s\" "
                "\n",
                "User proxy has indefinite lifetime");
        goto wont_expire;
    }

    cred_expiration_time += (time_t) lifetime;
    if (((long) lifetime - timeout) <= 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.register_proxy_timeout.end "
                "level=ERROR "
                "status=%d "
                "lifetime=%d "
                "msg=\"user proxy lifetime is less than minimum "
                "(%d seconds)\" "
                "reason=\"%s\" "
                "\n",
                (int) -rc,
                lifetime,
                timeout,
                globus_gram_protocol_error_string(rc));
        goto proxy_expired;
    }

    GlobusTimeReltimeSet(delay, lifetime - timeout, 0);
    manager->cred_expiration_time = cred_expiration_time;

    rc = globus_l_gram_job_manager_gsi_register_proxy_timeout(
            manager,
            &delay,
            callback_handle);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.register_proxy_timeout.end "
                "level=ERROR "
                "status=%d "
                "lifetime=%d "
                "msg=\"Error registering proxy timeout callback\" "
                "reason=\"%s\" "
                "\n",
                (int) -rc,
                lifetime,
                globus_gram_protocol_error_string(rc));
    }
    else
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.register_proxy_timeout.end "
                "level=TRACE "
                "status=%d "
                "lifetime=%d "
                "timeout=%d "
                "\n",
                (int) -rc,
                lifetime,
                timeout);
    }

proxy_expired:
wont_expire:
failed_inquire_cred:
    return rc;
}
/* globus_gram_job_manager_gsi_register_proxy_timeout() */

/**
 * Look up subject name from the process's credential.
 *
 * @param subject_namep
 *     Pointer to set to a copy of the subject name. The caller is responsible
 *     for freeing this string.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND
 *     Proxy not found.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 */
int
globus_gram_job_manager_gsi_get_subject(
    char **                             subject_namep)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 rc = GLOBUS_SUCCESS;
    gss_name_t                          name;
    gss_buffer_desc                     export_name;
    char *                              subject_name = NULL;

    export_name.value = NULL;
    export_name.length = 0;

    globus_gram_job_manager_log(
        NULL,
        GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
        "event=gram_gsi_get_subject.start "
        "level=TRACE \n");
    major_status = gss_inquire_cred(
            &minor_status,
            GSS_C_NO_CREDENTIAL,
            &name,
            NULL,
            NULL,
            NULL);
    if (major_status != GSS_S_COMPLETE)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;
        goto failed_inquire_cred;
    }

    major_status = gss_display_name(
            &minor_status,
            name,
            &export_name,
            NULL);
    if (major_status != GSS_S_COMPLETE)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto failed_display_name;
    }

    subject_name = strdup(export_name.value);
    if (subject_name == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto failed_subject_name_copy;
    }

failed_subject_name_copy:
    gss_release_buffer(&minor_status, &export_name);
failed_display_name:
    major_status = gss_release_name(
            &minor_status, 
            &name);
failed_inquire_cred:
    *subject_namep = subject_name;
    if (rc != GLOBUS_SUCCESS)
    {
        char *errmsg = NULL, *errmsg_escaped = NULL;
        if (major_status != GSS_S_COMPLETE)
        {
            globus_gss_assist_display_status_str(
                &errmsg,
                "Error getting subject",
                major_status,
                minor_status,
                0);

            errmsg_escaped = globus_gram_prepare_log_string(errmsg);
        }
        globus_gram_job_manager_log(
            NULL,
            GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
            "event=gram_gsi_get_subject.end "
            "level=ERROR "
            "status=%d "
            "reason=\"%s\" "
            "\n",
            -rc,
            errmsg_escaped
                ? errmsg_escaped :
                globus_gram_protocol_error_string(rc));
        if (errmsg)
        {
            free(errmsg);
        }
        if (errmsg_escaped)
        {
            free(errmsg_escaped);
        }
    }
    return rc;
}
/* globus_gram_job_manager_gsi_get_subject() */

/**
 * Register timeout to occur when the job manager's proxy is set to expire
 *
 * @param manager
 *     Job manager state (for logging)
 * @param timeout
 *     Relative time to delay before firing the proxy timeout
 * @param callback_handle
 *     Pointer to the expiration callback handle. If this points to 
 *     GLOBUS_NULL_HANDLE, then a new callback will be created and this will
 *     be modified to point to it. Otherwise, the callback handle will be
 *     modified.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED
 *     User proxy expired
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES
 *     No resources for callback
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND
 *     Proxy not found
 */
static
int
globus_l_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    globus_reltime_t *                  timeout,
    globus_callback_handle_t *          callback_handle)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_result_t                     result;

    if (*callback_handle == GLOBUS_NULL_HANDLE)
    {
        result = globus_callback_register_oneshot(
                callback_handle,
                timeout,
                globus_l_gram_job_manager_proxy_expiration,
                manager);
    }
    else
    {
        result = globus_callback_adjust_oneshot(
                *callback_handle,
                timeout);
    }
    if (result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }

    return rc;
}
/* globus_l_gram_job_manager_gsi_register_proxy_timeout() */

/**
 * Update the request with a new security credential.
 * 
 * If the new credential will live longer than the current Job Manager-wide
 * credential, use the new one with the GRAM protocol library, write it to the
 * state directory, and update the proxy timeout. 
 * 
 * If the request is non-null, update the proxy on disk in the job directory so
 * this particular job will have a copy of this credential.
 * 
 * The credential is either destroyed or passed to the GRAM Protocol library,
 * which will destroy it when no longer needed. The caller must not free
 * the credential.
 *
 * @param request
 *     Job request to update with this credential
 * @param credential
 *     New GSSAPI credential.
 */
int
globus_gram_job_manager_gsi_update_credential(
    globus_gram_job_manager_t *         manager,
    globus_gram_jobmanager_request_t *  request,
    gss_cred_id_t                       credential)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    OM_uint32                           lifetime;
    time_t                              credential_expiration_time;
    int                                 rc = GLOBUS_SUCCESS;
    globus_reltime_t                    delay_time;
    globus_bool_t                       set_credential = GLOBUS_FALSE;

    credential_expiration_time = time(NULL);

    major_status = gss_inquire_cred(
            &minor_status,
            credential,
            NULL,
            &lifetime,
            NULL,
            NULL);

    if (GSS_ERROR(major_status))
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto inquire_cred_failed;
    }

    if (lifetime != GSS_C_INDEFINITE)
    {
        credential_expiration_time += lifetime;
    }
    else
    {
        credential_expiration_time = 0;
    }

    if (manager->cred_expiration_time != 0 &&
        (lifetime == GSS_C_INDEFINITE ||
        credential_expiration_time > manager->cred_expiration_time))
    {
        manager->cred_expiration_time = credential_expiration_time;
        rc = globus_gram_job_manager_gsi_write_credential(
                request,
                credential,
                manager->cred_path);
        if (rc != 0)
        {
            goto write_manager_cred_failed;
        }
        set_credential = GLOBUS_TRUE;
        manager->stop = GLOBUS_FALSE;
    }

    if (request)
    {
        rc = globus_gram_job_manager_gsi_write_credential(
                request,
                credential,
                request->x509_user_proxy);
        if (rc != 0)
        {
            goto write_job_cred_failed;
        }
    }

    if (set_credential)
    {
        GlobusTimeReltimeSet(
                delay_time,
                lifetime - manager->config->proxy_timeout,
                0);
        rc = globus_l_gram_job_manager_gsi_register_proxy_timeout(
                manager,
                &delay_time,
                &manager->proxy_expiration_timer);
        if (rc != GLOBUS_SUCCESS)
        {
            goto register_timeout_failed;
        }

        rc = globus_gram_protocol_set_credentials(credential);
        credential = GSS_C_NO_CREDENTIAL;

        if (rc != GLOBUS_SUCCESS)
        {
            goto set_credentials_failed;
        }
    }

set_credentials_failed:
register_timeout_failed:
write_job_cred_failed:
write_manager_cred_failed:
inquire_cred_failed:
    if (credential != GSS_C_NO_CREDENTIAL)
    {
        gss_release_cred(&minor_status, &credential);
    }

    return rc;
}
/* globus_gram_job_manager_gsi_update_credential() */

/* Write a GSSAPI credential to a given path
 * @param credential
 *     Credential to write
 * @param path
 *     Path to write to
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY
 *     Error opening path
 */
int
globus_gram_job_manager_gsi_write_credential(
    globus_gram_jobmanager_request_t *  request,
    gss_cred_id_t                       credential,
    const char *                        path)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_desc                     credential_buffer;
    int                                 rc;
    int                                 fd;
    char *                              gt3_error_message = NULL;
    int                                 written;
    int                                 save_errno;

    major_status = gss_export_cred(&minor_status,
                                   credential,
                                   GSS_C_NO_OID,
                                   0,
                                   &credential_buffer);
    if(GSS_ERROR(major_status))
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
        (void) globus_gss_assist_display_status_str(
            &gt3_error_message,
            "credential export failed",
            major_status,
            minor_status,
            0);

        goto export_failed;
    }

    fd = open(
            path,
            O_WRONLY|O_CREAT|O_TRUNC,
            S_IRUSR|S_IWUSR);
    if(fd == -1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
        save_errno = errno;

        gt3_error_message = globus_common_create_string(
                "open credential file for writing failed: %s: %s (%d)",
                path,
                strerror(save_errno),
                save_errno);

        goto job_proxy_open_failed;
    }
    written = 0;

    do
    {
        rc = write(
                fd,
                ((char *) credential_buffer.value) + written,
                (size_t) credential_buffer.length - written);
        if(rc < 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
            save_errno = errno;
            gt3_error_message = globus_common_create_string(
                    "writing credential file failed: %s: %s (%d)",
                    path,
                    strerror(save_errno),
                    save_errno);

            goto job_proxy_write_failed;
        }
        else if (rc == 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
            gt3_error_message = globus_common_create_string(
                    "writing credential file failed: %s: %s",
                    path,
                    "short write");
            goto job_proxy_write_failed;
            
        }
        else
        {
            written += rc;
        }

    } while (written < credential_buffer.length);

    rc = close(fd);
    if (rc != 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;

        save_errno = errno;
        gt3_error_message = globus_common_create_string(
                "writing credential file failed: %s: %s (%d)",
                path,
                strerror(save_errno),
                save_errno);
        goto job_proxy_close_failed;
    }
    rc = 0;
    fd = -1;

job_proxy_write_failed:
    if(fd != -1)
    {
        close(fd);
        fd = -1;
    }
job_proxy_close_failed:
job_proxy_open_failed:
    (void) gss_release_buffer(&minor_status, &credential_buffer);
export_failed:
    if (request != NULL && request->gt3_failure_message == NULL)
    {
        request->gt3_failure_message = gt3_error_message;
    }
    else if (gt3_error_message)
    {
        free(gt3_error_message);
    }

    return rc;
}
/* globus_gram_job_manager_gsi_write_credential() */

static
void
globus_l_gram_job_manager_proxy_expiration(
    void *                              callback_arg)
{
    globus_gram_job_manager_t *         manager;

    manager = callback_arg;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
            "event=gram.proxy_expire.end level=WARN "
            "msg=\"Proxy expired, stopping job manager\"\n");

    globus_gram_job_manager_stop_all_jobs(manager);
}
/* globus_l_gram_job_manager_proxy_expiration() */

int
globus_gram_job_manager_call_authz_callout(
    globus_gram_job_manager_config_t *  config,
    gss_ctx_id_t                        request_context,
    gss_ctx_id_t                        authz_context,
    const char *                        uniq_id,
    const globus_rsl_t *                rsl,
    const char *                        auth_type)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_result_t                     result;
    globus_object_t *                   error;
    char *                              filename;
    globus_callout_handle_t             authz_handle;

    if (! config->enable_callout)
    {
        return GLOBUS_SUCCESS;
    }

    result = GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME(&filename);
    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_peek(result);
        
        if(! globus_error_match(
               error,
               GLOBUS_GSI_SYSCONFIG_MODULE,
               GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_AUTHZ_FILENAME))
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_SYSTEM_FAILURE;
        }
        goto conf_filename_failed;
    }

    result = globus_callout_handle_init(&authz_handle);
    if(result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_SYSTEM_FAILURE;
        goto handle_init_failed;
    }
    
    result = globus_callout_read_config(authz_handle, filename);
    if(result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_SYSTEM_FAILURE;
        goto read_config_failed;
    }
    
    result = globus_callout_call_type(authz_handle,
                                      GLOBUS_GRAM_AUTHZ_CALLOUT_TYPE,
                                      request_context,
                                      authz_context,
                                      uniq_id,
                                      rsl,
                                      auth_type);
    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_peek(result);
        
        if (globus_error_match(
               error,
               GLOBUS_CALLOUT_MODULE,
               GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED))
        {
            /* For queries, check authz self by default. The start case
             * is handled by the gatekeeper.
             */
            if (strcmp(auth_type, "start") != 0)
            {
                if (globus_gram_protocol_authorize_self(authz_context))
                {
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED;
                }
            }
        }
        else if (globus_error_match(
                   error,
                   GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
                   GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED))
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED;
        }
        else if (globus_error_match(
                    error,
                    GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
                    GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED_INVALID_JOB))
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED_JOB_ID;
        }
        else if (globus_error_match(
                    error,
                    GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
                    GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED_BAD_EXECUTABLE))
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED_EXECUTABLE;
        }
        else
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_SYSTEM_FAILURE;
            
        }
    }

read_config_failed:
    globus_callout_handle_destroy(authz_handle);
handle_init_failed:
    free(filename);
conf_filename_failed:
    return rc;
}
/* globus_gram_job_manager_call_authz_callout() */

int
globus_gram_job_manager_authz_query(
    globus_gram_job_manager_t *         manager,
    globus_gram_protocol_handle_t       handle,
    const char *                        uri,
    const char *                        auth_type)
{
    int                                 rc = GLOBUS_SUCCESS;
    gss_ctx_id_t                        context;
    globus_gram_jobmanager_request_t *  request;

    if (! manager->config->enable_callout)
    {
        goto skip_authz;
    }

    if ((rc = globus_gram_protocol_get_sec_context(
                handle,
                &context)) != GLOBUS_SUCCESS)
    {
        goto get_sec_context_failed;
    }

    rc = globus_gram_job_manager_add_reference(
            manager,
            uri,
            "query authz",
            &request);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_reference_failed;
    }

    rc = globus_gram_job_manager_call_authz_callout(
            request->config,
            request->response_context,
            context,
            request->uniq_id,
            request->rsl,
            auth_type);
    if (rc != GLOBUS_SUCCESS)
    {
        goto authz_failed;
    }

authz_failed:
    globus_gram_job_manager_remove_reference(
            manager,
            request->job_contact_path,
            "query authz");
add_reference_failed:
get_sec_context_failed:
skip_authz:
    return rc;
}
/* globus_gram_job_manager_authz_query() */

/**
 * @brief Look up the identity of a GSSAPI credential and generate a hash
 * @ingroup globus_gram_gsi
 *
 * @details
 * The globus_gram_gsi_get_dn_hash() function inspects the credential 
 * named by @a cred parameter to determine the identity of the credential.
 * It then computes the default hash on that name and assigns a copy of
 * that value to the @a hash parameter. The caller is responsible for freeing
 * that value.
 * 
 * @param cred
 *     GSSAPI credential to inspect
 * @param hash
 *     Pointer to be set to the hash of the identity of @a cred.
 *
 * @return 
 *     On success, globus_gram_gsi_get_dn_hash() returns GLOBUS_SUCCESS
 *     and modifies the @a hash parameter to point to a copy of the string
 *     representation of the hash. If an error occurs,
 *     globus_gram_gsi_get_dn_hash() returns a non-zero error code and the
 *     the value of @a hash is undefined.
 */
int
globus_gram_gsi_get_dn_hash(
    gss_cred_id_t                       cred,
    unsigned long *                     hash)
{
    int                                 rc = GLOBUS_SUCCESS;
    OM_uint32                           major, minor;
    gss_name_t                          name;
    gss_buffer_desc                     namebuf;
    unsigned char                       md[EVP_MAX_MD_SIZE+1];
    const EVP_MD *                      evp_md;
    EVP_MD_CTX *                        evp_ctx = NULL;
    unsigned int                        mdlen;
    unsigned long                       hash_value;

    if (hash == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto out;
    }
    *hash = 0L;
    if (cred == GSS_C_NO_CREDENTIAL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;

        goto out;
    }

    major = gss_inquire_cred(
            &minor,
            cred,
            &name,
            NULL,
            NULL,
            NULL);

    if (major != GSS_S_COMPLETE)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;

        goto out;
    }

    major = gss_display_name(
            &minor,
            name,
            &namebuf,
            NULL);
    if (major != GSS_S_COMPLETE)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;

        goto free_name_out;
    }

    evp_md = EVP_get_digestbyname("sha1");
    if (evp_md == NULL)
    {
        evp_md = EVP_get_digestbyname("md5");
    }
    if (evp_md == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto free_namebuf_out;
    }

    evp_ctx = EVP_MD_CTX_create();

    if (EVP_DigestInit_ex(evp_ctx, evp_md, NULL) != 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto free_namebuf_out;
    }

    if (EVP_DigestUpdate(evp_ctx, namebuf.value, namebuf.length) != 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto free_digest_out;
    }

    if (EVP_DigestFinal_ex(evp_ctx, md, &mdlen) != 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto free_digest_out;
    }
    hash_value = (((unsigned long)md[0]) |
                  ((unsigned long)md[1] << 8L) |
                  ((unsigned long)md[2] << 16L) |
                  ((unsigned long)md[3] << 24L)) & 0xffffffffL;

    *hash = hash_value;

free_digest_out:
    EVP_MD_CTX_destroy(evp_ctx);
free_namebuf_out:
    gss_release_buffer(&minor, &namebuf);
free_name_out:
    gss_release_name(&minor, &name);
out:
    return rc;
}
/* globus_gram_gsi_get_dn_hash() */
