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

static
void
globus_l_gram_job_manager_proxy_expiration(
    void *                              callback_arg);

static
int
globus_l_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    int                                 timeout,
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

    major_status = globus_gss_assist_import_sec_context(
        &minor_status,
        response_contextp,
        &token_status,
        context_fd,
        manager->jobmanager_log_fp);

    if(major_status != GSS_S_COMPLETE)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: Failed to load security context\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
    }
    globus_gram_job_manager_log(manager, "JM: Security context imported\n");
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
    *callback_handle = GLOBUS_NULL_HANDLE;

    return globus_l_gram_job_manager_gsi_register_proxy_timeout(
            manager,
            cred,
            timeout,
            callback_handle);
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

    subject_name = globus_libc_strdup(export_name.value);
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
    return rc;
}
/* globus_gram_job_manager_gsi_get_subject() */

/**
 * Modify timeout to occur when the job manager's proxy is set to expire based on a new credential
 *
 * @param manager
 *     Job manager state (for logging)
 * @param cred
 *     Job manager credential
 * @param timeout
 *     Time (in seconds) to stop the manager if no credential is available.
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
int
globus_gram_job_manager_gsi_update_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    int                                 timeout,
    globus_callback_handle_t *          callback_handle)
{
    return globus_l_gram_job_manager_gsi_register_proxy_timeout(
            manager,
            cred,
            timeout,
            callback_handle);

}
/* globus_gram_job_manager_gsi_update_proxy_timeout() */

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
    gss_cred_id_t                       cred,
    int                                 timeout,
    globus_callback_handle_t *          callback_handle)
{
    int                                 rc = GLOBUS_SUCCESS;
    OM_uint32                           lifetime;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    globus_result_t                     result;
    globus_reltime_t                    delay_time;

    major_status = gss_inquire_cred(
            &minor_status,
            cred,
            NULL,
            &lifetime,
            NULL,
            NULL);

    if(major_status == GSS_S_COMPLETE)
    {
        if (((int) lifetime - timeout) <= 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
            globus_gram_job_manager_log(
                    manager,
                    "JM: user proxy lifetime is less than minimum "
                    "(%d seconds)\n",
                    timeout);
            goto proxy_expired;
        }
        else
        {
            /* set timer */
            GlobusTimeReltimeSet(
                    delay_time,
                    lifetime - timeout,
                    0);

            if (*callback_handle == GLOBUS_NULL_HANDLE)
            {
                result = globus_callback_register_oneshot(
                        callback_handle,
                        &delay_time,
                        globus_l_gram_job_manager_proxy_expiration,
                        manager);
            }
            else
            {
                result = globus_callback_adjust_oneshot(
                        *callback_handle,
                        &delay_time);
            }
            if (result != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
                goto oneshot_failed;
            }
        }
    }
    else
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND;
        goto inquire_failed;
    }

inquire_failed:
proxy_expired:
oneshot_failed:
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
    globus_gram_jobmanager_request_t *  request,
    gss_cred_id_t                       credential)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_desc                     credential_buffer;
    int                                 rc;
    char *                              x509_filename;

    rc = globus_gram_protocol_set_credentials(credential);
    if(rc != GLOBUS_SUCCESS)
    {
        (void) gss_release_cred(&minor_status, &credential);
        return rc;
    }
    if(!globus_gram_job_manager_gsi_used(request))
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

    x509_filename = strstr(credential_buffer.value, "=");

    if(x509_filename == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
        goto strstr_failed;
    }

    /* skip '=' */
    x509_filename++;
    rc = globus_gram_job_manager_gsi_relocate_proxy(request, x509_filename);

    if(rc != GLOBUS_SUCCESS)
    {
        remove(x509_filename);
    }

strstr_failed:
export_failed:
    return rc;
}
/* globus_gram_job_manager_gsi_update_credential() */

/**
 * Relocates a proxy file into the GASS Cache. Updates the
 * X509_USER_PROXY environment variable to point to the new location
 * of the proxy, and then removes the file located at @a new_proxy.
 * In the case of an error, the @a new_proxy file will not be removed.
 *
 * @param request
 * @param new_proxy
 */
int
globus_gram_job_manager_gsi_relocate_proxy(
    globus_gram_jobmanager_request_t *  request,
    const char *                        new_proxy)
{
    struct stat                         statbuf;
    int                                 rc = 0;
    FILE *                              infp = NULL;
    int                                 fd = -1;
    char *                              cred_data = NULL;

    rc = stat(new_proxy, &statbuf);

    if(rc < 0 || statbuf.st_size <= 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto stat_failed;
    }

    cred_data = globus_libc_malloc(statbuf.st_size);

    if(cred_data == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto cred_data_malloc_failed;
    }
    infp = fopen(new_proxy, "r");

    if(infp == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto fopen_new_proxy_failed;
    }

    rc = fread(cred_data, (size_t) statbuf.st_size, 1, infp);

    if(rc != 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto fread_new_proxy_failed;
    }

    fclose(infp);
    infp = NULL;

    fd = open(request->x509_user_proxy, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if(fd == -1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto job_proxy_open_failed;
    }
    rc = write(fd, cred_data, (size_t) statbuf.st_size);
    if(rc != 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;

        goto job_proxy_write_failed;
    }
    rc = 0;
    close(fd);
    fd = -1;

job_proxy_write_failed:
    if(fd != -1)
    {
        close(fd);
        fd = -1;
    }
job_proxy_open_failed:
fread_new_proxy_failed:
    if(infp != NULL)
    {
        globus_libc_free(infp);
    }
fopen_new_proxy_failed:
    if(cred_data)
    {
        globus_libc_free(cred_data);
    }
cred_data_malloc_failed:
stat_failed:
    if(rc == GLOBUS_SUCCESS)
    {
        remove(new_proxy);
    }

    return rc;
}
/* globus_gram_job_manager_gsi_relocate_proxy() */

static
void
globus_l_gram_job_manager_proxy_expiration(
    void *                              callback_arg)
{
    globus_gram_jobmanager_request_t *  request;

    request = callback_arg;

    globus_gram_job_manager_request_log(
            request,
            "JM: User proxy expired! Abort, but leave job running!\n");

    globus_mutex_lock(&request->mutex);
    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
          /* Proxy expiration callback isn't registered until the
           * proxy has been relocated, so this should NEVER happen.
           */
          globus_assert(
                request->jobmanager_state!=GLOBUS_GRAM_JOB_MANAGER_STATE_START);
          break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH:
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
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
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
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
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
}
/* globus_l_gram_job_manager_proxy_expiration() */

int
globus_gram_job_manager_call_authz_callout(
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
